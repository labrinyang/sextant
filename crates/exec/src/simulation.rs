//! Block-pinned checks of one built Settler transaction before it is offered
//! for signing: the taker's input balance and AllowanceHolder allowance, one
//! `eth_call` of the exact transaction from the taker, and its gas estimate.
//! Every read uses the same canonical block hash, taken from the chain head
//! when the quote is finalized rather than from the AMM snapshot, so an
//! approval that landed a moment ago is seen. The head read is one round trip
//! and every check goes out together in a second.
//!
//! A public RPC can neither trace nor simulate with logs, so a successful
//! call proves only what the Settler enforces itself: the recipient
//! receives at least `minAmountOut`. When the taker's balance or allowance is
//! short, the call would revert in `transferFrom`, so the quote is returned as
//! indicative with the shortfall named instead; the client re-quotes once the
//! approval lands.

use crate::abi::{self, tohex};
use crate::chain::NATIVE;
use crate::rpc::{CanonicalBlock, RevertData, Rpc, RpcRejected};
use crate::settler::BuiltTx;
use alloy::eips::BlockId;
use alloy::transports::TransportError;
use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolCall;
use anyhow::{Context, ensure};
use serde::Serialize;
use serde_json::{Value, json};

/// The transaction would revert even though the taker holds the input and
/// its allowance: the route no longer meets its minimum, or an action fails.
/// The quote is not offered; the caller should quote again.
#[derive(Debug)]
pub struct SimulationFailed {
    pub block: CanonicalBlock,
    pub revert: Option<Bytes>,
}

impl std::fmt::Display for SimulationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.revert.as_ref().filter(|data| data.len() >= 4) {
            Some(data) => write!(
                f,
                "the transaction reverts at block {} with selector {}",
                self.block.number,
                tohex(&data[..4])
            ),
            None => write!(f, "the transaction reverts at block {}", self.block.number),
        }
    }
}

impl std::error::Error for SimulationFailed {}

/// `Some` when a rejected call reverted, with the revert data if the node
/// returned any. Other rejections (an unknown block, a node limit) are not
/// the transaction's fault and stay upstream errors.
fn revert_of(error: &anyhow::Error) -> Option<Option<Bytes>> {
    error.downcast_ref::<RpcRejected>()?;
    if let Some(data) = error.downcast_ref::<RevertData>() {
        return Some(Some(data.0.clone()));
    }
    let payload = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<TransportError>())?
        .as_error_resp()?;
    (payload.code == 3 || payload.message.to_ascii_lowercase().contains("revert")).then_some(None)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Shortfall {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spender: Option<String>,
    pub required: String,
    pub available: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Issues {
    pub allowance: Option<Shortfall>,
    pub balance: Option<Shortfall>,
    /// The taker's native balance does not cover the transaction's value plus
    /// an estimate of its gas. Reported, never blocking: the wallet prices the
    /// transaction itself.
    pub network_fee: Option<Shortfall>,
}

/// What the taker approves before an ERC-20 sell: exactly the input amount,
/// to AllowanceHolder, and only when the current allowance is short.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub token: String,
    pub spender: String,
    pub amount: String,
    pub current: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Simulation {
    /// `simulated`: the exact transaction succeeded from the taker at
    /// `blockHash`. `skipped`: a prerequisite is missing (see `reason`).
    pub status: &'static str,
    pub reason: Option<&'static str>,
    pub block: u64,
    pub block_hash: String,
    pub gas_estimate: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub simulation: Simulation,
    pub issues: Issues,
    pub approval: Option<Approval>,
}

impl Report {
    pub fn simulated(&self) -> bool {
        self.simulation.status == "simulated"
    }
}

fn pinned(block: CanonicalBlock) -> Value {
    json!({"blockHash": format!("{:#x}", block.hash), "requireCanonical": true})
}

fn quantity(value: &Value) -> anyhow::Result<U256> {
    let text = value.as_str().context("RPC quantity must be a string")?;
    let digits = text
        .strip_prefix("0x")
        .context("RPC quantity is not hexadecimal")?;
    U256::from_str_radix(if digits.is_empty() { "0" } else { digits }, 16)
        .context("invalid RPC quantity")
}

fn call_object(from: Address, tx: &BuiltTx) -> Value {
    json!({
        "from": format!("{from:#x}"),
        "to": format!("{:#x}", tx.to),
        "value": format!("{:#x}", tx.value),
        "input": tohex(&tx.data),
    })
}

/// A genuine lower bound on a plain EOA transaction's gas: 21,000 plus
/// calldata at 4 gas per zero byte and 16 per other byte.
pub fn intrinsic_gas_floor(data: &[u8]) -> anyhow::Result<u64> {
    data.iter().try_fold(21_000u64, |gas, byte| {
        gas.checked_add(if *byte == 0 { 4 } else { 16 })
            .context("intrinsic gas overflow")
    })
}

async fn erc20_word(
    rpc: &Rpc,
    token: Address,
    call: Vec<u8>,
    block: CanonicalBlock,
) -> anyhow::Result<U256> {
    let result = rpc
        .eth_call(token, call, BlockId::hash_canonical(block.hash))
        .await?;
    ensure!(result.len() >= 32, "token read returned no word");
    Ok(U256::from_be_slice(&result[..32]))
}

/// The chain head to simulate at. A node behind the AMM snapshot (a lagging
/// load-balanced backend) must not move the check to older state, so the
/// snapshot's own block is the floor.
pub async fn simulation_block(
    rpc: &Rpc,
    snapshot: CanonicalBlock,
) -> anyhow::Result<CanonicalBlock> {
    let head = rpc.canonical_block(BlockId::latest()).await?;
    Ok(if head.number >= snapshot.number {
        head
    } else {
        snapshot
    })
}

/// Check one transaction the solver built for `from`, all at `block`.
#[allow(clippy::too_many_arguments)]
pub async fn verify(
    rpc: &Rpc,
    tx: &BuiltTx,
    from: Address,
    sell_token: Address,
    amount_in: U256,
    block: CanonicalBlock,
) -> anyhow::Result<Report> {
    let native_sell = sell_token == NATIVE;
    if native_sell {
        ensure!(
            tx.value == amount_in && tx.allowance_target.is_none(),
            "an ETH sell must carry its input as value"
        );
    }
    let spender = if native_sell {
        None
    } else {
        let spender = tx
            .allowance_target
            .context("an ERC-20 sell must name its allowance target")?;
        ensure!(
            tx.value.is_zero() && tx.to == spender,
            "an ERC-20 sell goes through AllowanceHolder with no value"
        );
        Some(spender)
    };
    let token_words = async {
        let Some(spender) = spender else {
            return Ok(None);
        };
        let (balance, allowance) = tokio::try_join!(
            erc20_word(
                rpc,
                sell_token,
                abi::balanceOfCall { owner: from }.abi_encode(),
                block
            ),
            erc20_word(
                rpc,
                sell_token,
                abi::allowanceCall {
                    owner: from,
                    spender,
                }
                .abi_encode(),
                block
            ),
        )?;
        anyhow::Ok(Some((spender, balance, allowance)))
    };
    let call = call_object(from, tx);
    // One round trip: the prerequisites and the transaction go out together.
    // Without its prerequisites the transaction reverts in `transferFrom`, so
    // its result is read only once they hold.
    let (eth_balance, token_words, called, estimated, gas_price) = tokio::join!(
        async {
            quantity(
                &rpc.request(
                    "eth_getBalance",
                    json!([format!("{from:#x}"), pinned(block)]),
                )
                .await?,
            )
        },
        token_words,
        rpc.request("eth_call", json!([call, pinned(block)])),
        rpc.request("eth_estimateGas", json!([call, pinned(block)])),
        rpc.request("eth_gasPrice", json!([])),
    );
    let (eth_balance, token_words) = (eth_balance?, token_words?);
    let mut issues = Issues::default();
    let mut approval = None;
    if native_sell {
        if eth_balance < amount_in {
            issues.balance = Some(Shortfall {
                token: abi::addrhex(NATIVE),
                spender: None,
                required: amount_in.to_string(),
                available: eth_balance.to_string(),
            });
        }
    } else {
        let (spender, balance, allowance) =
            token_words.context("an ERC-20 sell reads its balance and allowance")?;
        if balance < amount_in {
            issues.balance = Some(Shortfall {
                token: abi::addrhex(sell_token),
                spender: None,
                required: amount_in.to_string(),
                available: balance.to_string(),
            });
        }
        if allowance < amount_in {
            issues.allowance = Some(Shortfall {
                token: abi::addrhex(sell_token),
                spender: Some(abi::addrhex(spender)),
                required: amount_in.to_string(),
                available: allowance.to_string(),
            });
        }
        approval = Some(Approval {
            token: abi::addrhex(sell_token),
            spender: abi::addrhex(spender),
            amount: amount_in.to_string(),
            current: allowance.to_string(),
        });
    }

    let reason = if issues.balance.is_some() {
        Some("balance")
    } else if issues.allowance.is_some() {
        Some("allowance")
    } else {
        None
    };
    if reason.is_some() {
        return Ok(Report {
            simulation: Simulation {
                status: "skipped",
                reason,
                block: block.number,
                block_hash: format!("{:#x}", block.hash),
                gas_estimate: None,
            },
            issues,
            approval,
        });
    }

    for result in [&called, &estimated] {
        if let Err(error) = result
            && let Some(revert) = revert_of(error)
        {
            return Err(anyhow::Error::new(SimulationFailed { block, revert }));
        }
    }
    called?;
    let gas = quantity(&estimated?)?;
    ensure!(
        gas >= U256::from(intrinsic_gas_floor(&tx.data)?),
        "gas estimate is below the transaction's intrinsic gas"
    );
    let gas_price = quantity(&gas_price?)?;
    // A quarter more gas than estimated stands in for the wallet's own limit.
    let gas_limit = gas + gas / U256::from(4);
    let network_fee = gas_limit
        .checked_mul(gas_price)
        .context("network fee overflow")?;
    let required = tx
        .value
        .checked_add(network_fee)
        .context("network fee overflow")?;
    if eth_balance < required {
        issues.network_fee = Some(Shortfall {
            token: abi::addrhex(NATIVE),
            spender: None,
            required: required.to_string(),
            available: eth_balance.to_string(),
        });
    }
    Ok(Report {
        simulation: Simulation {
            status: "simulated",
            reason: None,
            block: block.number,
            block_hash: format!("{:#x}", block.hash),
            gas_estimate: Some(gas.to_string()),
        },
        issues,
        approval,
    })
}

/// A JSON-RPC chain for tests of the simulation reads.
#[cfg(any(test, feature = "testing"))]
pub mod test_chain {
    use crate::abi::tohex;
    use alloy_primitives::{Address, B256, U256};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// The chain a built transaction is checked against: the taker holds
    /// `balance` ETH and of every token, with `allowance` to any spender, and
    /// the Settler transaction succeeds unless `revert` is set or
    /// `revert_first` has not fired yet.
    #[derive(Clone)]
    pub struct SimulationChain {
        pub balance: U256,
        pub allowance: U256,
        pub revert: bool,
        pub revert_first: Option<Arc<RevertFirst>>,
        pub calls: Arc<Mutex<Vec<String>>>,
    }

    /// The first check of the transaction reverts and runs `then`, which a
    /// test uses to move its chain on, as a trade landing would.
    pub struct RevertFirst {
        fired: AtomicBool,
        then: Box<dyn Fn() + Send + Sync>,
    }

    impl RevertFirst {
        pub fn new(then: impl Fn() + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Self {
                fired: AtomicBool::new(false),
                then: Box::new(then),
            })
        }

        fn fire(&self) -> bool {
            let first = !self.fired.swap(true, Ordering::AcqRel);
            if first {
                (self.then)();
            }
            first
        }
    }

    impl SimulationChain {
        pub fn funded() -> Self {
            Self {
                balance: U256::from(10u64).pow(U256::from(30u64)),
                allowance: U256::MAX,
                revert: false,
                revert_first: None,
                calls: Default::default(),
            }
        }

        fn reverts(&self) -> bool {
            let first = self.revert_first.as_ref().is_some_and(|first| first.fire());
            self.revert || first
        }

        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    pub const SIMULATION_HEAD: u64 = 2;
    pub const TOO_MUCH_SLIPPAGE: [u8; 4] = [0x97, 0xa6, 0xf3, 0xb9];

    async fn simulation_chain_rpc(
        axum::extract::State(chain): axum::extract::State<SimulationChain>,
        axum::Json(request): axum::Json<serde_json::Value>,
    ) -> axum::Json<serde_json::Value> {
        let method = request["method"].as_str().unwrap().to_string();
        let word = |value: U256| serde_json::json!(tohex(&value.to_be_bytes::<32>()));
        let reverted = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {
                "code": 3,
                "message": "execution reverted",
                "data": tohex(&TOO_MUCH_SLIPPAGE),
            },
        });
        let result = match method.as_str() {
            "eth_getBlockByNumber" => serde_json::json!({
                "hash": B256::repeat_byte(0x44), "parentHash": B256::repeat_byte(0x33),
                "sha3Uncles": B256::ZERO, "miner": Address::ZERO, "stateRoot": B256::ZERO,
                "transactionsRoot": B256::ZERO, "receiptsRoot": B256::ZERO,
                "logsBloom": format!("0x{}", "00".repeat(256)), "difficulty": "0x0",
                "number": format!("{SIMULATION_HEAD:#x}"), "gasLimit": "0x7a1200",
                "gasUsed": "0x0", "timestamp": format!("{:#x}", 1_800_000_001u64),
                "extraData": "0x", "mixHash": B256::ZERO, "nonce": "0x0000000000000000",
                "transactions": [], "uncles": [],
            }),
            "eth_getBalance" => serde_json::json!(format!("{:#x}", chain.balance)),
            "eth_call" => {
                let call = &request["params"][0];
                let input = call
                    .get("input")
                    .or_else(|| call.get("data"))
                    .unwrap()
                    .as_str()
                    .unwrap();
                let data = crate::abi::hexbytes(input).unwrap();
                if data[..4] == <crate::abi::balanceOfCall as alloy_sol_types::SolCall>::SELECTOR {
                    word(chain.balance)
                } else if data[..4]
                    == <crate::abi::allowanceCall as alloy_sol_types::SolCall>::SELECTOR
                {
                    word(chain.allowance)
                } else if chain.reverts() {
                    chain.calls.lock().unwrap().push(method);
                    return axum::Json(reverted);
                } else {
                    serde_json::json!("0x")
                }
            }
            "eth_estimateGas" if chain.reverts() => {
                chain.calls.lock().unwrap().push(method);
                return axum::Json(reverted);
            }
            "eth_estimateGas" => serde_json::json!("0x30d40"),
            "eth_gasPrice" => serde_json::json!("0x186a0"),
            other => panic!("unexpected simulation RPC method {other}"),
        };
        chain.calls.lock().unwrap().push(method);
        axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
    }

    /// Serve `chain` on a local port. Call inside a Tokio runtime.
    pub fn simulation_chain(
        chain: SimulationChain,
    ) -> (crate::rpc::Rpc, tokio::task::JoinHandle<()>) {
        let app = axum::Router::new()
            .route("/", axum::routing::post(simulation_chain_rpc))
            .with_state(chain);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            crate::rpc::Rpc::connect(&format!("http://{address}")).unwrap(),
            server,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intrinsic_gas_counts_zero_and_other_bytes() {
        assert_eq!(intrinsic_gas_floor(&[]).unwrap(), 21_000);
        assert_eq!(
            intrinsic_gas_floor(&[0, 1, 0, 2]).unwrap(),
            21_000 + 4 + 16 + 4 + 16
        );
    }

    #[test]
    fn failed_simulation_names_the_revert_selector() {
        let failure = SimulationFailed {
            block: CanonicalBlock {
                number: 9,
                hash: Default::default(),
                timestamp: 0,
            },
            revert: Some(Bytes::from(vec![0x97, 0xa6, 0xf3, 0xb9, 0, 0])),
        };
        assert_eq!(
            failure.to_string(),
            "the transaction reverts at block 9 with selector 0x97a6f3b9"
        );
    }
}
