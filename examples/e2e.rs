// End-to-end execution test on an Anvil fork. Quotes come from the
// LIVE chain through the production path — topology probes + the
// lens snapshot (plus pinned Sheriff fee calls) — then each AMM case forks
// anvil at the quote block and executes the returned tx there. The fork is
// frozen at exactly the quoted state, so AMM output must match to the wei.
// Native v6 instead forks at the later canonical block where the firm quote's
// signer and nonce were checked: pAMM output is measured at execution and may
// differ from its quote-time reference. The Settler is balance-funded and
// sweeps pre-existing output-token dust into fee + recipient payouts, so that
// dust is measured and accounted separately in both modes.
//
// (The pre-lens harness quoted THROUGH the fork. The lens made that
// unworkable — its single eth_call walks ~1.5k storage slots, which a cold
// fork serves at one ~1s upstream fetch each — and quoting live + pinning the
// source-appropriate replay block is the more faithful test anyway: it
// exercises the exact deployment configuration.)
//
// The taker is a FRESH address funded via anvil_setBalance and driven
// through --auto-impersonate. Do NOT use anvil's well-known accounts on a
// mainnet fork: their public keys carry EIP-7702 sweeper delegations on the
// real chain, and any native ETH they receive is instantly drained by that
// code. WETH funding wraps real ETH (deposit), USDG funding writes the
// balances-mapping slot; both approve the AllowanceHolder — never the
// Settler — so the TRANSFER_FROM pull path runs end to end.

use alloy::eips::BlockId;
use alloy_primitives::{Address, B256, U256, address, keccak256};
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sextant::abi::{self, addrhex, hexbytes, read_word, tohex};
use sextant::chain::SLVR;
use sextant::chain::{
    ALLOWANCE_HOLDER, ChainProfile, FORK_SHERIFF, NATIVE, ROBINHOOD_PROFILE, UP, USDG, WETH,
    profile_by_key,
};
use sextant::config::Config;
use sextant::engine::Engine;
use sextant::pools::{V2Protocol, V3Protocol};
use sextant::quotes::{AmountIn, HopJson, QuoteRequest, QuoteResponse, net_after_fee, quote_swap};
use sextant::route::{
    ALLOC_CHUNKS, HopKind, Leg, MIN_SHARE_BPS, Plan, PreparedRoutes, hops_between, quantized_plan,
};
use sextant::rpc::{Rpc, sanitized_error};
use sextant::settler::{
    BPS_BASE, BuiltTx, build_swap_tx_for_profile, segments, settler_proportion,
};
use sextant::state::snapshot_at_for;
use sextant::v3math::muldiv;
use std::sync::Arc;

mod support;
use support::ManagedAnvil;

sol! {
    function deposit() external payable;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

const USER: Address = address!("1111111111111111111111111111111111111111");
const FEE_RECEIVER: Address = address!("00000000000000000000000000000000000000fe");
const POSITIVE_SLIPPAGE_RECIPIENT: Address = address!("00000000000000000000000000000000000000fd");
const ANVIL_PORT: u16 = 8546;
const PROTOCOL_MATRIX_BLOCK: u64 = 14_403_251;
const PROTOCOL_MATRIX_AMOUNT: u128 = 300_000_000_000_000_000_000;
const NEW_V3_MATRIX_BLOCK: u64 = 15_724_416;
const NEW_V3_MATRIX_AMOUNT: u128 = 300_000_000_000_000;
const NEW_V3_VIP_AMOUNT: u128 = 100_000_000_000_000;
const SHERIFF_BLOCK: u64 = 15_633_596;
const SHERIFF_AMOUNT: u128 = 1_000_000_000_000_000_000;
const UP33V2_MATRIX_BLOCK: u64 = 13_283_648;
const UP33V2_MATRIX_AMOUNT: u128 = 200_000_000_000_000_000_000_000;
const FAILED_FOT_BLOCK: u64 = 13_904_490;
const FAILED_FOT_AMOUNT: u128 = 646_158_417_719_747_830;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutableQuoteJson {
    chain_id: u64,
    liquidity_source: String,
    native_observation: Option<ExecutableCanonicalBlockJson>,
    block: u64,
    settler: String,
    token_in: String,
    token_out: String,
    amount_in: String,
    amount_out_gross: String,
    amount_out_net: String,
    min_amount_out_net: String,
    fee_bps: u32,
    tx_origin: String,
    route: Vec<ExecutableRouteLegJson>,
    tx: ExecutableTxJson,
    allowance_target: Option<String>,
    fee_receiver: Option<String>,
    positive_slippage: Option<ExecutablePositiveSlippageJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutableCanonicalBlockJson {
    number: u64,
    hash: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettlementExpectation {
    ExactAmm,
    // Applies to every transaction containing a Native-authorized stage,
    // including a whole-order Native RFQ and an AMM/Native mixed route.
    NativeRfq,
}

impl SettlementExpectation {
    fn is_native(self) -> bool {
        self == Self::NativeRfq
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplayTarget {
    block: u64,
    expected_hash: Option<B256>,
    settlement: SettlementExpectation,
}

#[derive(Clone, Copy, Debug)]
struct ReplayExecutionConfig<'a> {
    settlement: SettlementExpectation,
    registry_settler: Address,
    profile: &'a ChainProfile,
    fee_receiver: Address,
}

fn replay_target(
    liquidity_source: &str,
    amm_block: u64,
    native_observation: Option<(u64, &str)>,
) -> anyhow::Result<ReplayTarget> {
    match (liquidity_source, native_observation) {
        ("amm", None) => Ok(ReplayTarget {
            block: amm_block,
            expected_hash: None,
            settlement: SettlementExpectation::ExactAmm,
        }),
        ("amm", Some(_)) => bail!("AMM quote unexpectedly has a Native observation"),
        ("native_rfq", None) => bail!("Native RFQ quote has no canonical observation"),
        ("mixed", None) => bail!("mixed quote has no canonical Native observation"),
        ("native_rfq" | "mixed", Some((number, hash))) => {
            ensure!(
                number >= amm_block,
                "Native observation predates the AMM snapshot"
            );
            let hash = hash
                .parse::<B256>()
                .context("Native observation has an invalid block hash")?;
            ensure!(
                hash != B256::ZERO,
                "Native observation has a zero block hash"
            );
            Ok(ReplayTarget {
                block: number,
                expected_hash: Some(hash),
                settlement: SettlementExpectation::NativeRfq,
            })
        }
        (source, _) => bail!("unsupported executable quote liquidity source {source}"),
    }
}

fn settlement_payout_basis(
    label: &str,
    settlement: SettlementExpectation,
    actual_total: U256,
    gross_reference: U256,
    output_dust: U256,
) -> anyhow::Result<(U256, U256)> {
    let reference_total = gross_reference
        .checked_add(output_dust)
        .context("gross reference plus dust overflow")?;
    let settled_output = actual_total
        .checked_sub(output_dust)
        .context("payouts did not recover the measured output-token dust")?;
    let payout_basis = match settlement {
        SettlementExpectation::ExactAmm => {
            ensure!(
                actual_total == reference_total,
                "[{label}] AMM swap output plus measured dust != payouts"
            );
            reference_total
        }
        SettlementExpectation::NativeRfq => {
            ensure!(
                !settled_output.is_zero(),
                "[{label}] Native v6 settlement produced no output"
            );
            actual_total
        }
    };
    Ok((payout_basis, settled_output))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutablePositiveSlippageJson {
    recipient: String,
    token: String,
    expected_amount: String,
    max_bps: u32,
}

#[derive(Deserialize)]
struct ExecutableRouteLegJson {
    hops: Vec<ExecutableHopJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutableHopJson {
    protocol: String,
    token_in: String,
    fee_ppm: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutableTxJson {
    required_from: String,
    to: String,
    value: String,
    data: String,
}

#[derive(Clone, Copy, Debug)]
struct ArtifactReplayConfig {
    profile: &'static ChainProfile,
    fee_receiver: Address,
}

fn artifact_replay_config(
    chain: &str,
    fee_receiver: Option<&str>,
) -> anyhow::Result<ArtifactReplayConfig> {
    let profile = profile_by_key(chain)?;
    let configured = fee_receiver
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let fee_receiver = match configured {
        Some(value) => value
            .parse::<Address>()
            .context("SOLVER_FEE_RECEIVER is invalid")?,
        None => bail!(
            "SOLVER_FEE_RECEIVER is required for {} artifact replay",
            profile.key
        ),
    };
    ensure!(
        fee_receiver != Address::ZERO,
        "SOLVER_FEE_RECEIVER must not be zero"
    );
    ensure!(
        profile.execution_enabled(),
        "SOLVER_CHAIN={} has no execution adapter",
        profile.key
    );
    Ok(ArtifactReplayConfig {
        profile,
        fee_receiver,
    })
}

fn artifact_replay_config_from_env() -> anyhow::Result<ArtifactReplayConfig> {
    let chain = std::env::var("SOLVER_CHAIN")
        .context("SOLVER_CHAIN required for executable artifact replay")?;
    let fee_receiver = match std::env::var("SOLVER_FEE_RECEIVER") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(anyhow::anyhow!("reading SOLVER_FEE_RECEIVER: {error}")),
    };
    artifact_replay_config(&chain, fee_receiver.as_deref())
}

fn trusted_allowance_target(
    profile: &ChainProfile,
    token_in: Address,
    reported: Option<Address>,
    tx_to: Address,
) -> anyhow::Result<Option<Address>> {
    let adapter = profile
        .settler
        .context("selected profile has no execution adapter")?;
    if token_in == NATIVE {
        ensure!(
            reported.is_none(),
            "native executable quote unexpectedly has an allowance target"
        );
        return Ok(None);
    }
    ensure!(
        reported == Some(adapter.allowance_holder),
        "ERC20 executable quote has the wrong allowance target"
    );
    ensure!(
        tx_to == adapter.allowance_holder,
        "ERC20 executable quote does not call the reviewed AllowanceHolder"
    );
    Ok(Some(adapter.allowance_holder))
}

fn validate_artifact_chain(profile: &ChainProfile, chain_id: u64) -> anyhow::Result<()> {
    ensure!(
        chain_id == profile.chain_id,
        "executable quote chain id {chain_id} does not match SOLVER_CHAIN={} ({})",
        profile.key,
        profile.chain_id
    );
    Ok(())
}

fn validate_artifact_execution_binding(
    profile: &ChainProfile,
    token_in: Address,
    amount_in: U256,
    registry_settler: Address,
    tx: &BuiltTx,
) -> anyhow::Result<()> {
    let adapter = profile
        .settler
        .context("selected profile has no execution adapter")?;
    ensure!(
        tx.settler == registry_settler,
        "executable quote Settler does not match the registry owner"
    );

    if token_in == NATIVE {
        ensure!(
            tx.allowance_target.is_none(),
            "native executable quote unexpectedly has an allowance target"
        );
        ensure!(
            tx.value == amount_in,
            "native executable quote value does not match the quote input amount"
        );
        ensure!(
            tx.to == registry_settler,
            "native executable quote does not call the registry Settler"
        );
        return Ok(());
    }

    ensure!(
        tx.value.is_zero(),
        "ERC20 executable quote unexpectedly carries native value"
    );
    ensure!(
        tx.allowance_target == Some(adapter.allowance_holder),
        "ERC20 executable quote has the wrong allowance target"
    );
    ensure!(
        tx.to == adapter.allowance_holder,
        "ERC20 executable quote does not call the reviewed AllowanceHolder"
    );
    let exec = abi::execCall::abi_decode(&tx.data)
        .context("decoding executable quote AllowanceHolder.exec")?;
    ensure!(
        exec.operator == registry_settler,
        "AllowanceHolder.exec operator does not match the registry Settler"
    );
    ensure!(
        exec.target == registry_settler,
        "AllowanceHolder.exec target does not match the registry Settler"
    );
    ensure!(
        exec.token == token_in,
        "AllowanceHolder.exec token does not match the quote input token"
    );
    ensure!(
        exec.amount == amount_in,
        "AllowanceHolder.exec amount does not match the quote input amount"
    );
    Ok(())
}

fn pow10(n: u64) -> U256 {
    U256::from(10).pow(U256::from(n))
}

fn hexu(x: U256) -> String {
    format!("{x:#x}")
}

fn u256_of(v: &Value) -> anyhow::Result<U256> {
    let s = v.as_str().context("expected a hex string")?;
    U256::from_str_radix(s.trim_start_matches("0x"), 16).context("bad hex quantity")
}

struct Fork {
    rpc: Rpc,
    _anvil: ManagedAnvil,
}

impl Fork {
    async fn start(fork_url: &str, block: u64) -> anyhow::Result<Fork> {
        let anvil = ManagedAnvil::spawn(fork_url, block, ANVIL_PORT)?;
        let mut fork = Fork {
            rpc: Rpc::connect(&format!("http://127.0.0.1:{ANVIL_PORT}"))?,
            _anvil: anvil,
        };
        for _ in 0..600 {
            fork._anvil.ensure_running()?;
            if fork
                .rpc
                .block_number()
                .await
                .is_ok_and(|head| head == block)
            {
                return Ok(fork);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        fork.stop(); // a late-arriving anvil must not squat on the port
        bail!("anvil did not come up")
    }

    /// ManagedAnvil's Drop sends SIGINT and waits, including on every `?` path.
    fn stop(self) {
        drop(self);
    }

    async fn send_with_status(
        &self,
        from: Address,
        to: &str,
        value: U256,
        data: Vec<u8>,
        expected_status: &str,
    ) -> anyhow::Result<Value> {
        let txhash = self
            .rpc
            .request(
                "eth_sendTransaction",
                json!([{ "from": addrhex(from), "to": to, "value": hexu(value), "data": tohex(&data), "gas": "0x7a1200" }]),
            )
            .await?;
        // cold fork state: anvil fetches remote slots during execution — be patient
        for _ in 0..1200 {
            let receipt = self
                .rpc
                .request("eth_getTransactionReceipt", json!([txhash]))
                .await?;
            if !receipt.is_null() {
                ensure!(
                    receipt["status"] == expected_status,
                    "tx receipt status was {}, expected {expected_status}: {txhash}",
                    receipt["status"]
                );
                return Ok(receipt);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        bail!("no receipt for {txhash}")
    }

    async fn send(
        &self,
        from: Address,
        to: &str,
        value: U256,
        data: Vec<u8>,
    ) -> anyhow::Result<Value> {
        self.send_with_status(from, to, value, data, "0x1").await
    }

    async fn send_expect_revert(
        &self,
        from: Address,
        to: &str,
        value: U256,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.send_with_status(from, to, value, data, "0x0")
            .await
            .map(|_| ())
    }

    async fn balance_of(&self, token: Address, owner: Address) -> anyhow::Result<U256> {
        let ret = self
            .rpc
            .eth_call(
                token,
                balanceOfCall { owner }.abi_encode(),
                BlockId::latest(),
            )
            .await?;
        read_word(&ret, 0)
    }

    async fn eth_balance(&self, owner: Address) -> anyhow::Result<U256> {
        u256_of(
            &self
                .rpc
                .request("eth_getBalance", json!([addrhex(owner), "latest"]))
                .await?,
        )
    }

    /// Fund by writing the balances-mapping slot directly (USDG lives in
    /// slot 51; probed, not assumed).
    async fn set_erc20_balance(
        &self,
        token: Address,
        owner: Address,
        amount: U256,
    ) -> anyhow::Result<()> {
        let token_hex = addrhex(token);
        for slot in 0u64..=64 {
            let mut preimage = [0u8; 64];
            preimage[12..32].copy_from_slice(owner.as_slice());
            preimage[32..64].copy_from_slice(&B256::from(U256::from(slot)).0);
            let key = format!("{:#x}", keccak256(preimage));
            let old = self
                .rpc
                .request("eth_getStorageAt", json!([token_hex, key, "latest"]))
                .await?;
            self.rpc
                .request(
                    "anvil_setStorageAt",
                    json!([token_hex, key, format!("0x{:064x}", amount)]),
                )
                .await?;
            if self.balance_of(token, owner).await? == amount {
                return Ok(());
            }
            self.rpc
                .request("anvil_setStorageAt", json!([token_hex, key, old]))
                .await?;
        }
        bail!("no balances-mapping slot found for {token_hex}")
    }
}

async fn verify_replay_fork_block(fork: &Fork, target: ReplayTarget) -> anyhow::Result<()> {
    let canonical = fork
        .rpc
        .canonical_block(BlockId::number(target.block))
        .await
        .context("resolving the replay fork block")?;
    ensure!(
        canonical.number == target.block,
        "replay fork returned block {}, expected {}",
        canonical.number,
        target.block
    );
    if let Some(expected_hash) = target.expected_hash {
        ensure!(
            canonical.hash == expected_hash,
            "Native RFQ replay block hash does not match its canonical observation"
        );
    }
    Ok(())
}

async fn registry_settler_at_replay_block(
    fork: &Fork,
    profile: &ChainProfile,
    block: u64,
) -> anyhow::Result<Address> {
    fork.rpc
        .verify_chain_id(profile.chain_id, "replay fork")
        .await?;
    let adapter = profile
        .settler
        .context("selected profile has no execution adapter")?;
    let owner = fork
        .rpc
        .eth_call(
            adapter.registry,
            abi::ISettlerRegistry::ownerOfCall {
                id: U256::from(adapter.registry_token_id),
            }
            .abi_encode(),
            BlockId::number(block),
        )
        .await?;
    let settler = abi::ISettlerRegistry::ownerOfCall::abi_decode_returns(&owner)
        .context("decoding replay fork Settler registry owner")?;
    ensure!(
        settler != Address::ZERO,
        "replay fork Settler registry returned zero"
    );
    Ok(settler)
}

fn gas_cost(receipt: &Value) -> anyhow::Result<U256> {
    Ok(u256_of(&receipt["gasUsed"])? * u256_of(&receipt["effectiveGasPrice"])?)
}

fn settler_execute_data(tx: &BuiltTx) -> anyhow::Result<Vec<u8>> {
    Ok(if tx.allowance_target.is_some() {
        abi::execCall::abi_decode(&tx.data)?.data.to_vec()
    } else {
        tx.data.clone()
    })
}

fn validate_settlement_wrapper(
    tx: &BuiltTx,
    settlement: SettlementExpectation,
) -> anyhow::Result<()> {
    let execute_data = settler_execute_data(tx)?;
    let expected = match settlement {
        SettlementExpectation::ExactAmm => abi::executeCall::SELECTOR,
        SettlementExpectation::NativeRfq => abi::executeWithNativeAuthorizationCall::SELECTOR,
    };
    ensure!(
        execute_data.get(..4) == Some(expected.as_slice()),
        "liquidity source does not match the Settler execution wrapper"
    );
    Ok(())
}

fn settler_actions(tx: &BuiltTx) -> anyhow::Result<Vec<alloy_primitives::Bytes>> {
    let execute_data = settler_execute_data(tx)?;
    match execute_data.get(..4) {
        Some(selector) if selector == abi::executeCall::SELECTOR => {
            Ok(abi::executeCall::abi_decode(&execute_data)?.actions)
        }
        Some(selector) if selector == abi::executeWithNativeAuthorizationCall::SELECTOR => {
            Ok(abi::executeWithNativeAuthorizationCall::abi_decode(&execute_data)?.actions)
        }
        _ => bail!("transaction has an unsupported Settler execution selector"),
    }
}

fn uses_native_route_balance(tx: &BuiltTx, wrapped_native: Address) -> anyhow::Result<bool> {
    for action in &settler_actions(tx)? {
        if action.len() < 4 {
            continue;
        }
        if action[..4] == abi::UNISWAPV4Call::SELECTOR {
            if abi::UNISWAPV4Call::abi_decode(action)?.sellToken == NATIVE {
                return Ok(true);
            }
        } else if action[..4] == abi::BASICCall::SELECTOR {
            let basic = abi::BASICCall::abi_decode(action)?;
            if basic.sellToken == NATIVE && basic.pool == wrapped_native {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn positive_slippage_action(tx: &BuiltTx) -> anyhow::Result<Option<abi::POSITIVE_SLIPPAGECall>> {
    for action in settler_actions(tx)? {
        if action.starts_with(&abi::POSITIVE_SLIPPAGECall::SELECTOR) {
            return Ok(Some(abi::POSITIVE_SLIPPAGECall::abi_decode(&action)?));
        }
    }
    Ok(None)
}

fn profile_proportion(profile: &ChainProfile, bps: u32) -> anyhow::Result<U256> {
    let encoding = profile
        .settler
        .context("selected profile has no execution adapter")?
        .encoding;
    Ok(settler_proportion(encoding, bps))
}

fn hop_protocol(h: &HopJson) -> &'static str {
    match h {
        HopJson::NativeRfq { protocol, .. }
        | HopJson::V3 { protocol, .. }
        | HopJson::V2 { protocol, .. }
        | HopJson::Ekubo { protocol, .. } => protocol,
    }
}

fn hop_token_in(hop: &HopJson) -> &str {
    match hop {
        HopJson::NativeRfq { token_in, .. }
        | HopJson::V3 { token_in, .. }
        | HopJson::V2 { token_in, .. }
        | HopJson::Ekubo { token_in, .. } => token_in,
    }
}

fn path_v3(hop: &HopJson) -> bool {
    matches!(hop, HopJson::V3 { protocol, .. } if *protocol != "univ4")
}

fn balance_funded_sell_tokens(
    q: &QuoteResponse,
    token_in: Address,
) -> anyhow::Result<Vec<Address>> {
    if token_in != NATIVE && q.route.len() == 1 && q.route[0].hops.iter().all(path_v3) {
        return Ok(Vec::new());
    }
    let mut tokens = Vec::new();
    for leg in &q.route {
        for (i, hop) in leg.hops.iter().enumerate() {
            if i == 0 || !path_v3(hop) || !path_v3(&leg.hops[i - 1]) {
                tokens.push(hop_token_in(hop).parse()?);
            }
        }
    }
    Ok(tokens)
}

fn artifact_balance_funded_sell_tokens(
    q: &ExecutableQuoteJson,
    token_in: Address,
) -> anyhow::Result<Vec<Address>> {
    let path_v3 = |hop: &ExecutableHopJson| hop.fee_ppm.is_some() && hop.protocol != "univ4";
    if token_in != NATIVE && q.route.len() == 1 && q.route[0].hops.iter().all(&path_v3) {
        return Ok(Vec::new());
    }
    let mut tokens = Vec::new();
    for leg in &q.route {
        for (i, hop) in leg.hops.iter().enumerate() {
            if i == 0 || !path_v3(hop) || !path_v3(&leg.hops[i - 1]) {
                tokens.push(hop.token_in.parse()?);
            }
        }
    }
    Ok(tokens)
}

async fn run_case(
    cfg: &Config,
    engine: &Arc<Engine>,
    fork_url: &str,
    label: &str,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
) -> anyhow::Result<QuoteResponse> {
    // quote on the live chain — the production path, lens snapshot included
    let req = QuoteRequest {
        chain_id: cfg.profile.chain_id,
        token_in: addrhex(token_in),
        token_out: addrhex(token_out),
        amount_in: AmountIn::Str(amount_in.to_string()),
        slippage_bps: 50,
        recipient: Some(addrhex(USER)),
        sender: Some(addrhex(USER)),
        tx_origin: None,
        deadline_seconds: 600,
        fee_bps: None,
    };
    let q = quote_swap(cfg, engine, req).await?;
    let replay = replay_target(
        q.liquidity_source,
        q.block,
        q.native_observation
            .as_ref()
            .map(|observation| (observation.number, observation.hash.as_str())),
    )?;
    if replay.settlement.is_native() {
        ensure!(
            cfg.profile.native_supported(),
            "Native RFQ quote selected on a profile without a reviewed adapter"
        );
    }
    let legs: Vec<String> = q
        .route
        .iter()
        .map(|l| {
            let protos: Vec<&str> = l.hops.iter().map(hop_protocol).collect();
            format!(
                "{}bps×{}hop({})",
                l.share_bps,
                l.hops.len(),
                protos.join("→")
            )
        })
        .collect();
    println!(
        "[{label}] AMM block {} replay block {}   route: {}   gross reference={} net reference={}",
        q.block,
        replay.block,
        legs.join(" + "),
        q.amount_out_gross,
        q.amount_out_net
    );

    let fork = Fork::start(fork_url, replay.block).await?;
    let fee_receiver = cfg
        .fee_receiver
        .context("live E2E configuration has no fee receiver")?;
    let result = async {
        verify_replay_fork_block(&fork, replay).await?;
        let registry_settler =
            registry_settler_at_replay_block(&fork, cfg.profile, replay.block).await?;
        exec_on_fork(
            &fork,
            label,
            token_in,
            token_out,
            &q,
            ReplayExecutionConfig {
                settlement: replay.settlement,
                registry_settler,
                profile: cfg.profile,
                fee_receiver,
            },
        )
        .await
    }
    .await;
    fork.stop();
    result.map(|()| q)
}

async fn exec_on_fork(
    fork: &Fork,
    label: &str,
    token_in: Address,
    token_out: Address,
    q: &QuoteResponse,
    replay: ReplayExecutionConfig<'_>,
) -> anyhow::Result<()> {
    let ReplayExecutionConfig {
        settlement,
        registry_settler,
        profile,
        fee_receiver,
    } = replay;
    let amount_in: U256 = q.amount_in.parse()?;
    let gross: U256 = q.amount_out_gross.parse()?;
    let net: U256 = q.amount_out_net.parse()?;
    let minimum: U256 = q.min_amount_out_net.parse()?;
    let tx = q.tx.as_ref().context("quote built no tx")?;
    ensure!(
        tx.required_from.parse::<Address>()? == USER,
        "quote requiredFrom does not match the funded sender"
    );
    let balance_funded_sell_tokens = balance_funded_sell_tokens(q, token_in)?;
    let tx_to = tx.to.parse()?;
    let reported_allowance_target = q
        .allowance_target
        .as_ref()
        .and_then(|value| value.as_ref())
        .map(|value| value.parse())
        .transpose()?;
    let allowance_target =
        trusted_allowance_target(profile, token_in, reported_allowance_target, tx_to)?;
    let built_tx = BuiltTx {
        to: tx_to,
        value: tx.value.parse()?,
        data: hexbytes(&tx.data)?,
        allowance_target,
        settler: q
            .settler
            .as_deref()
            .context("executable quote has no Settler identity")?
            .parse()?,
    };
    validate_artifact_execution_binding(profile, token_in, amount_in, registry_settler, &built_tx)?;
    let encoded_positive_slippage = positive_slippage_action(&built_tx)?;
    match (&q.positive_slippage, encoded_positive_slippage) {
        (None, None) => {}
        (Some(response), Some(action)) => {
            ensure!(
                action.recipient == response.recipient.parse::<Address>()?
                    && action.token == response.token.parse::<Address>()?
                    && action.expectedAmount == response.expected_amount.parse::<U256>()?
                    && action.maxPpm == profile_proportion(profile, response.max_bps)?,
                "positive slippage response does not match calldata"
            );
        }
        _ => bail!("positive slippage response/action mismatch"),
    }
    execute_built_on_fork(
        fork,
        label,
        token_in,
        token_out,
        amount_in,
        gross,
        net,
        minimum,
        q.fee_bps,
        &balance_funded_sell_tokens,
        &built_tx,
        settlement,
        profile,
        fee_receiver,
    )
    .await
}

async fn run_artifact_quote(
    fork_url: &str,
    quote_path: &str,
    replay: ArtifactReplayConfig,
) -> anyhow::Result<()> {
    let body = std::fs::read(quote_path)
        .with_context(|| format!("reading executable quote JSON from {quote_path}"))?;
    let q: ExecutableQuoteJson =
        serde_json::from_slice(&body).context("parsing executable quote JSON")?;
    validate_artifact_chain(replay.profile, q.chain_id)?;
    let replay_target = replay_target(
        &q.liquidity_source,
        q.block,
        q.native_observation
            .as_ref()
            .map(|observation| (observation.number, observation.hash.as_str())),
    )?;
    let verify_native_replay = replay_target.settlement.is_native();
    if verify_native_replay {
        ensure!(
            replay.profile.native_supported(),
            "Native RFQ artifact selected on a profile without a reviewed adapter"
        );
    }
    let token_in: Address = q.token_in.parse()?;
    let token_out: Address = q.token_out.parse()?;
    let amount_in: U256 = q.amount_in.parse()?;
    let gross: U256 = q.amount_out_gross.parse()?;
    let net: U256 = q.amount_out_net.parse()?;
    let minimum: U256 = q.min_amount_out_net.parse()?;
    ensure!(
        net == net_after_fee(gross, q.fee_bps)?,
        "executable quote net amount does not match its fee"
    );
    let fee_receiver: Address = q
        .fee_receiver
        .as_deref()
        .context("executable quote has no fee receiver")?
        .parse()?;
    ensure!(
        fee_receiver == replay.fee_receiver,
        "executable quote has the wrong fee receiver"
    );
    let reported_allowance_target = q.allowance_target.as_deref().map(str::parse).transpose()?;
    let balance_funded_sell_tokens = artifact_balance_funded_sell_tokens(&q, token_in)?;
    let tx_to = q.tx.to.parse()?;
    let allowance_target =
        trusted_allowance_target(replay.profile, token_in, reported_allowance_target, tx_to)?;
    let tx = BuiltTx {
        to: tx_to,
        value: q.tx.value.parse()?,
        data: hexbytes(&q.tx.data)?,
        allowance_target,
        settler: q.settler.parse()?,
    };
    ensure!(
        q.tx.required_from.parse::<Address>()? == USER,
        "executable quote requiredFrom does not match the funded sender"
    );
    ensure!(
        q.tx_origin.parse::<Address>()? == USER,
        "executable quote txOrigin does not match the fork transaction origin"
    );
    let encoded_positive_slippage = positive_slippage_action(&tx)?;
    match (&q.positive_slippage, encoded_positive_slippage) {
        (None, None) => {}
        (Some(response), Some(action)) => {
            ensure!(
                action.recipient == response.recipient.parse::<Address>()?
                    && action.token == response.token.parse::<Address>()?
                    && action.expectedAmount == response.expected_amount.parse::<U256>()?
                    && action.maxPpm == profile_proportion(replay.profile, response.max_bps)?,
                "positive slippage response does not match calldata"
            );
        }
        _ => bail!("positive slippage response/action mismatch"),
    }
    ensure!(
        tx.value
            == if token_in == NATIVE {
                amount_in
            } else {
                U256::ZERO
            },
        "executable quote has the wrong transaction value"
    );

    println!(
        "[artifact HTTP quote] AMM block {} replay block {} gross reference={gross} net reference={net}",
        q.block, replay_target.block
    );
    let fork = Fork::start(fork_url, replay_target.block).await?;
    let result = async {
        verify_replay_fork_block(&fork, replay_target).await?;
        let registry_settler =
            registry_settler_at_replay_block(&fork, replay.profile, replay_target.block).await?;
        validate_artifact_execution_binding(
            replay.profile,
            token_in,
            amount_in,
            registry_settler,
            &tx,
        )?;
        execute_built_on_fork(
            &fork,
            "artifact HTTP quote",
            token_in,
            token_out,
            amount_in,
            gross,
            net,
            minimum,
            q.fee_bps,
            &balance_funded_sell_tokens,
            &tx,
            replay_target.settlement,
            replay.profile,
            replay.fee_receiver,
        )
        .await?;
        if verify_native_replay {
            verify_native_replay_rejected(
                &fork,
                token_in,
                token_out,
                amount_in,
                &tx,
                replay.profile,
            )
            .await?;
        }
        Ok(())
    }
    .await;
    fork.stop();
    result
}

async fn token_balance_matrix(
    fork: &Fork,
    token_in: Address,
    token_out: Address,
    owners: &[Address],
) -> anyhow::Result<Vec<(U256, U256)>> {
    let mut balances = Vec::with_capacity(owners.len());
    for &owner in owners {
        balances.push((
            fork.balance_of(token_in, owner).await?,
            fork.balance_of(token_out, owner).await?,
        ));
    }
    Ok(balances)
}

/// Prove that the Native quote's on-chain nonce is consumed. The taker input
/// is replenished first, so an otherwise replayable transaction cannot appear
/// safe merely because its first execution emptied the taker balance.
async fn verify_native_replay_rejected(
    fork: &Fork,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    tx: &BuiltTx,
    profile: &ChainProfile,
) -> anyhow::Result<()> {
    ensure!(
        token_in != NATIVE && token_out != NATIVE,
        "Native RFQ replay gate supports ERC20 pairs only"
    );
    let native = profile
        .native_rfq
        .context("selected profile has no Native RFQ adapter")?;

    fork.set_erc20_balance(token_in, USER, amount_in).await?;
    let owners = [USER, tx.settler, native.router, native.pool];
    let before = token_balance_matrix(fork, token_in, token_out, &owners).await?;

    fork.send_expect_revert(USER, &addrhex(tx.to), tx.value, tx.data.clone())
        .await
        .context("exact Native RFQ calldata replay unexpectedly succeeded")?;

    let after = token_balance_matrix(fork, token_in, token_out, &owners).await?;
    ensure!(
        after == before,
        "reverted Native RFQ replay changed a user, Settler, Router, or Pool token balance"
    );
    println!("[artifact HTTP quote] exact Native calldata replay rejected with balances unchanged");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn execute_built_on_fork(
    fork: &Fork,
    label: &str,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    gross: U256,
    net: U256,
    minimum: U256,
    fee_bps: u32,
    balance_funded_sell_tokens: &[Address],
    tx: &BuiltTx,
    settlement: SettlementExpectation,
    profile: &ChainProfile,
    fee_receiver: Address,
) -> anyhow::Result<()> {
    validate_settlement_wrapper(tx, settlement)?;
    if settlement.is_native() {
        ensure!(
            profile.native_supported(),
            "[{label}] Native RFQ settlement has no reviewed profile adapter"
        );
        ensure!(
            token_in != NATIVE && token_out != NATIVE,
            "[{label}] Native RFQ settlement supports ERC20 pairs only"
        );
        ensure!(
            token_in != token_out,
            "[{label}] Native RFQ settlement requires distinct tokens"
        );
    }
    let allowance_holder = profile
        .settler
        .context("selected profile has no execution adapter")?
        .allowance_holder;
    let expected_allowance_target = (token_in != NATIVE).then_some(allowance_holder);
    ensure!(
        tx.allowance_target == expected_allowance_target,
        "[{label}] transaction allowance target is not the reviewed profile target"
    );
    if expected_allowance_target.is_some() {
        ensure!(
            tx.to == allowance_holder,
            "[{label}] ERC20 transaction does not call the reviewed AllowanceHolder"
        );
    } else {
        ensure!(
            tx.to == tx.settler,
            "[{label}] native transaction does not call its reported Settler"
        );
    }
    fork.rpc
        .request(
            "anvil_setBalance",
            json!([addrhex(USER), hexu(U256::from(10_000) * pow10(18))]),
        )
        .await?;
    if token_in == profile.wrapped_native {
        fork.send(
            USER,
            &addrhex(profile.wrapped_native),
            amount_in,
            depositCall {}.abi_encode(),
        )
        .await?;
    } else if token_in != NATIVE {
        fork.set_erc20_balance(token_in, USER, amount_in).await?;
    }
    if token_in != NATIVE {
        fork.send(
            USER,
            &addrhex(token_in),
            U256::ZERO,
            approveCall {
                spender: allowance_holder,
                amount: U256::MAX,
            }
            .abi_encode(),
        )
        .await?;
    }

    let native_out = token_out == NATIVE;
    let positive_slippage = positive_slippage_action(tx)?;
    if let Some(action) = &positive_slippage {
        ensure!(
            action.token == if native_out { NATIVE } else { token_out },
            "[{label}] positive slippage token does not match output"
        );
        ensure!(
            action.recipient != USER && action.recipient != fee_receiver,
            "[{label}] positive slippage recipient aliases another measured payout"
        );
    }
    if uses_native_route_balance(tx, profile.wrapped_native)? {
        ensure!(
            fork.eth_balance(tx.settler).await?.is_zero(),
            "[{label}] Settler has native route-input dust; exact parity is undefined"
        );
    }
    let mut checked_sell_tokens = Vec::new();
    for &token in balance_funded_sell_tokens {
        if checked_sell_tokens.contains(&token) {
            continue;
        }
        checked_sell_tokens.push(token);
        ensure!(
            fork.balance_of(token, tx.settler).await?.is_zero(),
            "[{label}] Settler has input/intermediate dust in {token:#x}; exact parity is undefined"
        );
    }
    if positive_slippage.is_some() && !native_out {
        // Force a known improvement over the production expectedAmount so the
        // fork test proves the transfer, cap, and final payout rather than only
        // the no-surplus branch.
        fork.set_erc20_balance(token_out, tx.settler, U256::from(1_000_000))
            .await?;
    }
    let output_dust = if native_out {
        fork.eth_balance(tx.settler)
            .await?
            .checked_add(fork.balance_of(profile.wrapped_native, tx.settler).await?)
            .context("terminal dust overflow")?
    } else {
        fork.balance_of(token_out, tx.settler).await?
    };
    let native_input_before = if settlement.is_native() {
        Some(fork.balance_of(token_in, USER).await?)
    } else {
        None
    };
    let user_before = if native_out {
        fork.eth_balance(USER).await?
    } else {
        fork.balance_of(token_out, USER).await?
    };
    let fee_before = if native_out {
        fork.eth_balance(fee_receiver).await?
    } else {
        fork.balance_of(token_out, fee_receiver).await?
    };
    let positive_before = match &positive_slippage {
        Some(action) if native_out => fork.eth_balance(action.recipient).await?,
        Some(action) => fork.balance_of(token_out, action.recipient).await?,
        None => U256::ZERO,
    };

    let tx_request = json!([{
        "from": addrhex(USER),
        "to": addrhex(tx.to),
        "value": hexu(tx.value),
        "data": tohex(&tx.data),
    }]);
    let estimate = fork.rpc.request("eth_estimateGas", tx_request).await?;
    println!(
        "[{label}] preflight gas={}",
        estimate.as_str().unwrap_or("?")
    );
    let receipt = fork
        .send(USER, &addrhex(tx.to), tx.value, tx.data.clone())
        .await?;

    if let Some(input_before) = native_input_before {
        let input_after = fork.balance_of(token_in, USER).await?;
        ensure!(
            input_before.checked_sub(input_after) == Some(amount_in),
            "[{label}] Native v6 settlement did not consume the quoted input"
        );
    }

    let user_after = if native_out {
        fork.eth_balance(USER).await?
    } else {
        fork.balance_of(token_out, USER).await?
    };
    let mut user_delta = user_after - user_before;
    if native_out {
        user_delta += gas_cost(&receipt)?;
    }
    let fee_after = if native_out {
        fork.eth_balance(fee_receiver).await?
    } else {
        fork.balance_of(token_out, fee_receiver).await?
    };
    let fee_delta = fee_after - fee_before;
    let positive_delta = match &positive_slippage {
        Some(action) if native_out => fork.eth_balance(action.recipient).await? - positive_before,
        Some(action) => fork.balance_of(token_out, action.recipient).await? - positive_before,
        None => U256::ZERO,
    };

    let actual_total = user_delta
        .checked_add(fee_delta)
        .and_then(|total| total.checked_add(positive_delta))
        .context("payout overflow")?;
    let (payout_basis, settled_output) =
        settlement_payout_basis(label, settlement, actual_total, gross, output_dust)?;
    let balance_after_fee = net_after_fee(payout_basis, fee_bps)?;
    let expected_fee = payout_basis - balance_after_fee;
    let expected_positive = match &positive_slippage {
        Some(action) if balance_after_fee > action.expectedAmount => {
            let surplus = balance_after_fee - action.expectedAmount;
            let cap = muldiv(
                balance_after_fee,
                action.maxPpm,
                profile_proportion(profile, BPS_BASE)?,
            )?;
            surplus.min(cap)
        }
        _ => U256::ZERO,
    };
    let expected_user = balance_after_fee - expected_positive;
    println!(
        "[{label}] received={user_delta} (net reference {net})   fee={fee_delta} (reference {})   positive={positive_delta}   settled_output={settled_output} (gross reference {gross})   output_dust={output_dust}",
        gross - net
    );
    ensure!(
        user_delta >= minimum,
        "[{label}] user delta below encoded minimum"
    );
    ensure!(
        user_delta == expected_user,
        "[{label}] recipient payout != actual dust-adjusted settlement"
    );
    ensure!(
        fee_delta == expected_fee,
        "[{label}] fee payout != actual dust-adjusted settlement"
    );
    ensure!(
        positive_delta == expected_positive,
        "[{label}] positive slippage payout != Settler formula"
    );
    Ok(())
}

struct PinnedCase<'a> {
    label: &'static str,
    block: u64,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    required_v3: &'a [V3Protocol],
    required_v2: &'a [V2Protocol],
    forced_v3: &'a [V3Protocol],
}

async fn run_pinned_case(
    cfg: &Config,
    rpc: &Rpc,
    fork_url: &str,
    case: PinnedCase<'_>,
) -> anyhow::Result<()> {
    let snap = snapshot_at_for(
        &ROBINHOOD_PROFILE,
        rpc,
        None,
        case.token_in,
        case.token_out,
        Some(case.block),
    )
    .await?;
    let seed = if case.forced_v3.is_empty() {
        PreparedRoutes::for_profile(&snap, &ROBINHOOD_PROFILE, case.token_in, case.token_out)?
            .solve(case.amount_in, *ALLOC_CHUNKS, *MIN_SHARE_BPS)?
    } else {
        let share = case.amount_in / U256::from(case.forced_v3.len());
        let mut remaining = case.amount_in;
        let mut legs = Vec::new();
        for (i, &protocol) in case.forced_v3.iter().enumerate() {
            let hop = hops_between(&snap, case.token_in, case.token_out)
                .into_iter()
                .find(|hop| hop.kind == HopKind::V3 && snap.v3[hop.index].0.protocol == protocol)
                .with_context(|| {
                    format!("{} has no direct {} pool", case.label, protocol.as_str())
                })?;
            let amount_in = if i + 1 == case.forced_v3.len() {
                remaining
            } else {
                share
            };
            remaining -= amount_in;
            legs.push(Leg {
                path: vec![hop],
                amount_in,
                amount_out: U256::ZERO,
                losses: Vec::new(),
                slice_bps: 0,
            });
        }
        Plan {
            legs,
            amount_out: U256::ZERO,
            universe_id: None,
        }
    };
    let plan = quantized_plan(&snap, &seed, case.amount_in)?;
    let mut v3_protocols = Vec::new();
    let mut v2_protocols = Vec::new();
    for hop in plan.legs.iter().flat_map(|leg| &leg.path) {
        match hop.kind {
            HopKind::V3 => {
                let protocol = snap.v3[hop.index].0.protocol;
                if !v3_protocols.contains(&protocol) {
                    v3_protocols.push(protocol);
                }
            }
            HopKind::V2 => {
                let protocol = snap.v2[hop.index].0.protocol;
                if !v2_protocols.contains(&protocol) {
                    v2_protocols.push(protocol);
                }
            }
            HopKind::Ekubo => {}
        }
    }
    for required in case.required_v3 {
        ensure!(
            v3_protocols.contains(required),
            "[{}] no longer exercises {}",
            case.label,
            required.as_str()
        );
    }
    for required in case.required_v2 {
        ensure!(
            v2_protocols.contains(required),
            "[{}] no longer exercises {}",
            case.label,
            required.as_str()
        );
    }

    let gross = plan.amount_out;
    let gross_min = muldiv(gross, U256::from(BPS_BASE - 50), U256::from(BPS_BASE))?;
    let net = net_after_fee(gross, cfg.fee_bps)?;
    let minimum = net_after_fee(gross_min, cfg.fee_bps)?;
    let tx = build_swap_tx_for_profile(
        &ROBINHOOD_PROFILE,
        cfg.fee_bps,
        cfg.fee_receiver,
        None,
        &snap,
        &plan,
        case.token_in,
        case.token_out,
        case.amount_in,
        minimum,
        USER,
        u64::MAX,
    )?;
    if case.forced_v3.len() == 1 {
        let holder = abi::execCall::abi_decode(&tx.data)?;
        let execute = abi::executeCall::abi_decode(&holder.data)?;
        let action = execute
            .actions
            .first()
            .with_context(|| format!("{} built no action", case.label))?;
        ensure!(
            action.starts_with(&abi::UNISWAPV3_VIPCall::SELECTOR),
            "[{}] single V3 route did not use UNISWAPV3_VIP",
            case.label
        );
        let vip = abi::UNISWAPV3_VIPCall::abi_decode(action)?;
        let hop = plan
            .legs
            .first()
            .and_then(|leg| leg.path.first())
            .with_context(|| format!("{} has no encoded hop", case.label))?;
        let expected_fork = snap.v3[hop.index]
            .0
            .execution
            .context("selected V3 hop has no execution metadata")?
            .fork_id;
        ensure!(
            vip.path.get(20).copied() == Some(expected_fork),
            "[{}] VIP path encoded fork {:?}, expected {expected_fork}",
            case.label,
            vip.path.get(20)
        );
    }
    let mut balance_funded_sell_tokens = Vec::new();
    for leg in &plan.legs {
        balance_funded_sell_tokens.extend(
            segments(&snap, &leg.path)?
                .into_iter()
                .map(|segment| segment[0].token_in),
        );
    }

    let protocols: Vec<&str> = v3_protocols
        .iter()
        .map(|protocol| protocol.as_str())
        .chain(v2_protocols.iter().map(|protocol| protocol.as_str()))
        .collect();
    println!(
        "[{}] block {} protocols={} gross={gross} net={net}",
        case.label,
        snap.block,
        protocols.join(",")
    );
    let fee_receiver = cfg
        .fee_receiver
        .context("live E2E configuration has no fee receiver")?;
    let fork = Fork::start(fork_url, snap.block).await?;
    let result = execute_built_on_fork(
        &fork,
        case.label,
        case.token_in,
        case.token_out,
        case.amount_in,
        gross,
        net,
        minimum,
        cfg.fee_bps,
        &balance_funded_sell_tokens,
        &tx,
        SettlementExpectation::ExactAmm,
        cfg.profile,
        fee_receiver,
    )
    .await;
    fork.stop();
    result
}

async fn run_new_v3_matrix(cfg: &Config, rpc: &Rpc, fork_url: &str) -> anyhow::Result<()> {
    run_pinned_case(
        cfg,
        rpc,
        fork_url,
        PinnedCase {
            label: "pinned new v3 matrix",
            block: NEW_V3_MATRIX_BLOCK,
            token_in: WETH,
            token_out: USDG,
            amount_in: U256::from(NEW_V3_MATRIX_AMOUNT),
            required_v3: &[
                V3Protocol::GIGADEXV3,
                V3Protocol::SUSHIV3,
                V3Protocol::ROBINSWAPV3,
            ],
            required_v2: &[],
            forced_v3: &[
                V3Protocol::GIGADEXV3,
                V3Protocol::SUSHIV3,
                V3Protocol::ROBINSWAPV3,
            ],
        },
    )
    .await
}

async fn run_new_v3_vip_cases(cfg: &Config, rpc: &Rpc, fork_url: &str) -> anyhow::Result<()> {
    for protocol in [
        V3Protocol::GIGADEXV3,
        V3Protocol::SUSHIV3,
        V3Protocol::ROBINSWAPV3,
    ] {
        let only = [protocol];
        run_pinned_case(
            cfg,
            rpc,
            fork_url,
            PinnedCase {
                label: protocol.as_str(),
                block: NEW_V3_MATRIX_BLOCK,
                token_in: WETH,
                token_out: USDG,
                amount_in: U256::from(NEW_V3_VIP_AMOUNT),
                required_v3: &only,
                required_v2: &[],
                forced_v3: &only,
            },
        )
        .await?;
    }
    Ok(())
}

async fn run_pinned_sheriff(cfg: &Config, rpc: &Rpc, fork_url: &str) -> anyhow::Result<()> {
    let snap = snapshot_at_for(
        &ROBINHOOD_PROFILE,
        rpc,
        None,
        WETH,
        USDG,
        Some(SHERIFF_BLOCK),
    )
    .await?;
    let amount_in = U256::from(SHERIFF_AMOUNT);
    let hop = hops_between(&snap, WETH, USDG)
        .into_iter()
        .find(|hop| hop.kind == HopKind::V3 && snap.v3[hop.index].0.protocol == V3Protocol::SHERIFF)
        .context("pinned snapshot has no executable Sheriff pool")?;
    let pool = &snap.v3[hop.index].0;
    ensure!(
        pool.execution.is_some_and(|execution| {
            execution.fork_id == FORK_SHERIFF && execution.pool_id == 0
        }) && pool.algebra.is_some(),
        "pinned Sheriff pool metadata is incomplete"
    );

    // Seed only the chosen path; quantized_plan re-simulates it through the
    // production transfer + V3 model without letting another venue win.
    let plan = quantized_plan(
        &snap,
        &Plan {
            legs: vec![Leg {
                path: vec![hop],
                amount_in,
                amount_out: U256::ZERO,
                losses: Vec::new(),
                slice_bps: 0,
            }],
            amount_out: U256::ZERO,
            universe_id: None,
        },
        amount_in,
    )?;
    let gross = plan.amount_out;
    let net = net_after_fee(gross, cfg.fee_bps)?;
    let tx = build_swap_tx_for_profile(
        &ROBINHOOD_PROFILE,
        cfg.fee_bps,
        cfg.fee_receiver,
        None,
        &snap,
        &plan,
        WETH,
        USDG,
        amount_in,
        net,
        USER,
        u64::MAX,
    )?;
    let holder = abi::execCall::abi_decode(&tx.data)?;
    let execute = abi::executeCall::abi_decode(&holder.data)?;
    let vip = abi::UNISWAPV3_VIPCall::abi_decode(
        execute
            .actions
            .first()
            .context("Sheriff plan built no action")?,
    )?;
    ensure!(
        vip.path.get(20).copied() == Some(FORK_SHERIFF),
        "Sheriff VIP path did not encode fork {FORK_SHERIFF}"
    );

    println!(
        "[pinned Sheriff] block {} fork={} gross={gross} net={net}",
        snap.block, FORK_SHERIFF
    );
    let fee_receiver = cfg
        .fee_receiver
        .context("live E2E configuration has no fee receiver")?;
    let fork = Fork::start(fork_url, snap.block).await?;
    let result = execute_built_on_fork(
        &fork,
        "pinned Sheriff",
        WETH,
        USDG,
        amount_in,
        gross,
        net,
        net,
        cfg.fee_bps,
        &[],
        &tx,
        SettlementExpectation::ExactAmm,
        cfg.profile,
        fee_receiver,
    )
    .await;
    fork.stop();
    result
}

/// The solver deliberately does not model transfer taxes. This regression
/// proves the uniform design on the original SLVR failure block: the quote is
/// plain pool math, every V2 action measures the pool's actual credited input
/// (sellTokenHasFee always set), execution SUCCEEDS despite the unmodeled
/// sell tax, and delivery lands inside [minimum, net] once the user's
/// slippage budget covers the token's tax.
async fn run_pinned_fot_regression(cfg: &Config, rpc: &Rpc, fork_url: &str) -> anyhow::Result<()> {
    let snap = snapshot_at_for(
        &ROBINHOOD_PROFILE,
        rpc,
        None,
        SLVR,
        WETH,
        Some(FAILED_FOT_BLOCK),
    )
    .await?;
    let amount_in = U256::from(FAILED_FOT_AMOUNT);
    let plan = quantized_plan(
        &snap,
        &PreparedRoutes::for_profile(&snap, &ROBINHOOD_PROFILE, SLVR, WETH)?.solve(
            amount_in,
            *ALLOC_CHUNKS,
            *MIN_SHARE_BPS,
        )?,
        amount_in,
    )?;
    ensure!(
        plan.legs.iter().any(|leg| leg
            .path
            .iter()
            .any(|hop| hop.kind == sextant::route::HopKind::V2)),
        "pinned regression no longer exercises V2"
    );
    let gross = plan.amount_out;
    // 500 bps of user slippage absorbs SLVR's 2% sell tax at this block.
    let gross_min = muldiv(gross, U256::from(BPS_BASE - 500), U256::from(BPS_BASE))?;
    let net = net_after_fee(gross, cfg.fee_bps)?;
    let minimum = net_after_fee(gross_min, cfg.fee_bps)?;
    let tx = build_swap_tx_for_profile(
        &ROBINHOOD_PROFILE,
        cfg.fee_bps,
        cfg.fee_receiver,
        None,
        &snap,
        &plan,
        SLVR,
        WETH,
        amount_in,
        minimum,
        USER,
        u64::MAX,
    )?;
    let holder = abi::execCall::abi_decode(&tx.data)?;
    let execute = abi::executeCall::abi_decode(&holder.data)?;
    let v2_actions: Vec<_> = execute
        .actions
        .iter()
        .filter_map(|action| {
            (action[..4] == abi::UNISWAPV2Call::SELECTOR)
                .then(|| abi::UNISWAPV2Call::abi_decode(action).ok())
                .flatten()
        })
        .collect();
    ensure!(
        !v2_actions.is_empty(),
        "pinned regression built no V2 action"
    );
    ensure!(
        v2_actions
            .iter()
            .all(|action| action.swapInfo.to::<u32>() & 2 != 0),
        "a V2 action did not set the universal measured-input bit"
    );

    println!(
        "[SLVR regression] pinned block {} gross={gross} net={net} minimum={minimum}",
        snap.block
    );
    let fork = Fork::start(fork_url, snap.block).await?;
    let result = execute_fot_on_fork(&fork, amount_in, net, minimum, &tx).await;
    fork.stop();
    result
}

/// Tolerant fork execution for an unmodeled fee-on-transfer input: asserts
/// success and bounded delivery instead of wei-exact parity.
async fn execute_fot_on_fork(
    fork: &Fork,
    amount_in: U256,
    net: U256,
    minimum: U256,
    tx: &BuiltTx,
) -> anyhow::Result<()> {
    fork.rpc
        .request(
            "anvil_setBalance",
            json!([addrhex(USER), hexu(U256::from(10_000) * pow10(18))]),
        )
        .await?;
    fork.set_erc20_balance(SLVR, USER, amount_in).await?;
    fork.send(
        USER,
        &addrhex(SLVR),
        U256::ZERO,
        approveCall {
            spender: ALLOWANCE_HOLDER,
            amount: U256::MAX,
        }
        .abi_encode(),
    )
    .await?;
    let before = fork.balance_of(WETH, USER).await?;
    let estimate = fork
        .rpc
        .request(
            "eth_estimateGas",
            json!([{
                "from": addrhex(USER),
                "to": addrhex(tx.to),
                "value": hexu(tx.value),
                "data": tohex(&tx.data),
            }]),
        )
        .await?;
    println!(
        "[SLVR regression] preflight gas={}",
        estimate.as_str().unwrap_or("?")
    );
    fork.send(USER, &addrhex(tx.to), tx.value, tx.data.clone())
        .await?;
    let received = fork.balance_of(WETH, USER).await? - before;
    println!("[SLVR regression] received={received} (quoted net {net}, minimum {minimum})");
    ensure!(
        received >= minimum,
        "delivery fell below the encoded minimum"
    );
    ensure!(
        received <= net,
        "delivery exceeded the tax-free quote; accounting is wrong"
    );
    Ok(())
}

fn render_top_level_error(error: &anyhow::Error, rpc_url: Option<&str>) -> String {
    let rendered = sanitized_error(error);
    rpc_url
        .filter(|url| !url.is_empty())
        .map_or(rendered.clone(), |url| {
            rendered.replace(url, "<redacted-rpc>")
        })
}

async fn run() -> anyhow::Result<()> {
    let rpc_url =
        std::env::var("SOLVER_RPC").context("SOLVER_RPC required (the live chain endpoint)")?;
    if let Ok(quote_path) = std::env::var("SOLVER_E2E_EXECUTABLE_JSON") {
        let replay = artifact_replay_config_from_env()?;
        run_artifact_quote(&rpc_url, &quote_path, replay).await?;
        println!(
            "\nArtifact HTTP E2E OK — canonical replay, actual settlement payouts, fee, and dust agree"
        );
        return Ok(());
    }
    let cfg = Config {
        profile: &sextant::chain::ROBINHOOD_PROFILE,
        rpc_url: rpc_url.clone(),
        logs_rpc_url: rpc_url.clone(),
        indexer_url: None,
        native_rfq: None,
        fee_bps: 9,
        fee_receiver: Some(FEE_RECEIVER),
        positive_slippage_max_bps: 5_000,
        positive_slippage_recipient: Some(POSITIVE_SLIPPAGE_RECIPIENT),
        port: 0,
        quote_timeout: 300,
    };
    let live = Rpc::connect(&rpc_url)?;
    live.verify_chain_id(ROBINHOOD_PROFILE.chain_id, "SOLVER_RPC")
        .await?;
    println!("live chain at block {}", live.block_number().await?);
    let engine_rpc = live.clone();
    let engine = Engine::for_profile(live, &ROBINHOOD_PROFILE);

    if std::env::var("SOLVER_E2E_POSITIVE_SLIPPAGE_ONLY").is_ok_and(|value| value == "1") {
        run_case(
            &cfg,
            &engine,
            &rpc_url,
            "positive slippage",
            WETH,
            USDG,
            U256::from(10) * pow10(18),
        )
        .await?;
        println!(
            "\nPositive-slippage E2E OK — response, calldata, fixed fee, capture, and user payout agree"
        );
        return Ok(());
    }
    if std::env::var("SOLVER_E2E_FOT_ONLY").is_ok_and(|value| value == "1") {
        run_pinned_fot_regression(&cfg, &engine_rpc, &rpc_url).await?;
        println!("\nFOT E2E OK — pinned quote, V2 flag, preflight, and recipient delta agree");
        return Ok(());
    }
    if std::env::var("SOLVER_E2E_SHERIFF_ONLY").is_ok_and(|value| value == "1") {
        run_pinned_sheriff(&cfg, &engine_rpc, &rpc_url).await?;
        println!("\nSheriff E2E OK — pinned beforeSwap fee, fork 41 path, and gross output agree");
        return Ok(());
    }
    if std::env::var("SOLVER_E2E_NEW_V3_ONLY").is_ok_and(|value| value == "1") {
        run_new_v3_matrix(&cfg, &engine_rpc, &rpc_url).await?;
        run_new_v3_vip_cases(&cfg, &engine_rpc, &rpc_url).await?;
        println!("\nNew V3 E2E OK — balance-funded matrix and each VIP path executed exactly");
        return Ok(());
    }

    // 1. ERC20 → ERC20, small (single leg ⇒ UNISWAPV3_VIP encoding)
    run_case(
        &cfg,
        &engine,
        &rpc_url,
        "weth→usdg 10",
        WETH,
        USDG,
        U256::from(10) * pow10(18),
    )
    .await?;

    // 2. native ETH in (NATIVE_CHECK + wrap + balance-funded swap, direct-to-Settler)
    run_case(
        &cfg,
        &engine,
        &rpc_url,
        "eth→usdg 5",
        NATIVE,
        USDG,
        U256::from(5) * pow10(18),
    )
    .await?;

    // 3. Fixed multi-venue state: keeps calldata + execution coverage for all
    // three V3 families that lack compatible reference quoters, independent
    // of which venues happen to win at the current head.
    run_pinned_case(
        &cfg,
        &engine_rpc,
        &rpc_url,
        PinnedCase {
            label: "pinned protocol matrix",
            block: PROTOCOL_MATRIX_BLOCK,
            token_in: WETH,
            token_out: USDG,
            amount_in: U256::from(PROTOCOL_MATRIX_AMOUNT),
            required_v3: &[
                V3Protocol::PANCAKEV3,
                V3Protocol::SWAPHOODV3,
                V3Protocol::UNIV4,
            ],
            required_v2: &[],
            forced_v3: &[],
        },
    )
    .await?;

    // 4. Force one direct slice through each newly supported fork in a single
    // transaction, pinning discovery, simulation, fork IDs, callbacks, and payouts.
    run_new_v3_matrix(&cfg, &engine_rpc, &rpc_url).await?;
    run_new_v3_vip_cases(&cfg, &engine_rpc, &rpc_url).await?;

    // 5. Fixed Sheriff state: bypass route selection so fork 41 execution and
    // its pinned beforeSwap fee are compared directly with the simulated gross.
    run_pinned_sheriff(&cfg, &engine_rpc, &rpc_url).await?;

    // 6. ERC20 → native ETH (unwrap + native fee + native slippage payout)
    run_case(
        &cfg,
        &engine,
        &rpc_url,
        "usdg→eth 5000",
        USDG,
        NATIVE,
        U256::from(5000) * pow10(6),
    )
    .await?;

    // 7. Fixed UP33 Solidly state (UNISWAPV2 action against an UP33 V2 pool).
    run_pinned_case(
        &cfg,
        &engine_rpc,
        &rpc_url,
        PinnedCase {
            label: "pinned up33v2 matrix",
            block: UP33V2_MATRIX_BLOCK,
            token_in: UP,
            token_out: WETH,
            amount_in: U256::from(UP33V2_MATRIX_AMOUNT),
            required_v3: &[],
            required_v2: &[V2Protocol::UP33V2],
            forced_v3: &[],
        },
    )
    .await?;

    // 8. Original SLVR tax failure, replayed at its block through the current
    // quote model, V2 flag compiler, exact gas preflight, and Settler calldata.
    run_pinned_fot_regression(&cfg, &engine_rpc, &rpc_url).await?;

    println!(
        "\nE2E OK — AMM parity, actual settlement payouts, measured Settler dust, and fees agree"
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let rpc_url = std::env::var("SOLVER_RPC").ok();
        eprintln!("{}", render_top_level_error(&error, rpc_url.as_deref()));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod artifact_replay_tests {
    use super::*;
    use sextant::chain::BSC_PROFILE;

    #[test]
    fn top_level_rpc_error_is_sanitized() {
        let secret = "https://paid-rpc.example/super-secret-e2e-key";
        let error = anyhow::anyhow!("operational setup failed at {secret}");
        let rendered = render_top_level_error(&error, Some(secret));
        assert_eq!(rendered, "operational setup failed at <redacted-rpc>");
        assert!(!rendered.contains(secret));
    }

    #[test]
    fn replay_target_requires_an_observation_for_every_native_backed_route() {
        let hash = B256::repeat_byte(0x42);
        let hash_string = format!("{hash:#x}");

        assert_eq!(
            replay_target("amm", 100, None).unwrap(),
            ReplayTarget {
                block: 100,
                expected_hash: None,
                settlement: SettlementExpectation::ExactAmm,
            }
        );
        assert!(replay_target("amm", 100, Some((101, &hash_string))).is_err());
        for source in ["native_rfq", "mixed"] {
            assert!(replay_target(source, 100, None).is_err());
            assert_eq!(
                replay_target(source, 100, Some((101, &hash_string))).unwrap(),
                ReplayTarget {
                    block: 101,
                    expected_hash: Some(hash),
                    settlement: SettlementExpectation::NativeRfq,
                }
            );
        }
    }

    #[test]
    fn native_replay_target_rejects_noncanonical_observation_metadata() {
        let hash = format!("{:#x}", B256::repeat_byte(0x42));
        for source in ["native_rfq", "mixed"] {
            assert!(replay_target(source, 100, Some((99, &hash))).is_err());
            assert!(replay_target(source, 100, Some((100, "not-a-hash"))).is_err());
            assert!(
                replay_target(source, 100, Some((100, &format!("{:#x}", B256::ZERO))),).is_err()
            );
        }
        assert!(replay_target("unknown", 100, None).is_err());
    }

    #[test]
    fn native_payout_accounting_uses_actual_settlement_not_gross_reference() {
        let (basis, settled) = settlement_payout_basis(
            "native",
            SettlementExpectation::NativeRfq,
            U256::from(955u64),
            U256::from(1_000u64),
            U256::from(5u64),
        )
        .unwrap();
        assert_eq!(basis, U256::from(955u64));
        assert_eq!(settled, U256::from(950u64));

        assert!(
            settlement_payout_basis(
                "amm",
                SettlementExpectation::ExactAmm,
                U256::from(955u64),
                U256::from(1_000u64),
                U256::from(5u64),
            )
            .is_err()
        );
        assert_eq!(
            settlement_payout_basis(
                "amm",
                SettlementExpectation::ExactAmm,
                U256::from(1_005u64),
                U256::from(1_000u64),
                U256::from(5u64),
            )
            .unwrap(),
            (U256::from(1_005u64), U256::from(1_000u64))
        );
    }

    fn execution_helper_actions(wrapped_native: Address) -> Vec<alloy_primitives::Bytes> {
        vec![
            abi::BASICCall {
                sellToken: NATIVE,
                ppm: U256::from(1_000_000u64),
                pool: wrapped_native,
                offset: U256::from(36),
                data: Default::default(),
            }
            .abi_encode()
            .into(),
            abi::POSITIVE_SLIPPAGECall {
                recipient: Address::repeat_byte(0xa1),
                token: Address::repeat_byte(0xa2),
                expectedAmount: U256::from(123u64),
                surplusPpm: U256::from(1_000_000u64),
                maxPpm: U256::from(500_000u64),
            }
            .abi_encode()
            .into(),
        ]
    }

    fn helper_tx(data: Vec<u8>, allowance_holder: Option<Address>) -> BuiltTx {
        let settler = Address::repeat_byte(0xb1);
        let data = match allowance_holder {
            Some(_) => abi::execCall {
                operator: settler,
                token: Address::repeat_byte(0xb2),
                amount: U256::ONE,
                target: settler,
                data: data.into(),
            }
            .abi_encode(),
            None => data,
        };
        BuiltTx {
            to: allowance_holder.unwrap_or(settler),
            value: U256::ZERO,
            data,
            allowance_target: allowance_holder,
            settler,
        }
    }

    #[test]
    fn action_helpers_accept_plain_and_native_authorized_execution_wrappers() {
        let wrapped_native = Address::repeat_byte(0xc1);
        let slippage = abi::AllowedSlippage {
            recipient: Address::repeat_byte(0xc2),
            buyToken: Address::repeat_byte(0xc3),
            minAmountOut: U256::ONE,
        };
        let actions = execution_helper_actions(wrapped_native);
        let plain = helper_tx(
            abi::executeCall {
                slippage: slippage.clone(),
                actions: actions.clone(),
                zid: B256::ZERO,
            }
            .abi_encode(),
            None,
        );
        let authorized = helper_tx(
            abi::executeWithNativeAuthorizationCall {
                slippage,
                actions,
                zid: B256::ZERO,
                authorizationDeadline: U256::from(456u64),
                r: B256::repeat_byte(0xd1),
                vs: B256::repeat_byte(0xd2),
            }
            .abi_encode(),
            Some(Address::repeat_byte(0xc4)),
        );

        for tx in [&plain, &authorized] {
            assert!(uses_native_route_balance(tx, wrapped_native).unwrap());
            let positive = positive_slippage_action(tx).unwrap().unwrap();
            assert_eq!(positive.expectedAmount, U256::from(123u64));
        }
        assert!(validate_settlement_wrapper(&plain, SettlementExpectation::ExactAmm).is_ok());
        assert!(validate_settlement_wrapper(&authorized, SettlementExpectation::NativeRfq).is_ok());
        assert!(validate_settlement_wrapper(&plain, SettlementExpectation::NativeRfq).is_err());
        assert!(validate_settlement_wrapper(&authorized, SettlementExpectation::ExactAmm).is_err());
    }

    fn erc20_artifact_tx(
        settler: Address,
        operator: Address,
        token: Address,
        amount: U256,
        target: Address,
    ) -> BuiltTx {
        let allowance_holder = BSC_PROFILE.settler.unwrap().allowance_holder;
        BuiltTx {
            to: allowance_holder,
            value: U256::ZERO,
            data: abi::execCall {
                operator,
                token,
                amount,
                target,
                data: Default::default(),
            }
            .abi_encode(),
            allowance_target: Some(allowance_holder),
            settler,
        }
    }

    #[test]
    fn replay_configuration_takes_any_profile_with_a_settler() {
        let configured_receiver = Address::repeat_byte(0xa1);
        for key in ["bsc", "robinhood"] {
            let config = artifact_replay_config(key, Some(&addrhex(configured_receiver))).unwrap();
            assert_eq!(config.profile.key, key);
            assert_eq!(config.fee_receiver, configured_receiver);
        }
        let unknown = artifact_replay_config("morph", Some(&addrhex(configured_receiver)))
            .unwrap_err()
            .to_string();
        assert!(unknown.contains("expected one of"), "{unknown}");
    }

    #[test]
    fn replay_requires_an_explicit_nonzero_fee_receiver() {
        assert!(
            artifact_replay_config("bsc", None)
                .unwrap_err()
                .to_string()
                .contains("SOLVER_FEE_RECEIVER is required")
        );
        assert!(
            artifact_replay_config("bsc", Some(&addrhex(Address::ZERO)))
                .unwrap_err()
                .to_string()
                .contains("must not be zero")
        );
    }

    #[test]
    fn erc20_replay_uses_the_profile_allowance_holder_not_the_reported_target() {
        let holder = BSC_PROFILE.settler.unwrap().allowance_holder;
        let token = BSC_PROFILE.wrapped_native;
        assert_eq!(
            trusted_allowance_target(&BSC_PROFILE, token, Some(holder), holder).unwrap(),
            Some(holder)
        );

        let spoofed = Address::repeat_byte(0xa2);
        assert!(trusted_allowance_target(&BSC_PROFILE, token, Some(spoofed), spoofed).is_err());
        assert!(trusted_allowance_target(&BSC_PROFILE, token, Some(holder), spoofed).is_err());
    }

    #[test]
    fn erc20_artifact_replay_binds_exec_to_the_registry_settler_and_quote_input() {
        let settler = Address::repeat_byte(0xb1);
        let token = BSC_PROFILE.wrapped_native;
        let amount = U256::from(123_456u64);
        let valid = erc20_artifact_tx(settler, settler, token, amount, settler);
        validate_artifact_execution_binding(&BSC_PROFILE, token, amount, settler, &valid).unwrap();

        let spoofed = Address::repeat_byte(0xb2);
        assert!(
            validate_artifact_execution_binding(&BSC_PROFILE, token, amount, spoofed, &valid)
                .is_err()
        );
        for invalid in [
            erc20_artifact_tx(settler, spoofed, token, amount, settler),
            erc20_artifact_tx(settler, settler, token, amount, spoofed),
            erc20_artifact_tx(settler, settler, spoofed, amount, settler),
            erc20_artifact_tx(settler, settler, token, amount + U256::from(1), settler),
        ] {
            assert!(
                validate_artifact_execution_binding(&BSC_PROFILE, token, amount, settler, &invalid)
                    .is_err()
            );
        }
        let mut carrying_native_value = valid;
        carrying_native_value.value = U256::from(1);
        assert!(
            validate_artifact_execution_binding(
                &BSC_PROFILE,
                token,
                amount,
                settler,
                &carrying_native_value,
            )
            .is_err()
        );
    }

    #[test]
    fn native_artifact_replay_calls_the_registry_settler_directly() {
        let settler = Address::repeat_byte(0xc1);
        let amount = U256::from(789u64);
        let mut tx = BuiltTx {
            to: settler,
            value: amount,
            data: Vec::new(),
            allowance_target: None,
            settler,
        };
        validate_artifact_execution_binding(&BSC_PROFILE, NATIVE, amount, settler, &tx).unwrap();

        tx.to = Address::repeat_byte(0xc2);
        assert!(
            validate_artifact_execution_binding(&BSC_PROFILE, NATIVE, amount, settler, &tx)
                .is_err()
        );
        tx.to = settler;
        tx.value = amount - U256::from(1);
        assert!(
            validate_artifact_execution_binding(&BSC_PROFILE, NATIVE, amount, settler, &tx)
                .is_err()
        );
    }
}
