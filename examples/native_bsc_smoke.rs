use alloy::eips::BlockId;
use alloy_primitives::{Address, B256, Bytes, Signature, U256, address, b256, keccak256};
use alloy_sol_types::{SolCall, SolValue, sol};
use anyhow::{Context, ensure};
use sextant::abi;
use sextant::chain::{
    BSC_NATIVE_RFQ, BSC_PROFILE, BSC_UNIV4_POOL_MANAGER, ChainProfile, SettlerEncoding,
    SettlerProfile, SettlerRuntimePolicy,
};
use sextant::pools::{V2Pool, V2Protocol, V2State};
use sextant::rfq::{FirmQuoteRequest, NativeRfqClient, NativeRfqConfig, NativeRfqSource};
use sextant::route::{Hop, HopKind, Leg, Plan};
use sextant::rpc::{Rpc, sanitized_error};
use sextant::settler::{
    BPS_BASE, BuiltTx, ComposedSwapStage, build_composed_native_rfq_tx_for_profile,
};
use sextant::state::Snapshot;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const RPC_URL: &str = "https://bsc-rpc.publicnode.com";
const TOKEN_IN: Address = address!("2494b603319d4d9f9715c9f4496d9e0364b59d93");
const RFQ_TOKEN_OUT: Address = address!("55d398326f99059ff775485246999027b3197955");
const FINAL_TOKEN_OUT: Address = address!("2170ed0880ac9a755fd29b2688956bd959f933f8");
const AMOUNT_IN: u64 = 1_000_000_000_000_000;
const REVERSE_AMOUNT_IN: u64 = 1_000_000_000_000_000_000;
const WBNB: Address = address!("bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c");
const USDC: Address = address!("8ac76a51cc950d9822d68b83fe1ad97b32cd580d");
const BTCB: Address = address!("7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c");
const NVDAON: Address = address!("a9ee28c80f960b889dfbd1902055218cba016f75");
const GOOGLON: Address = address!("091fc7778e6932d4009b087b191d1ee3bac5729a");
const QQQON: Address = address!("0cde6936d305d5b34667fc46425e852efd73559a");
/// The authorization type of the Native-capable Settler build this smoke runs
/// against.
const NATIVE_AUTHORIZATION_TYPEHASH: B256 =
    b256!("f1b70c5105f2c900fc2d52a933c7664d9bc4d771651a135b9b4f922e32d0dbd5");
const CUSTOM_ALLOWANCE_HOLDER: Address = address!("d6b6a3ca0cd07cc894ba4edbda05eaf0f8f8c609");
const PANCAKE_V2_FACTORY: Address = address!("ca143ce32fe78f1f7019d7d551a6402fc5350c73");
const PANCAKE_V2_POOL: Address = address!("531febfeb9a61d948c384acfbe6dcc51057aea7e");
const PANCAKE_V2_FEE_BPS: u32 = 25;

#[derive(Clone, Copy)]
struct LiveWorkloadCase {
    id: &'static str,
    class: &'static str,
    pair: &'static str,
    amount_tier: &'static str,
    token_in: Address,
    token_out: Address,
    amount_in: u128,
    primary_composition: bool,
}

// All listed tokens use 18 decimals on BSC. Every case except the two marked
// no-direction exercises a direction present in Native's 2026-09-04
// orderbook. ETH and BTCB are deliberate crypto controls, so the workload also
// measures the cheap `Ok(None)` path without issuing an invalid firm quote.
const LIVE_WORKLOAD: [LiveWorkloadCase; 14] = [
    LiveWorkloadCase {
        id: "tslaon-usdt-tiny",
        class: "stock",
        pair: "TSLAon->USDT",
        amount_tier: "tiny",
        token_in: TOKEN_IN,
        token_out: RFQ_TOKEN_OUT,
        amount_in: AMOUNT_IN as u128,
        primary_composition: true,
    },
    LiveWorkloadCase {
        id: "wbnb-usdt-small",
        class: "crypto",
        pair: "WBNB->USDT",
        amount_tier: "small",
        token_in: WBNB,
        token_out: RFQ_TOKEN_OUT,
        amount_in: 10_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "usdc-usdt-large",
        class: "stable",
        pair: "USDC->USDT",
        amount_tier: "large",
        token_in: USDC,
        token_out: RFQ_TOKEN_OUT,
        amount_in: 50_000_000_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "nvdaon-usdt-small",
        class: "stock",
        pair: "NVDAon->USDT",
        amount_tier: "small",
        token_in: NVDAON,
        token_out: RFQ_TOKEN_OUT,
        amount_in: 10_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "usdt-wbnb-large",
        class: "crypto",
        pair: "USDT->WBNB",
        amount_tier: "large",
        token_in: RFQ_TOKEN_OUT,
        token_out: WBNB,
        amount_in: 50_000_000_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "usdt-usdc-large",
        class: "stable",
        pair: "USDT->USDC",
        amount_tier: "large",
        token_in: RFQ_TOKEN_OUT,
        token_out: USDC,
        amount_in: 50_000_000_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "googlon-usdt-medium",
        class: "stock",
        pair: "GOOGLon->USDT",
        amount_tier: "medium",
        token_in: GOOGLON,
        token_out: RFQ_TOKEN_OUT,
        amount_in: 20_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "usdt-tslaon-large",
        class: "stock",
        pair: "USDT->TSLAon",
        amount_tier: "large",
        token_in: RFQ_TOKEN_OUT,
        token_out: TOKEN_IN,
        amount_in: 50_000_000_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "eth-usdt-small-no-direction",
        class: "crypto",
        pair: "ETH->USDT(no-direction)",
        amount_tier: "small",
        token_in: FINAL_TOKEN_OUT,
        token_out: RFQ_TOKEN_OUT,
        amount_in: 10_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "qqqon-usdt-medium",
        class: "stock",
        pair: "QQQon->USDT",
        amount_tier: "medium",
        token_in: QQQON,
        token_out: RFQ_TOKEN_OUT,
        amount_in: 50_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "wbnb-usdt-medium",
        class: "crypto",
        pair: "WBNB->USDT",
        amount_tier: "medium",
        token_in: WBNB,
        token_out: RFQ_TOKEN_OUT,
        amount_in: 500_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "usdc-usdt-xlarge",
        class: "stable",
        pair: "USDC->USDT",
        amount_tier: "xlarge",
        token_in: USDC,
        token_out: RFQ_TOKEN_OUT,
        amount_in: 100_000_000_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "btcb-usdt-small-no-direction",
        class: "crypto",
        pair: "BTCB->USDT(no-direction)",
        amount_tier: "small",
        token_in: BTCB,
        token_out: RFQ_TOKEN_OUT,
        amount_in: 1_000_000_000_000_000,
        primary_composition: false,
    },
    LiveWorkloadCase {
        id: "usdt-nvdaon-large",
        class: "stock",
        pair: "USDT->NVDAon",
        amount_tier: "large",
        token_in: RFQ_TOKEN_OUT,
        token_out: NVDAON,
        amount_in: 50_000_000_000_000_000_000_000,
        primary_composition: false,
    },
];

#[derive(Clone, Copy)]
enum LiveOutcome {
    Validated,
    NoQuote,
    Busy,
    Failure,
}

#[derive(Default)]
struct LiveStats {
    attempts: usize,
    validated: usize,
    no_quote: usize,
    busy: usize,
    failures: usize,
    latency_micros: Vec<u128>,
}

impl LiveStats {
    fn record(&mut self, outcome: LiveOutcome, latency: Duration) {
        self.attempts += 1;
        self.latency_micros.push(latency.as_micros());
        match outcome {
            LiveOutcome::Validated => self.validated += 1,
            LiveOutcome::NoQuote => self.no_quote += 1,
            LiveOutcome::Busy => self.busy += 1,
            LiveOutcome::Failure => self.failures += 1,
        }
    }

    fn percentiles(&self) -> (u128, u128, u128) {
        let mut values = self.latency_micros.clone();
        values.sort_unstable();
        let at = |percent: usize| {
            let index = (values.len() * percent).div_ceil(100).saturating_sub(1);
            values[index.min(values.len() - 1)]
        };
        (at(50), at(95), at(99))
    }
}

fn print_live_stats(scope: &str, name: &str, stats: &LiveStats) {
    let (p50, p95, p99) = stats.percentiles();
    eprintln!(
        "Native BSC {scope}={name} attempts={} validated_quotes={} no_quote={} busy={} failures={} p50_us={p50} p95_us={p95} p99_us={p99}",
        stats.attempts, stats.validated, stats.no_quote, stats.busy, stats.failures,
    );
}

sol! {
    struct LiveReverseBundle {
        address target;
        uint256 value;
        bytes data;
        address tokenIn;
        uint256 amountIn;
        address tokenOut;
        uint256 minimumOut;
        address beneficiary;
        uint256 quotedOut;
        uint256 deadline;
        uint256 observationBlock;
    }

    struct LiveSmokeBundle {
        address target;
        uint256 value;
        bytes data;
        address tokenIn;
        uint256 amountIn;
        address tokenOut;
        uint256 minimumOut;
        address beneficiary;
        uint256 quotedOut;
        uint256 deadline;
        uint256 observationBlock;
        bool reverseAvailable;
        LiveReverseBundle reverse;
    }

    function getPair(address tokenA, address tokenB) external view returns (address pair);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves()
        external
        view
        returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

const TEST_SETTLER: SettlerProfile = SettlerProfile {
    registry: Address::ZERO,
    registry_token_id: 0,
    allowance_holder: CUSTOM_ALLOWANCE_HOLDER,
    allowance_holder_runtime_hash: B256::ZERO,
    runtime: SettlerRuntimePolicy::Exact(B256::ZERO),
    encoding: SettlerEncoding::PpmVipPathFromPermit,
    ekubo_v3_runtimes: &[],
    indexed_v3: &[],
    univ4_pool_manager: Some(BSC_UNIV4_POOL_MANAGER),
    univ4_fork_id: None,
    native_authorization_typehash: Some(NATIVE_AUTHORIZATION_TYPEHASH),
};

async fn verify_native_identity(rpc: &Rpc) -> anyhow::Result<()> {
    let canonical = rpc.canonical_block(BlockId::latest()).await?;
    let at = BlockId::hash_canonical(canonical.hash);
    let router_code = rpc.code_at(BSC_NATIVE_RFQ.router, at).await?;
    let pool_code = rpc.code_at(BSC_NATIVE_RFQ.pool, at).await?;
    let vault_code = rpc.code_at(BSC_NATIVE_RFQ.credit_vault, at).await?;
    ensure!(
        keccak256(router_code) == BSC_NATIVE_RFQ.router_runtime_hash,
        "unreviewed Native Router runtime"
    );
    ensure!(
        keccak256(pool_code) == BSC_NATIVE_RFQ.pool_runtime_hash,
        "unreviewed Native pool runtime"
    );
    ensure!(
        keccak256(vault_code) == BSC_NATIVE_RFQ.credit_vault_runtime_hash,
        "unreviewed Native CreditVault runtime"
    );

    let revision_call = abi::contractRevisionCall {}.abi_encode();
    let router_revision = rpc
        .eth_call(BSC_NATIVE_RFQ.router, revision_call.clone(), at)
        .await?;
    let pool_revision = rpc.eth_call(BSC_NATIVE_RFQ.pool, revision_call, at).await?;
    ensure!(
        abi::contractRevisionCall::abi_decode_returns(&router_revision)?
            == U256::from(BSC_NATIVE_RFQ.contract_revision),
        "unreviewed Native Router revision"
    );
    ensure!(
        abi::contractRevisionCall::abi_decode_returns(&pool_revision)?
            == U256::from(BSC_NATIVE_RFQ.contract_revision),
        "unreviewed Native pool revision"
    );

    let recognized = rpc
        .eth_call(
            BSC_NATIVE_RFQ.router,
            abi::isNativePoolsCall {
                pool: BSC_NATIVE_RFQ.pool,
            }
            .abi_encode(),
            at,
        )
        .await?;
    ensure!(
        abi::isNativePoolsCall::abi_decode_returns(&recognized)?,
        "Native Router does not recognize the pool"
    );

    let pool_router = rpc
        .eth_call(BSC_NATIVE_RFQ.pool, abi::routerCall {}.abi_encode(), at)
        .await?;
    ensure!(
        abi::routerCall::abi_decode_returns(&pool_router)? == BSC_NATIVE_RFQ.router,
        "Native pool is wired to a different Router"
    );
    let router_vault = rpc
        .eth_call(BSC_NATIVE_RFQ.router, abi::vaultCall {}.abi_encode(), at)
        .await?;
    let pool_treasury = rpc
        .eth_call(BSC_NATIVE_RFQ.pool, abi::treasuryCall {}.abi_encode(), at)
        .await?;
    ensure!(
        abi::vaultCall::abi_decode_returns(&router_vault)? == BSC_NATIVE_RFQ.credit_vault
            && abi::treasuryCall::abi_decode_returns(&pool_treasury)?
                == BSC_NATIVE_RFQ.credit_vault,
        "Native Router/pool CreditVault wiring mismatch"
    );
    let router_weth = rpc
        .eth_call(BSC_NATIVE_RFQ.router, abi::WETH9Call {}.abi_encode(), at)
        .await?;
    let pool_weth = rpc
        .eth_call(BSC_NATIVE_RFQ.pool, abi::WETH9Call {}.abi_encode(), at)
        .await?;
    ensure!(
        abi::WETH9Call::abi_decode_returns(&router_weth)? == BSC_PROFILE.wrapped_native
            && abi::WETH9Call::abi_decode_returns(&pool_weth)? == BSC_PROFILE.wrapped_native,
        "Native Router/pool wrapped-native wiring mismatch"
    );

    let domain = rpc
        .eth_call(
            BSC_NATIVE_RFQ.pool,
            abi::eip712DomainCall {}.abi_encode(),
            at,
        )
        .await?;
    let domain = abi::eip712DomainCall::abi_decode_returns(&domain)?;
    ensure!(
        domain.fields[0] == BSC_NATIVE_RFQ.domain_fields
            && domain.name == BSC_NATIVE_RFQ.domain_name
            && domain.version == BSC_NATIVE_RFQ.domain_version
            && domain.chainId == U256::from(BSC_NATIVE_RFQ.domain_chain_id)
            && domain.verifyingContract == BSC_NATIVE_RFQ.pool
            && domain.salt == B256::ZERO
            && domain.extensions.is_empty(),
        "unreviewed Native pool EIP-712 domain"
    );
    Ok(())
}

async fn pancake_v2_snapshot(
    rpc: &Rpc,
    settler: Address,
    block: u64,
    hash: B256,
) -> anyhow::Result<Snapshot> {
    let at = BlockId::hash_canonical(hash);
    let pair = rpc
        .eth_call(
            PANCAKE_V2_FACTORY,
            getPairCall {
                tokenA: RFQ_TOKEN_OUT,
                tokenB: FINAL_TOKEN_OUT,
            }
            .abi_encode(),
            at,
        )
        .await?;
    ensure!(
        getPairCall::abi_decode_returns(&pair)? == PANCAKE_V2_POOL,
        "unexpected PancakeSwap V2 USDT/ETH pool"
    );
    let token0 = rpc
        .eth_call(PANCAKE_V2_POOL, token0Call {}.abi_encode(), at)
        .await?;
    let token1 = rpc
        .eth_call(PANCAKE_V2_POOL, token1Call {}.abi_encode(), at)
        .await?;
    ensure!(
        token0Call::abi_decode_returns(&token0)? == FINAL_TOKEN_OUT
            && token1Call::abi_decode_returns(&token1)? == RFQ_TOKEN_OUT,
        "unexpected PancakeSwap V2 pool tokens"
    );
    let reserves = rpc
        .eth_call(PANCAKE_V2_POOL, getReservesCall {}.abi_encode(), at)
        .await?;
    let reserves = getReservesCall::abi_decode_returns(&reserves)?;
    let reserve0 = U256::from(reserves.reserve0);
    let reserve1 = U256::from(reserves.reserve1);
    ensure!(reserve0 > U256::ZERO && reserve1 > U256::ZERO);

    Ok(Snapshot {
        block,
        settler: Some(settler),
        v3: Vec::new(),
        v2: vec![(
            V2Pool {
                protocol: V2Protocol::PANCAKEV2,
                address: PANCAKE_V2_POOL,
                token0: FINAL_TOKEN_OUT,
                token1: RFQ_TOKEN_OUT,
                fee_bps: PANCAKE_V2_FEE_BPS,
            },
            V2State { reserve0, reserve1 },
        )],
        ekubo: Vec::new(),
    })
}

fn pancake_v2_plan(
    snapshot: &Snapshot,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
) -> anyhow::Result<Plan> {
    let (pool, state) = snapshot.v2.first().context("missing PancakeSwap V2 pool")?;
    let zero_for_one = if (token_in, token_out) == (pool.token0, pool.token1) {
        true
    } else {
        ensure!(
            (token_in, token_out) == (pool.token1, pool.token0),
            "PancakeSwap V2 plan tokens do not match the reviewed pool"
        );
        false
    };
    let (reserve_in, reserve_out) = if zero_for_one {
        (state.reserve0, state.reserve1)
    } else {
        (state.reserve1, state.reserve0)
    };
    let amount_in_with_fee = amount_in * U256::from(10_000 - pool.fee_bps);
    let amount_out =
        amount_in_with_fee * reserve_out / (reserve_in * U256::from(10_000) + amount_in_with_fee);
    ensure!(
        amount_out > U256::ZERO,
        "PancakeSwap V2 quote rounded to zero"
    );

    Ok(Plan {
        legs: vec![Leg {
            path: vec![Hop {
                kind: HopKind::V2,
                index: 0,
                zero_for_one,
                token_in,
                token_out,
            }],
            amount_in,
            amount_out,
            losses: Vec::new(),
            slice_bps: BPS_BASE,
        }],
        amount_out,
        universe_id: None,
    })
}

fn action_selector(action: &Bytes) -> anyhow::Result<[u8; 4]> {
    action
        .get(..4)
        .context("truncated Settler action")?
        .try_into()
        .context("invalid Settler action selector")
}

#[allow(clippy::too_many_arguments)]
fn validate_composed_tx(
    profile: &ChainProfile,
    authorizer: &sextant::rfq::NativeBeneficiaryAuthorizer,
    tx: &BuiltTx,
    settler: Address,
    taker: Address,
    token_in: Address,
    amount_in: U256,
    deadline: u64,
    expected_actions: &[[u8; 4]],
) -> anyhow::Result<abi::executeWithNativeAuthorizationCall> {
    ensure!(
        tx.to == CUSTOM_ALLOWANCE_HOLDER
            && tx.allowance_target == Some(CUSTOM_ALLOWANCE_HOLDER)
            && tx.value == U256::ZERO
            && tx.settler == settler,
        "unexpected composed transaction envelope"
    );
    let holder = abi::execCall::abi_decode(&tx.data)?;
    ensure!(
        holder.operator == settler
            && holder.token == token_in
            && holder.amount == amount_in
            && holder.target == settler,
        "unexpected AllowanceHolder execution envelope"
    );
    let execute = abi::executeWithNativeAuthorizationCall::abi_decode(&holder.data)?;
    let actual_actions = execute
        .actions
        .iter()
        .map(action_selector)
        .collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(
        actual_actions == expected_actions,
        "unexpected composed Settler action order"
    );
    ensure!(
        execute.authorizationDeadline == U256::from(deadline),
        "unexpected Native authorization deadline"
    );

    let canonical_execute = abi::executeCall {
        slippage: execute.slippage.clone(),
        actions: execute.actions.clone(),
        zid: execute.zid,
    }
    .abi_encode();
    let struct_hash = sextant::rfq::NativeBeneficiaryAuthorizer::struct_hash(
        NATIVE_AUTHORIZATION_TYPEHASH,
        profile.chain_id,
        settler,
        taker,
        taker,
        &canonical_execute,
        deadline,
    );
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(execute.r.as_slice());
    compact[32..].copy_from_slice(execute.vs.as_slice());
    let recovered = Signature::from_erc2098(&compact)
        .recover_address_from_msg(struct_hash.as_slice())
        .context("recovering composed Native authorization signer")?;
    ensure!(
        recovered == authorizer.address(),
        "composed authorization does not commit the complete action list"
    );

    Ok(execute)
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
    let mut args = std::env::args().skip(1);
    let settler: Address = args
        .next()
        .context("missing Settler address")?
        .parse()
        .context("invalid Settler address")?;
    let taker: Address = args
        .next()
        .context("missing taker address")?
        .parse()
        .context("invalid taker address")?;
    ensure!(args.next().is_none(), "unexpected arguments");
    ensure!(settler != Address::ZERO && taker != Address::ZERO && settler != taker);
    let attempts = std::env::var("NATIVE_BSC_SMOKE_ATTEMPTS")
        .unwrap_or_else(|_| "1".to_string())
        .parse::<usize>()
        .context("NATIVE_BSC_SMOKE_ATTEMPTS is invalid")?;
    ensure!(
        (1..=256).contains(&attempts),
        "NATIVE_BSC_SMOKE_ATTEMPTS must be in 1..=256"
    );
    let waves = std::env::var("NATIVE_BSC_SMOKE_WAVES")
        .unwrap_or_else(|_| "1".to_string())
        .parse::<usize>()
        .context("NATIVE_BSC_SMOKE_WAVES is invalid")?;
    ensure!(
        (1..=32).contains(&waves),
        "NATIVE_BSC_SMOKE_WAVES must be in 1..=32"
    );
    let inter_wave_ms = std::env::var("NATIVE_BSC_SMOKE_INTER_WAVE_MS")
        .unwrap_or_else(|_| "0".to_string())
        .parse::<u64>()
        .context("NATIVE_BSC_SMOKE_INTER_WAVE_MS is invalid")?;
    ensure!(
        inter_wave_ms <= 60_000,
        "NATIVE_BSC_SMOKE_INTER_WAVE_MS must be in 0..=60000"
    );

    let rpc_url = std::env::var("BSC_RPC_URL").unwrap_or_else(|_| RPC_URL.to_string());
    let rpc = Rpc::connect(&rpc_url)?;
    ensure!(
        rpc.chain_id().await? == BSC_PROFILE.chain_id,
        "wrong RPC chain"
    );
    verify_native_identity(&rpc).await?;

    let profile = ChainProfile {
        settler: Some(TEST_SETTLER),
        native_rfq: Some(*BSC_NATIVE_RFQ),
        ..*BSC_PROFILE
    };
    let config = NativeRfqConfig::from_env(&profile)?
        .context("SOLVER_NATIVE_RFQ_ENABLED must enable the live smoke test")?;
    let authorizer = config.authorizer().clone();
    let qps = config.qps();
    let queue_wait_ms = config.queue_wait().as_millis();
    let max_inflight = config.max_inflight();
    let client = NativeRfqClient::new(config, rpc.clone())?;
    let requested_at = rpc.canonical_block(BlockId::latest()).await?;
    let chain_timestamp = requested_at.timestamp;
    for case in LIVE_WORKLOAD {
        eprintln!(
            "Native BSC workload case={} class={} pair={} amount_tier={} amount_wei={}",
            case.id, case.class, case.pair, case.amount_tier, case.amount_in
        );
    }
    let all_started = Instant::now();
    let mut first_quote = None;
    let mut total_stats = LiveStats::default();
    let mut category_stats = BTreeMap::<&'static str, LiveStats>::new();
    let mut pair_stats = BTreeMap::<&'static str, LiveStats>::new();
    for wave in 1..=waves {
        let wave_started = Instant::now();
        // Rotate the starting point between waves while keeping every wave
        // interleaved. Under a saturated eight-request Native bulkhead this
        // prevents one asset class from monopolizing the admitted prefix.
        let offset = ((wave - 1) * 5) % LIVE_WORKLOAD.len();
        let cases: Vec<_> = (0..attempts)
            .map(|index| LIVE_WORKLOAD[(offset + index) % LIVE_WORKLOAD.len()])
            .collect();
        let results = futures_util::future::join_all(cases.iter().copied().map(|case| {
            let request = FirmQuoteRequest {
                identity: *BSC_NATIVE_RFQ,
                token_in: case.token_in,
                token_out: case.token_out,
                amount_in: U256::from(case.amount_in),
                settler,
                beneficiary: taker,
                tx_origin: Some(taker),
                slippage_bps: 50,
                expiry_seconds: 60,
                chain_timestamp,
            };
            let client = &client;
            async move {
                let started = Instant::now();
                let result = client.firm_quote(request).await;
                (case, result, started.elapsed())
            }
        }))
        .await;
        let mut wave_stats = LiveStats::default();
        let mut error_kinds = BTreeMap::<String, usize>::new();
        for (case, result, latency) in results {
            let outcome = match result {
                Ok(Some(quote)) => {
                    if case.primary_composition && first_quote.is_none() {
                        first_quote = Some(quote.clone());
                    }
                    LiveOutcome::Validated
                }
                Ok(None) => LiveOutcome::NoQuote,
                Err(error) if error.is_retryable_capacity() => {
                    *error_kinds.entry(error.to_string()).or_default() += 1;
                    LiveOutcome::Busy
                }
                Err(error) => {
                    *error_kinds.entry(error.to_string()).or_default() += 1;
                    LiveOutcome::Failure
                }
            };
            wave_stats.record(outcome, latency);
            total_stats.record(outcome, latency);
            category_stats
                .entry(case.class)
                .or_default()
                .record(outcome, latency);
            pair_stats
                .entry(case.pair)
                .or_default()
                .record(outcome, latency);
        }
        let (p50, p95, p99) = wave_stats.percentiles();
        eprintln!(
            "Native BSC wave={} attempts={} max_inflight={} validated_quotes={} no_quote={} busy={} failures={} p50_us={} p95_us={} p99_us={} elapsed_ms={} outbound_qps_cap={} queue_wait_ms={}",
            wave,
            attempts,
            max_inflight,
            wave_stats.validated,
            wave_stats.no_quote,
            wave_stats.busy,
            wave_stats.failures,
            p50,
            p95,
            p99,
            wave_started.elapsed().as_millis(),
            qps,
            queue_wait_ms,
        );
        for (error, count) in error_kinds {
            eprintln!("Native BSC wave={wave} outcome_count={count} outcome={error}");
        }
        if wave < waves && inter_wave_ms > 0 {
            tokio::time::sleep(Duration::from_millis(inter_wave_ms)).await;
        }
    }
    eprintln!(
        "Native BSC total_waves={} total_attempts={} validated_quotes={} no_quote={} busy={} failures={} elapsed_ms={}",
        waves,
        attempts * waves,
        total_stats.validated,
        total_stats.no_quote,
        total_stats.busy,
        total_stats.failures,
        all_started.elapsed().as_millis(),
    );
    for (category, stats) in &category_stats {
        print_live_stats("category", category, stats);
    }
    for (pair, stats) in &pair_stats {
        print_live_stats("pair", pair, stats);
    }
    ensure!(
        total_stats.attempts == attempts * waves,
        "live workload lost an outcome"
    );
    ensure!(
        total_stats.failures == 0,
        "live workload returned {} unexpected failures",
        total_stats.failures
    );

    // Keep one deterministic TSLAon -> Native USDT -> Pancake ETH proof. If
    // burst admission excluded it, obtain one serial quote rather than
    // substituting another asset or amount.
    let forward_quote = match first_quote {
        Some(quote) => quote,
        None => client
            .firm_quote(FirmQuoteRequest {
                identity: *BSC_NATIVE_RFQ,
                token_in: TOKEN_IN,
                token_out: RFQ_TOKEN_OUT,
                amount_in: U256::from(AMOUNT_IN),
                settler,
                beneficiary: taker,
                tx_origin: Some(taker),
                slippage_bps: 50,
                expiry_seconds: 60,
                chain_timestamp,
            })
            .await?
            .context("Native returned no BSC TSLAon/USDT quote")?,
    };
    let amount_in = U256::from(AMOUNT_IN);
    let forward_observation = forward_quote
        .observation()
        .context("Native quote has no canonical observation")?;
    let forward_block = rpc
        .canonical_block(BlockId::hash_canonical(forward_observation.hash))
        .await?;
    ensure!(
        forward_block.number == forward_observation.number,
        "Native observation block changed before composed encoding"
    );
    let forward_snapshot =
        pancake_v2_snapshot(&rpc, settler, forward_block.number, forward_block.hash).await?;
    let forward_tail = pancake_v2_plan(
        &forward_snapshot,
        RFQ_TOKEN_OUT,
        FINAL_TOKEN_OUT,
        forward_quote.amount_out(),
    )?;
    ensure!(
        forward_quote.token_out() == forward_tail.legs[0].path[0].token_in
            && forward_quote.amount_out() == forward_tail.legs[0].amount_in,
        "Native -> Pancake stages are not continuous"
    );
    let forward_stages = [
        ComposedSwapStage::NativeRfq {
            quote: &forward_quote,
            token_in: TOKEN_IN,
            token_out: RFQ_TOKEN_OUT,
        },
        ComposedSwapStage::Amm {
            plan: &forward_tail,
        },
    ];
    let quoted_out = forward_tail.amount_out;
    let minimum_out = quoted_out * U256::from(9_900u64) / U256::from(10_000u64);
    ensure!(minimum_out > U256::ZERO);
    let deadline = forward_quote.deadline();
    let tx = build_composed_native_rfq_tx_for_profile(
        &profile,
        &authorizer,
        taker,
        0,
        None,
        None,
        &forward_snapshot,
        &forward_stages,
        TOKEN_IN,
        FINAL_TOKEN_OUT,
        amount_in,
        minimum_out,
        taker,
        forward_block.timestamp,
        deadline,
    )?;
    let forward_execute = validate_composed_tx(
        &profile,
        &authorizer,
        &tx,
        settler,
        taker,
        TOKEN_IN,
        amount_in,
        deadline,
        &[
            abi::TRANSFER_FROMCall::SELECTOR,
            abi::BASICCall::SELECTOR,
            abi::UNISWAPV2Call::SELECTOR,
        ],
    )?;
    ensure!(
        forward_execute.slippage.recipient == taker
            && forward_execute.slippage.buyToken == FINAL_TOKEN_OUT
            && forward_execute.slippage.minAmountOut == minimum_out,
        "unexpected Native -> Pancake final slippage policy"
    );
    let forward_native = abi::BASICCall::abi_decode(&forward_execute.actions[1])?;
    ensure!(
        forward_native.sellToken == TOKEN_IN
            && forward_native.ppm == U256::from(1_000_000u64)
            && forward_native.pool == BSC_NATIVE_RFQ.router
            && forward_native.offset == U256::from(forward_quote.amount_in_offset())
            && forward_native.data.as_ref() == forward_quote.calldata().as_ref(),
        "unexpected Native-first action"
    );
    let forward_amm = abi::UNISWAPV2Call::abi_decode(&forward_execute.actions[2])?;
    ensure!(
        forward_amm.recipient == settler
            && forward_amm.sellToken == RFQ_TOKEN_OUT
            && forward_amm.ppm == U256::from(1_000_000u64)
            && forward_amm.pool == PANCAKE_V2_POOL,
        "unexpected Pancake tail action"
    );

    // Exercise the inverse composition against the real API: Pancake ETH ->
    // USDT first, then request Native for exactly that simulated USDT amount.
    // Native may legitimately expose the pair but have no executable stock
    // inventory at this size; that is a named no-quote smoke outcome.
    let reverse_block = rpc.canonical_block(BlockId::latest()).await?;
    let reverse_snapshot =
        pancake_v2_snapshot(&rpc, settler, reverse_block.number, reverse_block.hash).await?;
    let reverse_amount_in = U256::from(REVERSE_AMOUNT_IN);
    let reverse_prefix = pancake_v2_plan(
        &reverse_snapshot,
        FINAL_TOKEN_OUT,
        RFQ_TOKEN_OUT,
        reverse_amount_in,
    )?;
    let reverse_quote = client
        .firm_quote(FirmQuoteRequest {
            identity: *BSC_NATIVE_RFQ,
            token_in: RFQ_TOKEN_OUT,
            token_out: TOKEN_IN,
            amount_in: reverse_prefix.amount_out,
            settler,
            beneficiary: taker,
            tx_origin: Some(taker),
            slippage_bps: 50,
            expiry_seconds: 60,
            chain_timestamp: reverse_block.timestamp,
        })
        .await?;
    let reverse_bundle = match reverse_quote {
        Some(reverse_quote) => {
            ensure!(
                reverse_prefix.legs[0].path[0].token_out == reverse_quote.token_in()
                    && reverse_prefix.amount_out == reverse_quote.amount_in(),
                "Pancake -> Native stages are not continuous"
            );
            let reverse_stages = [
                ComposedSwapStage::Amm {
                    plan: &reverse_prefix,
                },
                ComposedSwapStage::NativeRfq {
                    quote: &reverse_quote,
                    token_in: RFQ_TOKEN_OUT,
                    token_out: TOKEN_IN,
                },
            ];
            let reverse_minimum_out =
                reverse_quote.amount_out() * U256::from(9_950u64) / U256::from(10_000u64);
            ensure!(reverse_minimum_out > U256::ZERO);
            let reverse_observation = reverse_quote
                .observation()
                .context("reverse Native quote has no canonical observation")?;
            let reverse_finalized = rpc
                .canonical_block(BlockId::hash_canonical(reverse_observation.hash))
                .await?;
            ensure!(
                reverse_finalized.number == reverse_observation.number,
                "reverse Native observation block changed before composed encoding"
            );
            let reverse_deadline = reverse_quote.deadline();
            let reverse_tx = build_composed_native_rfq_tx_for_profile(
                &profile,
                &authorizer,
                taker,
                0,
                None,
                None,
                &reverse_snapshot,
                &reverse_stages,
                FINAL_TOKEN_OUT,
                TOKEN_IN,
                reverse_amount_in,
                reverse_minimum_out,
                taker,
                reverse_finalized.timestamp,
                reverse_deadline,
            )?;
            let reverse_execute = validate_composed_tx(
                &profile,
                &authorizer,
                &reverse_tx,
                settler,
                taker,
                FINAL_TOKEN_OUT,
                reverse_amount_in,
                reverse_deadline,
                &[
                    abi::TRANSFER_FROMCall::SELECTOR,
                    abi::UNISWAPV2Call::SELECTOR,
                    abi::BASICCall::SELECTOR,
                ],
            )?;
            ensure!(
                reverse_execute.slippage.recipient == taker
                    && reverse_execute.slippage.buyToken == TOKEN_IN
                    && reverse_execute.slippage.minAmountOut == reverse_minimum_out,
                "unexpected Pancake -> Native final slippage policy"
            );
            let reverse_amm = abi::UNISWAPV2Call::abi_decode(&reverse_execute.actions[1])?;
            ensure!(
                reverse_amm.recipient == settler
                    && reverse_amm.sellToken == FINAL_TOKEN_OUT
                    && reverse_amm.ppm == U256::from(1_000_000u64)
                    && reverse_amm.pool == PANCAKE_V2_POOL,
                "unexpected Pancake prefix action"
            );
            let reverse_native = abi::BASICCall::abi_decode(&reverse_execute.actions[2])?;
            ensure!(
                reverse_native.sellToken == RFQ_TOKEN_OUT
                    && reverse_native.ppm == U256::from(1_000_000u64)
                    && reverse_native.pool == BSC_NATIVE_RFQ.router
                    && reverse_native.offset == U256::from(reverse_quote.amount_in_offset())
                    && reverse_native.data.as_ref() == reverse_quote.calldata().as_ref(),
                "unexpected Native-last action"
            );
            eprintln!(
                "Native BSC composition=ETH->Pancake-USDT->Native-TSLAon outcome=encoded amount_in={} bridge_amount={} quoted_out={} observation_block={}",
                reverse_amount_in,
                reverse_prefix.amount_out,
                reverse_quote.amount_out(),
                reverse_observation.number,
            );
            Some(LiveReverseBundle {
                target: reverse_tx.to,
                value: reverse_tx.value,
                data: Bytes::from(reverse_tx.data),
                tokenIn: FINAL_TOKEN_OUT,
                amountIn: reverse_amount_in,
                tokenOut: TOKEN_IN,
                minimumOut: reverse_minimum_out,
                beneficiary: taker,
                quotedOut: reverse_quote.amount_out(),
                deadline: U256::from(reverse_deadline),
                observationBlock: U256::from(reverse_observation.number),
            })
        }
        None => {
            eprintln!(
                "Native BSC composition=ETH->Pancake-USDT->Native-TSLAon outcome=no_quote bridge_amount={}",
                reverse_prefix.amount_out,
            );
            None
        }
    };

    let reverse_available = reverse_bundle.is_some();
    let reverse = reverse_bundle.unwrap_or_else(|| LiveReverseBundle {
        target: Address::ZERO,
        value: U256::ZERO,
        data: Bytes::new(),
        tokenIn: Address::ZERO,
        amountIn: U256::ZERO,
        tokenOut: Address::ZERO,
        minimumOut: U256::ZERO,
        beneficiary: Address::ZERO,
        quotedOut: U256::ZERO,
        deadline: U256::ZERO,
        observationBlock: U256::ZERO,
    });

    let output = LiveSmokeBundle {
        target: tx.to,
        value: tx.value,
        data: Bytes::from(tx.data),
        tokenIn: TOKEN_IN,
        amountIn: amount_in,
        tokenOut: FINAL_TOKEN_OUT,
        minimumOut: minimum_out,
        beneficiary: taker,
        quotedOut: quoted_out,
        deadline: U256::from(deadline),
        observationBlock: U256::from(forward_observation.number),
        reverseAvailable: reverse_available,
        reverse,
    }
    .abi_encode();
    println!("0x{}", alloy_primitives::hex::encode(output));
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let rpc_url = std::env::var("BSC_RPC_URL").ok();
        eprintln!("{}", render_top_level_error(&error, rpc_url.as_deref()));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod top_level_error_tests {
    use super::*;

    #[test]
    fn top_level_rpc_error_is_sanitized() {
        let secret = "https://paid-rpc.example/super-secret-bsc-key";
        let error = anyhow::anyhow!("operational setup failed at {secret}");
        let rendered = render_top_level_error(&error, Some(secret));
        assert_eq!(rendered, "operational setup failed at <redacted-rpc>");
        assert!(!rendered.contains(secret));
    }
}
