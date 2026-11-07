use super::amm::{escalate_threshold_e4, fresh_amm_snapshot};
use super::fees::{fee_free_out, mid_amount_out, price_impact_bps, reference_metrics};
use super::native::{
    NativeDraft, OPTIONAL_RFQ_RESPONSE_RESERVE, choose_native_draft, native_quote_beats_amm,
    native_result_or_fallback, request_optional_native_quote, selected_deadline,
};
use super::request::{parse_execution_identities, routed_tokens};
use super::wire::{
    AmountIn, CanonicalBlockJson, HopJson, QuoteMeta, QuoteRequest, QuoteResponse,
    RouteUniverseJson, TxJson, certificate_json, hop_json,
};
use super::{PricedBeforeCheck, quote_swap_bounded};
use crate::abi::addrhex;
use crate::budget::SolverBudget;
use crate::certificate::certify;
use crate::chain::{
    BSC_NATIVE_RFQ, BSC_PROFILE, BSC_USD1, BSC_USDT, ChainProfile, FIXTURE_NATIVE_RFQ,
    FIXTURE_PROFILE, FIXTURE_USDT0, FIXTURE_WETH, NATIVE, WBNB,
};
use crate::config::Config;
use crate::engine::Engine;
use crate::pools::{AlgebraMeta, V2Pool, V2Protocol, V2State, V3Pool, V3Protocol, V3State, sim_v2};
use crate::rfq::{
    FirmQuoteRequest, NativeBeneficiaryAuthorizer, NativePair, NativeRfqConfig, NativeRfqError,
    NativeRfqSource, ValidatedFirmQuote,
};
use crate::route::{
    ALLOC_CHUNKS, Hop, HopKind, Leg, Plan, PreparedRoutes, best_plan, quantized_plan,
};
use crate::rpc::RpcUnavailable;
use crate::settler::BPS_BASE;
use crate::simulation::Issues;
use crate::snapshot::Snapshot;
use crate::state::ObservedSnapshot;
use crate::universe::RouteUniverseDiagnostics;
use crate::{certificate, simulation};
use alloy::eips::BlockId;
use alloy_primitives::{Address, B256, Bytes, U256};
use futures_util::future::BoxFuture;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const TEST_BENEFICIARY_KEY: &str =
    "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d";
const MIXED_STOCK: Address = Address::repeat_byte(0xa5);
const MIXED_SETTLER: Address = Address::repeat_byte(0x77);
const MIXED_STOCK_TOKENS: [Address; 1] = [MIXED_STOCK];
const MIXED_CONNECTORS: [Address; 4] = [WBNB, BSC_USDT, BSC_USD1, MIXED_STOCK];
static MIXED_NATIVE_RFQ: std::sync::LazyLock<crate::chain::NativeRfqProfile> =
    std::sync::LazyLock::new(|| crate::chain::NativeRfqProfile {
        stock_tokens: &MIXED_STOCK_TOKENS,
        ..*BSC_NATIVE_RFQ
    });
static MIXED_TEST_PROFILE: std::sync::LazyLock<ChainProfile> =
    std::sync::LazyLock::new(|| ChainProfile {
        connectors: &MIXED_CONNECTORS,
        native_rfq: Some(*MIXED_NATIVE_RFQ),
        settler: Some(crate::chain::with_native_entry(*crate::chain::BSC_SETTLER)),
        ..*BSC_PROFILE
    });

fn put_word(calldata: &mut [u8], offset: usize, value: U256) {
    calldata[offset..offset + 32].copy_from_slice(&value.to_be_bytes::<32>());
}

fn put_quote_address(calldata: &mut [u8], index: usize, value: Address) {
    let offset = 4 + 96 + index * 32;
    calldata[offset + 12..offset + 32].copy_from_slice(value.as_slice());
}

fn mock_native_calldata(request: FirmQuoteRequest, amount_out: U256, deadline: u64) -> Bytes {
    let mut calldata = vec![0u8; 4 + 96 + 16 * 32];
    calldata[..4].copy_from_slice(&request.identity.trade_selector);
    put_word(&mut calldata, 4, U256::from(96u64));
    put_quote_address(&mut calldata, 0, request.identity.pool);
    put_quote_address(&mut calldata, 2, request.settler);
    put_quote_address(&mut calldata, 3, request.token_in);
    put_quote_address(&mut calldata, 4, request.token_out);
    put_word(&mut calldata, 4 + 96 + 5 * 32, request.amount_in);
    put_word(&mut calldata, 4 + 96 + 6 * 32, amount_out);
    put_word(&mut calldata, 4 + 96 + 8 * 32, U256::from(deadline));
    put_quote_address(&mut calldata, 14, request.settler);
    put_quote_address(
        &mut calldata,
        15,
        request.tx_origin.unwrap_or(Address::ZERO),
    );
    calldata.into()
}

fn mock_validated_quote(request: FirmQuoteRequest, amount_out: U256) -> ValidatedFirmQuote {
    let deadline = request.chain_timestamp + 60;
    ValidatedFirmQuote {
        target: request.identity.router,
        pool: request.identity.pool,
        calldata: mock_native_calldata(request, amount_out, deadline),
        token_in: request.token_in,
        token_out: request.token_out,
        settler: request.settler,
        expected_origin: request.tx_origin.unwrap_or(Address::ZERO),
        amount_in: request.amount_in,
        amount_out,
        signer: Address::repeat_byte(0x66),
        nonce: U256::from(7u64),
        beneficiary: request.beneficiary,
        deadline,
        min_ttl_seconds: 10,
        amount_in_offset: 36,
        amount_out_minimum_offset: 68,
        router_version: request.identity.router_version,
        observation: Some(crate::rfq::NativeQuoteObservation {
            number: 2,
            hash: B256::repeat_byte(0x44),
        }),
    }
}

struct PlannedNativeSource {
    indicatives: Vec<(NativePair, U256)>,
    amount_out: U256,
    delay: Duration,
    pair_calls: AtomicUsize,
    firm_calls: AtomicUsize,
    requests: Mutex<Vec<FirmQuoteRequest>>,
}

impl PlannedNativeSource {
    fn new(available: Vec<NativePair>, amount_out: U256) -> Self {
        Self {
            indicatives: available
                .into_iter()
                .map(|pair| (pair, amount_out))
                .collect(),
            amount_out,
            delay: Duration::ZERO,
            pair_calls: AtomicUsize::new(0),
            firm_calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn with_indicatives(indicatives: Vec<(NativePair, U256)>, firm_amount_out: U256) -> Self {
        Self {
            indicatives,
            amount_out: firm_amount_out,
            delay: Duration::ZERO,
            pair_calls: AtomicUsize::new(0),
            firm_calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

impl NativeRfqSource for PlannedNativeSource {
    fn indicative_quotes<'a>(
        &'a self,
        _identity: crate::chain::NativeRfqProfile,
        requests: &'a [(NativePair, U256)],
    ) -> BoxFuture<'a, Result<Vec<(NativePair, U256, U256)>, NativeRfqError>> {
        Box::pin(async move {
            self.pair_calls.fetch_add(1, Ordering::SeqCst);
            Ok(requests
                .iter()
                .filter_map(|(pair, amount_in)| {
                    self.indicatives
                        .iter()
                        .find(|(candidate, _)| candidate == pair)
                        .map(|(_, amount_out)| (*pair, *amount_in, *amount_out))
                })
                .collect())
        })
    }

    fn available_pairs<'a>(
        &'a self,
        _identity: crate::chain::NativeRfqProfile,
        pairs: &'a [NativePair],
    ) -> BoxFuture<'a, Result<Vec<NativePair>, NativeRfqError>> {
        Box::pin(async move {
            self.pair_calls.fetch_add(1, Ordering::SeqCst);
            Ok(pairs
                .iter()
                .filter(|pair| {
                    self.indicatives
                        .iter()
                        .any(|(candidate, _)| candidate == *pair)
                })
                .copied()
                .collect())
        })
    }

    fn firm_quote<'a>(
        &'a self,
        request: FirmQuoteRequest,
    ) -> BoxFuture<'a, Result<Option<ValidatedFirmQuote>, NativeRfqError>> {
        Box::pin(async move {
            self.firm_calls.fetch_add(1, Ordering::SeqCst);
            self.requests.lock().unwrap().push(request);
            tokio::time::sleep(self.delay).await;
            Ok(Some(mock_validated_quote(request, self.amount_out)))
        })
    }
}

fn mixed_config() -> Config {
    let authorizer = NativeBeneficiaryAuthorizer::from_secret(TEST_BENEFICIARY_KEY).unwrap();
    Config {
        profile: &MIXED_TEST_PROFILE,
        rpc_url: MIXED_TEST_PROFILE.public_rpc.to_string(),
        logs_rpc_url: MIXED_TEST_PROFILE.public_rpc.to_string(),
        indexer_url: None,
        native_rfq: Some(
            NativeRfqConfig::new(
                "https://v2.api.native.org/swap-api-v2/",
                "test-api-key",
                Duration::from_millis(500),
                60,
                10,
                authorizer,
            )
            .unwrap(),
        ),
        fee_bps: 0,
        fee_receiver: None,
        positive_slippage_max_bps: 0,
        positive_slippage_recipient: None,
        port: 0,
        quote_timeout: 5,
    }
}

fn mixed_observation(token_in: Address, token_out: Address) -> ObservedSnapshot {
    ObservedSnapshot {
        snapshot: Snapshot {
            block: 1,
            settler: Some(MIXED_SETTLER),
            v3: Vec::new(),
            v2: vec![(
                V2Pool {
                    protocol: V2Protocol::PANCAKEV2,
                    address: Address::repeat_byte(0x88),
                    token0: WBNB,
                    token1: BSC_USDT,
                    fee_bps: 25,
                },
                V2State {
                    reserve0: U256::from(10u64).pow(U256::from(24u64)),
                    reserve1: U256::from(10u64).pow(U256::from(24u64)),
                },
            )],
            ekubo: Vec::new(),
        },
        screening: Default::default(),
        universe: crate::universe::RouteUniverse::profile_only(
            &MIXED_TEST_PROFILE,
            token_in,
            token_out,
        )
        .unwrap(),
        topology_fences: None,
        block_id: BlockId::hash_canonical(B256::repeat_byte(0x33)),
        block_timestamp: 1_800_000_000,
        observed_at: Instant::now(),
    }
}

fn mixed_request(token_in: Address, token_out: Address, amount_in: U256) -> QuoteRequest {
    let taker = Address::repeat_byte(0x99);
    QuoteRequest {
        chain_id: MIXED_TEST_PROFILE.chain_id,
        token_in: format!("{token_in:#x}"),
        token_out: format!("{token_out:#x}"),
        amount_in: AmountIn::Str(amount_in.to_string()),
        slippage_bps: 50,
        recipient: Some(format!("{taker:#x}")),
        sender: Some(format!("{taker:#x}")),
        tx_origin: Some(format!("{taker:#x}")),
        deadline_seconds: 60,
        fee_bps: None,
    }
}

use crate::simulation::test_chain::{
    RevertFirst, SIMULATION_HEAD, SimulationChain, TOO_MUCH_SLIPPAGE, simulation_chain,
};

#[tokio::test(flavor = "multi_thread")]
async fn solver_builds_amm_then_native_as_one_ordered_path() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let observation = mixed_observation(WBNB, MIXED_STOCK);
    let expected_prefix =
        PreparedRoutes::for_profile(&observation.snapshot, &MIXED_TEST_PROFILE, WBNB, BSC_USDT)
            .unwrap()
            .try_solve_single_quantized(amount_in, *ALLOC_CHUNKS)
            .unwrap()
            .expect("WBNB/USDT prefix");
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
    engine.cache_snapshot_for_test(WBNB, MIXED_STOCK, observation);
    let native_out = U256::from(2u64) * amount_in;
    let source = PlannedNativeSource::with_indicatives(
        vec![
            (
                NativePair::new(WBNB, MIXED_STOCK),
                amount_in * U256::from(2u64),
            ),
            (
                NativePair::new(BSC_USDT, MIXED_STOCK),
                amount_in * U256::from(3u64),
            ),
        ],
        native_out,
    );

    let response = quote_swap_bounded(
        &mixed_config(),
        &engine,
        mixed_request(WBNB, MIXED_STOCK, amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        Some(&source),
    )
    .await
    .unwrap();

    assert_eq!(response.liquidity_source, "mixed");
    assert_eq!(response.amount_out_gross, native_out.to_string());
    assert!(response.certificate.is_none());
    assert!(response.coverage.is_none());
    assert!(response.tx.is_some());
    assert_eq!(response.entrypoint, Some("executeWithNativeAuthorization"));
    assert_eq!(
        response.authorization_deadline,
        Some(Some(response.deadline))
    );
    assert_eq!(response.simulation.as_ref().unwrap().status, "simulated");
    server.abort();
    assert_eq!(response.route.len(), 1);
    assert_eq!(response.route[0].hops.len(), 2);
    assert!(matches!(response.route[0].hops[0], HopJson::V2 { .. }));
    assert!(matches!(
        response.route[0].hops[1],
        HopJson::NativeRfq { .. }
    ));
    assert_eq!(source.pair_calls.load(Ordering::SeqCst), 1);
    assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
    let requests = source.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].token_in, BSC_USDT);
    assert_eq!(requests[0].token_out, MIXED_STOCK);
    assert_eq!(requests[0].amount_in, expected_prefix.amount_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn solver_reprices_amm_tail_from_native_firm_output() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let native_out = U256::from(3u64) * amount_in;
    let observation = mixed_observation(MIXED_STOCK, WBNB);
    let expected_suffix =
        PreparedRoutes::for_profile(&observation.snapshot, &MIXED_TEST_PROFILE, BSC_USDT, WBNB)
            .unwrap()
            .try_solve_single_quantized(native_out, *ALLOC_CHUNKS)
            .unwrap()
            .expect("USDT/WBNB suffix");
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
    engine.cache_snapshot_for_test(MIXED_STOCK, WBNB, observation);
    let source = PlannedNativeSource::with_indicatives(
        vec![
            (
                NativePair::new(MIXED_STOCK, WBNB),
                amount_in * U256::from(2u64),
            ),
            (
                NativePair::new(MIXED_STOCK, BSC_USDT),
                amount_in * U256::from(3u64),
            ),
        ],
        native_out,
    );

    let response = quote_swap_bounded(
        &mixed_config(),
        &engine,
        mixed_request(MIXED_STOCK, WBNB, amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        Some(&source),
    )
    .await
    .unwrap();

    assert_eq!(response.liquidity_source, "mixed");
    assert_eq!(
        response.amount_out_gross,
        expected_suffix.amount_out.to_string()
    );
    assert!(response.tx.is_some());
    assert_eq!(response.simulation.as_ref().unwrap().status, "simulated");
    server.abort();
    assert_eq!(response.route.len(), 1);
    assert_eq!(response.route[0].hops.len(), 2);
    assert!(matches!(
        response.route[0].hops[0],
        HopJson::NativeRfq { .. }
    ));
    assert!(matches!(response.route[0].hops[1], HopJson::V2 { .. }));
    assert_eq!(source.pair_calls.load(Ordering::SeqCst), 1);
    assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
    let requests = source.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].token_in, MIXED_STOCK);
    assert_eq!(requests[0].token_out, BSC_USDT);
    assert_eq!(requests[0].amount_in, amount_in);
}

#[tokio::test(flavor = "multi_thread")]
async fn non_stock_endpoints_never_query_native() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    assert!(MIXED_TEST_PROFILE.connectors.contains(&MIXED_STOCK));
    let observation = mixed_observation(WBNB, BSC_USDT);
    let chain = SimulationChain::funded();
    let (rpc, server) = simulation_chain(chain.clone());
    let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
    engine.cache_snapshot_for_test(WBNB, BSC_USDT, observation);
    let source = PlannedNativeSource::with_indicatives(
        vec![(
            NativePair::new(WBNB, BSC_USDT),
            amount_in * U256::from(100u64),
        )],
        amount_in * U256::from(100u64),
    );

    let response = quote_swap_bounded(
        &mixed_config(),
        &engine,
        mixed_request(WBNB, BSC_USDT, amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        Some(&source),
    )
    .await
    .unwrap();

    assert_eq!(response.liquidity_source, "amm");
    assert!(response.tx.is_some());
    let holder = MIXED_TEST_PROFILE.settler.unwrap().allowance_holder;
    assert_eq!(response.allowance_holder, Some(addrhex(holder)));
    assert_eq!(response.entrypoint, Some("execute"));
    assert_eq!(response.authorization_deadline, Some(None));
    let approval = response.approval.clone().unwrap().unwrap();
    assert_eq!(approval.spender, addrhex(holder));
    assert_eq!(approval.amount, amount_in.to_string());
    let simulation = response.simulation.clone().unwrap();
    assert_eq!(simulation.status, "simulated");
    assert_eq!(simulation.block, SIMULATION_HEAD);
    assert_eq!(
        simulation.block_hash,
        format!("{:#x}", B256::repeat_byte(0x44))
    );
    assert_eq!(simulation.gas_estimate.as_deref(), Some("200000"));
    assert_eq!(response.issues, Some(Issues::default()));
    let mut calls = chain.calls();
    calls.sort();
    assert_eq!(
        calls,
        [
            "eth_call",
            "eth_call",
            "eth_call",
            "eth_estimateGas",
            "eth_gasPrice",
            "eth_getBalance",
            "eth_getBlockByNumber",
        ]
    );
    assert!(response.route[0].hops.iter().all(|hop| matches!(
        hop,
        HopJson::V2 {
            venue: "pancakev2",
            ..
        }
    )));
    server.abort();
    assert!(!response.meta.rfq_attempted);
    assert!(!response.meta.rfq_quoted);
    assert!(!response.meta.rfq_selected);
    assert_eq!(response.meta.rfq_ms, 0);
    assert_eq!(source.pair_calls.load(Ordering::SeqCst), 0);
    assert_eq!(source.firm_calls.load(Ordering::SeqCst), 0);
    assert!(response.route.iter().all(|leg| {
        leg.hops
            .iter()
            .all(|hop| !matches!(hop, HopJson::NativeRfq { .. }))
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn native_draft_ties_prefer_direct_and_still_use_one_firm_quote() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let observation = mixed_observation(WBNB, MIXED_STOCK);
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
    engine.cache_snapshot_for_test(WBNB, MIXED_STOCK, observation);
    let tied_out = amount_in * U256::from(3u64);
    let source = PlannedNativeSource::with_indicatives(
        vec![
            (NativePair::new(WBNB, MIXED_STOCK), tied_out),
            (NativePair::new(BSC_USDT, MIXED_STOCK), tied_out),
        ],
        tied_out,
    );

    let response = quote_swap_bounded(
        &mixed_config(),
        &engine,
        mixed_request(WBNB, MIXED_STOCK, amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        Some(&source),
    )
    .await
    .unwrap();

    assert_eq!(response.liquidity_source, "native_rfq");
    assert_eq!(response.simulation.as_ref().unwrap().status, "simulated");
    assert!(matches!(
        response.route[0].hops[0],
        HopJson::NativeRfq {
            venue: "native",
            ..
        }
    ));
    server.abort();
    assert_eq!(response.route.len(), 1);
    assert_eq!(response.route[0].hops.len(), 1);
    assert!(matches!(
        response.route[0].hops[0],
        HopJson::NativeRfq { .. }
    ));
    assert_eq!(source.pair_calls.load(Ordering::SeqCst), 1);
    assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
    let requests = source.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].token_in, WBNB);
    assert_eq!(requests[0].token_out, MIXED_STOCK);
    assert_eq!(requests[0].amount_in, amount_in);
}

#[tokio::test]
async fn native_draft_ties_prefer_last_over_first() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let first_indicative_out = amount_in * U256::from(2u64);
    let mut observation = mixed_observation(WBNB, MIXED_STOCK);
    observation.snapshot.v2.push((
        V2Pool {
            protocol: V2Protocol::PANCAKEV2,
            address: Address::repeat_byte(0x89),
            token0: BSC_USDT,
            token1: MIXED_STOCK,
            fee_bps: 25,
        },
        V2State {
            reserve0: U256::from(10u64).pow(U256::from(24u64)),
            reserve1: U256::from(10u64).pow(U256::from(24u64)),
        },
    ));
    let prefix =
        PreparedRoutes::for_profile(&observation.snapshot, &MIXED_TEST_PROFILE, WBNB, BSC_USDT)
            .unwrap()
            .try_solve_single_quantized(amount_in, *ALLOC_CHUNKS)
            .unwrap()
            .expect("WBNB/USDT prefix");
    let first_final_out = PreparedRoutes::for_profile(
        &observation.snapshot,
        &MIXED_TEST_PROFILE,
        BSC_USDT,
        MIXED_STOCK,
    )
    .unwrap()
    .try_solve_single_quantized(first_indicative_out, *ALLOC_CHUNKS)
    .unwrap()
    .expect("USDT/stock suffix")
    .amount_out;
    let engine = Engine::for_profile(
        crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
        &MIXED_TEST_PROFILE,
    );
    let stamped = engine.cache_snapshot_for_test(WBNB, MIXED_STOCK, observation);
    let source = PlannedNativeSource::with_indicatives(
        vec![
            (NativePair::new(BSC_USDT, MIXED_STOCK), first_final_out),
            (NativePair::new(WBNB, BSC_USDT), first_indicative_out),
        ],
        first_final_out,
    );

    let (draft, _) = choose_native_draft(
        &source,
        *MIXED_NATIVE_RFQ,
        (WBNB, MIXED_STOCK),
        BSC_USDT,
        amount_in,
        Some(prefix),
        &stamped,
        &MIXED_TEST_PROFILE,
        None,
        &SolverBudget::unlimited(),
    )
    .await
    .unwrap();

    assert!(matches!(draft, Some(NativeDraft::Last { .. })));
    assert_eq!(source.pair_calls.load(Ordering::SeqCst), 1);
    assert_eq!(source.firm_calls.load(Ordering::SeqCst), 0);
}

async fn amm_quote_against(chain: SimulationChain) -> anyhow::Result<QuoteResponse> {
    amm_quote_priced_at(chain, 1, Default::default()).await
}

/// The WBNB/USDT snapshot of `mixed_observation`, at `block`.
fn amm_observation_at(block: u64) -> ObservedSnapshot {
    let mut observation = mixed_observation(WBNB, BSC_USDT);
    observation.snapshot.block = block;
    observation
}

/// An AMM quote priced on a snapshot of `block`, checked against `chain`
/// at `SIMULATION_HEAD`. `engine` is filled in before the quote starts, so
/// the chain's hooks can reach the engine.
async fn amm_quote_priced_at(
    chain: SimulationChain,
    block: u64,
    engine: Arc<std::sync::OnceLock<Arc<Engine>>>,
) -> anyhow::Result<QuoteResponse> {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let (rpc, server) = simulation_chain(chain);
    let engine = engine
        .get_or_init(|| Engine::for_profile(rpc, &MIXED_TEST_PROFILE))
        .clone();
    engine.cache_snapshot_for_test(WBNB, BSC_USDT, amm_observation_at(block));
    let result = quote_swap_bounded(
        &mixed_config(),
        &engine,
        mixed_request(WBNB, BSC_USDT, amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await;
    server.abort();
    result
}

#[tokio::test(flavor = "multi_thread")]
async fn short_allowance_skips_simulation_and_names_the_approval() {
    let chain = SimulationChain {
        allowance: U256::from(7u64),
        ..SimulationChain::funded()
    };
    let response = amm_quote_against(chain.clone()).await.unwrap();

    let simulation = response.simulation.unwrap();
    assert_eq!(simulation.status, "skipped");
    assert_eq!(simulation.reason, Some("allowance"));
    assert_eq!(simulation.gas_estimate, None);
    let issues = response.issues.unwrap();
    let shortfall = issues.allowance.unwrap();
    assert_eq!(shortfall.available, "7");
    assert_eq!(issues.balance, None);
    let approval = response.approval.unwrap().unwrap();
    assert_eq!(approval.current, "7");
    assert_eq!(approval.amount, shortfall.required);
    assert!(response.tx.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_that_reverts_for_want_of_the_allowance_is_not_a_failure() {
    // The call goes out beside the allowance read and reverts in
    // transferFrom; the shortfall, not the revert, is the answer.
    let chain = SimulationChain {
        allowance: U256::from(7u64),
        revert: true,
        ..SimulationChain::funded()
    };
    let response = amm_quote_against(chain.clone()).await.unwrap();

    let simulation = response.simulation.unwrap();
    assert_eq!(simulation.status, "skipped");
    assert_eq!(simulation.reason, Some("allowance"));
    assert!(response.issues.unwrap().allowance.is_some());
    assert!(response.tx.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn short_balance_is_reported_before_the_allowance() {
    let chain = SimulationChain {
        balance: U256::ZERO,
        allowance: U256::ZERO,
        ..SimulationChain::funded()
    };
    let response = amm_quote_against(chain).await.unwrap();

    let simulation = response.simulation.unwrap();
    assert_eq!(simulation.status, "skipped");
    assert_eq!(simulation.reason, Some("balance"));
    let issues = response.issues.unwrap();
    assert!(issues.balance.is_some() && issues.allowance.is_some());
}

fn estimates(chain: &SimulationChain) -> usize {
    chain
        .calls()
        .iter()
        .filter(|call| *call == "eth_estimateGas")
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reverting_transaction_is_not_offered() {
    let chain = SimulationChain {
        revert: true,
        ..SimulationChain::funded()
    };
    // Priced on the block it is checked at: the revert is the answer.
    let Err(error) = amm_quote_priced_at(chain.clone(), SIMULATION_HEAD, Default::default()).await
    else {
        panic!("a reverting transaction was offered");
    };

    let failed = error
        .downcast_ref::<simulation::SimulationFailed>()
        .expect("a revert is a failed simulation");
    assert_eq!(failed.block.number, SIMULATION_HEAD);
    assert_eq!(
        failed.revert.as_deref().map(|data| &data[..4]),
        Some(TOO_MUCH_SLIPPAGE.as_slice())
    );
    assert!(error.downcast_ref::<PricedBeforeCheck>().is_none());
    assert_eq!(estimates(&chain), 1);
}

/// A chain whose first check reverts because a trade landed after the
/// quote was priced; the engine then holds a snapshot of the new head.
fn chain_moving_on(
    engine: &Arc<std::sync::OnceLock<Arc<Engine>>>,
    revert: bool,
) -> SimulationChain {
    let engine = engine.clone();
    SimulationChain {
        revert,
        revert_first: Some(RevertFirst::new(move || {
            engine.get().expect("engine").cache_snapshot_for_test(
                WBNB,
                BSC_USDT,
                amm_observation_at(SIMULATION_HEAD),
            );
        })),
        ..SimulationChain::funded()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_check_failed_after_the_chain_moved_is_priced_again() {
    let engine = Arc::<std::sync::OnceLock<Arc<Engine>>>::default();
    let chain = chain_moving_on(&engine, false);

    let response = amm_quote_priced_at(chain.clone(), 1, engine)
        .await
        .expect("priced again from the block of the check");

    assert!(response.meta.repriced);
    assert_eq!(response.block, SIMULATION_HEAD);
    let simulation = response.simulation.unwrap();
    assert_eq!(simulation.status, "simulated");
    assert_eq!(simulation.block, SIMULATION_HEAD);
    assert_eq!(estimates(&chain), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_route_is_priced_again_only_once() {
    let engine = Arc::<std::sync::OnceLock<Arc<Engine>>>::default();
    let chain = chain_moving_on(&engine, true);

    let Err(error) = amm_quote_priced_at(chain.clone(), 1, engine).await else {
        panic!("a reverting transaction was offered");
    };

    let failed = error
        .downcast_ref::<simulation::SimulationFailed>()
        .expect("the second revert is the answer");
    assert_eq!(failed.block.number, SIMULATION_HEAD);
    assert!(error.downcast_ref::<PricedBeforeCheck>().is_none());
    assert_eq!(estimates(&chain), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_native_route_is_not_priced_again() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let chain = SimulationChain {
        revert: true,
        ..SimulationChain::funded()
    };
    let (rpc, server) = simulation_chain(chain.clone());
    let engine = Engine::for_profile(rpc, &MIXED_TEST_PROFILE);
    // Priced a block before the check.
    engine.cache_snapshot_for_test(WBNB, MIXED_STOCK, mixed_observation(WBNB, MIXED_STOCK));
    let source = PlannedNativeSource::with_indicatives(
        vec![
            (
                NativePair::new(WBNB, MIXED_STOCK),
                amount_in * U256::from(2u64),
            ),
            (
                NativePair::new(BSC_USDT, MIXED_STOCK),
                amount_in * U256::from(3u64),
            ),
        ],
        U256::from(2u64) * amount_in,
    );

    let result = quote_swap_bounded(
        &mixed_config(),
        &engine,
        mixed_request(WBNB, MIXED_STOCK, amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        Some(&source),
    )
    .await;
    server.abort();

    let Err(error) = result else {
        panic!("a reverting transaction was offered");
    };
    assert!(
        error
            .downcast_ref::<simulation::SimulationFailed>()
            .is_some()
    );
    assert!(error.downcast_ref::<PricedBeforeCheck>().is_none());
    // One firm quote, never a second one for the same request.
    assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
    assert_eq!(estimates(&chain), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn fixture_quotes_simulate_and_name_their_venue() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let reserve = U256::from(10u64).pow(U256::from(24u64));
    let pair = alloy_primitives::address!("00bf5210b24d371e3df88179da61b2cd83ab44ee");
    let observation = ObservedSnapshot {
        snapshot: Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0x5e)),
            v3: vec![],
            v2: vec![(
                V2Pool {
                    protocol: V2Protocol::UNIV2,
                    address: pair,
                    token0: FIXTURE_WETH,
                    token1: FIXTURE_USDT0,
                    fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
                },
                V2State {
                    reserve0: reserve,
                    reserve1: reserve,
                },
            )],
            ekubo: vec![],
        },
        ..empty_fixture_observation(Instant::now())
    };
    let observation = ObservedSnapshot {
        block_id: BlockId::hash_canonical(B256::repeat_byte(0x33)),
        ..observation
    };
    let chain = SimulationChain::funded();
    let (rpc, server) = simulation_chain(chain.clone());
    let engine = Engine::for_profile(rpc, &FIXTURE_PROFILE);
    engine.cache_snapshot_for_test(FIXTURE_WETH, FIXTURE_USDT0, observation);
    let taker = Address::repeat_byte(0x99);
    let cfg = Config {
        profile: &FIXTURE_PROFILE,
        rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
        logs_rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
        indexer_url: None,
        native_rfq: None,
        fee_bps: 0,
        fee_receiver: None,
        positive_slippage_max_bps: 0,
        positive_slippage_recipient: None,
        port: 0,
        quote_timeout: 5,
    };

    let response = quote_swap_bounded(
        &cfg,
        &engine,
        QuoteRequest {
            chain_id: FIXTURE_PROFILE.chain_id,
            token_in: format!("{FIXTURE_WETH:#x}"),
            token_out: format!("{FIXTURE_USDT0:#x}"),
            amount_in: AmountIn::Str(amount_in.to_string()),
            slippage_bps: 50,
            recipient: Some(format!("{taker:#x}")),
            sender: None,
            tx_origin: None,
            deadline_seconds: 120,
            fee_bps: None,
        },
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await
    .unwrap();
    server.abort();

    assert_eq!(
        response.block_hash,
        format!("{:#x}", B256::repeat_byte(0x33))
    );
    assert_eq!(response.block_timestamp, 1_000);
    assert_eq!(
        response.allowance_holder,
        Some(addrhex(crate::chain::FIXTURE_ALLOWANCE_HOLDER))
    );
    let simulation = response.simulation.unwrap();
    assert_eq!(simulation.status, "simulated");
    assert!(matches!(
        response.route[0].hops[0],
        HopJson::V2 {
            protocol: "univ2",
            venue: "univ2",
            ..
        }
    ));
    let value = serde_json::to_value(&response.route[0].hops[0]).unwrap();
    assert_eq!(value["venue"], "univ2");
}

#[tokio::test(flavor = "multi_thread")]
async fn native_only_quote_rejects_a_stale_settler_observation() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let token_out = Address::repeat_byte(0xa6);
    let mut observation = mixed_observation(MIXED_STOCK, token_out);
    observation.observed_at = Instant::now()
        .checked_sub(Duration::from_millis(1_500))
        .unwrap();
    let engine = Engine::for_profile(
        crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
        &MIXED_TEST_PROFILE,
    );
    engine.cache_snapshot_for_test(MIXED_STOCK, token_out, observation);
    let source = PlannedNativeSource::new(
        vec![NativePair::new(MIXED_STOCK, token_out)],
        amount_in * U256::from(2u64),
    )
    // 2.4 s old after the wait: past the bound and its finishing grace.
    .with_delay(Duration::from_millis(900));

    let result = quote_swap_bounded(
        &mixed_config(),
        &engine,
        mixed_request(MIXED_STOCK, token_out, amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        Some(&source),
    )
    .await;
    let error = match result {
        Ok(_) => panic!("stale Settler observation was accepted"),
        Err(error) => error,
    };

    assert_eq!(
        error
            .downcast_ref::<RpcUnavailable>()
            .map(|marker| marker.0),
        Some("snapshot freshness")
    );
    assert_eq!(source.firm_calls.load(Ordering::SeqCst), 1);
}

fn fixture_weth_usdt0_v2(reserve_weth: U256, reserve_usdt0: U256) -> (V2Pool, V2State) {
    (
        V2Pool {
            protocol: V2Protocol::UNIV2,
            address: alloy_primitives::address!("00bf5210b24d371e3df88179da61b2cd83ab44ee"),
            token0: FIXTURE_WETH,
            token1: FIXTURE_USDT0,
            fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
        },
        V2State {
            reserve0: reserve_weth,
            reserve1: reserve_usdt0,
        },
    )
}

fn fixture_config() -> Config {
    Config {
        profile: &FIXTURE_PROFILE,
        rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
        logs_rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
        indexer_url: None,
        native_rfq: None,
        fee_bps: 0,
        fee_receiver: None,
        positive_slippage_max_bps: 0,
        positive_slippage_recipient: None,
        port: 0,
        quote_timeout: 5,
    }
}

fn fixture_request(amount_in: U256) -> QuoteRequest {
    QuoteRequest {
        chain_id: FIXTURE_PROFILE.chain_id,
        token_in: format!("{FIXTURE_WETH:#x}"),
        token_out: format!("{FIXTURE_USDT0:#x}"),
        amount_in: AmountIn::Str(amount_in.to_string()),
        slippage_bps: 50,
        recipient: Some(format!("{:#x}", Address::repeat_byte(0x99))),
        sender: None,
        tx_origin: None,
        deadline_seconds: 120,
        fee_bps: None,
    }
}

/// An engine whose resident state holds `pool` at block 2 and whose
/// per-pair memory holds the deep WETH/USDT0 pair at block 1.
fn fixture_engine_with_resident(rpc: crate::rpc::Rpc, pool: (V2Pool, V2State)) -> Arc<Engine> {
    fixture_engine_with_resident_pools(rpc, vec![pool], &[])
}

/// `fixture_engine_with_resident` with `pools`, `connectors` resident
/// connectors.
fn fixture_engine_with_resident_pools(
    rpc: crate::rpc::Rpc,
    pools: Vec<(V2Pool, V2State)>,
    connectors: &[Address],
) -> Arc<Engine> {
    fixture_engine_with_resident_connectors(rpc, pools, connectors, Vec::new())
}

/// `fixture_engine_with_resident_pools` whose resident state also admits
/// `others` where they have pools.
fn fixture_engine_with_resident_connectors(
    rpc: crate::rpc::Rpc,
    pools: Vec<(V2Pool, V2State)>,
    connectors: &[Address],
    others: Vec<Address>,
) -> Arc<Engine> {
    fixture_engine_with_resident_state(rpc, Vec::new(), pools, connectors, others)
}

/// `fixture_engine_with_resident_connectors` with V3 pools as well.
fn fixture_engine_with_resident_state(
    rpc: crate::rpc::Rpc,
    v3: Vec<(crate::pools::V3Pool, crate::pools::V3State)>,
    pools: Vec<(V2Pool, V2State)>,
    connectors: &[Address],
    others: Vec<Address>,
) -> Arc<Engine> {
    let resident = crate::resident::Resident::with_connectors(
        &FIXTURE_PROFILE,
        rpc.clone(),
        crate::resident::Settings {
            list_url: "http://127.0.0.1:1/pools".to_string(),
            poll: Duration::from_secs(1),
            connectors: Vec::new(),
            full_read: None,
        },
        vec![FIXTURE_WETH, FIXTURE_USDT0],
        connectors.iter().copied().chain(others).collect(),
    )
    .unwrap();
    resident.publish_for_test(
        Snapshot {
            block: 2,
            settler: Some(Address::repeat_byte(0x5e)),
            v3,
            v2: pools,
            ekubo: vec![],
        },
        crate::rpc::CanonicalBlock {
            number: 2,
            hash: B256::repeat_byte(0x22),
            timestamp: 1_002,
        },
        Instant::now(),
    );
    let engine = Engine::for_profile_with_resident(rpc, &FIXTURE_PROFILE, None, Some(resident));
    let reserve = U256::from(10u64).pow(U256::from(24u64));
    let observation = ObservedSnapshot {
        snapshot: Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0x5e)),
            v3: vec![],
            v2: vec![fixture_weth_usdt0_v2(reserve, reserve)],
            ekubo: vec![],
        },
        block_id: BlockId::hash_canonical(B256::repeat_byte(0x11)),
        ..empty_fixture_observation(Instant::now())
    };
    engine.cache_snapshot_for_test(FIXTURE_WETH, FIXTURE_USDT0, observation);
    engine
}

#[tokio::test(flavor = "multi_thread")]
async fn a_covered_pair_is_quoted_from_the_resident_state() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let reserve = U256::from(10u64).pow(U256::from(24u64));
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    let engine = fixture_engine_with_resident(rpc, fixture_weth_usdt0_v2(reserve, reserve));
    let response = quote_swap_bounded(
        &fixture_config(),
        &engine,
        fixture_request(amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await
    .unwrap();
    server.abort();
    assert_eq!(response.meta.source, "resident");
    assert_eq!(response.meta.universe_source, "resident");
    assert_eq!(response.meta.snapshot_rpc_calls, 0);
    assert_eq!(response.block, 2);
    assert_eq!(
        response.block_hash,
        format!("{:#x}", B256::repeat_byte(0x22))
    );
    assert_eq!(response.simulation.unwrap().status, "simulated");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resident_connector_carries_a_route_the_resident_state_has_no_other_way_for() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let reserve = U256::from(10u64).pow(U256::from(24u64));
    let connector = alloy_primitives::address!("f5634d07bfcd83152164629679076ec413a25688");
    let pool = |address: u8, a: Address, b: Address| {
        let (token0, token1) = if a < b { (a, b) } else { (b, a) };
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: Address::repeat_byte(address),
                token0,
                token1,
                fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
            },
            V2State {
                reserve0: reserve,
                reserve1: reserve,
            },
        )
    };
    let pools = vec![
        pool(0xb1, FIXTURE_WETH, connector),
        pool(0xb2, connector, FIXTURE_USDT0),
    ];
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    let engine = fixture_engine_with_resident_pools(rpc, pools, &[connector]);
    let response = quote_swap_bounded(
        &fixture_config(),
        &engine,
        fixture_request(amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await
    .unwrap();
    server.abort();
    assert_eq!(response.meta.source, "resident");
    assert_eq!(response.meta.snapshot_rpc_calls, 0);
    assert_eq!(response.meta.universe_connector_count, 1);
    assert_eq!(response.block, 2);
    let through: Vec<(String, String)> = response
        .route
        .iter()
        .flat_map(|leg| &leg.hops)
        .map(|hop| match hop {
            HopJson::V2 {
                token_in,
                token_out,
                ..
            } => (token_in.clone(), token_out.clone()),
            _ => panic!("only V2 pools are resident"),
        })
        .collect();
    assert_eq!(
        through,
        vec![
            (format!("{FIXTURE_WETH:#x}"), format!("{connector:#x}")),
            (format!("{connector:#x}"), format!("{FIXTURE_USDT0:#x}")),
        ]
    );
    assert_eq!(response.simulation.unwrap().status, "simulated");
}

/// A resident WETH→USDT0 quote with a thin direct pool at one for one and
/// a USDC route on deep pools paying `usdc_per_weth_bps` / 10⁴ per WETH.
async fn quote_beside_a_usdc_route(usdc_per_weth_bps: u64) -> QuoteResponse {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let deep = U256::from(10u64).pow(U256::from(24u64));
    let pool = |address: u8, a: Address, b: Address, reserve_a: U256, reserve_b: U256| {
        let ((token0, reserve0), (token1, reserve1)) = if a < b {
            ((a, reserve_a), (b, reserve_b))
        } else {
            ((b, reserve_b), (a, reserve_a))
        };
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: Address::repeat_byte(address),
                token0,
                token1,
                fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
            },
            V2State { reserve0, reserve1 },
        )
    };
    let thin = U256::from(10u64).pow(U256::from(20u64));
    let pools = vec![
        pool(0xb1, FIXTURE_WETH, FIXTURE_USDT0, thin, thin),
        pool(
            0xb2,
            FIXTURE_WETH,
            crate::chain::FIXTURE_USDC,
            deep,
            deep * U256::from(usdc_per_weth_bps) / U256::from(10_000),
        ),
        pool(0xb3, crate::chain::FIXTURE_USDC, FIXTURE_USDT0, deep, deep),
    ];
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    let engine =
        fixture_engine_with_resident_connectors(rpc, pools, &[], vec![crate::chain::FIXTURE_USDC]);
    let quote = || async {
        quote_swap_bounded(
            &fixture_config(),
            &engine,
            fixture_request(amount_in),
            SolverBudget::for_duration(Duration::from_secs(5)),
            Arc::new(Semaphore::new(1)),
            None,
        )
        .await
        .unwrap()
    };
    let response = quote().await;
    // The same request at the same block widens the same way: nothing is
    // remembered between quotes.
    let again = quote().await;
    server.abort();
    assert_eq!(response.meta.source, "resident");
    assert_eq!(response.meta.widening_candidates, 1);
    assert_eq!(again.block, response.block);
    assert_eq!(again.amount_out_gross, response.amount_out_gross);
    assert_eq!(hops(&again), hops(&response));
    assert_eq!(again.meta.widened, response.meta.widened);
    assert_eq!(again.meta.widening_rounds, response.meta.widening_rounds);
    response
}

fn hops(response: &QuoteResponse) -> Vec<(String, String)> {
    response
        .route
        .iter()
        .flat_map(|leg| &leg.hops)
        .map(|hop| match hop {
            HopJson::V2 {
                token_in,
                token_out,
                ..
            } => (token_in.clone(), token_out.clone()),
            _ => panic!("only V2 pools are resident"),
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resident_quote_admits_a_connector_its_probe_finds_better() {
    let response = quote_beside_a_usdc_route(20_000).await;
    assert_eq!(response.meta.widened, vec![crate::chain::FIXTURE_USDC]);
    assert_eq!(response.meta.widening_rounds, 1);
    assert_eq!(response.meta.widening_end, "settled");
    assert_eq!(response.meta.widening_left_out, 0);
    assert_eq!(response.meta.universe_connector_count, 1);
    assert!(
        hops(&response).contains(&(
            format!("{FIXTURE_WETH:#x}"),
            format!("{:#x}", crate::chain::FIXTURE_USDC)
        )),
        "routed through USDC"
    );
    // Widened in place: the same block, and a transaction built and
    // checked from the wider graph.
    assert_eq!(response.block, 2);
    assert_eq!(response.simulation.unwrap().status, "simulated");
    assert!(
        U256::from_str_radix(&response.amount_out_gross, 10).unwrap()
            > U256::from(10u64).pow(U256::from(18u64)),
        "more than the thin pool's one for one"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resident_quote_leaves_a_connector_probed_as_no_better_unrouted() {
    // Half a USDT0 per WETH through USDC cannot beat the direct pool at
    // one for one. Its probe says so without a second solve.
    let response = quote_beside_a_usdc_route(5_000).await;
    assert!(response.meta.widened.is_empty());
    assert_eq!(response.meta.widening_rounds, 0);
    assert_eq!(response.meta.widening_end, "settled");
    assert_eq!(response.meta.universe_connector_count, 0);
    assert_eq!(
        hops(&response),
        vec![(format!("{FIXTURE_WETH:#x}"), format!("{FIXTURE_USDT0:#x}"))]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_skeleton_through_two_candidates_admits_both() {
    // WETH → R1 → R2 → USDT0 on deep pools at two for one, beside a thin
    // direct pool at one for one. R1 and R2 are resident connectors.
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let deep = U256::from(10u64).pow(U256::from(24u64));
    let thin = U256::from(10u64).pow(U256::from(20u64));
    let (r1, r2) = (
        alloy_primitives::address!("f5634d07bfcd83152164629679076ec413a25688"),
        alloy_primitives::address!("444c8672b00fd1da2c135552a1ae06923424f5cc"),
    );
    let pool = |address: u8, a: Address, b: Address, reserve_a: U256, reserve_b: U256| {
        let ((token0, reserve0), (token1, reserve1)) = if a < b {
            ((a, reserve_a), (b, reserve_b))
        } else {
            ((b, reserve_b), (a, reserve_a))
        };
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: Address::repeat_byte(address),
                token0,
                token1,
                fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
            },
            V2State { reserve0, reserve1 },
        )
    };
    let pools = vec![
        pool(0xb1, FIXTURE_WETH, FIXTURE_USDT0, thin, thin),
        pool(0xb2, FIXTURE_WETH, r1, deep, deep * U256::from(2)),
        pool(0xb3, r1, r2, deep, deep),
        pool(0xb4, r2, FIXTURE_USDT0, deep, deep),
    ];
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    let engine = fixture_engine_with_resident_pools(rpc, pools, &[r1, r2]);
    let response = quote_swap_bounded(
        &fixture_config(),
        &engine,
        fixture_request(amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await
    .unwrap();
    server.abort();
    assert_eq!(response.meta.source, "resident");
    assert_eq!(response.meta.widening_candidates, 2);
    assert_eq!(response.meta.widened, vec![r1, r2]);
    assert_eq!(response.meta.widening_rounds, 1);
    assert_eq!(response.meta.widening_end, "settled");
    assert!(
        hops(&response).contains(&(format!("{r1:#x}"), format!("{r2:#x}"))),
        "routed through both"
    );
    assert_eq!(response.simulation.unwrap().status, "simulated");
}

/// A V2 pool holding `reserve_a` of `a` and `reserve_b` of `b`.
fn v2_pool(
    address: u8,
    a: Address,
    b: Address,
    reserve_a: U256,
    reserve_b: U256,
) -> (V2Pool, V2State) {
    let ((token0, reserve0), (token1, reserve1)) = if a < b {
        ((a, reserve_a), (b, reserve_b))
    } else {
        ((b, reserve_b), (a, reserve_a))
    };
    (
        V2Pool {
            protocol: V2Protocol::UNIV2,
            address: Address::repeat_byte(address),
            token0,
            token1,
            fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
        },
        V2State { reserve0, reserve1 },
    )
}

const DUST_CONNECTOR: Address =
    alloy_primitives::address!("f5634d07bfcd83152164629679076ec413a25688");

/// WETH/USDT0 at 2,500 USDT0 a WETH with $25M a side, and a resident
/// connector R whose two pools hold $250 and $500 a side at twice that price:
/// at the margin a WETH fetches about 4,500 USDT0 through R.
fn dust_connector_pools() -> Vec<(V2Pool, V2State)> {
    let e = |power: u64| U256::from(10u64).pow(U256::from(power));
    vec![
        v2_pool(
            0xd1,
            FIXTURE_WETH,
            FIXTURE_USDT0,
            e(22),
            U256::from(25u64) * e(12),
        ),
        v2_pool(0xd2, FIXTURE_WETH, DUST_CONNECTOR, e(17), e(20)),
        v2_pool(
            0xd3,
            DUST_CONNECTOR,
            FIXTURE_USDT0,
            e(20),
            U256::from(5u64) * e(8),
        ),
    ]
}

async fn dust_quote(
    pools: Vec<(V2Pool, V2State)>,
    connectors: &[Address],
    request: QuoteRequest,
) -> QuoteResponse {
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    let engine = fixture_engine_with_resident_pools(rpc, pools, connectors);
    let response = quote_swap_bounded(
        &fixture_config(),
        &engine,
        request,
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await
    .unwrap();
    server.abort();
    assert_eq!(response.meta.source, "resident");
    response
}

#[tokio::test(flavor = "multi_thread")]
async fn a_thin_pool_still_trades_its_own_token() {
    // The same thin pools are R's own market: buying R goes through them.
    let response = dust_quote(
        dust_connector_pools(),
        &[DUST_CONNECTOR],
        QuoteRequest {
            token_in: format!("{FIXTURE_USDT0:#x}"),
            token_out: format!("{DUST_CONNECTOR:#x}"),
            ..fixture_request(U256::from(100_000_000u64))
        },
    )
    .await;
    assert_eq!(response.meta.widening_thin_left_out, 0);
    assert!(!response.meta.widening_thin_kept);
    assert_eq!(
        hops(&response).last().unwrap().1,
        format!("{DUST_CONNECTOR:#x}")
    );
    assert_eq!(response.simulation.unwrap().status, "simulated");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_candidate_past_a_thin_shared_hop_is_admitted_on_its_edge() {
    // KAOLA → WETH through a pool a thousandth the size of the sale, then
    // WETH → USDC → USDT0 about 25 bp better than WETH → USDT0. The sale
    // leaves the shared pool paying about a millionth of a WETH per KAOLA
    // at the margin, so what one more probe of KAOLA fetches is dust, but
    // every WETH the sale already bought gets the 25 bp. Found on a Morph
    // fork at block 28073500, 15 Oct 2026: a thin token → USDT0 lost 3 bp this
    // way.
    let kaola = alloy_primitives::address!("bdef3827ab5b4ae52458f0a2b2348720504f3ef9");
    let thin = U256::from(10u64).pow(U256::from(18u64));
    let deep = U256::from(10u64).pow(U256::from(24u64));
    let amount_in = thin * U256::from(1_000u64);
    let pool = |address: u8, a: Address, b: Address, reserve_a: U256, reserve_b: U256| {
        let ((token0, reserve0), (token1, reserve1)) = if a < b {
            ((a, reserve_a), (b, reserve_b))
        } else {
            ((b, reserve_b), (a, reserve_a))
        };
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: Address::repeat_byte(address),
                token0,
                token1,
                fee_bps: crate::chain::FIXTURE_V2_FEE_PPM / 100,
            },
            V2State { reserve0, reserve1 },
        )
    };
    let usdc = crate::chain::FIXTURE_USDC;
    let pools = vec![
        pool(0xc1, kaola, FIXTURE_WETH, thin, thin),
        pool(0xc2, FIXTURE_WETH, FIXTURE_USDT0, deep, deep),
        pool(
            0xc3,
            FIXTURE_WETH,
            usdc,
            deep,
            deep * U256::from(10_060u64) / U256::from(10_000u64),
        ),
        pool(0xc4, usdc, FIXTURE_USDT0, deep, deep),
    ];
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    let engine = fixture_engine_with_resident_connectors(rpc, pools, &[], vec![usdc]);
    let response = quote_swap_bounded(
        &fixture_config(),
        &engine,
        QuoteRequest {
            token_in: format!("{kaola:#x}"),
            ..fixture_request(amount_in)
        },
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await
    .unwrap();
    server.abort();
    assert_eq!(response.meta.source, "resident");
    assert_eq!(response.meta.widening_candidates, 1);
    assert_eq!(response.meta.widened, vec![usdc]);
    assert_eq!(response.meta.widening_rounds, 1);
    assert!(
        hops(&response).contains(&(format!("{FIXTURE_WETH:#x}"), format!("{usdc:#x}"))),
        "routed through USDC"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pair_the_resident_state_cannot_fill_is_asked_of_its_own_pools() {
    let amount_in = U256::from(10u64).pow(U256::from(18u64));
    let reserve = U256::from(10u64).pow(U256::from(24u64));
    let (rpc, server) = simulation_chain(SimulationChain::funded());
    // The listed pair holds one unit of USDT0: it covers the pair and has
    // a skeleton, but nothing fills.
    let engine =
        fixture_engine_with_resident(rpc, fixture_weth_usdt0_v2(reserve, U256::from(1u64)));
    let response = quote_swap_bounded(
        &fixture_config(),
        &engine,
        fixture_request(amount_in),
        SolverBudget::for_duration(Duration::from_secs(5)),
        Arc::new(Semaphore::new(1)),
        None,
    )
    .await
    .unwrap();
    server.abort();
    assert_eq!(response.meta.source, "memory");
    assert_eq!(response.meta.universe_source, "profile_only");
    assert_eq!(response.block, 1);
}

fn empty_fixture_observation(observed_at: Instant) -> ObservedSnapshot {
    ObservedSnapshot {
        snapshot: Snapshot {
            block: 1,
            settler: None,
            v3: vec![],
            v2: vec![],
            ekubo: vec![],
        },
        screening: Default::default(),
        universe: crate::universe::RouteUniverse::profile_only(
            &FIXTURE_PROFILE,
            FIXTURE_WETH,
            FIXTURE_USDT0,
        )
        .unwrap(),
        topology_fences: None,
        block_id: BlockId::number(1),
        block_timestamp: 1_000,
        observed_at,
    }
}

#[tokio::test]
async fn compute_queue_refreshes_a_snapshot_that_expires_while_waiting() {
    let cfg = Config {
        profile: &FIXTURE_PROFILE,
        rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
        logs_rpc_url: FIXTURE_PROFILE.public_rpc.to_string(),
        indexer_url: None,
        native_rfq: None,
        fee_bps: 0,
        fee_receiver: None,
        positive_slippage_max_bps: 0,
        positive_slippage_recipient: None,
        port: 0,
        quote_timeout: 5,
    };
    let engine = Engine::for_profile(
        crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
        &FIXTURE_PROFILE,
    );
    let seeded = engine.cache_snapshot_for_test(
        FIXTURE_WETH,
        FIXTURE_USDT0,
        empty_fixture_observation(Instant::now()),
    );
    let compute_slots = Arc::new(Semaphore::new(0));
    let task_slots = compute_slots.clone();
    let task_engine = engine.clone();
    let quote = tokio::spawn(async move {
        quote_swap_bounded(
            &cfg,
            &task_engine,
            QuoteRequest {
                chain_id: FIXTURE_PROFILE.chain_id,
                token_in: format!("{FIXTURE_WETH:#x}"),
                token_out: format!("{FIXTURE_USDT0:#x}"),
                amount_in: AmountIn::Str("1".to_string()),
                slippage_bps: 50,
                recipient: None,
                sender: None,
                tx_origin: None,
                deadline_seconds: 60,
                fee_bps: None,
            },
            SolverBudget::for_duration(Duration::from_secs(5)),
            task_slots,
            None,
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&seeded) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("quote did not reach compute admission with the seeded snapshot");
    tokio::time::sleep(Duration::from_millis(2_050)).await;
    compute_slots.add_permits(1);

    let result = tokio::time::timeout(Duration::from_secs(1), quote)
        .await
        .expect("quote did not refresh after compute admission")
        .expect("quote task panicked");
    let error = match result {
        Ok(_) => panic!("quote used the snapshot after it became stale in the compute queue"),
        Err(error) => error,
    };
    // The refresh asks this test's dead RPC for the head block, the first
    // read of a new snapshot. Pricing the stale one would ask it nothing.
    assert!(
        error
            .downcast_ref::<crate::rpc::RpcUnavailable>()
            .is_some_and(|marker| marker.0 == "eth_getBlockByNumber"),
        "{error:#}"
    );
    assert_eq!(compute_slots.available_permits(), 1);
}

fn test_route_universe(block: u64) -> RouteUniverseJson {
    RouteUniverseJson::new(
        56,
        block,
        B256::repeat_byte(0x11),
        RouteUniverseDiagnostics {
            source: "profile_only",
            fallback_stage: None,
            fallback_reason: None,
            scope: "profile",
            selector: "none",
            selection_scope: "profile",
            protocol_mask: 0,
            eligible_count: 0,
            connector_count: 0,
            shortlist_truncated: false,
            screened_count: 0,
            adjacency_fences: None,
            fingerprint: B256::repeat_byte(0x22),
        },
        None,
    )
}

fn validated_native_quote(
    amount_out: u64,
    deadline: u64,
    min_ttl_seconds: u64,
) -> ValidatedFirmQuote {
    ValidatedFirmQuote {
        target: Address::repeat_byte(0x11),
        pool: Address::repeat_byte(0x22),
        calldata: Default::default(),
        token_in: Address::repeat_byte(0x11),
        token_out: Address::repeat_byte(0x22),
        settler: Address::repeat_byte(0x33),
        expected_origin: Address::repeat_byte(0x55),
        amount_in: U256::ONE,
        amount_out: U256::from(amount_out),
        signer: Address::repeat_byte(0x55),
        nonce: U256::from(7u64),
        beneficiary: Address::repeat_byte(0x33),
        deadline,
        min_ttl_seconds,
        amount_in_offset: 36,
        amount_out_minimum_offset: 68,
        router_version: 6,
        observation: Some(crate::rfq::NativeQuoteObservation {
            number: 123,
            hash: B256::repeat_byte(0x44),
        }),
    }
}

fn native_request() -> FirmQuoteRequest {
    FirmQuoteRequest {
        identity: FIXTURE_NATIVE_RFQ,
        token_in: Address::repeat_byte(0x11),
        token_out: Address::repeat_byte(0x22),
        amount_in: U256::ONE,
        settler: Address::repeat_byte(0x33),
        beneficiary: Address::repeat_byte(0x44),
        tx_origin: Some(Address::repeat_byte(0x55)),
        slippage_bps: 50,
        expiry_seconds: 60,
        chain_timestamp: 1_800_000_000,
    }
}

struct SlowNativeSource {
    delay: Duration,
    calls: AtomicUsize,
}

impl NativeRfqSource for SlowNativeSource {
    fn indicative_quotes<'a>(
        &'a self,
        _identity: crate::chain::NativeRfqProfile,
        _requests: &'a [(NativePair, U256)],
    ) -> BoxFuture<'a, Result<Vec<(NativePair, U256, U256)>, NativeRfqError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn firm_quote<'a>(
        &'a self,
        _request: FirmQuoteRequest,
    ) -> BoxFuture<'a, Result<Option<ValidatedFirmQuote>, NativeRfqError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(None)
        })
    }
}

fn amm_plan(amount_out: u64) -> Plan {
    Plan {
        legs: Vec::new(),
        amount_out: U256::from(amount_out),
        universe_id: None,
    }
}

#[test]
fn native_selection_uses_the_final_amm_amount_and_rechecks_ttl() {
    let now = 1_000;
    let quote = validated_native_quote(101, now + 10, 10);

    assert!(native_quote_beats_amm(&quote, Some(&amm_plan(100)), now));
    assert!(!native_quote_beats_amm(&quote, Some(&amm_plan(101)), now));
    assert!(!native_quote_beats_amm(&quote, Some(&amm_plan(102)), now));
    assert!(native_quote_beats_amm(&quote, None, now));
    // A quote that won comparison must still lose to the retained AMM
    // plan if the final encoding check crosses the TTL boundary.
    assert!(!native_quote_beats_amm(
        &quote,
        Some(&amm_plan(100)),
        now + 1
    ));

    let stale = validated_native_quote(1_000, now + 9, 10);
    assert!(!native_quote_beats_amm(&stale, Some(&amm_plan(1)), now));
    assert!(!native_quote_beats_amm(&stale, None, now));
}

#[test]
fn native_response_deadline_is_the_tighter_execution_deadline() {
    let quote = validated_native_quote(100, 1_050, 10);
    assert_eq!(selected_deadline(1_100, Some(&quote)), 1_050);
    assert_eq!(selected_deadline(1_025, Some(&quote)), 1_025);
    assert_eq!(selected_deadline(1_100, None), 1_100);
}

#[test]
fn native_capacity_errors_never_become_amm_fallbacks() {
    for error in [
        NativeRfqError::Saturated,
        NativeRfqError::QueueTimeout,
        NativeRfqError::Api(201_005),
    ] {
        assert_eq!(
            native_result_or_fallback(Err(error.clone())).unwrap_err(),
            error
        );
    }
    assert!(
        native_result_or_fallback(Err(NativeRfqError::Transport))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn optional_native_timeout_is_not_amm_fallback() {
    let source = SlowNativeSource {
        delay: Duration::from_secs(2),
        calls: AtomicUsize::new(0),
    };
    let budget = SolverBudget::for_duration(Duration::from_millis(250));
    let started = Instant::now();

    let error = request_optional_native_quote(&source, native_request(), &budget)
        .await
        .unwrap_err();

    assert_eq!(error, NativeRfqError::QueueTimeout);
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        budget
            .remaining()
            .is_some_and(|remaining| !remaining.is_zero())
    );
}

#[tokio::test]
async fn missing_native_response_budget_is_not_amm_fallback() {
    let source = SlowNativeSource {
        delay: Duration::ZERO,
        calls: AtomicUsize::new(0),
    };
    let budget = SolverBudget::for_duration(OPTIONAL_RFQ_RESPONSE_RESERVE);

    let error = request_optional_native_quote(&source, native_request(), &budget)
        .await
        .unwrap_err();

    assert_eq!(error, NativeRfqError::QueueTimeout);
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_wait_that_expires_snapshot_rejects_amm_fallback() {
    let engine = Engine::for_profile(
        crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
        &FIXTURE_PROFILE,
    );
    let observed_at = Instant::now()
        .checked_sub(Duration::from_millis(1_500))
        .unwrap();
    let stamped = engine.cache_snapshot_for_test(
        FIXTURE_WETH,
        FIXTURE_USDT0,
        empty_fixture_observation(observed_at),
    );
    assert!(stamped.is_fresh());
    // 2.4 s old after the wait: past the bound and its finishing grace.
    let source = SlowNativeSource {
        delay: Duration::from_millis(900),
        calls: AtomicUsize::new(0),
    };

    let quote = request_optional_native_quote(
        &source,
        native_request(),
        &SolverBudget::for_duration(Duration::from_secs(2)),
    )
    .await
    .unwrap();

    assert!(quote.is_none());
    let error = fresh_amm_snapshot(&stamped).unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<RpcUnavailable>()
            .map(|marker| marker.0),
        Some("snapshot freshness")
    );
}

#[tokio::test]
async fn fresh_native_miss_still_allows_amm_fallback() {
    let engine = Engine::for_profile(
        crate::rpc::Rpc::connect("http://127.0.0.1:1").unwrap(),
        &FIXTURE_PROFILE,
    );
    let stamped = engine.cache_snapshot_for_test(
        FIXTURE_WETH,
        FIXTURE_USDT0,
        empty_fixture_observation(Instant::now()),
    );
    let source = SlowNativeSource {
        delay: Duration::ZERO,
        calls: AtomicUsize::new(0),
    };

    let quote = request_optional_native_quote(
        &source,
        native_request(),
        &SolverBudget::for_duration(Duration::from_secs(1)),
    )
    .await
    .unwrap();

    assert!(quote.is_none());
    assert!(fresh_amm_snapshot(&stamped).is_ok());
}

#[test]
fn quote_token_normalization_uses_the_selected_profile() {
    let token = Address::repeat_byte(0x44);
    let (input, output) = routed_tokens(&crate::chain::BSC_PROFILE, NATIVE, token);
    assert_eq!(input, crate::chain::BSC_PROFILE.wrapped_native);
    assert_ne!(input, crate::chain::ROBINHOOD_PROFILE.wrapped_native);
    assert_eq!(output, token);
}

#[test]
fn escalation_threshold_parses_bps_and_disables_at_zero() {
    assert_eq!(escalate_threshold_e4("1").unwrap(), 10_000);
    assert_eq!(escalate_threshold_e4("0.5").unwrap(), 5_000);
    assert_eq!(escalate_threshold_e4(" 2.25 ").unwrap(), 22_500);
    assert_eq!(escalate_threshold_e4("0").unwrap(), 0);
    assert_eq!(escalate_threshold_e4("-3").unwrap(), 0);
    for bad in ["0.1bp", "inf", "NaN", ""] {
        assert!(
            escalate_threshold_e4(bad).is_err(),
            "{bad:?} must be refused at startup"
        );
    }
}

fn quote_request_with_identities(
    recipient: Option<Address>,
    sender: Option<Address>,
    tx_origin: Option<Address>,
) -> QuoteRequest {
    serde_json::from_value(serde_json::json!({
        "chainId": 2818,
        "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
        "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
        "amountIn": "1",
        "recipient": recipient.map(addrhex),
        "sender": sender.map(addrhex),
        "txOrigin": tx_origin.map(addrhex),
    }))
    .expect("valid quote request")
}

#[test]
fn execution_identity_keeps_smart_account_sender_separate_from_evm_origin() {
    let recipient = Address::repeat_byte(0x33);
    let safe = Address::repeat_byte(0x44);
    let owner_eoa = Address::repeat_byte(0x55);
    let request = quote_request_with_identities(Some(recipient), Some(safe), Some(owner_eoa));

    let identities = parse_execution_identities(&request).unwrap();

    assert_eq!(identities.recipient, Some(recipient));
    assert_eq!(identities.sender, Some(safe));
    assert_eq!(identities.required_from, Some(safe));
    assert_eq!(identities.tx_origin, Some(owner_eoa));
}

#[test]
fn sender_defaults_to_recipient_without_inventing_an_evm_origin() {
    let recipient = Address::repeat_byte(0x33);
    let request = quote_request_with_identities(Some(recipient), None, None);

    let identities = parse_execution_identities(&request).unwrap();

    assert_eq!(identities.required_from, Some(recipient));
    assert_eq!(identities.tx_origin, None);
}

#[test]
fn tx_origin_requires_an_execution_request_and_must_be_nonzero() {
    let eoa = Address::repeat_byte(0x55);
    let without_recipient = quote_request_with_identities(None, None, Some(eoa));
    assert_eq!(
        parse_execution_identities(&without_recipient)
            .unwrap_err()
            .to_string(),
        "txOrigin requires recipient"
    );

    let zero_origin =
        quote_request_with_identities(Some(Address::repeat_byte(0x33)), None, Some(Address::ZERO));
    assert_eq!(
        parse_execution_identities(&zero_origin)
            .unwrap_err()
            .to_string(),
        "txOrigin must not be zero"
    );
}

#[test]
fn transaction_json_serializes_the_checked_sender_as_required_from() {
    let sender = Address::repeat_byte(0x11);
    let value = serde_json::to_value(TxJson {
        required_from: addrhex(sender),
        to: addrhex(Address::repeat_byte(0x22)),
        value: "0".to_string(),
        data: "0x".to_string(),
    })
    .expect("serializable");
    assert_eq!(value["requiredFrom"], addrhex(sender));
}

#[test]
fn quote_json_omits_missing_settler_identity() {
    let mut response = QuoteResponse {
        chain: "bsc",
        chain_id: 56,
        liquidity_source: "amm",
        slippage_bps: 50,
        deadline_seconds: 600,
        requested_fee_bps: None,
        recipient: None,
        sender: None,
        tx_origin: None,
        native_observation: None,
        block: 1,
        block_hash: format!("{:#x}", B256::repeat_byte(0x12)),
        block_timestamp: 99,
        route_universe: test_route_universe(1),
        settler: None,
        token_in: addrhex(Address::repeat_byte(1)),
        token_out: addrhex(Address::repeat_byte(2)),
        amount_in: "1".to_string(),
        amount_out_gross: "1".to_string(),
        price_impact_bps: None,
        mid_amount_out: None,
        fee_bps: 0,
        amount_out_net: "1".to_string(),
        min_amount_out_net: "1".to_string(),
        deadline: 1,
        route: Vec::new(),
        tx: None,
        allowance_target: None,
        allowance_holder: None,
        entrypoint: None,
        authorization_deadline: None,
        approval: None,
        simulation: None,
        issues: None,
        fee_receiver: None,
        positive_slippage: None,
        certificate: None,
        coverage: None,
        meta: QuoteMeta::default(),
    };
    let value = serde_json::to_value(&response).expect("serializable");
    assert!(value.get("settler").is_none());
    // Quote-only responses carry none of the transaction fields.
    for field in [
        "tx",
        "allowanceTarget",
        "allowanceHolder",
        "entrypoint",
        "authorizationDeadline",
        "approval",
        "simulation",
        "issues",
    ] {
        assert!(value.get(field).is_none(), "{field}");
    }
    assert_eq!(
        value["blockHash"],
        format!("{:#x}", B256::repeat_byte(0x12))
    );
    assert_eq!(value["blockTimestamp"], 99);
    assert!(value.get("nativeObservation").is_none());
    assert!(value["txOrigin"].is_null());
    assert_eq!(value["routeUniverse"]["version"], 1);
    assert_eq!(value["routeUniverse"]["chainId"], 56);
    assert_eq!(value["routeUniverse"]["canonicalBlock"]["number"], 1);
    assert_eq!(value["routeUniverse"]["scope"], "profile");
    assert_eq!(value["routeUniverse"]["selectionScope"], "profile");

    response.settler = Some(addrhex(Address::repeat_byte(3)));
    response.tx_origin = Some(addrhex(Address::repeat_byte(4)));
    response.native_observation = Some(CanonicalBlockJson {
        number: 123,
        hash: format!("{:#x}", B256::repeat_byte(0x55)),
    });
    let value = serde_json::to_value(&response).expect("serializable");
    assert_eq!(value["settler"], addrhex(Address::repeat_byte(3)));
    assert_eq!(value["txOrigin"], addrhex(Address::repeat_byte(4)));
    assert_eq!(value["nativeObservation"]["number"], 123);
    assert_eq!(
        value["nativeObservation"]["hash"],
        format!("{:#x}", B256::repeat_byte(0x55))
    );
}

#[test]
fn executable_fair_price_impact_is_ceil_bps_and_never_negative() {
    assert_eq!(
        price_impact_bps(U256::from(30), U256::from(29), U256::ONE, U256::ONE),
        334
    );
    assert_eq!(
        price_impact_bps(U256::from(100), U256::from(101), U256::ONE, U256::ONE),
        0
    );
    assert_eq!(
        price_impact_bps(U256::MAX, U256::ZERO, U256::MAX, U256::MAX),
        BPS_BASE
    );
}

/// v2 pools at the given fee tiers; these functions read only the fees, so
/// the reserves are placeholders
fn fee_snapshot(fee_bps: &[u32]) -> Snapshot {
    Snapshot {
        block: 1,
        settler: Some(Address::repeat_byte(0xfe)),
        v3: vec![],
        v2: fee_bps
            .iter()
            .enumerate()
            .map(|(i, &fee_bps)| {
                let pool = V2Pool {
                    protocol: V2Protocol::UP33V2,
                    address: Address::repeat_byte(i as u8 + 1),
                    token0: Address::repeat_byte(0xa0),
                    token1: Address::repeat_byte(0xb0),
                    fee_bps,
                };
                (
                    pool,
                    V2State {
                        reserve0: U256::ONE,
                        reserve1: U256::ONE,
                    },
                )
            })
            .collect(),
        ekubo: vec![],
    }
}

/// The emitted artifact has to be enough to re-derive the claim: take the
/// serialized dual point, feed it back to `bound_at`, and get the same
/// bound. That round trip is what makes `boundWei` checkable by someone
/// who never runs our solver.
#[test]
fn the_serialized_certificate_reproduces_its_own_bound() {
    let token_in = Address::repeat_byte(0xa0);
    let token_out = Address::repeat_byte(0xb0);
    let amount_in = U256::from(10u64).pow(U256::from(20u64));
    let mut snap = fee_snapshot(&[30, 30]);
    snap.v2[0].1 = V2State {
        reserve0: U256::from(10u64).pow(U256::from(23u64)),
        reserve1: U256::from(12u64) * U256::from(10u64).pow(U256::from(22u64)),
    };
    snap.v2[1].1 = V2State {
        reserve0: U256::from(4u64) * U256::from(10u64).pow(U256::from(22u64)),
        reserve1: U256::from(5u64) * U256::from(10u64).pow(U256::from(22u64)),
    };
    let plan = best_plan(&snap, token_in, token_out, amount_in, 256, 50).expect("plan");
    let json = certificate_json(
        certify(
            &crate::chain::ROBINHOOD_PROFILE,
            &snap,
            token_in,
            token_out,
            amount_in,
            &plan,
        ),
        false,
    );
    assert_eq!(json.status, "certified");
    assert_eq!(json.mode, "shadow");
    assert_eq!(json.scope, "materialized_route_universe");

    let prices: std::collections::HashMap<Address, certificate::Price> = json
        .prices
        .iter()
        .map(|price| {
            (
                price.token.parse().expect("address"),
                certificate::Price {
                    num: price.num.parse().expect("numerator"),
                    den: price.den.parse().expect("denominator"),
                },
            )
        })
        .collect();
    let (bound, _) = certificate::bound_at(
        &snap,
        token_in,
        amount_in,
        &prices,
        Some(&certificate::PoolSet::reachable(
            &crate::chain::ROBINHOOD_PROFILE,
            &snap,
            token_in,
            token_out,
        )),
        &certificate::PoolSet::of(&snap, &plan),
    )
    .expect("re-evaluated bound");
    assert_eq!(bound.to_string(), json.bound_wei.expect("bound"));
    assert!(bound >= plan.amount_out);
}

#[test]
fn an_uncertifiable_plan_reports_a_reason_instead_of_failing_the_quote() {
    let token_in = Address::repeat_byte(0xa0);
    let token_out = Address::repeat_byte(0xb0);
    let snap = fee_snapshot(&[30]);
    let empty = Plan {
        legs: Vec::new(),
        amount_out: U256::ZERO,
        universe_id: None,
    };
    let json = certificate_json(
        certify(
            &crate::chain::ROBINHOOD_PROFILE,
            &snap,
            token_in,
            token_out,
            U256::ONE,
            &empty,
        ),
        true,
    );
    assert_eq!(json.mode, "active");
    assert_eq!(json.status, "unavailable");
    assert!(json.reason.is_some());
    assert!(json.bound_wei.is_none());
}

#[test]
fn hop_json_uses_the_directional_v3_fee() {
    let token0 = Address::repeat_byte(0xa0);
    let token1 = Address::repeat_byte(0xb0);
    let mut snap = fee_snapshot(&[]);
    snap.v3.push((
        V3Pool {
            protocol: V3Protocol::SHERIFF,
            address: Address::repeat_byte(1),
            token0,
            token1,
            fee_ppm: 400,
            tick_spacing: 10,
            verify_pool_spacing: false,
            execution: Some(crate::pools::V3ExecutionMeta {
                fork_id: 41,
                pool_id: 0,
            }),
            v4: None,
            algebra: Some(AlgebraMeta {
                fee_0to1_ppm: 365,
                fee_1to0_ppm: 434,
            }),
        },
        V3State {
            sqrt_price: U256::ONE << 96usize,
            tick: 0,
            liquidity: U256::ONE,
            ticks: Vec::new().into(),
            pos: 0,
            lo_cover: 0,
            hi_cover: 0,
        },
    ));

    for (zero_for_one, expected) in [(true, 365), (false, 434)] {
        let HopJson::V3 { fee_ppm, .. } = hop_json(
            &snap,
            &Hop {
                kind: HopKind::V3,
                index: 0,
                zero_for_one,
                token_in: token0,
                token_out: token1,
            },
        )
        .expect("valid Sheriff metadata") else {
            panic!("v3 hop")
        };
        assert_eq!(fee_ppm, expected);
    }
}

fn leg(pools: &[usize], amount_out: u64) -> Leg {
    Leg {
        path: pools
            .iter()
            .map(|&index| Hop {
                kind: HopKind::V2,
                index,
                zero_for_one: true,
                token_in: Address::repeat_byte(0xa0),
                token_out: Address::repeat_byte(0xb0),
            })
            .collect(),
        amount_in: U256::ONE,
        amount_out: U256::from(amount_out),
        losses: vec![],
        slice_bps: BPS_BASE,
    }
}

#[test]
fn fee_free_out_compounds_hop_fees_instead_of_adding_them() {
    let snap = fee_snapshot(&[30, 30, 60]);
    // 30 bps off a hop's input: 997_000 of 1_000_000 arrives
    assert_eq!(
        fee_free_out(&snap, &leg(&[0], 997_000), U256::ONE, U256::ONE).expect("fits"),
        U256::from(1_000_000)
    );
    // two 30 bps hops keep 0.997² = 0.994009, slightly MORE than the 0.994 a
    // summed 60 bps keeps — so summing overstates the fee and lifts the
    // baseline above the truth. Small (0.09 bps here), but the product is
    // free, and it is what the pools actually charge.
    assert_eq!(
        fee_free_out(&snap, &leg(&[0, 1], 994_009), U256::ONE, U256::ONE).expect("fits"),
        U256::from(1_000_000)
    );
    assert_eq!(
        fee_free_out(&snap, &leg(&[2], 994_009), U256::ONE, U256::ONE).expect("fits"),
        U256::from(1_000_009)
    );
    assert_eq!(
        fee_free_out(&snap, &leg(&[0, 1, 0], 991_026_973), U256::ONE, U256::ONE)
            .expect("three-hop fee product fits"),
        U256::from(1_000_000_000u64)
    );
}

#[test]
fn mid_amount_out_undoes_each_leg_at_its_own_fee_then_scales_to_full_size() {
    let snap = fee_snapshot(&[30, 100]); // 0.30% and 1.00%
    let fair = Plan {
        legs: vec![leg(&[0], 997), leg(&[1], 990)],
        amount_out: U256::from(1_987),
        universe_id: None,
    };
    // each leg grosses up at the fee IT paid — 997/0.997 + 990/0.99 = 2000 —
    // and a share-weighted average of the two would land somewhere else
    let (fair_in, amount_in) = (U256::from(100), U256::from(10_000));
    let mid = mid_amount_out(&snap, &fair, fair_in, amount_in).expect("fits");
    assert_eq!(mid, U256::from(200_000));
    // the baseline must sit ABOVE the executable output it came from: that
    // gap IS the pool fee the old headline left out
    assert!(mid > fair.amount_out * U256::from(100));
}

#[test]
fn mid_amount_out_matches_direct_fee_rounding_vectors() {
    let snap = fee_snapshot(&[100]);
    let fair = Plan {
        legs: vec![leg(&[0], 220)],
        amount_out: U256::from(220),
        universe_id: None,
    };
    assert_eq!(
        mid_amount_out(&snap, &fair, U256::from(100), U256::from(10_000)).expect("fits"),
        U256::from(22_222)
    );

    let snap = fee_snapshot(&[30]);
    let fair = Plan {
        legs: vec![leg(&[0], 332)],
        amount_out: U256::from(332),
        universe_id: None,
    };
    assert_eq!(
        mid_amount_out(&snap, &fair, U256::ONE, U256::from(100)).expect("fits"),
        U256::from(33_299)
    );
}

#[test]
fn rounded_v2_probe_drops_both_reference_metrics_when_mid_is_below_full_output() {
    let mut snap = fee_snapshot(&[30]);
    snap.v2[0].1 = V2State {
        reserve0: U256::from(1_000_000_000_000u64),
        reserve1: U256::from(1_000_000_000_000u64),
    };
    let amount_in = U256::from(300);
    let fair_in = amount_in / U256::from(100);
    let (pool, state) = &snap.v2[0];
    let full_out = sim_v2(pool, state, true, amount_in)
        .expect("full sim")
        .amount_out;
    let fair_out = sim_v2(pool, state, true, fair_in)
        .expect("probe sim")
        .amount_out;
    assert_eq!((full_out, fair_out), (U256::from(299), U256::from(2)));

    let full = Plan {
        legs: vec![],
        amount_out: full_out,
        universe_id: None,
    };
    let fair = Plan {
        legs: vec![Leg {
            amount_in: fair_in,
            amount_out: fair_out,
            ..leg(&[0], 0)
        }],
        amount_out: fair_out,
        universe_id: None,
    };
    assert_eq!(
        mid_amount_out(&snap, &fair, fair_in, amount_in).expect("mid"),
        U256::from(200)
    );

    let (price_impact_bps, mid_amount_out) =
        reference_metrics(&snap, &full, Some(&fair), fair_in, amount_in).expect("metrics");
    assert_eq!((price_impact_bps, mid_amount_out), (None, None));
}

#[test]
fn mid_amount_out_rounds_once_per_split_leg_after_all_hop_fees() {
    let snap = fee_snapshot(&[30, 100, 30]);
    let fair = Plan {
        legs: vec![leg(&[0, 1], 987), leg(&[2], 332)],
        amount_out: U256::from(1_319),
        universe_id: None,
    };

    assert_eq!(
        mid_amount_out(&snap, &fair, U256::from(100), U256::from(10_000)).expect("fits"),
        U256::from(133_295)
    );
}

#[test]
fn mid_amount_out_uses_the_v3_fee_actually_charged() {
    let token0 = Address::repeat_byte(0xa0);
    let token1 = Address::repeat_byte(0xb0);
    let snap = Snapshot {
        block: 1,
        settler: Some(Address::repeat_byte(0xfe)),
        v3: vec![(
            V3Pool {
                protocol: V3Protocol::UNIV3,
                address: Address::repeat_byte(1),
                token0,
                token1,
                fee_ppm: 3_000,
                tick_spacing: 60,
                verify_pool_spacing: false,
                execution: Some(crate::pools::V3ExecutionMeta {
                    fork_id: 0,
                    pool_id: 3_000,
                }),
                v4: None,
                algebra: None,
            },
            V3State {
                sqrt_price: U256::ONE << 96usize,
                tick: 0,
                liquidity: U256::from(1_000_000_000_000u64),
                ticks: Vec::new().into(),
                pos: 0,
                lo_cover: -180_000,
                hi_cover: 180_000,
            },
        )],
        v2: vec![],
        ekubo: vec![],
    };
    let fair_in = U256::from(768);
    let amount_in = U256::from(76_800);
    let fair = quantized_plan(
        &snap,
        &best_plan(&snap, token0, token1, fair_in, 256, 50).expect("route"),
        fair_in,
    )
    .expect("quantized");

    assert_eq!(fair.amount_out, U256::from(764));
    let [fee] = fair.legs[0].losses.as_slice() else {
        panic!("one v3 fee")
    };
    assert_eq!((fee.gross, fee.net), (U256::from(768), U256::from(765)));
    assert_eq!(
        mid_amount_out(&snap, &fair, fair_in, amount_in).expect("fits"),
        U256::from(76_699)
    );
}
