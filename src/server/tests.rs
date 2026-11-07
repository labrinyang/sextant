use super::admission::{
    parse_compute_concurrency, parse_max_inflight_quotes, parse_quote_admission_wait,
    quote_time_limit,
};
use super::readiness::{
    READINESS_PROBE_TIMEOUT, READINESS_REFRESH, READINESS_TTL, ReadinessState, cached_readiness,
    spawn_readiness_refresher,
};
use super::responses::{
    QuoteGate, gate_quote_request, native_busy_response, no_route_response, quote_error_response,
    quote_error_status,
};
use super::startup::{
    MAX_QUOTE_TIMEOUT_SECS, NativeAdapter, NativeSettlerTarget, check_indexer_url,
    configured_indexer, configured_native_adapter, native_rfq_adapter_error, validate_config,
    validate_execution_settings, validate_profile, verify_native_authorization_signer,
    verify_native_pool_domain, verify_native_rfq_adapter, verify_rpc_chain, warmup_for_profile,
};
use super::{
    App, MAX_QUOTE_LOG_FIELD_BYTES, MAX_QUOTE_REQUEST_BYTES, handle_health, handle_metrics,
    handle_quote, quote_log_field,
};
use crate::abi;
use crate::budget::SolverBudgetExceeded;
use crate::chain::{ChainProfile, DiscoveryProfile, FIXTURE_PROFILE};
use crate::config::Config;
use crate::engine::Engine;
use crate::indexer::IndexerClient;
use crate::pools::{V2Pool, V2State};
use crate::quote_metrics::{QuoteMetrics, QuoteOutcome};
use crate::quotes::{NoRouteError, QuoteRequest};
use crate::rfq::{NativeRfqClient, NativeRfqError, NativeRfqSource};
use crate::rpc::{Rpc, RpcRejected, RpcUnavailable};
use crate::snapshot::Snapshot;
use crate::state::UpstreamIntegrityError;
use crate::topology::CatalogFences;
use alloy_primitives::{Address, B256, U256, address, keccak256};
use alloy_sol_types::SolCall;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::header::{ACCESS_CONTROL_EXPOSE_HEADERS, RETRY_AFTER};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::post;
use futures_util::{StreamExt, future::BoxFuture, stream};
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Barrier;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

// Native is enabled only inside these request-path tests so this exact
// fork can exercise its BSC migration profile. No transaction is emitted:
// the synthetic Native source below always returns a capacity error.
static BURST_TEST_PROFILE: std::sync::LazyLock<ChainProfile> =
    std::sync::LazyLock::new(|| ChainProfile {
        native_rfq: Some(*crate::chain::BSC_NATIVE_RFQ),
        settler: Some(crate::chain::with_native_entry(*crate::chain::BSC_SETTLER)),
        ..*crate::chain::BSC_PROFILE
    });

const BURST_USDC: Address = address!("8ac76a51cc950d9822d68b83fe1ad97b32cd580d");
const BURST_ETH: Address = address!("2170ed0880ac9a755fd29b2688956bd959f933f8");
const BURST_BTCB: Address = address!("7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c");
const BURST_TSLAON: Address = address!("2494b603319d4d9f9715c9f4496d9e0364b59d93");
const BURST_NVDAON: Address = address!("a9ee28c80f960b889dfbd1902055218cba016f75");
const BURST_GOOGLON: Address = address!("091fc7778e6932d4009b087b191d1ee3bac5729a");
const BURST_QQQON: Address = address!("0cde6936d305d5b34667fc46425e852efd73559a");

#[derive(Clone, Copy)]
struct BurstMarket {
    name: &'static str,
    class: &'static str,
    route_shape: &'static str,
    token_in: Address,
    token_out: Address,
    amount_in: &'static str,
}

const BURST_MARKETS: [BurstMarket; 12] = [
    BurstMarket {
        name: "TSLAon->USDT",
        class: "stock",
        route_shape: "direct",
        token_in: BURST_TSLAON,
        token_out: crate::chain::BSC_USDT,
        amount_in: "1000000000000000",
    },
    BurstMarket {
        name: "WBNB->USDT",
        class: "crypto",
        route_shape: "direct",
        token_in: crate::chain::WBNB,
        token_out: crate::chain::BSC_USDT,
        amount_in: "10000000000000000",
    },
    BurstMarket {
        name: "USDC->USDT",
        class: "stable",
        route_shape: "direct",
        token_in: BURST_USDC,
        token_out: crate::chain::BSC_USDT,
        amount_in: "50000000000000000000000",
    },
    BurstMarket {
        name: "USDT->NVDAon",
        class: "stock",
        route_shape: "reverse",
        token_in: crate::chain::BSC_USDT,
        token_out: BURST_NVDAON,
        amount_in: "50000000000000000000000",
    },
    BurstMarket {
        name: "USDT->WBNB",
        class: "crypto",
        route_shape: "reverse",
        token_in: crate::chain::BSC_USDT,
        token_out: crate::chain::WBNB,
        amount_in: "100000000000000000000",
    },
    BurstMarket {
        name: "USDT->USDC",
        class: "stable",
        route_shape: "reverse",
        token_in: crate::chain::BSC_USDT,
        token_out: BURST_USDC,
        amount_in: "1000000000000000000000",
    },
    BurstMarket {
        name: "GOOGLon->USDT",
        class: "stock",
        route_shape: "direct",
        token_in: BURST_GOOGLON,
        token_out: crate::chain::BSC_USDT,
        amount_in: "20000000000000000",
    },
    BurstMarket {
        name: "QQQon->USDT",
        class: "stock",
        route_shape: "direct",
        token_in: BURST_QQQON,
        token_out: crate::chain::BSC_USDT,
        amount_in: "50000000000000000",
    },
    BurstMarket {
        name: "ETH->USDT",
        class: "crypto",
        route_shape: "two-hop",
        token_in: BURST_ETH,
        token_out: crate::chain::BSC_USDT,
        amount_in: "100000000000000000",
    },
    BurstMarket {
        name: "BTCB->USDT",
        class: "crypto",
        route_shape: "two-hop",
        token_in: BURST_BTCB,
        token_out: crate::chain::BSC_USDT,
        amount_in: "1000000000000000",
    },
    BurstMarket {
        name: "TSLAon->WBNB",
        class: "stock",
        route_shape: "two-hop",
        token_in: BURST_TSLAON,
        token_out: crate::chain::WBNB,
        amount_in: "250000000000000000",
    },
    BurstMarket {
        name: "WBNB->NVDAon",
        class: "stock",
        route_shape: "two-hop-reverse",
        token_in: crate::chain::WBNB,
        token_out: BURST_NVDAON,
        amount_in: "500000000000000000",
    },
];

// Only requests with a stock endpoint are Native-eligible. Crypto/stable
// directions remain AMM controls even if Native happens to advertise them.
const NATIVE_MARKET_INDICES: [usize; 6] = [0, 3, 6, 7, 10, 11];
const AMM_ONLY_MARKET_INDICES: [usize; 6] = [1, 2, 4, 5, 8, 9];

#[derive(Clone, Copy)]
struct BurstAttempt {
    market: BurstMarket,
    native_eligible: bool,
    execution_requested: bool,
}

fn diverse_burst_wave(size: usize, wave: usize, mix_native: bool) -> Vec<BurstAttempt> {
    (0..size)
        .map(|index| {
            if mix_native && index.is_multiple_of(2) {
                BurstAttempt {
                    market: BURST_MARKETS[NATIVE_MARKET_INDICES
                        [(index / 2 + wave * 3) % NATIVE_MARKET_INDICES.len()]],
                    native_eligible: true,
                    execution_requested: true,
                }
            } else if mix_native {
                BurstAttempt {
                    market: BURST_MARKETS[AMM_ONLY_MARKET_INDICES
                        [(index / 2 + wave * 3) % AMM_ONLY_MARKET_INDICES.len()]],
                    native_eligible: false,
                    // Supplying all execution identities proves these
                    // requests skip Native because of their endpoints, not
                    // because they are display-only quotes.
                    execution_requested: true,
                }
            } else {
                BurstAttempt {
                    market: BURST_MARKETS[(index + wave * 5) % BURST_MARKETS.len()],
                    native_eligible: false,
                    execution_requested: false,
                }
            }
        })
        .collect()
}

fn burst_v2_pools() -> Vec<(V2Pool, V2State)> {
    let reserve = U256::from(10u64).pow(U256::from(30u64));
    [
        (crate::chain::WBNB, crate::chain::BSC_USDT),
        (BURST_USDC, crate::chain::BSC_USDT),
        (BURST_TSLAON, crate::chain::BSC_USDT),
        (BURST_NVDAON, crate::chain::BSC_USDT),
        (BURST_GOOGLON, crate::chain::BSC_USDT),
        (BURST_QQQON, crate::chain::BSC_USDT),
        (BURST_ETH, crate::chain::WBNB),
        (BURST_BTCB, crate::chain::WBNB),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (token0, token1))| {
        (
            V2Pool {
                protocol: crate::pools::V2Protocol::PANCAKEV2,
                address: Address::repeat_byte(0x70 + index as u8),
                token0,
                token1,
                fee_bps: 25,
            },
            V2State {
                reserve0: reserve,
                reserve1: reserve,
            },
        )
    })
    .collect()
}

struct CapacityLimitedNative {
    slots: Semaphore,
    calls: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
}

impl CapacityLimitedNative {
    fn new(limit: usize) -> Self {
        Self {
            slots: Semaphore::new(limit),
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        }
    }
}

impl NativeRfqSource for CapacityLimitedNative {
    fn indicative_quotes<'a>(
        &'a self,
        _identity: crate::chain::NativeRfqProfile,
        requests: &'a [(crate::rfq::NativePair, U256)],
    ) -> BoxFuture<'a, Result<Vec<(crate::rfq::NativePair, U256, U256)>, NativeRfqError>> {
        Box::pin(async move {
            Ok(requests
                .iter()
                .map(|(pair, amount)| (*pair, *amount, *amount))
                .collect())
        })
    }

    fn firm_quote<'a>(
        &'a self,
        _request: crate::rfq::FirmQuoteRequest,
    ) -> BoxFuture<'a, Result<Option<crate::rfq::ValidatedFirmQuote>, NativeRfqError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _permit = self
                .slots
                .try_acquire()
                .map_err(|_| NativeRfqError::Saturated)?;
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(25)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Err(NativeRfqError::QueueTimeout)
        })
    }
}

fn burst_test_app(
    max_inflight: usize,
    compute_concurrency: usize,
    native_rfq: Option<Arc<dyn NativeRfqSource>>,
) -> Arc<App> {
    // Execution requests check their transaction against this chain.
    let (rpc, _server) = crate::simulation::test_chain::simulation_chain(
        crate::simulation::test_chain::SimulationChain::funded(),
    );
    let engine = Engine::for_profile(rpc.clone(), &BURST_TEST_PROFILE);
    seed_burst_snapshots(&engine);
    Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(16)),
        quote_admission_wait: Duration::ZERO,
        cfg: Config {
            profile: &BURST_TEST_PROFILE,
            rpc_url: BURST_TEST_PROFILE.public_rpc.to_string(),
            logs_rpc_url: BURST_TEST_PROFILE.public_rpc.to_string(),
            indexer_url: None,
            native_rfq: None,
            fee_bps: 0,
            fee_receiver: None,
            positive_slippage_max_bps: 0,
            positive_slippage_recipient: None,
            port: 0,
            quote_timeout: 5,
        },
        rpc,
        engine,
        indexer: None,
        native_rfq,
        native_adapter: None,
        quote_slots: Arc::new(Semaphore::new(max_inflight)),
        compute_slots: Arc::new(Semaphore::new(compute_concurrency)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: true,
        readiness: AsyncMutex::new(ReadinessState::new(true, true)),
    })
}

/// Publish a fresh snapshot for every burst market. Waves re-seed, so each
/// one measures admission rather than the age of the previous wave's state.
fn seed_burst_snapshots(engine: &Engine) {
    let mut seeded_pairs = Vec::new();
    for market in BURST_MARKETS {
        let pair = if market.token_in <= market.token_out {
            (market.token_in, market.token_out)
        } else {
            (market.token_out, market.token_in)
        };
        if seeded_pairs.contains(&pair) {
            continue;
        }
        seeded_pairs.push(pair);
        engine.cache_snapshot_for_test(
            market.token_in,
            market.token_out,
            crate::state::ObservedSnapshot {
                snapshot: Snapshot {
                    block: 1,
                    settler: Some(Address::repeat_byte(0x66)),
                    v3: vec![],
                    v2: burst_v2_pools(),
                    ekubo: vec![],
                },
                screening: Default::default(),
                universe: crate::universe::RouteUniverse::profile_only(
                    &BURST_TEST_PROFILE,
                    market.token_in,
                    market.token_out,
                )
                .unwrap(),
                topology_fences: None,
                block_id: alloy::eips::BlockId::hash_canonical(B256::repeat_byte(0x88)),
                block_timestamp: 1_800_000_000,
                observed_at: Instant::now(),
            },
        );
    }
}

fn burst_quote_body(attempt: BurstAttempt) -> Vec<u8> {
    let mut body = json!({
        "chainId": BURST_TEST_PROFILE.chain_id,
        "tokenIn": format!("{:#x}", attempt.market.token_in),
        "tokenOut": format!("{:#x}", attempt.market.token_out),
        "amountIn": attempt.market.amount_in,
        "slippageBps": 50,
        "deadlineSeconds": 60,
    });
    if attempt.execution_requested {
        let taker = format!("{:#x}", Address::repeat_byte(0x44));
        body["recipient"] = json!(taker);
        body["sender"] = json!(taker);
        body["txOrigin"] = json!(taker);
    }
    serde_json::to_vec(&body).unwrap()
}
#[tokio::test]
async fn process_rss_threshold_rejects_multi_request_work_without_spending_quote_or_compute_slots()
{
    let mut app = burst_test_app(2, 1, None);
    let memory = crate::process_memory::ProcessMemory::new(Some(1), 1).unwrap();
    assert!(memory.sample().rss_bytes.unwrap() > 1);
    Arc::get_mut(&mut app).unwrap().memory = memory.clone();
    let body = burst_quote_body(BurstAttempt {
        market: BURST_MARKETS[0],
        native_eligible: true,
        execution_requested: false,
    });
    let responses = futures_util::future::join_all(
        (0..32).map(|_| handle_quote(State(app.clone()), Request::new(Body::from(body.clone())))),
    )
    .await;
    assert!(
        responses
            .iter()
            .all(|response| response.status() == StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(app.quote_slots.available_permits(), 2);
    assert_eq!(app.compute_slots.available_permits(), 1);
    assert_eq!(memory.sample().rejected, 32);
    assert_eq!(memory.sample().reserved_new_work_bytes, 0);
}

fn fixture_display_quote_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "chainId": FIXTURE_PROFILE.chain_id,
        "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
        "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
        "amountIn": "1",
        "slippageBps": 50,
        "deadlineSeconds": 60,
    }))
    .unwrap()
}

async fn run_burst_wave(
    app: Arc<App>,
    traffic: Vec<BurstAttempt>,
) -> Vec<(BurstAttempt, Response, Duration)> {
    let barrier = Arc::new(Barrier::new(traffic.len() + 1));
    let tasks = traffic.into_iter().map(|attempt| {
        let app = app.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            let started = Instant::now();
            let response = handle_quote(
                State(app),
                Request::new(Body::from(burst_quote_body(attempt))),
            )
            .await;
            (attempt, response, started.elapsed())
        })
    });
    let tasks: Vec<_> = tasks.collect();
    barrier.wait().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        futures_util::future::join_all(tasks)
            .await
            .into_iter()
            .map(|result| result.expect("burst quote task panicked"))
            .collect()
    })
    .await
    .expect("burst wave did not drain")
}

fn latency_percentiles(
    responses: &[(BurstAttempt, Response, Duration)],
) -> (u128, u128, u128, u128) {
    let mut micros: Vec<_> = responses
        .iter()
        .map(|(_, _, latency)| latency.as_micros())
        .collect();
    micros.sort_unstable();
    let at = |percent: usize| {
        let index = (micros.len() * percent).div_ceil(100).saturating_sub(1);
        micros[index.min(micros.len() - 1)]
    };
    (at(50), at(95), at(99), *micros.last().unwrap())
}

fn assert_burst_workload_is_diverse(responses: &[(BurstAttempt, Response, Duration)]) {
    let classes: std::collections::BTreeSet<_> = responses
        .iter()
        .map(|(attempt, _, _)| attempt.market.class)
        .collect();
    let shapes: std::collections::BTreeSet<_> = responses
        .iter()
        .map(|(attempt, _, _)| attempt.market.route_shape)
        .collect();
    let markets: std::collections::BTreeSet<_> = responses
        .iter()
        .map(|(attempt, _, _)| attempt.market.name)
        .collect();
    let amounts: std::collections::BTreeSet<_> = responses
        .iter()
        .map(|(attempt, _, _)| attempt.market.amount_in)
        .collect();
    assert_eq!(classes, ["crypto", "stable", "stock"].into_iter().collect());
    assert!(shapes.contains("direct"));
    assert!(shapes.contains("reverse"));
    assert!(shapes.contains("two-hop"));
    assert_eq!(markets.len(), BURST_MARKETS.len());
    assert!(amounts.len() >= 8);
}

async fn assert_amm_response_shape(attempt: BurstAttempt, response: Response) {
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["liquiditySource"], "amm");
    let expected_hops = if attempt.market.route_shape.starts_with("two-hop") {
        2
    } else {
        1
    };
    let legs = body["route"]
        .as_array()
        .expect("quote route must be an array");
    assert!(!legs.is_empty());
    assert!(legs.iter().all(|leg| {
        leg["hops"]
            .as_array()
            .is_some_and(|hops| hops.len() == expected_hops)
    }));
}

fn config() -> Config {
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
        quote_timeout: 1,
    }
}

fn native_test_config() -> crate::rfq::NativeRfqConfig {
    crate::rfq::NativeRfqConfig::new(
        "https://v2.api.native.org/swap-api-v2/",
        "test-api-key",
        Duration::from_millis(1_500),
        60,
        10,
        crate::rfq::NativeBeneficiaryAuthorizer::from_secret(
            "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d",
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn fixture_native_rfq_uses_the_registry_settler_and_stays_closed_without_stock_endpoints() {
    let cfg = Config {
        native_rfq: Some(native_test_config()),
        ..config()
    };
    assert!(cfg.profile.execution_enabled());
    assert!(crate::chain::FIXTURE_NATIVE_RFQ.stock_tokens.is_empty());
    // The fixture lists no reviewed stock endpoint, so enabling Native refuses to start.
    assert!(validate_config(&cfg).is_err());
    assert!(configured_native_adapter(&FIXTURE_PROFILE).is_err());
    assert!(matches!(
        configured_native_adapter(&BURST_TEST_PROFILE)
            .unwrap()
            .settler,
        NativeSettlerTarget::Registry { .. }
    ));
}

#[derive(Clone)]
struct NativeStartupFixture {
    adapter: NativeAdapter,
    signer: Address,
    requests: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
}

async fn native_startup_rpc(
    State(state): State<NativeStartupFixture>,
    axum::Json(request): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    use alloy_sol_types::SolValue;
    state.requests.lock().unwrap().push(request.clone());
    let native = state.adapter.native;
    let result = match request["method"].as_str().unwrap() {
        "eth_getBlockByNumber" => json!({
            "hash": B256::repeat_byte(0x80), "parentHash": B256::repeat_byte(0x81),
            "sha3Uncles": B256::ZERO, "miner": Address::ZERO, "stateRoot": B256::ZERO,
            "transactionsRoot": B256::ZERO, "receiptsRoot": B256::ZERO,
            "logsBloom": format!("0x{}", "00".repeat(256)), "difficulty":"0x0", "number":"0x1",
            "gasLimit":"0x7a1200", "gasUsed":"0x0", "timestamp":"0x64", "extraData":"0x",
            "mixHash": B256::ZERO, "nonce":"0x0000000000000000", "transactions":[], "uncles":[],
        }),
        "eth_getCode" => {
            let to: Address = request["params"][0].as_str().unwrap().parse().unwrap();
            let code = if to == native.router {
                "0x6001"
            } else if to == native.pool {
                "0x6002"
            } else if to == native.credit_vault {
                "0x6003"
            } else {
                "0x6004"
            };
            json!(code)
        }
        "eth_call" => {
            let input = request["params"][0]
                .get("input")
                .or_else(|| request["params"][0].get("data"))
                .unwrap()
                .as_str()
                .unwrap();
            let data = crate::abi::hexbytes(input).unwrap();
            let selector = &data[..4];
            let output = if selector == abi::contractRevisionCall::SELECTOR {
                U256::from(native.contract_revision).abi_encode()
            } else if selector == abi::isNativePoolsCall::SELECTOR {
                true.abi_encode()
            } else if selector == abi::routerCall::SELECTOR {
                native.router.abi_encode()
            } else if selector == abi::vaultCall::SELECTOR
                || selector == abi::treasuryCall::SELECTOR
            {
                native.credit_vault.abi_encode()
            } else if selector == abi::WETH9Call::SELECTOR {
                FIXTURE_PROFILE.wrapped_native.abi_encode()
            } else if selector == abi::nativeAuthorizationSignerCall::SELECTOR {
                state.signer.abi_encode()
            } else if selector == abi::ISettlerRegistry::ownerOfCall::SELECTOR {
                Address::repeat_byte(0x61).abi_encode()
            } else if selector == abi::eip712DomainCall::SELECTOR {
                (
                    alloy_primitives::FixedBytes::<1>::from([native.domain_fields]),
                    native.domain_name.to_string(),
                    native.domain_version.to_string(),
                    U256::from(native.domain_chain_id),
                    native.pool,
                    B256::ZERO,
                    Vec::<U256>::new(),
                )
                    .abi_encode_params()
            } else {
                panic!("unexpected startup RPC selector")
            };
            json!(crate::abi::tohex(&output))
        }
        _ => panic!("unexpected startup RPC method"),
    };
    axum::Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
}

#[tokio::test]
async fn native_startup_checks_the_registry_settler_and_its_authorization_signer() {
    let expected = Address::repeat_byte(0x71);
    let executor = Address::repeat_byte(0x61);
    let adapter = NativeAdapter {
        native: crate::chain::NativeRfqProfile {
            router_runtime_hash: keccak256([0x60, 0x01]),
            pool_runtime_hash: keccak256([0x60, 0x02]),
            credit_vault_runtime_hash: keccak256([0x60, 0x03]),
            ..crate::chain::FIXTURE_NATIVE_RFQ
        },
        settler: NativeSettlerTarget::Registry {
            address: crate::chain::FIXTURE_SETTLER_REGISTRY,
            token_id: crate::chain::FIXTURE_SETTLER_TOKEN_ID,
        },
    };
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/", post(native_startup_rpc))
        .with_state(NativeStartupFixture {
            adapter,
            signer: expected,
            requests: requests.clone(),
        });
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let rpc = Rpc::connect(&format!("http://{address}")).unwrap();
    verify_native_rfq_adapter(&rpc, &FIXTURE_PROFILE, adapter, expected)
        .await
        .unwrap();
    let error =
        verify_native_rfq_adapter(&rpc, &FIXTURE_PROFILE, adapter, Address::repeat_byte(0x72))
            .await
            .unwrap_err();
    assert!(error.to_string().contains("does not match"));
    let recorded = requests.lock().unwrap();
    let auth_calls: Vec<_> = recorded
        .iter()
        .filter(|request| request["method"] == "eth_call")
        .filter(|request| {
            request["params"][0]
                .get("input")
                .or_else(|| request["params"][0].get("data"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|data| {
                    data.starts_with(&crate::abi::tohex(
                        &abi::nativeAuthorizationSignerCall::SELECTOR,
                    ))
                })
        })
        .collect();
    assert_eq!(auth_calls.len(), 2);
    assert!(auth_calls.iter().all(|request| {
        request["params"][0]["to"]
            .as_str()
            .unwrap()
            .parse::<Address>()
            .unwrap()
            == executor
    }));
    assert!(recorded.iter().any(|request| {
        request["method"] == "eth_call"
            && request["params"][0]
                .get("input")
                .or_else(|| request["params"][0].get("data"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|data| {
                    data.starts_with(&crate::abi::tohex(
                        &abi::ISettlerRegistry::ownerOfCall::SELECTOR,
                    ))
                })
    }));
    task.abort();
}

#[test]
fn bsc_warmup_covers_its_v4_execution_binding() {
    warmup_for_profile(&crate::chain::BSC_PROFILE).unwrap();
}

#[test]
fn quote_only_v4_warmup_uses_the_catalog_manager() {
    let mut profile = *crate::chain::BSC_PROFILE;
    profile.settler = None;
    assert!(!profile.execution_enabled());
    warmup_for_profile(&profile).unwrap();
}

#[test]
fn startup_rejects_zero_fee_receiver_even_when_the_fee_is_disabled() {
    let cfg = Config {
        fee_receiver: Some(Address::ZERO),
        ..config()
    };
    let error = validate_config(&cfg).unwrap_err();
    assert!(error.to_string().contains("FEE_RECEIVER must not be zero"));
}

#[test]
fn compute_concurrency_is_bounded_and_explicitly_validated() {
    assert_eq!(parse_compute_concurrency(None).unwrap(), 2);
    assert_eq!(parse_compute_concurrency(Some("1")).unwrap(), 1);
    assert_eq!(parse_compute_concurrency(Some("64")).unwrap(), 64);
    assert!(parse_compute_concurrency(Some("0")).is_err());
    assert!(parse_compute_concurrency(Some("65")).is_err());
    assert!(parse_compute_concurrency(Some("many")).is_err());
}

#[test]
fn max_inflight_quotes_is_bounded_and_never_below_compute() {
    assert_eq!(parse_max_inflight_quotes(None, 2).unwrap(), 8);
    assert_eq!(parse_max_inflight_quotes(Some("2"), 2).unwrap(), 2);
    assert_eq!(parse_max_inflight_quotes(Some("256"), 64).unwrap(), 256);
    assert!(parse_max_inflight_quotes(Some("1"), 2).is_err());
    assert!(parse_max_inflight_quotes(Some("257"), 2).is_err());
    assert!(parse_max_inflight_quotes(Some("many"), 2).is_err());
}

#[test]
fn quote_log_field_is_single_line_ascii_and_bounded() {
    let rendered = quote_log_field("token\nnext\r\t\0\u{1b}\\é");

    assert!(rendered.chars().all(|character| !character.is_control()));
    assert!(rendered.is_ascii());
    assert!(rendered.contains("\\n"));
    assert!(rendered.contains("\\r"));
    assert!(rendered.contains("\\u{1b}"));
    assert!(rendered.contains("\\\\"));

    let oversized = "é".repeat(MAX_QUOTE_LOG_FIELD_BYTES);
    let rendered = quote_log_field(&oversized);
    assert_eq!(rendered.len(), MAX_QUOTE_LOG_FIELD_BYTES);
    assert!(rendered.ends_with("..."));
}

#[test]
fn quote_log_field_preserves_canonical_values() {
    let address = format!("{:#x}", Address::repeat_byte(0xab));
    let amount = U256::MAX.to_string();

    assert_eq!(quote_log_field(&address), address);
    assert_eq!(quote_log_field(&amount), amount);
}

#[tokio::test]
async fn log_rendering_does_not_change_http_error_body() {
    let message = "bad address 0x1\nforged status=200".to_string();
    let rendered = quote_log_field(&message);
    assert!(!rendered.contains('\n'));
    assert!(rendered.contains("\\n"));

    let response = quote_error_response(
        StatusCode::BAD_REQUEST,
        &FIXTURE_PROFILE,
        "quote_failed",
        message.clone(),
        Some(FIXTURE_PROFILE.chain_id),
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], message);
}

#[test]
fn native_authorization_signer_mismatch_fails_closed() {
    let configured = Address::repeat_byte(0x11);
    assert!(verify_native_authorization_signer(configured, configured).is_ok());
    let error =
        verify_native_authorization_signer(Address::repeat_byte(0x22), configured).unwrap_err();
    assert!(error.to_string().contains("does not match"));
}

#[test]
fn native_pool_domain_matches_only_the_reviewed_identity() {
    let profile = &FIXTURE_PROFILE;
    let native = crate::chain::FIXTURE_NATIVE_RFQ;
    let valid = || {
        verify_native_pool_domain(
            profile,
            &native,
            native.domain_fields,
            native.domain_name,
            native.domain_version,
            U256::from(profile.chain_id),
            native.pool,
            B256::ZERO,
            &[],
        )
    };
    assert!(valid().is_ok());

    assert!(
        verify_native_pool_domain(
            profile,
            &native,
            native.domain_fields ^ 1,
            native.domain_name,
            native.domain_version,
            U256::from(profile.chain_id),
            native.pool,
            B256::ZERO,
            &[],
        )
        .is_err()
    );
    assert!(
        verify_native_pool_domain(
            profile,
            &native,
            native.domain_fields,
            "Native RFQ Pool lookalike",
            native.domain_version,
            U256::from(profile.chain_id),
            native.pool,
            B256::ZERO,
            &[],
        )
        .is_err()
    );
    assert!(
        verify_native_pool_domain(
            profile,
            &native,
            native.domain_fields,
            native.domain_name,
            "6",
            U256::from(profile.chain_id),
            native.pool,
            B256::ZERO,
            &[],
        )
        .is_err()
    );
    assert!(
        verify_native_pool_domain(
            profile,
            &native,
            native.domain_fields,
            native.domain_name,
            native.domain_version,
            U256::from(profile.chain_id + 1),
            native.pool,
            B256::ZERO,
            &[],
        )
        .is_err()
    );
    assert!(
        verify_native_pool_domain(
            profile,
            &native,
            native.domain_fields,
            native.domain_name,
            native.domain_version,
            U256::from(profile.chain_id),
            Address::repeat_byte(0x11),
            B256::ZERO,
            &[],
        )
        .is_err()
    );
    assert!(
        verify_native_pool_domain(
            profile,
            &native,
            native.domain_fields,
            native.domain_name,
            native.domain_version,
            U256::from(profile.chain_id),
            native.pool,
            B256::repeat_byte(0x22),
            &[],
        )
        .is_err()
    );
    assert!(
        verify_native_pool_domain(
            profile,
            &native,
            native.domain_fields,
            native.domain_name,
            native.domain_version,
            U256::from(profile.chain_id),
            native.pool,
            B256::ZERO,
            &[U256::from(1)],
        )
        .is_err()
    );
}

#[test]
fn native_adapter_rpc_error_drops_secret_source_chain() {
    let secret = "https://paid-rpc.example/super-secret-native-startup-key";
    let error = anyhow::anyhow!("transport failed at {secret}")
        .context(crate::rpc::RpcUnavailable("eth_call"));
    let rendered = format!("{:#}", native_rfq_adapter_error(error));

    assert!(rendered.contains("upstream rpc failed: eth_call"));
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("super-secret-native-startup-key"));
}

#[test]
fn quote_timeout_is_positive_and_bounded() {
    let zero = Config {
        quote_timeout: 0,
        ..config()
    };
    assert!(validate_config(&zero).is_err());
    let too_large = Config {
        quote_timeout: MAX_QUOTE_TIMEOUT_SECS + 1,
        ..config()
    };
    assert!(validate_config(&too_large).is_err());
    let boundary = Config {
        quote_timeout: MAX_QUOTE_TIMEOUT_SECS,
        ..config()
    };
    assert!(validate_config(&boundary).is_ok());
}

#[test]
fn startup_requires_nonzero_enabled_recipients() {
    let missing_fee = Config {
        fee_bps: 9,
        ..config()
    };
    assert!(validate_config(&missing_fee).is_err());

    let missing_positive = Config {
        positive_slippage_max_bps: 1,
        ..config()
    };
    assert!(validate_config(&missing_positive).is_err());

    let zero_positive = Config {
        positive_slippage_recipient: Some(Address::ZERO),
        ..config()
    };
    assert!(validate_config(&zero_positive).is_err());
}

#[test]
fn startup_takes_an_indexer_only_where_one_names_the_pools() {
    // The fixture's factories name its pools: an indexer URL is refused, not
    // silently ignored.
    assert!(validate_config(&config()).is_ok());
    let fixture_with_indexer = Config {
        indexer_url: Some("http://fixture-indexer:8787".to_string()),
        ..config()
    };
    let error = validate_config(&fixture_with_indexer).unwrap_err();
    assert!(
        error.to_string().contains("names its pools by factory"),
        "{error:#}"
    );
    assert!(configured_indexer(&config()).unwrap().is_none());

    // An indexer-backed table still requires one.
    let bsc = &crate::chain::BSC_PROFILE;
    let error = check_indexer_url(bsc, None).unwrap_err();
    assert!(error.to_string().contains("SOLVER_INDEXER_URL is required"));
    assert!(check_indexer_url(bsc, Some(" ")).is_err());
    assert!(check_indexer_url(bsc, Some("http://bsc-indexer:8787")).is_ok());

    let robinhood = &crate::chain::ROBINHOOD_PROFILE;
    assert!(check_indexer_url(robinhood, None).is_ok());
    assert!(check_indexer_url(robinhood, Some("http://indexer:8787")).is_err());
}

/// The fixture without its Settler, as a chain whose Settler is not deployed.
fn fixture_quote_only() -> &'static ChainProfile {
    Box::leak(Box::new(ChainProfile {
        settler: None,
        native_rfq: None,
        ..FIXTURE_PROFILE
    }))
}

#[test]
fn quote_only_profile_rejects_execution_configuration() {
    let quote_only = || Config {
        profile: fixture_quote_only(),
        ..config()
    };
    assert!(validate_execution_settings(&quote_only()).is_ok());
    let fee = Config {
        fee_bps: 9,
        fee_receiver: Some(Address::repeat_byte(0x11)),
        ..quote_only()
    };
    assert!(validate_execution_settings(&fee).is_err());
    let dormant_receiver = Config {
        fee_receiver: Some(Address::repeat_byte(0x11)),
        ..quote_only()
    };
    assert!(validate_execution_settings(&dormant_receiver).is_err());
    let positive_slippage = Config {
        positive_slippage_max_bps: 100,
        positive_slippage_recipient: Some(Address::repeat_byte(0x22)),
        ..quote_only()
    };
    assert!(validate_execution_settings(&positive_slippage).is_err());

    // With its Settler, the fixture accepts the same settings; the launch
    // configuration keeps both at zero.
    let executable_fee = Config {
        fee_bps: 9,
        fee_receiver: Some(Address::repeat_byte(0x11)),
        ..config()
    };
    assert!(validate_config(&executable_fee).is_ok());
}

#[test]
fn startup_rejects_incoherent_profile_capabilities() {
    let mut execution_without_quotes = *crate::chain::BSC_PROFILE;
    execution_without_quotes.capabilities.quote = false;
    execution_without_quotes.settler = crate::chain::ROBINHOOD_PROFILE.settler;
    let error = validate_profile(&execution_without_quotes).unwrap_err();
    assert!(error.to_string().contains("execution without quote"));

    let mut quotes_without_discovery = *crate::chain::BSC_PROFILE;
    quotes_without_discovery.discovery = DiscoveryProfile::Disabled;
    let error = validate_profile(&quotes_without_discovery).unwrap_err();
    assert!(error.to_string().contains("without pool discovery"));

    let mut indexed_with_foreign_execution_adapter = *crate::chain::BSC_PROFILE;
    indexed_with_foreign_execution_adapter.settler = crate::chain::ROBINHOOD_PROFILE.settler;
    let error = validate_profile(&indexed_with_foreign_execution_adapter).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("not an exact reviewed solver profile")
    );

    let mut bsc_with_robinhood_discovery = *crate::chain::BSC_PROFILE;
    bsc_with_robinhood_discovery.discovery = DiscoveryProfile::Robinhood;
    bsc_with_robinhood_discovery.capabilities.quote = true;
    let error = validate_profile(&bsc_with_robinhood_discovery).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("not an exact reviewed solver profile")
    );
}

#[test]
fn upstream_rpc_markers_never_map_to_bad_request() {
    let unavailable = anyhow::anyhow!("details").context(RpcUnavailable("eth_getBlockByNumber"));
    assert_eq!(quote_error_status(&unavailable), StatusCode::BAD_GATEWAY);

    let rejected = anyhow::anyhow!("details").context(RpcRejected("eth_call"));
    assert_eq!(quote_error_status(&rejected), StatusCode::BAD_GATEWAY);

    let indexer =
        IndexerClient::builder("://secret-indexer-key", &crate::chain::BSC_PROFILE).unwrap_err();
    assert_eq!(
        quote_error_status(&anyhow::Error::new(indexer)),
        StatusCode::BAD_GATEWAY
    );
    let integrity = anyhow::Error::new(UpstreamIntegrityError::test_only(
        "factory identity mismatch",
    ));
    assert_eq!(quote_error_status(&integrity), StatusCode::BAD_GATEWAY);
    assert_eq!(
        quote_error_status(&anyhow::anyhow!("no route")),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn native_capacity_is_retryable_service_unavailable() {
    for error in [
        NativeRfqError::Saturated,
        NativeRfqError::QueueTimeout,
        NativeRfqError::Api(201_005),
    ] {
        assert_eq!(
            quote_error_status(&anyhow::Error::new(error)),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    let response = native_busy_response(&FIXTURE_PROFILE, Some(FIXTURE_PROFILE.chain_id));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[RETRY_AFTER], "1");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "native_busy");
    assert_eq!(body["requestedChainId"], FIXTURE_PROFILE.chain_id);
}

#[test]
fn cooperative_compute_deadline_maps_to_gateway_timeout() {
    let error: anyhow::Error = SolverBudgetExceeded {
        stage: "route allocation",
    }
    .into();
    assert_eq!(quote_error_status(&error), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn typed_no_route_is_422_and_preserves_universe_provenance() {
    let fences = CatalogFences {
        v23: crate::topology::V23Fence {
            seq: 17,
            generation: 3,
        },
        v4: None,
    };
    let diagnostics =
        |source: &'static str, fallback_reason: Option<&'static str>, truncated: bool| {
            let scope = if source == "adjacency_complete" {
                "common_neighbor_two_hop"
            } else {
                "profile"
            };
            crate::universe::RouteUniverseDiagnostics {
                source,
                fallback_stage: fallback_reason.map(|_| "adjacency"),
                fallback_reason,
                scope,
                selector: "none",
                selection_scope: scope,
                protocol_mask: 0b1111,
                eligible_count: 0,
                connector_count: 0,
                shortlist_truncated: truncated,
                screened_count: 0,
                adjacency_fences: (fallback_reason.is_none()).then_some(fences),
                fingerprint: alloy_primitives::B256::repeat_byte(0x44),
            }
        };
    let complete = NoRouteError {
        route_universe: crate::quotes::RouteUniverseJson::new(
            56,
            123,
            alloy_primitives::B256::repeat_byte(0x55),
            diagnostics("adjacency_complete", None, false),
            Some(fences),
        ),
    };
    assert_eq!(
        quote_error_status(&anyhow::Error::new(complete.clone())),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let response = no_route_response(&crate::chain::BSC_PROFILE, &complete, Some(56));
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["schemaVersion"], 1);
    assert_eq!(body["code"], "no_route");
    assert_eq!(body["chain"], "bsc");
    assert_eq!(body["chainId"], 56);
    assert_eq!(body["requestedChainId"], 56);
    assert_eq!(body["routeUniverse"]["version"], 1);
    assert_eq!(body["routeUniverse"]["chainId"], 56);
    assert_eq!(body["routeUniverse"]["canonicalBlock"]["number"], 123);
    assert_eq!(
        body["routeUniverse"]["canonicalBlock"]["hash"],
        format!("{:#x}", alloy_primitives::B256::repeat_byte(0x55))
    );
    assert_eq!(body["routeUniverse"]["source"], "adjacency_complete");
    assert_eq!(body["routeUniverse"]["shortlistTruncated"], false);
    assert_eq!(body["routeUniverse"]["adjacencyFences"]["v23"]["seq"], "17");
    assert_eq!(
        body["routeUniverse"]["topologyFences"]["v23"]["generation"],
        "3"
    );

    let fallback = NoRouteError {
        route_universe: crate::quotes::RouteUniverseJson::new(
            56,
            124,
            alloy_primitives::B256::repeat_byte(0x66),
            diagnostics("adjacency_fallback", Some("transport"), true),
            Some(fences),
        ),
    };
    let response = no_route_response(&crate::chain::BSC_PROFILE, &fallback, Some(56));
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["routeUniverse"]["source"], "adjacency_fallback");
    assert_eq!(body["routeUniverse"]["fallbackReason"], "transport");
    assert_eq!(body["routeUniverse"]["shortlistTruncated"], true);
    assert!(body["routeUniverse"]["adjacencyFences"].is_null());
}

#[tokio::test]
async fn startup_chain_probe_drops_rpc_error_source() {
    let secret = "super-secret-rpc-key";
    let rpc = Rpc::connect(&format!("http://127.0.0.1:1/{secret}")).unwrap();
    let error = verify_rpc_chain(&rpc, 4663, "primary").await.unwrap_err();
    let rendered = format!("{error:#}");

    assert_eq!(
        rendered,
        "primary RPC verification failed: upstream rpc failed: eth_chainId"
    );
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("127.0.0.1"));
}

#[test]
fn request_chain_gate_rejects_mismatch_and_execution_on_quote_only_profiles() {
    let request = |chain_id, recipient| QuoteRequest {
        chain_id,
        token_in: format!("{:#x}", Address::repeat_byte(0x11)),
        token_out: format!("{:#x}", Address::repeat_byte(0x22)),
        amount_in: crate::quotes::AmountIn::Str("1".to_string()),
        slippage_bps: 50,
        recipient,
        sender: None,
        tx_origin: None,
        deadline_seconds: 600,
        fee_bps: None,
    };
    assert_eq!(
        gate_quote_request(&FIXTURE_PROFILE, &request(56, None)),
        Err(QuoteGate::ChainMismatch(56))
    );
    assert!(gate_quote_request(&FIXTURE_PROFILE, &request(2_818, None)).is_ok());
    let with_recipient = request(2_818, Some(format!("{:#x}", Address::repeat_byte(0x33))));
    assert!(gate_quote_request(&FIXTURE_PROFILE, &with_recipient).is_ok());
    let quote_only = fixture_quote_only();
    assert_eq!(
        gate_quote_request(quote_only, &with_recipient),
        Err(QuoteGate::ExecutionUnavailable)
    );
    let mut unexecutable_fee = request(2_818, None);
    unexecutable_fee.fee_bps = Some(9);
    assert_eq!(
        gate_quote_request(quote_only, &unexecutable_fee),
        Err(QuoteGate::ExecutionUnavailable)
    );
}

#[tokio::test]
async fn body_validation_precedes_saturated_quote_admission() {
    let quote_slots = Arc::new(Semaphore::new(1));
    let held = quote_slots.clone().acquire_owned().await.unwrap();
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(16)),
        quote_admission_wait: Duration::ZERO,
        cfg: config(),
        rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
        engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
        indexer: None,
        native_rfq: None,
        native_adapter: None,
        quote_slots: quote_slots.clone(),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: false,
        readiness: AsyncMutex::new(ReadinessState::new(false, true)),
    });

    let mut sampled_response = None;
    for _ in 0..3 {
        let responses =
            tokio::time::timeout(
                Duration::from_millis(500),
                futures_util::future::join_all((0..128).map(|_| {
                    handle_quote(State(app.clone()), Request::new(Body::from("not json")))
                })),
            )
            .await
            .expect("bounded malformed-body burst did not drain");
        assert_eq!(responses.len(), 128);
        for response in &responses {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        sampled_response = responses.into_iter().next();
    }

    let response = sampled_response.expect("burst produced no response");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "bad_request");
    assert_eq!(body["chainId"], 2_818);
    assert_eq!(body["requestedChainId"], serde_json::Value::Null);

    let response = handle_quote(
        State(app.clone()),
        Request::new(Body::from(vec![0; MAX_QUOTE_REQUEST_BYTES + 1])),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(quote_slots.available_permits(), 0);

    let response = handle_quote(
        State(app.clone()),
        Request::new(Body::from(fixture_display_quote_body())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[RETRY_AFTER], "1");
    assert_eq!(
        response.headers()[ACCESS_CONTROL_EXPOSE_HEADERS],
        "Retry-After"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "overloaded");

    drop(held);

    let response = handle_quote(State(app.clone()), Request::new(Body::from("not json"))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(quote_slots.available_permits(), 1);
    // Three bursts of malformed bodies, the oversized one and the last.
    assert_eq!(app.metrics.count(QuoteOutcome::BadRequest), 3 * 128 + 2);
    assert_eq!(app.metrics.count(QuoteOutcome::Overloaded), 1);
}

#[test]
fn a_callers_time_limit_only_shortens_the_quote() {
    assert_eq!(quote_time_limit(120, None), Duration::from_secs(120));
    assert_eq!(quote_time_limit(120, Some("5000")), Duration::from_secs(5));
    assert_eq!(quote_time_limit(5, Some("60000")), Duration::from_secs(5));
    for ignored in ["0", "-1", "soon", ""] {
        assert_eq!(quote_time_limit(5, Some(ignored)), Duration::from_secs(5));
    }
    assert_eq!(parse_quote_admission_wait("0").unwrap(), Duration::ZERO);
    assert_eq!(
        parse_quote_admission_wait("1000").unwrap(),
        Duration::from_secs(1)
    );
    assert!(parse_quote_admission_wait("10001").is_err());
    assert!(parse_quote_admission_wait("1s").is_err());
}

#[tokio::test]
async fn a_busy_solver_queues_quotes_in_order_until_their_deadline() {
    let quote_slots = Arc::new(Semaphore::new(1));
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(1)),
        quote_admission_wait: Duration::from_secs(5),
        cfg: config(),
        rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
        engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
        indexer: None,
        native_rfq: None,
        native_adapter: None,
        quote_slots: quote_slots.clone(),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: false,
        readiness: AsyncMutex::new(ReadinessState::new(false, true)),
    });
    let quote = |limit_ms: Option<&'static str>| {
        let mut request = Request::new(Body::from(fixture_display_quote_body()));
        if let Some(ms) = limit_ms {
            request
                .headers_mut()
                .insert("x-quote-timeout-ms", HeaderValue::from_static(ms));
        }
        handle_quote(State(app.clone()), request)
    };

    // With the one slot busy, a quote takes the queue's one place.
    let held = quote_slots.clone().acquire_owned().await.unwrap();
    let waiting = tokio::spawn(quote(None));
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.metrics.json()["waiting"] != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the quote never queued");
    // The next finds the queue full and is refused at once.
    let started = Instant::now();
    assert_eq!(quote(None).await.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(app.metrics.count(QuoteOutcome::Overloaded), 1);
    // The released slot goes to the waiting quote, which runs on (and finds
    // the solver not ready).
    drop(held);
    waiting.await.unwrap();
    assert_eq!(app.metrics.count(QuoteOutcome::NotReady), 1);
    assert_eq!(app.metrics.count(QuoteOutcome::Overloaded), 1);

    // A caller that stops waiting after 50 ms is refused then, not after
    // the solver's five-second wait.
    let held = quote_slots.clone().acquire_owned().await.unwrap();
    let started = Instant::now();
    assert_eq!(
        quote(Some("50")).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(50) && waited < Duration::from_secs(2),
        "{waited:?}"
    );
    assert_eq!(app.metrics.count(QuoteOutcome::Overloaded), 2);
    let metrics = app.metrics.json();
    assert_eq!(
        (metrics["waiting"].clone(), metrics["queued"].clone()),
        (json!(0), json!(2))
    );
    drop(held);
}

#[tokio::test]
async fn a_quote_answers_with_its_request_id_and_is_counted() {
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(16)),
        quote_admission_wait: Duration::ZERO,
        cfg: config(),
        rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
        engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
        indexer: None,
        native_rfq: None,
        native_adapter: None,
        quote_slots: Arc::new(Semaphore::new(1)),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: false,
        readiness: AsyncMutex::new(ReadinessState::new(false, true)),
    });
    let id = "6f2c7a1e-0b4d-4f6a-9a3e-2b1c0d9e8f7a";
    let mut request = Request::new(Body::from("not json"));
    request
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_static(id));
    let response = handle_quote(State(app.clone()), request).await;
    assert_eq!(response.headers()["x-request-id"], id);
    let unnamed = handle_quote(State(app.clone()), Request::new(Body::from("not json"))).await;
    assert!(
        unnamed.headers()["x-request-id"]
            .to_str()
            .unwrap()
            .starts_with("solver-")
    );

    let metrics = handle_metrics(State(app.clone())).await;
    assert_eq!(metrics.status(), StatusCode::OK);
    let text = String::from_utf8(
        axum::body::to_bytes(metrics.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(text.contains("solver_quotes_total{outcome=\"bad_request\"} 2\n"));
    assert!(text.contains("solver_quote_duration_ms_count 2\n"));
    assert!(text.contains("solver_quote_slots_available 1\n"));
    assert!(text.contains("solver_rpc_unknown_dispatches 0\n"));
}

#[tokio::test]
async fn slow_body_does_not_consume_quote_admission_capacity() {
    let quote_slots = Arc::new(Semaphore::new(1));
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(16)),
        quote_admission_wait: Duration::ZERO,
        cfg: config(),
        rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
        engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
        indexer: None,
        native_rfq: None,
        native_adapter: None,
        quote_slots: quote_slots.clone(),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: false,
        readiness: AsyncMutex::new(ReadinessState::new(false, true)),
    });
    let first_chunk_polled = Arc::new(AtomicBool::new(false));
    let polled = first_chunk_polled.clone();
    let slow_stream = stream::once(async move {
        polled.store(true, Ordering::SeqCst);
        Ok::<Bytes, Infallible>(Bytes::from_static(b"{"))
    })
    .chain(stream::pending::<Result<Bytes, Infallible>>());
    let slow_request = tokio::spawn(handle_quote(
        State(app.clone()),
        Request::new(Body::from_stream(slow_stream)),
    ));

    tokio::time::timeout(Duration::from_secs(1), async {
        while !first_chunk_polled.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("slow body was never polled");
    assert_eq!(quote_slots.available_permits(), 1);

    let response = handle_quote(
        State(app),
        Request::new(Body::from(fixture_display_quote_body())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "not_ready");
    assert_eq!(quote_slots.available_permits(), 1);

    slow_request.abort();
    let _ = slow_request.await;
    assert_eq!(quote_slots.available_permits(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_full_128_request_waves_drain_without_leaking_capacity() {
    const WAVE_SIZE: usize = 128;
    const WAVES: usize = 3;
    const COMPUTE_CONCURRENCY: usize = 4;
    let app = burst_test_app(WAVE_SIZE, COMPUTE_CONCURRENCY, None);

    for wave in 1..=WAVES {
        let responses =
            run_burst_wave(app.clone(), diverse_burst_wave(WAVE_SIZE, wave - 1, false)).await;
        assert_eq!(responses.len(), WAVE_SIZE);
        assert_burst_workload_is_diverse(&responses);
        assert!(
            responses
                .iter()
                .all(|(_, response, _)| { response.status() == StatusCode::OK })
        );
        let (p50_us, p95_us, p99_us, max_us) = latency_percentiles(&responses);
        eprintln!(
            "solver burst wave={wave} attempts={WAVE_SIZE} ok={WAVE_SIZE} p50_us={p50_us} p95_us={p95_us} p99_us={p99_us} max_us={max_us}",
        );
        for (attempt, response, _) in responses {
            assert_amm_response_shape(attempt, response).await;
        }
        assert_eq!(app.quote_slots.available_permits(), WAVE_SIZE);
        assert_eq!(app.compute_slots.available_permits(), COMPUTE_CONCURRENCY);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_128_request_waves_shed_load_and_fully_recover() {
    const WAVE_SIZE: usize = 128;
    const WAVES: usize = 3;
    const COMPUTE_CONCURRENCY: usize = 4;
    let app = burst_test_app(WAVE_SIZE, COMPUTE_CONCURRENCY, None);
    let waves = (0..WAVES).map(|wave| {
        let app = app.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis((wave * 10) as u64)).await;
            run_burst_wave(app, diverse_burst_wave(WAVE_SIZE, wave, false)).await
        })
    });
    let waves = futures_util::future::join_all(waves).await;
    let mut ok = 0usize;
    let mut overloaded = 0usize;
    for wave in waves {
        for (_, response, _) in wave.expect("overlapping wave task panicked") {
            match response.status() {
                StatusCode::OK => ok += 1,
                StatusCode::SERVICE_UNAVAILABLE => {
                    assert_eq!(response.headers()[RETRY_AFTER], "1");
                    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                        .await
                        .unwrap();
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["code"], "overloaded");
                    overloaded += 1;
                }
                status => panic!("unexpected overlapping-burst status {status}"),
            }
        }
    }
    eprintln!(
        "solver overlapping bursts waves={WAVES} attempts={} ok={ok} overloaded={overloaded}",
        WAVES * WAVE_SIZE
    );
    assert_eq!(ok + overloaded, WAVES * WAVE_SIZE);
    assert!(ok >= WAVE_SIZE);
    assert!(overloaded > 0);
    assert_eq!(app.quote_slots.available_permits(), WAVE_SIZE);
    assert_eq!(app.compute_slots.available_permits(), COMPUTE_CONCURRENCY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_capacity_waves_do_not_block_or_disguise_amm_quotes() {
    const WAVE_SIZE: usize = 128;
    const WAVES: usize = 3;
    const NATIVE_CONCURRENCY: usize = 8;
    const COMPUTE_CONCURRENCY: usize = 4;
    let native = Arc::new(CapacityLimitedNative::new(NATIVE_CONCURRENCY));
    let app = burst_test_app(
        WAVE_SIZE,
        COMPUTE_CONCURRENCY,
        Some(native.clone() as Arc<dyn NativeRfqSource>),
    );

    for wave in 1..=WAVES {
        // Native-eligible stock requests hit a separate capacity boundary
        // while diverse AMM-only crypto and stablecoin routes keep using
        // the same bounded solver compute pool.
        let traffic = diverse_burst_wave(WAVE_SIZE, wave - 1, true);
        seed_burst_snapshots(&app.engine);
        let responses = run_burst_wave(app.clone(), traffic).await;
        assert_burst_workload_is_diverse(&responses);
        let mut amm_ok = 0usize;
        let mut native_busy = 0usize;
        let mut max_latency = Duration::ZERO;
        let mut class_outcomes = std::collections::BTreeMap::<&'static str, (usize, usize)>::new();
        for (attempt, response, latency) in responses {
            max_latency = max_latency.max(latency);
            let outcomes = class_outcomes.entry(attempt.market.class).or_default();
            if attempt.native_eligible {
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(response.headers()[RETRY_AFTER], "1");
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["code"], "native_busy");
                native_busy += 1;
                outcomes.1 += 1;
            } else {
                assert_amm_response_shape(attempt, response).await;
                amm_ok += 1;
                outcomes.0 += 1;
            }
        }
        eprintln!(
            "solver mixed burst wave={wave} attempts={WAVE_SIZE} amm_ok={amm_ok} native_busy={native_busy} max_latency_ms={}",
            max_latency.as_millis()
        );
        assert_eq!(amm_ok, WAVE_SIZE / 2);
        assert_eq!(native_busy, WAVE_SIZE / 2);
        let (stock_amm_ok, stock_native_busy) = class_outcomes["stock"];
        assert_eq!(stock_amm_ok, 0);
        assert!(
            stock_native_busy > 0,
            "stock Native traffic was not exercised"
        );
        for class in ["crypto", "stable"] {
            let (class_amm_ok, class_native_busy) = class_outcomes[class];
            assert!(class_amm_ok > 0, "{class} AMM traffic was not exercised");
            assert_eq!(
                class_native_busy, 0,
                "{class} endpoints must never enter Native capacity"
            );
        }
        assert_eq!(app.quote_slots.available_permits(), WAVE_SIZE);
        assert_eq!(app.compute_slots.available_permits(), COMPUTE_CONCURRENCY);
        assert_eq!(native.slots.available_permits(), NATIVE_CONCURRENCY);
        assert_eq!(native.active.load(Ordering::SeqCst), 0);
    }

    assert_eq!(native.calls.load(Ordering::SeqCst), WAVES * WAVE_SIZE / 2);
    assert_eq!(native.max_active.load(Ordering::SeqCst), NATIVE_CONCURRENCY);
}

#[tokio::test]
async fn mismatched_request_is_rejected_before_any_snapshot_rpc() {
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(16)),
        quote_admission_wait: Duration::ZERO,
        cfg: config(),
        rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
        engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
        indexer: None,
        native_rfq: None,
        native_adapter: None,
        quote_slots: Arc::new(Semaphore::new(1)),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: false,
        readiness: AsyncMutex::new(ReadinessState::new(false, true)),
    });
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "chainId": 56,
            "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
            "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
            "amountIn": "1"
        }))
        .unwrap(),
    );
    let response = handle_quote(State(app), Request::new(Body::from(body))).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "chain_mismatch");
    assert_eq!(body["chainId"], 2_818);
    assert_eq!(body["requestedChainId"], 56);
}

#[tokio::test]
async fn missing_request_chain_id_is_rejected_as_a_bad_request() {
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(16)),
        quote_admission_wait: Duration::ZERO,
        cfg: config(),
        rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
        engine: Engine::new(Rpc::connect("http://127.0.0.1:1").unwrap()),
        indexer: None,
        native_rfq: None,
        native_adapter: None,
        quote_slots: Arc::new(Semaphore::new(1)),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: false,
        readiness: AsyncMutex::new(ReadinessState::new(false, true)),
    });
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
            "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
            "amountIn": "1"
        }))
        .unwrap(),
    );
    let response = handle_quote(State(app), Request::new(Body::from(body))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "bad_request");
    assert_eq!(body["chainId"], 2_818);
}

#[tokio::test]
async fn valid_quote_is_rejected_while_cached_readiness_is_failed() {
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(16)),
        quote_admission_wait: Duration::ZERO,
        cfg: config(),
        rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
        engine: Engine::for_profile(
            Rpc::connect("http://127.0.0.1:1").unwrap(),
            &FIXTURE_PROFILE,
        ),
        indexer: None,
        native_rfq: None,
        native_adapter: None,
        quote_slots: Arc::new(Semaphore::new(1)),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: true,
        readiness: AsyncMutex::new(ReadinessState::new(false, true)),
    });
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "chainId": 2_818,
            "tokenIn": format!("{:#x}", Address::repeat_byte(0x11)),
            "tokenOut": format!("{:#x}", Address::repeat_byte(0x22)),
            "amountIn": "1"
        }))
        .unwrap(),
    );

    let response = handle_quote(State(app), Request::new(Body::from(body))).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "not_ready");
    assert_eq!(body["chainId"], 2_818);
    assert_eq!(body["requestedChainId"], 2_818);
}

#[tokio::test]
async fn health_exposes_verified_instance_identity_and_capabilities() {
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(16)),
        quote_admission_wait: Duration::ZERO,
        cfg: config(),
        rpc: Rpc::connect("http://127.0.0.1:1").unwrap(),
        engine: Engine::for_profile(
            Rpc::connect("http://127.0.0.1:1").unwrap(),
            &FIXTURE_PROFILE,
        ),
        indexer: None,
        native_rfq: None,
        native_adapter: None,
        quote_slots: Arc::new(Semaphore::new(1)),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: true,
        readiness: AsyncMutex::new(ReadinessState::new(false, false)),
    });
    let response = handle_health(State(app)).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["ready"], false);
    assert_eq!(body["chainVerified"], true);
    assert_eq!(body["rpcReady"], false);
    assert_eq!(body["indexerReady"], false);
    assert_eq!(body["chain"], "fixture");
    assert_eq!(body["chainId"], 2_818);
    assert_eq!(body["capabilities"]["quote"], true);
    assert_eq!(body["capabilities"]["execution"], true);
    assert_eq!(body["capabilities"]["poolDiscovery"], "factories");
    assert_eq!(body["rpc"]["unknownDispatches"], 0);
    assert_eq!(body["rpc"]["unknownEpoch"], 0);
    assert_eq!(body["capabilities"]["protocols"], json!(["univ2", "univ3"]));
    assert_eq!(body["capabilities"]["nativeRfq"]["configured"], false);
    assert!(body["capabilities"]["nativeRfq"]["qps"].is_null());
    assert!(body["capabilities"]["nativeRfq"]["queueWaitMs"].is_null());
    assert!(body["capabilities"]["nativeRfq"]["maxInflight"].is_null());
    assert_eq!(body["capabilities"]["routeUniverseMode"], "profile_only");
    // A flat graphGapBps looks the same whether screening ran and found
    // nothing or never ran at all, so the setting has to be reportable.
    assert_eq!(body["capabilities"]["connectorScreening"], false);
}

#[tokio::test]
async fn health_exposes_native_rfq_capacity_and_queue_deadline() {
    let authorizer = crate::rfq::NativeBeneficiaryAuthorizer::from_secret(
        "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d",
    )
    .unwrap();
    let native_config = crate::rfq::NativeRfqConfig::new(
        "https://v2.api.native.org/swap-api-v2/",
        "test-api-key",
        Duration::from_millis(1_500),
        60,
        10,
        authorizer,
    )
    .unwrap();
    let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
    let native_client = NativeRfqClient::new(native_config.clone(), rpc.clone()).unwrap();
    let mut cfg = config();
    cfg.native_rfq = Some(native_config);
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(16)),
        quote_admission_wait: Duration::ZERO,
        cfg,
        rpc: rpc.clone(),
        engine: Engine::for_profile(rpc, &FIXTURE_PROFILE),
        indexer: None,
        native_rfq: Some(Arc::new(native_client)),
        native_adapter: Some(NativeAdapter {
            native: crate::chain::FIXTURE_NATIVE_RFQ,
            settler: NativeSettlerTarget::Registry {
                address: crate::chain::FIXTURE_SETTLER_REGISTRY,
                token_id: crate::chain::FIXTURE_SETTLER_TOKEN_ID,
            },
        }),
        quote_slots: Arc::new(Semaphore::new(1)),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: true,
        readiness: AsyncMutex::new(ReadinessState::new(false, false)),
    });

    let response = handle_health(State(app)).await;
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["capabilities"]["nativeRfq"]["configured"], true);
    assert_eq!(body["capabilities"]["nativeRfq"]["qps"], 4);
    assert_eq!(body["capabilities"]["nativeRfq"]["queueWaitMs"], 1_000);
    assert_eq!(body["capabilities"]["nativeRfq"]["maxInflight"], 8);
    assert_eq!(
        body["capabilities"]["protocols"],
        json!(["univ2", "univ3", "nativerfq"])
    );
}

#[tokio::test]
async fn readiness_timeout_is_failed_cached_and_singleflight() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let state = Arc::new(AsyncMutex::new(ReadinessState {
        checked_at: Instant::now() - READINESS_TTL,
        rpc_ready: true,
        indexer_ready: true,
    }));
    let calls = Arc::new(AtomicUsize::new(0));
    let call = |state: Arc<AsyncMutex<ReadinessState>>, calls: Arc<AtomicUsize>| async move {
        cached_readiness(&state, Duration::from_millis(20), async move {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<(bool, bool)>().await
        })
        .await
    };

    let started = Instant::now();
    let (first, second) = tokio::join!(
        call(state.clone(), calls.clone()),
        call(state.clone(), calls.clone())
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!first.rpc_ready && !first.indexer_ready);
    assert_eq!(first.rpc_ready, second.rpc_ready);
    assert_eq!(first.indexer_ready, second.indexer_ready);

    let cached = cached_readiness(&state, Duration::from_millis(20), async {
        panic!("a fresh failed readiness result must be served from cache")
    })
    .await;
    assert!(!cached.rpc_ready && !cached.indexer_ready);
}

#[tokio::test]
async fn a_result_younger_than_the_ttl_is_served_without_a_probe() {
    let state = AsyncMutex::new(ReadinessState {
        checked_at: Instant::now() - READINESS_REFRESH * 2,
        rpc_ready: true,
        indexer_ready: true,
    });
    let cached = cached_readiness(&state, Duration::from_millis(20), async {
        panic!("a result the refresher keeps younger than the TTL is never probed inline")
    })
    .await;
    assert!(cached.rpc_ready && cached.indexer_ready);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_refresher_records_a_failing_rpc_without_a_request() {
    // Nothing listens on port 1, so every probe fails at once.
    let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
    let app = Arc::new(App {
        metrics: QuoteMetrics::default(),
        quote_queue: Arc::new(Semaphore::new(1)),
        quote_admission_wait: Duration::ZERO,
        cfg: config(),
        rpc: rpc.clone(),
        engine: Engine::for_profile(rpc, &FIXTURE_PROFILE),
        indexer: None,
        native_rfq: None,
        native_adapter: None,
        quote_slots: Arc::new(Semaphore::new(1)),
        compute_slots: Arc::new(Semaphore::new(1)),
        memory: crate::process_memory::ProcessMemory::new(None, 0).unwrap(),
        chain_verified: true,
        readiness: AsyncMutex::new(ReadinessState::new(true, true)),
    });
    spawn_readiness_refresher(&app, Duration::from_millis(10));
    let deadline = Instant::now() + READINESS_PROBE_TIMEOUT + Duration::from_secs(2);
    while app.readiness.lock().await.rpc_ready {
        assert!(Instant::now() < deadline, "the refresher never ran");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(app.readiness.lock().await.checked_at.elapsed() < READINESS_TTL);
}
