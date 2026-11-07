use super::NativeBeneficiaryAuthorizer;
use super::types::{FirmQuoteRequest, FirmQuoteWire, NativePair, NativeRfqError, NativeRfqSource};
use super::validation::validate_firm_quote;
use crate::abi;
use crate::chain::ChainProfile;
use crate::rpc::Rpc;
use alloy::eips::BlockId;
use alloy_primitives::{Address, B256, U256, aliases::U1024, keccak256};
use alloy_sol_types::{SolCall, SolValue};
use futures_util::future::BoxFuture;
use reqwest::Url;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex as PublishedMutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};

const PRODUCTION_API_URL: &str = "https://v2.api.native.org/swap-api-v2/";
const MAX_FIRM_QUOTE_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_ORDERBOOK_RESPONSE_BYTES: usize = 1024 * 1024;
// Route discovery is control-plane data: a stale candidate is made safe by the
// firm path's separate last look and final AMM comparison, while a stale
// negative only delays an RFQ opportunity. Keep discovery refreshes below one
// request/s so they cannot consume the account's full four-request/s budget.
const ORDERBOOK_DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(1);
const ORDERBOOK_LAST_LOOK_TTL: Duration = Duration::from_millis(250);
const ORDERBOOK_DISCOVERY_STALE_IF_BUSY_TTL: Duration = Duration::from_secs(30);
const MIN_EXPIRY_SECONDS: u64 = 15;
const MAX_EXPIRY_SECONDS: u64 = 120;
// The current Native account ceiling is 5 QPS. Allocate 4 QPS to this process
// so one request/s remains for window jitter, restarts, and operational probes.
const DEFAULT_NATIVE_RFQ_QPS: u32 = 4;
const MAX_NATIVE_RFQ_QPS: u32 = 1_000;
const DEFAULT_NATIVE_RFQ_QUEUE_WAIT: Duration = Duration::from_secs(1);
const MIN_NATIVE_RFQ_QUEUE_WAIT: Duration = Duration::from_millis(1);
const MAX_NATIVE_RFQ_QUEUE_WAIT: Duration = Duration::from_secs(10);
const DEFAULT_NATIVE_RFQ_MAX_INFLIGHT: usize = 8;
const MAX_NATIVE_RFQ_MAX_INFLIGHT: usize = 128;
const NATIVE_RFQ_PACER_WINDOW_NANOS: u64 = 1_000_000_000;
const MAX_ERC20_DECIMALS: u8 = 77;
const ERC20_DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];

#[derive(Clone, Copy, Eq, PartialEq)]
struct NativeRfqLimits {
    qps: u32,
    queue_wait: Duration,
    max_inflight: usize,
}

impl NativeRfqLimits {
    const DEFAULT: Self = Self {
        qps: DEFAULT_NATIVE_RFQ_QPS,
        queue_wait: DEFAULT_NATIVE_RFQ_QUEUE_WAIT,
        max_inflight: DEFAULT_NATIVE_RFQ_MAX_INFLIGHT,
    };
}

#[derive(Clone)]
pub struct NativeRfqConfig {
    base_url: Url,
    api_key: HeaderValue,
    timeout: Duration,
    expiry_seconds: u64,
    min_ttl_seconds: u64,
    qps: u32,
    queue_wait: Duration,
    max_inflight: usize,
    authorizer: NativeBeneficiaryAuthorizer,
    coordinator: Option<crate::native_coordinator::CoordinatorConfig>,
}

impl fmt::Debug for NativeRfqConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeRfqConfig")
            .field("base_url", &"[redacted]")
            .field("api_key", &"[redacted]")
            .field("timeout", &self.timeout)
            .field("expiry_seconds", &self.expiry_seconds)
            .field("min_ttl_seconds", &self.min_ttl_seconds)
            .field("qps", &self.qps)
            .field("queue_wait", &self.queue_wait)
            .field("max_inflight", &self.max_inflight)
            .field("authorizer", &self.authorizer)
            .finish()
    }
}

impl NativeRfqConfig {
    pub fn new(
        base_url: &str,
        api_key: &str,
        timeout: Duration,
        expiry_seconds: u64,
        min_ttl_seconds: u64,
        authorizer: NativeBeneficiaryAuthorizer,
    ) -> anyhow::Result<Self> {
        Self::new_with_limits(
            base_url,
            api_key,
            timeout,
            expiry_seconds,
            min_ttl_seconds,
            NativeRfqLimits::DEFAULT,
            authorizer,
        )
    }

    fn new_with_limits(
        base_url: &str,
        api_key: &str,
        timeout: Duration,
        expiry_seconds: u64,
        min_ttl_seconds: u64,
        limits: NativeRfqLimits,
        authorizer: NativeBeneficiaryAuthorizer,
    ) -> anyhow::Result<Self> {
        let config = Self::parse(
            base_url,
            api_key,
            timeout,
            expiry_seconds,
            min_ttl_seconds,
            limits,
            authorizer,
        )?;
        anyhow::ensure!(
            config.base_url.as_str() == PRODUCTION_API_URL,
            "Native RFQ production URL must be {PRODUCTION_API_URL}"
        );
        Ok(config)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_test(
        base_url: &str,
        api_key: &str,
        timeout: Duration,
        expiry_seconds: u64,
        min_ttl_seconds: u64,
        authorizer: NativeBeneficiaryAuthorizer,
    ) -> anyhow::Result<Self> {
        Self::parse(
            base_url,
            api_key,
            timeout,
            expiry_seconds,
            min_ttl_seconds,
            NativeRfqLimits::DEFAULT,
            authorizer,
        )
    }

    #[cfg(test)]
    fn new_for_test_with_limits(
        base_url: &str,
        api_key: &str,
        timeout: Duration,
        expiry_seconds: u64,
        min_ttl_seconds: u64,
        limits: NativeRfqLimits,
        authorizer: NativeBeneficiaryAuthorizer,
    ) -> anyhow::Result<Self> {
        Self::parse(
            base_url,
            api_key,
            timeout,
            expiry_seconds,
            min_ttl_seconds,
            limits,
            authorizer,
        )
    }

    fn parse(
        base_url: &str,
        api_key: &str,
        timeout: Duration,
        expiry_seconds: u64,
        min_ttl_seconds: u64,
        limits: NativeRfqLimits,
        authorizer: NativeBeneficiaryAuthorizer,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!api_key.trim().is_empty(), "Native RFQ API key is empty");
        anyhow::ensure!(
            (100..=10_000).contains(&timeout.as_millis()),
            "Native RFQ timeout must be in 100..=10000 milliseconds"
        );
        anyhow::ensure!(
            (MIN_EXPIRY_SECONDS..=MAX_EXPIRY_SECONDS).contains(&expiry_seconds),
            "Native RFQ expiry must be in {MIN_EXPIRY_SECONDS}..={MAX_EXPIRY_SECONDS} seconds"
        );
        anyhow::ensure!(
            min_ttl_seconds > 0 && min_ttl_seconds < expiry_seconds,
            "Native RFQ minimum TTL must be positive and below quote expiry"
        );
        anyhow::ensure!(
            (1..=MAX_NATIVE_RFQ_QPS).contains(&limits.qps),
            "Native RFQ QPS must be in 1..={MAX_NATIVE_RFQ_QPS}"
        );
        anyhow::ensure!(
            (MIN_NATIVE_RFQ_QUEUE_WAIT..=MAX_NATIVE_RFQ_QUEUE_WAIT).contains(&limits.queue_wait),
            "Native RFQ queue wait must be in {}..={} milliseconds",
            MIN_NATIVE_RFQ_QUEUE_WAIT.as_millis(),
            MAX_NATIVE_RFQ_QUEUE_WAIT.as_millis()
        );
        anyhow::ensure!(
            (1..=MAX_NATIVE_RFQ_MAX_INFLIGHT).contains(&limits.max_inflight),
            "Native RFQ max in-flight requests must be in 1..={MAX_NATIVE_RFQ_MAX_INFLIGHT}"
        );

        let mut base_url: Url = base_url.parse().context("invalid Native RFQ URL")?;
        anyhow::ensure!(
            base_url.scheme() == "https"
                || (base_url.scheme() == "http"
                    && base_url.host_str().is_some_and(|host| host == "localhost"
                        || host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback()))),
            "Native RFQ URL must use HTTPS (HTTP is accepted only for loopback tests)"
        );
        anyhow::ensure!(
            base_url.username().is_empty()
                && base_url.password().is_none()
                && base_url.query().is_none()
                && base_url.fragment().is_none(),
            "Native RFQ URL must not contain credentials, query, or fragment"
        );
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }

        let mut api_key = HeaderValue::from_str(api_key.trim())
            .context("Native RFQ API key is not a valid HTTP header value")?;
        api_key.set_sensitive(true);
        Ok(Self {
            base_url,
            api_key,
            timeout,
            expiry_seconds,
            min_ttl_seconds,
            qps: limits.qps,
            queue_wait: limits.queue_wait,
            max_inflight: limits.max_inflight,
            authorizer,
            coordinator: None,
        })
    }

    pub fn from_env(profile: &ChainProfile) -> anyhow::Result<Option<Self>> {
        let enabled = match std::env::var("SOLVER_NATIVE_RFQ_ENABLED") {
            Ok(value) => match value.trim() {
                "1" | "true" => true,
                "0" | "false" => false,
                other => anyhow::bail!(
                    "SOLVER_NATIVE_RFQ_ENABLED must be true/false or 1/0, got {other:?}"
                ),
            },
            Err(std::env::VarError::NotPresent) => false,
            Err(error) => anyhow::bail!("reading SOLVER_NATIVE_RFQ_ENABLED: {error}"),
        };
        if !enabled {
            return Ok(None);
        }
        // The Settler that executes a Native quote is the registry's current
        // one; startup checks that it carries this process's signer. This is
        // the same gate `/health` and the server's adapter use.
        profile.native_adapter()?;

        let api_key = std::env::var("SOLVER_NATIVE_RFQ_API_KEY")
            .context("SOLVER_NATIVE_RFQ_API_KEY is required when Native RFQ is enabled")?;
        let base_url = std::env::var("SOLVER_NATIVE_RFQ_URL")
            .unwrap_or_else(|_| PRODUCTION_API_URL.to_string());
        let timeout_ms = env_u64("SOLVER_NATIVE_RFQ_TIMEOUT_MS", 1_500)?;
        let expiry_seconds = env_u64("SOLVER_NATIVE_RFQ_EXPIRY_SECONDS", 60)?;
        // The backend asks for a fresh quote 30 s before its deadline; 45 s
        // leaves any Native quote it is offered at least 15 s to be signed.
        let min_ttl_seconds = env_u64("SOLVER_NATIVE_RFQ_MIN_TTL_SECONDS", 45)?;
        let qps = env_u32("SOLVER_NATIVE_RFQ_QPS", DEFAULT_NATIVE_RFQ_QPS)?;
        let queue_wait_ms = env_u64(
            "SOLVER_NATIVE_RFQ_QUEUE_WAIT_MS",
            DEFAULT_NATIVE_RFQ_QUEUE_WAIT.as_millis() as u64,
        )?;
        let max_inflight = env_usize(
            "SOLVER_NATIVE_RFQ_MAX_INFLIGHT",
            DEFAULT_NATIVE_RFQ_MAX_INFLIGHT,
        )?;
        let authorizer = NativeBeneficiaryAuthorizer::from_env()?;
        let mut config = Self::new_with_limits(
            &base_url,
            &api_key,
            Duration::from_millis(timeout_ms),
            expiry_seconds,
            min_ttl_seconds,
            NativeRfqLimits {
                qps,
                queue_wait: Duration::from_millis(queue_wait_ms),
                max_inflight,
            },
            authorizer,
        )?;
        config.coordinator = crate::native_coordinator::CoordinatorConfig::from_env()?;
        Ok(Some(config))
    }

    pub fn expiry_seconds(&self) -> u64 {
        self.expiry_seconds
    }

    pub fn authorizer(&self) -> &NativeBeneficiaryAuthorizer {
        &self.authorizer
    }

    pub fn qps(&self) -> u32 {
        self.qps
    }

    pub fn queue_wait(&self) -> Duration {
        self.queue_wait
    }

    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }
    pub fn quota_scope(&self) -> B256 {
        keccak256(
            (
                keccak256(self.base_url.as_str().as_bytes()),
                keccak256(self.api_key.as_bytes()),
            )
                .abi_encode(),
        )
    }
    pub fn quota_mode(&self) -> &'static str {
        if self.coordinator.is_some() {
            "coordinated"
        } else {
            "process"
        }
    }
}

fn env_u64(key: &str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(key) {
        Ok(value) => value.parse().with_context(|| format!("{key} is invalid")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(anyhow::anyhow!("reading {key}: {error}")),
    }
}

fn env_usize(key: &str, default: usize) -> anyhow::Result<usize> {
    match std::env::var(key) {
        Ok(value) => value.parse().with_context(|| format!("{key} is invalid")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(anyhow::anyhow!("reading {key}: {error}")),
    }
}

fn env_u32(key: &str, default: u32) -> anyhow::Result<u32> {
    match std::env::var(key) {
        Ok(value) => value.parse().with_context(|| format!("{key} is invalid")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(anyhow::anyhow!("reading {key}: {error}")),
    }
}

fn native_request_interval(qps: u32) -> Duration {
    debug_assert!(qps > 0);
    Duration::from_nanos(NATIVE_RFQ_PACER_WINDOW_NANOS.div_ceil(u64::from(qps)))
}

#[derive(Clone)]
pub struct NativeRfqClient {
    http: reqwest::Client,
    rpc: Rpc,
    config: NativeRfqConfig,
    inflight: Arc<Semaphore>,
    next_request_at: Arc<Mutex<Instant>>,
    _quota: Arc<NativeQuota>,
    work: Option<crate::work_budget::WorkBudget>,
    // The inner Arc's identity is the generation token carried by a firm call.
    orderbook: Arc<BookRefresh>,
    // Preserve observed integration metadata, including negative entries.
    // Only missing batches wait for the serial RPC gate.
    token_decimals: Arc<NativeMetadata>,
    coordinator: Option<crate::native_coordinator::CoordinatorClient>,
}

struct NativeQuota {
    limits: NativeRfqLimits,
    inflight: Arc<Semaphore>,
    next_request_at: Arc<Mutex<Instant>>,
    coordinator: Option<crate::native_coordinator::CoordinatorConfig>,
    #[cfg(test)]
    admissions: PublishedMutex<Vec<Instant>>,
}

impl NativeQuota {
    fn shared(config: &NativeRfqConfig) -> anyhow::Result<Arc<Self>> {
        static SCOPES: OnceLock<PublishedMutex<HashMap<B256, Weak<NativeQuota>>>> = OnceLock::new();
        // Registry keys retain only digests, never another copy of credentials.
        let scope = config.quota_scope();
        let limits = NativeRfqLimits {
            qps: config.qps,
            queue_wait: config.queue_wait,
            max_inflight: config.max_inflight,
        };
        let mut scopes = SCOPES
            .get_or_init(PublishedMutex::default)
            .lock()
            .expect("Native quota registry lock");
        scopes.retain(|_, quota| quota.strong_count() > 0);
        if let Some(quota) = scopes.get(&scope).and_then(Weak::upgrade) {
            anyhow::ensure!(
                quota.limits == limits && quota.coordinator == config.coordinator,
                "Native clients sharing credentials must use identical quota limits"
            );
            return Ok(quota);
        }
        let quota = Arc::new(Self {
            limits,
            inflight: Arc::new(Semaphore::new(limits.max_inflight)),
            next_request_at: Arc::new(Mutex::new(Instant::now())),
            coordinator: config.coordinator.clone(),
            #[cfg(test)]
            admissions: PublishedMutex::new(Vec::new()),
        });
        scopes.insert(scope, Arc::downgrade(&quota));
        Ok(quota)
    }
}

#[derive(Default)]
struct BookRefresh {
    published: PublishedMutex<OrderbookCache>,
    // Observations and invalidations retain the original FIFO refresh order.
    // This gate may span HTTP; the published-state lock never does.
    gate: Mutex<()>,
    observed: PublishedMutex<Vec<Weak<CachedOrderbook>>>,
}

#[derive(Default)]
struct NativeMetadata {
    published: PublishedMutex<HashMap<Address, Option<u8>>>,
    // Serialize missing batches, including queued retries after transport
    // failures. Cached-only readers do not acquire this gate.
    missing_batch: Mutex<()>,
}

impl NativeMetadata {
    fn cached(&self, requested: &HashSet<Address>) -> Option<HashMap<Address, u8>> {
        let cache = self
            .published
            .lock()
            .expect("Native decimals published lock");
        requested
            .iter()
            .all(|token| cache.contains_key(token))
            .then(|| {
                requested
                    .iter()
                    .filter_map(|token| {
                        cache
                            .get(token)
                            .copied()
                            .flatten()
                            .map(|value| (*token, value))
                    })
                    .collect()
            })
    }
}

#[derive(Debug, Default)]
struct OrderbookCache {
    /// Most recent success or failure. Caching failures gives concurrent
    /// callers the same singleflight result instead of retrying in a convoy.
    latest: Option<Arc<CachedOrderbook>>,
    /// Kept separately so discovery can use a bounded stale orderbook when the
    /// shared account pacer is busy. Firm last-look never reads this fallback.
    last_success: Option<Arc<CachedOrderbook>>,
}

#[derive(Debug)]
struct CachedOrderbook {
    chain: String,
    fetched_at: Instant,
    result: Result<NativeOrderbook, NativeRfqError>,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeMemoryUsage {
    pub metadata_entries: usize,
    pub estimated_metadata_bytes: usize,
    pub estimated_cached_book_bytes: usize,
    pub estimated_live_book_bytes: usize,
    pub estimated_book_tracker_bytes: usize,
    pub process_firm_permits_used: usize,
    pub coordinator_configured: bool,
}

impl CachedOrderbook {
    fn estimated_bytes(&self) -> usize {
        let data = self.result.as_ref().ok().map_or(0, |book| {
            book.markets.capacity()
                * (std::mem::size_of::<NativePair>()
                    + std::mem::size_of::<Option<OrderbookMarket>>()
                    + 1)
                + book
                    .markets
                    .values()
                    .flatten()
                    .map(|market| {
                        market.levels.capacity() * std::mem::size_of::<(Decimal, Decimal)>()
                    })
                    .sum::<usize>()
        });
        std::mem::size_of::<Self>() + self.chain.capacity() + data
    }
}

#[derive(Debug, Default)]
struct NativeOrderbook {
    markets: HashMap<NativePair, Option<OrderbookMarket>>,
}

impl NativeOrderbook {
    #[cfg(test)]
    fn len(&self) -> usize {
        self.markets.len()
    }

    fn contains(&self, pair: &NativePair) -> bool {
        self.markets.contains_key(pair)
    }

    fn market(&self, pair: &NativePair) -> Option<&OrderbookMarket> {
        self.markets.get(pair).and_then(Option::as_ref)
    }

    #[cfg(test)]
    fn from_pairs(pairs: impl IntoIterator<Item = NativePair>) -> Self {
        Self {
            markets: pairs.into_iter().map(|pair| (pair, None)).collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrderbookSide {
    Bid,
    Ask,
}

#[derive(Debug)]
struct OrderbookMarket {
    side: OrderbookSide,
    minimum_in_base: Decimal,
    levels: Vec<(Decimal, Decimal)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Decimal {
    coefficient: U256,
    scale: u8,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DecimalWire {
    Number(serde_json::Number),
    String(String),
}

impl DecimalWire {
    fn parse(&self) -> Option<Decimal> {
        match self {
            Self::Number(value) => parse_decimal(&value.to_string()),
            Self::String(value) => parse_decimal(value),
        }
    }
}

#[derive(Debug, Deserialize)]
struct OrderbookEntryWire {
    base_address: String,
    quote_address: String,
    side: String,
    minimum_in_base: DecimalWire,
    levels: Vec<[DecimalWire; 2]>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OrderbookWire {
    Entries(Vec<OrderbookEntryWire>),
    Error { code: u32 },
}

fn parse_decimal(value: &str) -> Option<Decimal> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    let value = value.strip_prefix('+').unwrap_or(value);
    let mut exponent_parts = value.split(['e', 'E']);
    let mantissa = exponent_parts.next()?;
    let exponent = exponent_parts.next().map_or(Some(0i16), |part| {
        (!part.is_empty())
            .then(|| part.parse::<i16>().ok())
            .flatten()
    })?;
    if exponent_parts.next().is_some() {
        return None;
    }

    let mut mantissa_parts = mantissa.split('.');
    let whole = mantissa_parts.next()?;
    let fraction = mantissa_parts.next().unwrap_or_default();
    if mantissa_parts.next().is_some()
        || (whole.is_empty() && fraction.is_empty())
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let digits = format!("{whole}{fraction}");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some(Decimal {
            coefficient: U256::ZERO,
            scale: 0,
        });
    }
    let mut coefficient = U256::from_str_radix(digits, 10).ok()?;
    let scale = i32::try_from(fraction.len()).ok()? - i32::from(exponent);
    let mut scale = if scale < 0 {
        let multiplier = pow10_wide(u16::try_from(-scale).ok()?)?;
        coefficient = narrow_u1024(U1024::from(coefficient) * multiplier)?;
        0
    } else {
        u8::try_from(scale)
            .ok()
            .filter(|scale| *scale <= MAX_ERC20_DECIMALS)?
    };
    while scale > 0 && coefficient % U256::from(10u8) == U256::ZERO {
        coefficient /= U256::from(10u8);
        scale -= 1;
    }
    Some(Decimal { coefficient, scale })
}

fn pow10_wide(exponent: u16) -> Option<U1024> {
    if exponent > u16::from(MAX_ERC20_DECIMALS) * 2 {
        return None;
    }
    let mut value = U1024::ONE;
    for _ in 0..exponent {
        value *= U1024::from(10u8);
    }
    Some(value)
}

fn narrow_u1024(value: U1024) -> Option<U256> {
    if value >> 256usize != U1024::ZERO {
        return None;
    }
    Some(U256::from_limbs(
        value.as_limbs()[..4].try_into().expect("four low limbs"),
    ))
}

fn rounded_wide_ratio(numerator: U1024, denominator: U1024, round_up: bool) -> Option<U256> {
    if denominator.is_zero() {
        return None;
    }
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    let rounded = if round_up && !remainder.is_zero() {
        quotient + U1024::ONE
    } else {
        quotient
    };
    narrow_u1024(rounded)
}

fn decimal_to_units(value: Decimal, decimals: u8, round_up: bool) -> Option<U256> {
    if decimals >= value.scale {
        let multiplier = pow10_wide(u16::from(decimals - value.scale))?;
        narrow_u1024(U1024::from(value.coefficient) * multiplier)
    } else {
        rounded_wide_ratio(
            U1024::from(value.coefficient),
            pow10_wide(u16::from(value.scale - decimals))?,
            round_up,
        )
    }
}

/// Convert an exact raw base-token amount through a quote/base decimal price.
fn quote_units_for_base(
    base_amount: U256,
    base_decimals: u8,
    quote_decimals: u8,
    price: Decimal,
    round_up: bool,
) -> Option<U256> {
    let numerator = U1024::from(base_amount)
        * U1024::from(price.coefficient)
        * pow10_wide(u16::from(quote_decimals))?;
    let denominator = pow10_wide(u16::from(base_decimals))? * pow10_wide(u16::from(price.scale))?;
    rounded_wide_ratio(numerator, denominator, round_up)
}

/// Convert an exact raw quote-token amount through the inverse quote/base price.
fn base_units_for_quote(
    quote_amount: U256,
    quote_decimals: u8,
    base_decimals: u8,
    price: Decimal,
) -> Option<U256> {
    let numerator = U1024::from(quote_amount)
        * pow10_wide(u16::from(base_decimals))?
        * pow10_wide(u16::from(price.scale))?;
    let denominator = U1024::from(price.coefficient) * pow10_wide(u16::from(quote_decimals))?;
    rounded_wide_ratio(numerator, denominator, false)
}

impl OrderbookMarket {
    /// Integrate non-cumulative Native levels and round every conversion toward
    /// a lower output. Returning None means the request is below the advertised
    /// minimum, exceeds depth, or cannot be represented in token base units.
    fn indicative_amount_out(
        &self,
        amount_in: U256,
        token_in_decimals: u8,
        token_out_decimals: u8,
    ) -> Option<U256> {
        if amount_in.is_zero() {
            return None;
        }
        match self.side {
            OrderbookSide::Bid => {
                let minimum = decimal_to_units(self.minimum_in_base, token_in_decimals, true)?;
                if amount_in < minimum {
                    return None;
                }
                let mut remaining = amount_in;
                let mut output = U256::ZERO;
                for (quantity, price) in &self.levels {
                    let level = decimal_to_units(*quantity, token_in_decimals, false)?;
                    let taken = remaining.min(level);
                    if taken.is_zero() {
                        continue;
                    }
                    output = output.checked_add(quote_units_for_base(
                        taken,
                        token_in_decimals,
                        token_out_decimals,
                        *price,
                        false,
                    )?)?;
                    remaining -= taken;
                    if remaining.is_zero() {
                        return (!output.is_zero()).then_some(output);
                    }
                }
                None
            }
            OrderbookSide::Ask => {
                let minimum = decimal_to_units(self.minimum_in_base, token_out_decimals, true)?;
                let mut remaining = amount_in;
                let mut output = U256::ZERO;
                for (quantity, price) in &self.levels {
                    let level = decimal_to_units(*quantity, token_out_decimals, false)?;
                    if level.is_zero() {
                        continue;
                    }
                    let full_cost = quote_units_for_base(
                        level,
                        token_out_decimals,
                        token_in_decimals,
                        *price,
                        true,
                    )?;
                    if remaining >= full_cost {
                        output = output.checked_add(level)?;
                        remaining -= full_cost;
                        if remaining.is_zero() {
                            break;
                        }
                    } else {
                        let partial = base_units_for_quote(
                            remaining,
                            token_in_decimals,
                            token_out_decimals,
                            *price,
                        )?
                        .min(level);
                        output = output.checked_add(partial)?;
                        remaining = U256::ZERO;
                        break;
                    }
                }
                (remaining.is_zero() && output >= minimum && !output.is_zero()).then_some(output)
            }
        }
    }
}

impl NativeRfqClient {
    /// Known owned container sizes are estimates. RSS includes allocator,
    /// decoded HTTP buffers, leases and all other serving modules separately.
    pub fn memory_usage(&self) -> NativeMemoryUsage {
        let metadata = self
            .token_decimals
            .published
            .lock()
            .expect("Native metadata memory");
        let metadata_entries = metadata.len();
        let estimated_metadata_bytes = std::mem::size_of::<NativeMetadata>()
            + metadata.capacity()
                * (std::mem::size_of::<Address>() + std::mem::size_of::<Option<u8>>() + 1);
        drop(metadata);
        let cache = self.orderbook.published.lock().expect("Native book memory");
        let estimated_cached_book_bytes = cache
            .latest
            .as_ref()
            .map_or(0, |book| book.estimated_bytes())
            + cache
                .last_success
                .as_ref()
                .filter(|book| {
                    cache
                        .latest
                        .as_ref()
                        .is_none_or(|latest| !Arc::ptr_eq(book, latest))
                })
                .map_or(0, |book| book.estimated_bytes());
        drop(cache);
        let mut observed = self
            .orderbook
            .observed
            .lock()
            .expect("Native book allocation tracker");
        observed.retain(|book| book.strong_count() > 0);
        NativeMemoryUsage {
            metadata_entries,
            estimated_metadata_bytes,
            estimated_cached_book_bytes,
            estimated_live_book_bytes: observed
                .iter()
                .filter_map(Weak::upgrade)
                .map(|book| book.estimated_bytes())
                .sum(),
            estimated_book_tracker_bytes: observed.capacity()
                * std::mem::size_of::<Weak<CachedOrderbook>>(),
            process_firm_permits_used: self.config.max_inflight - self.inflight.available_permits(),
            coordinator_configured: self.coordinator.is_some(),
        }
    }
    pub fn new(config: NativeRfqConfig, rpc: Rpc) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building Native RFQ HTTP client")?;
        let quota = NativeQuota::shared(&config)?;
        let coordinator = config.coordinator.clone().map(|settings| {
            crate::native_coordinator::CoordinatorClient::new(
                settings,
                http.clone(),
                config.quota_scope(),
            )
        });
        Ok(Self {
            http,
            rpc,
            config,
            inflight: quota.inflight.clone(),
            next_request_at: quota.next_request_at.clone(),
            _quota: quota,
            work: None,
            orderbook: Arc::new(BookRefresh::default()),
            token_decimals: Arc::new(NativeMetadata::default()),
            coordinator,
        })
    }

    pub fn with_work(&self, work: crate::work_budget::WorkBudget) -> Self {
        let mut client = self.clone();
        client.rpc = self.rpc.with_work_budget(work.clone());
        client.work = Some(work);
        client
    }

    fn charge_http(
        &self,
        calls: u64,
        bytes: usize,
        firm: bool,
        work: Option<&crate::work_budget::WorkBudget>,
    ) -> Result<(), NativeRfqError> {
        if let Some(work) = work {
            work.charge(
                crate::work_budget::WorkCharge {
                    rpc_calls: calls,
                    rpc_bytes: bytes as u64,
                    quote_samples: u64::from(firm && calls > 0),
                    ..Default::default()
                },
                "Native physical HTTP",
            )
            .map_err(|_| NativeRfqError::WorkBudget)?;
        }
        Ok(())
    }

    async fn pace_outbound_request(
        &self,
    ) -> Result<Option<crate::native_coordinator::CoordinatorPermit>, NativeRfqError> {
        if let Some(coordinator) = &self.coordinator {
            return coordinator
                .acquire(false, true, self.config.queue_wait, self.work.as_ref())
                .await
                .map(Some);
        }
        // Keep the mutex through the wait: every endpoint and client clone
        // shares one FIFO schedule. A timed-out waiter drops its queue place
        // without reserving capacity, so another request may use it.
        tokio::time::timeout(self.config.queue_wait, async {
            let mut next = self.next_request_at.lock().await;
            let now = Instant::now();
            if *next > now {
                tokio::time::sleep(next.saturating_duration_since(now)).await;
            }
            let admitted_at = Instant::now();
            *next = admitted_at + native_request_interval(self.config.qps);
            #[cfg(test)]
            self._quota
                .admissions
                .lock()
                .expect("Native test admission clock")
                .push(admitted_at);
        })
        .await
        .map(|_| None)
        .map_err(|_| NativeRfqError::QueueTimeout)
    }
    fn outbound_timeout(
        &self,
        permit: Option<&crate::native_coordinator::CoordinatorPermit>,
    ) -> Result<Duration, NativeRfqError> {
        let remaining = permit.map_or(self.config.timeout, |permit| {
            permit
                .deadline()
                .saturating_duration_since(Instant::now())
                .min(self.config.timeout)
        });
        if remaining.is_zero() {
            return Err(NativeRfqError::QueueTimeout);
        }
        Ok(remaining)
    }

    async fn observe_orderbook(
        &self,
        chain: &str,
        max_age: Duration,
        stale_if_busy: Option<Duration>,
    ) -> Result<Option<Arc<CachedOrderbook>>, NativeRfqError> {
        // LatestAfterInFlight: even a TTL-valid previous book must not bypass
        // a refresh already ahead of this observation in the FIFO gate.
        let _refresh = self.orderbook.gate.lock().await;
        {
            let cache = self
                .orderbook
                .published
                .lock()
                .expect("Native orderbook published lock");
            if let Some(entry) = cache.latest.as_ref()
                && entry.chain == chain
                && entry.fetched_at.elapsed() < max_age
            {
                return Self::resolve_orderbook_entry(&cache, entry, chain, stale_if_busy);
            }
        }

        // Orderbook refresh is control-plane work, not a firm quote. It shares
        // the account-wide outbound pacer below but never occupies the firm
        // bulkhead; otherwise an unrelated AMM-only pair can be reported busy
        // before its absence from Native's inventory is known.
        let result = match self.fetch_orderbook(chain).await {
            Ok(Some(orderbook)) => Ok(orderbook),
            Ok(None) => return Ok(None),
            // Request-local admission failures are not market observations and
            // must not poison the public negative cache for another user.
            Err(NativeRfqError::WorkBudget) => return Err(NativeRfqError::WorkBudget),
            Err(error) => Err(error),
        };
        let entry = Arc::new(CachedOrderbook {
            chain: chain.to_owned(),
            fetched_at: Instant::now(),
            result,
        });
        {
            let mut observed = self
                .orderbook
                .observed
                .lock()
                .expect("Native book allocation tracker");
            observed.retain(|book| book.strong_count() > 0);
            observed.push(Arc::downgrade(&entry));
        }
        let mut cache = self
            .orderbook
            .published
            .lock()
            .expect("Native orderbook published lock");
        let observed = Self::resolve_orderbook_entry(&cache, &entry, chain, stale_if_busy);
        if entry.result.is_ok() {
            cache.last_success = Some(Arc::clone(&entry));
        }
        cache.latest = Some(entry);
        observed
    }

    fn resolve_orderbook_entry(
        cache: &OrderbookCache,
        entry: &Arc<CachedOrderbook>,
        chain: &str,
        stale_if_busy: Option<Duration>,
    ) -> Result<Option<Arc<CachedOrderbook>>, NativeRfqError> {
        match &entry.result {
            Ok(_) => Ok(Some(Arc::clone(entry))),
            Err(error) => {
                if error.is_retryable_capacity()
                    && let Some(max_stale) = stale_if_busy
                    && let Some(stale) = cache.last_success.as_ref()
                    && stale.chain == chain
                    && stale.fetched_at.elapsed() < max_stale
                {
                    return Ok(Some(Arc::clone(stale)));
                }
                Err(error.clone())
            }
        }
    }

    async fn observe_orderbook_direction(
        &self,
        chain: &str,
        token_in: Address,
        token_out: Address,
        max_age: Duration,
        stale_if_busy: Option<Duration>,
    ) -> Result<Option<Arc<CachedOrderbook>>, NativeRfqError> {
        let Some(observation) = self
            .observe_orderbook(chain, max_age, stale_if_busy)
            .await?
        else {
            return Ok(None);
        };
        let available = observation
            .result
            .as_ref()
            .map(|directions| directions.contains(&NativePair::new(token_in, token_out)))
            .map_err(Clone::clone)?;
        Ok(available.then_some(observation))
    }

    async fn observe_available_pairs(
        &self,
        chain: &str,
        pairs: &[NativePair],
    ) -> Result<Vec<NativePair>, NativeRfqError> {
        if pairs.is_empty() {
            return Ok(Vec::new());
        }
        let Some(observation) = self
            .observe_orderbook(
                chain,
                ORDERBOOK_DISCOVERY_CACHE_TTL,
                Some(ORDERBOOK_DISCOVERY_STALE_IF_BUSY_TTL),
            )
            .await?
        else {
            return Ok(Vec::new());
        };
        let directions = observation.result.as_ref().map_err(Clone::clone)?;
        Ok(pairs
            .iter()
            .copied()
            .filter(|pair| directions.contains(pair))
            .collect())
    }

    async fn fetch_orderbook(
        &self,
        chain: &str,
    ) -> Result<Option<NativeOrderbook>, NativeRfqError> {
        let mut endpoint = self
            .config
            .base_url
            .join("v1/orderbook")
            .map_err(|_| NativeRfqError::InvalidResponse("invalid configured endpoint"))?;
        endpoint.query_pairs_mut().append_pair("chain", chain);

        let mut headers = HeaderMap::new();
        headers.insert("apikey", self.config.api_key.clone());
        let outbound = self.pace_outbound_request().await?;
        let timeout = self.outbound_timeout(outbound.as_ref())?;
        let http_work = outbound
            .as_ref()
            .and_then(|permit| permit.dispatch_work())
            .or_else(|| self.work.clone());
        self.charge_http(1, 0, false, http_work.as_ref())?;
        let response = self
            .http
            .get(endpoint)
            .timeout(timeout)
            .headers(headers)
            .send()
            .await
            .map_err(|_| NativeRfqError::Transport)?;
        if !response.status().is_success() {
            return Err(NativeRfqError::Http(response.status().as_u16()));
        }
        let body =
            bounded_response_body(response, MAX_ORDERBOOK_RESPONSE_BYTES, http_work.as_ref())
                .await?;
        let wire: OrderbookWire =
            serde_json::from_slice(&body).map_err(|_| NativeRfqError::InvalidJson)?;
        let result = match wire {
            OrderbookWire::Entries(entries) => parse_orderbook(entries).map(Some),
            OrderbookWire::Error { code } => Err(NativeRfqError::Api(code)),
        };
        if let Some(outbound) = outbound {
            outbound.release();
        }
        result
    }

    async fn token_decimals(
        &self,
        tokens: impl IntoIterator<Item = Address>,
    ) -> Result<HashMap<Address, u8>, NativeRfqError> {
        let requested: HashSet<_> = tokens.into_iter().collect();
        if let Some(cached) = self.token_decimals.cached(&requested) {
            return Ok(cached);
        }
        let _batch = self.token_decimals.missing_batch.lock().await;
        let missing: Vec<_> = {
            let cache = self
                .token_decimals
                .published
                .lock()
                .expect("Native decimals published lock");
            requested
                .iter()
                .copied()
                .filter(|token| !cache.contains_key(token))
                .collect()
        };
        if !missing.is_empty() {
            let results = self
                .rpc
                .multicall(
                    missing
                        .iter()
                        .map(|token| (*token, ERC20_DECIMALS_SELECTOR.to_vec()))
                        .collect(),
                    BlockId::latest(),
                )
                .await
                .map_err(|error| {
                    if is_work_error(&error) {
                        NativeRfqError::WorkBudget
                    } else {
                        NativeRfqError::Transport
                    }
                })?;
            if results.len() != missing.len() {
                return Err(NativeRfqError::Transport);
            }
            let mut cache = self
                .token_decimals
                .published
                .lock()
                .expect("Native decimals published lock");
            for (token, result) in missing.into_iter().zip(results) {
                cache.insert(
                    token,
                    result
                        .as_deref()
                        .and_then(decode_token_decimals)
                        .filter(|decimals| *decimals <= MAX_ERC20_DECIMALS),
                );
            }
        }
        Ok(self
            .token_decimals
            .cached(&requested)
            .expect("missing batch published every requested token"))
    }

    async fn observe_indicative_quotes(
        &self,
        chain: &str,
        requests: &[(NativePair, U256)],
    ) -> Result<Vec<(NativePair, U256, U256)>, NativeRfqError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        let Some(observation) = self
            .observe_orderbook(
                chain,
                ORDERBOOK_DISCOVERY_CACHE_TTL,
                Some(ORDERBOOK_DISCOVERY_STALE_IF_BUSY_TTL),
            )
            .await?
        else {
            return Ok(Vec::new());
        };
        let orderbook = observation.result.as_ref().map_err(Clone::clone)?;
        let tokens = requests.iter().flat_map(|(pair, _)| {
            orderbook
                .market(pair)
                .is_some()
                .then_some([pair.token_in, pair.token_out])
                .into_iter()
                .flatten()
        });
        let decimals = self.token_decimals(tokens).await?;
        Ok(requests
            .iter()
            .filter_map(|(pair, amount_in)| {
                let market = orderbook.market(pair)?;
                let token_in_decimals = *decimals.get(&pair.token_in)?;
                let token_out_decimals = *decimals.get(&pair.token_out)?;
                let amount_out = market.indicative_amount_out(
                    *amount_in,
                    token_in_decimals,
                    token_out_decimals,
                )?;
                Some((*pair, *amount_in, amount_out))
            })
            .collect())
    }

    async fn invalidate_orderbook(&self, observed: &Arc<CachedOrderbook>) {
        let _refresh = self.orderbook.gate.lock().await;
        let mut cache = self
            .orderbook
            .published
            .lock()
            .expect("Native orderbook published lock");
        // An older firm response waits behind the refresh gate before checking
        // Arc identity, so it cannot erase a newer success or failure.
        if cache
            .latest
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, observed))
        {
            cache.latest = None;
        }
        if cache
            .last_success
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, observed))
        {
            cache.last_success = None;
        }
    }

    async fn request_firm_quote(
        &self,
        request: FirmQuoteRequest,
    ) -> Result<Option<super::ValidatedFirmQuote>, NativeRfqError> {
        let lease = match &self.coordinator {
            Some(coordinator) => Some(
                coordinator
                    .acquire(true, false, self.config.queue_wait, self.work.as_ref())
                    .await?,
            ),
            None => None,
        };
        let mut client = self.clone();
        if let Some(work) = lease.as_ref().and_then(|lease| lease.dispatch_work()) {
            client = self.with_work(work);
        }
        let result = if let Some(lease) = &lease {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(lease.deadline()),
                client.request_firm_quote_inner(request),
            )
            .await
            .map_err(|_| NativeRfqError::QueueTimeout)?
        } else {
            client.request_firm_quote_inner(request).await
        };
        if let Some(lease) = lease {
            lease.release();
        }
        result
    }

    async fn request_firm_quote_inner(
        &self,
        mut request: FirmQuoteRequest,
    ) -> Result<Option<super::ValidatedFirmQuote>, NativeRfqError> {
        // This bulkhead bounds active plus pace-waiting Native attempts. When
        // it is full, fail fast so the caller can retry instead of silently
        // changing a Native-eligible request into an AMM-only quote.
        // The permit stays live through HTTP parsing and on-chain validation.
        let inflight_permit = match Arc::clone(&self.inflight).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Err(NativeRfqError::Saturated),
        };
        let chain_clock_started = Instant::now();
        // V6 pAMM treats amountOut as a live reference and requires a real
        // amountOutMinimum. A zero-slippage request remains eligible for the
        // independently computed AMM route, but is not sent to Native.
        if request.slippage_bps == 0 {
            return Ok(None);
        }
        let Some(expiry_seconds) = usable_expiry(
            request.expiry_seconds,
            self.config.expiry_seconds,
            self.config.min_ttl_seconds,
        ) else {
            return Ok(None);
        };
        request.expiry_seconds = expiry_seconds;

        // Native removes the complete directional entry when liquidity is no
        // longer available. A short-cached last look avoids requesting firm
        // calldata for a direction Native has already withdrawn.
        let Some(orderbook_observation) = self
            .observe_orderbook_direction(
                request.identity.api_chain,
                request.token_in,
                request.token_out,
                ORDERBOOK_LAST_LOOK_TTL,
                None,
            )
            .await?
        else {
            return Ok(None);
        };

        let mut endpoint = self
            .config
            .base_url
            .join("v1/firm-quote")
            .map_err(|_| NativeRfqError::InvalidResponse("invalid configured endpoint"))?;
        let mut headers = HeaderMap::new();
        headers.insert("apikey", self.config.api_key.clone());
        let mut query = vec![
            ("from_address", format!("{:#x}", request.settler)),
            ("beneficiary_address", format!("{:#x}", request.beneficiary)),
            // Settler's BASIC action is the direct Native Router caller.
            ("execution_payer", format!("{:#x}", request.settler)),
            ("src_chain", request.identity.api_chain.to_string()),
            ("dst_chain", request.identity.api_chain.to_string()),
            ("token_in", format!("{:#x}", request.token_in)),
            ("token_out", format!("{:#x}", request.token_out)),
            ("amount_wei", request.amount_in.to_string()),
            ("expiry_time", request.expiry_seconds.to_string()),
            ("slippage", bps_as_percent(request.slippage_bps)),
            (
                "timeout_millis",
                self.config.timeout.as_millis().to_string(),
            ),
            ("version", request.identity.router_version.to_string()),
            ("allow_multihop", "false".to_string()),
            ("show_blacklist_status", "true".to_string()),
        ];
        if let Some(tx_origin) = request.tx_origin {
            query.push(("tx_origin", format!("{tx_origin:#x}")));
        }
        endpoint
            .query_pairs_mut()
            .extend_pairs(query.iter().map(|(key, value)| (*key, value.as_str())));

        let outbound = self.pace_outbound_request().await?;
        let timeout = self.outbound_timeout(outbound.as_ref())?;
        let http_work = outbound
            .as_ref()
            .and_then(|permit| permit.dispatch_work())
            .or_else(|| self.work.clone());
        self.charge_http(1, 0, true, http_work.as_ref())?;
        let response = self
            .http
            .get(endpoint)
            .timeout(timeout)
            .headers(headers)
            .send()
            .await
            .map_err(|_| NativeRfqError::Transport)?;
        if !response.status().is_success() {
            return Err(NativeRfqError::Http(response.status().as_u16()));
        }
        let body =
            bounded_response_body(response, MAX_FIRM_QUOTE_RESPONSE_BYTES, http_work.as_ref())
                .await?;
        let wire: FirmQuoteWire =
            serde_json::from_slice(&body).map_err(|_| NativeRfqError::InvalidJson)?;
        if let Some(outbound) = outbound {
            outbound.release();
        }
        if let Some(code) = wire.code {
            if is_direction_unavailable_code(code) {
                // The orderbook direction may have disappeared between the
                // last look and the firm request. Force the next solve to
                // refresh instead of serving the remaining cache window.
                self.invalidate_orderbook(&orderbook_observation).await;
            }
            return if is_no_quote_code(code) {
                Ok(None)
            } else {
                Err(NativeRfqError::Api(code))
            };
        }
        if !wire.success {
            return Err(NativeRfqError::InvalidResponse(
                "unsuccessful response has no API error code",
            ));
        }
        if wire.is_black_address {
            return Ok(None);
        }
        let validation_timestamp = request
            .chain_timestamp
            .saturating_add(chain_clock_started.elapsed().as_secs());
        let mut quote = validate_firm_quote(
            &request,
            wire,
            validation_timestamp,
            self.config.min_ttl_seconds,
        )?;
        let Some(observation) = self.quote_is_usable_onchain(&quote).await? else {
            return Ok(None);
        };
        quote.record_observation(observation.number, observation.hash);
        drop(inflight_permit);
        Ok(Some(quote))
    }

    async fn quote_is_usable_onchain(
        &self,
        quote: &super::ValidatedFirmQuote,
    ) -> Result<Option<crate::rpc::CanonicalBlock>, NativeRfqError> {
        let canonical = self
            .rpc
            .canonical_block(BlockId::latest())
            .await
            .map_err(onchain_getter_error)?;
        self.quote_is_usable_onchain_at(quote, canonical.hash)
            .await
            .map(|usable| usable.then_some(canonical))
    }

    async fn quote_is_usable_onchain_at(
        &self,
        quote: &super::ValidatedFirmQuote,
        block_hash: B256,
    ) -> Result<bool, NativeRfqError> {
        let at = BlockId::hash_canonical(block_hash);
        let signer_call = abi::rfqSignersCall {
            signer: quote.signer,
        }
        .abi_encode();
        let nonce_call = abi::noncesCall { nonce: quote.nonce }.abi_encode();
        let (signer_result, nonce_result) = tokio::try_join!(
            self.rpc.eth_call(quote.pool, signer_call, at),
            self.rpc.eth_call(quote.pool, nonce_call, at),
        )
        .map_err(onchain_getter_error)?;
        quote_pool_state_is_usable(&signer_result, &nonce_result)
    }
}

fn is_work_error(error: &anyhow::Error) -> bool {
    error.is::<crate::work_budget::WorkLimitExceeded>()
        || error.is::<crate::budget::SolverBudgetExceeded>()
}
fn onchain_getter_error(error: anyhow::Error) -> NativeRfqError {
    if is_work_error(&error) {
        NativeRfqError::WorkBudget
    } else {
        NativeRfqError::OnchainVerification
    }
}

fn quote_pool_state_is_usable(
    signer_result: &[u8],
    nonce_result: &[u8],
) -> Result<bool, NativeRfqError> {
    let signer_authorized = decode_canonical_abi_bool(signer_result)?;
    if !signer_authorized {
        return Err(NativeRfqError::InvalidResponse(
            "quote signer is not authorized by the Native RFQ pool",
        ));
    }
    let nonce_consumed = decode_canonical_abi_bool(nonce_result)?;
    Ok(!nonce_consumed)
}

fn decode_canonical_abi_bool(result: &[u8]) -> Result<bool, NativeRfqError> {
    let word: &[u8; 32] = result
        .try_into()
        .map_err(|_| NativeRfqError::OnchainVerification)?;
    if word[..31].iter().any(|byte| *byte != 0) || !matches!(word[31], 0 | 1) {
        return Err(NativeRfqError::OnchainVerification);
    }
    Ok(word[31] == 1)
}

fn decode_token_decimals(result: &[u8]) -> Option<u8> {
    let word: &[u8; 32] = result.try_into().ok()?;
    word[..31].iter().all(|byte| *byte == 0).then_some(word[31])
}

async fn bounded_response_body(
    mut response: reqwest::Response,
    max_bytes: usize,
    work: Option<&crate::work_budget::WorkBudget>,
) -> Result<Vec<u8>, NativeRfqError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(NativeRfqError::ResponseTooLarge);
    }
    // Do not rely only on Content-Length: chunked or dishonest upstream
    // responses must be stopped before they can allocate without bound.
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(max_bytes as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| NativeRfqError::Transport)?
    {
        if let Some(work) = work {
            work.record_rpc_response_bytes(chunk.len(), "Native HTTP response bytes")
                .map_err(|_| NativeRfqError::WorkBudget)?;
        }
        if chunk.len() > max_bytes.saturating_sub(body.len()) {
            return Err(NativeRfqError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_orderbook(entries: Vec<OrderbookEntryWire>) -> Result<NativeOrderbook, NativeRfqError> {
    let mut orderbook = NativeOrderbook {
        markets: HashMap::with_capacity(entries.len()),
    };
    for entry in entries {
        let Some(minimum_in_base) = entry.minimum_in_base.parse() else {
            continue;
        };
        let mut levels = Vec::with_capacity(entry.levels.len());
        let mut malformed = false;
        for [quantity, price] in &entry.levels {
            let Some(quantity) = quantity.parse() else {
                malformed = true;
                break;
            };
            let Some(price) = price.parse() else {
                malformed = true;
                break;
            };
            if !quantity.coefficient.is_zero() && !price.coefficient.is_zero() {
                levels.push((quantity, price));
            }
        }
        if malformed || levels.is_empty() {
            continue;
        }
        let base = parse_orderbook_address(&entry.base_address)?;
        let quote = parse_orderbook_address(&entry.quote_address)?;
        if base == Address::ZERO || quote == Address::ZERO || base == quote {
            return Err(NativeRfqError::InvalidResponse(
                "orderbook contains an invalid token pair",
            ));
        }
        let (direction, side) = if entry.side.eq_ignore_ascii_case("bid") {
            // Native bids for base: the taker sells base and receives quote.
            (NativePair::new(base, quote), OrderbookSide::Bid)
        } else if entry.side.eq_ignore_ascii_case("ask") {
            // Native offers base: the taker sells quote and receives base.
            (NativePair::new(quote, base), OrderbookSide::Ask)
        } else {
            return Err(NativeRfqError::InvalidResponse(
                "orderbook contains an unsupported side",
            ));
        };
        if orderbook
            .markets
            .insert(
                direction,
                Some(OrderbookMarket {
                    side,
                    minimum_in_base,
                    levels,
                }),
            )
            .is_some()
        {
            return Err(NativeRfqError::InvalidResponse(
                "orderbook contains a duplicate direction",
            ));
        }
    }
    Ok(orderbook)
}

fn parse_orderbook_address(value: &str) -> Result<Address, NativeRfqError> {
    value
        .parse()
        .map_err(|_| NativeRfqError::InvalidResponse("orderbook contains an invalid token address"))
}

impl NativeRfqSource for NativeRfqClient {
    fn indicative_quotes<'a>(
        &'a self,
        identity: crate::chain::NativeRfqProfile,
        requests: &'a [(NativePair, U256)],
    ) -> BoxFuture<'a, Result<Vec<(NativePair, U256, U256)>, NativeRfqError>> {
        Box::pin(self.observe_indicative_quotes(identity.api_chain, requests))
    }

    fn available_pairs<'a>(
        &'a self,
        identity: crate::chain::NativeRfqProfile,
        pairs: &'a [NativePair],
    ) -> BoxFuture<'a, Result<Vec<NativePair>, NativeRfqError>> {
        Box::pin(self.observe_available_pairs(identity.api_chain, pairs))
    }

    fn direction_available<'a>(
        &'a self,
        identity: crate::chain::NativeRfqProfile,
        token_in: Address,
        token_out: Address,
    ) -> BoxFuture<'a, Result<bool, NativeRfqError>> {
        Box::pin(async move {
            self.observe_orderbook_direction(
                identity.api_chain,
                token_in,
                token_out,
                ORDERBOOK_DISCOVERY_CACHE_TTL,
                Some(ORDERBOOK_DISCOVERY_STALE_IF_BUSY_TTL),
            )
            .await
            .map(|observation| observation.is_some())
        })
    }

    fn firm_quote<'a>(
        &'a self,
        request: FirmQuoteRequest,
    ) -> BoxFuture<'a, Result<Option<super::ValidatedFirmQuote>, NativeRfqError>> {
        Box::pin(self.request_firm_quote(request))
    }
}

fn bps_as_percent(bps: u32) -> String {
    let whole = bps / 100;
    let fraction = bps % 100;
    if fraction == 0 {
        whole.to_string()
    } else if fraction.is_multiple_of(10) {
        format!("{whole}.{}", fraction / 10)
    } else {
        format!("{whole}.{fraction:02}")
    }
}

fn usable_expiry(requested: u64, configured: u64, min_ttl: u64) -> Option<u64> {
    if requested < MIN_EXPIRY_SECONDS {
        return None;
    }
    let expiry = requested.min(configured);
    (expiry > min_ttl).then_some(expiry)
}

/// Business outcomes that mean "Native is not a candidate for this solve".
/// Authentication, rate-limit, malformed-request and unknown codes remain
/// errors so operators can distinguish a broken integration from empty RFQ
/// inventory while the caller still falls back to its independent AMM plan.
fn is_no_quote_code(code: u32) -> bool {
    matches!(
        code,
        101_007 | 101_010 | 171_011 | 171_012 | 171_015 | 171_037 | 301_016 | 405_030
    )
}

fn is_direction_unavailable_code(code: u32) -> bool {
    // 101010 means only that this particular amount exceeds current depth;
    // clearing the global cache for it would let oversized requests bypass
    // the short-cache rate bound while the direction itself still exists.
    matches!(code, 101_007 | 171_011 | 171_015 | 171_037)
}

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::FIXTURE_NATIVE_RFQ;
    use crate::rfq::ValidatedFirmQuote;
    use alloy_primitives::{Bytes, U256};
    use axum::Json;
    use axum::Router;
    use axum::extract::{RawQuery, State};
    use axum::routing::{get, post};
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    const TEST_SIGNING_KEY: &str =
        "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d";

    fn test_authorizer() -> NativeBeneficiaryAuthorizer {
        NativeBeneficiaryAuthorizer::from_secret(TEST_SIGNING_KEY).unwrap()
    }
    #[tokio::test]
    async fn coordinated_real_native_paths_share_global_firm_cap_and_all_outbound_pacing() {
        let entered = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let books = Arc::new(AtomicUsize::new(0));
        let firms = Arc::new(AtomicUsize::new(0));
        let request = firm_request();
        let base = format!("{:#x}", request.token_in);
        let quote = format!("{:#x}", request.token_out);
        let api=axum::Router::new().route("/swap-api-v2/v1/orderbook",get({let books=books.clone();move || {
            let books=books.clone();let base=base.clone();let quote=quote.clone();async move {
                books.fetch_add(1,Ordering::SeqCst);Json(json!([{"base_address":base,"quote_address":quote,"side":"bid","minimum_in_base":0,"levels":[[1,2]]}]))
            }
        }})).route("/swap-api-v2/v1/firm-quote",get({let entered=entered.clone();let finish=finish.clone();let firms=firms.clone();move ||{
            let entered=entered.clone();let finish=finish.clone();let firms=firms.clone();async move {
                firms.fetch_add(1,Ordering::SeqCst);entered.notify_one();finish.notified().await;Json(json!({"code":101010}))
            }
        }}));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_url = format!("http://{}/swap-api-v2/", listener.local_addr().unwrap());
        let api_server = tokio::spawn(async move { axum::serve(listener, api).await.unwrap() });
        let mut config = NativeRfqConfig::new_for_test(
            &api_url,
            "controlled-fixture-api-key",
            Duration::from_millis(1500),
            60,
            10,
            test_authorizer(),
        )
        .unwrap();
        let token = "controlled-fixture-service-token-00000000";
        assert!(
            crate::native_coordinator::NativeQuotaAuthority::from_serving_config(
                &config,
                token,
                Duration::from_secs(2)
            )
            .is_err(),
            "authority host must not independently use process quota"
        );
        let authority = crate::native_coordinator::NativeQuotaAuthority::new(
            config.quota_scope(),
            token,
            10,
            1,
            Duration::from_millis(500),
            Duration::from_secs(2),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let coordinator_url = format!("http://{}", listener.local_addr().unwrap());
        let router = authority.router();
        let coordinator_server =
            tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        config.coordinator = Some(
            crate::native_coordinator::CoordinatorConfig::new(&coordinator_url, token).unwrap(),
        );
        let configured_authority =
            crate::native_coordinator::NativeQuotaAuthority::from_serving_config(
                &config,
                token,
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(configured_authority.metrics().active_leases, 0);
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        let work = crate::work_budget::WorkBudget::bounded(
            crate::budget::SolverBudget::for_duration(Duration::from_secs(3)),
        );
        let first = NativeRfqClient::new(config.clone(), rpc.clone())
            .unwrap()
            .with_work(work.clone());
        let second = NativeRfqClient::new(config, rpc).unwrap();
        let pending = tokio::spawn(async move { first.request_firm_quote(request).await });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        assert_eq!(authority.metrics().active_firm_leases, 1);
        assert_eq!(
            second.request_firm_quote(request).await.unwrap_err(),
            NativeRfqError::Saturated
        );
        let pair = NativePair::new(request.token_in, request.token_out);
        assert_eq!(
            second
                .observe_available_pairs(request.identity.api_chain, &[pair])
                .await
                .unwrap(),
            vec![pair]
        );
        assert_eq!(authority.metrics().active_firm_leases, 1);
        assert_eq!(books.load(Ordering::SeqCst), 2);
        assert_eq!(firms.load(Ordering::SeqCst), 1);
        finish.notify_one();
        assert!(pending.await.unwrap().unwrap().is_none());
        // Provider completion transfers cleanup ownership without waiting for
        // its HTTP response. Drain the actual lease/account effects before
        // checking the unchanged physical-work totals.
        tokio::time::timeout(Duration::from_secs(2), async {
            while authority.metrics().active_leases != 0 || work.used().rpc_calls != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned Native cleanup did not release all leases and finish dispatch accounting");
        assert_eq!(authority.metrics().active_firm_leases, 0);
        assert_eq!(authority.metrics().acquisitions, 4); // one firm lease + three dispatch admissions
        assert_eq!(work.used().rpc_calls, 8);
        assert_eq!(work.used().quote_samples, 1);
        assert!(work.used().rpc_bytes > 0);
        let memory = second.memory_usage();
        assert!(memory.estimated_cached_book_bytes > 0);
        assert!(memory.estimated_live_book_bytes > 0);
        api_server.abort();
        coordinator_server.abort();
    }

    fn firm_request() -> FirmQuoteRequest {
        FirmQuoteRequest {
            identity: FIXTURE_NATIVE_RFQ,
            token_in: Address::repeat_byte(0x11),
            token_out: Address::repeat_byte(0x22),
            amount_in: U256::from(1_000u64),
            settler: Address::repeat_byte(0x33),
            beneficiary: Address::repeat_byte(0x44),
            tx_origin: Some(Address::repeat_byte(0x55)),
            slippage_bps: 50,
            expiry_seconds: 60,
            chain_timestamp: 1_800_000_000,
        }
    }

    fn validated_quote() -> ValidatedFirmQuote {
        ValidatedFirmQuote {
            target: FIXTURE_NATIVE_RFQ.router,
            pool: FIXTURE_NATIVE_RFQ.pool,
            calldata: Bytes::new(),
            token_in: Address::repeat_byte(0x11),
            token_out: Address::repeat_byte(0x22),
            settler: Address::repeat_byte(0x33),
            expected_origin: Address::repeat_byte(0x55),
            amount_in: U256::from(1_000u64),
            amount_out: U256::from(2_000u64),
            signer: Address::repeat_byte(0x66),
            nonce: U256::from(42u64),
            beneficiary: Address::repeat_byte(0x44),
            deadline: 1_800_000_060,
            min_ttl_seconds: 10,
            amount_in_offset: 36,
            amount_out_minimum_offset: 68,
            router_version: 6,
            observation: None,
        }
    }

    fn abi_bool(value: u8) -> Vec<u8> {
        let mut encoded = vec![0u8; 32];
        encoded[31] = value;
        encoded
    }

    fn decimal_wire(value: &str) -> DecimalWire {
        DecimalWire::String(value.to_owned())
    }

    fn decimal(value: &str) -> Decimal {
        parse_decimal(value).expect("valid test decimal")
    }

    fn orderbook_market(
        side: OrderbookSide,
        minimum_in_base: &str,
        levels: &[(&str, &str)],
    ) -> OrderbookMarket {
        OrderbookMarket {
            side,
            minimum_in_base: decimal(minimum_in_base),
            levels: levels
                .iter()
                .map(|(quantity, price)| (decimal(quantity), decimal(price)))
                .collect(),
        }
    }

    #[derive(Clone)]
    struct QuoteStateRpc {
        requests: Arc<Mutex<Vec<Value>>>,
        signer_authorized: u8,
        nonce_consumed: u8,
    }

    async fn quote_state_rpc(
        State(state): State<QuoteStateRpc>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(request["method"], "eth_call");
        let input = request["params"][0]
            .get("input")
            .or_else(|| request["params"][0].get("data"))
            .and_then(Value::as_str)
            .expect("eth_call input");
        let signer_selector = format!(
            "0x{}",
            alloy_primitives::hex::encode(abi::rfqSignersCall::SELECTOR)
        );
        let nonce_selector = format!(
            "0x{}",
            alloy_primitives::hex::encode(abi::noncesCall::SELECTOR)
        );
        let value = if input.starts_with(&signer_selector) {
            state.signer_authorized
        } else if input.starts_with(&nonce_selector) {
            state.nonce_consumed
        } else {
            panic!("unexpected eth_call selector: {input}");
        };
        state.requests.lock().await.push(request.clone());
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": format!("0x{}", alloy_primitives::hex::encode(abi_bool(value))),
        }))
    }

    #[derive(Clone)]
    struct DecimalsRpc {
        calls: Arc<AtomicUsize>,
        values: Arc<HashMap<Address, Vec<u8>>>,
    }

    async fn decimals_rpc(
        State(state): State<DecimalsRpc>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(request["method"], "eth_call");
        state.calls.fetch_add(1, Ordering::SeqCst);
        let input = request["params"][0]
            .get("input")
            .or_else(|| request["params"][0].get("data"))
            .and_then(Value::as_str)
            .expect("eth_call input");
        let encoded = alloy_primitives::hex::decode(input.trim_start_matches("0x")).unwrap();
        let call = abi::IMulticall3::aggregate3Call::abi_decode(&encoded).unwrap();
        let results = call
            .calls
            .into_iter()
            .map(|call| {
                assert_eq!(call.callData.as_ref(), ERC20_DECIMALS_SELECTOR);
                match state.values.get(&call.target) {
                    Some(value) => abi::IMulticall3::Result {
                        success: true,
                        returnData: value.clone().into(),
                    },
                    None => abi::IMulticall3::Result {
                        success: false,
                        returnData: Bytes::new(),
                    },
                }
            })
            .collect::<Vec<_>>();
        let result = abi::IMulticall3::aggregate3Call::abi_encode_returns(&results);
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": format!("0x{}", alloy_primitives::hex::encode(result)),
        }))
    }

    async fn client_with_quote_state_rpc(
        signer_authorized: u8,
        nonce_consumed: u8,
    ) -> (
        NativeRfqClient,
        Arc<Mutex<Vec<Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/", post(quote_state_rpc))
            .with_state(QuoteStateRpc {
                requests: Arc::clone(&requests),
                signer_authorized,
                nonce_consumed,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let rpc = Rpc::connect(&format!("http://{address}")).unwrap();
        let config = NativeRfqConfig::new_for_test(
            "http://127.0.0.1:1/swap-api-v2/",
            "test-api-key",
            Duration::from_millis(500),
            60,
            10,
            test_authorizer(),
        )
        .unwrap();
        (NativeRfqClient::new(config, rpc).unwrap(), requests, server)
    }

    async fn client_for_with_limits(
        app: Router,
        limits: NativeRfqLimits,
    ) -> (NativeRfqClient, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = NativeRfqConfig::new_for_test_with_limits(
            &format!("http://{address}/swap-api-v2/"),
            "test-api-key",
            Duration::from_millis(500),
            60,
            10,
            limits,
            test_authorizer(),
        )
        .unwrap();
        // These HTTP behavior tests never reach a successful firm response,
        // so the deliberately unreachable RPC endpoint must not be contacted.
        let rpc = Rpc::connect("http://127.0.0.1:1").unwrap();
        (NativeRfqClient::new(config, rpc).unwrap(), server)
    }

    async fn client_for_with_max_inflight(
        app: Router,
        max_inflight: usize,
    ) -> (NativeRfqClient, tokio::task::JoinHandle<()>) {
        client_for_with_limits(
            app,
            NativeRfqLimits {
                max_inflight,
                ..NativeRfqLimits::DEFAULT
            },
        )
        .await
    }

    async fn client_for(app: Router) -> (NativeRfqClient, tokio::task::JoinHandle<()>) {
        client_for_with_limits(app, NativeRfqLimits::DEFAULT).await
    }

    #[test]
    fn quote_pool_state_requires_an_authorized_signer_and_unused_nonce() {
        assert_eq!(
            quote_pool_state_is_usable(&abi_bool(1), &abi_bool(0)),
            Ok(true)
        );
        assert_eq!(
            quote_pool_state_is_usable(&abi_bool(1), &abi_bool(1)),
            Ok(false)
        );
        assert_eq!(
            quote_pool_state_is_usable(&abi_bool(0), &abi_bool(0)),
            Err(NativeRfqError::InvalidResponse(
                "quote signer is not authorized by the Native RFQ pool"
            ))
        );
    }

    #[test]
    fn quote_pool_state_rejects_malformed_contract_returns() {
        assert_eq!(
            quote_pool_state_is_usable(&[0u8; 31], &abi_bool(0)),
            Err(NativeRfqError::OnchainVerification)
        );
        assert_eq!(
            quote_pool_state_is_usable(&abi_bool(1), &abi_bool(2)),
            Err(NativeRfqError::OnchainVerification)
        );
    }

    #[tokio::test]
    async fn quote_pool_state_fails_closed_when_rpc_is_unavailable() {
        let (client, server) = client_for(Router::new()).await;

        assert_eq!(
            client
                .quote_is_usable_onchain(&validated_quote())
                .await
                .unwrap_err(),
            NativeRfqError::OnchainVerification
        );
        server.abort();
    }

    #[tokio::test]
    async fn quote_pool_getters_share_one_canonical_block_hash() {
        let (client, requests, server) = client_with_quote_state_rpc(1, 0).await;
        let block_hash = B256::repeat_byte(0xab);

        assert!(
            client
                .quote_is_usable_onchain_at(&validated_quote(), block_hash)
                .await
                .unwrap()
        );

        let requests = requests.lock().await;
        assert_eq!(requests.len(), 2);
        let expected_block = json!({
            "blockHash": format!("{block_hash:#x}"),
            "requireCanonical": true,
        });
        for request in requests.iter() {
            assert_eq!(request["params"][1], expected_block);
            assert_eq!(
                request["params"][0]["to"],
                format!("{:#x}", FIXTURE_NATIVE_RFQ.pool)
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn independent_clients_share_credential_pacing_and_firm_capacity() {
        let (client, server) = client_for(Router::new()).await;
        let second = NativeRfqClient::new(client.config.clone(), client.rpc.clone()).unwrap();
        assert!(Arc::ptr_eq(&client.inflight, &second.inflight));
        assert!(Arc::ptr_eq(
            &client.next_request_at,
            &second.next_request_at
        ));
        let _slots: Vec<_> = (0..client.config.max_inflight)
            .map(|_| client.inflight.clone().try_acquire_owned().unwrap())
            .collect();
        assert!(second.inflight.clone().try_acquire_owned().is_err());
        let mut conflicting = client.config.clone();
        conflicting.qps += 1;
        assert!(NativeRfqClient::new(conflicting, client.rpc.clone()).is_err());
        server.abort();
    }

    #[tokio::test]
    async fn request_budget_rejection_is_not_published_as_a_market_failure() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let app = Router::new().route(
            "/swap-api-v2/v1/orderbook",
            get(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(json!([]))
                }
            }),
        );
        let (client, server) = client_for(app).await;
        let work = crate::work_budget::WorkBudget::new(
            crate::budget::SolverBudget::unlimited(),
            crate::work_budget::WorkCharge {
                rpc_calls: 0,
                ..crate::work_budget::WorkCharge::bounded_default()
            },
        );
        assert_eq!(
            client
                .with_work(work.clone())
                .observe_orderbook("fixture", Duration::ZERO, None)
                .await
                .unwrap_err(),
            NativeRfqError::WorkBudget
        );
        assert!(client.orderbook.published.lock().unwrap().latest.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(work.used().rpc_calls, 0);
        client
            .observe_orderbook("fixture", Duration::ZERO, None)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn received_http_bytes_remain_counted_when_the_budget_is_exceeded() {
        let app = Router::new().route(
            "/swap-api-v2/v1/orderbook",
            get(|| async { Json(json!([])) }),
        );
        let (client, server) = client_for(app).await;
        let work = crate::work_budget::WorkBudget::new(
            crate::budget::SolverBudget::unlimited(),
            crate::work_budget::WorkLimits {
                rpc_bytes: 1,
                ..crate::work_budget::WorkLimits::bounded_default()
            },
        );
        assert_eq!(
            client
                .with_work(work.clone())
                .observe_orderbook("fixture", Duration::ZERO, None)
                .await
                .unwrap_err(),
            NativeRfqError::WorkBudget,
        );
        assert_eq!(work.used().rpc_calls, 1);
        assert_eq!(
            work.used().rpc_bytes,
            2,
            "the received [] body cost is not discarded"
        );
        assert!(client.orderbook.published.lock().unwrap().latest.is_none());
        server.abort();
    }

    async fn client_with_direction_and_firm_error(
        code: u32,
    ) -> (
        NativeRfqClient,
        FirmQuoteRequest,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let firm_calls = Arc::new(AtomicUsize::new(0));
        let orderbook_counter = Arc::clone(&orderbook_calls);
        let firm_counter = Arc::clone(&firm_calls);
        let request = firm_request();
        let base = format!("{:#x}", request.token_in);
        let quote = format!("{:#x}", request.token_out);
        let app = Router::new()
            .route(
                "/swap-api-v2/v1/orderbook",
                get(move || {
                    let counter = Arc::clone(&orderbook_counter);
                    let base = base.clone();
                    let quote = quote.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!([{
                            "base_address": base,
                            "quote_address": quote,
                            "side": "bid",
                            "minimum_in_base": 0,
                            "levels": [[1.0, 2.0]]
                        }]))
                    }
                }),
            )
            .route(
                "/swap-api-v2/v1/firm-quote",
                get(move || {
                    let counter = Arc::clone(&firm_counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({"code": code}))
                    }
                }),
            );
        // Keep both calls inside the cache TTL so these tests distinguish
        // explicit direction invalidation from ordinary time-based expiry.
        let (client, server) = client_for_with_limits(
            app,
            NativeRfqLimits {
                qps: MAX_NATIVE_RFQ_QPS,
                ..NativeRfqLimits::DEFAULT
            },
        )
        .await;
        (client, request, orderbook_calls, firm_calls, server)
    }

    async fn assert_stale_invalidation_preserves_refresh(
        refreshed_response: serde_json::Value,
        expected: Result<bool, NativeRfqError>,
    ) {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let refresh_started = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());
        let counter = Arc::clone(&orderbook_calls);
        let started = Arc::clone(&refresh_started);
        let release = Arc::clone(&release_refresh);
        let request = firm_request();
        let initial_response = serde_json::json!([{
            "base_address": format!("{:#x}", request.token_in),
            "quote_address": format!("{:#x}", request.token_out),
            "side": "bid",
            "minimum_in_base": 0,
            "levels": [[1.0, 2.0]]
        }]);
        let app = Router::new().route(
            "/swap-api-v2/v1/orderbook",
            get(move || {
                let counter = Arc::clone(&counter);
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                let initial_response = initial_response.clone();
                let refreshed_response = refreshed_response.clone();
                async move {
                    match counter.fetch_add(1, Ordering::SeqCst) {
                        0 => Json(initial_response),
                        1 => {
                            started.notify_one();
                            release.notified().await;
                            Json(refreshed_response)
                        }
                        _ => Json(refreshed_response),
                    }
                }
            }),
        );
        let (client, server) = client_for(app).await;
        let observed = client
            .observe_orderbook_direction(
                request.identity.api_chain,
                request.token_in,
                request.token_out,
                ORDERBOOK_LAST_LOOK_TTL,
                None,
            )
            .await
            .unwrap()
            .unwrap();

        tokio::time::sleep(ORDERBOOK_LAST_LOOK_TTL + Duration::from_millis(10)).await;
        let refreshing_client = client.clone();
        let refreshing = tokio::spawn(async move {
            refreshing_client
                .observe_orderbook_direction(
                    request.identity.api_chain,
                    request.token_in,
                    request.token_out,
                    ORDERBOOK_LAST_LOOK_TTL,
                    None,
                )
                .await
                .map(|observation| observation.is_some())
        });
        refresh_started.notified().await;

        // Queue an invalidation from the old observation while the refresh
        // owns the mutex. `Notify` fires before the invalidator tries the lock,
        // so receiving it means that task will enqueue before it yields.
        let invalidation_started = Arc::new(Notify::new());
        let invalidating_client = client.clone();
        let invalidation_signal = Arc::clone(&invalidation_started);
        let invalidating = tokio::spawn(async move {
            invalidation_signal.notify_one();
            invalidating_client.invalidate_orderbook(&observed).await;
        });
        invalidation_started.notified().await;
        tokio::task::yield_now().await;
        release_refresh.notify_one();

        assert_eq!(refreshing.await.unwrap(), expected.clone());
        invalidating.await.unwrap();
        assert_eq!(
            client
                .observe_orderbook_direction(
                    request.identity.api_chain,
                    request.token_in,
                    request.token_out,
                    ORDERBOOK_LAST_LOOK_TTL,
                    None,
                )
                .await
                .map(|observation| observation.is_some()),
            expected
        );
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[test]
    fn formats_basis_points_as_api_percent() {
        assert_eq!(bps_as_percent(0), "0");
        assert_eq!(bps_as_percent(1), "0.01");
        assert_eq!(bps_as_percent(10), "0.1");
        assert_eq!(bps_as_percent(50), "0.5");
        assert_eq!(bps_as_percent(100), "1");
    }

    #[test]
    fn skips_requests_without_a_meaningful_expiry_window() {
        assert_eq!(usable_expiry(14, 60, 10), None);
        assert_eq!(usable_expiry(15, 60, 10), Some(15));
        assert_eq!(usable_expiry(120, 60, 10), Some(60));
        assert_eq!(usable_expiry(15, 120, 15), None);
    }

    #[test]
    fn config_enforces_native_expiry_limit_and_redacts_secrets() {
        let config = NativeRfqConfig::new_for_test(
            "https://native.example/swap-api-v2/",
            "private-api-key-marker",
            Duration::from_millis(1_500),
            120,
            10,
            test_authorizer(),
        )
        .unwrap();
        assert_eq!(config.qps(), DEFAULT_NATIVE_RFQ_QPS);
        assert_eq!(config.queue_wait(), DEFAULT_NATIVE_RFQ_QUEUE_WAIT);
        assert_eq!(config.max_inflight(), DEFAULT_NATIVE_RFQ_MAX_INFLIGHT);
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("private-api-key-marker"));
        assert!(!rendered.contains("native.example"));

        assert!(
            NativeRfqConfig::new_for_test(
                "https://native.example/swap-api-v2/",
                "key",
                Duration::from_millis(1_500),
                121,
                10,
                test_authorizer(),
            )
            .is_err()
        );

        assert!(
            NativeRfqConfig::new(
                "https://attacker.example/swap-api-v2/",
                "key",
                Duration::from_millis(1_500),
                60,
                10,
                test_authorizer(),
            )
            .is_err()
        );
        assert!(
            NativeRfqConfig::new(
                "https://v2.api.native.org/swap-api-v2",
                "key",
                Duration::from_millis(1_500),
                60,
                10,
                test_authorizer(),
            )
            .is_ok()
        );
    }

    #[test]
    fn config_enforces_native_runtime_limits() {
        let config = NativeRfqConfig::new_for_test_with_limits(
            "https://native.example/swap-api-v2/",
            "key",
            Duration::from_millis(1_500),
            60,
            10,
            NativeRfqLimits {
                qps: MAX_NATIVE_RFQ_QPS,
                queue_wait: MAX_NATIVE_RFQ_QUEUE_WAIT,
                max_inflight: MAX_NATIVE_RFQ_MAX_INFLIGHT,
            },
            test_authorizer(),
        )
        .unwrap();
        assert_eq!(config.qps(), MAX_NATIVE_RFQ_QPS);
        assert_eq!(config.queue_wait(), MAX_NATIVE_RFQ_QUEUE_WAIT);
        assert_eq!(config.max_inflight(), MAX_NATIVE_RFQ_MAX_INFLIGHT);

        for limits in [
            NativeRfqLimits {
                qps: 0,
                ..NativeRfqLimits::DEFAULT
            },
            NativeRfqLimits {
                qps: MAX_NATIVE_RFQ_QPS + 1,
                ..NativeRfqLimits::DEFAULT
            },
            NativeRfqLimits {
                queue_wait: Duration::ZERO,
                ..NativeRfqLimits::DEFAULT
            },
            NativeRfqLimits {
                queue_wait: MAX_NATIVE_RFQ_QUEUE_WAIT + Duration::from_millis(1),
                ..NativeRfqLimits::DEFAULT
            },
            NativeRfqLimits {
                max_inflight: 0,
                ..NativeRfqLimits::DEFAULT
            },
            NativeRfqLimits {
                max_inflight: MAX_NATIVE_RFQ_MAX_INFLIGHT + 1,
                ..NativeRfqLimits::DEFAULT
            },
        ] {
            assert!(
                NativeRfqConfig::new_for_test_with_limits(
                    "https://native.example/swap-api-v2/",
                    "key",
                    Duration::from_millis(1_500),
                    60,
                    10,
                    limits,
                    test_authorizer(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn native_qps_interval_rounds_up_without_exceeding_the_limit() {
        assert_eq!(
            native_request_interval(DEFAULT_NATIVE_RFQ_QPS),
            Duration::from_millis(250)
        );
        assert_eq!(
            native_request_interval(3),
            Duration::from_nanos(333_333_334)
        );
        assert_eq!(native_request_interval(1), Duration::from_secs(1));
    }

    #[test]
    fn decimal_parser_preserves_high_precision_json_numbers() {
        let wire: DecimalWire =
            serde_json::from_str("12345678901234567890.123456789012345678901234567891").unwrap();

        assert_eq!(
            wire.parse(),
            Some(Decimal {
                coefficient: U256::from_str_radix(
                    "12345678901234567890123456789012345678901234567891",
                    10,
                )
                .unwrap(),
                scale: 30,
            })
        );
    }

    #[test]
    fn decimal_parser_supports_scientific_notation_without_floats() {
        assert_eq!(
            parse_decimal("1.2300e3"),
            Some(Decimal {
                coefficient: U256::from(1_230u64),
                scale: 0,
            })
        );
        assert_eq!(
            parse_decimal("4.2E-3"),
            Some(Decimal {
                coefficient: U256::from(42u64),
                scale: 4,
            })
        );
    }

    #[test]
    fn decimal_parser_rejects_negative_and_out_of_range_values() {
        for invalid in ["-1", "1e78", "1e-78", "NaN", "1.2.3", "1e2e3"] {
            assert_eq!(parse_decimal(invalid), None, "accepted {invalid}");
        }
        assert_eq!(narrow_u1024(U1024::from(U256::MAX)), Some(U256::MAX));
        assert_eq!(
            narrow_u1024(U1024::ONE << 256usize),
            None,
            "wide integers must never be truncated to their low limbs"
        );
    }

    #[test]
    fn bid_integrates_non_cumulative_levels_across_token_decimals() {
        let market = orderbook_market(OrderbookSide::Bid, "1.1", &[("1.5", "2"), ("2", "3")]);
        let one_base = U256::from(10u64).pow(U256::from(18u64));

        // 1.5 base at 2 quote/base plus 0.5 base at 3 quote/base.
        assert_eq!(
            market.indicative_amount_out(one_base * U256::from(2u64), 18, 6),
            Some(U256::from(4_500_000u64))
        );
        assert_eq!(
            market.indicative_amount_out(one_base, 18, 6),
            None,
            "minimum_in_base must be enforced in base-token units"
        );
        assert_eq!(
            market.indicative_amount_out(one_base * U256::from(4u64), 18, 6),
            None,
            "a request beyond the sum of non-cumulative levels has no quote"
        );

        let rounding = orderbook_market(OrderbookSide::Bid, "0", &[("2", "1.2345678")]);
        assert_eq!(
            rounding.indicative_amount_out(one_base, 18, 6),
            Some(U256::from(1_234_567u64)),
            "indicative output must round down"
        );
    }

    #[test]
    fn ask_converts_quote_input_to_base_output_and_enforces_base_minimum() {
        let market = orderbook_market(OrderbookSide::Ask, "2", &[("1.5", "2"), ("2", "3")]);
        let one_base = U256::from(10u64).pow(U256::from(18u64));

        // 4.5 quote buys all 1.5 base at 2 and another 0.5 base at 3.
        assert_eq!(
            market.indicative_amount_out(U256::from(4_500_000u64), 6, 18),
            Some(one_base * U256::from(2u64))
        );
        assert_eq!(
            orderbook_market(OrderbookSide::Ask, "2.1", &[("1.5", "2"), ("2", "3")],)
                .indicative_amount_out(U256::from(4_500_000u64), 6, 18),
            None,
            "minimum_in_base is measured in the base token received"
        );
        assert_eq!(
            market.indicative_amount_out(U256::from(10_000_000u64), 6, 18),
            None,
            "quote input beyond total ask depth must not receive a partial quote"
        );
        assert_eq!(
            orderbook_market(OrderbookSide::Ask, "0", &[("1", "3")]).indicative_amount_out(
                U256::ONE,
                6,
                18
            ),
            Some(U256::from(333_333_333_333u64)),
            "partial ask output must round down"
        );
    }

    #[test]
    fn token_decimals_decoder_is_strict_and_bounded() {
        assert_eq!(decode_token_decimals(&abi_bool(18)), Some(18));
        assert_eq!(decode_token_decimals(&[0u8; 31]), None);
        let mut non_canonical = abi_bool(18);
        non_canonical[0] = 1;
        assert_eq!(decode_token_decimals(&non_canonical), None);
        assert_eq!(
            decode_token_decimals(&abi_bool(MAX_ERC20_DECIMALS + 1))
                .filter(|value| *value <= MAX_ERC20_DECIMALS),
            None
        );
    }

    #[tokio::test]
    async fn all_native_endpoints_share_the_configured_qps_pacer() {
        let request = firm_request();
        let base = format!("{:#x}", request.token_in);
        let quote = format!("{:#x}", request.token_out);
        let observed = Arc::new(Mutex::new(Vec::<Instant>::new()));
        let orderbook_observed = Arc::clone(&observed);
        let firm_observed = Arc::clone(&observed);
        let app = Router::new()
            .route(
                "/swap-api-v2/v1/orderbook",
                get(move || {
                    let observed = Arc::clone(&orderbook_observed);
                    let base = base.clone();
                    let quote = quote.clone();
                    async move {
                        observed.lock().await.push(Instant::now());
                        Json(serde_json::json!([{
                            "base_address": base,
                            "quote_address": quote,
                            "side": "bid",
                            "minimum_in_base": 0,
                            "levels": [[1.0, 2.0]]
                        }]))
                    }
                }),
            )
            .route(
                "/swap-api-v2/v1/firm-quote",
                get(move || {
                    let observed = Arc::clone(&firm_observed);
                    async move {
                        observed.lock().await.push(Instant::now());
                        Json(serde_json::json!({"code": 101010}))
                    }
                }),
            );
        let (client, server) = client_for_with_limits(
            app,
            NativeRfqLimits {
                queue_wait: Duration::from_secs(2),
                ..NativeRfqLimits::DEFAULT
            },
        )
        .await;
        let request_interval = native_request_interval(DEFAULT_NATIVE_RFQ_QPS);

        let mut attempts = Vec::new();
        for _ in 0..5 {
            let client = client.clone();
            attempts.push(tokio::spawn(async move {
                client.request_firm_quote(request).await
            }));
        }
        for attempt in attempts {
            assert!(attempt.await.unwrap().unwrap().is_none());
        }

        let observed = observed.lock().await;
        assert_eq!(
            observed.len(),
            6,
            "one shared orderbook plus five firm calls"
        );
        // Server arrival times also include HTTP and executor scheduling jitter;
        // they cannot prove a minimum client admission interval. Inspect the
        // shared gate's clock and retain the endpoint dispatch count above.
        let admissions = client._quota.admissions.lock().unwrap();
        assert_eq!(admissions.len(), observed.len());
        for pair in admissions.windows(2) {
            assert!(
                pair[1].duration_since(pair[0]) >= request_interval,
                "Native pacing admissions were closer than the configured interval"
            );
        }
        assert!(
            admissions[5].duration_since(admissions[0]) >= Duration::from_secs(1),
            "six Native admissions fit inside one second"
        );
        server.abort();
    }

    #[tokio::test]
    async fn pacer_queue_timeout_is_retryable_without_sending_the_next_request() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let firm_calls = Arc::new(AtomicUsize::new(0));
        let orderbook_counter = Arc::clone(&orderbook_calls);
        let firm_counter = Arc::clone(&firm_calls);
        let request = firm_request();
        let base = format!("{:#x}", request.token_in);
        let quote = format!("{:#x}", request.token_out);
        let app = Router::new()
            .route(
                "/swap-api-v2/v1/orderbook",
                get(move || {
                    let counter = Arc::clone(&orderbook_counter);
                    let base = base.clone();
                    let quote = quote.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!([{
                            "base_address": base,
                            "quote_address": quote,
                            "side": "bid",
                            "minimum_in_base": 0,
                            "levels": [[1.0, 2.0]]
                        }]))
                    }
                }),
            )
            .route(
                "/swap-api-v2/v1/firm-quote",
                get(move || {
                    let counter = Arc::clone(&firm_counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({"code": 101010}))
                    }
                }),
            );
        let (client, server) = client_for_with_limits(
            app,
            NativeRfqLimits {
                qps: 1,
                queue_wait: Duration::from_millis(20),
                ..NativeRfqLimits::DEFAULT
            },
        )
        .await;

        let started = Instant::now();
        let error = client.request_firm_quote(request).await.unwrap_err();

        assert_eq!(error, NativeRfqError::QueueTimeout);
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "Native queue timeout did not return promptly"
        );
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(firm_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            client.inflight.available_permits(),
            DEFAULT_NATIVE_RFQ_MAX_INFLIGHT
        );
        server.abort();
    }

    #[tokio::test]
    async fn orderbook_pacer_timeout_is_short_cached() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&orderbook_calls);
        let app = Router::new().route(
            "/swap-api-v2/v1/orderbook",
            get(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!([]))
                }
            }),
        );
        let (client, server) = client_for_with_limits(
            app,
            NativeRfqLimits {
                qps: 1,
                queue_wait: Duration::from_millis(20),
                ..NativeRfqLimits::DEFAULT
            },
        )
        .await;
        *client.next_request_at.lock().await = Instant::now() + Duration::from_secs(1);
        let request = firm_request();

        let error = client
            .observe_orderbook_direction(
                request.identity.api_chain,
                request.token_in,
                request.token_out,
                ORDERBOOK_LAST_LOOK_TTL,
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(error, NativeRfqError::QueueTimeout);
        assert!(
            client
                .orderbook
                .published
                .lock()
                .unwrap()
                .latest
                .as_ref()
                .is_some_and(|entry| matches!(entry.result, Err(NativeRfqError::QueueTimeout)))
        );
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[test]
    fn only_liquidity_and_risk_codes_are_normal_no_quote_outcomes() {
        for code in [
            101_007, 101_010, 171_011, 171_012, 171_015, 171_037, 301_016, 405_030,
        ] {
            assert!(is_no_quote_code(code), "{code}");
        }
        for code in [
            131_003, 131_004, 131_011, 171_018, 201_001, 201_005, 999_999,
        ] {
            assert!(!is_no_quote_code(code), "{code}");
        }
    }

    #[tokio::test]
    async fn firm_quote_only_sends_an_explicit_transaction_origin() {
        let request = firm_request();
        let base = format!("{:#x}", request.token_in);
        let quote = format!("{:#x}", request.token_out);
        let observed_queries = Arc::new(Mutex::new(Vec::<String>::new()));
        let queries = Arc::clone(&observed_queries);
        let app = Router::new()
            .route(
                "/swap-api-v2/v1/orderbook",
                get(move || {
                    let base = base.clone();
                    let quote = quote.clone();
                    async move {
                        Json(serde_json::json!([{
                            "base_address": base,
                            "quote_address": quote,
                            "side": "bid",
                            "minimum_in_base": 0,
                            "levels": [[1.0, 2.0]]
                        }]))
                    }
                }),
            )
            .route(
                "/swap-api-v2/v1/firm-quote",
                get(move |RawQuery(query): RawQuery| {
                    let queries = Arc::clone(&queries);
                    async move {
                        queries.lock().await.push(query.unwrap_or_default());
                        Json(serde_json::json!({"code": 101010}))
                    }
                }),
            );
        let (client, server) = client_for(app).await;

        assert!(client.request_firm_quote(request).await.unwrap().is_none());
        let mut request_without_origin = request;
        request_without_origin.tx_origin = None;
        assert!(
            client
                .request_firm_quote(request_without_origin)
                .await
                .unwrap()
                .is_none()
        );

        let queries = observed_queries.lock().await;
        assert_eq!(queries.len(), 2);
        assert!(
            queries[0]
                .split('&')
                .any(|pair| { pair == format!("tx_origin={:#x}", request.tx_origin.unwrap()) })
        );
        assert!(
            !queries[1]
                .split('&')
                .any(|pair| pair.starts_with("tx_origin="))
        );
        server.abort();
    }

    #[test]
    fn orderbook_maps_bid_to_base_sell_direction() {
        let base = Address::repeat_byte(0x11);
        let quote = Address::repeat_byte(0x22);
        let entry = OrderbookEntryWire {
            base_address: format!("{base:#x}"),
            quote_address: format!("{quote:#x}"),
            side: "bid".to_string(),
            minimum_in_base: decimal_wire("0"),
            levels: vec![[decimal_wire("1"), decimal_wire("2")]],
        };

        let directions = parse_orderbook(vec![entry]).unwrap();

        assert_eq!(directions.len(), 1);
        assert!(directions.contains(&NativePair::new(base, quote)));
        assert!(!directions.contains(&NativePair::new(quote, base)));
    }

    #[test]
    fn orderbook_maps_ask_to_quote_sell_direction() {
        let base = Address::repeat_byte(0x11);
        let quote = Address::repeat_byte(0x22);
        let entry = OrderbookEntryWire {
            base_address: format!("{base:#x}"),
            quote_address: format!("{quote:#x}"),
            side: "ask".to_string(),
            minimum_in_base: decimal_wire("0"),
            levels: vec![[decimal_wire("2"), decimal_wire("1")]],
        };

        let directions = parse_orderbook(vec![entry]).unwrap();

        assert_eq!(directions.len(), 1);
        assert!(directions.contains(&NativePair::new(quote, base)));
        assert!(!directions.contains(&NativePair::new(base, quote)));
    }

    #[test]
    fn orderbook_ignores_empty_levels_and_rejects_unknown_sides() {
        let base = Address::repeat_byte(0x11);
        let quote = Address::repeat_byte(0x22);
        let empty = OrderbookEntryWire {
            base_address: "not-an-address".to_string(),
            quote_address: "also-not-an-address".to_string(),
            side: "unknown".to_string(),
            minimum_in_base: decimal_wire("0"),
            levels: Vec::new(),
        };
        assert!(parse_orderbook(vec![empty]).unwrap().markets.is_empty());

        let unknown = OrderbookEntryWire {
            base_address: format!("{base:#x}"),
            quote_address: format!("{quote:#x}"),
            side: "unknown".to_string(),
            minimum_in_base: decimal_wire("0"),
            levels: vec![[decimal_wire("1"), decimal_wire("2")]],
        };
        assert_eq!(
            parse_orderbook(vec![unknown]).unwrap_err(),
            NativeRfqError::InvalidResponse("orderbook contains an unsupported side")
        );
    }

    #[tokio::test]
    async fn batch_availability_uses_one_cached_orderbook_and_preserves_request_order() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&orderbook_calls);
        let token_a = Address::repeat_byte(0x11);
        let token_b = Address::repeat_byte(0x22);
        let token_c = Address::repeat_byte(0x33);
        let app = Router::new().route(
            "/swap-api-v2/v1/orderbook",
            get(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!([
                        {
                            "base_address": format!("{token_a:#x}"),
                            "quote_address": format!("{token_b:#x}"),
                            "side": "bid",
                            "minimum_in_base": 0,
                            "levels": [[1000000000000000000u64, 125u64]]
                        },
                        {
                            "base_address": format!("{token_c:#x}"),
                            "quote_address": format!("{token_b:#x}"),
                            "side": "ask",
                            "minimum_in_base": 0,
                            "levels": [[2000000u64, 75u64]]
                        }
                    ]))
                }
            }),
        );
        let (client, server) = client_for(app).await;
        let requested = [
            NativePair::new(token_c, token_a),
            NativePair::new(token_b, token_c),
            NativePair::new(token_a, token_b),
            NativePair::new(token_b, token_c),
        ];
        let expected = vec![requested[1], requested[2], requested[3]];
        let source: &dyn NativeRfqSource = &client;

        assert_eq!(
            source
                .available_pairs(FIXTURE_NATIVE_RFQ, &requested)
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            source
                .available_pairs(FIXTURE_NATIVE_RFQ, &requested)
                .await
                .unwrap(),
            expected
        );
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_indicatives_singleflight_decimals_and_skip_only_invalid_tokens() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let decimals_calls = Arc::new(AtomicUsize::new(0));
        let orderbook_counter = Arc::clone(&orderbook_calls);
        let good_base = Address::repeat_byte(0x11);
        let good_quote = Address::repeat_byte(0x22);
        let invalid_base = Address::repeat_byte(0x33);
        let values = Arc::new(HashMap::from([
            (good_base, abi_bool(18)),
            (good_quote, abi_bool(6)),
            (invalid_base, abi_bool(MAX_ERC20_DECIMALS.saturating_add(1))),
        ]));
        let rpc_state = DecimalsRpc {
            calls: Arc::clone(&decimals_calls),
            values,
        };
        let app = Router::new()
            .route(
                "/swap-api-v2/v1/orderbook",
                get(move || {
                    let counter = Arc::clone(&orderbook_counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(json!([
                            {
                                "base_address": format!("{good_base:#x}"),
                                "quote_address": format!("{good_quote:#x}"),
                                "side": "bid",
                                "minimum_in_base": 0,
                                "levels": [["10", "2"]]
                            },
                            {
                                "base_address": format!("{invalid_base:#x}"),
                                "quote_address": format!("{good_quote:#x}"),
                                "side": "bid",
                                "minimum_in_base": 0,
                                "levels": [["10", "2"]]
                            }
                        ]))
                    }
                }),
            )
            .route("/", post(decimals_rpc))
            .with_state(rpc_state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = NativeRfqConfig::new_for_test_with_limits(
            &format!("http://{address}/swap-api-v2/"),
            "test-api-key",
            Duration::from_millis(500),
            60,
            10,
            NativeRfqLimits {
                qps: MAX_NATIVE_RFQ_QPS,
                ..NativeRfqLimits::DEFAULT
            },
            test_authorizer(),
        )
        .unwrap();
        let rpc = Rpc::connect(&format!("http://{address}")).unwrap();
        let client = NativeRfqClient::new(config, rpc).unwrap();
        let amount_in = U256::from(10u64).pow(U256::from(18u64));
        let requests = [
            (NativePair::new(good_base, good_quote), amount_in),
            (NativePair::new(invalid_base, good_quote), amount_in),
        ];

        let attempts = (0..32)
            .map(|_| {
                let client = client.clone();
                tokio::spawn(async move {
                    client
                        .indicative_quotes(FIXTURE_NATIVE_RFQ, &requests)
                        .await
                })
            })
            .collect::<Vec<_>>();
        for attempt in attempts {
            assert_eq!(
                attempt.await.unwrap().unwrap(),
                vec![(
                    NativePair::new(good_base, good_quote),
                    amount_in,
                    U256::from(2_000_000u64),
                )]
            );
        }
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(decimals_calls.load(Ordering::SeqCst), 1);

        // Invalid results are negative-cached too; they do not cause another
        // Multicall3 request on the next solver request.
        assert_eq!(
            client
                .indicative_quotes(FIXTURE_NATIVE_RFQ, &requests)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(decimals_calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn cached_decimals_and_negative_entries_bypass_unrelated_missing_batch() {
        let (client, server) = client_for(Router::new()).await;
        let known = Address::repeat_byte(1);
        let negative = Address::repeat_byte(2);
        client
            .token_decimals
            .published
            .lock()
            .unwrap()
            .extend([(known, Some(6)), (negative, None)]);
        let _pending_batch = client.token_decimals.missing_batch.lock().await;
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            client.token_decimals([known, negative]),
        )
        .await
        .expect("cached-only decimals waited for the missing batch")
        .unwrap();
        assert_eq!(result, HashMap::from([(known, 6)]));
        assert!(
            client
                .token_decimals
                .published
                .lock()
                .unwrap()
                .contains_key(&negative)
        );
        server.abort();
    }

    #[tokio::test]
    async fn queued_decimals_waiter_retries_after_owner_transport_failure() {
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let counter = calls.clone();
        let signal = started.clone();
        let unblock = release.clone();
        let app = Router::new().route("/", post(move |Json(request): Json<Value>| {
            let counter = counter.clone();
            let signal = signal.clone();
            let unblock = unblock.clone();
            async move {
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    signal.notify_one();
                    unblock.notified().await;
                    return Json(json!({"jsonrpc":"2.0", "id":request["id"], "error":{"code":-32000,"message":"fixture unavailable"}}));
                }
                let encoded = request["params"][0].get("input").or_else(|| request["params"][0].get("data")).unwrap().as_str().unwrap();
                let input = alloy_primitives::hex::decode(encoded.trim_start_matches("0x")).unwrap();
                let call = abi::IMulticall3::aggregate3Call::abi_decode(&input).unwrap();
                let results: Vec<_> = call.calls.into_iter().map(|_| abi::IMulticall3::Result { success:true, returnData:abi_bool(6).into() }).collect();
                Json(json!({"jsonrpc":"2.0", "id":request["id"], "result":format!("0x{}", alloy_primitives::hex::encode(abi::IMulticall3::aggregate3Call::abi_encode_returns(&results)))}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = NativeRfqConfig::new_for_test(
            "http://127.0.0.1:1/swap-api-v2/",
            "test",
            Duration::from_secs(1),
            60,
            10,
            test_authorizer(),
        )
        .unwrap();
        let client =
            NativeRfqClient::new(config, Rpc::connect(&format!("http://{address}")).unwrap())
                .unwrap();
        let token = Address::repeat_byte(3);
        let first_client = client.clone();
        let first = tokio::spawn(async move { first_client.token_decimals([token]).await });
        started.notified().await;
        let second_client = client.clone();
        let mut second = tokio::spawn(async move { second_client.token_decimals([token]).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second)
                .await
                .is_err()
        );
        release.notify_one();
        assert_eq!(first.await.unwrap().unwrap_err(), NativeRfqError::Transport);
        assert_eq!(second.await.unwrap().unwrap(), HashMap::from([(token, 6)]));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn ttl_valid_book_waits_for_inflight_refresh_while_published_state_is_readable() {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let signal = started.clone();
        let unblock = release.clone();
        let app = Router::new().route(
            "/swap-api-v2/v1/orderbook",
            get(move || {
                let signal = signal.clone();
                let unblock = unblock.clone();
                async move {
                    signal.notify_one();
                    unblock.notified().await;
                    Json(json!([]))
                }
            }),
        );
        let (client, server) = client_for(app).await;
        let old = Arc::new(CachedOrderbook {
            chain: "fixture".into(),
            fetched_at: Instant::now(),
            result: Ok(NativeOrderbook::default()),
        });
        {
            let mut cache = client.orderbook.published.lock().unwrap();
            cache.latest = Some(old.clone());
            cache.last_success = Some(old.clone());
        }
        let refreshing_client = client.clone();
        let refreshing = tokio::spawn(async move {
            refreshing_client
                .observe_orderbook("fixture", Duration::ZERO, None)
                .await
        });
        started.notified().await;
        // HTTP owns only the refresh gate, not the published-state mutex.
        assert!(Arc::ptr_eq(
            client
                .orderbook
                .published
                .try_lock()
                .unwrap()
                .latest
                .as_ref()
                .unwrap(),
            &old
        ));
        let waiting_client = client.clone();
        let mut waiting = tokio::spawn(async move {
            waiting_client
                .observe_orderbook("fixture", Duration::from_secs(60), None)
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        release.notify_one();
        let new = refreshing.await.unwrap().unwrap().unwrap();
        assert!(!Arc::ptr_eq(&old, &new));
        assert!(Arc::ptr_eq(&new, &waiting.await.unwrap().unwrap().unwrap()));
        server.abort();
    }

    #[tokio::test]
    async fn discovery_refresh_is_singleflight_and_does_not_use_firm_capacity() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let refresh_started = Arc::new(Notify::new());
        let release_refresh = Arc::new(Notify::new());
        let counter = Arc::clone(&orderbook_calls);
        let started = Arc::clone(&refresh_started);
        let release = Arc::clone(&release_refresh);
        let pair = NativePair::new(Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        let app = Router::new().route(
            "/swap-api-v2/v1/orderbook",
            get(move || {
                let counter = Arc::clone(&counter);
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    started.notify_one();
                    release.notified().await;
                    Json(serde_json::json!([{
                        "base_address": format!("{:#x}", pair.token_in),
                        "quote_address": format!("{:#x}", pair.token_out),
                        "side": "bid",
                        "minimum_in_base": 0,
                        "levels": [[1.0, 2.0]]
                    }]))
                }
            }),
        );
        let (client, server) = client_for_with_max_inflight(app, 1).await;
        let firm_capacity = Arc::clone(&client.inflight).acquire_owned().await.unwrap();

        let attempts = (0..32)
            .map(|_| {
                let client = client.clone();
                tokio::spawn(
                    async move { client.available_pairs(FIXTURE_NATIVE_RFQ, &[pair]).await },
                )
            })
            .collect::<Vec<_>>();
        tokio::time::timeout(Duration::from_secs(1), refresh_started.notified())
            .await
            .expect("discovery refresh incorrectly waited for firm capacity");
        tokio::task::yield_now().await;
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(client.inflight.available_permits(), 0);

        release_refresh.notify_one();
        for attempt in attempts {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), attempt)
                    .await
                    .expect("discovery waiter did not share the refresh")
                    .unwrap()
                    .unwrap(),
                vec![pair]
            );
        }
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        drop(firm_capacity);
        server.abort();
    }

    #[tokio::test]
    async fn discovery_uses_bounded_stale_membership_when_the_shared_pacer_is_busy() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&orderbook_calls);
        let app = Router::new().route(
            "/swap-api-v2/v1/orderbook",
            get(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!([]))
                }
            }),
        );
        let (client, server) = client_for_with_limits(
            app,
            NativeRfqLimits {
                qps: 1,
                queue_wait: Duration::from_millis(20),
                ..NativeRfqLimits::DEFAULT
            },
        )
        .await;
        let native_pair = NativePair::new(firm_request().token_in, firm_request().token_out);
        let amm_only_pair = NativePair::new(Address::repeat_byte(0x77), Address::repeat_byte(0x88));
        let stale = Arc::new(CachedOrderbook {
            chain: FIXTURE_NATIVE_RFQ.api_chain.to_owned(),
            fetched_at: Instant::now() - Duration::from_secs(2),
            result: Ok(NativeOrderbook::from_pairs([native_pair])),
        });
        {
            let mut cache = client.orderbook.published.lock().unwrap();
            cache.latest = Some(Arc::clone(&stale));
            cache.last_success = Some(stale);
        }
        *client.next_request_at.lock().await = Instant::now() + Duration::from_secs(1);

        assert_eq!(
            client
                .available_pairs(FIXTURE_NATIVE_RFQ, &[amm_only_pair, native_pair])
                .await
                .unwrap(),
            vec![native_pair]
        );
        let failed_generation = Arc::clone(
            client
                .orderbook
                .published
                .lock()
                .unwrap()
                .latest
                .as_ref()
                .expect("capacity failure is cached"),
        );
        assert!(matches!(
            &failed_generation.result,
            Err(NativeRfqError::QueueTimeout)
        ));

        // The cached capacity failure prevents every request in the burst from
        // retrying the pacer. A pair absent from the stale membership remains
        // a normal AMM-only result rather than becoming native_busy.
        for _ in 0..32 {
            assert!(
                client
                    .available_pairs(FIXTURE_NATIVE_RFQ, &[amm_only_pair])
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(Arc::ptr_eq(
            &failed_generation,
            client
                .orderbook
                .published
                .lock()
                .unwrap()
                .latest
                .as_ref()
                .unwrap()
        ));
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 0);

        // Execution never consumes stale membership: its strict 250 ms last
        // look surfaces the shared-pacer timeout as retryable capacity.
        assert_eq!(
            client.request_firm_quote(firm_request()).await.unwrap_err(),
            NativeRfqError::QueueTimeout
        );
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn discovery_cache_does_not_weaken_the_firm_last_look() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let firm_calls = Arc::new(AtomicUsize::new(0));
        let orderbook_counter = Arc::clone(&orderbook_calls);
        let firm_counter = Arc::clone(&firm_calls);
        let request = firm_request();
        let pair = NativePair::new(request.token_in, request.token_out);
        let app = Router::new()
            .route(
                "/swap-api-v2/v1/orderbook",
                get(move || {
                    let counter = Arc::clone(&orderbook_counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!([{
                            "base_address": format!("{:#x}", pair.token_in),
                            "quote_address": format!("{:#x}", pair.token_out),
                            "side": "bid",
                            "minimum_in_base": 0,
                            "levels": [[1.0, 2.0]]
                        }]))
                    }
                }),
            )
            .route(
                "/swap-api-v2/v1/firm-quote",
                get(move || {
                    let counter = Arc::clone(&firm_counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({"code": 101010}))
                    }
                }),
            );
        let (client, server) = client_for_with_limits(
            app,
            NativeRfqLimits {
                qps: MAX_NATIVE_RFQ_QPS,
                ..NativeRfqLimits::DEFAULT
            },
        )
        .await;
        let cached = Arc::new(CachedOrderbook {
            chain: FIXTURE_NATIVE_RFQ.api_chain.to_owned(),
            fetched_at: Instant::now() - (ORDERBOOK_LAST_LOOK_TTL + Duration::from_millis(10)),
            result: Ok(NativeOrderbook::from_pairs([pair])),
        });
        {
            let mut cache = client.orderbook.published.lock().unwrap();
            cache.latest = Some(Arc::clone(&cached));
            cache.last_success = Some(cached);
        }

        assert_eq!(
            client
                .available_pairs(FIXTURE_NATIVE_RFQ, &[pair])
                .await
                .unwrap(),
            vec![pair]
        );
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 0);

        assert!(client.request_firm_quote(request).await.unwrap().is_none());
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(firm_calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[test]
    fn discovery_stale_if_busy_window_is_bounded() {
        let pair = NativePair::new(Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        let stale = Arc::new(CachedOrderbook {
            chain: FIXTURE_NATIVE_RFQ.api_chain.to_owned(),
            fetched_at: Instant::now() - ORDERBOOK_DISCOVERY_STALE_IF_BUSY_TTL,
            result: Ok(NativeOrderbook::from_pairs([pair])),
        });
        let failure = Arc::new(CachedOrderbook {
            chain: FIXTURE_NATIVE_RFQ.api_chain.to_owned(),
            fetched_at: Instant::now(),
            result: Err(NativeRfqError::QueueTimeout),
        });
        let cache = OrderbookCache {
            latest: Some(Arc::clone(&failure)),
            last_success: Some(stale),
        };

        assert!(matches!(
            NativeRfqClient::resolve_orderbook_entry(
                &cache,
                &failure,
                FIXTURE_NATIVE_RFQ.api_chain,
                Some(ORDERBOOK_DISCOVERY_STALE_IF_BUSY_TTL),
            ),
            Err(NativeRfqError::QueueTimeout)
        ));
    }

    #[tokio::test]
    async fn empty_orderbook_is_short_cached_and_skips_firm_quote() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let firm_calls = Arc::new(AtomicUsize::new(0));
        let orderbook_counter = Arc::clone(&orderbook_calls);
        let firm_counter = Arc::clone(&firm_calls);
        let app = Router::new()
            .route(
                "/swap-api-v2/v1/orderbook",
                get(move || {
                    let counter = Arc::clone(&orderbook_counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!([]))
                    }
                }),
            )
            .route(
                "/swap-api-v2/v1/firm-quote",
                get(move || {
                    let counter = Arc::clone(&firm_counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({"code": 171037}))
                    }
                }),
            );
        let (client, server) = client_for(app).await;

        assert!(
            client
                .request_firm_quote(firm_request())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            client
                .request_firm_quote(firm_request())
                .await
                .unwrap()
                .is_none()
        );

        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(firm_calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn saturated_bulkhead_rejects_without_starting_http_work() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let firm_calls = Arc::new(AtomicUsize::new(0));
        let orderbook_started = Arc::new(Notify::new());
        let release_orderbook = Arc::new(Notify::new());
        let orderbook_counter = Arc::clone(&orderbook_calls);
        let firm_counter = Arc::clone(&firm_calls);
        let started = Arc::clone(&orderbook_started);
        let release = Arc::clone(&release_orderbook);
        let request = firm_request();
        let base = format!("{:#x}", request.token_in);
        let quote = format!("{:#x}", request.token_out);
        let app = Router::new()
            .route(
                "/swap-api-v2/v1/orderbook",
                get(move || {
                    let counter = Arc::clone(&orderbook_counter);
                    let started = Arc::clone(&started);
                    let release = Arc::clone(&release);
                    let base = base.clone();
                    let quote = quote.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        started.notify_one();
                        release.notified().await;
                        Json(serde_json::json!([{
                            "base_address": base,
                            "quote_address": quote,
                            "side": "bid",
                            "minimum_in_base": 0,
                            "levels": [[1.0, 2.0]]
                        }]))
                    }
                }),
            )
            .route(
                "/swap-api-v2/v1/firm-quote",
                get(move || {
                    let counter = Arc::clone(&firm_counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({"code": 101010}))
                    }
                }),
            );
        let (client, server) = client_for_with_max_inflight(app, 1).await;

        let first_client = client.clone();
        let first = tokio::spawn(async move { first_client.request_firm_quote(request).await });
        tokio::time::timeout(Duration::from_secs(1), orderbook_started.notified())
            .await
            .expect("first request did not reach Native orderbook");
        assert_eq!(client.inflight.available_permits(), 0);

        for _ in 0..3 {
            let wave = tokio::time::timeout(
                Duration::from_millis(50),
                futures_util::future::join_all((0..32).map(|_| client.request_firm_quote(request))),
            )
            .await
            .expect("saturated burst queued instead of rejecting");
            assert_eq!(wave.len(), 32);
            assert!(
                wave.into_iter()
                    .all(|result| matches!(result, Err(NativeRfqError::Saturated)))
            );
        }
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(firm_calls.load(Ordering::SeqCst), 0);

        release_orderbook.notify_one();
        let first_result = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .expect("first request did not finish after orderbook release")
            .expect("first request task panicked")
            .unwrap();
        assert!(first_result.is_none());
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(firm_calls.load(Ordering::SeqCst), 1);
        assert_eq!(client.inflight.available_permits(), 1);
        server.abort();
    }

    #[tokio::test]
    async fn direction_unavailable_error_invalidates_last_look_cache() {
        let (client, request, orderbook_calls, firm_calls, server) =
            client_with_direction_and_firm_error(171_037).await;

        assert!(client.request_firm_quote(request).await.unwrap().is_none());
        assert!(client.request_firm_quote(request).await.unwrap().is_none());

        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 2);
        assert_eq!(firm_calls.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn amount_above_depth_does_not_invalidate_the_global_orderbook() {
        let (client, request, orderbook_calls, firm_calls, server) =
            client_with_direction_and_firm_error(101_010).await;

        assert!(client.request_firm_quote(request).await.unwrap().is_none());
        assert!(client.request_firm_quote(request).await.unwrap().is_none());

        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(firm_calls.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn concurrent_orderbook_api_failures_share_one_short_cached_result() {
        let orderbook_calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&orderbook_calls);
        let app = Router::new().route(
            "/swap-api-v2/v1/orderbook",
            get(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Json(serde_json::json!({
                        "code": 201006,
                        "message": "api_key not found"
                    }))
                }
            }),
        );
        // Keep this cache single-flight test focused on all 16 callers; the
        // separate bulkhead test covers saturation behavior.
        let (client, server) = client_for_with_max_inflight(app, 16).await;
        let mut attempts = Vec::new();
        for _ in 0..16 {
            let client = client.clone();
            attempts.push(tokio::spawn(async move {
                client.request_firm_quote(firm_request()).await
            }));
        }

        for attempt in attempts {
            assert_eq!(
                attempt.await.unwrap().unwrap_err(),
                NativeRfqError::Api(201_006)
            );
        }
        assert_eq!(orderbook_calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn stale_invalidation_cannot_clear_a_newer_success_or_failure_cache() {
        let request = firm_request();
        assert_stale_invalidation_preserves_refresh(
            serde_json::json!([{
                "base_address": format!("{:#x}", request.token_in),
                "quote_address": format!("{:#x}", request.token_out),
                "side": "bid",
                "minimum_in_base": 0,
                "levels": [[1.0, 2.0]]
            }]),
            Ok(true),
        )
        .await;
        assert_stale_invalidation_preserves_refresh(
            serde_json::json!({
                "code": 201006,
                "message": "api_key not found"
            }),
            Err(NativeRfqError::Api(201_006)),
        )
        .await;
    }
}
