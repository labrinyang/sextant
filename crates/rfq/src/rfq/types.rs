use crate::chain::NativeRfqProfile;
use alloy_primitives::{Address, B256, Bytes, U256};
use futures_util::future::BoxFuture;
use serde::Deserialize;
use std::fmt;

/// A directional Native market requested by the route planner.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NativePair {
    pub token_in: Address,
    pub token_out: Address,
}

impl NativePair {
    pub const fn new(token_in: Address, token_out: Address) -> Self {
        Self {
            token_in,
            token_out,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmQuoteRequest {
    pub identity: NativeRfqProfile,
    pub token_in: Address,
    pub token_out: Address,
    pub amount_in: U256,
    /// Native Router's direct caller and payout address. For composed swaps
    /// both are the Settler, which retains output for the global slippage gate.
    pub settler: Address,
    /// End-user identity supplied to Native's risk controls.
    pub beneficiary: Address,
    /// EOA expected to submit the transaction. V6 binds this to tx.origin when
    /// it is known; absence is represented by a zero expectedOrigin on-chain.
    pub tx_origin: Option<Address>,
    pub slippage_bps: u32,
    pub expiry_seconds: u64,
    /// Trusted chain time projected from the canonical snapshot header at the
    /// instant this optional request starts. The HTTP client advances it with
    /// a monotonic timer while waiting for Native.
    pub chain_timestamp: u64,
}

/// Canonical chain state against which the Native Pool signer and nonce were
/// checked after the firm quote arrived. This is deliberately separate from
/// the earlier AMM snapshot: Native v6 pAMM output is a live reference, so a
/// fork replay must start from this observation rather than the AMM block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeQuoteObservation {
    pub number: u64,
    pub hash: B256,
}

/// Only `validation` may construct this type. Downstream encoders can forward
/// the original calldata, but cannot accidentally consume an unchecked target
/// or response amount.
#[derive(Clone)]
pub struct ValidatedFirmQuote {
    pub target: Address,
    pub pool: Address,
    pub calldata: Bytes,
    /// Request bindings retained after validation so a composed-route encoder
    /// cannot accidentally attach a valid firm quote to the wrong stage.
    pub token_in: Address,
    pub token_out: Address,
    pub settler: Address,
    pub expected_origin: Address,
    pub amount_in: U256,
    pub amount_out: U256,
    /// Native Pool signer recovered from the EIP-712 order signature.
    pub signer: Address,
    /// Global Native Pool nonce checked on-chain after the firm response.
    pub nonce: U256,
    pub beneficiary: Address,
    pub deadline: u64,
    /// Safety window enforced when validation accepted the quote. Keep it on
    /// the validated artifact so a quote that ages while the solver assembles
    /// its response can be checked against the same policy before encoding.
    pub min_ttl_seconds: u64,
    pub amount_in_offset: usize,
    pub amount_out_minimum_offset: usize,
    pub router_version: u8,
    /// Filled only after signer authorization and nonce state have both been
    /// checked at this exact canonical block.
    pub observation: Option<NativeQuoteObservation>,
}

impl ValidatedFirmQuote {
    pub fn target(&self) -> Address {
        self.target
    }

    pub fn pool(&self) -> Address {
        self.pool
    }

    pub fn calldata(&self) -> &Bytes {
        &self.calldata
    }

    pub fn token_in(&self) -> Address {
        self.token_in
    }

    pub fn token_out(&self) -> Address {
        self.token_out
    }

    pub fn settler(&self) -> Address {
        self.settler
    }

    pub fn expected_origin(&self) -> Address {
        self.expected_origin
    }

    pub fn amount_in(&self) -> U256 {
        self.amount_in
    }

    pub fn amount_out(&self) -> U256 {
        self.amount_out
    }

    pub fn beneficiary(&self) -> Address {
        self.beneficiary
    }

    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Whether the quote still satisfies the source's configured safety
    /// window at `now`. Equality is accepted, matching initial validation.
    pub fn is_live_at(&self, now: u64) -> bool {
        self.deadline >= now.saturating_add(self.min_ttl_seconds)
    }

    pub fn amount_in_offset(&self) -> usize {
        self.amount_in_offset
    }

    pub fn amount_out_minimum_offset(&self) -> usize {
        self.amount_out_minimum_offset
    }

    pub fn router_version(&self) -> u8 {
        self.router_version
    }

    pub fn observation(&self) -> Option<NativeQuoteObservation> {
        self.observation
    }

    pub fn record_observation(&mut self, number: u64, hash: B256) {
        self.observation = Some(NativeQuoteObservation { number, hash });
    }
}

impl fmt::Debug for ValidatedFirmQuote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedFirmQuote")
            .field("target", &self.target)
            .field("pool", &self.pool)
            .field("calldata_bytes", &self.calldata.len())
            .field("token_in", &self.token_in)
            .field("token_out", &self.token_out)
            .field("settler", &self.settler)
            .field("expected_origin", &self.expected_origin)
            .field("amount_in", &self.amount_in)
            .field("amount_out", &self.amount_out)
            .field("signer", &self.signer)
            .field("nonce", &self.nonce)
            .field("beneficiary", &self.beneficiary)
            .field("deadline", &self.deadline)
            .field("min_ttl_seconds", &self.min_ttl_seconds)
            .field("amount_in_offset", &self.amount_in_offset)
            .field("amount_out_minimum_offset", &self.amount_out_minimum_offset)
            .field("router_version", &self.router_version)
            .field("observation", &self.observation)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeRfqError {
    WorkBudget,
    Saturated,
    QueueTimeout,
    Transport,
    OnchainVerification,
    Http(u16),
    Api(u32),
    ResponseTooLarge,
    InvalidJson,
    InvalidResponse(&'static str),
}

impl NativeRfqError {
    /// Capacity failures are retryable and must not silently change the quote
    /// from Native-eligible execution to an AMM-only result.
    pub fn is_retryable_capacity(&self) -> bool {
        matches!(
            self,
            Self::Saturated | Self::QueueTimeout | Self::Api(201_005)
        )
    }
}

impl fmt::Display for NativeRfqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkBudget => f.write_str("Native RFQ request work budget exhausted"),
            Self::Saturated => f.write_str("Native RFQ concurrency capacity is exhausted"),
            Self::QueueTimeout => f.write_str("Native RFQ pacing queue deadline exceeded"),
            Self::Transport => f.write_str("Native RFQ transport failed"),
            Self::OnchainVerification => {
                f.write_str("Native RFQ on-chain state verification failed")
            }
            Self::Http(status) => write!(f, "Native RFQ returned HTTP {status}"),
            Self::Api(code) => write!(f, "Native RFQ returned API error {code}"),
            Self::ResponseTooLarge => f.write_str("Native RFQ response exceeded the size limit"),
            Self::InvalidJson => f.write_str("Native RFQ returned invalid JSON"),
            Self::InvalidResponse(reason) => write!(f, "Native RFQ response rejected: {reason}"),
        }
    }
}

impl std::error::Error for NativeRfqError {}

pub trait NativeRfqSource: Send + Sync {
    /// Price every depth-sufficient directional request from one short-cached
    /// orderbook observation. Each tuple is `(pair, requested amount in,
    /// conservative amount out)` in raw token units; unsupported, malformed,
    /// below-minimum, or over-depth requests are omitted. The result is only a
    /// pathfinding indication. `firm_quote` remains the sole executable quote.
    #[allow(clippy::type_complexity)] // preserves the documented batch tuple at the source boundary
    fn indicative_quotes<'a>(
        &'a self,
        identity: NativeRfqProfile,
        requests: &'a [(NativePair, U256)],
    ) -> BoxFuture<'a, Result<Vec<(NativePair, U256, U256)>, NativeRfqError>>;

    /// Return the requested directional markets currently advertised by the
    /// source, preserving request order (and duplicates).
    ///
    /// The production client resolves the whole slice from one short-cached
    /// orderbook snapshot. This membership-only interface remains useful for
    /// last-look diagnostics; route planners use `indicative_quotes` above.
    fn available_pairs<'a>(
        &'a self,
        identity: NativeRfqProfile,
        pairs: &'a [NativePair],
    ) -> BoxFuture<'a, Result<Vec<NativePair>, NativeRfqError>> {
        Box::pin(async move {
            let mut available = Vec::with_capacity(pairs.len());
            for pair in pairs {
                if self
                    .direction_available(identity, pair.token_in, pair.token_out)
                    .await?
                {
                    available.push(*pair);
                }
            }
            Ok(available)
        })
    }

    /// Cheap, short-cached orderbook membership used by last-look callers and
    /// diagnostics that do not need an indicative amount.
    ///
    /// The production client overrides this with Native's directional
    /// `/orderbook` last look. A `true` here is only eligibility and never an
    /// executable quote -- `firm_quote` remains mandatory and rechecks the
    /// orderbook immediately before requesting calldata.
    fn direction_available<'a>(
        &'a self,
        _identity: NativeRfqProfile,
        _token_in: Address,
        _token_out: Address,
    ) -> BoxFuture<'a, Result<bool, NativeRfqError>> {
        Box::pin(async { Ok(true) })
    }

    fn firm_quote<'a>(
        &'a self,
        request: FirmQuoteRequest,
    ) -> BoxFuture<'a, Result<Option<ValidatedFirmQuote>, NativeRfqError>>;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirmQuoteWire {
    #[serde(default)]
    pub success: bool,
    pub code: Option<u32>,
    #[serde(default)]
    pub recipient: String,
    #[serde(default)]
    pub amount_in: String,
    #[serde(default)]
    pub amount_out: String,
    pub tx_request: Option<TxRequestWire>,
    #[serde(rename = "router_version", alias = "routerVersion")]
    pub router_version: Option<NumberOrString>,
    pub amount_in_offset: Option<usize>,
    pub amount_out_minimum_offset: Option<usize>,
    #[serde(default, rename = "is_black_address", alias = "isBlackAddress")]
    pub is_black_address: bool,
}

#[derive(Debug, Deserialize)]
pub struct TxRequestWire {
    pub target: String,
    pub calldata: String,
    pub value: String,
    #[serde(default)]
    pub function: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(u64),
    String(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_native_firm_quote_mixed_case_wire_fields() {
        let wire: FirmQuoteWire = serde_json::from_value(serde_json::json!({
            "success": true,
            "recipient": "0x1111111111111111111111111111111111111111",
            "amountIn": "1000",
            "amountOut": "2000",
            "txRequest": {
                "target": "0x2222222222222222222222222222222222222222",
                "calldata": "0x7083527c",
                "value": "0",
                "function": "tradeRFQT"
            },
            "router_version": "6",
            "amountInOffset": 36,
            "amountOutMinimumOffset": 68,
            "is_black_address": true
        }))
        .unwrap();

        assert!(wire.success);
        assert!(wire.is_black_address);
        assert!(matches!(
            wire.router_version,
            Some(NumberOrString::String(ref value)) if value == "6"
        ));
        assert_eq!(wire.amount_in_offset, Some(36));
        assert_eq!(wire.amount_out_minimum_offset, Some(68));
    }

    #[test]
    fn decodes_http_200_business_error_as_unsuccessful_quote() {
        let wire: FirmQuoteWire = serde_json::from_value(serde_json::json!({
            "code": 171037,
            "message": "orderbook empty for quoted trade"
        }))
        .unwrap();

        assert!(!wire.success);
        assert_eq!(wire.code, Some(171037));
        assert!(wire.tx_request.is_none());
    }
}
