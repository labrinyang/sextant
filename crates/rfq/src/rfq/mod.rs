//! External RFQ liquidity sources.
//!
//! `native` means Native.org here. It is intentionally not represented by
//! 0x Settler's Permit2 `RFQ` action: Native returns Router calldata and it
//! is executed through a tightly validated Settler `BASIC` action.

mod authorization;
mod native;
mod types;
mod validation;

/// The validation fixtures (a signed v6 quote and its request), for
/// dependents' tests.
#[cfg(any(test, feature = "testing"))]
pub use validation::test_support as validation_support;

pub use authorization::{NativeAuthorization, NativeBeneficiaryAuthorizer};
pub use native::{NativeRfqClient, NativeRfqConfig};
pub use types::{
    FirmQuoteRequest, NativePair, NativeQuoteObservation, NativeRfqError, NativeRfqSource,
    ValidatedFirmQuote,
};
