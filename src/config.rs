//! The process configuration: the chain this process serves and its
//! upstreams, fees and limits, read from the environment at boot.

use crate::chain::{ChainProfile, MAX_FEE_BPS, MAX_POSITIVE_SLIPPAGE_BPS, env_or, profile_by_key};
use crate::rfq::NativeRfqConfig;
use alloy_primitives::Address;
use anyhow::Context;

#[derive(Clone)]
pub struct Config {
    pub profile: &'static ChainProfile,
    pub rpc_url: String,
    pub logs_rpc_url: String,
    /// Required only by an indexer-backed discovery profile. It is an internal,
    /// identity-only catalog endpoint and may itself contain credentials, so
    /// callers must never include it in diagnostics.
    pub indexer_url: Option<String>,
    /// Outbound Native.org firm-quote client. The API key is held inside a
    /// redacted config type and never included in diagnostics.
    pub native_rfq: Option<NativeRfqConfig>,
    pub fee_bps: u32,
    pub fee_receiver: Option<Address>,
    pub positive_slippage_max_bps: u32,
    pub positive_slippage_recipient: Option<Address>,
    pub port: u16,
    /// Hard cap on total /quote handling time, seconds (SOLVER_QUOTE_TIMEOUT).
    pub quote_timeout: u64,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("profile", &self.profile.key)
            .field("rpc_url", &"[redacted]")
            .field("logs_rpc_url", &"[redacted]")
            .field(
                "indexer_url",
                &self.indexer_url.as_ref().map(|_| "[configured]"),
            )
            .field(
                "native_rfq",
                &self.native_rfq.as_ref().map(|_| "[configured]"),
            )
            .field("fee_bps", &self.fee_bps)
            .field("fee_receiver", &self.fee_receiver)
            .field("positive_slippage_max_bps", &self.positive_slippage_max_bps)
            .field(
                "positive_slippage_recipient",
                &self.positive_slippage_recipient,
            )
            .field("port", &self.port)
            .field("quote_timeout", &self.quote_timeout)
            .finish()
    }
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let profile = profile_by_key(&env_or("SOLVER_CHAIN", "")?)?;
        let native_rfq = NativeRfqConfig::from_env(profile)?;
        let receiver = env_or("SOLVER_FEE_RECEIVER", "")?;
        // No fee unless one is configured: positive slippage goes to the user.
        let fee_bps: u32 = env_or("SOLVER_FEE_BPS", "0")?
            .parse()
            .context("SOLVER_FEE_BPS is invalid")?;
        let positive_slippage_recipient = env_or("SOLVER_POSITIVE_SLIPPAGE_RECIPIENT", "")?;
        let positive_slippage_max_bps: u32 = env_or("SOLVER_POSITIVE_SLIPPAGE_MAX_BPS", "0")?
            .parse()
            .context("SOLVER_POSITIVE_SLIPPAGE_MAX_BPS is invalid")?;
        anyhow::ensure!(
            fee_bps <= MAX_FEE_BPS,
            "SOLVER_FEE_BPS {fee_bps} exceeds the {MAX_FEE_BPS} (10%) sanity cap"
        );
        anyhow::ensure!(
            positive_slippage_max_bps <= MAX_POSITIVE_SLIPPAGE_BPS,
            "SOLVER_POSITIVE_SLIPPAGE_MAX_BPS {positive_slippage_max_bps} exceeds {MAX_POSITIVE_SLIPPAGE_BPS}"
        );
        Ok(Config {
            profile,
            rpc_url: env_or("SOLVER_RPC", profile.public_rpc)?,
            logs_rpc_url: env_or("SOLVER_LOGS_RPC", profile.public_rpc)?,
            indexer_url: match env_or("SOLVER_INDEXER_URL", "")?.trim() {
                "" => None,
                value => Some(value.to_string()),
            },
            native_rfq,
            fee_bps,
            fee_receiver: if receiver.is_empty() {
                None
            } else {
                Some(receiver.parse().context("SOLVER_FEE_RECEIVER is invalid")?)
            },
            positive_slippage_max_bps,
            positive_slippage_recipient: if positive_slippage_recipient.is_empty() {
                None
            } else {
                Some(
                    positive_slippage_recipient
                        .parse()
                        .context("SOLVER_POSITIVE_SLIPPAGE_RECIPIENT is invalid")?,
                )
            },
            port: env_or("SOLVER_PORT", "8899")?
                .parse()
                .context("SOLVER_PORT is invalid")?,
            quote_timeout: env_or("SOLVER_QUOTE_TIMEOUT", "120")?
                .parse()
                .context("SOLVER_QUOTE_TIMEOUT is invalid")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::BSC_PROFILE;

    #[test]
    fn config_debug_redacts_every_upstream_url() {
        let rpc_secret =
            "https://rpc-user:rpc-password@rpc.example/secret-rpc-path?apiKey=rpc-query-secret";
        let logs_secret =
            "https://logs-user:logs-password@logs.example/secret-logs-path?token=logs-query-secret";
        let indexer_secret = "https://indexer-user:indexer-password@indexer.example/secret-indexer-path?key=indexer-query-secret";
        let config = Config {
            profile: &BSC_PROFILE,
            rpc_url: rpc_secret.to_string(),
            logs_rpc_url: logs_secret.to_string(),
            indexer_url: Some(indexer_secret.to_string()),
            native_rfq: None,
            fee_bps: 0,
            fee_receiver: None,
            positive_slippage_max_bps: 0,
            positive_slippage_recipient: None,
            port: 8899,
            quote_timeout: 120,
        };
        let rendered = format!("{config:?}");
        assert_eq!(
            rendered,
            "Config { profile: \"bsc\", rpc_url: \"[redacted]\", logs_rpc_url: \"[redacted]\", indexer_url: Some(\"[configured]\"), native_rfq: None, fee_bps: 0, fee_receiver: None, positive_slippage_max_bps: 0, positive_slippage_recipient: None, port: 8899, quote_timeout: 120 }"
        );
        let pretty = format!("{config:#?}");
        for secret in [
            "rpc-user",
            "rpc-password",
            "secret-rpc-path",
            "rpc-query-secret",
            "logs-user",
            "logs-password",
            "secret-logs-path",
            "logs-query-secret",
            "indexer-user",
            "indexer-password",
            "secret-indexer-path",
            "indexer-query-secret",
        ] {
            assert!(!pretty.contains(secret), "Debug leaked marker {secret}");
        }
    }
}
