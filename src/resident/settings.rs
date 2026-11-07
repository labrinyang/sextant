use crate::chain::ChainProfile;
use alloy_primitives::Address;
use anyhow::{Context, ensure};
use std::time::Duration;

/// How often every pool is read whole when logs say few changed.
const FULL_READ_DEFAULT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub list_url: String,
    pub poll: Duration,
    /// Connectors beyond the profile's own, admitted where they have pools.
    pub connectors: Vec<Address>,
    /// The longest every pool goes without being read whole; `None` reads
    /// every block whole and asks for no logs.
    pub full_read: Option<Duration>,
}

impl Settings {
    /// `None` when resident state is off, which it is unless
    /// `SOLVER_RESIDENT=on`; on, it needs `SOLVER_RESIDENT_POOL_LIST_URL`.
    pub fn from_env(profile: &ChainProfile) -> anyhow::Result<Option<Self>> {
        let read = |key| crate::chain::env_or(key, "");
        Self::parse(
            profile,
            &read("SOLVER_RESIDENT")?,
            &read("SOLVER_RESIDENT_POLL_MS")?,
            &read("SOLVER_RESIDENT_POOL_LIST_URL")?,
            &read("SOLVER_RESIDENT_CONNECTORS")?,
            &read("SOLVER_RESIDENT_FULL_READ_MS")?,
        )
    }

    pub(super) fn parse(
        profile: &ChainProfile,
        mode: &str,
        poll_ms: &str,
        list_url: &str,
        connectors: &str,
        full_read_ms: &str,
    ) -> anyhow::Result<Option<Self>> {
        match mode.trim() {
            "" | "off" => return Ok(None),
            "on" => {}
            other => anyhow::bail!("SOLVER_RESIDENT={other:?} is invalid: use on or off"),
        }
        ensure!(
            profile.indexed_discovery().is_some(),
            "SOLVER_RESIDENT=on needs a profile with a venue table; {} has none",
            profile.key
        );
        let poll = match poll_ms.trim() {
            "" => 1_000,
            value => value
                .parse::<u64>()
                .with_context(|| format!("SOLVER_RESIDENT_POLL_MS={value:?} is invalid"))?,
        };
        ensure!(
            (200..=10_000).contains(&poll),
            "SOLVER_RESIDENT_POLL_MS must be 200 to 10000"
        );
        let list_url = list_url.trim();
        ensure!(
            !list_url.is_empty(),
            "SOLVER_RESIDENT=on needs SOLVER_RESIDENT_POOL_LIST_URL"
        );
        let parsed: reqwest::Url = list_url
            .parse()
            .context("SOLVER_RESIDENT_POOL_LIST_URL is not a URL")?;
        ensure!(
            matches!(parsed.scheme(), "https" | "http"),
            "SOLVER_RESIDENT_POOL_LIST_URL must be http(s)"
        );
        let connectors = connectors
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(|token| {
                token.parse::<Address>().with_context(|| {
                    format!("SOLVER_RESIDENT_CONNECTORS: {token:?} is not an address")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let full_read = match full_read_ms.trim() {
            "" => Some(FULL_READ_DEFAULT),
            "0" => None,
            value => {
                let ms = value.parse::<u64>().with_context(|| {
                    format!("SOLVER_RESIDENT_FULL_READ_MS={value:?} is invalid")
                })?;
                ensure!(
                    ms <= 3_600_000,
                    "SOLVER_RESIDENT_FULL_READ_MS must be 0 to 3600000"
                );
                Some(Duration::from_millis(ms))
            }
        };
        Ok(Some(Self {
            list_url: list_url.to_string(),
            poll: Duration::from_millis(poll),
            connectors,
            full_read,
        }))
    }
}
