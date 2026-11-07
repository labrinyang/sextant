use crate::catalog::CandidateSource;
use crate::chain::ChainProfile;
use alloy_primitives::U256;
use anyhow::{Context, ensure};
use std::sync::LazyLock;

/// Snapshot word-window half-width (SOLVER_BITMAP_WORDS, default 16): each
/// pool's tick coverage is ±words·256·spacing around the current tick.
fn read_env_value<T>(key: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(value) => value
            .parse()
            .map_err(|error| anyhow::anyhow!("{key}={value:?} is invalid: {error}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(anyhow::anyhow!("reading {key}: {error}")),
    }
}

fn env_value<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    read_env_value(key, default).unwrap_or_else(|error| panic!("{error:#}"))
}

pub(super) static BITMAP_WORDS: LazyLock<i32> =
    LazyLock::new(|| env_value("SOLVER_BITMAP_WORDS", 16));
pub(super) static TOPO_TTL: LazyLock<u64> = LazyLock::new(|| env_value("SOLVER_TOPO_TTL", 600));
pub(super) static V4_RETRY_TTL: LazyLock<u64> =
    LazyLock::new(|| env_value("SOLVER_V4_RETRY_TTL", 30));
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DynamicConnectorMode {
    ProfileOnly,
    Shadow,
    Adjacency,
}

impl DynamicConnectorMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileOnly => "profile_only",
            Self::Shadow => "shadow",
            Self::Adjacency => "adjacency",
        }
    }
}

pub(super) static DYNAMIC_CONNECTORS: LazyLock<DynamicConnectorMode> =
    LazyLock::new(|| read_dynamic_connector_mode().unwrap_or_else(|error| panic!("{error:#}")));

/// SOLVER_CONNECTOR_SCREENING: price the connectors the pair budget could not
/// make routable, so `graphGapBps` reports what the shortlist left behind.
///
/// Off by default. It costs one indexer request, one Multicall3 round and one
/// Lens read per topology refresh, all pinned to the same canonical block, and
/// it is measurement only: screened pools never enter `Snapshot`, so no plan
/// can be built on them and `gapBps` is unchanged whether it runs or not.
/// Requires a dynamic connector mode — there is no ranking to carry otherwise.
pub(super) static CONNECTOR_SCREENING: LazyLock<bool> =
    LazyLock::new(|| read_connector_screening().unwrap_or_else(|error| panic!("{error:#}")));

pub(super) fn parse_connector_screening(value: Option<&str>) -> anyhow::Result<bool> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(value) => {
            anyhow::bail!("SOLVER_CONNECTOR_SCREENING must be 0 or 1, got {value:?}")
        }
    }
}

/// Screening needs a ranking to screen, and `profile_only` produces none.
/// Accepting the pair silently would report `screened=0` forever and read as
/// "measured, found nothing" when the truth is "never asked".
pub(super) fn screening_setting_admitted(screening: bool, mode: DynamicConnectorMode) -> bool {
    !screening || mode != DynamicConnectorMode::ProfileOnly
}

/// The dual pass is the only consumer of screened state. With the certificate
/// off, screening still pays for a topology request, a Multicall3 round and a
/// Lens read per lease and reports nothing — a cost with no reader.
pub(super) fn screening_has_a_reader(screening: bool, certificate: bool) -> bool {
    !screening || certificate
}

fn read_connector_screening() -> anyhow::Result<bool> {
    match std::env::var("SOLVER_CONNECTOR_SCREENING") {
        Ok(value) => parse_connector_screening(Some(&value)),
        Err(std::env::VarError::NotPresent) => parse_connector_screening(None),
        Err(error) => Err(anyhow::anyhow!(
            "reading SOLVER_CONNECTOR_SCREENING: {error}"
        )),
    }
}

/// SOLVER_RANKED_CONNECTORS: choose candidates from the indexer's materialized
/// depth ranking instead of walking both endpoints' complete adjacency.
///
/// Off by default. The walk is the narrower behaviour, but it is the one every
/// existing deployment already validates against, so moving off it is an
/// explicit decision rather than a consequence of shipping a new binary.
///
/// The walk enumerates every common neighbour and ranks by shared protocol
/// count, which says nothing about depth and cannot even complete on a chain
/// whose hub tokens carry millions of neighbours. The ranking answers in one
/// request, ordered by what a two-hop route could actually carry — at the cost
/// of covering only the protocols the indexer can price from pool state, so a
/// connector reachable solely through V4 stops being discoverable.
pub(super) static RANKED_CONNECTORS: LazyLock<bool> =
    LazyLock::new(|| read_ranked_connectors().unwrap_or_else(|error| panic!("{error:#}")));

fn read_ranked_connectors() -> anyhow::Result<bool> {
    match std::env::var("SOLVER_RANKED_CONNECTORS") {
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        Ok(value) => anyhow::bail!("SOLVER_RANKED_CONNECTORS must be 0 or 1, got {value:?}"),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(anyhow::anyhow!("reading SOLVER_RANKED_CONNECTORS: {error}")),
    }
}

/// SOLVER_CONNECTOR_ADMISSION: give a slot held by a PROVEN-IDLE connector to a
/// candidate that beats the certified cost of taking it.
///
/// Off by default, and the gate proves that default.
///
/// The ranking orders by what a two-hop route *could* carry; measurement says
/// what one *did*, and they disagree completely — the connector carrying 100%
/// of a 30.9 bp gain ranked fourth (§13, §16), and three connectors holding
/// paid slots measured at exactly zero (§21).
///
/// The rule is the one in `counterfactual::admit_by_certified_value`, and its
/// whole argument fits in a sentence: a connector the served plan routed no
/// flow through can be dropped without making the plan infeasible, so losing it
/// costs at most the certificate's own gap, and a candidate measured above that
/// gap leaves the universe strictly better. No incumbent is ever compared with
/// a candidate.
///
/// It needs verdicts, so it does nothing until connector screening has run for
/// this pair inside the coverage lease, and nothing at all where no admitted
/// connector is idle.
///
/// # Sound, and not yet validated in production
///
/// The rule it replaced was argued for over three sections, built, unit-tested,
/// gated and deployed — and cost 142 bp the first time it acted (§19), because
/// it evicted a connector carrying the route on the strength of a comparison
/// that was never performed. This one cannot do that: a connector carrying the
/// route is never idle, so its slot is not one this rule can offer, at any
/// candidate value.
///
/// That is an argument. §19 is what arguments are worth here, so the flag stays
/// off until a window shows it acting.
pub(super) static CONNECTOR_ADMISSION: LazyLock<bool> =
    LazyLock::new(|| read_connector_admission().unwrap_or_else(|error| panic!("{error:#}")));

fn read_connector_admission() -> anyhow::Result<bool> {
    match std::env::var("SOLVER_CONNECTOR_ADMISSION") {
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        Ok(value) => anyhow::bail!("SOLVER_CONNECTOR_ADMISSION must be 0 or 1, got {value:?}"),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(anyhow::anyhow!(
            "reading SOLVER_CONNECTOR_ADMISSION: {error}"
        )),
    }
}

/// SOLVER_CONNECTOR_MIN_BPS_E4: the churn floor under admission, in basis
/// points × 10⁴. Default 10000 — one basis point.
///
/// Soundness comes from the certified gap, never from this. §22's rule already
/// requires a candidate to beat what evicting an idle connector can cost, and
/// that bound is measured per quote rather than configured. This is the floor
/// UNDER that bound, and it exists because §21 measured gaps as low as
/// 0.0043 bp: a candidate clearing one of those by a hair would be a provably
/// profitable swap that rewrites the route for nothing.
///
/// One bp is roughly where an extra hop pays for itself on BSC gas (§0
/// conclusion 7), and it sits inside the measured population rather than above
/// or below all of it: §21's WBNB→USDT candidate ran 0.2752 to 2.6116 bp across
/// three sizes, so the floor separates sizes on a single pair.
///
/// Demotion is by expiry rather than by re-measurement. A verdict measured
/// anywhere in one lease stays readable to admission throughout the next and
/// expires before it can answer for a third, after which an admitted connector
/// falls back to the ranking's order and must earn its slot again.
pub(super) static CONNECTOR_MIN_BPS_E4: LazyLock<U256> = LazyLock::new(|| {
    U256::from(read_connector_min_bps_e4().unwrap_or_else(|error| panic!("{error:#}")))
});

pub(crate) fn read_connector_min_bps_e4() -> anyhow::Result<u64> {
    match std::env::var("SOLVER_CONNECTOR_MIN_BPS_E4") {
        Ok(value) => value.parse().map_err(|error| {
            anyhow::anyhow!("SOLVER_CONNECTOR_MIN_BPS_E4={value:?} is invalid: {error}")
        }),
        Err(std::env::VarError::NotPresent) => Ok(10_000),
        Err(error) => Err(anyhow::anyhow!(
            "reading SOLVER_CONNECTOR_MIN_BPS_E4: {error}"
        )),
    }
}

/// Admission needs a mode whose connectors actually route, exactly as screening
/// needs one that ranks. Under `profile_only` there is no shortlist to reorder,
/// and under `shadow` the shortlist never becomes routable — so accepting the
/// pair silently would leave an operator believing measurement was steering the
/// budget when nothing it produced could reach a quote.
pub(super) fn admission_setting_admitted(admission: bool, mode: DynamicConnectorMode) -> bool {
    !admission || mode == DynamicConnectorMode::Adjacency
}

/// A ranked selector needs a dynamic mode to select for, exactly as screening
/// does. Accepting the pair silently would leave an operator believing the
/// ranking was consulted when nothing ever asked it a question.
pub(super) fn ranked_setting_admitted(ranked: bool, mode: DynamicConnectorMode) -> bool {
    !ranked || mode != DynamicConnectorMode::ProfileOnly
}

/// Whether this process selects connectors from the indexer's ranking.
///
/// Reported at `/health` for the same reason screening is: with the ranking
/// unpublished the solver falls back to the walk and still answers, so a flat
/// reading cannot distinguish a flag that took from one that did not.
pub fn ranked_connectors() -> bool {
    *RANKED_CONNECTORS
}

fn read_dynamic_connector_mode() -> anyhow::Result<DynamicConnectorMode> {
    match std::env::var("SOLVER_DYNAMIC_CONNECTORS") {
        Ok(value) if value == "profile_only" => Ok(DynamicConnectorMode::ProfileOnly),
        Ok(value) if value == "shadow" => Ok(DynamicConnectorMode::Shadow),
        Ok(value) if value == "adjacency" => Ok(DynamicConnectorMode::Adjacency),
        Ok(value) => anyhow::bail!(
            "SOLVER_DYNAMIC_CONNECTORS must be profile_only, shadow, or adjacency, got {value:?}"
        ),
        Err(std::env::VarError::NotPresent) => Ok(DynamicConnectorMode::ProfileOnly),
        Err(error) => Err(anyhow::anyhow!(
            "reading SOLVER_DYNAMIC_CONNECTORS: {error}"
        )),
    }
}

pub fn dynamic_connector_mode() -> &'static str {
    DYNAMIC_CONNECTORS.as_str()
}

/// Whether connector screening is buying state this process will report on.
///
/// Reported at `/health` because it cannot be inferred from anything else a
/// caller can see: with it off, `graphGapBps` still ships and still equals
/// `catalogGapBps`, so a flat reading is indistinguishable from a flag that
/// never took. Operators flipping it need to confirm it took, and the release
/// gate needs to prove the shipped default is off.
pub fn connector_screening() -> bool {
    *CONNECTOR_SCREENING
}

/// Whether measurement, rather than the depth ranking, decides which connectors
/// hold the pair budget's slots.
///
/// Reported at `/health` for the reason the other two are, and one more: with no
/// verdicts yet measured admission is a deliberate no-op, so the shortlist it
/// produces is byte-identical to the ranking's. A flat reading therefore cannot
/// distinguish a flag that took from one that did not, and this flag is the
/// first in the group that can change a served quote.
pub fn connector_admission() -> bool {
    *CONNECTOR_ADMISSION
}

/// The measured value a connector must carry to hold a slot, in bps × 10⁴.
///
/// Reported alongside the flag because the flag alone does not say what it
/// admits. A threshold set past every measured value is indistinguishable at
/// `/health` from admission being off, and §16 measured the whole population
/// between 0.19 and 30.9 bp — a range a single mistyped zero clears entirely.
pub fn connector_min_bps_e4() -> String {
    crate::certificate::format_bps_e4(*CONNECTOR_MIN_BPS_E4)
}

/// Choosing a connector the profile does not name needs a catalog that knows
/// which tokens hold pools. Factories answer only for the pairs they are
/// asked about, so a profile whose factories name its pools routes through
/// its own connectors alone.
pub(super) fn connector_mode_admitted(
    candidates: Option<CandidateSource>,
    mode: DynamicConnectorMode,
) -> bool {
    candidates != Some(CandidateSource::Factories) || mode == DynamicConnectorMode::ProfileOnly
}

/// Validate every state/discovery setting before the server starts accepting
/// traffic. The lazies below retain cheap process-wide access on the hot path.
pub fn validate_settings(profile: &ChainProfile, logs_url: Option<&str>) -> anyhow::Result<()> {
    let bitmap_words = read_env_value("SOLVER_BITMAP_WORDS", 16i32)?;
    ensure!(
        (0..=8192).contains(&bitmap_words),
        "SOLVER_BITMAP_WORDS out of range"
    );
    let _: u64 = read_env_value("SOLVER_TOPO_TTL", 600)?;
    let _: u64 = read_env_value("SOLVER_V4_RETRY_TTL", 30)?;
    let _: u64 = crate::counterfactual::read_coverage_ttl()?;
    let mode = read_dynamic_connector_mode()?;
    ensure!(
        connector_mode_admitted(
            profile
                .indexed_discovery()
                .map(|discovery| discovery.candidates),
            mode
        ),
        "SOLVER_DYNAMIC_CONNECTORS needs a topology indexer to rank connectors; {} names \
         its pools by factory, so only profile_only can route",
        profile.name
    );
    let screening = read_connector_screening()?;
    ensure!(
        screening_setting_admitted(screening, mode),
        "SOLVER_CONNECTOR_SCREENING needs SOLVER_DYNAMIC_CONNECTORS=shadow or adjacency: \
         profile_only produces no ranking to screen"
    );
    ensure!(
        screening_has_a_reader(screening, crate::certificate::read_enabled()?),
        "SOLVER_CONNECTOR_SCREENING needs SOLVER_CERTIFICATE=1: the dual pass is what \
         reads screened state, so with it off the reads are paid for and discarded"
    );
    ensure!(
        ranked_setting_admitted(read_ranked_connectors()?, mode),
        "SOLVER_RANKED_CONNECTORS needs SOLVER_DYNAMIC_CONNECTORS=shadow or adjacency: \
         profile_only never asks for a connector at all"
    );
    ensure!(
        admission_setting_admitted(read_connector_admission()?, mode),
        "SOLVER_CONNECTOR_ADMISSION needs SOLVER_DYNAMIC_CONNECTORS=adjacency: under \
         profile_only there is no shortlist to reorder, and under shadow the shortlist \
         never becomes routable, so admission could not reach a quote either way"
    );
    let _: u64 = read_connector_min_bps_e4()?;
    if let Some(logs_url) = logs_url {
        logs_url
            .parse::<reqwest::Url>()
            .context("SOLVER_LOGS_RPC is invalid")?;
    }
    Ok(())
}

/// The tick-bitmap window each side of a pool's current word, as every
/// snapshot reads it.
pub fn bitmap_words() -> anyhow::Result<u16> {
    u16::try_from(*BITMAP_WORDS)
        .ok()
        .filter(|&words| words <= 8192) // keeps every window word inside int16
        .context("SOLVER_BITMAP_WORDS out of range")
}
