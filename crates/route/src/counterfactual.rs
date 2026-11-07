//! What the connectors the pair budget declined would actually have been worth.
//!
//! The screening bound answers this by upper-bounding it: it prices each
//! screened pool's arbitrage value at a relaxed dual point and sums. That number
//! is valid for every ν ≥ 0 and, on BSC, loose by four to nine orders of
//! magnitude — `arb ≈ ½·TVL·(√κ−1)²` for a token mispriced by κ, against a true
//! value that is O(amount_in). The looseness therefore scales as TVL/amount and
//! no choice of ν repairs it, because the two quantities have different
//! dimensions. The unpublished dynamic-connectors notes (§11) derive this and
//! close the derivation against production to 0.09%.
//!
//! So this module measures instead of bounding. `V(S)` is the best output
//! reachable using pool set `S`; the coverage question is
//! `V(U ∪ screened) − V(U)`, and the same allocator that produced the served
//! quote computes both sides. The result is exact, carries no relaxation, and
//! cannot overflow a report.
//!
//! Three properties do the work:
//!
//! - **Monotone.** `S ⊆ S′ ⟹ V(S) ≤ V(S′)`, since surplus pools can go unused.
//!   So the widened solve dominates every subset, and a total gain of zero
//!   PROVES no subset of these connectors helps at this size. That is the
//!   "provably worthless" verdict, reached in one solve.
//! - **Attribution is free.** The widened plan names the pools it used, so the
//!   connectors that carried value are read off its hops. No separate scoring
//!   pass, and nothing to get out of step with the plan.
//! - **Leave-one-out is small.** Marginals are only meaningful for connectors
//!   the plan actually chose — typically one to three against the ranking's ten
//!   to twenty-nine — so the extra solves scale with what was used.
//!
//! # Why nothing here returns a `Plan`
//!
//! Screened pools are kept unroutable twice over: out of `Snapshot`, so every
//! router entry point structurally excludes them, and out of
//! `RouteUniverse::token_paths`, so no edge is built for them. Measuring their
//! worth means deliberately undoing both, which makes this the one place in the
//! solver where a screened pool can appear in a route.
//!
//! The containment is that the resulting `Plan` never leaves this module. The
//! public surface hands back `U256` amounts and connector addresses, so there is
//! no shadow plan for any caller to certify, quantize or encode. The shadow
//! snapshot also carries `settler: None`, so a plan that escaped anyway would
//! fail transaction encoding rather than produce calldata.

use crate::budget::SolverBudget;
use crate::route::{Plan, PreparedRoutes};
use crate::snapshot::{ScreeningPools, Snapshot};
use crate::universe::RouteUniverse;
use alloy_primitives::{Address, B256, U256, keccak256};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Domain tag keeping a shadow universe id away from any real fingerprint, so a
/// plan built here cannot be mistaken for one built over a served universe.
const SHADOW_DOMAIN: &[u8] = b"swap-solver/counterfactual/v1";

/// SOLVER_COVERAGE_TTL: seconds a measured verdict keeps answering for.
///
/// The measurement costs 112–721 ms in production against a warm quote's ~2 ms
/// (docs §13), so charging every request for it would spend the whole latency
/// budget several times over. It is amortized instead — measured once per
/// universe per size band, reused until this expires. `0` measures on every
/// quote, which is what the diagnostic did before this existed and what a size
/// ladder wants.
///
/// The default matches `SOLVER_TOPO_TTL` deliberately. Connector selection is a
/// once-per-topology-lease decision, so a verdict outliving its lease would
/// speak for a shortlist the topology has already replaced.
static COVERAGE_TTL: LazyLock<u64> =
    LazyLock::new(|| read_coverage_ttl().unwrap_or_else(|error| panic!("{error:#}")));

/// Readable before the lazy is forced, so `validate_settings` can reject a bad
/// value at startup instead of panicking under the first quote that needs it.
pub fn read_coverage_ttl() -> anyhow::Result<u64> {
    match std::env::var("SOLVER_COVERAGE_TTL") {
        Ok(value) => value
            .parse()
            .map_err(|error| anyhow::anyhow!("SOLVER_COVERAGE_TTL={value:?} is invalid: {error}")),
        Err(std::env::VarError::NotPresent) => Ok(600),
        Err(error) => Err(anyhow::anyhow!("reading SOLVER_COVERAGE_TTL: {error}")),
    }
}

const COVERAGE_CACHE_CAP: usize = 512;

/// The pair a verdict belongs to, and the size band it was measured at.
///
/// Deliberately WITHOUT the universe fingerprint, which lives in the entry
/// instead. Admission runs at universe *construction* and `fingerprint_universe`
/// hashes both `screening_pairs` and `connectors` — precisely the two lists
/// admission moves a token between — so a verdict filed under a fingerprint
/// could never be looked up at the moment admission needs it. Keying on the pair
/// makes the lookup possible; carrying the fingerprint in the value lets each
/// reader decide whether it cares (unpublished dynamic-connectors notes, §15).
type CoverageKey = (u64, Address, Address, u32);

/// The pair, without a band — what admission merges across.
type PairKey = (u64, Address, Address);

/// An entry carries its own lifetime rather than being swept against a
/// caller-supplied one. A sweep keyed on the reader's TTL would let one reader
/// evict entries written under a different one, which is a whole-cache effect
/// reached through a single-key lookup.
struct CoverageEntry {
    value: CoverageValue,
    /// The universe this was measured over. Reporting requires it to match,
    /// because `total_gain` is a statement about one specific universe and is
    /// meaningless attached to another. Admission ignores it, because a
    /// per-connector marginal is a statement about that connector — and a
    /// shortlist that just moved is exactly when the last measurement is worth
    /// having.
    fingerprint: B256,
    amount_in: U256,
    at: Instant,
    ttl: Duration,
}

impl CoverageEntry {
    /// Fresh enough to publish as this quote's own coverage.
    fn readable(&self) -> bool {
        self.at.elapsed() < self.ttl
    }

    /// Still worth keeping, and still worth admitting on.
    ///
    /// Twice the reporting horizon, because the two readers meet an entry at
    /// different ages by construction. Reporting reads it on the quote that
    /// measured it and on every quote until the TTL runs out. Admission reads
    /// it only when the topology rotates — and the verdict was filed a few
    /// hundred milliseconds *after* the topology it was measured over, so at
    /// one lifetime the entry is already gone by the time admission asks.
    ///
    /// Two lifetimes make the guarantee the threshold's documentation states:
    /// a verdict measured anywhere in one lease is readable throughout the
    /// next, and expires before it can answer for a third.
    fn retained(&self) -> bool {
        self.at.elapsed() < self.ttl.saturating_mul(2)
    }
}

/// The verdicts `coverage` measured, each kept for twice its TTL
/// (`CoverageEntry::retained`). The quote path files them, and connector
/// admission reads them back through `certified_admission` when discovery
/// builds the pair's next universe. The engine owns one and hands it to both,
/// so this flow from the quotes back into discovery shows in their signatures.
#[derive(Default)]
pub struct CoverageCache {
    entries: Mutex<HashMap<CoverageKey, CoverageEntry>>,
}

/// Binary magnitude of the trade.
///
/// A two-hop leg pays an extra LP fee, so a connector is worth nothing below
/// some size and grows above it (docs §11). Banding by binary magnitude keeps
/// that threshold inside one band instead of letting a verdict measured at one
/// size answer for every size.
fn size_bucket(amount_in: U256) -> u32 {
    amount_in.bit_len() as u32
}

/// A verdict, with enough provenance that a reader cannot mistake a reused one
/// for a fresh one.
#[derive(Clone, Debug)]
pub struct CoverageReading {
    pub value: CoverageValue,
    /// The `amount_in` this was measured at — this quote's own when `age` is
    /// zero, within a factor of two of it otherwise. The wei amounts in `value`
    /// belong to THIS size, not to the quote being served.
    pub measured_in: U256,
    /// How long ago it was measured. Zero when this quote measured it.
    pub age: Duration,
}

impl CoverageCache {
    /// `measure_coverage`, amortized over the topology lease.
    ///
    /// A hit returns the stored verdict; a miss measures and stores. Declining to
    /// answer is never stored: the cheap decline (nothing screened is reachable)
    /// costs almost nothing to re-derive, and the expensive one (a non-monotone
    /// solve) is a property of one allocator run rather than of the universe, so
    /// caching it would suppress measurement for a full lease off a single hiccup.
    #[allow(clippy::too_many_arguments)]
    pub fn coverage(
        &self,
        snap: &Snapshot,
        universe: &RouteUniverse,
        screening: &ScreeningPools,
        served: &Plan,
        loss_bound_bps_e4: U256,
        achieved: U256,
        amount_in: U256,
        chunks: u32,
        min_share_bps: u32,
        budget: &SolverBudget,
    ) -> anyhow::Result<Option<CoverageReading>> {
        let ttl = Duration::from_secs(*COVERAGE_TTL);
        let (token_in, token_out) = universe.endpoints();
        let fingerprint = universe.fingerprint();
        let key = (
            universe.chain_id(),
            token_in,
            token_out,
            size_bucket(amount_in),
        );
        // Reporting requires the fingerprint to match: a `total_gain` measured over
        // another universe describes connectors this shortlist may no longer offer.
        // A mismatch re-measures and overwrites, which is also what keeps the entry
        // admission reads from drifting behind the current topology.
        if !ttl.is_zero()
            && let Some(reading) = self.cached_coverage(key, fingerprint)
        {
            return Ok(Some(reading));
        }
        let Some(value) = measure_coverage(
            snap,
            universe,
            screening,
            served,
            loss_bound_bps_e4,
            achieved,
            amount_in,
            chunks,
            min_share_bps,
            budget,
        )?
        else {
            return Ok(None);
        };
        if !ttl.is_zero() {
            self.store_coverage(key, fingerprint, &value, amount_in, ttl);
        }
        Ok(Some(CoverageReading {
            value,
            measured_in: amount_in,
            age: Duration::ZERO,
        }))
    }
}

impl CoverageCache {
    fn cached_coverage(&self, key: CoverageKey, fingerprint: B256) -> Option<CoverageReading> {
        let mut cache = self.entries.lock().expect("coverage cache lock");
        cache.retain(|_, entry| entry.retained());
        cache
            .get(&key)
            .filter(|entry| entry.readable() && entry.fingerprint == fingerprint)
            .map(|entry| CoverageReading {
                value: entry.value.clone(),
                measured_in: entry.amount_in,
                age: entry.at.elapsed(),
            })
    }
}

/// Everything admission is allowed to act on for this pair, merged across every
/// live band and both directions (docs §22).
///
/// Reads across a fingerprint change on purpose — see `CoverageEntry` — and
/// across both orientations, because the engine keys its resident pair with
/// `canon`: one universe is built for the address-sorted ordering and serves
/// quotes in both directions, while verdicts are filed under the direction that
/// was quoted. Matching only the ordering admission is called with finds
/// nothing on every pair whose traffic runs against address order (§18).
///
/// Each field merges in the direction that costs a swap rather than licenses
/// one, which is §20's min-G / max-L asymmetry:
///
/// - `idle` INTERSECTS. A connector must have been idle in every band that
///   measured it; carrying flow at any size disqualifies it.
/// - `gains` take the MINIMUM. A candidate must clear the bound at every size
///   that measured it.
/// - `loss_bound_bps_e4` takes the MAXIMUM, so the bound a candidate must beat
///   is the loosest certificate any band produced.
#[derive(Clone, Debug, Default)]
pub struct AdmissionEvidence {
    pub idle: Vec<Address>,
    /// Each candidate's best verdict across the live size bands.
    ///
    /// The MAXIMUM, paired with the `bands` multiplier below. See
    /// `certified_admission` for why this is not the minimum, and what the
    /// change costs in guarantee.
    pub gains: HashMap<Address, U256>,
    pub loss_bound_bps_e4: U256,
    /// How many size bands contributed a verdict. One swap serves all of them,
    /// so this is what converts a per-band eviction cost into a total.
    pub bands: usize,
}

impl CoverageCache {
    /// Merge every live band's verdict for this pair into one admission decision.
    ///
    /// `idle` intersects and `loss_bound_bps_e4` takes the maximum: a connector is
    /// only free to lose if every band proved it idle, and the cost of losing it is
    /// the worst band's certified gap. Both are unchanged and both are the safe
    /// direction.
    ///
    /// `gains` takes the MAXIMUM, and that is a change from §20's minimum. The
    /// reason it had to change, and exactly what it costs:
    ///
    /// **Why the minimum closed the window.** One connector set serves every size,
    /// so §20 required a candidate to clear the bound in the worst band. But a
    /// two-hop connector is worth nothing below some size — it pays an extra LP fee
    /// (§11) — so any pair taking both small and large trades has a small-band
    /// verdict pricing every candidate at zero, and `min = 0` can never clear a
    /// positive bound. §25 measured the consequence: 181 of 181 declines, with
    /// USDC on WBNB→USDT worth 3.3269 bp at 3,000 and 0.2153 bp at 100, its merged
    /// value falling 7× the moment the 100-band entered retention. That is not
    /// conservatism about *when* to promote; it is a rule that cannot fire.
    ///
    /// **What replaces it.** Let `g_b` be the candidate's verdict in band `b` and
    /// `L` the worst band's certified eviction cost. Every `g_b ≥ 0`, because a
    /// marginal is a gain or an unused offer. So over the `|B|` live bands,
    /// `Σ_b (g_b − L) ≥ max_b g_b − |B|·L`,
    /// and `admit_by_certified_value` requires `max_b g_b > |B|·L`. **Even if the
    /// candidate delivers nothing in every band but one, and the eviction costs
    /// its full certified bound in every band, the swap is still ahead.** No
    /// incumbent is compared against a candidate anywhere in that argument — the
    /// property §19 cost 142 bp to learn — and `L` still carries the churn floor
    /// `state.rs` folds into it.
    ///
    /// **What it costs, stated plainly.** The minimum guaranteed no band could be
    /// worse off. This guarantees the bands are not worse off *in total*, which is
    /// weaker: a single small-band quote can lose up to `L` so that large ones
    /// gain. `L` is what makes that trade defensible rather than a guess — §25
    /// measured it at 0.0000 on five of seven pairs and 0.3529 at its worst, against
    /// gains of 20 to 790 bp. The rule forfeits a bounded, certified, sub-basis-point
    /// amount at one size to win two to three orders of magnitude more at another.
    pub fn certified_admission(
        &self,
        chain_id: u64,
        token_in: Address,
        token_out: Address,
    ) -> AdmissionEvidence {
        let quoted: PairKey = (chain_id, token_in, token_out);
        let reversed: PairKey = (chain_id, token_out, token_in);
        let mut cache = self.entries.lock().expect("coverage cache lock");
        cache.retain(|_, entry| entry.retained());

        let mut evidence = AdmissionEvidence::default();
        let mut idle: Option<Vec<Address>> = None;
        for (key, entry) in cache.iter() {
            let pair = (key.0, key.1, key.2);
            if pair != quoted && pair != reversed {
                continue;
            }
            evidence.loss_bound_bps_e4 = evidence
                .loss_bound_bps_e4
                .max(entry.value.loss_bound_bps_e4);
            idle = Some(match idle {
                None => entry.value.idle.clone(),
                Some(seen) => seen
                    .into_iter()
                    .filter(|connector| entry.value.idle.contains(connector))
                    .collect(),
            });
            // This band's own verdict, assembled before it meets the others. A
            // candidate OFFERED to a measurement and left unused is worth zero at
            // that size, and that is a verdict; one the widened plan routed carries
            // its marginal. Assembling per band first keeps a zero attributable to
            // the band that produced it rather than to the candidate.
            let mut band: HashMap<Address, U256> = HashMap::new();
            for connector in &entry.value.offered {
                band.insert(*connector, U256::ZERO);
            }
            for marginal in &entry.value.marginals {
                band.insert(marginal.connector, marginal.marginal_bps_e4);
            }
            for (connector, gain) in band {
                evidence
                    .gains
                    .entry(connector)
                    .and_modify(|slot| *slot = (*slot).max(gain))
                    .or_insert(gain);
            }
            evidence.bands += 1;
        }
        evidence.idle = idle.unwrap_or_default();
        evidence
    }
}

/// Give a slot held by a PROVEN-IDLE connector to a candidate whose measured
/// marginal beats the certified cost of taking it (docs §22).
///
/// The whole rule, and every term in it is already published per quote:
///
/// > `a` routed no flow, so `V(A−a) ≥ achieved`; the certificate gives
/// > `V(A) ≤ bound`; so evicting `a` costs at most `bound − achieved`. A
/// > candidate measured above that leaves the universe strictly better.
///
/// It replaces R2's three-tier ordering, which compared a candidate's marginal
/// against no measurement of the incumbent at all and cost 142 bp the first
/// time it acted (§19). Nothing here compares an incumbent with a candidate:
/// the incumbents it touches have been proven free, and the only comparison is
/// between a candidate and a certificate.
///
/// Evicting SEVERAL idle connectors at once is equally sound — the served plan
/// touches none of them, so it stays feasible without all of them — and one
/// promoted candidate clearing the bound carries the whole swap, because
/// monotonicity makes the others free.
///
/// Returns the shortlist reordered so its first `admitted` entries are the new
/// routable set, which is exactly how `connector_selection` derives one.
///
/// `churn_floor_bps_e4` is applied to the TOTAL rather than to the per-band
/// bound, and the difference is not cosmetic. Folding it in before the band
/// multiplier would make a 1 bp floor mean 3 bp on a pair with three live
/// bands — scaling a churn-suppression policy by how many sizes happen to be
/// in retention, which is a property of recent traffic and nothing to do with
/// how much rewriting a route is worth avoiding. Soundness comes from the
/// certified term; this only sets how large a proven gain has to be before it
/// is worth acting on.
pub fn admit_by_certified_value(
    screened: &[Address],
    admitted: usize,
    evidence: &AdmissionEvidence,
    churn_floor_bps_e4: U256,
) -> Vec<Address> {
    let admitted = admitted.min(screened.len());
    let (incumbents, rest) = screened.split_at(admitted);

    // Free to lose, lowest-ranked first: those disturb the ranking least.
    let mut free: Vec<Address> = incumbents
        .iter()
        .copied()
        .filter(|connector| evidence.idle.contains(connector))
        .collect();
    free.reverse();
    if free.is_empty() {
        return screened.to_vec();
    }

    // What one swap can cost across every band it will serve: the certified
    // eviction bound, taken at its worst band and charged once per band. See
    // the note on `certified_admission` for why the comparison is against this
    // total rather than against the bound alone.
    let total_cost = evidence
        .loss_bound_bps_e4
        .saturating_mul(U256::from(evidence.bands.max(1)))
        .max(churn_floor_bps_e4);

    let mut proven: Vec<(U256, usize, Address)> = rest
        .iter()
        .enumerate()
        .filter_map(|(offset, &connector)| {
            evidence
                .gains
                .get(&connector)
                .filter(|gain| **gain > total_cost)
                .map(|gain| (*gain, offset, connector))
        })
        .collect();
    proven.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    proven.truncate(free.len());
    if proven.is_empty() {
        return screened.to_vec();
    }

    free.truncate(proven.len());
    let promoted: Vec<Address> = proven
        .into_iter()
        .map(|(_, _, connector)| connector)
        .collect();
    let mut head: Vec<Address> = incumbents
        .iter()
        .copied()
        .filter(|connector| !free.contains(connector))
        .collect();
    head.extend(promoted);

    let mut reordered = head.clone();
    reordered.extend(
        screened
            .iter()
            .copied()
            .filter(|connector| !head.contains(connector)),
    );
    reordered
}

impl CoverageCache {
    fn store_coverage(
        &self,
        key: CoverageKey,
        fingerprint: B256,
        value: &CoverageValue,
        amount_in: U256,
        ttl: Duration,
    ) {
        let mut cache = self.entries.lock().expect("coverage cache lock");
        cache.retain(|_, entry| entry.retained());
        if !cache.contains_key(&key)
            && cache.len() >= COVERAGE_CACHE_CAP
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(key, entry)| (entry.at, **key))
                .map(|(key, _)| *key)
        {
            cache.remove(&oldest);
        }
        cache.insert(
            key,
            CoverageEntry {
                value: value.clone(),
                fingerprint,
                amount_in,
                at: Instant::now(),
                ttl,
            },
        );
    }
}

#[cfg(test)]
impl CoverageCache {
    /// File a verdict as though it had been measured `age` ago.
    ///
    /// Admission reads at topology rotation, one whole lease after the verdict was
    /// written, so every question about its horizon is a question about an old
    /// entry. Real time does not run backwards, so the test places the entry where
    /// the question is.
    fn store_coverage_aged(
        &self,
        key: CoverageKey,
        fingerprint: B256,
        value: &CoverageValue,
        amount_in: U256,
        ttl: Duration,
        age: Duration,
    ) {
        let mut cache = self.entries.lock().expect("coverage cache lock");
        cache.insert(
            key,
            CoverageEntry {
                value: value.clone(),
                fingerprint,
                amount_in,
                at: Instant::now()
                    .checked_sub(age)
                    .expect("test clock predates the process"),
                ttl,
            },
        );
    }
}

/// What removing one connector from the widened universe costs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorMarginal {
    pub connector: Address,
    /// `V(U ∪ all) − V(U ∪ all ∖ {connector})`, saturating at zero.
    ///
    /// Measured against the widened universe rather than against `U`, so
    /// substitutable connectors do not each claim the same gain. A connector
    /// the widened plan used can still show zero here when another covers for
    /// it exactly.
    ///
    /// Saturation is deliberate and one-sided here: monotonicity says a subset
    /// cannot beat the widened set, so a heuristic that lands the other way
    /// under-credits the connector rather than inventing value for it.
    pub marginal_out: U256,
    /// `marginal_out` over the achieved output, in basis points × 10⁴.
    ///
    /// This is the field to compare and to threshold against. `marginal_out` is
    /// an absolute wei amount at ONE size, so it cannot be compared across pairs
    /// with different output tokens, across size bands, or against the amount a
    /// reusing quote is serving. The ratio survives all three.
    pub marginal_bps_e4: U256,
}

/// The coverage question, answered by measurement.
///
/// Deliberately NOT `Default`. A zero `total_gain` is the PROOF that no screened
/// connector improves the quote, so a constructor that materializes one by
/// accident publishes a proof nothing measured — which is how the defect
/// `1455cd7` fixed came to ship. Tests that need a placeholder use
/// `CoverageValue::placeholder`, which is `#[cfg(test)]` and named to say so.
#[derive(Clone, Debug)]
pub struct CoverageValue {
    /// `V(U ∪ all)` — what the widened universe delivers.
    pub widened_out: U256,
    /// `V(U ∪ all) − V(U)`, both sides solved by this module at one setting.
    /// Zero PROVES that no subset of the screened connectors improves this
    /// quote at this size, by monotonicity — for as long as the allocator is
    /// monotone, which the unpublished allocator-monotonicity notes (§6) show is
    /// a weaker footing than a dual bound would be.
    ///
    /// Never saturates: a widened solve that came out below the base one has
    /// lost the monotonicity the proof rests on, and `measure_coverage` reports
    /// absence for it rather than a zero.
    pub total_gain: U256,
    /// `total_gain` over the achieved output, in basis points × 10⁴.
    ///
    /// The reuse-safe form of the verdict, and the one to threshold against.
    /// The wei fields above are absolute amounts at ONE size: a verdict reused
    /// for a larger quote in the same band publishes a `widened_out` BELOW that
    /// quote's own output, since a band spans a factor of two and the served
    /// output scales with it. That reads as the widened universe losing to a
    /// subset of itself, which monotonicity forbids and which the ratio simply
    /// does not express.
    pub gain_bps_e4: U256,
    /// `B(U ∪ all)` — a dual upper bound on what ANY plan over the widened
    /// universe could deliver, tightened over that universe's own pools.
    ///
    /// Absent when the bound could not be evaluated, which leaves the two
    /// fields below absent with it.
    pub widened_bound: Option<U256>,
    /// `B(U ∪ all) − achieved`, in bps × 10⁴ of `achieved`, saturating.
    ///
    /// The certified ceiling on coverage regret: no plan over the widened
    /// universe beats the served quote by more than this.
    ///
    /// **A value under the churn floor retires the whole candidate set, and it
    /// does so whatever the allocator did.** `gain_bps_e4`'s zero says the
    /// allocator found nothing over there; this says nothing is there. It needs
    /// only the served plan's own output and a valid dual, so it survives the
    /// non-monotone case the guard exists for.
    pub regret_bound_bps_e4: Option<U256>,
    /// `B(U ∪ all) − widened_out`, in bps × 10⁴ of `achieved`.
    ///
    /// The widened solve's own optimality gap: how much of the measurement's
    /// silence could be the instrument rather than the answer. Read `gain` next
    /// to it — a gain smaller than this gap is inside the noise.
    pub widened_gap_bps_e4: Option<U256>,
    /// Every connector this measurement considered — the screened set minus
    /// anything already routable.
    ///
    /// Retained so a reader can tell "offered and worth nothing" from "never
    /// measured". Only the first is a verdict; admission must not treat the
    /// second as one, since a connector nothing has measured may still be the
    /// valuable one.
    pub offered: Vec<Address>,
    /// Connectors the widened plan routed through, in the ranking's order.
    pub used: Vec<Address>,
    /// Leave-one-out marginals for `used`, richest first.
    pub marginals: Vec<ConnectorMarginal>,
    /// What dropping each ALREADY-ROUTABLE dynamic connector would cost —
    /// `V(A) − V(A − a)` — costliest first (docs §20).
    ///
    /// The other half of the swap decision, and the half R2 never had. A
    /// `marginals` entry says what ADDING a candidate is worth over a universe
    /// that already routes these; only an entry here says what losing one of
    /// these costs. Comparing the two is the whole point, which is why both
    /// report against `achieved`.
    ///
    /// An incumbent is ABSENT when its reading lost monotonicity, and absent
    /// must mean unevictable. Publishing a zero there would read as free to
    /// evict, which is the direction that cost 142 bp (§19).
    pub incumbents: Vec<ConnectorMarginal>,
    /// Admitted dynamic connectors the SERVED plan routed no flow through
    /// (docs §22).
    ///
    /// Evicting one of these costs at most `loss_bound_bps_e4`, and the proof is
    /// three lines: the served plan never touches such a connector, so it stays
    /// feasible without it, so `V(A−a) ≥ achieved`; the certificate gives
    /// `V(A) ≤ bound`; therefore `L(a) ≤ bound − achieved`.
    ///
    /// This costs nothing to compute — it reads the plan the quote already
    /// produced — and it is the only admission evidence that does not depend on
    /// the allocator being optimal.
    pub idle: Vec<Address>,
    /// The certified optimality gap at measurement time, in basis points × 10⁴
    /// of `achieved` — the same denominator as `gain_bps_e4` and every
    /// `marginal_bps_e4`.
    ///
    /// The upper bound on what evicting any `idle` connector can cost, which
    /// makes it the number a candidate's marginal must beat to earn that slot.
    pub loss_bound_bps_e4: U256,
    /// Solves performed, so the cost of the diagnostic is observable rather
    /// than inferred from the connector count.
    pub solves: usize,
    /// The served plan beat the allocator's own solve over the served universe.
    ///
    /// Nonzero on 6 of 16 cells in the section-34 window, by up to 3.9105 bp,
    /// before seeding removed it. It stays published because it prices the
    /// resolution difference between a served quote that may have escalated and
    /// a measurement that never does — a quantity worth watching rather than
    /// silently absorbing.
    pub base_seeded: bool,
    /// The widened solve came out BELOW the served universe's own plan, and the
    /// seed carried the measurement.
    ///
    /// **A `true` here disarms this verdict's zero.** `gain_bps_e4 == 0` normally
    /// says the allocator searched the wider universe and found nothing; with
    /// this set it says the allocator did worse over the wider universe and was
    /// rescued. `regret_bound_bps_e4` is the reading to trust in that case,
    /// because it does not depend on the allocator at all.
    pub widened_seeded: bool,
}

#[cfg(test)]
impl CoverageValue {
    /// A stand-in for cache tests, which exercise identity, lifetime and
    /// eviction rather than any verdict. Named for what it is: the zeros here
    /// are placeholders, and reading one as a proof is the confusion the
    /// missing `Default` exists to prevent.
    pub fn placeholder() -> Self {
        Self {
            widened_out: U256::ZERO,
            total_gain: U256::ZERO,
            gain_bps_e4: U256::ZERO,
            widened_bound: None,
            regret_bound_bps_e4: None,
            widened_gap_bps_e4: None,
            offered: Vec::new(),
            incumbents: Vec::new(),
            idle: Vec::new(),
            loss_bound_bps_e4: U256::ZERO,
            used: Vec::new(),
            marginals: Vec::new(),
            solves: 0,
            base_seeded: false,
            widened_seeded: false,
        }
    }
}

/// Measure `V(U ∪ screened) − V(U)` and attribute it.
///
/// `achieved` is the served quote's own output. It is the denominator every
/// ratio reports against, so a gain, an incumbent's loss and the certified loss
/// bound all land on one scale. Both sides of the subtraction itself are solved
/// here, at the settings this call was given.
#[allow(clippy::too_many_arguments)]
pub fn measure_coverage(
    snap: &Snapshot,
    universe: &RouteUniverse,
    screening: &ScreeningPools,
    served: &Plan,
    loss_bound_bps_e4: U256,
    achieved: U256,
    amount_in: U256,
    chunks: u32,
    min_share_bps: u32,
    budget: &SolverBudget,
) -> anyhow::Result<Option<CoverageValue>> {
    let (token_in, token_out) = universe.endpoints();
    let base_paths = universe.token_paths().to_vec();

    // A connector the served universe already routes through carries value that
    // is inside `achieved` already, and crediting it would attribute a gain its
    // screened pools never produced. `priced_beyond_universe` should exclude
    // these — a connector reachable on both legs contributes no screening pair —
    // but attribution reads tokens off hops, so it would mis-credit if that ever
    // stopped holding. Filtering here makes the reading correct without
    // depending on the invariant.
    let connectors: Vec<Address> = universe
        .priced_beyond_universe()
        .into_iter()
        .filter(|connector| !base_paths.iter().any(|path| path.contains(connector)))
        .collect();
    if connectors.is_empty() || screening.is_empty() {
        // Nothing to measure. Distinct from a measured zero, which is a proof
        // that no connector helps — so this reports absence, not a value.
        return Ok(None);
    }
    budget.checkpoint("counterfactual preparation")?;

    // `V(U)`, recomputed here rather than taken from `achieved`.
    //
    // The served quote may have been re-solved at the escalated resolution
    // (`quotes.rs`), and the widened solve below always runs at the resolution
    // this call was given. Subtracting a 256/50 widened output from a 4096/0
    // served one prices that resolution difference as coverage, with the sign
    // that fires the guard — see the unpublished allocator-monotonicity notes, §5.
    // Solving the served universe's own paths on the same allocator at the same
    // settings puts both sides of `V(U ∪ S) − V(U)` on one instrument, which is
    // the choice `measure_incumbents` already makes for the same reason.
    //
    // Over `snap` rather than the shadow snapshot, so a screened pool joining
    // two base tokens cannot inflate the side being subtracted.
    // Seeded with the served plan, which is feasible over `base_paths` because
    // it was built from them. Without it `base` can land BELOW `achieved` — the
    // window measured that on 6 of 16 cells, up to 3.9105 bp — and every gain is
    // then quoted against a baseline the quote itself already beat (docs §35.4).
    let (Some(base), base_seeded) = solve_shadow_seeded(
        snap,
        &base_paths,
        shadow_id(universe, None),
        amount_in,
        chunks,
        min_share_bps,
        Some(served),
        budget,
    )?
    else {
        // The served universe's own paths found no route at this resolution, so
        // there is nothing to measure a gain against. Absence, not a zero.
        return Ok(None);
    };
    let base_out = base.amount_out;
    let mut solves = 1usize;

    let shadow = shadow_snapshot(snap, screening);
    let widened_paths = paths_with(&base_paths, token_in, token_out, &connectors, None);
    // Seeded with `base`, whose hops index into `snap` and stay valid because
    // `shadow_snapshot` APPENDS. This is what makes `widened >= base` structural
    // rather than hoped for, so `total_gain` can no longer be negative and the
    // guard below can no longer fire.
    let (Some(widened), widened_seeded) = solve_shadow_seeded(
        &shadow,
        &widened_paths,
        shadow_id(universe, None),
        amount_in,
        chunks,
        min_share_bps,
        Some(&base),
        budget,
    )?
    else {
        // The widened universe found no route at all, despite containing every
        // path the served universe had. The served quote therefore came from
        // somewhere this measurement cannot reproduce, so report absence.
        return Ok(None);
    };
    solves += 1;
    let widened_out = widened.amount_out;

    // Before the guard, so a widened solve that lost monotonicity still says
    // what it could not have been hiding.
    let bound = match widened_bound(
        &shadow,
        &widened_paths,
        &widened,
        token_in,
        token_out,
        amount_in,
        budget,
    ) {
        Ok(bound) => Some(bound),
        Err(error)
            if error
                .downcast_ref::<crate::budget::SolverBudgetExceeded>()
                .is_some() =>
        {
            return Err(error);
        }
        Err(error) => {
            println!("coverage bound unavailable: {error:#}");
            None
        }
    };

    // Monotonicity is what makes a zero a proof: the widened pool set contains
    // the base one, so it cannot deliver less. The allocator is a chunked
    // heuristic though, and a larger candidate set can send it somewhere worse.
    // When that happens the guarantee is gone for this quote, and saturating the
    // subtraction would publish `0` — the proof — off the back of a regression.
    // Report absence and say so.
    //
    // Against `base_out`, so what remains here is allocator non-monotonicity
    // alone rather than the resolution gap the served plan may carry.
    if widened_out < base_out {
        // Unreachable while the widened solve is seeded with `base`: the seed is
        // one of the candidates, so the winner is at least as good as it. Kept as
        // a backstop, because the way this could come back is a snapshot whose
        // pool indices moved under a seeded plan, and that is worth an alarm
        // rather than a silently wrong subtraction.
        println!(
            "coverage non-monotone: widened {widened_out} below base {base_out}, \
             {} connectors, bound {}",
            connectors.len(),
            bound.map(|bound| bound.to_string()).unwrap_or("-".into())
        );
        return Ok(None);
    }

    // What the guard used to print, kept now that it cannot fire. A seeded
    // widened solve means the allocator did WORSE over the larger universe and
    // the seed carried the measurement — so this verdict's zero says the
    // allocator found nothing, never that nothing is there. Reading a seeded
    // zero as a proof is the failure fix C was warned to avoid.
    if base_seeded || widened_seeded {
        println!(
            "coverage seeded: base {base_seeded} widened {widened_seeded}, \
             {} connectors, base {base_out}, widened {widened_out}",
            connectors.len()
        );
    }

    let used = connectors_used(&widened, &connectors);

    let mut marginals = Vec::with_capacity(used.len());
    for &connector in &used {
        budget.checkpoint("counterfactual leave-one-out")?;
        let without = paths_with(
            &base_paths,
            token_in,
            token_out,
            &connectors,
            Some(connector),
        );
        let reduced = solve_shadow(
            &shadow,
            &without,
            shadow_id(universe, Some(connector)),
            amount_in,
            chunks,
            min_share_bps,
            budget,
        )?;
        solves += 1;
        // A universe that loses every route when one connector is dropped
        // credits that connector with the whole widened output.
        let reduced_out = reduced.map(|plan| plan.amount_out).unwrap_or(U256::ZERO);
        let marginal_out = widened_out.saturating_sub(reduced_out);
        marginals.push(ConnectorMarginal {
            connector,
            marginal_out,
            // Against `achieved`, the same denominator as `gain_bps_e4`, so a
            // connector's share and the total it belongs to are one scale.
            marginal_bps_e4: crate::certificate::ratio_bps_e4(marginal_out, achieved)?,
        });
    }
    marginals.sort_by(|a, b| {
        b.marginal_out
            .cmp(&a.marginal_out)
            .then_with(|| a.connector.cmp(&b.connector))
    });

    // Which admitted connectors the SERVED plan left alone. Free: it reads the
    // plan this quote already produced (docs §22).
    let routable = routable_dynamic_connectors(universe, &base_paths);
    let carrying = connectors_used(served, &routable);
    let idle: Vec<Address> = routable
        .iter()
        .copied()
        .filter(|connector| !carrying.contains(connector))
        .collect();

    let (incumbents, incumbent_solves) = measure_incumbents(
        snap,
        universe,
        &base_paths,
        &routable,
        base_out,
        achieved,
        amount_in,
        chunks,
        min_share_bps,
        budget,
    )?;
    solves += incumbent_solves;

    // Never saturates: the non-monotone case returned above.
    let total_gain = widened_out - base_out;
    let regret_bound_bps_e4 = bound
        .map(|bound| crate::certificate::ratio_bps_e4(bound.saturating_sub(achieved), achieved))
        .transpose()?;
    let widened_gap_bps_e4 = bound
        .map(|bound| crate::certificate::ratio_bps_e4(bound.saturating_sub(widened_out), achieved))
        .transpose()?;
    Ok(Some(CoverageValue {
        widened_out,
        total_gain,
        gain_bps_e4: crate::certificate::ratio_bps_e4(total_gain, achieved)?,
        widened_bound: bound,
        regret_bound_bps_e4,
        widened_gap_bps_e4,
        offered: connectors.clone(),
        used,
        marginals,
        incumbents,
        idle,
        loss_bound_bps_e4,
        solves,
        base_seeded,
        widened_seeded,
    }))
}

/// What dropping one ALREADY-ROUTABLE connector would cost — `V(A) − V(A − a)`
/// (docs §20).
///
/// The symmetric half of the leave-one-out above, and the quantity a swap
/// decision actually needs. A candidate's marginal is measured over a universe
/// that already routes the incumbents, so it states what ADDING that candidate
/// is worth and can never state whether it beats one of them. §19 measured what
/// deciding without this costs: 142 bp.
///
/// Three choices decide whether the number means anything.
///
/// It solves over `snap` rather than the shadow snapshot, because the shadow
/// carries screening pools that could serve a surviving base path and inflate
/// the reduced side — which would understate the loss, in the direction that
/// evicts.
///
/// It measures against a recomputed `V(A)` instead of against `achieved`. The
/// non-monotone guard above exists because those two can disagree, and a loss
/// has to be the difference of two like computations. `measure_coverage` solves
/// that baseline once and hands it down.
///
/// It reports against `achieved`, the denominator `gain_bps_e4` and
/// `marginal_bps_e4` already use, so a candidate's gain and an incumbent's loss
/// land on one scale. Comparing across two denominators is §17's mistake.
#[allow(clippy::too_many_arguments)]
/// The shortlist entries this universe actually routes: the connectors
/// admission holds a slot for, and the only ones it can evict.
///
/// The shortlist minus the part screening prices beyond the universe, minus
/// anything no base path names. Static profile connectors are deliberately
/// outside it — admission cannot move them, so their loss is not a decision
/// anyone can act on.
fn routable_dynamic_connectors(
    universe: &RouteUniverse,
    base_paths: &[Vec<Address>],
) -> Vec<Address> {
    let beyond = universe.priced_beyond_universe();
    universe
        .screened()
        .iter()
        .copied()
        .filter(|connector| !beyond.contains(connector))
        .filter(|connector| base_paths.iter().any(|path| path.contains(connector)))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn measure_incumbents(
    snap: &Snapshot,
    universe: &RouteUniverse,
    base_paths: &[Vec<Address>],
    incumbents: &[Address],
    base_out: U256,
    achieved: U256,
    amount_in: U256,
    chunks: u32,
    min_share_bps: u32,
    budget: &SolverBudget,
) -> anyhow::Result<(Vec<ConnectorMarginal>, usize)> {
    if incumbents.is_empty() {
        return Ok((Vec::new(), 0));
    }
    budget.checkpoint("incumbent preparation")?;

    let mut solves = 0usize;
    let mut losses = Vec::with_capacity(incumbents.len());
    for &incumbent in incumbents {
        budget.checkpoint("incumbent leave-one-out")?;
        let without: Vec<Vec<Address>> = base_paths
            .iter()
            .filter(|path| !path.contains(&incumbent))
            .cloned()
            .collect();
        let reduced = solve_shadow(
            snap,
            &without,
            shadow_id(universe, Some(incumbent)),
            amount_in,
            chunks,
            min_share_bps,
            budget,
        )?;
        solves += 1;
        // Dropping a connector cannot raise the optimum, so a strictly larger
        // reduced output is allocator error rather than a reading. Saturating
        // it would publish a zero loss, which reads as "free to evict" — the
        // one direction that costs 142 bp (§19, §20). Omit it instead, and let
        // an incumbent with no reading stay unevictable.
        let reduced_out = reduced.map(|plan| plan.amount_out).unwrap_or(U256::ZERO);
        if reduced_out > base_out {
            println!(
                "incumbent non-monotone: without {incumbent:#x} {reduced_out} \
                 above base {base_out}"
            );
            continue;
        }
        let loss = base_out - reduced_out;
        losses.push(ConnectorMarginal {
            connector: incumbent,
            marginal_out: loss,
            marginal_bps_e4: crate::certificate::ratio_bps_e4(loss, achieved)?,
        });
    }
    losses.sort_by(|left, right| {
        right
            .marginal_out
            .cmp(&left.marginal_out)
            .then_with(|| left.connector.cmp(&right.connector))
    });
    Ok((losses, solves))
}

/// `Snapshot` plus the screened pools, with execution identity removed.
///
/// Dropping `settler` is defence in depth: this snapshot exists to be routed
/// over and never to be executed, and transaction encoding requires a nonzero
/// identity, so a plan built here fails to encode even if one escaped.
fn shadow_snapshot(snap: &Snapshot, screening: &ScreeningPools) -> Snapshot {
    let mut v3 = snap.v3.clone();
    let mut v2 = snap.v2.clone();
    v3.extend(screening.v3.iter().cloned());
    v2.extend(screening.v2.iter().cloned());
    Snapshot {
        block: snap.block,
        settler: None,
        v3,
        v2,
        ekubo: snap.ekubo.clone(),
    }
}

/// The served universe's paths, plus a two-hop skeleton per connector.
///
/// `exclude` drops one connector's skeleton for the leave-one-out pass. Its
/// pools stay in the shadow snapshot and become unreachable, because an edge is
/// only built for a token pair some path names.
fn paths_with(
    base: &[Vec<Address>],
    token_in: Address,
    token_out: Address,
    connectors: &[Address],
    exclude: Option<Address>,
) -> Vec<Vec<Address>> {
    let mut paths = base.to_vec();
    paths.extend(
        connectors
            .iter()
            .copied()
            .filter(|connector| Some(*connector) != exclude)
            .map(|connector| vec![token_in, connector, token_out]),
    );
    paths
}

fn shadow_id(universe: &RouteUniverse, excluded: Option<Address>) -> B256 {
    let mut preimage = Vec::with_capacity(SHADOW_DOMAIN.len() + 52);
    preimage.extend_from_slice(SHADOW_DOMAIN);
    preimage.extend_from_slice(universe.fingerprint().as_slice());
    if let Some(connector) = excluded {
        preimage.extend_from_slice(connector.as_slice());
    }
    keccak256(preimage)
}

/// Solve over `token_paths`, and keep `seed` if the allocator cannot beat it.
///
/// `seed` must be feasible in `shadow` — the caller passes a plan built over a
/// subset of the same snapshot, which `route::requantize_plan_in` documents the
/// index requirement for. The bool reports whether the seed won, which is the
/// signal the monotonicity guard used to print: once seeding makes a regression
/// impossible, the fact that one WOULD have happened is the thing worth keeping
/// (the unpublished allocator-monotonicity notes, §7 fix C, name this as the
/// danger of landing C at all).
#[allow(clippy::too_many_arguments)]
fn solve_shadow_seeded(
    shadow: &Snapshot,
    token_paths: &[Vec<Address>],
    universe_id: B256,
    amount_in: U256,
    chunks: u32,
    min_share_bps: u32,
    seed: Option<&Plan>,
    budget: &SolverBudget,
) -> anyhow::Result<(Option<Plan>, bool)> {
    let solved =
        PreparedRoutes::for_shadow_paths(shadow, token_paths, universe_id, budget.clone())?
            .try_solve_quantized(amount_in, chunks, min_share_bps)?;
    let Some(seed) = seed else {
        return Ok((solved, false));
    };
    let Some(seeded) =
        crate::route::requantize_plan_in(shadow, seed, amount_in, Some(universe_id), budget)?
    else {
        return Ok((solved, false));
    };
    match &solved {
        Some(plan) if plan.amount_out >= seeded.amount_out => Ok((solved, false)),
        _ => Ok((Some(seeded), true)),
    }
}

/// The unseeded solve, for the leave-one-out measurements.
///
/// A leave-one-out asks what the universe delivers WITHOUT a connector, so
/// seeding it with a plan that routes through that connector would answer a
/// different question. These stay honest by staying unseeded, and
/// `measure_incumbents` already rejects a reading that comes out above its
/// baseline rather than publishing it.
fn solve_shadow(
    shadow: &Snapshot,
    token_paths: &[Vec<Address>],
    universe_id: B256,
    amount_in: U256,
    chunks: u32,
    min_share_bps: u32,
    budget: &SolverBudget,
) -> anyhow::Result<Option<Plan>> {
    Ok(solve_shadow_seeded(
        shadow,
        token_paths,
        universe_id,
        amount_in,
        chunks,
        min_share_bps,
        None,
        budget,
    )?
    .0)
}

/// `B(U ∪ S)`: a dual upper bound on everything the widened universe could
/// deliver, tightened over that universe's own pools.
///
/// The one number this module produces that does not depend on the allocator.
/// Everything else here is a difference of two heuristic solves, so it inherits
/// the heuristic's error in both directions and states neither
/// (unpublished allocator-monotonicity notes, §1.3).
///
/// §11 measured `graph_gap_bps` between 45,380 and 1.4×10⁹ bps and concluded a
/// bound cannot answer the coverage question. That measurement belongs to a
/// different object: the whole catalog, priced at a dual tightened for the
/// SERVED scope, so every price disagreement among pools this trade will never
/// touch lands in it, and the connectors' own prices never move. The scope here
/// is the served universe plus the screened connectors, and the dual moves for
/// all of it — the same construction the served certificate already runs, over
/// a set that is larger by the pools being asked about.
fn widened_bound(
    shadow: &Snapshot,
    widened_paths: &[Vec<Address>],
    widened: &Plan,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    budget: &SolverBudget,
) -> anyhow::Result<U256> {
    use crate::certificate::{PoolSet, bound_at, dual_prices, tighten_with_solver_budget};
    budget.checkpoint("coverage bound")?;
    let states = crate::route::plan_states(shadow, widened)?;
    let routed = PoolSet::of(shadow, widened);
    let mut prices = dual_prices(shadow, token_out, &states, &routed)?;
    let scope = PoolSet::reachable_over_paths(shadow, widened_paths);
    let iterations = crate::certificate::tighten_budget();
    if iterations > 0 {
        tighten_with_solver_budget(
            shadow,
            token_in,
            token_out,
            amount_in,
            &mut prices,
            Some(&scope),
            &routed,
            iterations,
            budget,
        )?;
    }
    let (bound, _) = bound_at(shadow, token_in, amount_in, &prices, Some(&scope), &routed)?;
    Ok(bound)
}

/// Connectors appearing in the plan, in the ranking's order.
///
/// Read off the hops' own tokens rather than off pool indices, so attribution
/// stays correct however the shadow snapshot is laid out. A connector is never
/// an endpoint — `RouteUniverse` refuses that — so any appearance is an
/// intermediate hop.
fn connectors_used(plan: &Plan, connectors: &[Address]) -> Vec<Address> {
    let mut seen: Vec<Address> = Vec::new();
    for leg in &plan.legs {
        for hop in &leg.path {
            for token in [hop.token_in, hop.token_out] {
                if connectors.contains(&token) && !seen.contains(&token) {
                    seen.push(token);
                }
            }
        }
    }
    connectors
        .iter()
        .copied()
        .filter(|connector| seen.contains(connector))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ROBINHOOD_PROFILE, SLVR, USDG};
    use crate::pools::{V2Pool, V2Protocol, V2State};
    use crate::route::PreparedRoutes;
    use crate::topology::{
        CatalogFences, ConnectorSelection, ConnectorSelector, Protocol, V23Fence,
    };

    const CHUNKS: u32 = 256;
    const MIN_SHARE: u32 = 50;
    /// Long enough that no cache test can expire mid-run.
    const LEASE: Duration = Duration::from_secs(600);

    fn v2_pool(
        id: u8,
        token0: Address,
        token1: Address,
        reserve0: u128,
        reserve1: u128,
    ) -> (V2Pool, V2State) {
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: Address::repeat_byte(id),
                token0,
                token1,
                fee_bps: 30,
            },
            V2State {
                reserve0: U256::from(reserve0),
                reserve1: U256::from(reserve1),
            },
        )
    }

    /// One screened connector: its token, its inbound pool reserves and its
    /// outbound pool reserves.
    type ConnectorSpec = (Address, (u128, u128), (u128, u128));

    /// A profile-only universe over one direct pool, plus screened connectors
    /// whose pools sit outside the snapshot entirely — the production shape.
    fn fixture(
        connectors: &[ConnectorSpec],
    ) -> (RouteUniverse, Snapshot, ScreeningPools, U256, U256) {
        let (token_in, token_out) = (SLVR, USDG);
        let amount_in = U256::from(1_000_000u64);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: Vec::new(),
            v2: vec![v2_pool(
                1,
                token_in,
                token_out,
                1_000_000_000,
                1_000_000_000,
            )],
            ekubo: vec![],
        };
        let universe = RouteUniverse::profile_only_shadow_complete(
            &ROBINHOOD_PROFILE,
            token_in,
            token_out,
            ConnectorSelection {
                fences: CatalogFences {
                    v23: V23Fence {
                        seq: 1,
                        generation: 1,
                    },
                    v4: None,
                },
                protocols: vec![Protocol::UNIV2],
                connectors: Vec::new(),
                screened: connectors.iter().map(|(token, _, _)| *token).collect(),
                eligible_count: connectors.len(),
                shortlist_truncated: false,
                selector: ConnectorSelector::AdjacencyWalk,
            },
        )
        .expect("screened universe");
        let mut screening = ScreeningPools::default();
        for (index, (connector, inbound, outbound)) in connectors.iter().enumerate() {
            let base = 0x20 + (index as u8) * 2;
            screening
                .v2
                .push(v2_pool(base, token_in, *connector, inbound.0, inbound.1));
            screening.v2.push(v2_pool(
                base + 1,
                *connector,
                token_out,
                outbound.0,
                outbound.1,
            ));
        }
        let achieved = served_output(&snap, &universe, amount_in);
        (universe, snap, screening, amount_in, achieved)
    }

    /// §19's shape in miniature: one connector ALREADY routable through pools
    /// in the snapshot, and one screened candidate outside it.
    ///
    /// `fixture` cannot express this — it admits nothing, so every screened
    /// token is priced beyond the universe and there is no incumbent to lose.
    fn fixture_with_incumbent(
        incumbent: ConnectorSpec,
        candidate: ConnectorSpec,
    ) -> (RouteUniverse, Snapshot, ScreeningPools, U256, U256) {
        let (token_in, token_out) = (SLVR, USDG);
        let amount_in = U256::from(1_000_000u64);
        let (held, inbound, outbound) = incumbent;
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: Vec::new(),
            v2: vec![
                v2_pool(1, token_in, token_out, 1_000_000_000, 1_000_000_000),
                v2_pool(2, token_in, held, inbound.0, inbound.1),
                v2_pool(3, held, token_out, outbound.0, outbound.1),
            ],
            ekubo: vec![],
        };
        let universe = RouteUniverse::adjacency_complete(
            &ROBINHOOD_PROFILE,
            token_in,
            token_out,
            ConnectorSelection {
                fences: CatalogFences {
                    v23: V23Fence {
                        seq: 1,
                        generation: 1,
                    },
                    v4: None,
                },
                protocols: vec![Protocol::UNIV2],
                connectors: vec![held],
                screened: vec![held, candidate.0],
                eligible_count: 2,
                shortlist_truncated: false,
                selector: ConnectorSelector::AdjacencyWalk,
            },
        )
        .expect("universe with one admitted connector");
        let mut screening = ScreeningPools::default();
        screening.v2.push(v2_pool(
            0x40,
            token_in,
            candidate.0,
            candidate.1.0,
            candidate.1.1,
        ));
        screening.v2.push(v2_pool(
            0x41,
            candidate.0,
            token_out,
            candidate.2.0,
            candidate.2.1,
        ));
        let achieved = served_output(&snap, &universe, amount_in);
        (universe, snap, screening, amount_in, achieved)
    }

    fn served_output(snap: &Snapshot, universe: &RouteUniverse, amount_in: U256) -> U256 {
        PreparedRoutes::for_universe(snap, universe)
            .expect("routes")
            .try_solve_quantized(amount_in, CHUNKS, MIN_SHARE)
            .expect("solve")
            .expect("plan exists")
            .amount_out
    }

    /// The plan the served universe produces — what `idle` is read against.
    fn served_plan(snap: &Snapshot, universe: &RouteUniverse, amount_in: U256) -> Plan {
        PreparedRoutes::for_universe(snap, universe)
            .expect("routes")
            .try_solve_quantized(amount_in, CHUNKS, MIN_SHARE)
            .expect("solve")
            .expect("plan exists")
    }

    fn measure(
        snap: &Snapshot,
        universe: &RouteUniverse,
        screening: &ScreeningPools,
        achieved: U256,
        amount_in: U256,
    ) -> Option<CoverageValue> {
        measure_coverage(
            snap,
            universe,
            screening,
            &served_plan(snap, universe, amount_in),
            // A generous bound: these fixtures test the measurement, and §22's
            // rule is exercised by its own tests.
            U256::from(10_000u64),
            achieved,
            amount_in,
            CHUNKS,
            MIN_SHARE,
            &SolverBudget::unlimited(),
        )
        .expect("measurement ran without error")
    }

    /// Helper for the cases that must produce a value.
    fn measured(
        snap: &Snapshot,
        universe: &RouteUniverse,
        screening: &ScreeningPools,
        achieved: U256,
        amount_in: U256,
    ) -> CoverageValue {
        measure(snap, universe, screening, achieved, amount_in).expect("coverage measured")
    }

    /// A connector paying twice the routed pool is worth a measurable amount of
    /// output, and the measurement says which connector and how much — in the
    /// output token's own wei, with no dual point involved.
    #[test]
    fn a_better_priced_connector_measures_a_real_gain_and_names_itself() {
        let connector = Address::repeat_byte(0x77);
        let (universe, snap, screening, amount_in, achieved) = fixture(&[(
            connector,
            (1_000_000_000_000, 2_000_000_000_000),
            (1_000_000_000_000, 1_000_000_000_000),
        )]);

        let value = measured(&snap, &universe, &screening, achieved, amount_in);

        assert!(
            value.total_gain > U256::ZERO,
            "gain {} widened {} achieved {}",
            value.total_gain,
            value.widened_out,
            achieved
        );
        assert_eq!(value.used, vec![connector]);
        assert_eq!(value.marginals.len(), 1);
        assert_eq!(value.marginals[0].connector, connector);
        // The only connector, so dropping it returns the served universe and its
        // marginal is the whole gain.
        assert_eq!(value.marginals[0].marginal_out, value.total_gain);
        // Monotone: a superset of pools never delivers less.
        assert!(value.widened_out >= achieved);
        // The baseline, the widened solve, and one leave-one-out.
        assert_eq!(value.solves, 3);

        // The bound covers the solve it was computed for, and the certified
        // ceiling on regret is never below the gain measured under it.
        let bound = value.widened_bound.expect("widened bound");
        assert!(bound >= value.widened_out);
        assert!(value.regret_bound_bps_e4.unwrap() >= value.gain_bps_e4);
    }

    /// A connector that costs a second fee for nothing is certified worthless,
    /// by a dual rather than by two runs of the allocator.
    ///
    /// This is the claim the unpublished allocator-monotonicity notes make
    /// (§6.1) against §11: scoped to the served universe plus the connectors being
    /// asked about, and tightened over that scope, the bound is tight enough to
    /// answer. §11's 45,380–1.4×10⁹ bps belongs to the catalog-scope bound at
    /// the served quote's own dual.
    #[test]
    fn a_connector_that_only_adds_a_fee_is_certified_worthless() {
        let connector = Address::repeat_byte(0x78);
        let (universe, snap, screening, amount_in, achieved) = fixture(&[(
            connector,
            (1_000_000_000, 1_000_000_000),
            (1_000_000_000, 1_000_000_000),
        )]);

        let value = measured(&snap, &universe, &screening, achieved, amount_in);

        assert_eq!(value.total_gain, U256::ZERO, "a second fee cannot pay");
        let regret = value.regret_bound_bps_e4.expect("regret bound");
        println!(
            "worthless connector: gain {} regret bound {} widened gap {}",
            value.gain_bps_e4,
            regret,
            value.widened_gap_bps_e4.unwrap()
        );
        // Measured 302, or 0.0302 bp. §11's catalog-scope bound reported
        // 45,380 to 1.4×10⁹ bps for the same question.
        assert!(
            regret <= U256::from(1_000),
            "the scoped bound must stay inside a tenth of a basis point, got {regret}"
        );
    }

    /// Fix C, in the shape section 5 of the monotonicity document described:
    /// the served quote was produced at one resolution and the measurement runs
    /// at another, so the baseline it subtracts can sit BELOW the quote it is
    /// measuring against. The window read that on 6 of 16 cells, up to 3.9105 bp.
    ///
    /// Measuring at one chunk against a plan solved at `CHUNKS` reproduces it.
    /// The seed makes the baseline at least the served plan, and says so.
    #[test]
    fn a_coarser_measurement_cannot_price_its_own_resolution_as_coverage() {
        // Two routes in the SERVED universe that a split genuinely improves on:
        // the direct pool is shallow enough that its price impact outruns the
        // second fee the incumbent's two hops pay. One pool, or two pools of
        // equal depth, cannot express that — the winner takes everything and
        // chunk count stops mattering.
        let (universe, mut snap, screening, amount_in, _) = fixture_with_incumbent(
            (
                Address::repeat_byte(0x81),
                (1_000_000_000_000, 1_000_000_000_000),
                (1_000_000_000_000, 1_000_000_000_000),
            ),
            (
                Address::repeat_byte(0x82),
                (1_000_000_000_000, 2_000_000_000_000),
                (1_000_000_000_000, 1_000_000_000_000),
            ),
        );
        snap.v2[0].1 = V2State {
            reserve0: U256::from(4_000_000u64),
            reserve1: U256::from(4_000_000u64),
        };
        let served = served_plan(&snap, &universe, amount_in);
        let achieved = served.amount_out;

        let value = measure_coverage(
            &snap,
            &universe,
            &screening,
            &served,
            U256::from(10_000u64),
            achieved,
            amount_in,
            // Coarse where the served plan was fine: the same asymmetry
            // escalation produces in production.
            1,
            MIN_SHARE,
            &SolverBudget::unlimited(),
        )
        .expect("measurement ran")
        .expect("coverage measured");

        // The baseline is now the served plan or better, so no part of the
        // resolution difference can be reported as coverage.
        assert!(
            value.widened_out >= achieved,
            "widened {} below achieved {achieved}",
            value.widened_out
        );
        assert!(
            value.base_seeded,
            "a one-chunk baseline cannot beat a {CHUNKS}-chunk served plan; \
             the seed should have carried it"
        );
        // To the wei. Re-quantizing the served plan recovers its split exactly,
        // so the baseline is the served output rather than an approximation of
        // it, and no rounding leaks back in as coverage.
        assert_eq!(
            value.widened_out - value.total_gain,
            achieved,
            "the seeded baseline must reproduce the served output exactly"
        );
    }

    /// The guard's job, kept after seeding made the guard unfirable.
    ///
    /// A widened universe that cannot route at all is the extreme of the case
    /// fix C exists for. The seed carries the measurement, and `widened_seeded`
    /// is what stops the resulting zero from reading as a proof — which is the
    /// danger section 7 named as the reason C had to land after D.
    #[test]
    fn a_solve_that_loses_to_its_seed_is_carried_and_says_so() {
        let (universe, snap, _screening, amount_in, achieved) = fixture(&[]);
        let served = served_plan(&snap, &universe, amount_in);
        assert!(served.amount_out > U256::ZERO);

        // No paths at all: the allocator has nothing to find.
        let (plan, seeded) = solve_shadow_seeded(
            &snap,
            &[],
            B256::repeat_byte(0x5e),
            amount_in,
            CHUNKS,
            MIN_SHARE,
            Some(&served),
            &SolverBudget::unlimited(),
        )
        .expect("seeded solve");

        assert!(seeded, "the seed was the only feasible plan");
        let plan = plan.expect("the seed carries it");
        assert_eq!(plan.amount_out, achieved);
        assert_eq!(
            plan.universe_id,
            Some(B256::repeat_byte(0x5e)),
            "a seeded winner is labelled by the universe it was re-evaluated in"
        );

        // And the unseeded call still reports what it found, which is nothing.
        assert!(
            solve_shadow(
                &snap,
                &[],
                B256::repeat_byte(0x5e),
                amount_in,
                CHUNKS,
                MIN_SHARE,
                &SolverBudget::unlimited(),
            )
            .expect("unseeded solve")
            .is_none(),
            "the leave-one-out path must not inherit a seed"
        );
    }

    /// The other half of the swap, measured: what losing an incumbent costs.
    ///
    /// This is §19 in miniature. The incumbent is deep and carries the route;
    /// the candidate is thin and is worth a little ON TOP of it. R2 saw only
    /// the candidate's number, promoted it, evicted the incumbent, and lost
    /// 142 bp. Both numbers exist here, on one denominator, and they order the
    /// only way that makes the swap refusable.
    #[test]
    fn an_incumbent_reports_what_losing_it_would_cost() {
        let (incumbent, candidate) = (Address::repeat_byte(0x81), Address::repeat_byte(0x82));

        let (universe, snap, screening, amount_in, achieved) = fixture_with_incumbent(
            // Better priced than the direct pool, and shallow enough that the
            // trade moves it: the route leans on it and then saturates it.
            (
                incumbent,
                (10_000_000, 40_000_000),
                (10_000_000, 10_000_000),
            ),
            // Also better than direct, clearly worse than the incumbent. It
            // picks up what saturation spills, which is a real gain ON TOP of
            // the incumbent and never a substitute for it.
            (
                candidate,
                (10_000_000, 20_000_000),
                (10_000_000, 10_000_000),
            ),
        );

        let value = measured(&snap, &universe, &screening, achieved, amount_in);

        let loss = value
            .incumbents
            .iter()
            .find(|entry| entry.connector == incumbent)
            .expect("the routable connector reports a loss");
        assert!(
            loss.marginal_out > U256::ZERO,
            "the route leans on it, so dropping it must cost something"
        );
        assert_eq!(
            value.offered,
            vec![candidate],
            "an incumbent is never offered to the candidate measurement"
        );
        // Both numbers have to be real or the comparison proves nothing: a
        // candidate the widened solve never routed would report zero and clear
        // any incumbent trivially.
        assert_eq!(value.used, vec![candidate], "the candidate must be routed");
        let gain = value
            .marginals
            .iter()
            .find(|entry| entry.connector == candidate)
            .expect("a routed candidate reports a marginal")
            .marginal_bps_e4;
        assert!(gain > U256::ZERO, "the candidate is worth something");
        // 36.56 bp of gain against 6249.22 bp of loss. R2 compared the first
        // against nothing and swapped.
        assert!(
            gain < loss.marginal_bps_e4,
            "candidate {gain} must not outrank incumbent {} on one denominator",
            loss.marginal_bps_e4
        );
    }

    /// An incumbent nothing could measure stays out of the list, because absent
    /// has to mean unevictable. A zero would read as free to evict.
    #[test]
    fn an_unroutable_shortlist_reports_no_incumbents() {
        let connector = Address::repeat_byte(0x83);
        let (universe, snap, screening, amount_in, achieved) = fixture(&[(
            connector,
            (1_000_000_000_000, 2_000_000_000_000),
            (1_000_000_000_000, 1_000_000_000_000),
        )]);

        let value = measured(&snap, &universe, &screening, achieved, amount_in);

        assert!(value.incumbents.is_empty(), "nothing was admitted to lose");
    }

    /// The rule, in the shape §21 measured: a slot held by a proven-idle
    /// connector goes to a candidate that beats the certified bound.
    ///
    /// CAKE held a slot on WBNB→USDT and measured exactly zero at all three
    /// sizes, while USDC was worth 0.2752 to 2.6116 bp against a gap of 0.0094
    /// to 0.8500. Nothing here compares CAKE with USDC.
    #[test]
    fn a_proven_idle_slot_goes_to_a_candidate_that_beats_the_bound() {
        let (held, idle, candidate) = (
            Address::repeat_byte(0xc1),
            Address::repeat_byte(0xc2),
            Address::repeat_byte(0xc3),
        );
        let screened = vec![held, idle, candidate];
        let evidence = AdmissionEvidence {
            idle: vec![idle],
            gains: HashMap::from([(candidate, U256::from(26_116u64))]), // 2.6116 bp
            loss_bound_bps_e4: U256::from(8_500u64),                    // 0.8500 bp
            bands: 1,
        };

        let ordered = admit_by_certified_value(&screened, 2, &evidence, U256::ZERO);

        assert_eq!(
            &ordered[..2],
            &[held, candidate],
            "the idle slot goes to the proven candidate"
        );
        assert_eq!(ordered.len(), screened.len(), "length is preserved");
        assert!(ordered.contains(&idle), "the evicted one stays screened");
    }

    /// A candidate under the certified bound proves nothing, so nothing moves.
    /// The gap is what evicting the idle connector might cost, and a gain
    /// smaller than that leaves the universe possibly worse.
    #[test]
    fn a_candidate_below_the_certified_bound_moves_nothing() {
        let (held, idle, candidate) = (
            Address::repeat_byte(0xc4),
            Address::repeat_byte(0xc5),
            Address::repeat_byte(0xc6),
        );
        let screened = vec![held, idle, candidate];
        let evidence = AdmissionEvidence {
            idle: vec![idle],
            gains: HashMap::from([(candidate, U256::from(2_000u64))]), // 0.2 bp
            loss_bound_bps_e4: U256::from(8_500u64),                   // 0.85 bp
            bands: 1,
        };

        let ordered = admit_by_certified_value(&screened, 2, &evidence, U256::ZERO);

        assert_eq!(ordered, screened);
    }

    /// The §19 case, refused by construction. BTCB carried the route, so it is
    /// never idle, so its slot is not one this rule can offer — however large
    /// the candidate's measured gain is.
    #[test]
    fn a_connector_carrying_the_route_is_never_evicted() {
        let (carrying, other, candidate) = (
            Address::repeat_byte(0xc7),
            Address::repeat_byte(0xc8),
            Address::repeat_byte(0xc9),
        );
        let screened = vec![carrying, other, candidate];
        let evidence = AdmissionEvidence {
            idle: Vec::new(), // both incumbents route flow
            gains: HashMap::from([(candidate, U256::from(1_000_000u64))]), // 100 bp
            loss_bound_bps_e4: U256::from(1_388u64),
            bands: 1,
        };

        let ordered = admit_by_certified_value(&screened, 2, &evidence, U256::ZERO);

        assert_eq!(ordered, screened, "no idle slot means no swap");
    }

    /// Idle intersects, the bound maxes, and gains take the maximum against a
    /// cost charged once per band.
    ///
    /// The two directions are deliberate and asymmetric. A connector is free to
    /// lose only if EVERY band proved it idle, and losing it costs the WORST
    /// band's certified gap — both safe. What a candidate is worth takes its
    /// best band, because `admit_by_certified_value` then charges the bound
    /// once per band, so a candidate that delivers in one band and nothing in
    /// the others still has to cover the whole swap.
    #[test]
    fn evidence_merges_conservatively_across_bands() {
        let cache = CoverageCache::default();
        let (tin, tout) = (Address::repeat_byte(0xd1), Address::repeat_byte(0xd2));
        let (steady, sometimes, candidate) = (
            Address::repeat_byte(0xd3),
            Address::repeat_byte(0xd4),
            Address::repeat_byte(0xd5),
        );
        let print = B256::repeat_byte(0xd6);
        let band = |band, idle: Vec<Address>, bps: u64, bound: u64| {
            let mut value = CoverageValue::placeholder();
            value.idle = idle;
            value.loss_bound_bps_e4 = U256::from(bound);
            value.offered = vec![candidate];
            value.marginals = vec![ConnectorMarginal {
                connector: candidate,
                marginal_out: U256::from(bps),
                marginal_bps_e4: U256::from(bps),
            }];
            cache.store_coverage((7, tin, tout, band), print, &value, U256::from(1u64), LEASE);
        };
        band(20, vec![steady, sometimes], 90_000, 5_000);
        band(21, vec![steady], 30_000, 8_500);

        let evidence = cache.certified_admission(7, tin, tout);

        assert_eq!(evidence.idle, vec![steady], "idle intersects across bands");
        assert_eq!(
            evidence.gains.get(&candidate),
            Some(&U256::from(90_000u64)),
            "gains take the maximum"
        );
        assert_eq!(
            evidence.loss_bound_bps_e4,
            U256::from(8_500u64),
            "the bound takes the maximum"
        );
        assert_eq!(evidence.bands, 2, "both bands are charged for");
        assert!(
            cache.certified_admission(8, tin, tout).idle.is_empty(),
            "another chain"
        );
    }

    /// §25's window, replayed: the case the minimum could not promote and this
    /// rule can, plus the neighbouring case neither may.
    ///
    /// USDC on WBNB→USDT was measured at 0.2153 bp in the 100 band and 3.3269
    /// in the 3,000 band. Under the minimum its merged value was 0.2153 against
    /// a 0.3166 bound and it was declined 181 times out of 181. Its best band
    /// covers the bound charged across all three; a candidate whose best band
    /// does not still gets nowhere.
    #[test]
    fn the_band_that_pays_carries_the_swap_and_a_weak_one_still_cannot() {
        let cache = CoverageCache::default();
        let (tin, tout) = (Address::repeat_byte(0xf1), Address::repeat_byte(0xf2));
        let (held, idle, usdc, weak) = (
            Address::repeat_byte(0xf3),
            Address::repeat_byte(0xf4),
            Address::repeat_byte(0xf5),
            Address::repeat_byte(0xf6),
        );
        let print = B256::repeat_byte(0xf7);
        let band = |band: u32, usdc_bps: u64, weak_bps: u64, bound: u64| {
            let mut value = CoverageValue::placeholder();
            value.idle = vec![idle];
            value.loss_bound_bps_e4 = U256::from(bound);
            value.offered = vec![usdc, weak];
            value.marginals = vec![
                ConnectorMarginal {
                    connector: usdc,
                    marginal_out: U256::from(usdc_bps),
                    marginal_bps_e4: U256::from(usdc_bps),
                },
                ConnectorMarginal {
                    connector: weak,
                    marginal_out: U256::from(weak_bps),
                    marginal_bps_e4: U256::from(weak_bps),
                },
            ];
            cache.store_coverage((9, tin, tout, band), print, &value, U256::from(1u64), LEASE);
        };
        // §25's three retained bands, at its measured gaps.
        band(7, 2_153, 1_000, 377); // 100:   0.2153 bp, gap 0.0377
        band(10, 15_276, 2_000, 3_166); // 1,000: 1.5276 bp, gap 0.3166
        band(12, 33_269, 3_000, 78); // 3,000: 3.3269 bp, gap 0.0078

        let evidence = cache.certified_admission(9, tin, tout);
        assert_eq!(evidence.bands, 3);
        assert_eq!(evidence.gains.get(&usdc), Some(&U256::from(33_269u64)));
        assert_eq!(evidence.loss_bound_bps_e4, U256::from(3_166u64));

        // 3.3269 bp against 3 x 0.3166 = 0.9498 bp of total certified cost.
        let ordered = admit_by_certified_value(&[held, idle, usdc, weak], 2, &evidence, U256::ZERO);
        assert_eq!(
            &ordered[..2],
            &[held, usdc],
            "the band that pays carries the swap"
        );

        // The weak candidate's best band is 0.3000 bp, under the same total.
        let ordered = admit_by_certified_value(&[held, idle, weak], 2, &evidence, U256::ZERO);
        assert_eq!(
            ordered,
            vec![held, idle, weak],
            "a candidate that covers no band's share moves nothing"
        );

        // The churn floor bounds the TOTAL, not each band's share. Folding it
        // into the bound first would charge 3 x 1.0 bp here and refuse a swap
        // the operator asked to see at 1.0 — a churn policy silently scaled by
        // how many sizes happen to be in retention.
        let floor = U256::from(10_000u64); // 1.0000 bp, the shipped default
        let ordered = admit_by_certified_value(&[held, idle, usdc, weak], 2, &evidence, floor);
        assert_eq!(
            &ordered[..2],
            &[held, usdc],
            "3 x 0.3166 = 0.9498 is under the floor, so the floor is what binds \
             and 3.3269 clears it"
        );
        let steep = U256::from(40_000u64); // 4.0000 bp
        assert_eq!(
            admit_by_certified_value(&[held, idle, usdc, weak], 2, &evidence, steep),
            vec![held, idle, usdc, weak],
            "a floor above the gain refuses the swap on churn grounds alone"
        );
    }

    /// One verdict, aged to where each reader actually meets it.
    fn aged_verdict(
        cache: &CoverageCache,
        chain: u64,
        age: Duration,
    ) -> (Address, Address, Address, B256, CoverageKey) {
        let (tin, tout) = (Address::repeat_byte(0xe1), Address::repeat_byte(0xe2));
        let connector = Address::repeat_byte(0xe3);
        let print = B256::repeat_byte(0xe4);
        let key = (chain, tin, tout, 20);
        let mut value = CoverageValue::placeholder();
        value.offered = vec![connector];
        value.marginals = vec![ConnectorMarginal {
            connector,
            marginal_out: U256::from(1u64),
            marginal_bps_e4: U256::from(309_000u64), // 30.9 bp, §16's richest
        }];
        cache.store_coverage_aged(key, print, &value, U256::from(1u64), LEASE, age);
        (tin, tout, connector, print, key)
    }

    /// Admission must still see a verdict measured one lease ago, because that
    /// is the only age at which it ever reads one.
    ///
    /// The two clocks are set in the same request and in this order: the
    /// topology is cached, then the measurement runs and files its verdict a
    /// few hundred milliseconds later. Admission runs when the topology
    /// expires. Swept against a single lifetime equal to the lease, the verdict
    /// outlives the topology by exactly the measurement's own duration — so
    /// admission reads it only if the rebuilding quote lands inside a
    /// sub-second window, and silently admits nothing the rest of the time.
    #[test]
    fn admission_reads_a_verdict_measured_one_lease_ago() {
        let cache = CoverageCache::default();
        let (tin, tout, connector, _, _) = aged_verdict(&cache, 9, LEASE + Duration::from_secs(30));

        let merged = cache.certified_admission(9, tin, tout).gains;

        assert_eq!(
            merged.get(&connector),
            Some(&U256::from(309_000u64)),
            "a verdict one lease old is exactly what admission was built to read"
        );
    }

    /// Reporting keeps the shorter horizon. Publishing a verdict older than its
    /// TTL as this quote's own coverage is the freshness claim the TTL exists
    /// to make, and admission reading further back must not relax it.
    #[test]
    fn reporting_refuses_a_verdict_past_its_ttl() {
        let cache = CoverageCache::default();
        let (_, _, _, print, key) = aged_verdict(&cache, 10, LEASE + Duration::from_secs(30));

        assert!(cache.cached_coverage(key, print).is_none());
    }

    /// Both horizons end. A verdict two leases old describes a topology two
    /// rotations gone, and admission falls back to the ranking's order.
    #[test]
    fn admission_drops_a_verdict_past_two_leases() {
        let cache = CoverageCache::default();
        let (tin, tout, _, _, _) = aged_verdict(&cache, 11, LEASE * 2 + Duration::from_secs(30));

        assert!(cache.certified_admission(11, tin, tout).gains.is_empty());
    }

    /// Admission is called with the pair the engine canonicalized, while the
    /// verdict was filed under the direction someone quoted. One universe
    /// serves both, so the lookup has to.
    ///
    /// Without this, admission finds nothing on every pair whose traffic runs
    /// against address order — silently, and on half of them.
    #[test]
    fn admission_reads_a_verdict_filed_in_the_other_direction() {
        let cache = CoverageCache::default();
        let (tin, tout, connector, _, _) = aged_verdict(&cache, 12, Duration::from_secs(1));

        let merged = cache.certified_admission(12, tout, tin).gains;

        assert_eq!(merged.get(&connector), Some(&U256::from(309_000u64)));
    }

    /// Why the verdict is published as a ratio.
    ///
    /// A band spans a factor of two, so a quote near the top of one reusing a
    /// verdict measured near the bottom serves MORE than the widened universe
    /// was measured to deliver. The wei fields then read as the widened set
    /// losing to a subset of itself — which monotonicity forbids, and which
    /// production did on 2026-08-05: a quote at 1.10e18 published
    /// `widenedWei` 590.17e18 against its own `amountOutNet` of 616.32e18.
    ///
    /// This is the common case rather than a rare one: it applies to every
    /// reuse above the measured size. `gain_bps_e4` is scale-free, so it is the
    /// field that stays true across the band.
    #[test]
    fn a_reused_verdict_keeps_its_ratio_while_its_wei_amounts_go_stale() {
        // This test's own cache: the first quote measures, the second reuses.
        let cache = CoverageCache::default();
        let connector = Address::repeat_byte(0x78);
        // Rate-neutral and deep, so the connector's edge is the direct pool's
        // slippage minus one extra LP fee — percent, not the fixture default's
        // rate arbitrage, which doubles the output and swamps any size effect.
        // Production's gains were 0.19 to 30.9 bp (docs §16).
        let (universe, snap, screening, _, _) = fixture(&[(
            connector,
            (1_000_000_000_000, 1_000_000_000_000),
            (1_000_000_000_000, 1_000_000_000_000),
        )]);

        // Both inside band 26 = [2^25, 2^26), near its bottom and its top.
        // Sized against the fixture's 1e9 direct pool so slippage — and so the
        // connector's edge — is a few percent rather than a few bp.
        let measured_at = U256::from(40_000_000u64);
        let served_at = U256::from(67_000_000u64);
        assert_eq!(
            size_bucket(measured_at),
            size_bucket(served_at),
            "the two sizes must share a band for this to test reuse"
        );

        let serve = |amount_in| {
            cache
                .coverage(
                    &snap,
                    &universe,
                    &screening,
                    &served_plan(&snap, &universe, amount_in),
                    U256::from(10_000u64),
                    served_output(&snap, &universe, amount_in),
                    amount_in,
                    CHUNKS,
                    MIN_SHARE,
                    &SolverBudget::unlimited(),
                )
                .expect("coverage ran without error")
                .expect("a screened universe is measurable")
        };

        let measured = serve(measured_at);
        assert_eq!(
            measured.age,
            Duration::ZERO,
            "the first quote must measure, not reuse"
        );
        assert!(measured.value.gain_bps_e4 > U256::ZERO);

        let reused = serve(served_at);
        assert_eq!(
            reused.measured_in, measured_at,
            "the larger quote re-measured instead of reusing"
        );

        // The ratio carries across the band unchanged.
        assert_eq!(reused.value.gain_bps_e4, measured.value.gain_bps_e4);

        // The wei amounts do not: the widened output measured at the smaller
        // size is BELOW what this quote itself achieved. Publishing only the wei
        // fields would state that a superset lost to one of its own subsets.
        let achieved_here = served_output(&snap, &universe, served_at);
        assert!(
            reused.value.widened_out < achieved_here,
            "expected the stale wei amounts to understate this quote: \
             widened {} vs achieved {achieved_here}",
            reused.value.widened_out
        );
    }
}
