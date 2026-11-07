use super::Resident;
use super::graph::Venue;
use crate::chain::ChainProfile;
use crate::snapshot::Snapshot;
use alloy_primitives::{Address, U256};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How often every pool's liquidity is tested again. A pool new to the state
/// is tested in the block it arrives.
const LIQUIDITY_RETEST: Duration = Duration::from_secs(30 * 60);
/// The test's smaller trade, in dollars; the larger is twice it.
pub(super) const LIQUIDITY_TEST_USD: u64 = 500;

/// Jupiter's routing liquidity test (developers.jup.ag, "Market Listing",
/// read 16 Oct 2026), run on every resident pool: a pool passes when $500 of
/// its token, bought and sold straight back, loses under 30%, or else when
/// a $1,000 buy's unit price is within 20% of a $500 buy's. Both legs of a
/// test are priced on the same state, as two quotes. A pool is tested from
/// the side priced first, starting from the profile's stable
/// (`dollar_amounts`). A pool with no priced side is not tested. A pool that
/// failed is tested again at every block.
#[derive(Default)]
pub(super) struct Liquidity {
    /// When every pool was last tested.
    pub(super) tested_at: Option<Instant>,
    /// Pools tested since then.
    tested: HashSet<Address>,
    /// Those that failed.
    thin: Arc<HashSet<Address>>,
}

impl Resident {
    /// The pools of `snapshot` that failed the liquidity test: every pool
    /// again once `LIQUIDITY_RETEST` has passed, otherwise the ones it has not
    /// tested and the ones that failed. A pool often arrives empty and is
    /// funded a few blocks later, so a failure is checked again at every
    /// block, which costs a dozen pools' worth of arithmetic; a pass stands
    /// until the retest.
    pub(super) fn thin_pools(&self, snapshot: &Snapshot) -> Arc<HashSet<Address>> {
        let mut liquidity = self.liquidity.lock().expect("resident liquidity");
        if liquidity
            .tested_at
            .is_none_or(|at| at.elapsed() >= LIQUIDITY_RETEST)
        {
            *liquidity = Liquidity {
                tested_at: Some(Instant::now()),
                ..Liquidity::default()
            };
        }
        let venues: Vec<Venue<'_>> = testable_venues(snapshot)
            .filter(|venue| {
                !liquidity.tested.contains(&venue.address())
                    || liquidity.thin.contains(&venue.address())
            })
            .collect();
        if venues.is_empty() {
            return liquidity.thin.clone();
        }
        let started = Instant::now();
        let dollars = dollar_amounts(snapshot, self.profile, &self.connectors, LIQUIDITY_TEST_USD);
        let new = venues
            .iter()
            .filter(|venue| !liquidity.tested.contains(&venue.address()))
            .count();
        let mut thin = HashSet::new();
        for venue in &venues {
            liquidity.tested.insert(venue.address());
            if fails_liquidity_test(venue, &dollars) {
                thin.insert(venue.address());
            }
        }
        if new > 0 || thin != *liquidity.thin {
            tracing::info!(
                "resident: liquidity test at block {}: {} pools tested ({new} new) in {} us, {} of {} thin",
                snapshot.block,
                venues.len(),
                started.elapsed().as_micros(),
                thin.len(),
                liquidity.tested.len()
            );
            liquidity.thin = Arc::new(thin);
        }
        liquidity.thin.clone()
    }
}

/// The V3 and V2 pools of `snapshot`, which the test can price.
pub(super) fn testable_venues(snapshot: &Snapshot) -> impl Iterator<Item = Venue<'_>> {
    snapshot
        .v3
        .iter()
        .map(|(pool, state)| Venue::V3(pool, state))
        .chain(
            snapshot
                .v2
                .iter()
                .map(|(pool, state)| Venue::V2(pool, state)),
        )
}

/// `usd` dollars of each connector `snapshot` can price, in its smallest
/// unit, in the order they were priced: the profile's stable at face value,
/// then each other connector by what that much of a priced one buys of it
/// through the best pool between them that passes the test from the priced
/// side. A connector whose every path crosses a thin pool has no price: a
/// thin pool's price is the one a single trade can move.
pub(super) fn dollar_amounts(
    snapshot: &Snapshot,
    profile: &ChainProfile,
    connectors: &[Address],
    usd: u64,
) -> Vec<(Address, U256)> {
    let mut priced = Vec::new();
    let Some(dollar) = U256::from(10u8).checked_pow(U256::from(profile.stable_decimals)) else {
        return priced;
    };
    priced.push((profile.stable, U256::from(usd) * dollar));
    let price = |priced: &[(Address, U256)], token: Address| {
        priced
            .iter()
            .find(|(priced, _)| *priced == token)
            .map(|(_, amount)| *amount)
    };
    for _ in 0..connectors.len() {
        let mut found: Vec<(Address, U256)> = Vec::new();
        for venue in testable_venues(snapshot) {
            let (token0, token1) = venue.tokens();
            for (from, to) in [(token0, token1), (token1, token0)] {
                if !connectors.contains(&to) || price(&priced, to).is_some() {
                    continue;
                }
                let Some(amount) = price(&priced, from) else {
                    continue;
                };
                if fails_from(&venue, from, to, amount) {
                    continue;
                }
                let Some(out) = venue.out(from, amount) else {
                    continue;
                };
                match found.iter_mut().find(|(token, _)| *token == to) {
                    Some((_, best)) => *best = (*best).max(out),
                    None => found.push((to, out)),
                }
            }
        }
        if found.is_empty() {
            break;
        }
        // In connector order, so the result does not hang on pool order.
        found.sort_by_key(|(token, _)| connectors.iter().position(|c| c == token));
        priced.extend(found);
    }
    priced
}

/// Whether `venue` fails the liquidity test, priced in whichever of its
/// tokens `dollars` priced first. A pool with neither side priced is not
/// tested.
pub(super) fn fails_liquidity_test(venue: &Venue<'_>, dollars: &[(Address, U256)]) -> bool {
    let (token0, token1) = venue.tokens();
    let Some(&(quote, small)) = dollars
        .iter()
        .find(|(token, _)| *token == token0 || *token == token1)
    else {
        return false;
    };
    let token = if quote == token0 { token1 } else { token0 };
    fails_from(venue, quote, token, small)
}

/// The test proper: `small` of `quote` buys `token` and sells it straight
/// back, and a $1,000 buy is priced beside the $500 one. A pool that cannot
/// fill the trade fails.
fn fails_from(venue: &Venue<'_>, quote: Address, token: Address, small: U256) -> bool {
    let Some(bought) = venue.out(quote, small) else {
        return true;
    };
    let back = venue.out(token, bought).unwrap_or_default();
    // Under 30% lost on the round trip.
    if back.saturating_mul(U256::from(10u8)) > small.saturating_mul(U256::from(7u8)) {
        return false;
    }
    let Some(bought_twice) = venue.out(quote, small.saturating_mul(U256::from(2u8))) else {
        return true;
    };
    // The $1,000 unit price, 2·small / bought_twice, above 1.2 times the $500
    // one, small / bought.
    bought.saturating_mul(U256::from(5u8)) > bought_twice.saturating_mul(U256::from(3u8))
}
