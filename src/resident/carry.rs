//! Carrying pool state from one read to the next.
//!
//! A Uniswap V2 pair moves its reserves only with `Sync`. A Uniswap V3 pool
//! moves its price, active liquidity or ticks only with `Initialize`, `Swap`,
//! `Mint` or `Burn`, and its fee is fixed. PancakeSwap V3 differs only in its
//! `Swap`. So a pool of one of the venues known to run that code
//! ([`carries_v3`], [`carries_v2`]) that emitted none of [`MOVES`] in the
//! blocks since the last read still has the state that read found. A pool of
//! any other venue is read at every block.
//!
//! Each block's logs are asked by its hash (EIP-234) and those events,
//! without an address list, so the request does not grow with the list.
//! This holds only along one chain: the blocks since the last read are
//! linked parent to child by hash, from the last read to the head, so a
//! reorg, or a node on another branch, can only send the reader to a whole
//! read.

use crate::pools::{V2Pool, V2State, V3Pool, V3State};
use crate::rpc::{CanonicalBlock, CanonicalHeader};
use crate::snapshot::Snapshot;
use crate::venue::Core;
use alloy_primitives::{Address, B256, b256};
use anyhow::{Context, ensure};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// `Initialize(uint160,int24)`.
const INITIALIZE: B256 = b256!("98636036cb66a9c19a37435efc1e90142190214e8abeb821bdba3f2990dd4c95");
/// Uniswap V3's `Swap(address,address,int256,int256,uint160,uint128,int24)`.
const SWAP_UNISWAP_V3: B256 =
    b256!("c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67");
/// PancakeSwap V3's `Swap`, which adds the two protocol fees:
/// `Swap(address,address,int256,int256,uint160,uint128,int24,uint128,uint128)`.
const SWAP_PANCAKE_V3: B256 =
    b256!("19b47279256b2a23a1665c810c8d55a1758940ee09377d4f8d26497a3577dc83");
/// `Mint(address,address,int24,int24,uint128,uint256,uint256)`.
const MINT_V3: B256 = b256!("7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde");
/// `Burn(address,int24,int24,uint128,uint256,uint256)`.
const BURN_V3: B256 = b256!("0c396cd989a39f4459b5fa1aed6a9a8dcdbc45908acfd67e028cd568da98982c");
/// `Sync(uint112,uint112)`.
const SYNC_V2: B256 = b256!("1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1");

/// Every event a carried pool moves its state with: the topics each block's
/// logs are asked by.
pub(super) const MOVES: [B256; 6] = [
    INITIALIZE,
    SWAP_UNISWAP_V3,
    SWAP_PANCAKE_V3,
    MINT_V3,
    BURN_V3,
    SYNC_V2,
];

/// Whether `pool` runs Uniswap V3's core (or PancakeSwap's, which differs
/// only in `Swap`), so that its state moves only with [`MOVES`].
pub(super) fn carries_v3(pool: &V3Pool) -> bool {
    pool.v4.is_none() && pool.algebra.is_none() && pool.protocol.core() == Core::UniV3
}

/// Whether `pool` is a Uniswap V2 pair, whose reserves move only with `Sync`.
pub(super) fn carries_v2(pool: &V2Pool) -> bool {
    pool.protocol.core() == Core::UniV2
}

/// A pool with its state.
pub(super) type V3Entry = (V3Pool, V3State);
pub(super) type V2Entry = (V2Pool, V2State);

/// What the reader keeps of its last read, for the next to build on.
pub(super) struct LastRead {
    pub block: CanonicalBlock,
    /// Every pool that read covered, kept or not: an uninitialized pool is
    /// read and left out.
    pub covered: HashSet<Address>,
    pub v3: HashMap<Address, (V3Pool, V3State)>,
    pub v2: HashMap<Address, (V2Pool, V2State)>,
    /// When every pool was last read whole.
    pub whole_at: Instant,
}

impl LastRead {
    pub fn new(
        block: CanonicalBlock,
        covered: HashSet<Address>,
        v3: &[(V3Pool, V3State)],
        v2: &[(V2Pool, V2State)],
        whole_at: Instant,
    ) -> Self {
        Self {
            block,
            covered,
            v3: v3
                .iter()
                .map(|entry| (entry.0.address, entry.clone()))
                .collect(),
            v2: v2
                .iter()
                .map(|entry| (entry.0.address, entry.clone()))
                .collect(),
            whole_at,
        }
    }
}

/// The blocks after `last` through `head`, oldest first, when `between` (the
/// headers after `last` and before `head`, oldest first) links them parent to
/// child; `None` when a link is missing: a reorg, or a node on another
/// branch.
pub(super) fn linked(
    last: &CanonicalBlock,
    between: &[CanonicalHeader],
    head: &CanonicalHeader,
) -> Option<Vec<CanonicalBlock>> {
    let mut parent = last.hash;
    let mut number = last.number;
    let mut blocks = Vec::with_capacity(between.len() + 1);
    for header in between.iter().chain(std::iter::once(head)) {
        number += 1;
        if header.block.number != number || header.parent_hash != parent {
            return None;
        }
        parent = header.block.hash;
        blocks.push(header.block);
    }
    Some(blocks)
}

/// The pools of `pools` that moved in `block`, from an `eth_getLogs` answer
/// asked by `block`'s hash and [`MOVES`]. A log of another block refuses the
/// answer, since the node did not keep to the hash, and so does a log the
/// node calls removed.
pub(super) fn logged(
    logs: &[Value],
    block: &CanonicalBlock,
    pools: &HashSet<Address>,
) -> anyhow::Result<HashSet<Address>> {
    let mut changed = HashSet::new();
    for log in logs {
        let hash: B256 = log["blockHash"]
            .as_str()
            .context("a log without its block hash")?
            .parse()
            .context("a log's block hash is not a hash")?;
        ensure!(
            hash == block.hash,
            "asked for the logs of block {}, the node answered with block {hash:#x}",
            block.number
        );
        ensure!(
            log["removed"].as_bool() != Some(true),
            "the node calls a log of block {} removed",
            block.number
        );
        let address: Address = log["address"]
            .as_str()
            .context("a log without its address")?
            .parse()
            .context("a log's address is not an address")?;
        if pools.contains(&address) {
            changed.insert(address);
        }
    }
    Ok(changed)
}

/// The pools a step must read: those that logged, and those `last` did not
/// cover (new to the list).
pub(super) fn to_read(
    listed: &HashSet<Address>,
    last: &LastRead,
    changed: &HashSet<Address>,
) -> HashSet<Address> {
    listed
        .iter()
        .filter(|&address| changed.contains(address) || !last.covered.contains(address))
        .copied()
        .collect()
}

/// Every listed pool's state at the head, in the list's order: from `fresh`
/// for the pools in `read`, carried from `last` for the others. A pool
/// either left out keeps out.
pub(super) fn merge(
    list_v3: &[V3Pool],
    list_v2: &[V2Pool],
    read: &HashSet<Address>,
    fresh: &Snapshot,
    last: &LastRead,
) -> (Vec<V3Entry>, Vec<V2Entry>) {
    let fresh_v3: HashMap<Address, &(V3Pool, V3State)> = fresh
        .v3
        .iter()
        .map(|entry| (entry.0.address, entry))
        .collect();
    let fresh_v2: HashMap<Address, &(V2Pool, V2State)> = fresh
        .v2
        .iter()
        .map(|entry| (entry.0.address, entry))
        .collect();
    let v3 = list_v3
        .iter()
        .filter_map(|pool| {
            if read.contains(&pool.address) {
                fresh_v3.get(&pool.address).map(|entry| (*entry).clone())
            } else {
                last.v3.get(&pool.address).cloned()
            }
        })
        .collect();
    let v2 = list_v2
        .iter()
        .filter_map(|pool| {
            if read.contains(&pool.address) {
                fresh_v2.get(&pool.address).map(|entry| (*entry).clone())
            } else {
                last.v2.get(&pool.address).cloned()
            }
        })
        .collect();
    (v3, v2)
}

/// A whole read checked against what carrying `last` would have given: each
/// pool `last` covered that is still listed and logged nothing since. Returns
/// how many pools were checked and the ones whose state was not what was
/// carried.
pub(super) fn audit(
    last: &LastRead,
    changed: &HashSet<Address>,
    whole: &Snapshot,
    listed: &HashSet<Address>,
) -> (usize, Vec<Address>) {
    let whole_v3: HashMap<Address, &V3State> = whole
        .v3
        .iter()
        .map(|(pool, state)| (pool.address, state))
        .collect();
    let whole_v2: HashMap<Address, &V2State> = whole
        .v2
        .iter()
        .map(|(pool, state)| (pool.address, state))
        .collect();
    let mut checked = 0;
    let mut drifted = Vec::new();
    for address in listed {
        if !last.covered.contains(address) || changed.contains(address) {
            continue;
        }
        checked += 1;
        let v3 = match (last.v3.get(address), whole_v3.get(address)) {
            (None, None) => true,
            (Some((_, carried)), Some(read)) => same_v3(carried, read),
            _ => false,
        };
        let v2 = match (last.v2.get(address), whole_v2.get(address)) {
            (None, None) => true,
            (Some((_, carried)), Some(read)) => same_v2(carried, read),
            _ => false,
        };
        if !(v3 && v2) {
            drifted.push(*address);
        }
    }
    drifted.sort();
    (checked, drifted)
}

fn same_v3(a: &V3State, b: &V3State) -> bool {
    a.sqrt_price == b.sqrt_price
        && a.tick == b.tick
        && a.liquidity == b.liquidity
        && a.pos == b.pos
        && a.lo_cover == b.lo_cover
        && a.hi_cover == b.hi_cover
        && a.ticks.len() == b.ticks.len()
        && a.ticks
            .iter()
            .zip(b.ticks.iter())
            .all(|(x, y)| x.tick == y.tick && x.liquidity_net == y.liquidity_net)
}

fn same_v2(a: &V2State, b: &V2State) -> bool {
    a.reserve0 == b.reserve0 && a.reserve1 == b.reserve1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CatalogVenue;
    use crate::chain::{BSC_PROFILE, ETHEREUM_PROFILE};
    use crate::pools::{AlgebraMeta, TickInfo, V2Protocol, V3Protocol, V4Meta};
    use crate::venue::VenueId;
    use alloy_primitives::{I256, U256, address};
    use serde_json::json;

    const P1: Address = address!("00000000000000000000000000000000000000a1");
    const P2: Address = address!("00000000000000000000000000000000000000a2");
    const P3: Address = address!("00000000000000000000000000000000000000a3");
    const Q1: Address = address!("00000000000000000000000000000000000000b1");
    const STRANGER: Address = address!("00000000000000000000000000000000000000ff");

    fn block(number: u64) -> CanonicalBlock {
        CanonicalBlock {
            number,
            hash: B256::repeat_byte(number as u8),
            timestamp: 1_000 + number,
        }
    }

    fn header(number: u64, parent: B256) -> CanonicalHeader {
        CanonicalHeader {
            block: block(number),
            parent_hash: parent,
            logs_bloom: Default::default(),
        }
    }

    fn v3(address: Address, price: u64) -> (V3Pool, V3State) {
        (
            V3Pool {
                protocol: V3Protocol::UNIV3,
                address,
                token0: Address::repeat_byte(1),
                token1: Address::repeat_byte(2),
                fee_ppm: 500,
                tick_spacing: 10,
                verify_pool_spacing: false,
                execution: None,
                v4: None,
                algebra: None,
            },
            V3State {
                sqrt_price: U256::from(price),
                tick: 0,
                liquidity: U256::from(1_000u64),
                ticks: vec![TickInfo {
                    tick: 10,
                    liquidity_net: I256::try_from(5).unwrap(),
                }]
                .into(),
                pos: 0,
                lo_cover: -100,
                hi_cover: 100,
            },
        )
    }

    fn v2(address: Address, reserve: u64) -> (V2Pool, V2State) {
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address,
                token0: Address::repeat_byte(1),
                token1: Address::repeat_byte(2),
                fee_bps: 30,
            },
            V2State {
                reserve0: U256::from(reserve),
                reserve1: U256::from(reserve),
            },
        )
    }

    fn snapshot(v3: Vec<(V3Pool, V3State)>, v2: Vec<(V2Pool, V2State)>) -> Snapshot {
        Snapshot {
            block: 0,
            settler: None,
            v3,
            v2,
            ekubo: Vec::new(),
        }
    }

    fn set(addresses: &[Address]) -> HashSet<Address> {
        addresses.iter().copied().collect()
    }

    fn log(address: Address, block: &CanonicalBlock) -> Value {
        json!({"address": address, "blockHash": block.hash, "removed": false})
    }

    /// Every venue by name: the ids compiled in `crate::venue`, then sushiv2
    /// and an id no build knows, both interned as a manifest interns its ids.
    fn venues() -> Vec<VenueId> {
        let compiled = [
            "univ2",
            "univ3",
            "pancakev2",
            "pancakev3",
            "univ4",
            "up33v2",
            "up33cl",
            "swaphoodv3",
            "gigadexv3",
            "sushiv3",
            "robinswapv3",
            "sheriff",
        ]
        .map(|id| VenueId::known(id).expect("a compiled id"));
        let interned = ["sushiv2", "unknownvenue"].map(|id| VenueId::intern(id).unwrap());
        [compiled.as_slice(), interned.as_slice()].concat()
    }

    fn v4_state() -> V4Meta {
        V4Meta {
            pool_id: B256::repeat_byte(0x41),
            state_slot: B256::repeat_byte(0x42),
            native: false,
            hooks: Address::ZERO,
            swap_fee_0to1_ppm: 500,
            swap_fee_1to0_ppm: 500,
        }
    }

    #[test]
    fn the_events_are_the_hashes_of_their_signatures() {
        for (topic, signature) in [
            (INITIALIZE, "Initialize(uint160,int24)"),
            (
                SWAP_UNISWAP_V3,
                "Swap(address,address,int256,int256,uint160,uint128,int24)",
            ),
            (
                SWAP_PANCAKE_V3,
                "Swap(address,address,int256,int256,uint160,uint128,int24,uint128,uint128)",
            ),
            (
                MINT_V3,
                "Mint(address,address,int24,int24,uint128,uint256,uint256)",
            ),
            (BURN_V3, "Burn(address,int24,int24,uint128,uint256,uint256)"),
            (SYNC_V2, "Sync(uint112,uint112)"),
        ] {
            assert_eq!(topic, alloy_primitives::keccak256(signature), "{signature}");
        }
    }

    /// Every venue by name, as a V3 pool with no state of its own, with
    /// Algebra's and with V4's, and as a V2 pair. Only univ3, sushiv3 and
    /// pancakev3 pools with neither state are carried, and of the pairs only
    /// univ2's, sushiv2's and pancakev2's.
    #[test]
    fn only_venues_known_to_run_uniswap_code_are_carried() {
        for venue in venues() {
            let id = venue.as_str();
            let mut pool = v3(P1, 1).0;
            pool.protocol = venue;
            assert_eq!(
                carries_v3(&pool),
                matches!(id, "univ3" | "sushiv3" | "pancakev3"),
                "{id} pool"
            );
            let algebra = V3Pool {
                algebra: Some(AlgebraMeta {
                    fee_0to1_ppm: 500,
                    fee_1to0_ppm: 500,
                }),
                ..pool.clone()
            };
            assert!(!carries_v3(&algebra), "{id} pool with Algebra state");
            pool.v4 = Some(v4_state());
            assert!(!carries_v3(&pool), "{id} pool with V4 state");
            let mut pair = v2(Q1, 1).0;
            pair.protocol = venue;
            assert_eq!(
                carries_v2(&pair),
                matches!(id, "univ2" | "sushiv2" | "pancakev2"),
                "{id} pair"
            );
        }
    }

    /// Every venue the BSC and Ethereum tables list, as the reader gets its
    /// pools: a V2 venue's pairs, a V3 venue's pools, and V4's pools with
    /// their PoolManager state. Each is carried exactly when the rule above
    /// carries its id.
    #[test]
    fn the_bsc_and_ethereum_table_venues_are_carried_by_the_same_rule() {
        for profile in [&*BSC_PROFILE, &*ETHEREUM_PROFILE] {
            let table = profile.indexed_discovery().expect("a venue table");
            for venue in table.venues {
                let id = venue.protocol().as_str();
                let (carried, want) = match *venue {
                    CatalogVenue::V2 { protocol, .. } => {
                        let mut pair = v2(Q1, 1).0;
                        pair.protocol = protocol;
                        (
                            carries_v2(&pair),
                            matches!(id, "univ2" | "sushiv2" | "pancakev2"),
                        )
                    }
                    CatalogVenue::V3 {
                        protocol,
                        verify_pool_spacing,
                        ..
                    } => {
                        let mut pool = v3(P1, 1).0;
                        pool.protocol = protocol;
                        pool.verify_pool_spacing = verify_pool_spacing;
                        (
                            carries_v3(&pool),
                            matches!(id, "univ3" | "sushiv3" | "pancakev3"),
                        )
                    }
                    CatalogVenue::V4 { protocol, .. } => {
                        let mut pool = v3(P1, 1).0;
                        pool.protocol = protocol;
                        pool.v4 = Some(v4_state());
                        (carries_v3(&pool), false)
                    }
                };
                assert_eq!(carried, want, "{} {id}", profile.key);
            }
        }
    }

    #[test]
    fn blocks_link_to_the_last_read_or_are_refused() {
        let last = block(10);
        let b11 = header(11, last.hash);
        let b12 = header(12, b11.block.hash);
        let head = header(13, b12.block.hash);
        let blocks = linked(&last, &[b11, b12], &head).unwrap();
        assert_eq!(
            blocks.iter().map(|b| b.number).collect::<Vec<_>>(),
            [11, 12, 13]
        );
        assert_eq!(
            linked(&last, &[], &header(11, last.hash)).unwrap(),
            [block(11)]
        );
        // A sibling of the last read, a broken link, a missing block.
        assert!(linked(&last, &[], &header(11, B256::repeat_byte(0xee))).is_none());
        assert!(linked(&last, &[b11, header(12, B256::ZERO)], &head).is_none());
        assert!(linked(&last, &[b11], &head).is_none());
    }

    #[test]
    fn a_log_marks_its_pool_and_another_blocks_log_refuses_the_answer() {
        let at = block(11);
        let pools = set(&[P1, P2]);
        let changed = logged(&[log(P1, &at), log(STRANGER, &at)], &at, &pools).unwrap();
        assert_eq!(changed, set(&[P1]));
        assert!(logged(&[log(P2, &block(12))], &at, &pools).is_err());
        let removed = json!({"address": P2, "blockHash": at.hash, "removed": true});
        assert!(logged(&[removed], &at, &pools).is_err());
        assert!(logged(&[json!({"address": P2})], &at, &pools).is_err());
    }

    #[test]
    fn silent_pools_are_carried_with_their_memo_and_the_rest_are_read() {
        let first = snapshot(vec![v3(P1, 100), v3(P2, 200)], vec![v2(Q1, 7)]);
        // P3 was covered but left out (uninitialized).
        let last = LastRead::new(
            block(10),
            set(&[P1, P2, P3, Q1]),
            &first.v3,
            &first.v2,
            Instant::now(),
        );
        let list_v3: Vec<V3Pool> = [P1, P2, P3].map(|a| v3(a, 0).0).to_vec();
        let list_v2 = vec![v2(Q1, 0).0];
        let listed = set(&[P1, P2, P3, Q1]);
        let changed = set(&[P2]);
        let read = to_read(&listed, &last, &changed);
        assert_eq!(read, set(&[P2]));
        let fresh = snapshot(vec![v3(P2, 250)], Vec::new());
        let (merged_v3, merged_v2) = merge(&list_v3, &list_v2, &read, &fresh, &last);
        let prices: Vec<(Address, U256)> = merged_v3
            .iter()
            .map(|(pool, state)| (pool.address, state.sqrt_price))
            .collect();
        assert_eq!(prices, [(P1, U256::from(100)), (P2, U256::from(250))]);
        assert_eq!(merged_v2[0].1.reserve0, U256::from(7));
        // The carried state is the same tick list, memo and all.
        assert!(std::ptr::eq(
            &merged_v3[0].1.ticks[0],
            &last.v3[&P1].1.ticks[0]
        ));
        // A pool new to the list is read though it logged nothing.
        let wider = set(&[P1, P2, P3, Q1, STRANGER]);
        assert_eq!(to_read(&wider, &last, &set(&[])), set(&[STRANGER]));
    }

    #[test]
    fn the_audit_finds_a_silent_pool_that_moved() {
        let first = snapshot(vec![v3(P1, 100), v3(P2, 200)], vec![v2(Q1, 7)]);
        let last = LastRead::new(
            block(10),
            set(&[P1, P2, P3, Q1]),
            &first.v3,
            &first.v2,
            Instant::now(),
        );
        let listed = set(&[P1, P2, P3, Q1]);
        // P2 logged and moved; Q1 moved without a log; P3 appeared silently.
        let whole = snapshot(vec![v3(P1, 100), v3(P2, 999), v3(P3, 5)], vec![v2(Q1, 8)]);
        let (checked, drifted) = audit(&last, &set(&[P2]), &whole, &listed);
        assert_eq!(checked, 3);
        assert_eq!(drifted, [P3, Q1]);
        let same = snapshot(vec![v3(P1, 100), v3(P2, 999)], vec![v2(Q1, 7)]);
        assert_eq!(audit(&last, &set(&[P2]), &same, &listed), (3, Vec::new()));
    }
}
