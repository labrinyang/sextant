//! Venue ids: the protocol id every wire already carries (`univ2`,
//! `pancakev3`, `sushiv3`, ...). A venue is data: a chain's manifest names its
//! venues and each one's pool family. What a venue *does* is decided by its
//! family and its deployment (factory, fee, Settler fork), never by its id,
//! except for the few legacy ids whose pools carry their own state shape
//! (`UP33V2`, `UP33CL`, `SHERIFF`, `UNIV4`).
//!
//! Each id has a small rank, stable within a process: the ids compiled here
//! keep the ranks the solver has always used, and an id a manifest adds is
//! ranked after them in load order. Ranks order pools in caches and fill
//! protocol bitmasks, so there are at most [`MAX_VENUES`] ids.

use std::fmt;
use std::sync::Mutex;

/// The most venue ids a process may know: a protocol bitmask is a `u32`.
pub const MAX_VENUES: usize = 32;

/// The code a venue's pools run. Each id compiled here carries its own; an id
/// added at run time is [`Core::Unreviewed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Core {
    /// Uniswap V2's pair: constant product, under the fee its venue charges.
    UniV2,
    /// Up33's Solidly-style pair, whose fee is set per pool.
    Up33V2,
    /// Uniswap V3's pool, or PancakeSwap V3's, which differs only in its
    /// `Swap` event.
    UniV3,
    /// Up33's Slipstream-style concentrated-liquidity pool, which reports its
    /// own fee.
    Up33Cl,
    /// A Uniswap V3 clone: only its swap math is known to be Uniswap V3's.
    V3Clone,
    /// Algebra Integral: Uniswap V3's math, with a fee per direction from its
    /// plugin and the initialized ticks in a linked list.
    Algebra,
    /// Uniswap V4's singleton PoolManager, which keeps each pool's state under
    /// its PoolKey hash and charges a fee per direction.
    UniV4,
    /// Code nobody reviewed: the core of every id added at run time.
    Unreviewed,
}

#[derive(PartialEq, Eq, Hash)]
pub struct VenueName {
    id: &'static str,
    rank: u8,
    core: Core,
}

/// A venue id. Cheap to copy and compare.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VenueId(&'static VenueName);

macro_rules! known {
    ($($name:ident = $id:literal, $rank:literal, $core:expr;)*) => {
        impl VenueId {
            $(pub const $name: Self = Self(&VenueName { id: $id, rank: $rank, core: $core });)*
        }
        const KNOWN: &[VenueId] = &[$(VenueId::$name),*];
    };
}

known! {
    UNIV2 = "univ2", 0, Core::UniV2;
    UNIV3 = "univ3", 1, Core::UniV3;
    PANCAKEV2 = "pancakev2", 2, Core::UniV2;
    PANCAKEV3 = "pancakev3", 3, Core::UniV3;
    UNIV4 = "univ4", 4, Core::UniV4;
    UP33V2 = "up33v2", 5, Core::Up33V2;
    UP33CL = "up33cl", 6, Core::Up33Cl;
    SWAPHOODV3 = "swaphoodv3", 7, Core::V3Clone;
    GIGADEXV3 = "gigadexv3", 8, Core::V3Clone;
    SUSHIV3 = "sushiv3", 9, Core::UniV3;
    ROBINSWAPV3 = "robinswapv3", 10, Core::V3Clone;
    SHERIFF = "sheriff", 11, Core::Algebra;
    SUSHIV2 = "sushiv2", 12, Core::UniV2;
}

/// Ids added at run time, after the known ones.
static ADDED: Mutex<Vec<VenueId>> = Mutex::new(Vec::new());

impl VenueId {
    pub const fn as_str(self) -> &'static str {
        self.0.id
    }

    pub const fn rank(self) -> u8 {
        self.0.rank
    }

    /// This id's bit in a protocol mask.
    pub const fn bit(self) -> u32 {
        1 << self.0.rank
    }

    /// The code this venue's pools run.
    pub const fn core(self) -> Core {
        self.0.core
    }

    /// The id already known by this name, compiled or added.
    pub fn known(id: &str) -> Option<Self> {
        KNOWN
            .iter()
            .copied()
            .find(|venue| venue.as_str() == id)
            .or_else(|| {
                ADDED
                    .lock()
                    .expect("venue ids")
                    .iter()
                    .copied()
                    .find(|venue| venue.as_str() == id)
            })
    }

    /// The id by this name, added if it is new. An id is 1 to 32 lowercase
    /// letters and digits, starting with a letter. An added id's core is
    /// [`Core::Unreviewed`].
    pub fn intern(id: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=32).contains(&id.len())
                && id.starts_with(|c: char| c.is_ascii_lowercase())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "venue id {id:?} must be 1 to 32 lowercase letters and digits"
        );
        if let Some(known) = Self::known(id) {
            return Ok(known);
        }
        let mut added = ADDED.lock().expect("venue ids");
        if let Some(known) = added.iter().copied().find(|venue| venue.as_str() == id) {
            return Ok(known);
        }
        let rank = KNOWN.len() + added.len();
        anyhow::ensure!(
            rank < MAX_VENUES,
            "more than {MAX_VENUES} venue ids; {id} cannot be added"
        );
        let name: &'static VenueName = Box::leak(Box::new(VenueName {
            id: Box::leak(id.to_owned().into_boxed_str()),
            rank: rank as u8,
            core: Core::Unreviewed,
        }));
        let venue = Self(name);
        added.push(venue);
        Ok(venue)
    }
}

impl PartialOrd for VenueId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// By rank: the order the solver has always sorted protocols in.
impl Ord for VenueId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Debug for VenueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for VenueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ids_keep_their_ranks_and_new_ones_follow() {
        assert_eq!(VenueId::UNIV2.rank(), 0);
        assert_eq!(VenueId::UNIV4.rank(), 4);
        assert_eq!(VenueId::known("pancakev3"), Some(VenueId::PANCAKEV3));
        assert_eq!(VenueId::intern("univ3").unwrap(), VenueId::UNIV3);
        let added = VenueId::intern("venuetestonly").unwrap();
        assert!(added.rank() as usize >= KNOWN.len());
        assert_eq!(VenueId::intern("venuetestonly").unwrap(), added);
        assert_eq!(added.as_str(), "venuetestonly");
        for bad in ["", "Univ2", "2swap", "sushi-v2", &"a".repeat(33)] {
            assert!(VenueId::intern(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn known_ids_are_unique() {
        for (index, venue) in KNOWN.iter().enumerate() {
            assert_eq!(venue.rank() as usize, index);
            assert!(
                KNOWN[..index]
                    .iter()
                    .all(|other| other.as_str() != venue.as_str())
            );
        }
    }

    /// Every compiled id, in rank order, with the code its pools run.
    #[test]
    fn cores_by_id() {
        let cores: Vec<(&str, Core)> = KNOWN
            .iter()
            .map(|venue| (venue.as_str(), venue.core()))
            .collect();
        assert_eq!(
            cores,
            [
                ("univ2", Core::UniV2),
                ("univ3", Core::UniV3),
                ("pancakev2", Core::UniV2),
                ("pancakev3", Core::UniV3),
                ("univ4", Core::UniV4),
                ("up33v2", Core::Up33V2),
                ("up33cl", Core::Up33Cl),
                ("swaphoodv3", Core::V3Clone),
                ("gigadexv3", Core::V3Clone),
                ("sushiv3", Core::UniV3),
                ("robinswapv3", Core::V3Clone),
                ("sheriff", Core::Algebra),
                ("sushiv2", Core::UniV2),
            ]
        );
    }

    /// An id a manifest adds runs no reviewed code. A compiled id that a
    /// manifest names, as Ethereum's names sushiv2, is the compiled id, with
    /// its rank and its core.
    #[test]
    fn interned_ids_are_unreviewed() {
        let added = VenueId::intern("unknownvenue").unwrap();
        assert_eq!(added.core(), Core::Unreviewed);
        assert!(added.rank() as usize >= KNOWN.len());
        let sushiv2 = VenueId::intern("sushiv2").unwrap();
        assert_eq!(sushiv2, VenueId::SUSHIV2);
        assert_eq!((sushiv2.rank(), sushiv2.core()), (12, Core::UniV2));
    }
}
