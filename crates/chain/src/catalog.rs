//! Declarative venue table for indexer-backed EVM chains.
//!
//! A chain profile selects reusable protocol adapters here; the solver core
//! does not branch on the chain name.  A pair's candidate pools come from the
//! table's `CandidateSource`: a topology indexer, which is an identity-only
//! candidate source, or the venues' own factories.  Either way `state`
//! re-proves every venue through `identity()` at a canonical RPC block before
//! QuoteLens reads mutable state.

use crate::venue::Core;
use alloy_primitives::Address;
use anyhow::{Context, ensure};

/// A catalog venue's id (`crate::venue::VenueId`). A venue's pool family is
/// its `CatalogVenue` variant, not its id: adding a chain that deploys these
/// families needs only a manifest. A genuinely new pool family is a separate,
/// reviewed adapter change.
pub type CatalogProtocol = crate::venue::VenueId;

/// The venue ids indexer schema v2 can carry. The wire's catalog and factory
/// rows are closed structs keyed by these names, so a manifest naming anything
/// else would request a protocol no indexer answer can cover.
pub const SCHEMA_V2_VENUES: [CatalogProtocol; 5] = [
    CatalogProtocol::UNIV2,
    CatalogProtocol::UNIV3,
    CatalogProtocol::PANCAKEV2,
    CatalogProtocol::PANCAKEV3,
    CatalogProtocol::UNIV4,
];

/// One reusable quote-state adapter plus its chain deployment identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogVenue {
    /// Uniswap-v2-compatible constant-product pair.
    V2 {
        protocol: CatalogProtocol,
        factory: Address,
        fee_ppm: u32,
        quote: bool,
    },
    /// Uniswap-v3-compatible concentrated-liquidity pool.
    V3 {
        protocol: CatalogProtocol,
        factory: Address,
        /// Some forks expose immutable tickSpacing on the pool as well as the
        /// factory.  QuoteLens re-reads it when this is true.
        verify_pool_spacing: bool,
        /// The fees `getPool` is asked at when the factories name a pair's
        /// candidates (`CandidateSource::Factories`): every tier the factory
        /// has enabled, ascending. Empty when an indexer names them, because
        /// the catalog carries each pool's fee.
        fee_tiers: &'static [u32],
        quote: bool,
    },
    /// Uniswap v4 singleton.  It can be catalogued before its quote/execution
    /// adapter is enabled for a chain.
    V4 {
        protocol: CatalogProtocol,
        pool_manager: Address,
        /// StateLibrary's pools mapping slot for this reviewed deployment.
        /// Standard Uniswap v4 deployments use slot 6; keeping it on the
        /// venue makes state reads chain-declarative instead of global.
        pools_slot: u64,
        quote: bool,
    },
}

impl CatalogVenue {
    pub const fn protocol(self) -> CatalogProtocol {
        match self {
            Self::V2 { protocol, .. } | Self::V3 { protocol, .. } | Self::V4 { protocol, .. } => {
                protocol
            }
        }
    }

    pub const fn identity(self) -> Address {
        match self {
            Self::V2 { factory, .. } | Self::V3 { factory, .. } => factory,
            Self::V4 { pool_manager, .. } => pool_manager,
        }
    }

    pub const fn quote_enabled(self) -> bool {
        match self {
            Self::V2 { quote, .. } | Self::V3 { quote, .. } | Self::V4 { quote, .. } => quote,
        }
    }

    pub const fn v2_fee_ppm(self) -> Option<u32> {
        match self {
            Self::V2 { fee_ppm, .. } => Some(fee_ppm),
            Self::V3 { .. } | Self::V4 { .. } => None,
        }
    }

    pub const fn verify_pool_spacing(self) -> bool {
        matches!(
            self,
            Self::V3 {
                verify_pool_spacing: true,
                ..
            }
        )
    }

    pub const fn fee_tiers(self) -> &'static [u32] {
        match self {
            Self::V3 { fee_tiers, .. } => fee_tiers,
            Self::V2 { .. } | Self::V4 { .. } => &[],
        }
    }
}

/// Who names a pair's candidate pools before `state` proves them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateSource {
    /// A schema-v2 topology indexer (`SOLVER_INDEXER_URL`).
    Indexer,
    /// The venues' own factories, asked at the quote's canonical block:
    /// `getPair` for each V2 venue and `getPool` at each of a V3 venue's
    /// `fee_tiers`. A pool exists only through its factory, so this names
    /// every pool the venues hold for the pairs it is asked about. It cannot
    /// say which other tokens hold pools, so dynamic connectors need an
    /// indexer, and a V4 singleton's pools cannot be listed this way at all.
    Factories,
}

/// Complete topology contract for one indexer-backed chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessPolicy {
    /// Every catalog carried by the wire contract must be healthy. Useful for
    /// a snapshot/bootstrap contract whose generations advance atomically.
    WholeContract,
    /// Only configured venues must be healthy. Intended for future generic
    /// catalog deployments with independently advancing protocol streams.
    ConfiguredVenues,
    /// Validate only the protocol scope echoed by the topology response. This
    /// prevents an unquoted permissionless catalog (for example V4) from
    /// exhausting the capacity or readiness budget of V2/V3 quotes.
    RequestedVenues,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexedEvmDiscovery {
    /// The indexer's wire schema and readiness contract. Unread when the
    /// factories name the candidates.
    pub schema_version: u32,
    pub readiness: ReadinessPolicy,
    pub venues: &'static [CatalogVenue],
    pub candidates: CandidateSource,
}

impl IndexedEvmDiscovery {
    pub fn venue(self, protocol: CatalogProtocol) -> Option<CatalogVenue> {
        self.venues
            .iter()
            .copied()
            .find(|venue| venue.protocol() == protocol)
    }

    pub fn quote_protocols(self) -> Vec<CatalogProtocol> {
        self.venues
            .iter()
            .copied()
            .filter(|venue| venue.quote_enabled())
            .map(CatalogVenue::protocol)
            .collect()
    }

    pub fn validate(self) -> anyhow::Result<()> {
        ensure!(!self.venues.is_empty(), "indexed discovery has no venues");
        ensure!(self.schema_version > 0, "indexed schema version is zero");
        for (index, venue) in self.venues.iter().enumerate() {
            let protocol = venue.protocol();
            let core = protocol.core();
            ensure!(
                self.venues[..index]
                    .iter()
                    .all(|other| other.protocol() != protocol),
                "indexed venue {protocol} is listed twice"
            );
            // These cores select their own pool state shape wherever a pool is
            // read; a table venue of another family must not borrow one.
            ensure!(
                !matches!(core, Core::Up33V2 | Core::Up33Cl | Core::Algebra),
                "{protocol} is not a table venue"
            );
            ensure!(
                venue.identity() != Address::ZERO,
                "{} venue identity is zero",
                protocol.as_str()
            );
            match *venue {
                CatalogVenue::V2 { fee_ppm, .. } => {
                    ensure!(
                        core != Core::UniV4,
                        "{} is not a v2 protocol",
                        protocol.as_str()
                    );
                    ensure!(
                        fee_ppm > 0 && fee_ppm < 1_000_000 && fee_ppm % 100 == 0,
                        "{} has an invalid v2 fee",
                        protocol.as_str()
                    );
                }
                CatalogVenue::V3 {
                    fee_tiers, quote, ..
                } => {
                    ensure!(
                        core != Core::UniV4,
                        "{} is not a v3 protocol",
                        protocol.as_str()
                    );
                    match self.candidates {
                        CandidateSource::Indexer => ensure!(
                            fee_tiers.is_empty(),
                            "{} lists fee tiers, but an indexer names its pools",
                            protocol.as_str()
                        ),
                        CandidateSource::Factories => {
                            ensure!(
                                !quote || !fee_tiers.is_empty(),
                                "{} has no fee tier to ask its factory at",
                                protocol.as_str()
                            );
                            ensure!(
                                fee_tiers.windows(2).all(|pair| pair[0] < pair[1]),
                                "{} fee tiers must be unique and ascending",
                                protocol.as_str()
                            );
                            ensure!(
                                fee_tiers.iter().all(|fee| *fee < 1_000_000),
                                "{} has a fee tier a V3 factory cannot enable",
                                protocol.as_str()
                            );
                        }
                    }
                }
                CatalogVenue::V4 { quote, .. } => {
                    ensure!(
                        core == Core::UniV4,
                        "{} is not a v4 protocol",
                        protocol.as_str()
                    );
                    ensure!(
                        !quote || self.candidates == CandidateSource::Indexer,
                        "a V4 singleton's pools cannot be named by a factory; quoting univ4 \
                         needs an indexer"
                    );
                }
            }
        }
        ensure!(
            self.venues.iter().any(|venue| venue.quote_enabled()),
            "indexed discovery has no quote-enabled venues"
        );
        Ok(())
    }

    pub fn require_venue(self, protocol: CatalogProtocol) -> anyhow::Result<CatalogVenue> {
        self.venue(protocol).with_context(|| {
            format!(
                "indexer returned unconfigured protocol {}",
                protocol.as_str()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn venue_table_is_ordered_unique_and_family_safe() {
        const GOOD: IndexedEvmDiscovery = IndexedEvmDiscovery {
            schema_version: 1,
            readiness: ReadinessPolicy::ConfiguredVenues,
            venues: &[
                CatalogVenue::V2 {
                    protocol: CatalogProtocol::UNIV2,
                    factory: address!("0000000000000000000000000000000000000001"),
                    fee_ppm: 3_000,
                    quote: true,
                },
                CatalogVenue::V3 {
                    protocol: CatalogProtocol::UNIV3,
                    factory: address!("0000000000000000000000000000000000000002"),
                    verify_pool_spacing: false,
                    fee_tiers: &[],
                    quote: true,
                },
            ],
            candidates: CandidateSource::Indexer,
        };
        GOOD.validate().unwrap();
        assert_eq!(
            GOOD.quote_protocols(),
            vec![CatalogProtocol::UNIV2, CatalogProtocol::UNIV3]
        );

        const DUPLICATE_VENUES: [CatalogVenue; 2] = [GOOD.venues[0], GOOD.venues[0]];
        let duplicate = IndexedEvmDiscovery {
            venues: &DUPLICATE_VENUES,
            ..GOOD
        };
        assert!(duplicate.validate().is_err());

        const QUOTED_V4: IndexedEvmDiscovery = IndexedEvmDiscovery {
            schema_version: 1,
            readiness: ReadinessPolicy::RequestedVenues,
            venues: &[CatalogVenue::V4 {
                protocol: CatalogProtocol::UNIV4,
                pool_manager: address!("0000000000000000000000000000000000000003"),
                pools_slot: 6,
                quote: true,
            }],
            candidates: CandidateSource::Indexer,
        };
        QUOTED_V4.validate().unwrap();
        assert_eq!(QUOTED_V4.quote_protocols(), vec![CatalogProtocol::UNIV4]);
    }

    fn v3_at(fee_tiers: &'static [u32]) -> CatalogVenue {
        CatalogVenue::V3 {
            protocol: CatalogProtocol::UNIV3,
            factory: address!("0000000000000000000000000000000000000002"),
            verify_pool_spacing: false,
            fee_tiers,
            quote: true,
        }
    }

    fn factories(venues: &'static [CatalogVenue]) -> IndexedEvmDiscovery {
        IndexedEvmDiscovery {
            schema_version: 2,
            readiness: ReadinessPolicy::RequestedVenues,
            venues,
            candidates: CandidateSource::Factories,
        }
    }

    #[test]
    fn factory_candidates_need_each_quoted_v3_tier_and_no_quoted_v4() {
        let good = factories(vec![v3_at(&[100, 500, 3_000, 10_000])].leak());
        good.validate().unwrap();
        assert_eq!(good.venues[0].fee_tiers(), &[100, 500, 3_000, 10_000][..]);

        for bad in [&[][..], &[500, 100], &[500, 500], &[1_000_000]] {
            let table = factories(vec![v3_at(bad)].leak());
            assert!(table.validate().is_err(), "{bad:?}");
        }

        // An indexer carries each pool's fee, so a tier list there would be a
        // second, unread source of truth.
        let indexed = IndexedEvmDiscovery {
            candidates: CandidateSource::Indexer,
            ..good
        };
        assert!(indexed.validate().is_err());

        let v4 = factories(
            vec![
                v3_at(&[500]),
                CatalogVenue::V4 {
                    protocol: CatalogProtocol::UNIV4,
                    pool_manager: address!("0000000000000000000000000000000000000003"),
                    pools_slot: 6,
                    quote: true,
                },
            ]
            .leak(),
        );
        let error = v4.validate().unwrap_err();
        assert!(error.to_string().contains("needs an indexer"), "{error:#}");
    }

    /// Every venue by name: the ids compiled in `crate::venue`, then sushiv2
    /// and an id no build knows, both interned as a manifest interns its ids.
    fn venues() -> Vec<CatalogProtocol> {
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
        .map(|id| CatalogProtocol::known(id).expect("a compiled id"));
        let interned = ["sushiv2", "unknownvenue"].map(|id| CatalogProtocol::intern(id).unwrap());
        [compiled.as_slice(), interned.as_slice()].concat()
    }

    /// Every venue by name as a one-venue table of each family. up33v2,
    /// up33cl and sheriff pick their own pool state wherever a pool is read,
    /// so no table lists them; univ4 is the V4 singleton's id and no other's;
    /// and a V2 or V3 entry takes any other id, so a {v2, univ3} entry loads.
    #[test]
    fn validate_by_venue_and_family() {
        let identity = address!("0000000000000000000000000000000000000001");
        for protocol in venues() {
            let id = protocol.as_str();
            for (family, venue) in [
                (
                    "v2",
                    CatalogVenue::V2 {
                        protocol,
                        factory: identity,
                        fee_ppm: 3_000,
                        quote: true,
                    },
                ),
                (
                    "v3",
                    CatalogVenue::V3 {
                        protocol,
                        factory: identity,
                        verify_pool_spacing: false,
                        fee_tiers: &[],
                        quote: true,
                    },
                ),
                (
                    "v4",
                    CatalogVenue::V4 {
                        protocol,
                        pool_manager: identity,
                        pools_slot: 6,
                        quote: true,
                    },
                ),
            ] {
                let table = IndexedEvmDiscovery {
                    schema_version: 1,
                    readiness: ReadinessPolicy::RequestedVenues,
                    venues: vec![venue].leak(),
                    candidates: CandidateSource::Indexer,
                };
                let want = match (id, family) {
                    ("up33v2" | "up33cl" | "sheriff", _) => {
                        Err(format!("{id} is not a table venue"))
                    }
                    ("univ4", "v4") => Ok(()),
                    ("univ4", _) | (_, "v4") => Err(format!("{id} is not a {family} protocol")),
                    _ => Ok(()),
                };
                assert_eq!(
                    table.validate().map_err(|error| error.to_string()),
                    want,
                    "{id} as a {family} entry"
                );
            }
        }
    }
}
