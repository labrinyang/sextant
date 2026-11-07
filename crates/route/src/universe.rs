//! Immutable route-search scope shared by discovery, simulation, and proofs.
//!
//! Pool catalogs may suggest additional token skeletons, but they never supply
//! executable identity or mutable state.  Keeping the exact skeletons and pair
//! order here prevents discovery, routing, and certification from silently
//! operating on different graphs.

use crate::chain::{ChainProfile, MAX_ROUTE_HOPS, route_token_paths_for};
use crate::topology::{CatalogFences, ConnectorSelection, ConnectorSelector, MAX_PAIRS, Protocol};
use alloy_primitives::{Address, B256, keccak256};
use anyhow::{Context, ensure};

/// The largest dynamic connector count any chain profile may admit, and the
/// ceiling this module asserts. What a given pair actually admits is
/// `ChainProfile::dynamic_connector_cap` bounded by that chain's pair budget;
/// this is the structural limit both must stay under, checked by a test in
/// `chain.rs` so a profile can never raise its cap past what routing accepts.
pub const MAX_DYNAMIC_CONNECTORS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackKind {
    Transport,
    Conflict,
    Capacity,
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSearchScope {
    CommonNeighborTwoHop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteUniverseSource {
    ProfileOnly,
    AdjacencyComplete {
        fences: CatalogFences,
        protocols: Vec<Protocol>,
        connectors: Vec<Address>,
        eligible_count: usize,
        shortlist_truncated: bool,
        scope: RouteSearchScope,
        selector: ConnectorSelector,
    },
    AdjacencyFallback {
        reason: FallbackKind,
    },
    /// Every pool on the resident list, read each block, routed through the
    /// resident connector set rather than the profile's.
    Resident,
}

/// Pairs a resident universe may span. It asks no indexer, so the indexer's
/// `MAX_PAIRS` request ceiling does not bind it; this bounds the route search
/// instead. The profile's three static connectors take ten with both
/// endpoints, and skeletons the list admits by their pools may use the rest.
/// Which of those a quote routes is decided by probing them, not by this
/// ceiling (`resident::Widening`); one it leaves out is counted.
pub const RESIDENT_MAX_PAIRS: usize = 36;

#[derive(Clone, Debug, Eq, PartialEq)]
enum ShadowObservation {
    Complete {
        fences: CatalogFences,
        protocols: Vec<Protocol>,
        connector_count: usize,
        eligible_count: usize,
        shortlist_truncated: bool,
        screened: Vec<Address>,
        selector: ConnectorSelector,
    },
    Fallback {
        reason: FallbackKind,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteUniverse {
    chain_id: u64,
    profile_key: &'static str,
    endpoints: (Address, Address),
    source: RouteUniverseSource,
    static_connectors: Vec<Address>,
    token_paths: Vec<Vec<Address>>,
    pairs: Vec<(Address, Address)>,
    /// Pairs whose state is read for pricing and never for routing.
    ///
    /// These are deliberately absent from `token_paths` and `pairs`, which is
    /// what makes them unreachable rather than merely unused: route
    /// preparation builds its edge index from `token_paths`, so a pool on one
    /// of these pairs yields no `Hop`, and the certificate's plan-membership
    /// check requires every leg's skeleton to appear in `token_paths`. The
    /// fingerprint covers them so a screened universe is never confused with
    /// an unscreened one.
    screening_pairs: Vec<(Address, Address)>,
    /// The tokens `screening_pairs` was derived from, retained so `orient` can
    /// rebuild the same set for the reversed direction.
    screened: Vec<Address>,
    /// This chain's topology pair budget, retained for the same reason: `orient`
    /// rebuilds the universe and must spend the budget it was built under.
    pair_budget: usize,
    /// Skeletons through connectors the resident list admits by their pools
    /// (`resident::ListedGraph`), in this universe's direction: on the per-pair
    /// path, the resident's connectors beyond the profile's. They are also in
    /// `token_paths`; kept apart so `orient` can reverse them.
    listed_paths: Vec<Vec<Address>>,
    fingerprint: B256,
    shadow: Option<ShadowObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteUniverseDiagnostics {
    pub source: &'static str,
    pub fallback_stage: Option<&'static str>,
    pub fallback_reason: Option<&'static str>,
    /// Token-path domain whose pool states were materialized and can therefore
    /// be covered by a quote certificate.
    pub scope: &'static str,
    /// Which selector produced the candidates. The search shape is the same
    /// two-hop question either way; what differs is whether the candidates came
    /// from enumerating both endpoints or from the indexer's depth ranking.
    pub selector: &'static str,
    /// Candidate-selection domain observed by the adjacency stage. In shadow
    /// mode this can be wider than `scope`, but it never widens the certificate.
    pub selection_scope: &'static str,
    pub protocol_mask: u32,
    pub eligible_count: usize,
    /// Connectors beyond the profile's static ones: those the adjacency
    /// stage admitted, and those the resident list admits by their pools.
    pub connector_count: usize,
    pub shortlist_truncated: bool,
    /// Connector tokens whose pools were priced without being made routable.
    /// Zero means the coverage question went unmeasured for this quote.
    pub screened_count: usize,
    pub adjacency_fences: Option<CatalogFences>,
    pub fingerprint: B256,
}

impl RouteUniverse {
    pub fn profile_only(
        profile: &ChainProfile,
        token_in: Address,
        token_out: Address,
    ) -> anyhow::Result<Self> {
        Self::from_parts(
            (token_in, token_out),
            RouteUniverseSource::ProfileOnly,
            profile.chain_id,
            profile.key,
            profile.connectors.to_vec(),
            route_token_paths_for(profile.connectors, token_in, token_out),
            &[],
            profile.topology_pair_budget,
        )
    }

    /// The resident graph for one pair: the direct pool, every skeleton
    /// through the static `connectors`, and the skeletons in `listed`, through
    /// connectors the list admits by their pools, that fit within
    /// `RESIDENT_MAX_PAIRS`. Its pair budget is what those skeletons use.
    pub fn resident(
        profile: &ChainProfile,
        connectors: &[Address],
        listed: &[Vec<Address>],
        token_in: Address,
        token_out: Address,
    ) -> anyhow::Result<Self> {
        let k = connectors.len();
        let mut token_paths = route_token_paths_for(connectors, token_in, token_out);
        let listed = fit_listed(&token_paths, listed, RESIDENT_MAX_PAIRS);
        token_paths.extend(listed.iter().cloned());
        let budget = ((k + 2) * (k + 1) / 2).max(pairs_from_paths(&token_paths)?.len());
        let mut universe = Self::from_parts(
            (token_in, token_out),
            RouteUniverseSource::Resident,
            profile.chain_id,
            profile.key,
            connectors.to_vec(),
            token_paths,
            &[],
            budget,
        )?;
        universe.listed_paths = listed;
        Ok(universe)
    }

    /// This universe with the skeletons in `listed` added, as many as fit
    /// within the indexer's `MAX_PAIRS`. The per-pair path takes them from the
    /// resident list, which knows the pools of the resident's other
    /// connectors; the resident graph builds its own.
    pub fn with_listed(self, listed: &[Vec<Address>]) -> anyhow::Result<Self> {
        if listed.is_empty() || self.is_resident() {
            return Ok(self);
        }
        let listed = fit_listed(&self.token_paths, listed, MAX_PAIRS);
        if listed.is_empty() {
            return Ok(self);
        }
        let mut token_paths = self.token_paths.clone();
        token_paths.extend(listed.iter().cloned());
        let budget = self.pair_budget.max(pairs_from_paths(&token_paths)?.len());
        let mut universe = Self::from_parts(
            self.endpoints,
            self.source.clone(),
            self.chain_id,
            self.profile_key,
            self.static_connectors.clone(),
            token_paths,
            &self.screened,
            budget,
        )?;
        universe.shadow = self.shadow.clone();
        universe.listed_paths = listed;
        Ok(universe)
    }

    /// Connectors beyond the static ones this universe routes through, where
    /// the resident list has their pools.
    pub fn listed_connectors(&self) -> Vec<Address> {
        let mut connectors: Vec<Address> = self
            .listed_paths
            .iter()
            .flat_map(|path| path[1..path.len() - 1].iter().copied())
            .filter(|token| !self.static_connectors.contains(token))
            .collect();
        connectors.sort_unstable();
        connectors.dedup();
        connectors
    }

    pub fn adjacency_fallback(
        profile: &ChainProfile,
        token_in: Address,
        token_out: Address,
        reason: FallbackKind,
    ) -> anyhow::Result<Self> {
        Self::from_parts(
            (token_in, token_out),
            RouteUniverseSource::AdjacencyFallback { reason },
            profile.chain_id,
            profile.key,
            profile.connectors.to_vec(),
            route_token_paths_for(profile.connectors, token_in, token_out),
            &[],
            profile.topology_pair_budget,
        )
    }

    pub fn adjacency_complete(
        profile: &ChainProfile,
        token_in: Address,
        token_out: Address,
        selection: ConnectorSelection,
    ) -> anyhow::Result<Self> {
        let ConnectorSelection {
            fences,
            protocols,
            connectors,
            screened,
            eligible_count,
            shortlist_truncated,
            selector,
        } = selection;
        ensure!(
            connectors.len() <= MAX_DYNAMIC_CONNECTORS,
            "dynamic connector count {} exceeds the {MAX_DYNAMIC_CONNECTORS} ceiling",
            connectors.len()
        );
        ensure!(
            connectors.len() <= profile.dynamic_connector_cap,
            "dynamic connector count {} exceeds {}'s cap of {}",
            connectors.len(),
            profile.key,
            profile.dynamic_connector_cap
        );
        // Empty means screening is off and no ranking was carried at all —
        // the only case where the admitted set has nothing to agree with.
        // Otherwise the work gate can still drop a connector from the middle
        // of the ranking, so the admitted set is a subsequence rather than a
        // prefix; what must hold is that it came from this ranking.
        ensure!(
            screened.is_empty()
                || connectors
                    .iter()
                    .all(|connector| screened.contains(connector)),
            "an admitted connector is absent from the screened ranking"
        );
        ensure!(!protocols.is_empty(), "dynamic protocol scope is empty");
        ensure!(
            protocols.windows(2).all(|window| window[0] < window[1]),
            "dynamic protocol scope is not strictly ordered"
        );
        ensure!(
            eligible_count >= connectors.len(),
            "eligible connector count is smaller than the admitted shortlist"
        );
        let mut seen = Vec::with_capacity(connectors.len());
        for &connector in &connectors {
            ensure!(connector != Address::ZERO, "zero cannot be a connector");
            ensure!(
                connector != token_in && connector != token_out,
                "an endpoint cannot be a connector"
            );
            ensure!(
                !profile.connectors.contains(&connector),
                "a static connector cannot be admitted dynamically"
            );
            ensure!(!seen.contains(&connector), "duplicate dynamic connector");
            seen.push(connector);
        }

        let mut token_paths = route_token_paths_for(profile.connectors, token_in, token_out);
        token_paths.extend(
            connectors
                .iter()
                .map(|&connector| vec![token_in, connector, token_out]),
        );
        Self::from_parts(
            (token_in, token_out),
            RouteUniverseSource::AdjacencyComplete {
                fences,
                protocols,
                connectors,
                eligible_count,
                shortlist_truncated,
                scope: RouteSearchScope::CommonNeighborTwoHop,
                selector,
            },
            profile.chain_id,
            profile.key,
            profile.connectors.to_vec(),
            token_paths,
            &screened,
            profile.topology_pair_budget,
        )
    }

    pub fn profile_only_shadow_complete(
        profile: &ChainProfile,
        token_in: Address,
        token_out: Address,
        selection: ConnectorSelection,
    ) -> anyhow::Result<Self> {
        let ConnectorSelection {
            fences,
            protocols,
            connectors,
            screened,
            eligible_count,
            shortlist_truncated,
            selector,
        } = selection;
        let connector_count = connectors.len();
        ensure!(
            connector_count <= MAX_DYNAMIC_CONNECTORS,
            "shadow connector count exceeds {MAX_DYNAMIC_CONNECTORS}"
        );
        ensure!(!protocols.is_empty(), "shadow protocol scope is empty");
        ensure!(
            protocols.windows(2).all(|window| window[0] < window[1]),
            "shadow protocol scope is not strictly ordered"
        );
        ensure!(
            eligible_count >= connector_count,
            "shadow eligible count is smaller than its shortlist"
        );
        // The routable graph stays profile-only; the screened ranking still
        // gets priced, which is what makes shadow an observation rather than a
        // guess. Nothing here reaches `token_paths`.
        let mut universe = Self::from_parts(
            (token_in, token_out),
            RouteUniverseSource::ProfileOnly,
            profile.chain_id,
            profile.key,
            profile.connectors.to_vec(),
            route_token_paths_for(profile.connectors, token_in, token_out),
            &screened,
            profile.topology_pair_budget,
        )?;
        universe.shadow = Some(ShadowObservation::Complete {
            fences,
            protocols,
            connector_count,
            eligible_count,
            shortlist_truncated,
            screened,
            selector,
        });
        Ok(universe)
    }

    pub fn profile_only_shadow_fallback(
        profile: &ChainProfile,
        token_in: Address,
        token_out: Address,
        reason: FallbackKind,
    ) -> anyhow::Result<Self> {
        let mut universe = Self::profile_only(profile, token_in, token_out)?;
        universe.shadow = Some(ShadowObservation::Fallback { reason });
        Ok(universe)
    }

    /// Pairs to price but never to route: both endpoint edges of every
    /// screened connector, minus anything the routable graph already covers.
    /// They travel in a request of their own, so the pair budget bounds them
    /// independently of what the skeletons spent.
    fn screening_pairs_from(
        token_in: Address,
        token_out: Address,
        screened: &[Address],
        routable: &[(Address, Address)],
        pair_budget: usize,
    ) -> Vec<(Address, Address)> {
        let mut pairs: Vec<(Address, Address)> = Vec::new();
        for &connector in screened {
            if connector == Address::ZERO || connector == token_in || connector == token_out {
                continue;
            }
            for pair in [(token_in, connector), (connector, token_out)] {
                let canonical = canonical_pair(pair.0, pair.1);
                let covered = routable
                    .iter()
                    .chain(pairs.iter())
                    .any(|&(a, b)| canonical_pair(a, b) == canonical);
                if !covered && pairs.len() < pair_budget {
                    pairs.push(pair);
                }
            }
        }
        pairs
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        endpoints: (Address, Address),
        source: RouteUniverseSource,
        chain_id: u64,
        profile_key: &'static str,
        static_connectors: Vec<Address>,
        token_paths: Vec<Vec<Address>>,
        screened: &[Address],
        pair_budget: usize,
    ) -> anyhow::Result<Self> {
        let (token_in, token_out) = endpoints;
        ensure!(token_in != token_out, "identical route-universe endpoints");
        ensure!(!token_paths.is_empty(), "empty route universe");
        for path in &token_paths {
            ensure!(
                (2..=MAX_ROUTE_HOPS + 1).contains(&path.len()),
                "route skeleton exceeds configured hop count"
            );
            ensure!(
                path.first() == Some(&token_in) && path.last() == Some(&token_out),
                "route skeleton endpoints do not match its universe"
            );
            for (index, token) in path.iter().enumerate() {
                ensure!(
                    !path[..index].contains(token),
                    "route skeleton contains a token cycle"
                );
            }
        }

        let ceiling = match source {
            RouteUniverseSource::Resident => RESIDENT_MAX_PAIRS,
            _ => MAX_PAIRS,
        };
        ensure!(
            pair_budget <= ceiling,
            "route universe pair budget {pair_budget} exceeds the {ceiling} ceiling"
        );
        let pairs = pairs_from_paths(&token_paths)?;
        ensure!(
            pairs.len() <= pair_budget,
            "route universe pair count exceeds its {pair_budget}-pair budget"
        );
        let screening_pairs =
            Self::screening_pairs_from(token_in, token_out, screened, &pairs, pair_budget);
        let fingerprint = fingerprint_universe(
            chain_id,
            profile_key,
            &source,
            &static_connectors,
            &token_paths,
            &screening_pairs,
        );
        Ok(Self {
            chain_id,
            profile_key,
            endpoints: (token_in, token_out),
            source,
            static_connectors,
            token_paths,
            pair_budget,
            pairs,
            screening_pairs,
            screened: screened.to_vec(),
            listed_paths: Vec::new(),
            fingerprint,
            shadow: None,
        })
    }

    pub fn endpoints(&self) -> (Address, Address) {
        self.endpoints
    }

    /// The chain this universe was built for.
    ///
    /// Exposed so a cache keyed on the pair rather than on the fingerprint
    /// still cannot serve one chain's verdict to another — this process serves
    /// one chain, but the test binary builds universes on both.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn source(&self) -> &RouteUniverseSource {
        &self.source
    }

    pub fn token_paths(&self) -> &[Vec<Address>] {
        &self.token_paths
    }

    /// First-seen direction is retained for byte-compatible discovery order.
    /// Consumers that require canonical pairs sort each tuple at their trust
    /// boundary.
    pub fn pairs(&self) -> &[(Address, Address)] {
        &self.pairs
    }

    /// Pairs loaded for pricing only. Disjoint from `pairs()` by construction,
    /// and absent from `token_paths()`, so no plan can be built on them.
    pub fn screening_pairs(&self) -> &[(Address, Address)] {
        &self.screening_pairs
    }

    /// Connector tokens behind `screening_pairs`, in rank order.
    pub fn screened(&self) -> &[Address] {
        &self.screened
    }

    /// Screened connectors that actually contributed a pair — the tokens
    /// priced BEYOND what this quote could reach, which is the quantity the
    /// coverage measurement is about.
    ///
    /// A connector the universe already routes through contributes no pair, so
    /// it is absent here. That exclusion is load-bearing for attribution: its
    /// value is already inside `bound`, and reporting it beside the unroutable
    /// candidates as a zero would read as "measured, worthless" when it means
    /// "measured, and being used".
    fn priced_beyond_universe_iter(&self) -> impl Iterator<Item = Address> + '_ {
        self.screened.iter().copied().filter(|connector| {
            self.screening_pairs
                .iter()
                .any(|&(a, b)| a == *connector || b == *connector)
        })
    }

    /// `priced_beyond_universe_iter` collected, in rank order.
    pub fn priced_beyond_universe(&self) -> Vec<Address> {
        self.priced_beyond_universe_iter().collect()
    }

    fn screened_beyond_universe(&self) -> usize {
        self.priced_beyond_universe_iter().count()
    }

    pub fn fingerprint(&self) -> B256 {
        self.fingerprint
    }

    pub fn diagnostics(&self) -> RouteUniverseDiagnostics {
        if let Some(shadow) = &self.shadow {
            return match shadow {
                ShadowObservation::Complete {
                    fences,
                    protocols,
                    connector_count,
                    eligible_count,
                    shortlist_truncated,
                    screened: _,
                    selector,
                } => RouteUniverseDiagnostics {
                    source: "adjacency_shadow",
                    fallback_stage: None,
                    fallback_reason: None,
                    scope: "profile",
                    selector: selector.as_str(),
                    selection_scope: "common_neighbor_two_hop",
                    protocol_mask: protocols
                        .iter()
                        .fold(0u32, |mask, protocol| mask | protocol.bit()),
                    eligible_count: *eligible_count,
                    connector_count: *connector_count,
                    shortlist_truncated: *shortlist_truncated,
                    screened_count: self.screened_beyond_universe(),
                    adjacency_fences: Some(*fences),
                    fingerprint: self.fingerprint,
                },
                ShadowObservation::Fallback { reason } => RouteUniverseDiagnostics {
                    source: "adjacency_shadow_fallback",
                    fallback_stage: Some("adjacency"),
                    fallback_reason: Some(fallback_reason(*reason)),
                    scope: "profile",
                    selector: "none",
                    selection_scope: "common_neighbor_two_hop",
                    protocol_mask: 0,
                    eligible_count: 0,
                    connector_count: 0,
                    shortlist_truncated: true,
                    screened_count: self.screened_beyond_universe(),
                    adjacency_fences: None,
                    fingerprint: self.fingerprint,
                },
            };
        }
        match &self.source {
            RouteUniverseSource::ProfileOnly => RouteUniverseDiagnostics {
                source: "profile_only",
                fallback_stage: None,
                fallback_reason: None,
                scope: "profile",
                selector: "none",
                selection_scope: "profile",
                protocol_mask: 0,
                eligible_count: 0,
                connector_count: self.listed_connectors().len(),
                shortlist_truncated: false,
                screened_count: self.screened_beyond_universe(),
                adjacency_fences: None,
                fingerprint: self.fingerprint,
            },
            RouteUniverseSource::AdjacencyComplete {
                fences,
                protocols,
                connectors,
                eligible_count,
                shortlist_truncated,
                selector,
                ..
            } => RouteUniverseDiagnostics {
                source: "adjacency_complete",
                fallback_stage: None,
                fallback_reason: None,
                scope: "common_neighbor_two_hop",
                selector: selector.as_str(),
                selection_scope: "common_neighbor_two_hop",
                protocol_mask: protocols
                    .iter()
                    .fold(0u32, |mask, protocol| mask | protocol.bit()),
                eligible_count: *eligible_count,
                connector_count: connectors.len() + self.listed_connectors().len(),
                shortlist_truncated: *shortlist_truncated,
                screened_count: self.screened_beyond_universe(),
                adjacency_fences: Some(*fences),
                fingerprint: self.fingerprint,
            },
            RouteUniverseSource::AdjacencyFallback { reason } => RouteUniverseDiagnostics {
                source: "adjacency_fallback",
                fallback_stage: Some("adjacency"),
                fallback_reason: Some(fallback_reason(*reason)),
                scope: "profile",
                selector: "none",
                selection_scope: "profile",
                protocol_mask: 0,
                eligible_count: 0,
                connector_count: self.listed_connectors().len(),
                shortlist_truncated: true,
                screened_count: self.screened_beyond_universe(),
                adjacency_fences: None,
                fingerprint: self.fingerprint,
            },
            RouteUniverseSource::Resident => RouteUniverseDiagnostics {
                source: "resident",
                fallback_stage: None,
                fallback_reason: None,
                scope: "resident",
                selector: "none",
                selection_scope: "resident",
                protocol_mask: 0,
                eligible_count: 0,
                connector_count: self.listed_connectors().len(),
                shortlist_truncated: false,
                screened_count: self.screened_beyond_universe(),
                adjacency_fences: None,
                fingerprint: self.fingerprint,
            },
        }
    }

    /// Whether this universe was built over the resident pool list.
    pub fn is_resident(&self) -> bool {
        matches!(self.source, RouteUniverseSource::Resident)
    }

    pub fn fallback_kind(&self) -> Option<FallbackKind> {
        match (&self.source, &self.shadow) {
            (RouteUniverseSource::AdjacencyFallback { reason }, _) => Some(*reason),
            (_, Some(ShadowObservation::Fallback { reason })) => Some(*reason),
            _ => None,
        }
    }

    /// Rebuild the deterministic path order for the request direction while
    /// retaining the exact catalog provenance and dynamic shortlist published
    /// with the unordered pair snapshot.
    pub fn orient(&self, token_in: Address, token_out: Address) -> anyhow::Result<Self> {
        ensure!(
            (token_in, token_out) == self.endpoints || (token_out, token_in) == self.endpoints,
            "requested direction does not match the route universe"
        );
        if (token_in, token_out) == self.endpoints {
            return Ok(self.clone());
        }
        let mut token_paths = route_token_paths_for(&self.static_connectors, token_in, token_out);
        if let RouteUniverseSource::AdjacencyComplete { connectors, .. } = &self.source {
            token_paths.extend(
                connectors
                    .iter()
                    .map(|&connector| vec![token_in, connector, token_out]),
            );
        }
        // Their order does not depend on direction (`resident::path_order`),
        // so reversed in place they are what this direction would be given.
        let listed: Vec<Vec<Address>> = self
            .listed_paths
            .iter()
            .map(|path| path.iter().rev().copied().collect())
            .collect();
        token_paths.extend(listed.iter().cloned());
        let mut oriented = Self::from_parts(
            (token_in, token_out),
            self.source.clone(),
            self.chain_id,
            self.profile_key,
            self.static_connectors.clone(),
            token_paths,
            &self.screened,
            self.pair_budget,
        )?;
        oriented.shadow = self.shadow.clone();
        oriented.listed_paths = listed;
        Ok(oriented)
    }
}

fn fallback_reason(reason: FallbackKind) -> &'static str {
    match reason {
        FallbackKind::Transport => "transport",
        FallbackKind::Conflict => "conflict",
        FallbackKind::Capacity => "capacity",
        FallbackKind::InvalidResponse => "invalid_response",
    }
}

fn fingerprint_universe(
    chain_id: u64,
    profile_key: &str,
    source: &RouteUniverseSource,
    static_connectors: &[Address],
    paths: &[Vec<Address>],
    screening_pairs: &[(Address, Address)],
) -> B256 {
    let mut encoded =
        Vec::with_capacity(64 + paths.iter().map(|path| 1 + path.len() * 20).sum::<usize>());
    encoded.push(2); // fingerprint schema
    encoded.extend_from_slice(&chain_id.to_be_bytes());
    encoded.extend_from_slice(&(profile_key.len() as u16).to_be_bytes());
    encoded.extend_from_slice(profile_key.as_bytes());
    encoded.push(static_connectors.len() as u8);
    for connector in static_connectors {
        encoded.extend_from_slice(connector.as_slice());
    }
    match source {
        RouteUniverseSource::ProfileOnly => encoded.push(0),
        RouteUniverseSource::AdjacencyComplete {
            fences,
            protocols,
            connectors,
            eligible_count,
            shortlist_truncated,
            scope,
            selector,
        } => {
            encoded.push(1);
            encoded.extend_from_slice(&fences.v23.seq.to_be_bytes());
            encoded.extend_from_slice(&fences.v23.generation.to_be_bytes());
            match fences.v4 {
                Some(v4) => {
                    encoded.push(1);
                    encoded.extend_from_slice(&v4.block.to_be_bytes());
                    encoded.extend_from_slice(v4.generation.as_slice());
                }
                None => encoded.push(0),
            }
            encoded.push(protocols.len() as u8);
            for protocol in protocols {
                encoded.push(protocol.rank());
            }
            encoded.push(connectors.len() as u8);
            for connector in connectors {
                encoded.extend_from_slice(connector.as_slice());
            }
            encoded.extend_from_slice(&(*eligible_count as u64).to_be_bytes());
            encoded.push(u8::from(*shortlist_truncated));
            encoded.push(match scope {
                RouteSearchScope::CommonNeighborTwoHop => 0,
            });
            encoded.push(match selector {
                ConnectorSelector::AdjacencyWalk => 0,
                ConnectorSelector::RankedProjection => 1,
            });
        }
        RouteUniverseSource::AdjacencyFallback { reason } => {
            encoded.push(2);
            encoded.push(match reason {
                FallbackKind::Transport => 0,
                FallbackKind::Conflict => 1,
                FallbackKind::Capacity => 2,
                FallbackKind::InvalidResponse => 3,
            });
        }
        RouteUniverseSource::Resident => encoded.push(3),
    }
    encoded.extend_from_slice(&(paths.len() as u16).to_be_bytes());
    for path in paths {
        encoded.push(path.len() as u8);
        for token in path {
            encoded.extend_from_slice(token.as_slice());
        }
    }
    // Screened pairs change what evidence the certificate saw without changing
    // what the router could reach, so they belong in the identity even though
    // they are absent from every skeleton above. Appending this length moves
    // every fingerprint, which is why the schema byte above went to 2.
    encoded.push(screening_pairs.len() as u8);
    for (token0, token1) in screening_pairs {
        encoded.extend_from_slice(token0.as_slice());
        encoded.extend_from_slice(token1.as_slice());
    }
    keccak256(encoded)
}

fn pairs_from_paths(paths: &[Vec<Address>]) -> anyhow::Result<Vec<(Address, Address)>> {
    let mut pairs = Vec::new();
    for path in paths {
        for edge in path.windows(2) {
            let pair = (*edge.first().context("missing edge input")?, edge[1]);
            let canonical = canonical_pair(pair.0, pair.1);
            if !pairs
                .iter()
                .any(|&(a, b)| canonical_pair(a, b) == canonical)
            {
                pairs.push(pair);
            }
        }
    }
    Ok(pairs)
}

fn canonical_pair(a: Address, b: Address) -> (Address, Address) {
    if a < b { (a, b) } else { (b, a) }
}

/// The skeletons of `listed` that fit beside `base` within `budget` pairs,
/// taken in order: one that would pass the budget is left out and the rest
/// are still tried. Pairs are counted unordered, so a pair and its reverse
/// keep the same skeletons.
fn fit_listed(base: &[Vec<Address>], listed: &[Vec<Address>], budget: usize) -> Vec<Vec<Address>> {
    let edges = |path: &[Address]| -> Vec<(Address, Address)> {
        path.windows(2)
            .map(|edge| canonical_pair(edge[0], edge[1]))
            .collect()
    };
    let mut pairs: std::collections::HashSet<(Address, Address)> =
        base.iter().flat_map(|path| edges(path)).collect();
    let mut kept = Vec::new();
    for path in listed {
        if base.contains(path) || kept.contains(path) {
            continue;
        }
        let added: std::collections::HashSet<(Address, Address)> = edges(path)
            .into_iter()
            .filter(|pair| !pairs.contains(pair))
            .collect();
        if pairs.len() + added.len() > budget {
            continue;
        }
        pairs.extend(added);
        kept.push(path.clone());
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{BSC_PROFILE, BSC_USD1, BSC_USDT, WBNB};
    use crate::topology::{V4Fence, V23Fence};
    use alloy_primitives::{B256, address};

    fn fences() -> CatalogFences {
        CatalogFences {
            v23: V23Fence {
                seq: 7,
                generation: 9,
            },
            v4: Some(V4Fence {
                block: 11,
                generation: B256::repeat_byte(0xaa),
            }),
        }
    }

    fn selection(
        connectors: Vec<Address>,
        eligible_count: usize,
        shortlist_truncated: bool,
    ) -> ConnectorSelection {
        ConnectorSelection {
            fences: fences(),
            protocols: vec![Protocol::UNIV2, Protocol::UNIV3],
            screened: connectors.clone(),
            connectors,
            eligible_count,
            shortlist_truncated,
            selector: ConnectorSelector::AdjacencyWalk,
        }
    }

    #[test]
    fn the_selector_that_found_a_connector_is_part_of_the_universe_identity() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let connector = address!("3333333333333333333333333333333333333333");
        let build = |selector| {
            let mut selection = selection(vec![connector], 1, false);
            selection.selector = selector;
            RouteUniverse::adjacency_complete(&BSC_PROFILE, token_in, token_out, selection).unwrap()
        };
        let walked = build(ConnectorSelector::AdjacencyWalk);
        let ranked = build(ConnectorSelector::RankedProjection);

        // Identical graphs, different provenance. Two selectors answer the same
        // question by different evidence, and a topology cached under one must
        // never be served as if the other had produced it.
        assert_eq!(walked.token_paths(), ranked.token_paths());
        assert_eq!(walked.pairs(), ranked.pairs());
        assert_ne!(walked.fingerprint(), ranked.fingerprint());
        assert_eq!(walked.diagnostics().selector, "adjacency_walk");
        assert_eq!(ranked.diagnostics().selector, "ranked_projection");
        // The search shape is the same two-hop question either way.
        assert_eq!(
            walked.diagnostics().selection_scope,
            ranked.diagnostics().selection_scope
        );
    }

    #[test]
    fn profile_only_is_the_existing_graph_byte_for_byte() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let universe = RouteUniverse::profile_only(&BSC_PROFILE, token_in, token_out).unwrap();
        assert_eq!(
            universe.token_paths(),
            route_token_paths_for(BSC_PROFILE.connectors, token_in, token_out)
        );
        assert_eq!(
            universe.pairs(),
            crate::chain::route_pairs_for(BSC_PROFILE.connectors, token_in, token_out)
        );
        assert_eq!(universe.source(), &RouteUniverseSource::ProfileOnly);
    }

    #[test]
    fn a_resident_universe_routes_through_its_own_connectors() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let mut connectors = BSC_PROFILE.connectors.to_vec();
        connectors.push(address!("5555555555555555555555555555555555555555"));
        let resident =
            RouteUniverse::resident(&BSC_PROFILE, &connectors, &[], token_in, token_out).unwrap();
        assert_eq!(
            resident.token_paths(),
            route_token_paths_for(&connectors, token_in, token_out)
        );
        assert!(resident.is_resident());
        let diagnostics = resident.diagnostics();
        assert_eq!(diagnostics.source, "resident");
        assert_eq!(diagnostics.connector_count, 0);
        let profile = RouteUniverse::profile_only(&BSC_PROFILE, token_in, token_out).unwrap();
        assert!(!profile.is_resident());
        assert_ne!(resident.fingerprint(), profile.fingerprint());
        // The same connectors as the profile still name a different universe.
        let same = RouteUniverse::resident(
            &BSC_PROFILE,
            BSC_PROFILE.connectors,
            &[],
            token_in,
            token_out,
        )
        .unwrap();
        assert_eq!(same.token_paths(), profile.token_paths());
        assert_ne!(same.fingerprint(), profile.fingerprint());

        let reversed = resident.orient(token_out, token_in).unwrap();
        assert!(reversed.is_resident());
        assert_eq!(
            reversed.token_paths(),
            route_token_paths_for(&connectors, token_out, token_in)
        );
    }

    #[test]
    fn a_resident_universe_is_bounded_by_its_own_pair_ceiling() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let connectors = |count: u8| -> Vec<Address> {
            (0x20..0x20 + count).map(Address::repeat_byte).collect()
        };
        let resident = |count: u8| {
            RouteUniverse::resident(&BSC_PROFILE, &connectors(count), &[], token_in, token_out)
        };
        // Six connectors span 28 pairs: past the indexer's 24, inside 36.
        assert!(resident(6).is_ok());
        assert!(resident(7).is_ok());
        assert!(resident(8).is_err());
    }

    /// Listed skeletons for `token_in`/`token_out`: one
    /// three-hop path, then four-hop paths through `count` tokens, each with
    /// pools of its own.
    fn listed_paths(token_in: Address, token_out: Address, count: u8) -> Vec<Vec<Address>> {
        let mut paths = vec![vec![token_in, Address::repeat_byte(0x40), token_out]];
        for index in 0..count {
            paths.push(vec![
                token_in,
                Address::repeat_byte(0x41 + index),
                WBNB,
                token_out,
            ]);
        }
        paths
    }

    #[test]
    fn listed_skeletons_join_a_universe_and_turn_with_it() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let connectors = BSC_PROFILE.connectors;
        let listed = listed_paths(token_in, token_out, 2);
        let resident =
            RouteUniverse::resident(&BSC_PROFILE, connectors, &listed, token_in, token_out)
                .unwrap();
        let mut expected = route_token_paths_for(connectors, token_in, token_out);
        expected.extend(listed.iter().cloned());
        assert_eq!(resident.token_paths(), expected);
        assert_eq!(resident.diagnostics().connector_count, 3);
        assert_eq!(
            resident.listed_connectors(),
            vec![
                Address::repeat_byte(0x40),
                Address::repeat_byte(0x41),
                Address::repeat_byte(0x42)
            ]
        );
        let plain =
            RouteUniverse::resident(&BSC_PROFILE, connectors, &[], token_in, token_out).unwrap();
        assert_ne!(resident.fingerprint(), plain.fingerprint());

        // Turned around, it is the universe the reverse pair would be given.
        let reversed_listed: Vec<Vec<Address>> = listed
            .iter()
            .map(|path| path.iter().rev().copied().collect())
            .collect();
        let fresh = RouteUniverse::resident(
            &BSC_PROFILE,
            connectors,
            &reversed_listed,
            token_out,
            token_in,
        )
        .unwrap();
        let turned = resident.orient(token_out, token_in).unwrap();
        assert_eq!(turned.token_paths(), fresh.token_paths());
        assert_eq!(turned.fingerprint(), fresh.fingerprint());

        // The per-pair universe takes the same skeletons.
        let profile = RouteUniverse::profile_only(&BSC_PROFILE, token_in, token_out).unwrap();
        let unchanged = profile.clone().with_listed(&[]).unwrap();
        assert_eq!(unchanged.fingerprint(), profile.fingerprint());
        let widened = profile.with_listed(&listed).unwrap();
        assert_eq!(widened.token_paths(), expected);
        assert_eq!(widened.source(), &RouteUniverseSource::ProfileOnly);
        assert_eq!(widened.diagnostics().connector_count, 3);
        let turned = widened.orient(token_out, token_in).unwrap();
        let fresh = RouteUniverse::profile_only(&BSC_PROFILE, token_out, token_in)
            .unwrap()
            .with_listed(&reversed_listed)
            .unwrap();
        assert_eq!(turned.token_paths(), fresh.token_paths());
        assert_eq!(turned.fingerprint(), fresh.fingerprint());
    }

    #[test]
    fn listed_skeletons_past_the_pair_ceiling_are_left_out() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let connectors = BSC_PROFILE.connectors;
        // Ten static pairs; each four-hop skeleton adds two, the first three-hop one two.
        let listed = listed_paths(token_in, token_out, 20);
        let resident =
            RouteUniverse::resident(&BSC_PROFILE, connectors, &listed, token_in, token_out)
                .unwrap();
        assert_eq!(resident.pairs().len(), RESIDENT_MAX_PAIRS);
        assert_eq!(resident.listed_connectors().len(), 1 + 12);
        let per_pair = RouteUniverse::profile_only(&BSC_PROFILE, token_in, token_out)
            .unwrap()
            .with_listed(&listed)
            .unwrap();
        assert_eq!(per_pair.pairs().len(), MAX_PAIRS);
        assert_eq!(per_pair.listed_connectors().len(), 1 + 6);
        // The same skeletons are kept whichever way the pair is asked.
        let reversed: Vec<Vec<Address>> = listed
            .iter()
            .map(|path| path.iter().rev().copied().collect())
            .collect();
        let backward = RouteUniverse::profile_only(&BSC_PROFILE, token_out, token_in)
            .unwrap()
            .with_listed(&reversed)
            .unwrap();
        assert_eq!(backward.listed_connectors(), per_pair.listed_connectors());
    }

    #[test]
    fn shadow_observation_preserves_the_profile_only_graph_and_fingerprint() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let baseline = RouteUniverse::profile_only(&BSC_PROFILE, token_in, token_out).unwrap();
        let shadow = RouteUniverse::profile_only_shadow_complete(
            &BSC_PROFILE,
            token_in,
            token_out,
            selection(
                vec![
                    address!("2222222222222222222222222222222222222222"),
                    address!("3333333333333333333333333333333333333333"),
                    address!("4444444444444444444444444444444444444444"),
                ],
                7,
                true,
            ),
        )
        .unwrap();

        // The routable graph is what shadow mode must leave alone: identical
        // skeletons, identical pairs, so no plan can differ. The fingerprint
        // moves here because this selection carries a screened ranking, and a
        // bound computed against more pools is a different artifact.
        assert_eq!(shadow.token_paths(), baseline.token_paths());
        assert_eq!(shadow.pairs(), baseline.pairs());
        assert_ne!(shadow.fingerprint(), baseline.fingerprint());
        // With screening off the ranking arrives empty, and then shadow mode
        // is byte-for-byte what it was before screening existed — fingerprint
        // included. Shadow is the mode where this is easy to get wrong: its
        // admitted connectors are deliberately unroutable, so truncating the
        // ranking to them rather than clearing it would screen every one.
        let unscreened = RouteUniverse::profile_only_shadow_complete(
            &BSC_PROFILE,
            token_in,
            token_out,
            ConnectorSelection {
                screened: Vec::new(),
                ..selection(
                    vec![
                        address!("2222222222222222222222222222222222222222"),
                        address!("3333333333333333333333333333333333333333"),
                        address!("4444444444444444444444444444444444444444"),
                    ],
                    7,
                    true,
                )
            },
        )
        .unwrap();
        assert!(unscreened.screening_pairs().is_empty());
        assert_eq!(unscreened.fingerprint(), baseline.fingerprint());
        assert_eq!(unscreened.diagnostics().screened_count, 0);
        let diagnostics = shadow.diagnostics();
        assert_eq!(diagnostics.source, "adjacency_shadow");
        assert_eq!(diagnostics.scope, "profile");
        assert_eq!(diagnostics.selection_scope, "common_neighbor_two_hop");
        assert_eq!(diagnostics.connector_count, 3);
        assert_eq!(diagnostics.eligible_count, 7);
        assert!(diagnostics.shortlist_truncated);
        assert_eq!(diagnostics.adjacency_fences, Some(fences()));
    }

    #[test]
    fn screening_pairs_are_unreachable_by_construction() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let screened = vec![
            address!("2222222222222222222222222222222222222222"),
            address!("3333333333333333333333333333333333333333"),
        ];
        let universe = RouteUniverse::profile_only_shadow_complete(
            &BSC_PROFILE,
            token_in,
            token_out,
            ConnectorSelection {
                fences: fences(),
                protocols: vec![Protocol::UNIV2, Protocol::UNIV3],
                connectors: Vec::new(),
                screened: screened.clone(),
                eligible_count: 5,
                shortlist_truncated: true,
                selector: ConnectorSelector::AdjacencyWalk,
            },
        )
        .unwrap();

        // Two endpoint edges per screened token, none of them routable.
        assert_eq!(universe.screening_pairs().len(), 2 * screened.len());
        for &connector in &screened {
            for pair in [(token_in, connector), (connector, token_out)] {
                assert!(universe.screening_pairs().contains(&pair));
            }
            // The property the whole design rests on: a screened token appears
            // in no skeleton, so route preparation builds no edge for it and
            // the certificate's membership check can never admit a leg on it.
            assert!(
                universe
                    .token_paths()
                    .iter()
                    .all(|path| !path.contains(&connector))
            );
        }
        let routable: Vec<(Address, Address)> = universe
            .pairs()
            .iter()
            .map(|&(a, b)| canonical_pair(a, b))
            .collect();
        for &(a, b) in universe.screening_pairs() {
            assert!(!routable.contains(&canonical_pair(a, b)));
        }
        assert_eq!(universe.diagnostics().screened_count, screened.len());
    }

    /// BSC's profile admits four connectors, and this module carries its own
    /// structural ceiling on that count. When the two disagreed, the selection
    /// was rejected here and reported as an indexer `invalid_response` — every
    /// quote fell back to profile-only with nothing naming the real cause, and
    /// the whole existing suite still passed. Pin the agreement.
    #[test]
    fn a_budget_worth_of_connectors_builds_a_universe_and_a_cap_worth_would_not() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        // What the PAIR BUDGET affords, which since the cap moved to eight is
        // the quantity that decides every shape. Ten static skeleton pairs when
        // neither endpoint is a static connector, two per dynamic connector —
        // and a cap-worth would need 26 against a budget of 24, which is why
        // the selector's `min` is load-bearing rather than defensive.
        assert!(
            10 + 2 * BSC_PROFILE.dynamic_connector_cap > BSC_PROFILE.topology_pair_budget,
            "a cap-worth still fits the budget, so the `min` in the selector is dead code"
        );
        let affordable = BSC_PROFILE
            .dynamic_connector_cap
            .min((BSC_PROFILE.topology_pair_budget - 10) / 2);
        let connectors: Vec<Address> = (0..affordable)
            .map(|index| Address::repeat_byte(0x21 + index as u8))
            .collect();
        let universe = RouteUniverse::adjacency_complete(
            &BSC_PROFILE,
            token_in,
            token_out,
            ConnectorSelection {
                fences: fences(),
                protocols: vec![Protocol::UNIV2, Protocol::UNIV3],
                connectors: connectors.clone(),
                screened: connectors.clone(),
                eligible_count: connectors.len(),
                shortlist_truncated: false,
                selector: ConnectorSelector::RankedProjection,
            },
        )
        .expect("a selection at the profile's own cap must build a universe");
        assert_eq!(universe.diagnostics().connector_count, connectors.len());
        assert_eq!(
            universe.pairs().len(),
            // Ten static BSC skeleton pairs when neither endpoint is itself a
            // static connector, plus both endpoint edges per dynamic one.
            10 + 2 * connectors.len()
        );
        assert!(universe.pairs().len() <= BSC_PROFILE.topology_pair_budget);
    }

    #[test]
    fn an_admitted_connector_is_not_screened_twice() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let admitted = address!("2222222222222222222222222222222222222222");
        let extra = address!("3333333333333333333333333333333333333333");
        let universe = RouteUniverse::adjacency_complete(
            &BSC_PROFILE,
            token_in,
            token_out,
            ConnectorSelection {
                fences: fences(),
                protocols: vec![Protocol::UNIV2, Protocol::UNIV3],
                connectors: vec![admitted],
                screened: vec![admitted, extra],
                eligible_count: 4,
                shortlist_truncated: true,
                selector: ConnectorSelector::AdjacencyWalk,
            },
        )
        .unwrap();

        // The admitted connector's edges are already routable, so screening
        // covers only what the pair budget could not buy.
        assert_eq!(
            universe.screening_pairs(),
            &[(token_in, extra), (extra, token_out)]
        );
        assert_eq!(universe.diagnostics().screened_count, 1);
        // And attribution sees the same set the pairs were built from. The
        // admitted connector stays out: its value is already inside `bound`,
        // so reporting it as a screened zero would say "provably worthless"
        // about the connector the plan is actively routing through.
        assert_eq!(universe.priced_beyond_universe(), vec![extra]);
        assert_eq!(universe.screened(), &[admitted, extra]);
    }

    #[test]
    fn reversing_a_screened_universe_reverses_its_screening_pairs() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let connector = address!("2222222222222222222222222222222222222222");
        let selection = ConnectorSelection {
            fences: fences(),
            protocols: vec![Protocol::UNIV2, Protocol::UNIV3],
            connectors: Vec::new(),
            screened: vec![connector],
            eligible_count: 1,
            shortlist_truncated: false,
            selector: ConnectorSelector::AdjacencyWalk,
        };
        let forward = RouteUniverse::profile_only_shadow_complete(
            &BSC_PROFILE,
            token_in,
            token_out,
            selection.clone(),
        )
        .unwrap();
        let reverse = forward.orient(token_out, token_in).unwrap();
        let independently_built = RouteUniverse::profile_only_shadow_complete(
            &BSC_PROFILE,
            token_out,
            token_in,
            selection,
        )
        .unwrap();

        assert_eq!(reverse, independently_built);
        assert_eq!(
            reverse.screening_pairs(),
            &[(token_out, connector), (connector, token_in)]
        );
    }

    #[test]
    fn an_unscreened_universe_carries_no_screening_pairs() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        for universe in [
            RouteUniverse::profile_only(&BSC_PROFILE, token_in, token_out).unwrap(),
            RouteUniverse::adjacency_fallback(
                &BSC_PROFILE,
                token_in,
                token_out,
                FallbackKind::Transport,
            )
            .unwrap(),
        ] {
            assert!(universe.screening_pairs().is_empty());
            assert_eq!(universe.diagnostics().screened_count, 0);
        }
    }

    #[test]
    fn shadow_failure_is_visible_and_requests_a_short_cache_ttl() {
        let universe = RouteUniverse::profile_only_shadow_fallback(
            &BSC_PROFILE,
            address!("1111111111111111111111111111111111111111"),
            address!("9999999999999999999999999999999999999999"),
            FallbackKind::Transport,
        )
        .unwrap();

        assert_eq!(universe.fallback_kind(), Some(FallbackKind::Transport));
        let diagnostics = universe.diagnostics();
        assert_eq!(diagnostics.source, "adjacency_shadow_fallback");
        assert_eq!(diagnostics.scope, "profile");
        assert_eq!(diagnostics.selection_scope, "common_neighbor_two_hop");
        assert_eq!(diagnostics.fallback_stage, Some("adjacency"));
        assert_eq!(diagnostics.fallback_reason, Some("transport"));
    }

    #[test]
    fn dynamic_paths_are_an_append_only_bounded_suffix() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let c1 = address!("2222222222222222222222222222222222222222");
        let c2 = address!("3333333333333333333333333333333333333333");
        let static_paths = route_token_paths_for(BSC_PROFILE.connectors, token_in, token_out);
        let universe = RouteUniverse::adjacency_complete(
            &BSC_PROFILE,
            token_in,
            token_out,
            selection(vec![c1, c2], 4, true),
        )
        .unwrap();
        assert_eq!(
            &universe.token_paths()[..static_paths.len()],
            static_paths.as_slice()
        );
        assert_eq!(
            &universe.token_paths()[static_paths.len()..],
            &[vec![token_in, c1, token_out], vec![token_in, c2, token_out]]
        );
        assert!(universe.pairs().len() <= MAX_PAIRS);
    }

    #[test]
    fn dynamic_connectors_cannot_reintroduce_static_or_special_tokens() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        for connector in [Address::ZERO, token_in, token_out, WBNB, BSC_USDT, BSC_USD1] {
            assert!(
                RouteUniverse::adjacency_complete(
                    &BSC_PROFILE,
                    token_in,
                    token_out,
                    selection(vec![connector], 1, false),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn reverse_universe_reverses_the_dynamic_suffix() {
        let token_in = address!("1111111111111111111111111111111111111111");
        let token_out = address!("9999999999999999999999999999999999999999");
        let connector = address!("2222222222222222222222222222222222222222");
        let forward = RouteUniverse::adjacency_complete(
            &BSC_PROFILE,
            token_in,
            token_out,
            selection(vec![connector], 1, false),
        )
        .unwrap();
        let reverse = forward.orient(token_out, token_in).unwrap();
        let independently_built = RouteUniverse::adjacency_complete(
            &BSC_PROFILE,
            token_out,
            token_in,
            selection(vec![connector], 1, false),
        )
        .unwrap();
        assert_eq!(reverse, independently_built);
        assert_eq!(forward.token_paths().len(), reverse.token_paths().len());
        assert_eq!(
            forward.token_paths().last().unwrap(),
            &vec![token_in, connector, token_out]
        );
        assert_eq!(
            reverse.token_paths().last().unwrap(),
            &vec![token_out, connector, token_in]
        );
    }

    /// `MAX_PAIRS` is the ceiling every pair-count assertion checks against. A
    /// profile above the ceiling would trip those assertions at runtime rather
    /// than here.
    #[test]
    fn every_profile_budget_fits_under_the_pair_ceiling() {
        for profile in crate::chain::CHAIN_PROFILES.iter() {
            assert!(
                profile.topology_pair_budget <= crate::topology::MAX_PAIRS,
                "{} budget {} exceeds the {} ceiling",
                profile.key,
                profile.topology_pair_budget,
                crate::topology::MAX_PAIRS
            );
            assert!(profile.topology_pair_budget > 0);
            assert!(profile.dynamic_connector_cap > 0);
            // `universe.rs` asserts its own structural ceiling on the admitted
            // set, and a profile above it fails at route-universe construction
            // rather than here -- where the error is reported as an indexer
            // `invalid_response`, naming the wrong process entirely.
            assert!(
                profile.dynamic_connector_cap <= crate::universe::MAX_DYNAMIC_CONNECTORS,
                "{} cap {} exceeds the {} routing ceiling",
                profile.key,
                profile.dynamic_connector_cap,
                crate::universe::MAX_DYNAMIC_CONNECTORS
            );
        }
    }
}
