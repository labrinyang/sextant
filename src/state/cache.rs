use super::*;

const TOPO_CACHE_CAP: usize = 256;

// Keyed by the quoted (a, b) DIRECTION, not the sorted pair: probe order — and
// with it every downstream enumeration and tie-break — stays byte-identical to
// a fresh discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TopologyStatus {
    Complete,
    RetryV4,
    AdjacencyFallback,
}

impl TopologyStatus {
    pub(super) fn ttl(self) -> u64 {
        match self {
            Self::Complete => *TOPO_TTL,
            Self::RetryV4 => (*V4_RETRY_TTL).min(*TOPO_TTL),
            Self::AdjacencyFallback => 30.min(*TOPO_TTL),
        }
    }

    pub(super) fn from_v4(discoveries: &[V4KeyDiscovery]) -> Self {
        if discoveries.iter().all(V4KeyDiscovery::is_fresh) {
            Self::Complete
        } else {
            Self::RetryV4
        }
    }
}

#[derive(Clone)]
pub(super) struct Topology {
    pub(super) at: Instant,
    pub(super) status: TopologyStatus,
    pub(super) universe: RouteUniverse,
    pub(super) topology_fences: Option<CatalogFences>,
    pub(super) v3: Vec<V3Pool>,
    pub(super) v2: Vec<V2Pool>,
    /// Screened identities, cached beside the routable ones so a 600 s lease
    /// buys one screening topology request rather than one per pull.
    pub(super) screen_v3: Vec<V3Pool>,
    pub(super) screen_v2: Vec<V2Pool>,
}

type TopologyKey = (u64, B256, Address, Address);

pub(super) static TOPO_CACHE: LazyLock<Mutex<HashMap<TopologyKey, Topology>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn topology_key(
    profile: &ChainProfile,
    token_in: Address,
    token_out: Address,
) -> TopologyKey {
    let mut scope = Vec::with_capacity(96);
    scope.push(3); // topology-cache scope schema
    scope.extend_from_slice(&profile.chain_id.to_be_bytes());
    scope.extend_from_slice(&(profile.key.len() as u16).to_be_bytes());
    scope.extend_from_slice(profile.key.as_bytes());
    scope.push(profile.connectors.len() as u8);
    for connector in profile.connectors {
        scope.extend_from_slice(connector.as_slice());
    }
    match profile.discovery {
        DiscoveryProfile::IndexedEvm(discovery) => {
            scope.push(1);
            scope.push(match *DYNAMIC_CONNECTORS {
                DynamicConnectorMode::ProfileOnly => 0,
                DynamicConnectorMode::Shadow => 1,
                DynamicConnectorMode::Adjacency => 2,
            });
            scope.push(1); // connector-selector algorithm version
            scope.push(u8::from(*CONNECTOR_SCREENING));
            // Two selectors answer the same question differently, so a cached
            // topology from one must never be served to the other.
            scope.push(u8::from(*RANKED_CONNECTORS));
            let protocols = discovery.quote_protocols();
            scope.push(protocols.len() as u8);
            for protocol in protocols {
                scope.push(protocol.rank());
            }
            match discovery.candidates {
                CandidateSource::Indexer => scope.push(0),
                CandidateSource::Factories => {
                    scope.push(1);
                    for venue in discovery.venues {
                        let tiers = venue.fee_tiers();
                        scope.push(tiers.len() as u8);
                        for fee in tiers {
                            scope.extend_from_slice(&fee.to_be_bytes());
                        }
                    }
                }
            }
        }
        DiscoveryProfile::Robinhood => scope.push(2),
        DiscoveryProfile::Disabled => scope.push(3),
    }
    (profile.chain_id, keccak256(scope), token_in, token_out)
}

/// `key`, told apart by the listed skeletons the universe was given: the
/// resident list can add or drop one while a topology is cached.
pub(super) fn listed_topology_key(key: TopologyKey, listed: &[Vec<Address>]) -> TopologyKey {
    if listed.is_empty() {
        return key;
    }
    let mut scope = key.1.to_vec();
    for path in listed {
        scope.push(path.len() as u8);
        for token in path {
            scope.extend_from_slice(token.as_slice());
        }
    }
    (key.0, keccak256(scope), key.2, key.3)
}

pub(super) fn topology_cached(key: TopologyKey) -> Option<Topology> {
    let mut cache = TOPO_CACHE.lock().expect("topo cache lock");
    cache.retain(|_, topology| topology.at.elapsed().as_secs() < topology.status.ttl());
    cache.get(&key).cloned()
}

pub(super) fn cache_topology(key: TopologyKey, topology: Topology) {
    let mut cache = TOPO_CACHE.lock().expect("topo cache lock");
    cache.retain(|_, cached| cached.at.elapsed().as_secs() < cached.status.ttl());
    if !cache.contains_key(&key)
        && cache.len() >= TOPO_CACHE_CAP
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(key, cached)| (cached.at, **key))
            .map(|(key, _)| *key)
    {
        cache.remove(&oldest);
    }
    cache.insert(key, topology);
}
