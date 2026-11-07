//! The topology a pool indexer names: candidate pool identities, catalog
//! fences and connector selections. Identity only: no reserves, ticks or
//! other mutable state. The client that fetches and validates these is the
//! application's (`sextant::indexer`).

use alloy_primitives::{Address, B256};
pub use sextant_chain::catalog::CatalogProtocol as Protocol;
use std::fmt;

/// The largest topology budget any chain profile may take, and the ceiling
/// every pair-count assertion checks. The budget a given quote actually spends
/// is `ChainProfile::topology_pair_budget`, because the limit is a contract
/// with one chain's indexer rather than a property of this client.
pub const MAX_PAIRS: usize = 24;

/// Stable classification for callers and tests. The error never retains a
/// reqwest error or endpoint, so even alternate/debug formatting cannot reveal
/// credentials embedded in an operator-supplied URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexerErrorKind {
    InvalidConfiguration,
    InvalidRequest,
    Transport,
    Conflict,
    Capacity,
    HttpStatus,
    BodyTooLarge,
    InvalidResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexerError {
    kind: IndexerErrorKind,
    detail: String,
}

impl IndexerError {
    pub fn new(kind: IndexerErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub fn kind(&self) -> IndexerErrorKind {
        self.kind
    }
}

impl fmt::Display for IndexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pool indexer {}: {}", self.kind.label(), self.detail)
    }
}

impl std::error::Error for IndexerError {}

impl IndexerErrorKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "configuration rejected",
            Self::InvalidRequest => "request rejected",
            Self::Transport => "request failed",
            Self::Conflict => "catalog conflict",
            Self::Capacity => "capacity exceeded",
            Self::HttpStatus => "HTTP response rejected",
            Self::BodyTooLarge => "response body rejected",
            Self::InvalidResponse => "response validation failed",
        }
    }
}

pub type Result<T> = std::result::Result<T, IndexerError>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TokenPair {
    pub token0: Address,
    pub token1: Address,
}

impl TokenPair {
    /// Require the same canonical order the indexer persists and echoes. A
    /// reversed pair is a caller bug, not something this trust boundary hides.
    pub fn new(token0: Address, token1: Address) -> Result<Self> {
        if token0 >= token1 {
            return Err(IndexerError::new(
                IndexerErrorKind::InvalidRequest,
                "pair must satisfy token0 < token1",
            ));
        }
        Ok(Self { token0, token1 })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V23Fence {
    pub seq: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V4Fence {
    pub block: u64,
    pub generation: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogFences {
    pub v23: V23Fence,
    pub v4: Option<V4Fence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressPoolTopology {
    pub protocol: Protocol,
    pub address: Address,
    pub token0: Address,
    pub token1: Address,
    pub fee_ppm: u32,
    pub tick_spacing: Option<i32>,
    pub created_block: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V4PoolTopology {
    pub pool_manager: Address,
    pub pool_id: B256,
    pub currency0: Address,
    pub currency1: Address,
    /// `None` is an intentional historical Graph candidate. It cannot quote
    /// until a pinned StateView read yields a unique PoolKey fee.
    pub key_fee_ppm: Option<u32>,
    pub tick_spacing: i32,
    pub hooks: Address,
    pub created_block: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolTopology {
    Address(AddressPoolTopology),
    Univ4(V4PoolTopology),
}

impl PoolTopology {
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::Address(pool) => pool.protocol,
            Self::Univ4(_) => Protocol::UNIV4,
        }
    }

    pub fn pair(&self) -> TokenPair {
        match self {
            Self::Address(pool) => TokenPair {
                token0: pool.token0,
                token1: pool.token1,
            },
            Self::Univ4(pool) => TokenPair {
                token0: pool.currency0,
                token1: pool.currency1,
            },
        }
    }

    pub fn identity(&self) -> Identity {
        match self {
            Self::Address(pool) => Identity::Address(pool.address),
            Self::Univ4(pool) => Identity::PoolId(pool.pool_id),
        }
    }

    pub fn sort_key(&self) -> (TokenPair, u8, Identity) {
        (self.pair(), self.protocol().rank(), self.identity())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Topology {
    pub pairs: Vec<TokenPair>,
    pub protocols: Vec<Protocol>,
    pub fences: CatalogFences,
    pub pools: Vec<PoolTopology>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdjacencyEdge {
    pub token0: Address,
    pub token1: Address,
    pub protocols: Vec<Protocol>,
}

impl AdjacencyEdge {
    pub fn neighbor(&self, token: Address) -> Option<Address> {
        if self.token0 == token {
            Some(self.token1)
        } else if self.token1 == token {
            Some(self.token0)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Adjacency {
    pub token: Address,
    pub protocols: Vec<Protocol>,
    pub fences: CatalogFences,
    pub edges: Vec<AdjacencyEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorSelection {
    pub fences: CatalogFences,
    pub protocols: Vec<Protocol>,
    pub connectors: Vec<Address>,
    /// The same ranking carried further than the pair budget can admit, for
    /// pricing rather than for routing.
    ///
    /// `connectors` is drawn from its head, but the work gate downstream may
    /// drop one from the middle, so the admitted set is a subsequence rather
    /// than a prefix. Empty means connector screening is off and no ranking
    /// was carried at all — which is what keeps a screening-off run byte-for-
    /// byte identical to one built before screening existed, in every mode.
    ///
    /// A candidate the universe cannot afford is invisible to `gap_bps`,
    /// which bounds regret only over pools a quote actually loaded. Reading
    /// state for these tokens — never routing through them — turns that blind
    /// spot into a number: what the shortlist left on the table, priced at
    /// the same dual point the quote was certified against.
    pub screened: Vec<Address>,
    pub eligible_count: usize,
    pub shortlist_truncated: bool,
    pub selector: ConnectorSelector,
}

/// Which selector produced a shortlist. Carried into the universe fingerprint,
/// so a universe built from one is never confused with a universe built from
/// the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorSelector {
    /// Both endpoints' complete adjacency, intersected in this process. Ranks
    /// by shared protocol count, which says nothing about depth, so it is only
    /// defensible over a candidate set small enough to enumerate completely.
    AdjacencyWalk,
    /// The indexer's materialized ranking, intersected there and ordered by
    /// what a two-hop route through each candidate could carry.
    ///
    /// Candidate discovery covers only the protocols that ranking can rank. A
    /// connector reachable from an endpoint solely through V4 is therefore
    /// invisible here, even though a selected pair still routes over V4 like
    /// any other. That narrowing is why `selection_protocols` is reported
    /// separately from the protocols a quote goes on to use.
    RankedProjection,
}

impl ConnectorSelector {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdjacencyWalk => "adjacency_walk",
            Self::RankedProjection => "ranked_projection",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Identity {
    Address(Address),
    PoolId(B256),
}
