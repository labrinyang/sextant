//! Strict, read-only client for an indexed EVM immutable pool topology.
//!
//! The index is a candidate identity directory, never a source of quote state.
//! Consequently the public types in this module contain no reserves, ticks,
//! liquidity, token metadata, TVL, or other mutable/display fields. Callers are
//! still responsible for verifying candidates against the configured factories
//! and reading every price-affecting word from one canonical RPC block.

use crate::catalog::{CandidateSource, CatalogVenue, IndexedEvmDiscovery, ReadinessPolicy};
use crate::chain::{ChainProfile, DiscoveryProfile};
use alloy_primitives::{Address, B256};
use reqwest::{StatusCode, Url, redirect};
use serde::Deserialize;
pub use sextant_route::topology::*;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_POOLS: usize = 2_048;

pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

pub const ADJACENCY_PAGE_SIZE: usize = 512;

pub const MAX_ADJACENCY_PAGES: usize = 4;

pub const MAX_ADJACENCY_EDGES: usize = ADJACENCY_PAGE_SIZE * MAX_ADJACENCY_PAGES;

pub const MAX_ADJACENCY_RESPONSE_BYTES: usize = 256 * 1024;

/// Candidates requested from the indexer's ranked connector projection. The
/// ranking is already ordered by what a two-hop route through each candidate
/// could carry, so this only has to cover the screening shortlist with room to
/// discard the endpoints' own static connectors.
pub const RANKED_CONNECTOR_CANDIDATES: usize = 32;

pub const MAX_CONNECTORS_RESPONSE_BYTES: usize = 64 * 1024;

/// The ranked connector contract is chain-independent in shape, unlike the
/// topology and adjacency schemas each chain profile pins for itself.
const CONNECTORS_SCHEMA_VERSION: u32 = 1;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

const DEFAULT_CONNECTOR_SELECTION_TIMEOUT: Duration = Duration::from_secs(2);

const DEFAULT_MAX_V23_AGE: Duration = Duration::from_secs(2 * 60 * 60);

const MAX_FUTURE_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

const ENDPOINT_PATH: &str = "/api/solver/topology";

const ADJACENCY_ENDPOINT_PATH: &str = "/api/solver/adjacency";

const CONNECTORS_ENDPOINT_PATH: &str = "/api/solver/connectors";

const V4_DYNAMIC_FEE_FLAG: u32 = 0x80_0000;

#[derive(Clone)]
pub struct IndexerClient {
    http: reqwest::Client,
    endpoint: Url,
    adjacency_endpoint: Url,
    connectors_endpoint: Url,
    ranked_connectors: bool,
    connector_selection_timeout: Duration,
    max_v23_age: Duration,
    profile: &'static ChainProfile,
    discovery: &'static IndexedEvmDiscovery,
}

impl fmt::Debug for IndexerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexerClient")
            .field("endpoint", &"[redacted]")
            .field("chain", &self.profile.key)
            .finish_non_exhaustive()
    }
}

pub struct IndexerClientBuilder {
    endpoint: Url,
    adjacency_endpoint: Url,
    connectors_endpoint: Url,
    ranked_connectors: bool,
    timeout: Duration,
    connect_timeout: Duration,
    connector_selection_timeout: Duration,
    max_v23_age: Duration,
    profile: &'static ChainProfile,
    discovery: &'static IndexedEvmDiscovery,
}

impl fmt::Debug for IndexerClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexerClientBuilder")
            .field("endpoint", &"[redacted]")
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field(
                "connector_selection_timeout",
                &self.connector_selection_timeout,
            )
            .field("max_v23_age", &self.max_v23_age)
            .field("chain", &self.profile.key)
            .finish()
    }
}

impl IndexerClient {
    pub fn builder(base_url: &str, profile: &'static ChainProfile) -> Result<IndexerClientBuilder> {
        let DiscoveryProfile::IndexedEvm(discovery) = profile.discovery else {
            return Err(IndexerError::new(
                IndexerErrorKind::InvalidConfiguration,
                "chain profile is not indexer-backed",
            ));
        };
        if discovery.candidates != CandidateSource::Indexer {
            return Err(IndexerError::new(
                IndexerErrorKind::InvalidConfiguration,
                "chain profile names its pools by factory and takes no indexer",
            ));
        }
        discovery.validate().map_err(|_| {
            IndexerError::new(
                IndexerErrorKind::InvalidConfiguration,
                "chain venue policy is invalid",
            )
        })?;
        let mut endpoint = Url::parse(base_url).map_err(|_| {
            IndexerError::new(
                IndexerErrorKind::InvalidConfiguration,
                "endpoint URL is invalid",
            )
        })?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.cannot_be_a_base() {
            return Err(IndexerError::new(
                IndexerErrorKind::InvalidConfiguration,
                "endpoint must be an HTTP(S) base URL",
            ));
        }
        endpoint.set_path(ENDPOINT_PATH);
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let mut adjacency_endpoint = endpoint.clone();
        adjacency_endpoint.set_path(ADJACENCY_ENDPOINT_PATH);
        let mut connectors_endpoint = endpoint.clone();
        connectors_endpoint.set_path(CONNECTORS_ENDPOINT_PATH);
        Ok(IndexerClientBuilder {
            endpoint,
            adjacency_endpoint,
            connectors_endpoint,
            ranked_connectors: false,
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            connector_selection_timeout: DEFAULT_CONNECTOR_SELECTION_TIMEOUT,
            max_v23_age: DEFAULT_MAX_V23_AGE,
            profile,
            discovery,
        })
    }

    /// Fetch a protocol-scoped topology response. Both sides echo the exact
    /// ordered scope, so an indexer cannot hide extra rows behind local
    /// filtering or let an unquoted permissionless catalog consume the cap.
    pub async fn topology(&self, pairs: &[TokenPair], protocols: &[Protocol]) -> Result<Topology> {
        let pairs = normalized_pairs(pairs)?;
        let protocols = normalized_protocols(protocols, self.discovery)?;
        let mut url = self.endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            for pair in &pairs {
                query.append_pair("pair", &format!("{:#x},{:#x}", pair.token0, pair.token1));
            }
            for protocol in &protocols {
                query.append_pair("protocol", protocol.as_str());
            }
        }

        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| IndexerError::new(IndexerErrorKind::Transport, "transport error"))?;
        require_ok(response.status())?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(IndexerError::new(
                IndexerErrorKind::BodyTooLarge,
                format!("Content-Length exceeds {MAX_RESPONSE_BYTES} bytes"),
            ));
        }

        let body = read_capped(response).await?;
        let wire: WireResponse = serde_json::from_slice(&body).map_err(|_| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                "body is not valid schema JSON",
            )
        })?;
        validate_response(
            wire,
            pairs,
            protocols,
            self.max_v23_age,
            self.profile,
            self.discovery,
        )
    }

    /// Traverse one endpoint's complete bounded adjacency under a single
    /// catalog fence. Partial pages are never returned to callers.
    pub async fn adjacency(
        &self,
        token: Address,
        protocols: &[Protocol],
        explicit_fences: Option<CatalogFences>,
    ) -> Result<Adjacency> {
        let protocols = normalized_protocols(protocols, self.discovery)?;
        let mut expected_fences = explicit_fences;
        let mut next_page_token: Option<String> = None;
        let mut edges = Vec::new();
        let mut previous_neighbor = None;

        for page_index in 0..MAX_ADJACENCY_PAGES {
            let mut url = self.adjacency_endpoint.clone();
            {
                let mut query = url.query_pairs_mut();
                query.append_pair("token", &format!("{token:#x}"));
                for protocol in &protocols {
                    query.append_pair("protocol", protocol.as_str());
                }
                query.append_pair("limit", &ADJACENCY_PAGE_SIZE.to_string());
                if let Some(cursor) = &next_page_token {
                    query.append_pair("page_token", cursor);
                } else if let Some(fences) = explicit_fences {
                    query.append_pair("v23_seq", &fences.v23.seq.to_string());
                    query.append_pair("v23_generation", &fences.v23.generation.to_string());
                    if let Some(v4) = fences.v4 {
                        query.append_pair("v4_block", &v4.block.to_string());
                        query.append_pair("v4_generation", &format!("{:#x}", v4.generation));
                    }
                }
            }

            let response =
                self.http.get(url).send().await.map_err(|_| {
                    IndexerError::new(IndexerErrorKind::Transport, "transport error")
                })?;
            require_ok(response.status())?;
            if response
                .content_length()
                .is_some_and(|length| length > MAX_ADJACENCY_RESPONSE_BYTES as u64)
            {
                return Err(IndexerError::new(
                    IndexerErrorKind::BodyTooLarge,
                    format!("Content-Length exceeds {MAX_ADJACENCY_RESPONSE_BYTES} bytes"),
                ));
            }
            let body = read_capped_to(response, MAX_ADJACENCY_RESPONSE_BYTES).await?;
            let wire: WireAdjacencyResponse = serde_json::from_slice(&body).map_err(|_| {
                IndexerError::new(
                    IndexerErrorKind::InvalidResponse,
                    "body is not valid adjacency schema JSON",
                )
            })?;
            let page = validate_adjacency_response(
                wire,
                token,
                &protocols,
                expected_fences,
                self.max_v23_age,
                self.profile,
                self.discovery,
            )?;
            expected_fences = Some(page.fences);
            for edge in page.edges {
                let neighbor = edge.neighbor(token).ok_or_else(|| {
                    IndexerError::new(
                        IndexerErrorKind::InvalidResponse,
                        "adjacency edge is not incident to its token",
                    )
                })?;
                if previous_neighbor.is_some_and(|previous| previous >= neighbor) {
                    return invalid("adjacency pages are not globally strictly ordered");
                }
                previous_neighbor = Some(neighbor);
                edges.push(edge);
            }
            if edges.len() > MAX_ADJACENCY_EDGES {
                return Err(IndexerError::new(
                    IndexerErrorKind::Capacity,
                    format!("adjacency exceeds {MAX_ADJACENCY_EDGES} edges"),
                ));
            }
            next_page_token = page.next_page_token;
            if next_page_token.is_none() {
                return Ok(Adjacency {
                    token,
                    protocols,
                    fences: expected_fences.expect("a validated page has fences"),
                    edges,
                });
            }
            if page_index + 1 == MAX_ADJACENCY_PAGES {
                break;
            }
        }
        Err(IndexerError::new(
            IndexerErrorKind::Capacity,
            format!("adjacency requires more than {MAX_ADJACENCY_PAGES} pages"),
        ))
    }

    /// Ask the indexer which tokens could connect a pair, ranked by what a
    /// two-hop route through each could carry.
    ///
    /// The ranking covers only the protocols it can price from pool state, so
    /// the request is narrowed to the V2/V3 subset of the quote scope and the
    /// answer records that narrowing. Sending the full scope instead would be
    /// declined by the indexer, which refuses to rank a subset while a caller
    /// believes the whole scope was weighed.
    pub async fn connector_candidates(
        &self,
        token_in: Address,
        token_out: Address,
        protocols: &[Protocol],
    ) -> Result<RankedConnectors> {
        if token_in == token_out {
            return Err(IndexerError::new(
                IndexerErrorKind::InvalidRequest,
                "connector endpoints must differ",
            ));
        }
        let protocols = normalized_protocols(protocols, self.discovery)?;
        let ranked_protocols = protocols
            .iter()
            .copied()
            .filter(|protocol| *protocol != Protocol::UNIV4)
            .collect::<Vec<_>>();
        if ranked_protocols.is_empty() {
            return Err(IndexerError::new(
                IndexerErrorKind::Capacity,
                "no requested protocol can be ranked",
            ));
        }

        let mut url = self.connectors_endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("a", &format!("{token_in:#x}"));
            query.append_pair("b", &format!("{token_out:#x}"));
            for protocol in &ranked_protocols {
                query.append_pair("protocol", protocol.as_str());
            }
            query.append_pair("limit", &RANKED_CONNECTOR_CANDIDATES.to_string());
        }
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| IndexerError::new(IndexerErrorKind::Transport, "transport error"))?;
        // An indexer without the route at all is a capacity answer, not a
        // protocol error: it means this deployment cannot rank yet, which is
        // exactly what the adjacency fallback exists to cover.
        if response.status() == StatusCode::NOT_FOUND {
            return Err(IndexerError::new(
                IndexerErrorKind::Capacity,
                "indexer does not serve ranked connectors",
            ));
        }
        require_ok(response.status())?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_CONNECTORS_RESPONSE_BYTES as u64)
        {
            return Err(IndexerError::new(
                IndexerErrorKind::BodyTooLarge,
                format!("Content-Length exceeds {MAX_CONNECTORS_RESPONSE_BYTES} bytes"),
            ));
        }
        let body = read_capped_to(response, MAX_CONNECTORS_RESPONSE_BYTES).await?;
        let wire: WireConnectorsResponse = serde_json::from_slice(&body).map_err(|_| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                "body is not valid connectors schema JSON",
            )
        })?;
        validate_connectors_response(
            wire,
            token_in,
            token_out,
            &ranked_protocols,
            self.max_v23_age,
            self.profile,
            self.discovery,
        )
    }

    /// Fetch both endpoint catalogs at one fence and select a deterministic
    /// connectivity-only shortlist. A catalog conflict retries the complete
    /// two-sided traversal once; no partial evidence escapes.
    pub async fn connector_selection(
        &self,
        token_in: Address,
        token_out: Address,
        protocols: &[Protocol],
    ) -> Result<ConnectorSelection> {
        tokio::time::timeout(
            self.connector_selection_timeout,
            self.connector_selection_inner(token_in, token_out, protocols),
        )
        .await
        .map_err(|_| {
            IndexerError::new(IndexerErrorKind::Transport, "connector selection timed out")
        })?
    }

    async fn connector_selection_inner(
        &self,
        token_in: Address,
        token_out: Address,
        protocols: &[Protocol],
    ) -> Result<ConnectorSelection> {
        if token_in == token_out {
            return Err(IndexerError::new(
                IndexerErrorKind::InvalidRequest,
                "connector endpoints must differ",
            ));
        }
        if self.ranked_connectors {
            match self
                .connector_candidates(token_in, token_out, protocols)
                .await
            {
                Ok(ranked) => {
                    return select_ranked_connectors(self.profile, token_in, token_out, &ranked);
                }
                // Only a deployment that cannot rank falls through. A malformed
                // or chain-mismatched answer is a real fault, and quietly
                // walking adjacency instead would hide it behind a slower path
                // that happens to work on small chains.
                Err(error) if error.kind() == IndexerErrorKind::Capacity => {}
                Err(error) => return Err(error),
            }
        }
        for attempt in 0..2 {
            let left = match self.adjacency(token_in, protocols, None).await {
                Err(error) if error.kind() == IndexerErrorKind::Conflict && attempt == 0 => {
                    continue;
                }
                result => result?,
            };
            let right = match self
                .adjacency(token_out, protocols, Some(left.fences))
                .await
            {
                Err(error) if error.kind() == IndexerErrorKind::Conflict && attempt == 0 => {
                    continue;
                }
                result => result?,
            };
            return select_connectors(self.profile, token_in, token_out, &left, &right);
        }
        Err(IndexerError::new(
            IndexerErrorKind::Conflict,
            "catalog changed twice during adjacency traversal",
        ))
    }
}

impl IndexerClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Total budget for both paginated endpoint traversals and the one complete
    /// conflict retry. This is deliberately independent of the per-request
    /// timeout so optional graph expansion cannot consume the quote budget.
    pub fn connector_selection_timeout(mut self, timeout: Duration) -> Self {
        self.connector_selection_timeout = timeout;
        self
    }

    /// Select connectors from the indexer's ranked projection, falling back to
    /// the two-sided adjacency walk when no ranking is published.
    ///
    /// Off by default. The walk is the older and narrower behaviour, but it is
    /// the one every existing deployment already validates against, so moving
    /// off it is an explicit operator decision rather than a consequence of
    /// upgrading the binary.
    pub fn ranked_connectors(mut self, ranked: bool) -> Self {
        self.ranked_connectors = ranked;
        self
    }

    /// Maximum accepted age for the last complete V2/V3 catalog tail. Zero
    /// disables only the age check; a positive timestamp and future-skew check
    /// remain mandatory. Disabling this is intended for deterministic replay,
    /// not production service startup.
    pub fn max_v23_age(mut self, max_age: Duration) -> Self {
        self.max_v23_age = max_age;
        self
    }

    pub fn build(self) -> Result<IndexerClient> {
        if self.timeout.is_zero()
            || self.connect_timeout.is_zero()
            || self.connector_selection_timeout.is_zero()
        {
            return Err(IndexerError::new(
                IndexerErrorKind::InvalidConfiguration,
                "timeouts must be positive",
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|_| {
                IndexerError::new(
                    IndexerErrorKind::InvalidConfiguration,
                    "HTTP client could not be built",
                )
            })?;
        Ok(IndexerClient {
            http,
            endpoint: self.endpoint,
            adjacency_endpoint: self.adjacency_endpoint,
            connectors_endpoint: self.connectors_endpoint,
            ranked_connectors: self.ranked_connectors,
            connector_selection_timeout: self.connector_selection_timeout,
            max_v23_age: self.max_v23_age,
            profile: self.profile,
            discovery: self.discovery,
        })
    }
}

async fn read_capped(response: reqwest::Response) -> Result<Vec<u8>> {
    read_capped_to(response, MAX_RESPONSE_BYTES).await
}

async fn read_capped_to(mut response: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    let initial = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(max_bytes);
    let mut body = Vec::with_capacity(initial);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| IndexerError::new(IndexerErrorKind::Transport, "body stream failed"))?
    {
        let next = body.len().checked_add(chunk.len()).ok_or_else(|| {
            IndexerError::new(IndexerErrorKind::BodyTooLarge, "response length overflow")
        })?;
        if next > max_bytes {
            return Err(IndexerError::new(
                IndexerErrorKind::BodyTooLarge,
                format!("streamed body exceeds {max_bytes} bytes"),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn require_ok(status: StatusCode) -> Result<()> {
    if status == StatusCode::OK {
        return Ok(());
    }
    let kind = match status {
        StatusCode::CONFLICT => IndexerErrorKind::Conflict,
        StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::TOO_MANY_REQUESTS
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::INSUFFICIENT_STORAGE => IndexerErrorKind::Capacity,
        StatusCode::REQUEST_TIMEOUT
        | StatusCode::TOO_EARLY
        | StatusCode::BAD_GATEWAY
        | StatusCode::GATEWAY_TIMEOUT
        | StatusCode::INTERNAL_SERVER_ERROR => IndexerErrorKind::Transport,
        _ => IndexerErrorKind::HttpStatus,
    };
    Err(IndexerError::new(
        kind,
        format!("expected HTTP 200, got {}", status.as_u16()),
    ))
}

fn normalized_pairs(pairs: &[TokenPair]) -> Result<Vec<TokenPair>> {
    if pairs.is_empty() || pairs.len() > MAX_PAIRS {
        return Err(IndexerError::new(
            IndexerErrorKind::InvalidRequest,
            format!("pair count must be in 1..={MAX_PAIRS}"),
        ));
    }
    let mut normalized = pairs.to_vec();
    if normalized.iter().any(|pair| pair.token0 >= pair.token1) {
        return Err(IndexerError::new(
            IndexerErrorKind::InvalidRequest,
            "every pair must satisfy token0 < token1",
        ));
    }
    normalized.sort_unstable();
    if normalized.windows(2).any(|window| window[0] == window[1]) {
        return Err(IndexerError::new(
            IndexerErrorKind::InvalidRequest,
            "duplicate pairs are not allowed",
        ));
    }
    Ok(normalized)
}

fn normalized_protocols(
    protocols: &[Protocol],
    discovery: &IndexedEvmDiscovery,
) -> Result<Vec<Protocol>> {
    if protocols.is_empty() {
        return Err(IndexerError::new(
            IndexerErrorKind::InvalidRequest,
            "at least one protocol must be selected",
        ));
    }
    let mut normalized = protocols.to_vec();
    normalized.sort_unstable();
    if normalized.windows(2).any(|window| window[0] == window[1]) {
        return Err(IndexerError::new(
            IndexerErrorKind::InvalidRequest,
            "duplicate protocols are not allowed",
        ));
    }
    if normalized
        .iter()
        .any(|protocol| discovery.venue(*protocol).is_none())
    {
        return Err(IndexerError::new(
            IndexerErrorKind::InvalidRequest,
            "selected protocol is not configured for this chain",
        ));
    }
    Ok(normalized)
}

struct AdjacencyPage {
    fences: CatalogFences,
    next_page_token: Option<String>,
    edges: Vec<AdjacencyEdge>,
}

fn validate_adjacency_response(
    wire: WireAdjacencyResponse,
    requested_token: Address,
    protocols: &[Protocol],
    expected_fences: Option<CatalogFences>,
    max_v23_age: Duration,
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
) -> Result<AdjacencyPage> {
    if wire.schema_version != discovery.schema_version {
        return invalid(format!(
            "schemaVersion must be {}",
            discovery.schema_version
        ));
    }
    if wire.chain_id != profile.chain_id
        || wire.chain.id != profile.chain_id
        || wire.chain.key != profile.key
    {
        return invalid("adjacency response is not bound to the selected chain profile");
    }
    if !wire.ready {
        return invalid("top-level adjacency catalog is not ready");
    }
    let echoed_protocols = wire
        .protocols
        .iter()
        .map(|protocol| parse_protocol(protocol))
        .collect::<Result<Vec<_>>>()?;
    if echoed_protocols != protocols {
        return invalid("adjacency protocol echo does not exactly match the request");
    }
    let v4_catalog = validate_catalogs(&wire.catalogs, max_v23_age, discovery, protocols)?;
    validate_factories(wire.factories, discovery)?;
    let require_v4 = required_protocols(discovery, protocols).contains(&Protocol::UNIV4);
    let fences = validate_fences(wire.v23_fence, wire.v4_fence, require_v4)?;
    if expected_fences.is_some_and(|expected| expected != fences) {
        return invalid("adjacency fence does not match the requested traversal");
    }
    if require_v4 {
        let fence = fences.v4.ok_or_else(|| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                "required adjacency v4 catalog is missing its fence",
            )
        })?;
        validate_v4_adjacency_fence_binding(
            v4_catalog.as_ref().ok_or_else(|| {
                IndexerError::new(
                    IndexerErrorKind::InvalidResponse,
                    "required adjacency v4 catalog was not decoded",
                )
            })?,
            fence,
        )?;
    }

    let token = parse_lower_address(&wire.token, "adjacency token")?;
    if token != requested_token {
        return invalid("adjacency token echo does not match the request");
    }
    if wire.count > ADJACENCY_PAGE_SIZE || wire.edges.len() > ADJACENCY_PAGE_SIZE {
        return invalid("adjacency page exceeds its row limit");
    }
    if wire.count != wire.edges.len() {
        return invalid("adjacency count does not equal edges length");
    }
    if wire.next_page_token.is_some() && wire.count != ADJACENCY_PAGE_SIZE {
        return invalid("a continued adjacency page must be full");
    }
    if let Some(cursor) = &wire.next_page_token
        && (cursor.is_empty()
            || cursor.len() > 512
            || !cursor
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    {
        return invalid("nextPageToken is not canonical bounded base64url");
    }

    let mut previous_neighbor = None;
    let mut edges = Vec::with_capacity(wire.edges.len());
    for edge in wire.edges {
        let token0 = parse_lower_address(&edge.token0, "adjacency edge token0")?;
        let token1 = parse_lower_address(&edge.token1, "adjacency edge token1")?;
        if token0 >= token1 {
            return invalid("adjacency edge pair is not canonical");
        }
        let neighbor = if token0 == requested_token {
            token1
        } else if token1 == requested_token {
            token0
        } else {
            return invalid("adjacency edge is not incident to its token");
        };
        if previous_neighbor.is_some_and(|previous| previous >= neighbor) {
            return invalid("adjacency edges are not in strict neighbor order");
        }
        previous_neighbor = Some(neighbor);
        let edge_protocols = edge
            .protocols
            .iter()
            .map(|protocol| parse_protocol(protocol))
            .collect::<Result<Vec<_>>>()?;
        if edge_protocols.is_empty()
            || edge_protocols
                .windows(2)
                .any(|window| window[0] >= window[1])
            || edge_protocols
                .iter()
                .any(|protocol| !protocols.contains(protocol))
        {
            return invalid("adjacency edge protocols are empty, unordered, or out of scope");
        }
        edges.push(AdjacencyEdge {
            token0,
            token1,
            protocols: edge_protocols,
        });
    }

    Ok(AdjacencyPage {
        fences,
        next_page_token: wire.next_page_token,
        edges,
    })
}

fn validate_connectors_response(
    wire: WireConnectorsResponse,
    token_in: Address,
    token_out: Address,
    protocols: &[Protocol],
    max_v23_age: Duration,
    profile: &ChainProfile,
    discovery: &'static IndexedEvmDiscovery,
) -> Result<RankedConnectors> {
    if wire.schema_version != CONNECTORS_SCHEMA_VERSION {
        return invalid(format!("schemaVersion must be {CONNECTORS_SCHEMA_VERSION}"));
    }
    if wire.chain_id != profile.chain_id
        || wire.chain.id != profile.chain_id
        || wire.chain.key != profile.key
    {
        return invalid("connectors response is not bound to the selected chain profile");
    }
    if !wire.ready {
        return invalid("top-level connectors catalog is not ready");
    }
    let echoed_protocols = wire
        .protocols
        .iter()
        .map(|protocol| parse_protocol(protocol))
        .collect::<Result<Vec<_>>>()?;
    if echoed_protocols != protocols {
        return invalid("connectors protocol echo does not exactly match the request");
    }
    // The V2/V3 catalogs are checked exactly as adjacency checks them. V4 is
    // never required: the ranking does not cover it, and the narrowing is
    // reported rather than repaired.
    validate_catalogs(&wire.catalogs, max_v23_age, discovery, protocols)?;
    validate_factories(wire.factories, discovery)?;
    let fences = validate_fences(wire.ranking.v23_fence, serde_json::Value::Null, false)?;
    if wire.ranking.built_at == 0 {
        return invalid("connectors ranking reports no build time");
    }
    if wire.ranking.per_token_limit == 0 {
        return invalid("connectors ranking reports an empty per-token budget");
    }
    if parse_lower_address(&wire.a, "connectors token a")? != token_in
        || parse_lower_address(&wire.b, "connectors token b")? != token_out
    {
        return invalid("connectors endpoint echo does not match the request");
    }
    if wire.count != wire.candidates.len() || wire.count > RANKED_CONNECTOR_CANDIDATES {
        return invalid("connectors count does not describe the returned candidates");
    }
    for side in [&wire.sides.a, &wire.sides.b] {
        if side.ranked > wire.ranking.per_token_limit {
            return invalid("a connectors side ranked more neighbours than its budget allows");
        }
        if side.truncated != (side.ranked == wire.ranking.per_token_limit) {
            return invalid("a connectors side contradicts its own truncation flag");
        }
    }

    let mut candidates = Vec::with_capacity(wire.candidates.len());
    let mut previous_bottleneck: Option<f64> = None;
    for candidate in wire.candidates {
        if !candidate.bottleneck_usd.is_finite() || candidate.bottleneck_usd <= 0.0 {
            return invalid("connectors candidate carries no usable ranking figure");
        }
        // The order is the whole product of this endpoint. Accepting a
        // mis-ordered list would silently substitute the indexer's insertion
        // order for the ranking this selector exists to consume.
        if previous_bottleneck.is_some_and(|previous| previous < candidate.bottleneck_usd) {
            return invalid("connectors candidates are not ordered by their ranking figure");
        }
        previous_bottleneck = Some(candidate.bottleneck_usd);
        for side in [&candidate.a_protocols, &candidate.b_protocols] {
            let decoded = side
                .iter()
                .map(|protocol| parse_protocol(protocol))
                .collect::<Result<Vec<_>>>()?;
            if decoded.is_empty() || !decoded.iter().all(|entry| protocols.contains(entry)) {
                return invalid("a connectors candidate leg falls outside the requested scope");
            }
        }
        candidates.push(parse_lower_address(
            &candidate.token,
            "connectors candidate",
        )?);
    }

    Ok(RankedConnectors {
        fences,
        protocols: echoed_protocols,
        candidates,
        truncated: wire.sides.a.truncated || wire.sides.b.truncated,
    })
}

/// Whether the chain permits this token to be a dynamic connector at all.
///
/// Both selectors ask before spending a shortlist slot, and the reason is the
/// budget rather than the rule: `screened` and `connectors` are prefixes of the
/// ranking, so a refused candidate filtered downstream would take its slot with
/// it and the permitted candidate one rank below could never move up. Measured
/// against the live BSC ranking on 2026-08-06, filtering downstream cost one
/// routing slot and four screening slots across ten pairs — WBNB->USDC routed
/// three connectors where four were available and affordable.
///
/// Asked after `eligible_count` has already counted the candidate, so that
/// number keeps meaning what the ranking offered. A pair with nothing to route
/// and a pair whose candidates were all refused stay distinguishable.
fn permitted_connector(profile: &ChainProfile, connector: Address) -> bool {
    profile.dynamic_connector_allowlist.contains(&connector)
}

fn select_connectors(
    profile: &ChainProfile,
    token_in: Address,
    token_out: Address,
    left: &Adjacency,
    right: &Adjacency,
) -> Result<ConnectorSelection> {
    if left.token != token_in
        || right.token != token_out
        || left.protocols != right.protocols
        || left.fences != right.fences
    {
        return invalid("adjacency sides do not share endpoints, scope, and fences");
    }
    let edge_mask = |edge: &AdjacencyEdge| {
        edge.protocols
            .iter()
            .fold(0u32, |mask, protocol| mask | protocol.bit())
    };
    let mut right_masks = HashMap::with_capacity(right.edges.len());
    for edge in &right.edges {
        let neighbor = edge.neighbor(right.token).ok_or_else(|| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                "validated adjacency edge lost endpoint incidence",
            )
        })?;
        if right_masks.insert(neighbor, edge_mask(edge)).is_some() {
            return invalid("adjacency side contains a duplicate neighbor");
        }
    }
    let static_pairs = crate::chain::route_pairs_for(profile.connectors, token_in, token_out);
    let v4_enabled = left.protocols.contains(&Protocol::UNIV4);
    let native_alias_count = if v4_enabled {
        static_pairs
            .iter()
            .filter(|(token0, token1)| {
                *token0 == profile.wrapped_native || *token1 == profile.wrapped_native
            })
            .count()
    } else {
        0
    };
    // Each dynamic common-neighbor route contributes its two endpoint edges.
    // If an endpoint is wrapped native, its V4 address(0) alias consumes one
    // more topology pair. Keep selection within the same request budget used
    // by the indexed state adapter instead of discovering an unusable scope.
    let dynamic_pair_cost = 2 + usize::from(
        v4_enabled && (token_in == profile.wrapped_native || token_out == profile.wrapped_native),
    );
    let budget = profile.topology_pair_budget;
    let base_pair_count = static_pairs.len() + native_alias_count;
    let connector_limit = profile
        .dynamic_connector_cap
        .min(budget.saturating_sub(base_pair_count) / dynamic_pair_cost);
    // Screening carries the same ranking past the routable budget. Its pairs
    // travel in a request of their own, so the ceiling is the whole pair
    // allowance rather than what the static skeletons left over.
    let screen_limit = profile
        .screen_connector_cap
        .min(budget / dynamic_pair_cost)
        .max(connector_limit);
    let candidate_order = |left: &(Address, u32, u32, u32), right: &(Address, u32, u32, u32)| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
    };
    let mut eligible_count = 0usize;
    let mut shortlist = Vec::with_capacity(screen_limit + 1);
    let mut left_seen = HashSet::with_capacity(left.edges.len());
    for edge in &left.edges {
        let connector = edge.neighbor(left.token).ok_or_else(|| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                "validated adjacency edge lost endpoint incidence",
            )
        })?;
        if !left_seen.insert(connector) {
            return invalid("adjacency side contains a duplicate neighbor");
        }
        let left_mask = edge_mask(edge);
        let Some(&right_mask) = right_masks.get(&connector) else {
            continue;
        };
        if connector == Address::ZERO
            || connector == token_in
            || connector == token_out
            || profile.connectors.contains(&connector)
        {
            continue;
        }
        eligible_count += 1;
        if !permitted_connector(profile, connector) {
            continue;
        }
        // Ranking continues even when the routable budget is exhausted: a pair
        // that can admit nothing is exactly where the missing coverage is
        // worth measuring.
        if screen_limit == 0 {
            continue;
        }
        let candidate = (
            connector,
            (left_mask & right_mask).count_ones(),
            left_mask.count_ones().min(right_mask.count_ones()),
            (left_mask | right_mask).count_ones(),
        );
        let index = shortlist
            .binary_search_by(|existing| candidate_order(existing, &candidate))
            .unwrap_or_else(|index| index);
        shortlist.insert(index, candidate);
        if shortlist.len() > screen_limit {
            shortlist.pop();
        }
    }
    // One ranking, two prefixes of it. Taking the admitted set from the head of
    // the longer list keeps it byte-identical to what a `connector_limit`-sized
    // shortlist would have produced, because the rank is a total order.
    let screened = shortlist
        .into_iter()
        .map(|candidate| candidate.0)
        .collect::<Vec<_>>();
    let connectors = screened
        .iter()
        .take(connector_limit)
        .copied()
        .collect::<Vec<_>>();
    Ok(ConnectorSelection {
        fences: left.fences,
        protocols: left.protocols.clone(),
        shortlist_truncated: eligible_count > connectors.len(),
        connectors,
        screened,
        eligible_count,
        selector: ConnectorSelector::AdjacencyWalk,
    })
}

/// One endpoint's ranked connector candidates, already intersected and ordered
/// by the indexer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RankedConnectors {
    pub fences: CatalogFences,
    /// The protocols the ranking covered, which is the V2/V3 subset of the
    /// quote scope rather than the quote scope itself.
    pub protocols: Vec<Protocol>,
    pub candidates: Vec<Address>,
    /// True when either endpoint's ranking filled its per-token budget, so
    /// neighbours below its floor existed and were never weighed.
    pub truncated: bool,
}

/// Take the admitted and screened prefixes from a ranking the indexer already
/// ordered.
///
/// The popcount triple that ranks an adjacency walk plays no part here. It
/// measures how many protocols carry an edge, which says nothing about depth,
/// and it was only ever defensible over a candidate set small enough to
/// enumerate completely. Over a set already ordered by what a route through it
/// could carry, re-sorting by protocol count would actively destroy the signal.
fn select_ranked_connectors(
    profile: &ChainProfile,
    token_in: Address,
    token_out: Address,
    ranked: &RankedConnectors,
) -> Result<ConnectorSelection> {
    let static_pairs = crate::chain::route_pairs_for(profile.connectors, token_in, token_out);
    // The ranking is scoped to V2/V3, so no V4 native alias can be implied by a
    // candidate; the pair cost is the two endpoint edges plus the same alias
    // surcharge the walk pays when an endpoint is wrapped native and V4 routes.
    let v4_enabled = profile
        .quote_protocols()
        .iter()
        .any(|protocol| *protocol == Protocol::UNIV4.as_str());
    let native_alias_count = if v4_enabled {
        static_pairs
            .iter()
            .filter(|(token0, token1)| {
                *token0 == profile.wrapped_native || *token1 == profile.wrapped_native
            })
            .count()
    } else {
        0
    };
    let dynamic_pair_cost = 2 + usize::from(
        v4_enabled && (token_in == profile.wrapped_native || token_out == profile.wrapped_native),
    );
    let budget = profile.topology_pair_budget;
    let base_pair_count = static_pairs.len() + native_alias_count;
    let connector_limit = profile
        .dynamic_connector_cap
        .min(budget.saturating_sub(base_pair_count) / dynamic_pair_cost);
    let screen_limit = profile
        .screen_connector_cap
        .min(budget / dynamic_pair_cost)
        .max(connector_limit);

    let mut seen = HashSet::with_capacity(ranked.candidates.len());
    let mut eligible_count = 0usize;
    let mut screened = Vec::with_capacity(screen_limit);
    for candidate in &ranked.candidates {
        let connector = *candidate;
        if !seen.insert(connector) {
            return invalid("ranked connectors contain a duplicate candidate");
        }
        if connector == Address::ZERO
            || connector == token_in
            || connector == token_out
            || profile.connectors.contains(&connector)
        {
            continue;
        }
        eligible_count += 1;
        if !permitted_connector(profile, connector) {
            continue;
        }
        if screened.len() < screen_limit {
            screened.push(connector);
        }
    }
    let connectors = screened
        .iter()
        .take(connector_limit)
        .copied()
        .collect::<Vec<_>>();
    Ok(ConnectorSelection {
        fences: ranked.fences,
        protocols: ranked.protocols.clone(),
        shortlist_truncated: eligible_count > connectors.len() || ranked.truncated,
        connectors,
        screened,
        eligible_count,
        selector: ConnectorSelector::RankedProjection,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WireResponse {
    schema_version: u32,
    chain_id: u64,
    chain: WireChain,
    ready: bool,
    catalogs: WireCatalogs,
    factories: WireFactories,
    v23_fence: WireV23Fence,
    // V4 is deliberately left opaque until the selected readiness policy
    // requires it. A corrupt, unrequested V4 catalog must not take down a
    // V2/V3-only solver.
    v4_fence: serde_json::Value,
    protocols: Vec<String>,
    pairs: Vec<WirePair>,
    count: usize,
    pools: Vec<WirePool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WireAdjacencyResponse {
    schema_version: u32,
    chain_id: u64,
    chain: WireChain,
    ready: bool,
    catalogs: WireCatalogs,
    factories: WireFactories,
    v23_fence: WireV23Fence,
    v4_fence: serde_json::Value,
    protocols: Vec<String>,
    token: String,
    count: usize,
    next_page_token: Option<String>,
    edges: Vec<WireAdjacencyEdge>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAdjacencyEdge {
    token0: String,
    token1: String,
    protocols: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WireConnectorsResponse {
    schema_version: u32,
    chain_id: u64,
    chain: WireChain,
    ready: bool,
    catalogs: WireCatalogs,
    factories: WireFactories,
    protocols: Vec<String>,
    a: String,
    b: String,
    ranking: WireRanking,
    sides: WireConnectorSides,
    count: usize,
    candidates: Vec<WireConnectorCandidate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WireRanking {
    built_at: u64,
    #[allow(dead_code)]
    age_seconds: u64,
    per_token_limit: usize,
    #[allow(dead_code)]
    edges: u64,
    #[allow(dead_code)]
    tokens: u64,
    v23_fence: WireV23Fence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConnectorSides {
    a: WireConnectorSide,
    b: WireConnectorSide,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WireConnectorSide {
    ranked: usize,
    truncated: bool,
    #[allow(dead_code)]
    floor_usd: Option<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WireConnectorCandidate {
    token: String,
    // Ranking figures are read for ordering evidence only. They are floats from
    // an off-chain pricing pass and never reach a quote, an amount, or a
    // calldata field, so no exactness claim rests on them.
    bottleneck_usd: f64,
    #[allow(dead_code)]
    a_tvl_usd: f64,
    #[allow(dead_code)]
    b_tvl_usd: f64,
    a_protocols: Vec<String>,
    b_protocols: Vec<String>,
    #[allow(dead_code)]
    approx: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireChain {
    key: String,
    id: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCatalogs {
    v23: WireV23Catalog,
    univ2: WireCatalog,
    univ3: WireCatalog,
    pancakev2: WireCatalog,
    pancakev3: WireCatalog,
    univ4: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WireV23Catalog {
    ready: bool,
    degraded: bool,
    last_error: Option<String>,
    #[allow(dead_code)]
    last_error_at: Option<u64>,
    last_success_at: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCatalog {
    supported: bool,
    ready: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WireV4Catalog {
    supported: bool,
    ready: bool,
    degraded: bool,
    last_error: Option<String>,
    last_error_at: Option<u64>,
    local_count: u64,
    cursor_block: u64,
    target_block: u64,
    backfilled: bool,
    snapshot_source: Option<String>,
    snapshot_block: Option<u64>,
    snapshot_block_hash: Option<String>,
    snapshot_pool_count: Option<u64>,
    snapshot_deployment: Option<String>,
    snapshot_subgraph_id: Option<String>,
    snapshot_generation: Option<String>,
    snapshot_complete: bool,
    featured_block: Option<u64>,
    featured_count: Option<u64>,
    featured_asof: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFactories {
    univ2: Option<String>,
    univ3: Option<String>,
    pancakev2: Option<String>,
    pancakev3: Option<String>,
    univ4: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireV23Fence {
    seq: String,
    generation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireV4Fence {
    block: u64,
    generation: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePair {
    token0: String,
    token1: String,
}

/// One pool row. `proto` is a venue id; the chain's venue table says whether
/// it is an address pool or a V4 pool, and so which fields it must carry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct WirePool {
    proto: String,
    address: String,
    token0: String,
    token1: String,
    fee_ppm: Option<u32>,
    pool_id: Option<String>,
    key_fee_ppm: Option<u32>,
    tick_spacing: Option<i32>,
    hooks: Option<String>,
    created_block: Option<u64>,
}

impl WirePool {
    fn address_pool(self) -> Result<WireAddressPool> {
        if self.pool_id.is_some() || self.key_fee_ppm.is_some() || self.hooks.is_some() {
            return invalid("an address pool row carries V4 fields");
        }
        let Some(fee_ppm) = self.fee_ppm else {
            return invalid("an address pool row has no feePpm");
        };
        Ok(WireAddressPool {
            address: self.address,
            token0: self.token0,
            token1: self.token1,
            fee_ppm,
            tick_spacing: self.tick_spacing,
            created_block: self.created_block,
        })
    }

    fn v4_pool(self) -> Result<WireV4Pool> {
        if self.fee_ppm.is_some() {
            return invalid("a V4 pool row carries feePpm");
        }
        let (Some(pool_id), Some(tick_spacing), Some(hooks)) =
            (self.pool_id, self.tick_spacing, self.hooks)
        else {
            return invalid("a V4 pool row needs poolId, tickSpacing and hooks");
        };
        Ok(WireV4Pool {
            address: self.address,
            pool_id,
            token0: self.token0,
            token1: self.token1,
            key_fee_ppm: self.key_fee_ppm,
            tick_spacing,
            hooks,
            created_block: self.created_block,
        })
    }
}

struct WireAddressPool {
    address: String,
    token0: String,
    token1: String,
    fee_ppm: u32,
    tick_spacing: Option<i32>,
    created_block: Option<u64>,
}

struct WireV4Pool {
    address: String,
    pool_id: String,
    token0: String,
    token1: String,
    key_fee_ppm: Option<u32>,
    tick_spacing: i32,
    hooks: String,
    created_block: Option<u64>,
}

fn validate_response(
    wire: WireResponse,
    requested_pairs: Vec<TokenPair>,
    protocols: Vec<Protocol>,
    max_v23_age: Duration,
    profile: &ChainProfile,
    discovery: &IndexedEvmDiscovery,
) -> Result<Topology> {
    if wire.schema_version != discovery.schema_version {
        return invalid(format!(
            "schemaVersion must be {}",
            discovery.schema_version
        ));
    }
    if wire.chain_id != profile.chain_id
        || wire.chain.id != profile.chain_id
        || wire.chain.key != profile.key
    {
        return invalid("response is not bound to the selected chain profile");
    }
    if !wire.ready {
        return invalid("top-level catalog is not ready");
    }
    let echoed_protocols = wire
        .protocols
        .iter()
        .map(|protocol| parse_protocol(protocol))
        .collect::<Result<Vec<_>>>()?;
    if echoed_protocols != protocols {
        return invalid("protocol echo does not exactly match the request");
    }
    let v4_catalog = validate_catalogs(&wire.catalogs, max_v23_age, discovery, &protocols)?;
    validate_factories(wire.factories, discovery)?;
    let require_v4 = required_protocols(discovery, &protocols).contains(&Protocol::UNIV4);
    let fences = validate_fences(wire.v23_fence, wire.v4_fence, require_v4)?;
    if require_v4 {
        let fence = fences.v4.ok_or_else(|| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                "required v4 catalog is missing its fence",
            )
        })?;
        validate_v4_fence_binding(
            v4_catalog.as_ref().ok_or_else(|| {
                IndexerError::new(
                    IndexerErrorKind::InvalidResponse,
                    "required v4 catalog was not decoded",
                )
            })?,
            fence,
        )?;
    }

    let echoed_pairs = wire
        .pairs
        .into_iter()
        .map(|pair| {
            Ok(TokenPair {
                token0: parse_lower_address(&pair.token0, "echo token0")?,
                token1: parse_lower_address(&pair.token1, "echo token1")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if echoed_pairs != requested_pairs {
        return invalid("pairs echo does not exactly match the request");
    }
    if wire.count > MAX_POOLS || wire.pools.len() > MAX_POOLS {
        return invalid("pool count exceeds the 2048-row limit");
    }
    if wire.count != wire.pools.len() {
        return invalid("count does not equal pools length");
    }

    let requested: HashSet<TokenPair> = requested_pairs.iter().copied().collect();
    let mut identities: HashMap<Identity, PoolTopology> = HashMap::new();
    let mut previous = None;
    let mut all_pools = Vec::with_capacity(wire.pools.len());
    for pool in wire.pools {
        let pool = validate_pool(pool, &requested, discovery, &protocols)?;
        let sort_key = pool.sort_key();
        if previous
            .as_ref()
            .is_some_and(|previous| previous >= &sort_key)
        {
            return invalid("pools are not in deterministic strict order");
        }
        previous = Some(sort_key);
        let identity = pool.identity();
        if let Some(existing) = identities.insert(identity, pool.clone()) {
            return if existing == pool {
                invalid("response contains a duplicate pool identity")
            } else {
                invalid("response contains a conflicting pool identity")
            };
        }
        all_pools.push(pool);
    }

    let selected: HashSet<Protocol> = protocols.iter().copied().collect();
    let pools = all_pools
        .into_iter()
        .filter(|pool| selected.contains(&pool.protocol()))
        .collect();
    Ok(Topology {
        pairs: requested_pairs,
        protocols,
        fences,
        pools,
    })
}

fn parse_protocol(value: &str) -> Result<Protocol> {
    match Protocol::known(value) {
        Some(protocol) => Ok(protocol),
        None => invalid("protocol echo contains an unknown protocol"),
    }
}

fn required_protocols(
    discovery: &IndexedEvmDiscovery,
    requested: &[Protocol],
) -> HashSet<Protocol> {
    match discovery.readiness {
        ReadinessPolicy::WholeContract | ReadinessPolicy::ConfiguredVenues => discovery
            .venues
            .iter()
            .map(|venue| venue.protocol())
            .collect(),
        ReadinessPolicy::RequestedVenues => requested.iter().copied().collect(),
    }
}

fn validate_catalogs(
    catalogs: &WireCatalogs,
    max_v23_age: Duration,
    discovery: &IndexedEvmDiscovery,
    requested: &[Protocol],
) -> Result<Option<WireV4Catalog>> {
    let required = required_protocols(discovery, requested);
    let require_v23 = required.iter().any(|protocol| *protocol != Protocol::UNIV4);
    if require_v23 {
        if !catalogs.v23.ready
            || catalogs.v23.degraded
            || catalogs.v23.last_error.is_some()
            || catalogs.v23.last_error_at.is_some()
        {
            return invalid("v23 catalog is not healthy and ready");
        }
        let last_success_at = catalogs
            .v23
            .last_success_at
            .filter(|timestamp| *timestamp > 0)
            .ok_or_else(|| {
                IndexerError::new(
                    IndexerErrorKind::InvalidResponse,
                    "ready v23 catalog is missing a positive lastSuccessAt",
                )
            })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                IndexerError::new(
                    IndexerErrorKind::InvalidResponse,
                    "system clock is before the Unix epoch",
                )
            })?
            .as_secs();
        if last_success_at > now.saturating_add(MAX_FUTURE_CLOCK_SKEW.as_secs()) {
            return invalid("v23 lastSuccessAt is implausibly in the future");
        }
        if !max_v23_age.is_zero() && now.saturating_sub(last_success_at) > max_v23_age.as_secs() {
            return invalid("v23 catalog is stale");
        }
        for (protocol, catalog) in [
            (Protocol::UNIV2, &catalogs.univ2),
            (Protocol::UNIV3, &catalogs.univ3),
            (Protocol::PANCAKEV2, &catalogs.pancakev2),
            (Protocol::PANCAKEV3, &catalogs.pancakev3),
        ] {
            if !required.contains(&protocol) {
                continue;
            }
            if !catalog.supported || !catalog.ready {
                return invalid(format!(
                    "{} catalog is not supported and ready",
                    protocol.as_str()
                ));
            }
        }
    }
    let require_v4 = required.contains(&Protocol::UNIV4);
    if !require_v4 {
        return Ok(None);
    }
    let v4: WireV4Catalog = serde_json::from_value(catalogs.univ4.clone()).map_err(|_| {
        IndexerError::new(
            IndexerErrorKind::InvalidResponse,
            "univ4 capability is malformed",
        )
    })?;
    if !v4.supported
        || !v4.ready
        || v4.degraded
        || v4.last_error.is_some()
        || v4.last_error_at.is_some()
    {
        return invalid("univ4 catalog is not healthy, supported and ready");
    }
    if !v4.backfilled
        || !v4.snapshot_complete
        || v4.local_count == 0
        || v4.cursor_block == 0
        || v4.target_block == 0
        || v4.cursor_block < v4.target_block
    {
        return invalid("univ4 capability contradicts its ready state");
    }
    if v4.snapshot_source.as_deref() != Some("thegraph") {
        return invalid("univ4 ready snapshot is not sourced from The Graph");
    }
    let snapshot_block = v4
        .snapshot_block
        .filter(|block| *block > 0)
        .ok_or_else(|| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                "univ4 ready snapshot is missing a positive block",
            )
        })?;
    if snapshot_block > v4.cursor_block {
        return invalid("univ4 snapshot block is ahead of its cursor");
    }
    v4.snapshot_block_hash
        .as_deref()
        .ok_or_else(|| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                "univ4 ready snapshot is missing a block hash",
            )
        })
        .and_then(|hash| parse_lower_b256(hash, "univ4 snapshot block hash"))?;
    let snapshot_count = v4
        .snapshot_pool_count
        .filter(|count| *count > 0)
        .ok_or_else(|| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                "univ4 ready snapshot is missing a positive pool count",
            )
        })?;
    if snapshot_count > v4.local_count {
        return invalid("univ4 snapshot pool count exceeds the local catalog");
    }
    for (label, value) in [
        (
            "univ4 snapshot deployment",
            v4.snapshot_deployment.as_deref(),
        ),
        (
            "univ4 snapshot subgraph id",
            v4.snapshot_subgraph_id.as_deref(),
        ),
    ] {
        if !value.is_some_and(is_graph_identifier) {
            return invalid(format!("{label} is missing or malformed"));
        }
    }
    match (v4.featured_block, v4.featured_count, v4.featured_asof) {
        (None, None, None) => {}
        (Some(block), Some(count), Some(asof))
            if block > 0 && count > 0 && count <= v4.local_count && asof > 0 => {}
        _ => return invalid("univ4 featured snapshot metadata is incomplete or inconsistent"),
    }
    Ok(Some(v4))
}

fn is_graph_identifier(value: &str) -> bool {
    (32..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() && !matches!(byte, b'0' | b'O' | b'I' | b'l'))
}

fn validate_v4_fence_binding(catalog: &WireV4Catalog, fence: V4Fence) -> Result<()> {
    if catalog.cursor_block != fence.block {
        return invalid("v4 capability cursorBlock does not match its fence");
    }
    let generation = catalog.snapshot_generation.as_deref().ok_or_else(|| {
        IndexerError::new(
            IndexerErrorKind::InvalidResponse,
            "ready v4 capability is missing snapshotGeneration",
        )
    })?;
    if parse_lower_b256(generation, "v4 capability snapshotGeneration")? != fence.generation {
        return invalid("v4 capability generation does not match its fence");
    }
    Ok(())
}

fn validate_v4_adjacency_fence_binding(catalog: &WireV4Catalog, fence: V4Fence) -> Result<()> {
    if catalog.cursor_block < fence.block {
        return invalid("v4 capability cursorBlock is behind its adjacency fence");
    }
    let generation = catalog.snapshot_generation.as_deref().ok_or_else(|| {
        IndexerError::new(
            IndexerErrorKind::InvalidResponse,
            "ready v4 capability is missing snapshotGeneration",
        )
    })?;
    if parse_lower_b256(generation, "v4 capability snapshotGeneration")? != fence.generation {
        return invalid("v4 capability generation does not match its adjacency fence");
    }
    Ok(())
}

fn validate_factories(wire: WireFactories, discovery: &IndexedEvmDiscovery) -> Result<()> {
    let factories = [
        (Protocol::UNIV2, wire.univ2, "univ2 factory"),
        (Protocol::UNIV3, wire.univ3, "univ3 factory"),
        (Protocol::PANCAKEV2, wire.pancakev2, "pancakev2 factory"),
        (Protocol::PANCAKEV3, wire.pancakev3, "pancakev3 factory"),
        (Protocol::UNIV4, wire.univ4, "univ4 PoolManager"),
    ];
    for (protocol, value, label) in factories {
        let Some(venue) = discovery.venue(protocol) else {
            // Schema v2 keeps stable well-known keys, but an EVM profile need
            // not deploy every family. Unsupported null/absent identities are
            // outside this profile's trust contract and are deliberately not
            // parsed or assigned dummy addresses.
            continue;
        };
        let value = value.as_deref().ok_or_else(|| {
            IndexerError::new(
                IndexerErrorKind::InvalidResponse,
                format!("configured {label} is missing"),
            )
        })?;
        let actual = parse_lower_address(value, label)?;
        if actual != venue.identity() {
            return invalid(format!(
                "{} deployment identity mismatch",
                protocol.as_str()
            ));
        }
    }
    Ok(())
}

fn validate_fences(
    v23: WireV23Fence,
    v4: serde_json::Value,
    require_v4: bool,
) -> Result<CatalogFences> {
    let seq = parse_decimal_fence(&v23.seq, "v23 seq")?;
    let generation = parse_decimal_fence(&v23.generation, "v23 generation")?;
    if !require_v4 {
        return Ok(CatalogFences {
            v23: V23Fence { seq, generation },
            v4: None,
        });
    }
    let v4: WireV4Fence = serde_json::from_value(v4).map_err(|_| {
        IndexerError::new(
            IndexerErrorKind::InvalidResponse,
            "required v4 fence is malformed",
        )
    })?;
    let v4 = match (v4.block, v4.generation) {
        (block, Some(generation)) => {
            if block == 0 {
                return invalid("v4 fence block must be positive when present");
            }
            Some(V4Fence {
                block,
                generation: parse_lower_b256(&generation, "v4 generation")?,
            })
        }
        (_, None) => {
            return invalid("ready v4 catalog is missing its generation");
        }
    };
    Ok(CatalogFences {
        v23: V23Fence { seq, generation },
        v4,
    })
}

fn validate_pool(
    pool: WirePool,
    requested: &HashSet<TokenPair>,
    discovery: &IndexedEvmDiscovery,
    protocols: &[Protocol],
) -> Result<PoolTopology> {
    let protocol = parse_protocol(&pool.proto)?;
    let parsed = match discovery.venue(protocol) {
        Some(CatalogVenue::V4 { .. }) => validate_v4_pool(pool.v4_pool()?, discovery)?,
        Some(_) => validate_address_pool(protocol, pool.address_pool()?, discovery)?,
        None => return invalid(format!("unconfigured protocol row {protocol}")),
    };
    if !protocols.contains(&parsed.protocol()) {
        return invalid("pool row is outside the echoed protocol scope");
    }
    if !requested.contains(&parsed.pair()) {
        return invalid("pool row does not belong to a requested pair");
    }
    Ok(parsed)
}

fn validate_address_pool(
    protocol: Protocol,
    wire: WireAddressPool,
    discovery: &IndexedEvmDiscovery,
) -> Result<PoolTopology> {
    let venue = discovery.venue(protocol).ok_or_else(|| {
        IndexerError::new(
            IndexerErrorKind::InvalidResponse,
            format!("unconfigured protocol row {}", protocol.as_str()),
        )
    })?;
    let address = parse_lower_address(&wire.address, "pool address")?;
    let token0 = parse_lower_address(&wire.token0, "pool token0")?;
    let token1 = parse_lower_address(&wire.token1, "pool token1")?;
    if address == Address::ZERO || token0 == Address::ZERO || token0 >= token1 {
        return invalid("address pool identity is zero or non-canonical");
    }
    if wire.created_block == Some(0) {
        return invalid("createdBlock must be positive when present");
    }
    match venue {
        CatalogVenue::V2 { fee_ppm, .. } => {
            if wire.fee_ppm != fee_ppm || wire.tick_spacing.is_some() {
                return invalid(format!(
                    "{} row has invalid fee or tickSpacing",
                    protocol.as_str()
                ));
            }
        }
        CatalogVenue::V3 { .. } => {
            if wire.fee_ppm == 0 || wire.fee_ppm >= 1_000_000 {
                return invalid("v3 feePpm is out of range");
            }
            if !wire
                .tick_spacing
                .is_some_and(|spacing| (1..=32_767).contains(&spacing))
            {
                return invalid("v3 tickSpacing is out of range");
            }
        }
        CatalogVenue::V4 { .. } => return invalid("v4 has a distinct wire row"),
    }
    Ok(PoolTopology::Address(AddressPoolTopology {
        protocol,
        address,
        token0,
        token1,
        fee_ppm: wire.fee_ppm,
        tick_spacing: wire.tick_spacing,
        created_block: wire.created_block,
    }))
}

fn validate_v4_pool(wire: WireV4Pool, discovery: &IndexedEvmDiscovery) -> Result<PoolTopology> {
    let venue = discovery.venue(Protocol::UNIV4).ok_or_else(|| {
        IndexerError::new(
            IndexerErrorKind::InvalidResponse,
            "unconfigured protocol row univ4",
        )
    })?;
    let manager = parse_lower_address(&wire.address, "v4 PoolManager")?;
    let pool_id = parse_lower_b256(&wire.pool_id, "v4 PoolId")?;
    let currency0 = parse_lower_address(&wire.token0, "v4 currency0")?;
    let currency1 = parse_lower_address(&wire.token1, "v4 currency1")?;
    let hooks = parse_lower_address(&wire.hooks, "v4 hooks")?;
    if manager != venue.identity() || pool_id == B256::ZERO || currency0 >= currency1 {
        return invalid("v4 identity is zero, non-canonical, or uses the wrong PoolManager");
    }
    if !matches!(
        wire.key_fee_ppm,
        None | Some(0..=1_000_000) | Some(V4_DYNAMIC_FEE_FLAG)
    ) {
        return invalid("v4 keyFeePpm is out of range");
    }
    if !(1..=32_767).contains(&wire.tick_spacing) {
        return invalid("v4 tickSpacing is out of range");
    }
    if wire.created_block == Some(0) {
        return invalid("v4 createdBlock must be positive when present");
    }
    Ok(PoolTopology::Univ4(V4PoolTopology {
        pool_manager: manager,
        pool_id,
        currency0,
        currency1,
        key_fee_ppm: wire.key_fee_ppm,
        tick_spacing: wire.tick_spacing,
        hooks,
        created_block: wire.created_block,
    }))
}

fn parse_address(value: &str, label: &str) -> Result<Address> {
    if value.len() != 42
        || !value.starts_with("0x")
        || !value.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
    {
        return invalid(format!("{label} is not an address"));
    }
    value.parse().map_err(|_| {
        IndexerError::new(
            IndexerErrorKind::InvalidResponse,
            format!("{label} is invalid"),
        )
    })
}

fn parse_lower_address(value: &str, label: &str) -> Result<Address> {
    if !is_lower_hex(value, 40) {
        return invalid(format!("{label} is not canonical lowercase hex"));
    }
    parse_address(value, label)
}

fn parse_lower_b256(value: &str, label: &str) -> Result<B256> {
    if !is_lower_hex(value, 64) {
        return invalid(format!("{label} is not canonical lowercase bytes32"));
    }
    value.parse().map_err(|_| {
        IndexerError::new(
            IndexerErrorKind::InvalidResponse,
            format!("{label} is invalid"),
        )
    })
}

fn is_lower_hex(value: &str, digits: usize) -> bool {
    value.len() == digits + 2
        && value.starts_with("0x")
        && value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn parse_decimal_fence(value: &str, label: &str) -> Result<u64> {
    let canonical = value == "0"
        || (value
            .as_bytes()
            .first()
            .is_some_and(|byte| (b'1'..=b'9').contains(byte))
            && value.as_bytes()[1..].iter().all(u8::is_ascii_digit));
    if !canonical {
        return invalid(format!("{label} is not a canonical decimal"));
    }
    value.parse().map_err(|_| {
        IndexerError::new(
            IndexerErrorKind::InvalidResponse,
            format!("{label} is out of range"),
        )
    })
}

fn invalid<T>(detail: impl Into<String>) -> Result<T> {
    Err(IndexerError::new(IndexerErrorKind::InvalidResponse, detail))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every protocol the synthetic indexer serves.
    const ALL_SYNTHETIC: [Protocol; 5] = [
        Protocol::UNIV2,
        Protocol::UNIV3,
        Protocol::PANCAKEV2,
        Protocol::PANCAKEV3,
        Protocol::UNIV4,
    ];
    use alloy_primitives::address;
    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::{Response, StatusCode, header};
    use axum::routing::get;
    use serde_json::{Value, json};
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    const ZERO: &str = "0x0000000000000000000000000000000000000000";
    const USDT: &str = "0x55d398326f99059ff775485246999027b3197955";
    const WBNB: &str = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c";
    const MANAGER: &str = "0x28e2ea090877bf75740558f6bfb36a5ffee9e9df";

    /// Every `Address::repeat_byte` fixture, permitted as a connector.
    ///
    /// A selector refuses any token its chain does not permit, so budget
    /// arithmetic cannot be tested against a real profile using invented
    /// addresses. The rules those tests are about — the pair budget, the V4
    /// native-alias reservation, determinism, symmetry — hold whatever a chain
    /// permits, and the permit rule has tests of its own. Covering the whole
    /// byte range keeps a new fixture from silently selecting nothing.
    const FIXTURE_CONNECTORS: [Address; 256] = {
        let mut fixtures = [Address::ZERO; 256];
        let mut byte = 0usize;
        while byte < 256 {
            fixtures[byte] = Address::repeat_byte(byte as u8);
            byte += 1;
        }
        fixtures
    };

    /// BSC's budgets over fixture tokens.
    static SELECTION_PROFILE: std::sync::LazyLock<ChainProfile> =
        std::sync::LazyLock::new(|| ChainProfile {
            dynamic_connector_allowlist: &FIXTURE_CONNECTORS,
            ..*crate::chain::BSC_PROFILE
        });

    const SYNTHETIC_VENUES: [CatalogVenue; 2] = [
        CatalogVenue::V2 {
            protocol: Protocol::UNIV2,
            factory: address!("00000000000000000000000000000000000000a1"),
            fee_ppm: 3_000,
            quote: true,
        },
        CatalogVenue::V3 {
            protocol: Protocol::UNIV3,
            factory: address!("00000000000000000000000000000000000000a2"),
            verify_pool_spacing: false,
            fee_tiers: &[],
            quote: true,
        },
    ];
    const SYNTHETIC_DISCOVERY: IndexedEvmDiscovery = IndexedEvmDiscovery {
        schema_version: 2,
        readiness: ReadinessPolicy::RequestedVenues,
        venues: &SYNTHETIC_VENUES,
        candidates: crate::catalog::CandidateSource::Indexer,
    };
    const SYNTHETIC_PROFILE: ChainProfile = ChainProfile {
        key: "synthetic",
        name: "Synthetic EVM",
        chain_id: 9_999,
        public_rpc: "http://127.0.0.1:1",
        wrapped_native: address!("00000000000000000000000000000000000000b1"),
        stable: address!("00000000000000000000000000000000000000b2"),
        stable_decimals: 18,
        connectors: &[],
        topology_pair_budget: MAX_PAIRS,
        dynamic_connector_cap: 3,
        screen_connector_cap: 6,
        // Unused here: the allowlist is applied where the ranking meets the
        // route universe, and these tests stop at the client.
        dynamic_connector_allowlist: &[],
        discovery: DiscoveryProfile::IndexedEvm(&SYNTHETIC_DISCOVERY),
        settler: None,
        native_rfq: None,
        capabilities: crate::chain::SolverCapabilities {
            quote: true,
            unavailable_reason: None,
        },
    };

    #[derive(Clone, Debug)]
    enum Reply {
        Json(Arc<Vec<u8>>),
        DeclaredOversize,
        StreamedOversize,
        Redirect(String),
    }

    #[derive(Clone)]
    struct MockState {
        reply: Reply,
        queries: Arc<Mutex<Vec<String>>>,
    }

    async fn mock_handler(State(state): State<MockState>, uri: axum::http::Uri) -> Response<Body> {
        state
            .queries
            .lock()
            .expect("query lock")
            .push(uri.query().unwrap_or_default().to_string());
        match state.reply {
            Reply::Json(body) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.as_ref().clone()))
                .unwrap(),
            Reply::DeclaredOversize => Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(vec![b' '; MAX_RESPONSE_BYTES + 1]))
                .unwrap(),
            Reply::StreamedOversize => {
                let chunks = futures_util::stream::iter([
                    Ok::<Bytes, Infallible>(Bytes::from(vec![b' '; MAX_RESPONSE_BYTES])),
                    Ok(Bytes::from_static(b"x")),
                ]);
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(chunks))
                    .unwrap()
            }
            Reply::Redirect(location) => Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, location)
                .body(Body::empty())
                .unwrap(),
        }
    }

    async fn spawn(reply: Reply) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let queries = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route(ENDPOINT_PATH, get(mock_handler))
            .route(ADJACENCY_ENDPOINT_PATH, get(mock_handler))
            .with_state(MockState {
                reply,
                queries: queries.clone(),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), queries, server)
    }

    async fn spawn_json(
        value: Value,
    ) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        spawn(Reply::Json(Arc::new(serde_json::to_vec(&value).unwrap()))).await
    }

    #[derive(Clone)]
    struct SlowAdjacencyState {
        delay: Duration,
        requests: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn slow_adjacency_handler(
        State(state): State<SlowAdjacencyState>,
        uri: axum::http::Uri,
    ) -> Response<Body> {
        state
            .requests
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(state.delay).await;
        let token = uri
            .query()
            .and_then(|query| {
                query
                    .split('&')
                    .find_map(|part| part.strip_prefix("token="))
            })
            .and_then(|token| token.parse::<Address>().ok())
            .expect("test adjacency request has a token");
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&valid_adjacency_response(token, &[])).unwrap(),
            ))
            .unwrap()
    }

    async fn spawn_slow_adjacency(
        delay: Duration,
    ) -> (
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let app = Router::new()
            .route(ADJACENCY_ENDPOINT_PATH, get(slow_adjacency_handler))
            .with_state(SlowAdjacencyState {
                delay,
                requests: requests.clone(),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), requests, server)
    }

    fn native_pair() -> TokenPair {
        TokenPair::new(Address::ZERO, USDT.parse().unwrap()).unwrap()
    }

    fn wrapped_pair() -> TokenPair {
        TokenPair::new(USDT.parse().unwrap(), WBNB.parse().unwrap()).unwrap()
    }

    fn valid_response() -> Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        json!({
            "schemaVersion": 2,
            "chainId": 56,
            "chain": { "key": "bsc", "id": 56 },
            "ready": true,
            "catalogs": {
                "v23": {
                    "ready": true,
                    "degraded": false,
                    "lastError": null,
                    "lastErrorAt": null,
                    "lastSuccessAt": now
                },
                "univ2": { "supported": true, "ready": true },
                "univ3": { "supported": true, "ready": true },
                "pancakev2": { "supported": true, "ready": true },
                "pancakev3": { "supported": true, "ready": true },
                "univ4": {
                    "supported": true,
                    "ready": true,
                    "degraded": false,
                    "lastError": null,
                    "lastErrorAt": null,
                    "localCount": 100,
                    "cursorBlock": 120_000_000,
                    "targetBlock": 120_000_000,
                    "backfilled": true,
                    "snapshotSource": "thegraph",
                    "snapshotBlock": 119_900_000,
                    "snapshotBlockHash": format!("0x{}", "cd".repeat(32)),
                    "snapshotPoolCount": 100,
                    "snapshotDeployment": format!("Qm{}", "a".repeat(44)),
                    "snapshotSubgraphId": "a".repeat(44),
                    "snapshotGeneration": format!("0x{}", "ab".repeat(32)),
                    "snapshotComplete": true,
                    "featuredBlock": null,
                    "featuredCount": null,
                    "featuredAsof": null
                }
            },
            "factories": {
                "univ2": "0x8909dc15e40173ff4699343b6eb8132c65e18ec6",
                "univ3": "0xdb1d10011ad0ff90774d0c6bb92e5c5c8b4461f7",
                "pancakev2": "0xca143ce32fe78f1f7019d7d551a6402fc5350c73",
                "pancakev3": "0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865",
                "univ4": MANAGER
            },
            "v23Fence": { "seq": "123", "generation": "4" },
            "v4Fence": {
                "block": 120_000_000,
                "generation": format!("0x{}", "ab".repeat(32))
            },
            "protocols": ["univ2", "univ3", "pancakev2", "pancakev3", "univ4"],
            "pairs": [
                { "token0": ZERO, "token1": USDT },
                { "token0": USDT, "token1": WBNB }
            ],
            "count": 5,
            "pools": [
                {
                    "proto": "univ4",
                    "address": MANAGER,
                    "poolId": format!("0x{}", "11".repeat(32)),
                    "token0": ZERO,
                    "token1": USDT,
                    "keyFeePpm": null,
                    "tickSpacing": 10,
                    "hooks": ZERO,
                    "createdBlock": null
                },
                {
                    "proto": "univ2",
                    "address": "0x0000000000000000000000000000000000000001",
                    "token0": USDT,
                    "token1": WBNB,
                    "feePpm": 3000,
                    "tickSpacing": null,
                    "createdBlock": null
                },
                {
                    "proto": "univ3",
                    "address": "0x0000000000000000000000000000000000000002",
                    "token0": USDT,
                    "token1": WBNB,
                    "feePpm": 500,
                    "tickSpacing": 10,
                    "createdBlock": 12_400_000
                },
                {
                    "proto": "pancakev2",
                    "address": "0x0000000000000000000000000000000000000003",
                    "token0": USDT,
                    "token1": WBNB,
                    "feePpm": 2500,
                    "tickSpacing": null,
                    "createdBlock": null
                },
                {
                    "proto": "pancakev3",
                    "address": "0x0000000000000000000000000000000000000004",
                    "token0": USDT,
                    "token1": WBNB,
                    "feePpm": 2500,
                    "tickSpacing": 50,
                    "createdBlock": 27_000_000
                }
            ]
        })
    }

    fn valid_response_for(protocols: &[Protocol]) -> Value {
        let mut response = valid_response();
        response["protocols"] = Value::Array(
            protocols
                .iter()
                .map(|protocol| Value::String(protocol.as_str().to_string()))
                .collect(),
        );
        let selected: HashSet<_> = protocols.iter().map(|protocol| protocol.as_str()).collect();
        response["pools"]
            .as_array_mut()
            .unwrap()
            .retain(|pool| selected.contains(pool["proto"].as_str().unwrap()));
        response["count"] = json!(response["pools"].as_array().unwrap().len());
        response
    }

    async fn fetch_value(value: Value) -> Result<Topology> {
        let (url, _, server) = spawn_json(value).await;
        let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        let result = client
            .topology(&[wrapped_pair(), native_pair()], &ALL_SYNTHETIC)
            .await;
        server.abort();
        result
    }

    fn quote_protocols() -> Vec<Protocol> {
        vec![
            Protocol::UNIV2,
            Protocol::UNIV3,
            Protocol::PANCAKEV2,
            Protocol::PANCAKEV3,
        ]
    }

    fn valid_adjacency_response(token: Address, neighbors: &[(Address, Vec<Protocol>)]) -> Value {
        let protocols = quote_protocols();
        let mut response = valid_response_for(&protocols);
        let object = response.as_object_mut().unwrap();
        object.remove("pairs");
        object.remove("pools");
        object.insert("token".to_string(), json!(format!("{token:#x}")));
        object.insert("nextPageToken".to_string(), Value::Null);
        let mut neighbors = neighbors.to_vec();
        neighbors.sort_by_key(|(neighbor, _)| *neighbor);
        let edges = neighbors
            .into_iter()
            .map(|(neighbor, protocols)| {
                let (token0, token1) = if token < neighbor {
                    (token, neighbor)
                } else {
                    (neighbor, token)
                };
                json!({
                    "token0": format!("{token0:#x}"),
                    "token1": format!("{token1:#x}"),
                    "protocols": protocols
                        .iter()
                        .map(|protocol| protocol.as_str())
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        object.insert("count".to_string(), json!(edges.len()));
        object.insert("edges".to_string(), Value::Array(edges));
        response
    }

    async fn fetch_adjacency_value(
        value: Value,
        token: Address,
        explicit_fences: Option<CatalogFences>,
    ) -> Result<Adjacency> {
        let (url, _, server) = spawn_json(value).await;
        let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        let result = client
            .adjacency(token, &quote_protocols(), explicit_fences)
            .await;
        server.abort();
        result
    }

    #[tokio::test]
    async fn adjacency_accepts_a_strict_page_and_reuses_explicit_fences() {
        let token = Address::repeat_byte(0x11);
        let neighbors = vec![
            (
                Address::repeat_byte(0x22),
                vec![Protocol::UNIV2, Protocol::PANCAKEV2],
            ),
            (Address::repeat_byte(0x33), vec![Protocol::UNIV3]),
        ];
        let response = valid_adjacency_response(token, &neighbors);
        let fences = CatalogFences {
            v23: V23Fence {
                seq: 123,
                generation: 4,
            },
            v4: None,
        };
        let (url, queries, server) = spawn_json(response).await;
        let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        let adjacency = client
            .adjacency(token, &quote_protocols(), Some(fences))
            .await
            .unwrap();
        server.abort();
        assert_eq!(adjacency.fences, fences);
        assert_eq!(adjacency.edges.len(), 2);
        assert_eq!(adjacency.edges[0].neighbor(token), Some(neighbors[0].0));
        let query = &queries.lock().unwrap()[0];
        assert!(query.contains("limit=512"));
        assert!(query.contains("v23_seq=123"));
        assert!(query.contains("v23_generation=4"));
        assert!(!query.contains("page_token="));
    }

    #[tokio::test]
    async fn native_zero_is_a_valid_edge_but_not_a_connector() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x99);
        let response =
            valid_adjacency_response(token_in, &[(Address::ZERO, vec![Protocol::UNIV2])]);
        let adjacency = fetch_adjacency_value(response, token_in, None)
            .await
            .unwrap();
        assert_eq!(adjacency.edges[0].neighbor(token_in), Some(Address::ZERO));

        let fences = adjacency.fences;
        let right = adjacency_fixture(token_out, &[(Address::ZERO, &[Protocol::UNIV2])], fences);
        let selected =
            select_connectors(&SELECTION_PROFILE, token_in, token_out, &adjacency, &right).unwrap();
        assert!(selected.connectors.is_empty());
        assert_eq!(selected.eligible_count, 0);
    }

    #[tokio::test]
    async fn adjacency_rejects_noncanonical_rows_scope_and_pagination() {
        let token = Address::repeat_byte(0x11);
        let neighbor = Address::repeat_byte(0x22);
        let base =
            valid_adjacency_response(token, &[(neighbor, vec![Protocol::UNIV2, Protocol::UNIV3])]);

        let mut uppercase = base.clone();
        uppercase["edges"][0]["token1"] = json!(format!("0x{}", "AB".repeat(20)));
        let mut unordered = base.clone();
        unordered["edges"][0]["protocols"] = json!(["univ3", "univ2"]);
        let mut foreign = base.clone();
        foreign["edges"][0]["token0"] = json!(format!("{:#x}", Address::repeat_byte(0x01)));
        let mut partial = base.clone();
        partial["nextPageToken"] = json!("YWJj");
        let mut unknown = base;
        unknown["aggregateTotal"] = json!(1);

        for (label, response) in [
            ("uppercase", uppercase),
            ("unordered", unordered),
            ("foreign", foreign),
            ("partial", partial),
            ("unknown", unknown),
        ] {
            let error = fetch_adjacency_value(response, token, None)
                .await
                .expect_err(label);
            assert_eq!(error.kind(), IndexerErrorKind::InvalidResponse, "{label}");
        }
    }

    #[tokio::test]
    async fn connector_selection_timeout_covers_both_endpoint_requests() {
        let (url, requests, server) = spawn_slow_adjacency(Duration::from_millis(100)).await;
        let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .timeout(Duration::from_secs(1))
            .connector_selection_timeout(Duration::from_millis(175))
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let error = client
            .connector_selection(
                Address::repeat_byte(0x11),
                Address::repeat_byte(0x99),
                &quote_protocols(),
            )
            .await
            .unwrap_err();
        server.abort();

        assert_eq!(error.kind(), IndexerErrorKind::Transport);
        assert!(error.to_string().contains("selection timed out"));
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the first subrequest should finish inside its per-request timeout"
        );
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    fn adjacency_fixture(
        token: Address,
        rows: &[(Address, &[Protocol])],
        fences: CatalogFences,
    ) -> Adjacency {
        Adjacency {
            token,
            protocols: quote_protocols(),
            fences,
            edges: rows
                .iter()
                .map(|(neighbor, protocols)| {
                    let (token0, token1) = if token < *neighbor {
                        (token, *neighbor)
                    } else {
                        (*neighbor, token)
                    };
                    AdjacencyEdge {
                        token0,
                        token1,
                        protocols: protocols.to_vec(),
                    }
                })
                .collect(),
        }
    }

    /// The pair budget that production actually runs: with V4 in scope every
    /// WBNB edge costs an `address(0)` alias too, which on a generic pair
    /// leaves room for exactly one routable connector. Screening is what keeps
    /// the other candidates measurable.
    #[test]
    fn screening_carries_the_ranking_past_the_routable_budget() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x99);
        // Eight, so the routable budget (five here) is genuinely smaller than
        // the screening shortlist (six) and both are smaller than the ranking.
        // At five the cap used to make that true; at eight the budget must.
        let candidates: Vec<Address> = (1..=8u8).map(Address::repeat_byte).collect();
        let fences = CatalogFences {
            v23: V23Fence {
                seq: 4,
                generation: 2,
            },
            v4: Some(V4Fence {
                block: 9,
                generation: B256::repeat_byte(0x33),
            }),
        };
        let with_v4 = |token: Address| Adjacency {
            token,
            protocols: vec![
                Protocol::UNIV2,
                Protocol::UNIV3,
                Protocol::PANCAKEV2,
                Protocol::PANCAKEV3,
                Protocol::UNIV4,
            ],
            fences,
            edges: candidates
                .iter()
                .map(|&neighbor| {
                    let (token0, token1) = if token < neighbor {
                        (token, neighbor)
                    } else {
                        (neighbor, token)
                    };
                    AdjacencyEdge {
                        token0,
                        token1,
                        protocols: vec![Protocol::UNIV2, Protocol::UNIV3],
                    }
                })
                .collect(),
        };
        let selected = select_connectors(
            &SELECTION_PROFILE,
            token_in,
            token_out,
            &with_v4(token_in),
            &with_v4(token_out),
        )
        .unwrap();

        // 10 static pairs + 4 wrapped-native aliases leaves 10 of BSC's 24, at
        // two pairs per connector — five affordable, and the cap is no longer
        // what decides that.
        let base = 14usize;
        let affordable = crate::chain::BSC_PROFILE
            .dynamic_connector_cap
            .min((crate::chain::BSC_PROFILE.topology_pair_budget - base) / 2);
        assert_eq!(selected.connectors.len(), affordable);
        assert_eq!(selected.eligible_count, 8);
        // The screening shortlist reaches past the routable budget, which is
        // the whole point of carrying one.
        assert_eq!(
            selected.screened.len(),
            crate::chain::BSC_PROFILE.screen_connector_cap
        );
        assert!(selected.screened.len() > selected.connectors.len());
        assert!(selected.screened.starts_with(&selected.connectors));
        assert!(selected.shortlist_truncated);
    }

    #[test]
    fn connector_selector_is_deterministic_symmetric_and_score_complete() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x99);
        let c1 = Address::repeat_byte(0x21);
        let c2 = Address::repeat_byte(0x22);
        let c3 = Address::repeat_byte(0x23);
        let c4 = Address::repeat_byte(0x24);
        let one_sided = Address::repeat_byte(0x25);
        let fences = CatalogFences {
            v23: V23Fence {
                seq: 123,
                generation: 4,
            },
            v4: None,
        };
        let left_rows: Vec<(Address, &[Protocol])> = vec![
            (c4, &[Protocol::UNIV2, Protocol::UNIV3]),
            (c2, &[Protocol::UNIV2, Protocol::UNIV3, Protocol::PANCAKEV2]),
            (
                c3,
                &[
                    Protocol::UNIV2,
                    Protocol::UNIV3,
                    Protocol::PANCAKEV2,
                    Protocol::PANCAKEV3,
                ],
            ),
            (c1, &[Protocol::UNIV2, Protocol::UNIV3]),
            (Address::ZERO, &[Protocol::UNIV2]),
            (crate::chain::WBNB, &[Protocol::UNIV2]),
            (one_sided, &[Protocol::UNIV2]),
        ];
        let right_rows: Vec<(Address, &[Protocol])> = vec![
            (c1, &[Protocol::UNIV2, Protocol::UNIV3]),
            (c3, &[Protocol::UNIV2]),
            (c2, &[Protocol::UNIV2, Protocol::PANCAKEV2]),
            (c4, &[Protocol::UNIV2]),
            (Address::ZERO, &[Protocol::UNIV2]),
            (crate::chain::WBNB, &[Protocol::UNIV2]),
        ];
        let left = adjacency_fixture(token_in, &left_rows, fences);
        let right = adjacency_fixture(token_out, &right_rows, fences);
        let selected =
            select_connectors(&SELECTION_PROFILE, token_in, token_out, &left, &right).unwrap();
        // Four eligible, and BSC's cap now admits four.
        assert_eq!(selected.connectors, vec![c2, c1, c3, c4]);
        assert_eq!(selected.eligible_count, 4);

        let reversed =
            select_connectors(&SELECTION_PROFILE, token_out, token_in, &right, &left).unwrap();
        assert_eq!(reversed, selected);

        let mut shuffled_left = left.clone();
        shuffled_left.edges.reverse();
        let mut shuffled_right = right.clone();
        shuffled_right.edges.reverse();
        assert_eq!(
            select_connectors(
                &SELECTION_PROFILE,
                token_in,
                token_out,
                &shuffled_left,
                &shuffled_right,
            )
            .unwrap(),
            selected
        );
    }

    /// Tokens a chain refuses, ranked above the ones it permits.
    ///
    /// Both selectors take `connectors` and `screened` as prefixes of the
    /// ranking, so a token filtered after those prefixes were cut would carry
    /// a slot out with it and the permitted candidate one rank below could
    /// never move up.
    const REFUSED_ABOVE_PERMITTED: [Address; 2] =
        [Address::repeat_byte(0x01), Address::repeat_byte(0x02)];

    #[test]
    fn the_walk_gives_a_refused_candidates_slot_to_the_next_permitted_one() {
        const PERMITTED: [Address; 4] = [
            Address::repeat_byte(0x21),
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x23),
            Address::repeat_byte(0x24),
        ];
        static NARROW: std::sync::LazyLock<ChainProfile> =
            std::sync::LazyLock::new(|| ChainProfile {
                dynamic_connector_allowlist: &PERMITTED,
                ..*crate::chain::BSC_PROFILE
            });
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x99);
        let fences = CatalogFences {
            v23: V23Fence {
                seq: 123,
                generation: 4,
            },
            v4: None,
        };
        // One protocol set for every candidate, so the popcount triple ties
        // and the rank falls to ascending address — which puts both refused
        // tokens above all four permitted ones.
        let rows: Vec<(Address, &[Protocol])> = REFUSED_ABOVE_PERMITTED
            .iter()
            .chain(PERMITTED.iter())
            .map(|&token| (token, &[Protocol::UNIV2, Protocol::UNIV3][..]))
            .collect();
        let left = adjacency_fixture(token_in, &rows, fences);
        let right = adjacency_fixture(token_out, &rows, fences);

        let selected = select_connectors(&NARROW, token_in, token_out, &left, &right).unwrap();

        assert_eq!(selected.connectors, PERMITTED);
        assert_eq!(selected.screened, PERMITTED);
        // The ranking's own count survives the refusal, so a thin pair and a
        // filtered one stay distinguishable.
        assert_eq!(selected.eligible_count, rows.len());
    }

    #[test]
    fn bsc_v4_connector_shortlist_reserves_native_alias_pairs() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x99);
        let c1 = Address::repeat_byte(0x21);
        let c2 = Address::repeat_byte(0x22);
        let fences = CatalogFences {
            v23: V23Fence {
                seq: 123,
                generation: 4,
            },
            v4: Some(V4Fence {
                block: 456,
                generation: B256::repeat_byte(0x44),
            }),
        };
        let rows = [(c1, &[Protocol::UNIV4][..]), (c2, &[Protocol::UNIV4][..])];
        let mut left = adjacency_fixture(token_in, &rows, fences);
        let mut right = adjacency_fixture(token_out, &rows, fences);
        let protocols = crate::chain::BSC_INDEXED_DISCOVERY.quote_protocols();
        left.protocols = protocols.clone();
        right.protocols = protocols;

        let selected =
            select_connectors(&SELECTION_PROFILE, token_in, token_out, &left, &right).unwrap();

        // The static BSC graph needs 10 wrapped pairs plus four V4 native
        // aliases, so 14 of BSC's 24 are spent before a dynamic route is
        // considered. The alias reservation is the point: without it the base
        // would be 10 and two more connectors would be affordable.
        assert_eq!(selected.connectors, vec![c1, c2]);
        assert_eq!(selected.eligible_count, 2);
    }

    #[test]
    #[ignore = "manual release-mode selector performance gate"]
    fn connector_selector_profile_4096_edges() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x99);
        let protocols = quote_protocols();
        let fences = CatalogFences {
            v23: V23Fence {
                seq: 123,
                generation: 4,
            },
            v4: None,
        };
        let neighbor_at = |index: usize| {
            let mut bytes = [0u8; 20];
            bytes[0] = 0x70;
            bytes[16..].copy_from_slice(&(index as u32).to_be_bytes());
            Address::from(bytes)
        };
        let side = |token: Address| Adjacency {
            token,
            protocols: protocols.clone(),
            fences,
            edges: (1..=MAX_ADJACENCY_EDGES)
                .map(|index| {
                    let neighbor = neighbor_at(index);
                    let (token0, token1) = if token < neighbor {
                        (token, neighbor)
                    } else {
                        (neighbor, token)
                    };
                    AdjacencyEdge {
                        token0,
                        token1,
                        protocols: protocols.clone(),
                    }
                })
                .collect(),
        };
        let left = side(token_in);
        let right = side(token_out);
        // The shape a real chain presents: an allowlist of a few dozen tokens
        // against a full adjacency page, where every candidate pays the permit
        // scan and the few that pass go on to pay the sorted insert. BSC's own
        // list is 27. Permitting none would leave the insert unmeasured;
        // permitting all 4096 would measure a scan no chain performs.
        let permitted: &'static [Address] = Box::leak(
            (1..=32)
                .map(neighbor_at)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        let profile = ChainProfile {
            dynamic_connector_allowlist: permitted,
            ..*crate::chain::BSC_PROFILE
        };

        for _ in 0..100 {
            std::hint::black_box(
                select_connectors(&profile, token_in, token_out, &left, &right).unwrap(),
            );
        }
        let mut samples = Vec::with_capacity(1_000);
        for _ in 0..1_000 {
            let started = std::time::Instant::now();
            let selection =
                select_connectors(&profile, token_in, token_out, &left, &right).unwrap();
            assert_eq!(selection.eligible_count, MAX_ADJACENCY_EDGES);
            samples.push(started.elapsed().as_nanos());
        }
        samples.sort_unstable();
        let p95_ns = samples[samples.len() * 95 / 100];
        eprintln!("connector selector 4096-edge p95={p95_ns}ns");
        assert!(
            p95_ns < 200_000,
            "connector selector p95 exceeds the 200us release gate"
        );
    }

    #[tokio::test]
    async fn accepts_all_five_venues_and_native_v4_and_filters_after_validation() {
        let (url, queries, server) = spawn_json(valid_response()).await;
        let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        let topology = client
            .topology(&[wrapped_pair(), native_pair()], &ALL_SYNTHETIC)
            .await
            .unwrap();

        assert_eq!(topology.pairs, vec![native_pair(), wrapped_pair()]);
        assert_eq!(
            topology.fences.v23,
            V23Fence {
                seq: 123,
                generation: 4
            }
        );
        assert_eq!(topology.fences.v4.unwrap().block, 120_000_000);
        assert_eq!(topology.pools.len(), 5);
        let PoolTopology::Univ4(v4) = &topology.pools[0] else {
            panic!("native row must be v4")
        };
        assert_eq!(v4.currency0, Address::ZERO);
        assert_eq!(v4.key_fee_ppm, None);

        let query = queries.lock().unwrap().first().cloned().unwrap();
        let query_url = Url::parse(&format!("http://mock.invalid/?{query}")).unwrap();
        let decoded: Vec<_> = query_url
            .query_pairs()
            .filter(|(name, _)| name == "pair")
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(
            decoded,
            vec![format!("{ZERO},{USDT}"), format!("{USDT},{WBNB}")]
        );

        let selected_protocols = [Protocol::UNIV2, Protocol::PANCAKEV2];
        let (selected_url, _, selected_server) =
            spawn_json(valid_response_for(&selected_protocols)).await;
        let selected_client = IndexerClient::builder(&selected_url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        let selected = selected_client
            .topology(&[native_pair(), wrapped_pair()], &selected_protocols)
            .await
            .unwrap();
        assert_eq!(selected.pools.len(), 2);
        assert!(
            selected
                .pools
                .iter()
                .all(|pool| matches!(pool.protocol(), Protocol::UNIV2 | Protocol::PANCAKEV2))
        );
        selected_server.abort();
        server.abort();
    }

    #[tokio::test]
    async fn indexed_client_is_profile_driven_for_a_third_evm_chain() {
        let protocols = [Protocol::UNIV2, Protocol::UNIV3];
        let mut response = valid_response_for(&protocols);
        response["chainId"] = json!(SYNTHETIC_PROFILE.chain_id);
        response["chain"]["key"] = json!(SYNTHETIC_PROFILE.key);
        response["chain"]["id"] = json!(SYNTHETIC_PROFILE.chain_id);
        response["factories"]["univ2"] = json!(format!(
            "{:#x}",
            SYNTHETIC_DISCOVERY
                .venue(Protocol::UNIV2)
                .unwrap()
                .identity()
        ));
        response["factories"]["univ3"] = json!(format!(
            "{:#x}",
            SYNTHETIC_DISCOVERY
                .venue(Protocol::UNIV3)
                .unwrap()
                .identity()
        ));
        response["factories"]["pancakev2"] = Value::Null;
        response["factories"]["pancakev3"] = Value::Null;
        response["factories"]["univ4"] = Value::Null;

        let (url, _, server) = spawn_json(response).await;
        let client = IndexerClient::builder(&url, &SYNTHETIC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        let topology = client
            .topology(&[native_pair(), wrapped_pair()], &protocols)
            .await
            .unwrap();

        assert_eq!(topology.protocols, protocols);
        assert_eq!(topology.pools.len(), 2);
        assert!(
            topology
                .pools
                .iter()
                .all(|pool| matches!(pool.protocol(), Protocol::UNIV2 | Protocol::UNIV3))
        );
        server.abort();
    }

    #[tokio::test]
    async fn rejects_wrong_schema_chain_factory_and_readiness() {
        let mut cases = Vec::new();
        let mut wrong_schema = valid_response();
        wrong_schema["schemaVersion"] = json!(3);
        cases.push(wrong_schema);
        let mut wrong_chain = valid_response();
        wrong_chain["chainId"] = json!(1);
        cases.push(wrong_chain);
        let mut wrong_factory = valid_response();
        wrong_factory["factories"]["pancakev3"] =
            json!("0x0000000000000000000000000000000000000001");
        cases.push(wrong_factory);
        let mut not_ready = valid_response();
        not_ready["catalogs"]["pancakev2"]["ready"] = json!(false);
        cases.push(not_ready);
        let mut unsupported = valid_response();
        unsupported["catalogs"]["univ4"]["supported"] = json!(false);
        cases.push(unsupported);
        let mut degraded = valid_response();
        degraded["catalogs"]["v23"]["degraded"] = json!(true);
        cases.push(degraded);
        for (field, invalid_value) in [
            ("backfilled", json!(false)),
            ("snapshotComplete", json!(false)),
            ("snapshotBlockHash", json!("0x1234")),
            ("snapshotPoolCount", json!(101)),
            ("snapshotSource", json!("rpc")),
            ("snapshotDeployment", json!("bad")),
            ("snapshotSubgraphId", json!("bad")),
        ] {
            let mut contradictory_v4 = valid_response();
            contradictory_v4["catalogs"]["univ4"][field] = invalid_value;
            cases.push(contradictory_v4);
        }
        let mut cursor_behind = valid_response();
        cursor_behind["catalogs"]["univ4"]["targetBlock"] = json!(120_000_001u64);
        cases.push(cursor_behind);
        let mut snapshot_ahead = valid_response();
        snapshot_ahead["catalogs"]["univ4"]["snapshotBlock"] = json!(120_000_001u64);
        cases.push(snapshot_ahead);
        let mut partial_featured = valid_response();
        partial_featured["catalogs"]["univ4"]["featuredBlock"] = json!(120_000_100u64);
        cases.push(partial_featured);
        let mut oversized_featured = valid_response();
        oversized_featured["catalogs"]["univ4"]["featuredBlock"] = json!(120_000_100u64);
        oversized_featured["catalogs"]["univ4"]["featuredCount"] = json!(101u64);
        oversized_featured["catalogs"]["univ4"]["featuredAsof"] = json!(1_800_000_000u64);
        cases.push(oversized_featured);

        for value in cases {
            let error = fetch_value(value).await.unwrap_err();
            assert_eq!(error.kind(), IndexerErrorKind::InvalidResponse);
        }
    }

    #[tokio::test]
    async fn requested_scope_isolated_from_unquoted_v4_readiness_and_rows() {
        let protocols = [Protocol::UNIV2, Protocol::PANCAKEV2];
        let mut scoped = valid_response_for(&protocols);
        scoped["catalogs"]["univ4"]["ready"] = json!(false);
        scoped["catalogs"]["univ4"]["degraded"] = json!(true);
        scoped["catalogs"]["univ4"]["lastError"] = json!("unavailable");
        scoped["catalogs"]["univ4"]["snapshotGeneration"] = Value::Null;
        scoped["v4Fence"] = json!({ "block": 0, "generation": null });

        let (url, _, server) = spawn_json(scoped.clone()).await;
        let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        let topology = client
            .topology(&[wrapped_pair(), native_pair()], &protocols)
            .await
            .unwrap();
        assert_eq!(topology.protocols, protocols);
        assert!(topology.fences.v4.is_none());
        server.abort();

        let mut opaque = scoped.clone();
        opaque["catalogs"]["univ4"] = json!({ "corrupt": ["unrequested"] });
        opaque["v4Fence"] = json!({ "block": "not-a-number", "generation": 7 });
        let (url, _, server) = spawn_json(opaque).await;
        let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        let topology = client
            .topology(&[wrapped_pair(), native_pair()], &protocols)
            .await
            .unwrap();
        assert!(topology.fences.v4.is_none());
        server.abort();

        let mut smuggled = scoped;
        let v4 = valid_response()["pools"][0].clone();
        smuggled["pools"].as_array_mut().unwrap().insert(0, v4);
        smuggled["count"] = json!(3);
        let (url, _, server) = spawn_json(smuggled).await;
        let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            client
                .topology(&[wrapped_pair(), native_pair()], &protocols)
                .await
                .unwrap_err()
                .kind(),
            IndexerErrorKind::InvalidResponse
        );
        server.abort();
    }

    #[tokio::test]
    async fn rejects_stale_or_implausibly_future_v23_success_time() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut stale = valid_response();
        stale["catalogs"]["v23"]["lastSuccessAt"] = json!(now - 2 * 60 * 60 - 1);
        assert_eq!(
            fetch_value(stale.clone()).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );

        // Explicit replay-only opt-out disables age, while retaining every
        // identity/readiness validation.
        let (url, _, server) = spawn_json(stale).await;
        let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
            .unwrap()
            .max_v23_age(Duration::ZERO)
            .build()
            .unwrap();
        client
            .topology(&[wrapped_pair(), native_pair()], &ALL_SYNTHETIC)
            .await
            .unwrap();
        server.abort();

        let mut future = valid_response();
        future["catalogs"]["v23"]["lastSuccessAt"] =
            // Leave enough margin for the async loopback request to cross a
            // wall-clock second while the full suite is under load.
            json!(now + MAX_FUTURE_CLOCK_SKEW.as_secs() + 60);
        assert_eq!(
            fetch_value(future).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );
    }

    #[tokio::test]
    async fn rejects_pair_echo_extra_rows_bad_count_and_bad_fences() {
        let mut echo = valid_response();
        echo["pairs"].as_array_mut().unwrap().remove(0);
        assert_eq!(
            fetch_value(echo).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );

        let mut extra = valid_response();
        let mut row = extra["pools"][1].clone();
        row["address"] = json!("0x0000000000000000000000000000000000000005");
        row["token0"] = json!("0x0000000000000000000000000000000000000010");
        row["token1"] = json!("0x0000000000000000000000000000000000000020");
        extra["pools"].as_array_mut().unwrap().push(row);
        extra["count"] = json!(6);
        assert_eq!(
            fetch_value(extra).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );

        let mut count = valid_response();
        count["count"] = json!(4);
        assert_eq!(
            fetch_value(count).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );

        let mut v23 = valid_response();
        v23["v23Fence"]["seq"] = json!("0123");
        assert_eq!(
            fetch_value(v23).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );

        let mut v4 = valid_response();
        v4["v4Fence"]["generation"] = Value::Null;
        assert_eq!(
            fetch_value(v4).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_and_conflicting_identities_and_nondeterminism() {
        let mut duplicate = valid_response();
        let row = duplicate["pools"][1].clone();
        duplicate["pools"].as_array_mut().unwrap().insert(2, row);
        duplicate["count"] = json!(6);
        assert_eq!(
            fetch_value(duplicate).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );

        let mut conflict = valid_response();
        conflict["pools"][2]["address"] = json!("0x0000000000000000000000000000000000000001");
        assert_eq!(
            fetch_value(conflict).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );

        let mut unordered = valid_response();
        unordered["pools"].as_array_mut().unwrap().swap(1, 2);
        assert_eq!(
            fetch_value(unordered).await.unwrap_err().kind(),
            IndexerErrorKind::InvalidResponse
        );
    }

    #[tokio::test]
    async fn enforces_declared_and_streamed_two_mibibyte_caps() {
        for reply in [Reply::DeclaredOversize, Reply::StreamedOversize] {
            let label = format!("{reply:?}");
            let (url, _, server) = spawn(reply).await;
            let client = IndexerClient::builder(&url, &crate::chain::BSC_PROFILE)
                .unwrap()
                .build()
                .unwrap();
            let error = client
                .topology(&[wrapped_pair()], &ALL_SYNTHETIC)
                .await
                .unwrap_err();
            assert_eq!(
                error.kind(),
                IndexerErrorKind::BodyTooLarge,
                "{label}: {error}"
            );
            server.abort();
        }
    }

    #[test]
    fn a_profile_whose_factories_name_its_pools_takes_no_indexer() {
        let error = IndexerClient::builder("http://127.0.0.1:1", &crate::chain::FIXTURE_PROFILE)
            .unwrap_err();
        assert_eq!(error.kind(), IndexerErrorKind::InvalidConfiguration);
        assert!(error.to_string().contains("by factory"), "{error}");
    }

    #[tokio::test]
    async fn redirect_policy_is_none() {
        let (target, _, target_server) = spawn_json(valid_response()).await;
        let location = format!("{target}{ENDPOINT_PATH}");
        let (source, _, source_server) = spawn(Reply::Redirect(location)).await;
        let client = IndexerClient::builder(&source, &crate::chain::BSC_PROFILE)
            .unwrap()
            .build()
            .unwrap();
        let error = client
            .topology(&[wrapped_pair(), native_pair()], &ALL_SYNTHETIC)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), IndexerErrorKind::HttpStatus);
        source_server.abort();
        target_server.abort();
    }

    #[tokio::test]
    async fn transport_errors_and_debug_output_never_reveal_endpoint_secrets() {
        let secret = "never-print-this-indexer-token";
        let client = IndexerClient::builder(
            &format!("http://127.0.0.1:1/{secret}?apiKey={secret}"),
            &crate::chain::BSC_PROFILE,
        )
        .unwrap()
        .timeout(Duration::from_millis(100))
        .connect_timeout(Duration::from_millis(100))
        .build()
        .unwrap();
        assert!(!format!("{client:?}").contains(secret));
        let error = client
            .topology(&[wrapped_pair()], &ALL_SYNTHETIC)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), IndexerErrorKind::Transport);
        assert!(!format!("{error}").contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn request_bounds_and_canonical_pairs_fail_before_io() {
        assert_eq!(
            TokenPair::new(Address::repeat_byte(2), Address::repeat_byte(1))
                .unwrap_err()
                .kind(),
            IndexerErrorKind::InvalidRequest
        );
        let pairs = vec![wrapped_pair(); MAX_PAIRS + 1];
        assert_eq!(
            normalized_pairs(&pairs).unwrap_err().kind(),
            IndexerErrorKind::InvalidRequest
        );
        assert_eq!(
            normalized_protocols(&[], &crate::chain::BSC_INDEXED_DISCOVERY)
                .unwrap_err()
                .kind(),
            IndexerErrorKind::InvalidRequest
        );
    }

    // ---- ranked connectors ----

    fn ranked_protocols() -> Vec<Protocol> {
        quote_protocols()
    }

    /// A well-formed connectors response. `candidates` are (token, bottleneck)
    /// in the order the indexer would return them.
    fn valid_connectors_response(
        a: Address,
        b: Address,
        candidates: &[(Address, f64)],
        sides: (usize, usize),
    ) -> Value {
        let protocols = ranked_protocols();
        let mut response = valid_response_for(&protocols);
        let object = response.as_object_mut().unwrap();
        object.remove("pairs");
        object.remove("pools");
        object.remove("v23Fence");
        object.remove("v4Fence");
        // The connectors contract versions independently of topology/adjacency.
        object.insert(
            "schemaVersion".to_string(),
            json!(CONNECTORS_SCHEMA_VERSION),
        );
        object.insert("a".to_string(), json!(format!("{a:#x}")));
        object.insert("b".to_string(), json!(format!("{b:#x}")));
        object.insert(
            "ranking".to_string(),
            json!({
                "builtAt": 1_754_000_000u64,
                "ageSeconds": 42u64,
                "perTokenLimit": 256usize,
                "edges": 918_000u64,
                "tokens": 12_345u64,
                "v23Fence": { "seq": "1", "generation": "0" },
            }),
        );
        let side = |ranked: usize| {
            json!({
                "ranked": ranked,
                "truncated": ranked == 256,
                "floorUsd": 1_234.5,
            })
        };
        object.insert(
            "sides".to_string(),
            json!({ "a": side(sides.0), "b": side(sides.1) }),
        );
        object.insert("count".to_string(), json!(candidates.len()));
        object.insert(
            "candidates".to_string(),
            Value::Array(
                candidates
                    .iter()
                    .map(|(token, bottleneck)| {
                        json!({
                            "token": format!("{token:#x}"),
                            "bottleneckUsd": bottleneck,
                            "aTvlUsd": bottleneck * 2.0,
                            "bTvlUsd": bottleneck,
                            "aProtocols": ["univ3"],
                            "bProtocols": ["pancakev2"],
                            "approx": false,
                        })
                    })
                    .collect(),
            ),
        );
        response
    }

    #[derive(Clone)]
    struct RankedMockState {
        connectors: Option<Arc<Vec<u8>>>,
        adjacency_hits: Arc<std::sync::atomic::AtomicUsize>,
        connector_queries: Arc<Mutex<Vec<String>>>,
    }

    async fn ranked_connectors_handler(
        State(state): State<RankedMockState>,
        uri: axum::http::Uri,
    ) -> Response<Body> {
        state
            .connector_queries
            .lock()
            .unwrap()
            .push(uri.query().unwrap_or_default().to_string());
        match &state.connectors {
            // No route at all is what an indexer without the feature answers.
            None => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap(),
            Some(body) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.as_ref().clone()))
                .unwrap(),
        }
    }

    async fn ranked_adjacency_handler(
        State(state): State<RankedMockState>,
        uri: axum::http::Uri,
    ) -> Response<Body> {
        state
            .adjacency_hits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let token = uri
            .query()
            .and_then(|query| {
                query
                    .split('&')
                    .find_map(|part| part.strip_prefix("token="))
            })
            .and_then(|token| token.parse::<Address>().ok())
            .expect("test adjacency request has a token");
        // One shared neighbour, so the walk produces a distinguishable answer.
        let shared = Address::repeat_byte(0x77);
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&valid_adjacency_response(
                    token,
                    &[(shared, vec![Protocol::UNIV2])],
                ))
                .unwrap(),
            ))
            .unwrap()
    }

    #[allow(clippy::type_complexity)]
    async fn spawn_ranked(
        connectors: Option<Value>,
    ) -> (
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = RankedMockState {
            connectors: connectors.map(|value| Arc::new(serde_json::to_vec(&value).unwrap())),
            adjacency_hits: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            connector_queries: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route(CONNECTORS_ENDPOINT_PATH, get(ranked_connectors_handler))
            .route(ADJACENCY_ENDPOINT_PATH, get(ranked_adjacency_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            format!("http://{address}"),
            state.adjacency_hits,
            state.connector_queries,
            server,
        )
    }

    fn ranked_client(url: &str, ranked: bool) -> IndexerClient {
        IndexerClient::builder(url, &SELECTION_PROFILE)
            .unwrap()
            .ranked_connectors(ranked)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn ranking_replaces_both_adjacency_walks_with_one_request() {
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x99));
        let (best, second) = (Address::repeat_byte(0x33), Address::repeat_byte(0x22));
        // Ordered by depth, and deliberately NOT by address: a selector that
        // re-sorted the list would put 0x22 first.
        let response = valid_connectors_response(
            a,
            b,
            &[(best, 13_500_000.0), (second, 900_000.0)],
            (256, 12),
        );
        let (url, adjacency_hits, queries, server) = spawn_ranked(Some(response)).await;
        let selection = ranked_client(&url, true)
            .connector_selection(a, b, &quote_protocols())
            .await
            .unwrap();
        server.abort();

        assert_eq!(selection.selector, ConnectorSelector::RankedProjection);
        assert_eq!(selection.screened, vec![best, second]);
        assert_eq!(selection.eligible_count, 2);
        assert_eq!(
            adjacency_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the ranked path must not also walk adjacency"
        );
        let query = queries.lock().unwrap()[0].clone();
        assert!(query.contains(&format!("a={a:#x}")) && query.contains(&format!("b={b:#x}")));
        // V4 cannot be ranked from pool state, so it is dropped from the ask
        // rather than sent for the indexer to decline.
        assert!(!query.contains("univ4"), "{query}");
        assert!(query.contains("protocol=univ2") && query.contains("protocol=pancakev3"));
    }

    #[tokio::test]
    async fn an_indexer_without_a_ranking_falls_back_to_the_walk() {
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x99));
        let (url, adjacency_hits, _, server) = spawn_ranked(None).await;
        let selection = ranked_client(&url, true)
            .connector_selection(a, b, &quote_protocols())
            .await
            .unwrap();
        server.abort();

        assert_eq!(selection.selector, ConnectorSelector::AdjacencyWalk);
        assert_eq!(selection.screened, vec![Address::repeat_byte(0x77)]);
        assert_eq!(adjacency_hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_malformed_ranking_fails_instead_of_quietly_walking() {
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x99));
        let mut response = valid_connectors_response(a, b, &[], (4, 4));
        response["chainId"] = json!(1);
        let (url, adjacency_hits, _, server) = spawn_ranked(Some(response)).await;
        let error = ranked_client(&url, true)
            .connector_selection(a, b, &quote_protocols())
            .await
            .unwrap_err();
        server.abort();

        assert_eq!(error.kind(), IndexerErrorKind::InvalidResponse);
        assert_eq!(
            adjacency_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a faulty indexer must not be masked by a slower path that happens to work"
        );
    }

    #[tokio::test]
    async fn the_flag_alone_decides_which_selector_runs() {
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x99));
        let response =
            valid_connectors_response(a, b, &[(Address::repeat_byte(0x33), 5.0)], (4, 4));
        let (url, adjacency_hits, queries, server) = spawn_ranked(Some(response)).await;
        let selection = ranked_client(&url, false)
            .connector_selection(a, b, &quote_protocols())
            .await
            .unwrap();
        server.abort();

        assert_eq!(selection.selector, ConnectorSelector::AdjacencyWalk);
        assert_eq!(adjacency_hits.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(
            queries.lock().unwrap().is_empty(),
            "a ranking must not be fetched when it was not asked for"
        );
    }

    #[tokio::test]
    async fn a_misordered_ranking_is_refused() {
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x99));
        // The order is the whole product of the endpoint. Accepting this would
        // substitute the indexer's row order for the ranking.
        let response = valid_connectors_response(
            a,
            b,
            &[
                (Address::repeat_byte(0x33), 100.0),
                (Address::repeat_byte(0x44), 900.0),
            ],
            (4, 4),
        );
        let (url, _, _, server) = spawn_ranked(Some(response)).await;
        let error = ranked_client(&url, true)
            .connector_candidates(a, b, &quote_protocols())
            .await
            .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("not ordered"), "{error}");
    }

    #[tokio::test]
    async fn a_ranking_that_contradicts_its_own_reach_is_refused() {
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x99));
        let mut response = valid_connectors_response(a, b, &[], (4, 4));
        // Claims a full budget without having filled it.
        response["sides"]["a"]["truncated"] = json!(true);
        let (url, _, _, server) = spawn_ranked(Some(response)).await;
        let error = ranked_client(&url, true)
            .connector_candidates(a, b, &quote_protocols())
            .await
            .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("truncation flag"), "{error}");
    }

    #[tokio::test]
    async fn an_endpoint_or_static_connector_is_never_admitted_from_a_ranking() {
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x99));
        let real = Address::repeat_byte(0x33);
        let static_connector = crate::chain::BSC_PROFILE.connectors[0];
        let response = valid_connectors_response(
            a,
            b,
            &[
                (b, 9_000_000.0),
                (static_connector, 8_000_000.0),
                (Address::ZERO, 7_000_000.0),
                (real, 100.0),
            ],
            (4, 4),
        );
        let (url, _, _, server) = spawn_ranked(Some(response)).await;
        let selection = ranked_client(&url, true)
            .connector_selection(a, b, &quote_protocols())
            .await
            .unwrap();
        server.abort();

        assert_eq!(selection.screened, vec![real]);
        assert_eq!(selection.eligible_count, 1);
    }

    /// The same property on the path BSC actually runs.
    ///
    /// Measured against the live BSC ranking on 2026-08-06, filtering after
    /// the prefixes were cut left WBNB->USDC routing three connectors where
    /// four were available and affordable, and cost four screening slots
    /// across ten pairs.
    #[tokio::test]
    async fn a_ranking_gives_a_refused_candidates_slot_to_the_next_permitted_one() {
        const PERMITTED: [Address; 6] = [
            Address::repeat_byte(0x21),
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x23),
            Address::repeat_byte(0x24),
            Address::repeat_byte(0x25),
            Address::repeat_byte(0x26),
        ];
        static NARROW: std::sync::LazyLock<ChainProfile> =
            std::sync::LazyLock::new(|| ChainProfile {
                dynamic_connector_allowlist: &PERMITTED,
                ..*crate::chain::BSC_PROFILE
            });
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x99));
        // Refused at the head of the ranking and again inside the routable
        // prefix — the two places a downstream filter loses a slot.
        let ranking = [
            (REFUSED_ABOVE_PERMITTED[0], 9_000_000.0),
            (PERMITTED[0], 8_000_000.0),
            (PERMITTED[1], 7_000_000.0),
            (REFUSED_ABOVE_PERMITTED[1], 6_000_000.0),
            (PERMITTED[2], 5_000_000.0),
            (PERMITTED[3], 4_000_000.0),
            (PERMITTED[4], 3_000_000.0),
            (PERMITTED[5], 2_000_000.0),
        ];
        let response = valid_connectors_response(a, b, &ranking, (256, 12));
        let (url, _, _, server) = spawn_ranked(Some(response)).await;
        let selection = IndexerClient::builder(&url, &NARROW)
            .unwrap()
            .ranked_connectors(true)
            .build()
            .unwrap()
            .connector_selection(a, b, &quote_protocols())
            .await
            .unwrap();
        server.abort();

        // The cap no longer binds, so the routable prefix is whatever the pair
        // budget affords -- and the property under test is sharper for it:
        // every slot goes to a permitted candidate, in the ranking's own order,
        // and neither refused entry consumes one.
        // Neither endpoint is a static connector, so the skeleton is 10 pairs
        // plus 4 wrapped-native aliases — the same base the walk selector's own
        // test spells out — leaving five of BSC's 24 at two pairs per connector.
        let affordable = crate::chain::BSC_PROFILE
            .dynamic_connector_cap
            .min((crate::chain::BSC_PROFILE.topology_pair_budget - 14) / 2);
        let routable = PERMITTED.len().min(affordable);
        assert_eq!(selection.connectors.as_slice(), &PERMITTED[..routable]);
        assert_eq!(selection.screened, PERMITTED);
        assert_eq!(selection.eligible_count, ranking.len());
    }

    #[tokio::test]
    async fn a_truncated_ranking_reports_its_shortlist_as_truncated() {
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x99));
        // One candidate, admitted in full -- so only the ranking's own reach
        // can explain a truncated shortlist.
        let response =
            valid_connectors_response(a, b, &[(Address::repeat_byte(0x33), 5.0)], (256, 4));
        let (url, _, _, server) = spawn_ranked(Some(response)).await;
        let selection = ranked_client(&url, true)
            .connector_selection(a, b, &quote_protocols())
            .await
            .unwrap();
        server.abort();

        assert_eq!(selection.eligible_count, selection.connectors.len());
        assert!(selection.shortlist_truncated);
    }
}
