//! Chain manifests: `manifest/<key>.json`, one per chain, embedded at build
//! time and read once. A chain is data: its identity, tokens, connectors,
//! routing budgets, venue table, Settler trust anchors and Native identity.
//! Pool math families and discovery kinds are code; a manifest only selects
//! among them.
//!
//! Every type here refuses a field it does not name, addresses parse only in
//! their EIP-55 form and hashes only as 32 lowercase hex bytes, so a typo
//! fails the build's tests instead of loading. What the types cannot say
//! (unique venue ids, a fork for every executable V3 venue, ...) is checked
//! when the profile is built and again by `server::validate_profile` at boot.

use crate::catalog::{
    CandidateSource, CatalogProtocol, CatalogVenue, IndexedEvmDiscovery, ReadinessPolicy,
};
use crate::chain::{
    ChainProfile, DiscoveryProfile, IndexedV3Execution, NativeRfqProfile, SettlerEncoding,
    SettlerProfile, SettlerRuntimePolicy, SolverCapabilities,
};
use alloy_primitives::{Address, B256};
use anyhow::{Context, ensure};
use serde::{Deserialize, Deserializer};

/// Every chain this build serves, by key.
pub const SOURCES: &[(&str, &str)] = &[
    ("bsc", include_str!("../manifest/bsc.json")),
    ("robinhood", include_str!("../manifest/robinhood.json")),
    ("ethereum", include_str!("../manifest/ethereum.json")),
];

/// The compiled-in manifest for `key`, built into a profile.
pub fn embedded(key: &str) -> anyhow::Result<ChainProfile> {
    let (_, json) = SOURCES
        .iter()
        .find(|(source, _)| *source == key)
        .with_context(|| format!("no manifest for chain {key:?}"))?;
    let profile = parse(json).with_context(|| format!("the {key} manifest"))?;
    ensure!(
        profile.key == key,
        "the {key} manifest carries key {}",
        profile.key
    );
    Ok(profile)
}

/// A manifest's text, checked and built. Its allocations live for the
/// process: a profile is built once per chain.
pub fn parse(json: &str) -> anyhow::Result<ChainProfile> {
    let manifest: Manifest = serde_json::from_str(json).map_err(|error| {
        anyhow::anyhow!(
            "does not match the manifest schema at line {}, column {}: {error}",
            error.line(),
            error.column()
        )
    })?;
    manifest.build()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    key: String,
    name: String,
    chain_id: u64,
    public_rpc: String,
    #[serde(deserialize_with = "strict::address")]
    wrapped_native: Address,
    stable: Stable,
    #[serde(deserialize_with = "strict::addresses")]
    connectors: Vec<Address>,
    routing: Routing,
    discovery: Discovery,
    #[serde(default)]
    settler: Option<Settler>,
    #[serde(default)]
    native_rfq: Option<NativeRfq>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stable {
    #[serde(deserialize_with = "strict::address")]
    address: Address,
    decimals: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Routing {
    topology_pair_budget: usize,
    dynamic_connector_cap: usize,
    screen_connector_cap: usize,
    #[serde(deserialize_with = "strict::addresses")]
    dynamic_connector_allowlist: Vec<Address>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum Discovery {
    /// Robinhood's own discovery (code in `state`), over its compiled venues.
    Robinhood,
    /// A schema-versioned topology indexer names candidates.
    #[serde(rename_all = "camelCase")]
    Indexer {
        schema_version: u32,
        readiness: Readiness,
        venues: Vec<Venue>,
    },
    /// The venues' own factories name candidates.
    Factories {
        venues: Vec<Venue>,
    },
    Disabled,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Readiness {
    WholeContract,
    ConfiguredVenues,
    RequestedVenues,
}

#[derive(Deserialize)]
#[serde(tag = "family", rename_all = "lowercase", deny_unknown_fields)]
enum Venue {
    #[serde(rename_all = "camelCase")]
    V2 {
        id: String,
        #[serde(deserialize_with = "strict::address")]
        factory: Address,
        fee_ppm: u32,
        quote: bool,
    },
    #[serde(rename_all = "camelCase")]
    V3 {
        id: String,
        #[serde(deserialize_with = "strict::address")]
        factory: Address,
        verify_pool_spacing: bool,
        fee_tiers: Vec<u32>,
        quote: bool,
    },
    #[serde(rename_all = "camelCase")]
    V4 {
        id: String,
        #[serde(deserialize_with = "strict::address")]
        pool_manager: Address,
        pools_slot: u64,
        quote: bool,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Settler {
    #[serde(deserialize_with = "strict::address")]
    registry: Address,
    registry_token_id: u64,
    #[serde(deserialize_with = "strict::address")]
    allowance_holder: Address,
    #[serde(deserialize_with = "strict::word")]
    allowance_holder_runtime_hash: B256,
    runtime: Runtime,
    encoding: Encoding,
    v3_forks: Vec<V3Fork>,
    #[serde(default, deserialize_with = "strict::address_opt")]
    univ4_pool_manager: Option<Address>,
    /// Present for a build whose `UNISWAPV4` names its V4 fork.
    #[serde(default)]
    univ4_fork_id: Option<u8>,
    #[serde(deserialize_with = "strict::words")]
    ekubo_v3_runtimes: Vec<B256>,
    #[serde(default, deserialize_with = "strict::word_opt")]
    native_authorization_typehash: Option<B256>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum Runtime {
    Exact(#[serde(deserialize_with = "strict::word")] B256),
    #[serde(rename_all = "camelCase")]
    Compatible {
        #[serde(deserialize_with = "strict::word")]
        extended_v3_hash: B256,
    },
    #[serde(rename_all = "camelCase")]
    SignerMasked {
        #[serde(deserialize_with = "strict::word")]
        masked_hash: B256,
        length: usize,
        signer_offsets: Vec<usize>,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Encoding {
    LegacyBpsVipPathWithSellToken,
    PpmVipPathFromPermit,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V3Fork {
    venue: String,
    fork_id: u8,
    #[serde(deserialize_with = "strict::address")]
    deployer: Address,
    #[serde(deserialize_with = "strict::word")]
    init_hash: B256,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeRfq {
    api_chain: String,
    router_version: u8,
    contract_revision: u64,
    #[serde(deserialize_with = "strict::address")]
    router: Address,
    #[serde(deserialize_with = "strict::word")]
    router_runtime_hash: B256,
    #[serde(deserialize_with = "strict::address")]
    pool: Address,
    #[serde(deserialize_with = "strict::word")]
    pool_runtime_hash: B256,
    #[serde(deserialize_with = "strict::address")]
    credit_vault: Address,
    #[serde(deserialize_with = "strict::word")]
    credit_vault_runtime_hash: B256,
    #[serde(deserialize_with = "strict::selector")]
    trade_selector: [u8; 4],
    domain_fields: u8,
    domain_name: String,
    domain_version: String,
    domain_chain_id: u64,
    #[serde(deserialize_with = "strict::addresses")]
    stock_tokens: Vec<Address>,
}

fn leak<T>(items: Vec<T>) -> &'static [T] {
    Box::leak(items.into_boxed_slice())
}

fn leak_str(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

impl Manifest {
    fn build(self) -> anyhow::Result<ChainProfile> {
        ensure!(
            !self.key.is_empty()
                && self
                    .key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "chain key {:?} must be lowercase letters and digits",
            self.key
        );
        ensure!(self.chain_id > 0, "chain id is zero");
        ensure!(
            self.public_rpc.starts_with("https://")
                && self.public_rpc.len() > "https://".len()
                && !self.public_rpc.contains(char::is_whitespace),
            "publicRpc must be an https URL"
        );
        ensure!(
            self.wrapped_native != Address::ZERO && self.stable.address != Address::ZERO,
            "wrappedNative and stable must be tokens"
        );
        ensure!(
            (1..=36).contains(&self.stable.decimals),
            "stable decimals must be 1 to 36"
        );
        unique("connectors", &self.connectors)?;
        unique(
            "dynamicConnectorAllowlist",
            &self.routing.dynamic_connector_allowlist,
        )?;
        let robinhood_discovery = matches!(&self.discovery, Discovery::Robinhood);
        let discovery = match self.discovery {
            Discovery::Robinhood => {
                ensure!(
                    self.chain_id == crate::chain::CHAIN_ID,
                    "robinhood discovery is compiled for chain {} only, not {}",
                    crate::chain::CHAIN_ID,
                    self.chain_id
                );
                DiscoveryProfile::Robinhood
            }
            Discovery::Disabled => DiscoveryProfile::Disabled,
            Discovery::Indexer {
                schema_version,
                readiness,
                venues,
            } => {
                ensure!(
                    schema_version == 2,
                    "indexer schema version {schema_version} is not supported; the wire is schema v2"
                );
                let venues = venues
                    .into_iter()
                    .map(Venue::build)
                    .collect::<anyhow::Result<Vec<_>>>()?;
                for venue in &venues {
                    ensure!(
                        crate::catalog::SCHEMA_V2_VENUES.contains(&venue.protocol()),
                        "{} is not carried by indexer schema v2",
                        venue.protocol()
                    );
                }
                DiscoveryProfile::IndexedEvm(Box::leak(Box::new(IndexedEvmDiscovery {
                    schema_version,
                    readiness: match readiness {
                        Readiness::WholeContract => ReadinessPolicy::WholeContract,
                        Readiness::ConfiguredVenues => ReadinessPolicy::ConfiguredVenues,
                        Readiness::RequestedVenues => ReadinessPolicy::RequestedVenues,
                    },
                    venues: leak(venues),
                    candidates: CandidateSource::Indexer,
                })))
            }
            Discovery::Factories { venues } => {
                DiscoveryProfile::IndexedEvm(Box::leak(Box::new(IndexedEvmDiscovery {
                    // Unread: no indexer names this chain's candidates.
                    schema_version: 2,
                    readiness: ReadinessPolicy::ConfiguredVenues,
                    venues: leak(
                        venues
                            .into_iter()
                            .map(Venue::build)
                            .collect::<anyhow::Result<_>>()?,
                    ),
                    candidates: CandidateSource::Factories,
                })))
            }
        };
        if let DiscoveryProfile::IndexedEvm(table) = discovery {
            table.validate()?;
        }
        let settler = self.settler.map(Settler::build).transpose()?;
        if let Some(settler) = &settler {
            // Only Robinhood's fork gates review that policy; every other
            // chain pins an exact runtime.
            ensure!(
                !matches!(settler.runtime, SettlerRuntimePolicy::Compatible { .. })
                    || robinhood_discovery,
                "runtime.compatible is reviewed only with robinhood discovery"
            );
        }
        let native_rfq = self.native_rfq.map(NativeRfq::build).transpose()?;
        if let Some(native) = native_rfq {
            ensure!(
                native.domain_chain_id == self.chain_id,
                "the Native RFQ domain names another chain"
            );
        }
        Ok(ChainProfile {
            key: leak_str(self.key),
            name: leak_str(self.name),
            chain_id: self.chain_id,
            public_rpc: leak_str(self.public_rpc),
            wrapped_native: self.wrapped_native,
            stable: self.stable.address,
            stable_decimals: self.stable.decimals,
            connectors: leak(self.connectors),
            topology_pair_budget: self.routing.topology_pair_budget,
            dynamic_connector_cap: self.routing.dynamic_connector_cap,
            screen_connector_cap: self.routing.screen_connector_cap,
            dynamic_connector_allowlist: leak(self.routing.dynamic_connector_allowlist),
            discovery,
            settler,
            native_rfq,
            capabilities: SolverCapabilities {
                quote: discovery != DiscoveryProfile::Disabled,
                unavailable_reason: None,
            },
        })
    }
}

fn unique(field: &str, addresses: &[Address]) -> anyhow::Result<()> {
    for (index, address) in addresses.iter().enumerate() {
        ensure!(*address != Address::ZERO, "{field} lists the zero address");
        ensure!(
            !addresses[..index].contains(address),
            "{field} lists {address} twice"
        );
    }
    Ok(())
}

/// Interns a manifest's venue id and refuses one nobody reviewed: an
/// unreviewed id would run with a family's default fees and Lens reads.
fn reviewed_venue(id: &str) -> anyhow::Result<CatalogProtocol> {
    let protocol = CatalogProtocol::intern(id)?;
    ensure!(
        protocol.core() != crate::venue::Core::Unreviewed,
        "venue {id} has no compiled core; add it to sextant_amm::venue"
    );
    Ok(protocol)
}

impl Venue {
    fn build(self) -> anyhow::Result<CatalogVenue> {
        Ok(match self {
            Venue::V2 {
                id,
                factory,
                fee_ppm,
                quote,
            } => CatalogVenue::V2 {
                protocol: reviewed_venue(&id)?,
                factory,
                fee_ppm,
                quote,
            },
            Venue::V3 {
                id,
                factory,
                verify_pool_spacing,
                fee_tiers,
                quote,
            } => CatalogVenue::V3 {
                protocol: reviewed_venue(&id)?,
                factory,
                verify_pool_spacing,
                fee_tiers: leak(fee_tiers),
                quote,
            },
            Venue::V4 {
                id,
                pool_manager,
                pools_slot,
                quote,
            } => CatalogVenue::V4 {
                protocol: reviewed_venue(&id)?,
                pool_manager,
                pools_slot,
                quote,
            },
        })
    }
}

impl Settler {
    fn build(self) -> anyhow::Result<SettlerProfile> {
        let runtime = match self.runtime {
            Runtime::Exact(hash) => SettlerRuntimePolicy::Exact(hash),
            Runtime::Compatible { extended_v3_hash } => {
                SettlerRuntimePolicy::Compatible { extended_v3_hash }
            }
            Runtime::SignerMasked {
                masked_hash,
                length,
                signer_offsets,
            } => SettlerRuntimePolicy::SignerMasked {
                masked_hash,
                length,
                signer_offsets: leak(signer_offsets),
            },
        };
        ensure!(
            runtime.is_complete(),
            "the Settler runtime policy is incomplete"
        );
        let mut indexed_v3 = Vec::with_capacity(self.v3_forks.len());
        for fork in self.v3_forks {
            let protocol = reviewed_venue(&fork.venue)?;
            ensure!(
                indexed_v3
                    .iter()
                    .all(|other: &IndexedV3Execution| other.protocol != protocol
                        && other.fork_id != fork.fork_id),
                "v3Forks repeats {protocol} or fork {}",
                fork.fork_id
            );
            indexed_v3.push(IndexedV3Execution {
                protocol,
                fork_id: fork.fork_id,
                deployer: fork.deployer,
                init_hash: fork.init_hash,
            });
        }
        Ok(SettlerProfile {
            registry: self.registry,
            registry_token_id: self.registry_token_id,
            allowance_holder: self.allowance_holder,
            allowance_holder_runtime_hash: self.allowance_holder_runtime_hash,
            runtime,
            encoding: match self.encoding {
                Encoding::LegacyBpsVipPathWithSellToken => {
                    SettlerEncoding::LegacyBpsVipPathWithSellToken
                }
                Encoding::PpmVipPathFromPermit => SettlerEncoding::PpmVipPathFromPermit,
            },
            ekubo_v3_runtimes: leak(self.ekubo_v3_runtimes),
            indexed_v3: leak(indexed_v3),
            univ4_pool_manager: self.univ4_pool_manager,
            univ4_fork_id: self.univ4_fork_id,
            native_authorization_typehash: self.native_authorization_typehash,
        })
    }
}

impl NativeRfq {
    fn build(self) -> anyhow::Result<NativeRfqProfile> {
        unique("stockTokens", &self.stock_tokens)?;
        Ok(NativeRfqProfile {
            api_chain: leak_str(self.api_chain),
            router_version: self.router_version,
            contract_revision: self.contract_revision,
            router: self.router,
            router_runtime_hash: self.router_runtime_hash,
            pool: self.pool,
            pool_runtime_hash: self.pool_runtime_hash,
            credit_vault: self.credit_vault,
            credit_vault_runtime_hash: self.credit_vault_runtime_hash,
            trade_selector: self.trade_selector,
            domain_fields: self.domain_fields,
            domain_name: leak_str(self.domain_name),
            domain_version: leak_str(self.domain_version),
            domain_chain_id: self.domain_chain_id,
            stock_tokens: leak(self.stock_tokens),
        })
    }
}

/// Deserializers that accept one spelling of each value.
mod strict {
    use super::*;
    use serde::de::Error;

    fn parse_address<E: Error>(text: &str) -> Result<Address, E> {
        Address::parse_checksummed(text, None)
            .map_err(|_| E::custom(format!("{text:?} is not an EIP-55 address")))
    }

    fn parse_word<E: Error>(text: &str) -> Result<B256, E> {
        let hex = text
            .strip_prefix("0x")
            .filter(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or_else(|| E::custom(format!("{text:?} is not 32 lowercase hex bytes")))?;
        hex.parse().map_err(E::custom)
    }

    pub fn address<'de, D: Deserializer<'de>>(d: D) -> Result<Address, D::Error> {
        parse_address(&String::deserialize(d)?)
    }

    pub fn address_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Address>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|text| parse_address(&text))
            .transpose()
    }

    pub fn addresses<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Address>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|text| parse_address(text))
            .collect()
    }

    pub fn word<'de, D: Deserializer<'de>>(d: D) -> Result<B256, D::Error> {
        parse_word(&String::deserialize(d)?)
    }

    pub fn word_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<B256>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|text| parse_word(&text))
            .transpose()
    }

    pub fn words<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<B256>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|text| parse_word(text))
            .collect()
    }

    pub fn selector<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 4], D::Error> {
        let text = String::deserialize(d)?;
        let hex = text
            .strip_prefix("0x")
            .filter(|hex| hex.len() == 8)
            .ok_or_else(|| D::Error::custom(format!("{text:?} is not a 4-byte selector")))?;
        let mut selector = [0u8; 4];
        alloy_primitives::hex::decode_to_slice(hex, &mut selector).map_err(D::Error::custom)?;
        Ok(selector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_embedded_manifest_builds_under_its_own_key() {
        for (key, _) in SOURCES {
            let profile = embedded(key).unwrap();
            assert_eq!(profile.key, *key);
        }
        assert!(embedded("morph").is_err());
    }

    #[test]
    fn a_manifest_refuses_what_it_does_not_name() {
        let (_, json) = SOURCES[0];
        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["surprise"] = serde_json::json!(1);
        assert!(parse(&value.to_string()).is_err(), "an unknown field");

        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        let lower = value["wrappedNative"].as_str().unwrap().to_lowercase();
        value["wrappedNative"] = serde_json::json!(lower);
        let error = parse(&value.to_string()).unwrap_err();
        assert!(format!("{error:#}").contains("EIP-55"), "{error:#}");

        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        let first = value["connectors"][0].clone();
        value["connectors"].as_array_mut().unwrap().push(first);
        assert!(parse(&value.to_string()).is_err(), "a repeated connector");

        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        let hash = value["settler"]["allowanceHolderRuntimeHash"]
            .as_str()
            .unwrap()
            .to_uppercase()
            .replace("0X", "0x");
        value["settler"]["allowanceHolderRuntimeHash"] = serde_json::json!(hash);
        assert!(parse(&value.to_string()).is_err(), "an uppercase hash");
    }

    #[test]
    fn a_manifest_cannot_weaken_a_reviewed_guarantee() {
        let (_, json) = SOURCES.iter().find(|(key, _)| *key == "bsc").unwrap();
        let original: serde_json::Value = serde_json::from_str(json).unwrap();

        // A compatible Settler runtime is reviewed only beside Robinhood's
        // fork gates.
        let mut value = original.clone();
        let hash = value["settler"]["allowanceHolderRuntimeHash"].clone();
        value["settler"]["runtime"] = serde_json::json!({
            "compatible": { "extendedV3Hash": hash }
        });
        let error = parse(&value.to_string()).unwrap_err();
        assert!(
            format!("{error:#}").contains("runtime.compatible"),
            "{error:#}"
        );

        // The indexer wire is schema v2 and carries five venues.
        let mut value = original.clone();
        value["discovery"]["schemaVersion"] = serde_json::json!(3);
        let error = parse(&value.to_string()).unwrap_err();
        assert!(
            format!("{error:#}").contains("schema version 3"),
            "{error:#}"
        );

        // A venue id nobody compiled would run with family defaults.
        let mut value = original;
        let mut row = value["discovery"]["venues"][1].clone();
        row["id"] = serde_json::json!("unknownvenue");
        value["discovery"]["venues"]
            .as_array_mut()
            .unwrap()
            .push(row);
        let error = parse(&value.to_string()).unwrap_err();
        assert!(
            format!("{error:#}").contains("no compiled core"),
            "{error:#}"
        );
    }

    #[test]
    fn robinhood_discovery_is_bound_to_its_chain() {
        let (_, json) = SOURCES.iter().find(|(key, _)| *key == "robinhood").unwrap();
        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["chainId"] = serde_json::json!(1);
        let error = parse(&value.to_string()).unwrap_err();
        assert!(
            format!("{error:#}").contains("robinhood discovery"),
            "{error:#}"
        );
    }
}
