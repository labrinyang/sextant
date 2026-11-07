use super::*;

type SettlerCodehashKey = (u64, Address);

/// A verified execution contract: its runtime hash and, for a Settler build
/// that carries one, its Native authorization signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VerifiedRuntime {
    hash: B256,
    signer: Option<Address>,
}

static SETTLER_CODEHASHES: LazyLock<Mutex<HashMap<SettlerCodehashKey, VerifiedRuntime>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Read and check an execution contract's runtime once per chain and address.
/// Code at an address cannot change once deployed (EIP-6780 leaves
/// SELFDESTRUCT no way to clear it), and the registry lookup that names the
/// Settler stays block-pinned.
async fn verified_runtime_at(
    profile: &ChainProfile,
    rpc: &Rpc,
    address: Address,
    block: BlockId,
    check: impl FnOnce(&[u8]) -> anyhow::Result<Option<Address>>,
) -> anyhow::Result<VerifiedRuntime> {
    let cache_key = (profile.chain_id, address);
    if let Some(runtime) = SETTLER_CODEHASHES
        .lock()
        .expect("execution codehash cache")
        .get(&cache_key)
        .copied()
    {
        return Ok(runtime);
    }
    let code = rpc.code_at(address, block).await?;
    ensure_integrity!(
        !code.is_empty(),
        "execution contract {address:#x} has no code"
    );
    let signer = match check(&code) {
        Ok(signer) => signer,
        Err(error) => {
            return Err(anyhow::Error::new(UpstreamIntegrityError::new(format!(
                "execution contract {address:#x} is not reviewed for {}: {error}",
                profile.name
            ))));
        }
    };
    let runtime = VerifiedRuntime {
        hash: keccak256(code),
        signer,
    };
    SETTLER_CODEHASHES
        .lock()
        .expect("execution codehash cache")
        .insert(cache_key, runtime);
    Ok(runtime)
}

pub(super) fn settler_registry_call(profile: &ChainProfile) -> anyhow::Result<(Address, Vec<u8>)> {
    let settler = profile
        .settler
        .context("chain profile has no transaction adapter")?;
    Ok((
        settler.registry,
        ISettlerRegistry::ownerOfCall {
            id: U256::from(settler.registry_token_id),
        }
        .abi_encode(),
    ))
}

/// The registry has no current Settler for the feature: it was never
/// deployed, or the pause module removed every instance. Quotes stay
/// indicative until a Settler is back.
#[derive(Debug)]
pub struct SettlerUnavailable;

impl std::fmt::Display for SettlerUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the Settler registry has no current Settler")
    }
}

impl std::error::Error for SettlerUnavailable {}

/// Resolve the rotating Settler from this profile's registry at the exact
/// canonical block used for pool state. Settler identity is intentionally
/// resolved outside QuoteLens so pool-state reads have no chain-specific
/// registry dependency.
async fn settler_at(profile: &ChainProfile, rpc: &Rpc, block: BlockId) -> anyhow::Result<Address> {
    let (registry, call) = settler_registry_call(profile)?;
    let ret = match rpc.eth_call(registry, call, block).await {
        Ok(ret) => ret,
        // A revert is the registry's answer: no instance (`ownerOf` reverts
        // for a removed or never-deployed feature) or no registry code at all.
        Err(error) if error.downcast_ref::<crate::rpc::RevertData>().is_some() => {
            return Err(anyhow::Error::new(SettlerUnavailable));
        }
        Err(error) => return Err(error),
    };
    if ret.is_empty() {
        return Err(anyhow::Error::new(SettlerUnavailable));
    }
    let settler = ISettlerRegistry::ownerOfCall::abi_decode_returns(&ret).context(
        crate::rpc::RpcUnavailable("decoding Settler registry ownerOf"),
    )?;
    ensure!(settler != Address::ZERO, "Settler registry returned zero");
    Ok(settler)
}

/// The resolved and verified execution identity at one canonical block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionIdentity {
    pub settler: Address,
    pub runtime_hash: B256,
    /// The Native authorization signer compiled into this Settler.
    pub authorization_signer: Option<Address>,
}

/// Resolve and verify every contract that can receive a user approval or
/// execute solver calldata. The registry lookup remains block-pinned while
/// immutable runtimes are cached by chain and address.
pub(crate) async fn verify_execution_adapter_at(
    profile: &ChainProfile,
    rpc: &Rpc,
    block: BlockId,
) -> anyhow::Result<ExecutionIdentity> {
    let adapter = profile
        .settler
        .context("chain profile has no transaction adapter")?;
    let expected_holder = adapter.allowance_holder_runtime_hash;
    verified_runtime_at(profile, rpc, adapter.allowance_holder, block, |code| {
        anyhow::ensure!(
            keccak256(code) == expected_holder,
            "AllowanceHolder runtime is not the reviewed build"
        );
        Ok(None)
    })
    .await?;

    let settler = settler_at(profile, rpc, block).await?;
    let runtime = verified_runtime_at(profile, rpc, settler, block, |code| {
        adapter.runtime.verify(code)
    })
    .await?;
    Ok(ExecutionIdentity {
        settler,
        runtime_hash: runtime.hash,
        authorization_signer: runtime.signer,
    })
}

/// The registry read that names the current Settler, for a caller that reads
/// it beside other state in one multicall.
pub(crate) fn execution_registry_call(
    profile: &ChainProfile,
) -> anyhow::Result<(Address, Vec<u8>)> {
    settler_registry_call(profile)
}

/// `verify_execution_adapter_at`, from a registry answer already read at
/// `block`. `Ok(None)` is the registry having no current Settler, which leaves
/// quotes indicative exactly as the per-pair snapshot does.
pub(crate) async fn execution_identity_from(
    profile: &ChainProfile,
    rpc: &Rpc,
    block: BlockId,
    owner: &Option<Vec<u8>>,
) -> anyhow::Result<Option<ExecutionIdentity>> {
    let adapter = profile
        .settler
        .context("chain profile has no transaction adapter")?;
    let expected_holder = adapter.allowance_holder_runtime_hash;
    verified_runtime_at(profile, rpc, adapter.allowance_holder, block, |code| {
        anyhow::ensure!(
            keccak256(code) == expected_holder,
            "AllowanceHolder runtime is not the reviewed build"
        );
        Ok(None)
    })
    .await?;
    let Some(ret) = owner.as_deref().filter(|ret| !ret.is_empty()) else {
        return Ok(None);
    };
    let settler = ISettlerRegistry::ownerOfCall::abi_decode_returns(ret).context(
        crate::rpc::RpcUnavailable("decoding Settler registry ownerOf"),
    )?;
    ensure!(settler != Address::ZERO, "Settler registry returned zero");
    let runtime = verified_runtime_at(profile, rpc, settler, block, |code| {
        adapter.runtime.verify(code)
    })
    .await?;
    Ok(Some(ExecutionIdentity {
        settler,
        runtime_hash: runtime.hash,
        authorization_signer: runtime.signer,
    }))
}
