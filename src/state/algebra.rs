use super::*;

// The directional snapshot model is valid for Sheriff's SlidingFee plugin,
// whose result is amount-independent. Unknown Algebra plugins fail closed.
pub(super) const SHERIFF_SLIDING_FEE_PLUGIN: Address =
    alloy_primitives::address!("3a04e527a7aef9cb4c953d59ae8988134e2fa9f9");
pub(super) const SHERIFF_SLIDING_FEE_PLUGIN_CODEHASH: B256 =
    alloy_primitives::b256!("1e392f56e5af82ce2c54ef72175494590d8211bd33ca0449b1a6679e09b18138");
// Bind the pool's hook dispatch as well as the plugin code: the pool admin can
// toggle beforeSwap without replacing the plugin contract.
pub(super) const SHERIFF_PLUGIN_CONFIG: u8 = 215;

pub(super) fn before_swap_call(settler: Address, zero_to_one: bool) -> Vec<u8> {
    let limit = sqrt_limit(zero_to_one).to_be_bytes::<32>();
    beforeSwapCall {
        sender: settler,
        recipient: settler,
        zeroToOne: zero_to_one,
        amountRequired: I256::ONE,
        limitSqrtPrice: U160::from_be_slice(&limit[12..]),
        withPaymentInAdvance: false,
        data: Bytes::new(),
    }
    .abi_encode()
}

pub(super) fn decode_before_swap_fee(ret: &[u8], last_fee: u32) -> anyhow::Result<u32> {
    ensure!(ret.len() >= 96, "short beforeSwap response");
    ensure!(
        ret[..4] == beforeSwapCall::SELECTOR,
        "wrong beforeSwap callback selector"
    );
    let override_fee = u32::try_from(read_word(ret, 32)?).context("override fee out of range")?;
    let plugin_fee = u32::try_from(read_word(ret, 64)?).context("plugin fee out of range")?;
    let swap_fee = if override_fee == 0 {
        last_fee
    } else {
        override_fee
    };
    let fee = swap_fee
        .checked_add(plugin_fee)
        .context("Algebra fee overflow")?;
    ensure!(fee < 1_000_000, "invalid effective fee {fee}");
    Ok(fee)
}

pub(super) fn validate_sheriff_binding(binding: SheriffBinding) -> anyhow::Result<()> {
    ensure!(
        binding.plugin == SHERIFF_SLIDING_FEE_PLUGIN,
        "unsupported Algebra plugin"
    );
    ensure!(
        binding.codehash == SHERIFF_SLIDING_FEE_PLUGIN_CODEHASH,
        "unsupported Algebra plugin code"
    );
    ensure!(
        binding.config == SHERIFF_PLUGIN_CONFIG,
        "unsupported Algebra plugin config"
    );
    ensure!(binding.last_fee < 1_000_000, "invalid Algebra fallback fee");
    Ok(())
}

async fn algebra_fees(
    rpc: &Rpc,
    block: BlockId,
    settler: Address,
    pool: Address,
    binding: SheriffBinding,
) -> anyhow::Result<AlgebraMeta> {
    let call0 = rpc.eth_call_from(pool, binding.plugin, before_swap_call(settler, true), block);
    let call1 = rpc.eth_call_from(
        pool,
        binding.plugin,
        before_swap_call(settler, false),
        block,
    );
    let (ret0, ret1) = tokio::try_join!(call0, call1)?;
    Ok(AlgebraMeta {
        fee_0to1_ppm: decode_before_swap_fee(&ret0, binding.last_fee)?,
        fee_1to0_ppm: decode_before_swap_fee(&ret1, binding.last_fee)?,
    })
}

pub(super) async fn attach_algebra_fees(
    rpc: &Rpc,
    mut parsed: ParsedLens,
    block: BlockId,
) -> anyhow::Result<Snapshot> {
    let mut dropped = vec![false; parsed.snapshot.v3.len()];
    let mut calls = Vec::with_capacity(parsed.sheriff_plugins.len());
    for binding in parsed.sheriff_plugins {
        let pool = parsed.snapshot.v3[binding.index].0.address;
        match validate_sheriff_binding(binding) {
            Ok(()) => calls.push((pool, binding)),
            Err(error) => {
                tracing::info!("snapshot: Sheriff pool {pool:#x} dropped ({error})");
                dropped[binding.index] = true;
            }
        }
    }
    let settler = if calls.is_empty() {
        None
    } else {
        let settler = parsed
            .snapshot
            .settler
            .context("snapshot has no Settler identity for Sheriff fee reads")?;
        ensure!(
            settler != Address::ZERO,
            "snapshot Settler must not be zero"
        );
        Some(settler)
    };
    let results =
        futures_util::future::join_all(calls.into_iter().map(|(pool, binding)| async move {
            (
                binding.index,
                pool,
                algebra_fees(
                    rpc,
                    block,
                    settler.expect("Sheriff calls require a Settler"),
                    pool,
                    binding,
                )
                .await,
            )
        }))
        .await;
    for (i, pool, result) in results {
        match result {
            Ok(meta) => parsed.snapshot.v3[i].0.algebra = Some(meta),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading Sheriff beforeSwap fee for pool {pool:#x}"));
            }
        }
    }
    parsed.snapshot.v3 = parsed
        .snapshot
        .v3
        .into_iter()
        .enumerate()
        .filter_map(|(i, pool)| (!dropped[i]).then_some(pool))
        .collect();
    Ok(parsed.snapshot)
}
