use crate::abi::IExtsload;
use crate::chain::{V4_DYNAMIC_FEE_FLAG, V4_POOLS_SLOT};
use crate::pools::{V3Pool, V4Meta};
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::SolCall;
use anyhow::Context;

/// CREATE2 pool address for Settler-supported V3 forks — byte-identical to the
/// derivation the Settler's UNISWAPV3 action performs before calling the pool.
pub fn clone_pool_addr(
    deployer: Address,
    init: B256,
    t0: Address,
    t1: Address,
    fee: u32,
) -> Address {
    let mut preimage = [0u8; 96];
    preimage[12..32].copy_from_slice(t0.as_slice());
    preimage[44..64].copy_from_slice(t1.as_slice());
    preimage[64..96].copy_from_slice(&B256::from(U256::from(fee)).0);
    deployer.create2(keccak256(preimage), init)
}

/// Sheriff uses Settler's poolId=0 branch: the CREATE2 salt is exactly
/// keccak(abi.encode(token0, token1)), with no third fee/pool-id word.
pub(super) fn algebra_pool_addr(
    deployer: Address,
    init: B256,
    t0: Address,
    t1: Address,
) -> Address {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(t0.as_slice());
    preimage[44..64].copy_from_slice(t1.as_slice());
    deployer.create2(keccak256(preimage), init)
}

pub(super) fn v4_pool_id(c0: Address, c1: Address, fee: u32, spacing: i32, hooks: Address) -> B256 {
    let mut key = [0u8; 160];
    key[12..32].copy_from_slice(c0.as_slice());
    key[44..64].copy_from_slice(c1.as_slice());
    key[64..96].copy_from_slice(&B256::from(U256::from(fee)).0);
    key[96..128].copy_from_slice(&B256::from(U256::from(spacing as u32)).0); // spacing > 0 always
    key[140..160].copy_from_slice(hooks.as_slice());
    keccak256(key)
}

fn v4_state_slot(pool_id: B256, pools_slot: u64) -> B256 {
    let mut slot = [0u8; 64];
    slot[..32].copy_from_slice(pool_id.as_slice());
    slot[32..].copy_from_slice(&B256::from(U256::from(pools_slot)).0);
    keccak256(slot)
}

pub(super) fn v4_meta_from_pool_id(
    pool_id: B256,
    pools_slot: u64,
    native: bool,
    hooks: Address,
) -> V4Meta {
    V4Meta {
        pool_id,
        state_slot: v4_state_slot(pool_id, pools_slot),
        native,
        hooks,
        // Real values come from slot0 at snapshot time; until then they
        // poison (> 100%) so a pre-snapshot sim fails loudly, never cheaply.
        swap_fee_0to1_ppm: u32::MAX,
        swap_fee_1to0_ppm: u32::MAX,
    }
}

fn v4_meta_for(
    pools_slot: u64,
    c0: Address,
    c1: Address,
    fee: u32,
    spacing: i32,
    hooks: Address,
) -> V4Meta {
    v4_meta_from_pool_id(
        v4_pool_id(c0, c1, fee, spacing, hooks),
        pools_slot,
        c0 == Address::ZERO,
        hooks,
    )
}

/// V4 metadata for reviewed deployments that use the standard pools slot.
/// Runtime indexed adapters use `v4_meta_for` with their venue-declared slot.
pub fn v4_meta(c0: Address, c1: Address, fee: u32, spacing: i32, hooks: Address) -> V4Meta {
    v4_meta_for(V4_POOLS_SLOT, c0, c1, fee, spacing, hooks)
}

pub(super) fn v4_key_fee_from_slot0(pool: &V3Pool, lp_fee: u32) -> Option<u32> {
    let meta = pool.v4.as_ref()?;
    let (currency0, currency1) = if meta.native {
        (Address::ZERO, pool.token1)
    } else {
        (pool.token0, pool.token1)
    };
    [lp_fee, V4_DYNAMIC_FEE_FLAG].into_iter().find(|fee| {
        v4_pool_id(currency0, currency1, *fee, pool.tick_spacing, meta.hooks) == meta.pool_id
    })
}

/// Effective swap fee for one direction — Pool.sol:307 of the deployed
/// PoolManager: `pf + lpFee - floor(pf * lpFee / 1e6)`, all in pips. Trader
/// amounts depend only on this combined fee; the protocol's cut is split out
/// of the fee AFTER computeSwapStep and never touches amountIn/amountOut.
pub(super) fn v4_swap_fee(protocol_fee_dir: u32, lp_fee: u32) -> anyhow::Result<u32> {
    let pf = u64::from(protocol_fee_dir);
    let lp = u64::from(lp_fee);
    u32::try_from(pf + lp - pf * lp / 1_000_000).context("v4 swap fee out of range")
}

/// Hook permission bits: the LOW 14 bits of the hook address (Hooks.sol).
pub(super) fn v4_hook_flags(hooks: Address) -> u32 {
    let b = hooks.as_slice();
    (u32::from(b[18]) << 8 | u32::from(b[19])) & 0x3fff
}

pub(super) fn extsload(slot: B256) -> Vec<u8> {
    IExtsload::extsloadCall { slot }.abi_encode()
}

/// V4 packed Slot0: sqrtPrice[0..160) | tick[160..184) | protocolFee[184..208) | lpFee[208..232).
pub(super) fn v4_slot0(word: U256) -> (U256, i32, u32, u32) {
    let sqrt = word & ((U256::from(1u8) << 160usize) - U256::from(1u8));
    let t = u32::try_from((word >> 160usize) & U256::from(0xffffffu32)).expect("24 bits");
    let tick = if t >= 0x80_0000 {
        t as i32 - 0x100_0000
    } else {
        t as i32
    };
    let protocol_fee =
        u32::try_from((word >> 184usize) & U256::from(0xffffffu32)).expect("24 bits");
    let lp_fee = u32::try_from((word >> 208usize) & U256::from(0xffffffu32)).expect("24 bits");
    (sqrt, tick, protocol_fee, lp_fee)
}

/// int128 stored in the high half of a storage word (v4 TickInfo packs
/// liquidityGross low, liquidityNet high).
pub(super) fn v4_liquidity_net(word: U256) -> alloy_primitives::I256 {
    let hi = word >> 128usize;
    let raw = if hi.bit(127) {
        hi | (U256::MAX << 128usize)
    } else {
        hi
    };
    alloy_primitives::I256::from_raw(raw)
}
