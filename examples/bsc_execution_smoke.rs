//! Read-only BSC execution smoke test.
//!
//! Each case uses the production Settler encoder, then submits the resulting
//! native-BNB transaction with `eth_call` at one canonical mainnet block. No
//! transaction is signed or broadcast. This pins the reviewed Settler runtime,
//! AllowanceHolder runtime, native wrapping, V2 fee flags, both V3 fork ids,
//! and the BSC Uniswap V4 PoolManager binding.

use alloy::eips::BlockId;
use alloy_primitives::{Address, B256, U256, address, b256, keccak256};
use alloy_sol_types::SolCall;
use anyhow::{Context, ensure};
use serde_json::json;
use sextant::abi::{ISettlerRegistry, addrhex, tohex};
use sextant::chain::{
    BSC_PROFILE, BSC_SETTLER, BSC_UNIV4_POOL_MANAGER, NATIVE, SettlerRuntimePolicy, WBNB,
};
use sextant::pools::{V2Pool, V2Protocol, V2State, V3ExecutionMeta, V3Pool, V3Protocol, V3State};
use sextant::route::{Hop, HopKind, Leg, Plan};
use sextant::rpc::{Rpc, sanitized_error};
use sextant::settler::{BPS_BASE, build_swap_tx_for_profile};
use sextant::state::{Snapshot, v4_meta};

const USER: Address = address!("1111111111111111111111111111111111111111");
const AMOUNT_IN: u128 = 1_000_000_000_000_000; // 0.001 BNB

const UNISWAP_V2_POOL: Address = address!("8a1ed8e124fdfbd534bf48baf732e26db9cc0cf4");
const PANCAKE_V2_POOL: Address = address!("16b9a82891338f9ba80e2d6970fdda79d1eb0dae");
const UNISWAP_V3_POOL: Address = address!("6fe9e9de56356f7edbfcbb29fab7cd69471a4869");
const PANCAKE_V3_POOL: Address = address!("36696169c63e42cd08ce11f5deebbcebae652050");
const UNISWAP_V4_POOL_ID: B256 =
    b256!("a77d89e40ddd6a57b72ad4a8c55554b2fd6171026c903462a9f9c7be133811a6");

enum Venue {
    V2 {
        protocol: V2Protocol,
        pool: Address,
        fee_bps: u32,
    },
    V3 {
        protocol: V3Protocol,
        pool: Address,
        fork_id: u8,
        fee_ppm: u32,
    },
    V4 {
        pool_manager: Address,
        pool_id: B256,
        fee_ppm: u32,
        tick_spacing: i32,
        hooks: Address,
    },
}

fn execution_fixture(settler: Address, venue: Venue) -> anyhow::Result<(Snapshot, Plan)> {
    let token0 = BSC_PROFILE.stable;
    let token1 = WBNB;
    let (snapshot, hop) = match venue {
        Venue::V2 {
            protocol,
            pool,
            fee_bps,
        } => (
            Snapshot {
                block: 0,
                settler: Some(settler),
                v3: Vec::new(),
                v2: vec![(
                    V2Pool {
                        protocol,
                        address: pool,
                        token0,
                        token1,
                        fee_bps,
                    },
                    V2State {
                        reserve0: U256::ZERO,
                        reserve1: U256::ZERO,
                    },
                )],
                ekubo: vec![],
            },
            Hop {
                kind: HopKind::V2,
                index: 0,
                zero_for_one: false,
                token_in: token1,
                token_out: token0,
            },
        ),
        Venue::V3 {
            protocol,
            pool,
            fork_id,
            fee_ppm,
        } => (
            Snapshot {
                block: 0,
                settler: Some(settler),
                v3: vec![(
                    V3Pool {
                        protocol,
                        address: pool,
                        token0,
                        token1,
                        fee_ppm,
                        tick_spacing: 10,
                        verify_pool_spacing: false,
                        execution: Some(V3ExecutionMeta {
                            fork_id,
                            pool_id: fee_ppm,
                        }),
                        v4: None,
                        algebra: None,
                    },
                    V3State {
                        sqrt_price: U256::ZERO,
                        tick: 0,
                        liquidity: U256::ZERO,
                        ticks: Vec::new().into(),
                        pos: 0,
                        lo_cover: 0,
                        hi_cover: 0,
                    },
                )],
                v2: Vec::new(),
                ekubo: vec![],
            },
            Hop {
                kind: HopKind::V3,
                index: 0,
                zero_for_one: false,
                token_in: token1,
                token_out: token0,
            },
        ),
        Venue::V4 {
            pool_manager,
            pool_id,
            fee_ppm,
            tick_spacing,
            hooks,
        } => {
            let meta = v4_meta(
                Address::ZERO,
                BSC_PROFILE.stable,
                fee_ppm,
                tick_spacing,
                hooks,
            );
            ensure!(
                pool_manager == BSC_UNIV4_POOL_MANAGER,
                "Uniswap V4 fixture uses the wrong BSC PoolManager"
            );
            ensure!(
                meta.pool_id == pool_id,
                "Uniswap V4 fixture PoolKey does not match its reviewed PoolId"
            );
            ensure!(meta.native, "Uniswap V4 fixture is not native-keyed");
            (
                Snapshot {
                    block: 0,
                    settler: Some(settler),
                    v3: vec![(
                        V3Pool {
                            protocol: V3Protocol::UNIV4,
                            address: pool_manager,
                            token0: WBNB,
                            token1: BSC_PROFILE.stable,
                            fee_ppm,
                            tick_spacing,
                            verify_pool_spacing: false,
                            execution: None,
                            v4: Some(meta),
                            algebra: None,
                        },
                        V3State {
                            sqrt_price: U256::ZERO,
                            tick: 0,
                            liquidity: U256::ZERO,
                            ticks: Vec::new().into(),
                            pos: 0,
                            lo_cover: 0,
                            hi_cover: 0,
                        },
                    )],
                    v2: Vec::new(),
                    ekubo: vec![],
                },
                Hop {
                    kind: HopKind::V3,
                    index: 0,
                    zero_for_one: true,
                    token_in: WBNB,
                    token_out: BSC_PROFILE.stable,
                },
            )
        }
    };
    let amount_in = U256::from(AMOUNT_IN);
    // The encoder refuses a leg that claims no output. One wei is a minimum
    // any live pool clears; the check is that the transaction executes.
    let plan = Plan {
        legs: vec![Leg {
            path: vec![hop],
            amount_in,
            amount_out: U256::ONE,
            losses: Vec::new(),
            slice_bps: BPS_BASE,
        }],
        amount_out: U256::ONE,
        universe_id: None,
    };
    Ok((snapshot, plan))
}

async fn run() -> anyhow::Result<()> {
    let rpc_url = std::env::var("SOLVER_RPC").context("SOLVER_RPC is required")?;
    let rpc = Rpc::connect(&rpc_url)?;
    rpc.verify_chain_id(BSC_PROFILE.chain_id, "BSC execution smoke")
        .await?;
    let canonical = rpc.canonical_block(BlockId::latest()).await?;
    let block = BlockId::hash_canonical(canonical.hash);

    let adapter = BSC_PROFILE
        .settler
        .context("BSC execution adapter missing")?;
    let owner = rpc
        .eth_call(
            adapter.registry,
            ISettlerRegistry::ownerOfCall {
                id: U256::from(adapter.registry_token_id),
            }
            .abi_encode(),
            block,
        )
        .await?;
    let settler = ISettlerRegistry::ownerOfCall::abi_decode_returns(&owner)
        .context("decoding BSC Settler registry owner")?;
    ensure!(
        settler != Address::ZERO,
        "BSC registry returned zero Settler"
    );

    let allowance_hash = keccak256(rpc.code_at(adapter.allowance_holder, block).await?);
    ensure!(
        allowance_hash == adapter.allowance_holder_runtime_hash,
        "BSC AllowanceHolder runtime is not reviewed"
    );
    let runtime_hash = keccak256(rpc.code_at(settler, block).await?);
    let SettlerRuntimePolicy::Exact(expected_runtime) = adapter.runtime else {
        anyhow::bail!("BSC Settler runtime policy must be exact")
    };
    ensure!(
        runtime_hash == expected_runtime,
        "BSC Settler runtime is not reviewed"
    );
    ensure!(adapter == *BSC_SETTLER, "BSC profile adapter drifted");

    let cases = [
        (
            "Uniswap V2",
            Venue::V2 {
                protocol: V2Protocol::UNIV2,
                pool: UNISWAP_V2_POOL,
                fee_bps: 30,
            },
        ),
        (
            "Pancake V2",
            Venue::V2 {
                protocol: V2Protocol::PANCAKEV2,
                pool: PANCAKE_V2_POOL,
                fee_bps: 25,
            },
        ),
        (
            "Uniswap V3",
            Venue::V3 {
                protocol: V3Protocol::UNIV3,
                pool: UNISWAP_V3_POOL,
                fork_id: 0,
                fee_ppm: 500,
            },
        ),
        (
            "Pancake V3",
            Venue::V3 {
                protocol: V3Protocol::PANCAKEV3,
                pool: PANCAKE_V3_POOL,
                fork_id: 1,
                fee_ppm: 500,
            },
        ),
        (
            "Uniswap V4",
            Venue::V4 {
                pool_manager: BSC_UNIV4_POOL_MANAGER,
                pool_id: UNISWAP_V4_POOL_ID,
                fee_ppm: 500,
                tick_spacing: 10,
                hooks: Address::ZERO,
            },
        ),
    ];
    let block_number = format!("{:#x}", canonical.number);
    for (label, venue) in cases {
        let (snapshot, plan) = execution_fixture(settler, venue)?;
        let tx = build_swap_tx_for_profile(
            &BSC_PROFILE,
            0,
            None,
            None,
            &snapshot,
            &plan,
            NATIVE,
            BSC_PROFILE.stable,
            U256::from(AMOUNT_IN),
            U256::ONE,
            USER,
            u64::MAX,
        )?;
        ensure!(tx.to == settler, "{label} did not target the Settler");
        ensure!(
            tx.allowance_target.is_none(),
            "{label} native input unexpectedly requires approval"
        );
        rpc.request(
            "eth_call",
            json!([{
                "from": addrhex(USER),
                "to": addrhex(tx.to),
                "value": format!("{:#x}", tx.value),
                "data": tohex(&tx.data),
            }, block_number]),
        )
        .await
        .with_context(|| format!("{label} execution call reverted"))?;
        println!("{label}: executable at block {}", canonical.number);
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{}", sanitized_error(&error));
        std::process::exit(1);
    }
}
