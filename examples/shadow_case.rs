// Shadow-diff fixture: quote + build one swap at a pinned block with FIXED
// deadline/recipient/fee, print machine-readable JSON. The original solver's
// twin did the same; byte-equality of quotes and calldata was the check.
//
//   cargo run --release --example shadow_case -- <tokenIn|native> <tokenOut|native> <amount> [block]

use alloy_primitives::{Address, U256, address};
use sextant::abi::{addrhex, tohex};
use sextant::chain::{NATIVE, PUBLIC_RPC, ROBINHOOD_PROFILE};
use sextant::quotes::net_after_fee;
use sextant::route::{HopKind, PreparedRoutes, quantized_plan};
use sextant::rpc::Rpc;
use sextant::settler::{BPS_BASE, build_swap_tx_for_profile};
use sextant::state::snapshot_at_for;
use sextant::v3math::muldiv;

const DEADLINE: u64 = 1789000000;
const SLIPPAGE_BPS: u32 = 50;
const FEE_BPS: u32 = 9;

fn parse_token(s: &str) -> Address {
    if s == "native" {
        NATIVE
    } else {
        s.parse().expect("bad token address")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let token_in = parse_token(&args[1]);
    let token_out = parse_token(&args[2]);
    let amount: U256 = args[3].parse().expect("bad amount");
    let pin = args.get(4).map(|s| s.parse::<u64>().expect("bad block"));

    let rpc = Rpc::connect(&std::env::var("SOLVER_RPC").unwrap_or_else(|_| PUBLIC_RPC.into()))?;
    rpc.verify_chain_id(ROBINHOOD_PROFILE.chain_id, "SOLVER_RPC")
        .await?;
    let (a, b) = (
        ROBINHOOD_PROFILE.erc20_of(token_in),
        ROBINHOOD_PROFILE.erc20_of(token_out),
    );
    let snap = snapshot_at_for(&ROBINHOOD_PROFILE, &rpc, None, a, b, pin).await?;
    let plan = quantized_plan(
        &snap,
        &PreparedRoutes::for_profile(&snap, &ROBINHOOD_PROFILE, a, b)?.solve(amount, 64, 200)?,
        amount,
    )?;

    let gross = plan.amount_out;
    let gross_min = muldiv(
        gross,
        U256::from(BPS_BASE - SLIPPAGE_BPS),
        U256::from(BPS_BASE),
    )?;
    let tx = build_swap_tx_for_profile(
        &ROBINHOOD_PROFILE,
        FEE_BPS,
        Some(address!("00000000000000000000000000000000000000fe")),
        None,
        &snap,
        &plan,
        token_in,
        token_out,
        amount,
        net_after_fee(gross_min, FEE_BPS)?,
        address!("7665c425b5f3a0249644024bb32a179ab2d5e0a2"),
        DEADLINE,
    )?;

    let legs: Vec<serde_json::Value> = plan
        .legs
        .iter()
        .map(|leg| {
            serde_json::json!({
                "sliceBps": leg.slice_bps,
                "amountIn": leg.amount_in.to_string(),
                "amountOut": leg.amount_out.to_string(),
                "pools": leg.path.iter().map(|h| {
                    match h.kind {
                        HopKind::V3 => addrhex(snap.v3[h.index].0.address),
                        HopKind::V2 => addrhex(snap.v2[h.index].0.address),
                        HopKind::Ekubo => format!("{:#x}", snap.ekubo[h.index].0.pool_id),
                    }
                }).collect::<Vec<_>>(),
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::json!({
            "block": snap.block,
            "settler": snap.settler.map(addrhex),
            "gross": gross.to_string(),
            "minOutNet": net_after_fee(gross_min, FEE_BPS)?.to_string(),
            "legs": legs,
            "txTo": addrhex(tx.to),
            "txValue": tx.value.to_string(),
            "txData": tohex(&tx.data),
        })
    );
    Ok(())
}
