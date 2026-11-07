//! W1's acceptance gate, measured: certified optimality gap across the size
//! ladder, against real chain state.
//!
//! Every case is a fee-free quote through the production `/quote` path, so the
//! certificate reported here is the one a caller would receive. One block is
//! pinned for the whole run, which makes the table reproducible and removes
//! staleness as a variable — this measures ALLOCATION quality, not freshness.
//!
//! Run with: `cargo run --release --example certificate_ladder [--block N]`,
//! with SOLVER_RPC set (it defaults to the profile's public RPC).
//!
//! Reads only. No transactions, no external quote APIs, no fork.

use alloy_primitives::address;
use alloy_primitives::{Address, U256};
use anyhow::Context;
use sextant::abi::addrhex;
use sextant::chain::{NATIVE, PUBLIC_RPC, SLVR, UP, USDG, WETH};
use sextant::config::Config;
use sextant::engine::Engine;
use sextant::quotes::{AmountIn, QuoteRequest, QuoteResponse, quote_swap};
use sextant::rpc::Rpc;
use std::sync::Arc;

/// top-TVL meme pair on the chain (CASHCAT/WETH univ3 1%; 18 decimals)
const CASHCAT: Address = address!("020bfc650a365f8bb26819deaabf3e21291018b4");

/// tokenized stock routed through the v4 dynamic-fee hooked pool (18
/// decimals) — the case class where the tighten search is known to stall
const NVDA: Address = address!("d0601ce157db5bdc3162bbac2a2c8af5320d9eec");

fn pow10(n: u64) -> U256 {
    U256::from(10).pow(U256::from(n))
}

struct Case {
    label: String,
    token_in: Address,
    token_out: Address,
    amount: U256,
}

/// Size ladders per pair — the same shape as the compare0x sweep, because the
/// question this answers is about those same cases: of the ground the sweep
/// showed we lose, how much could the allocator have recovered?
fn ladder() -> Vec<Case> {
    let mut cases = Vec::new();
    let mut push = |label: &str, token_in: Address, token_out: Address, amount: U256| {
        cases.push(Case {
            label: label.to_string(),
            token_in,
            token_out,
            amount,
        });
    };
    for (label, tenths) in [
        ("0.1", 1u64),
        ("1", 10),
        ("10", 100),
        ("100", 1_000),
        ("500", 5_000),
    ] {
        push(
            &format!("WETH→USDG {label}"),
            WETH,
            USDG,
            U256::from(tenths) * pow10(17),
        );
        push(
            &format!("WETH→CASHCAT {label}"),
            WETH,
            CASHCAT,
            U256::from(tenths) * pow10(17),
        );
        push(
            &format!("ETH→USDG {label}"),
            NATIVE,
            USDG,
            U256::from(tenths) * pow10(17),
        );
    }
    for (label, units) in [
        ("200", 200u64),
        ("2k", 2_000),
        ("20k", 20_000),
        ("200k", 200_000),
    ] {
        push(
            &format!("USDG→WETH {label}"),
            USDG,
            WETH,
            U256::from(units) * pow10(6),
        );
        push(
            &format!("USDG→CASHCAT {label}"),
            USDG,
            CASHCAT,
            U256::from(units) * pow10(6),
        );
    }
    for (label, units) in [("3k", 3_000u64), ("30k", 30_000), ("600k", 600_000)] {
        push(
            &format!("CASHCAT→WETH {label}"),
            CASHCAT,
            WETH,
            U256::from(units) * pow10(18),
        );
        push(
            &format!("CASHCAT→USDG {label}"),
            CASHCAT,
            USDG,
            U256::from(units) * pow10(18),
        );
    }
    push("WETH→UP 1", WETH, UP, pow10(18));
    push("WETH→UP 10", WETH, UP, U256::from(10) * pow10(18));
    push("UP→WETH 200k", UP, WETH, U256::from(200_000) * pow10(18));
    push("WETH→SLVR 0.1", WETH, SLVR, pow10(17));
    push("SLVR→WETH 0.3", SLVR, WETH, U256::from(3) * pow10(17));
    push("SLVR→USDG 0.3", SLVR, USDG, U256::from(3) * pow10(17));
    push("WETH→NVDA 0.1", WETH, NVDA, pow10(17));
    push("NVDA→USDG 2", NVDA, USDG, U256::from(2) * pow10(18));
    cases
}

async fn quote(cfg: &Config, engine: &Arc<Engine>, case: &Case) -> anyhow::Result<QuoteResponse> {
    quote_swap(
        cfg,
        engine,
        QuoteRequest {
            chain_id: cfg.profile.chain_id,
            token_in: addrhex(case.token_in),
            token_out: addrhex(case.token_out),
            amount_in: AmountIn::Str(case.amount.to_string()),
            slippage_bps: 100,
            recipient: None,
            sender: None,
            tx_origin: None,
            deadline_seconds: 600,
            fee_bps: None,
        },
    )
    .await
}

/// Parsed back from the reported string so the table reports exactly what a
/// caller reads off the wire, not an internal field.
fn gap_e4(text: &str) -> Option<U256> {
    let (whole, frac) = text.split_once('.')?;
    // Full width on the whole part: a screened bound can report a ratio past
    // `u64`, and parsing it narrow would reintroduce the sentinel this format
    // exists to remove.
    let whole = U256::from_str_radix(whole, 10).ok()?;
    let frac = frac.parse::<u64>().ok()?;
    Some(whole * U256::from(10_000u64) + U256::from(frac))
}

fn quantile<T: Copy + Default>(sorted: &[T], numerator: usize, denominator: usize) -> T {
    if sorted.is_empty() {
        return T::default();
    }
    let rank = (sorted.len() * numerator).div_ceil(denominator);
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn render(value: U256) -> String {
    sextant::certificate::format_bps_e4(value)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut pinned: Option<u64> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--block" => {
                pinned = Some(
                    rest.next()
                        .context("--block needs a number")?
                        .parse()
                        .context("--block must be a block number")?,
                );
            }
            other => anyhow::bail!("unexpected argument {other:?}"),
        }
    }

    let rpc_url = std::env::var("SOLVER_RPC").unwrap_or_else(|_| PUBLIC_RPC.to_string());
    let cfg = Config {
        profile: &sextant::chain::ROBINHOOD_PROFILE,
        rpc_url: rpc_url.clone(),
        logs_rpc_url: rpc_url.clone(),
        indexer_url: None,
        native_rfq: None,
        // Fee-free: this measures routing, and a terminal fee would scale both
        // sides of the ratio anyway.
        fee_bps: 0,
        fee_receiver: None,
        positive_slippage_max_bps: 0,
        positive_slippage_recipient: None,
        port: 0,
        quote_timeout: 300,
    };
    let rpc = Rpc::connect(&rpc_url)?;
    rpc.verify_chain_id(sextant::chain::ROBINHOOD_PROFILE.chain_id, "SOLVER_RPC")
        .await?;
    let block = match pinned {
        Some(block) => block,
        None => rpc.block_number().await?,
    };
    let engine = Engine::for_profile_pinned(rpc, &sextant::chain::ROBINHOOD_PROFILE, None, block);

    println!("block {block}");
    println!(
        "{:<22} {:>26} {:>12} {:>9} {:>7} {:>8} {:>5} {:>8}",
        "case", "amount_out", "gap_bps", "unrouted", "pools", "cert_us", "legs", "solve_ms"
    );
    let mut gaps: Vec<U256> = Vec::new();
    let mut cert_us: Vec<u64> = Vec::new();
    // What a plan costs to carry: quantization and polish are quadratic in the
    // leg count, so a change that funds more legs pays for it here.
    let mut legs: Vec<u64> = Vec::new();
    let mut solve_ms: Vec<u64> = Vec::new();
    let mut failures = 0usize;
    let mut uncertified = 0usize;
    for case in ladder() {
        let response = match quote(&cfg, &engine, &case).await {
            Ok(response) => response,
            Err(error) => {
                failures += 1;
                println!("{:<22} {:>26}", case.label, format!("— {error}"));
                continue;
            }
        };
        let Some(certificate) = response.certificate.as_ref() else {
            anyhow::bail!("certificate disabled: set SOLVER_CERTIFICATE=1");
        };
        if certificate.status != "certified" {
            uncertified += 1;
            println!(
                "{:<22} {:>26} {:>12}",
                case.label, response.amount_out_gross, certificate.status
            );
            continue;
        }
        let text = certificate.gap_bps.as_deref().unwrap_or("-");
        if let Some(value) = gap_e4(text) {
            gaps.push(value);
        }
        cert_us.push(response.meta.certificate_us);
        legs.push(response.route.len() as u64);
        solve_ms.push(response.meta.solve_ms);
        println!(
            "{:<22} {:>26} {:>12} {:>9} {:>7} {:>8} {:>5} {:>8}",
            case.label,
            response.amount_out_gross,
            text,
            certificate.unrouted_pools.unwrap_or(0),
            certificate.scanned_pools.unwrap_or(0),
            response.meta.certificate_us,
            response.route.len(),
            response.meta.solve_ms,
        );
    }

    gaps.sort_unstable();
    cert_us.sort_unstable();
    println!();
    println!(
        "certified={} p50={} p95={} max={} uncertified={} no_route={}",
        gaps.len(),
        render(quantile(&gaps, 1, 2)),
        render(quantile(&gaps, 19, 20)),
        render(gaps.last().copied().unwrap_or(U256::ZERO)),
        uncertified,
        failures,
    );
    println!(
        "cert_us p50={} p95={} max={}",
        quantile(&cert_us, 1, 2),
        quantile(&cert_us, 19, 20),
        cert_us.last().copied().unwrap_or(0),
    );
    legs.sort_unstable();
    solve_ms.sort_unstable();
    println!(
        "legs p50={} p95={} max={} | solve_ms p50={} p95={} max={}",
        quantile(&legs, 1, 2),
        quantile(&legs, 19, 20),
        legs.last().copied().unwrap_or(0),
        quantile(&solve_ms, 1, 2),
        quantile(&solve_ms, 19, 20),
        solve_ms.last().copied().unwrap_or(0),
    );
    // The gate P1 ships against.
    println!(
        "P1 gate (p95 gap <= 1 bp): {}",
        if quantile(&gaps, 19, 20) <= U256::from(10_000u64) {
            "PASS"
        } else {
            "FAIL"
        }
    );
    Ok(())
}
