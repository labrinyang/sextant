// Head-to-head vs 0x (a port of the original solver's comparison script), fee-neutral on
// both sides so the comparison measures routing capability, not commercial
// fees. 0x buy-side fees are added back; sell-side fees are removed from the
// amount quoted through both routers.
//
//   cargo run --release --example compare0x -- sweep   quote-only screening, never used to rank
//   cargo run --release --example compare0x             fork-execute the canonical cases
//   cargo run --release --example compare0x -- UP      … filtered by label substring
//   cargo run --release --example compare0x -- --case 'WETH→USDG 1' --case 'WETH→UP 10'
//   cargo run --release --example compare0x -- --chain bsc  same harness on BNB Smart Chain
//
// The chain comes from --chain, else SOLVER_CHAIN, else robinhood. Indexer-
// backed profiles (BSC) additionally require SOLVER_INDEXER_URL; the engine is
// then built exactly as production builds it, ranked connectors included.
//
// Exec mode, per case:
//   1. 0x allowance-holder quote supplies block B and the routed sell amount
//   2. our fee-free quote is pinned to B against the live RPC
//   3. anvil fork @ B: fund and approve through storage-slot probes, then
//      execute both sides at B+1 and the same timestamp in separate
//      evm_snapshot/evm_revert bubbles
//   4. report actual user price, fee-neutral routing edge, gas and quote phases;
//      require our output to equal its quote and 0x output to meet minBuyAmount

use alloy::eips::BlockId;
use alloy_primitives::{Address, B256, U256, address, keccak256};
use alloy_sol_types::{SolCall, sol};
use anyhow::{Context, bail};
use serde_json::{Value, json};
use sextant::abi::{addrhex, hexbytes, read_word, tohex};
use sextant::chain::{
    BSC_USD1, BSC_USDT, ChainProfile, NATIVE, SLVR, UP, USDG, WBNB, WETH, profile_by_key,
};
use sextant::config::Config;
use sextant::engine::Engine;
use sextant::indexer::IndexerClient;
use sextant::quotes::{AmountIn, HopJson, QuoteRequest, QuoteResponse, quote_swap};
use sextant::rpc::Rpc;
use sextant::v3math::muldiv;
use std::sync::Arc;
use std::time::Instant;

mod support;
use support::ManagedAnvil;

sol! {
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address owner) external view returns (uint256);
}

/// top-TVL meme pair on the chain (CASHCAT/WETH univ3 1%; 18 decimals)
const CASHCAT: Address = address!("020bfc650a365f8bb26819deaabf3e21291018b4");
const PONS: Address = address!("39dbed3a2bd333467115de45665cc57f813c4571");
const TENDIES: Address = address!("45242320dbb855eea8fd36804c6487e10e97fcf9");
const INDEX: Address = address!("56910d4409f3a0c78c64dd8d0545ff0705389870");

// BSC case tokens. All are plain BEP-20s with 18 decimals and no transfer
// behaviour, drawn from the reviewed dynamic-connector allowlist.
const BSC_USDC: Address = address!("8ac76a51cc950d9822d68b83fe1ad97b32cd580d");
const BSC_BTCB: Address = address!("7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c");
const BSC_ETH: Address = address!("2170ed0880ac9a755fd29b2688956bd959f933f8");
const BSC_XRP: Address = address!("1d2f0da169ceb9fc7b3144628db156f3f6c60dbe");
const BSC_CAKE: Address = address!("0e09fabb73bd3ade0a17ecc321fd13a19e81ce82");

const TAKER: Address = address!("1111111111111111111111111111111111111111");
const ANVIL_PORT: u16 = 8548;
const GAS: &str = "0x7a1200";

fn pow10(n: u64) -> U256 {
    U256::from(10).pow(U256::from(n))
}

fn hexu(x: U256) -> String {
    format!("{x:#x}")
}

fn ubig(s: &str) -> anyhow::Result<U256> {
    U256::from_str_radix(s, 10).context("decimal amount")
}

fn ubig_hex(v: &Value) -> anyhow::Result<U256> {
    let s = v.as_str().context("hex quantity")?;
    U256::from_str_radix(s.trim_start_matches("0x"), 16).context("bad hex quantity")
}

fn f64_of(x: U256) -> anyhow::Result<f64> {
    x.to_string().parse().context("converting U256 to f64")
}

fn bps(a: U256, b: U256) -> anyhow::Result<f64> {
    anyhow::ensure!(b != U256::ZERO, "basis-point denominator is zero");
    Ok(((f64_of(a)? / f64_of(b)?) - 1.0) * 10_000.0)
}

fn execution_price_bps(ours: &Execution, zeroex: &Execution) -> anyhow::Result<f64> {
    anyhow::ensure!(
        ours.actual_spent != U256::ZERO && zeroex.actual_spent != U256::ZERO,
        "executed input amount is zero"
    );
    anyhow::ensure!(
        ours.raw_received != U256::ZERO && zeroex.raw_received != U256::ZERO,
        "executed output amount is zero"
    );
    let ours_price = f64_of(ours.raw_received)? / f64_of(ours.actual_spent)?;
    let zeroex_price = f64_of(zeroex.raw_received)? / f64_of(zeroex.actual_spent)?;
    Ok((ours_price / zeroex_price - 1.0) * 10_000.0)
}

fn redacted_error(error: &anyhow::Error, rpc_url: &str) -> String {
    format!("{error:#}").replace(rpc_url, "<RPC>")
}

#[derive(Clone, Copy)]
enum FeeSide {
    None,
    Sell,
    Buy,
}

/// Return the common routed sell amount and fee-neutral buy amount. A
/// sell-side fee reduces the amount quoted by our solver instead of linearly
/// scaling 0x's output through nonlinear AMM price impact.
fn fee_neutral_terms(
    buy: U256,
    sell: U256,
    fee: U256,
    side: FeeSide,
) -> anyhow::Result<(U256, U256)> {
    match side {
        FeeSide::None => Ok((sell, buy)),
        FeeSide::Buy => Ok((
            sell,
            buy.checked_add(fee).context("0x buy-side fee overflow")?,
        )),
        FeeSide::Sell => {
            let routed_sell = sell
                .checked_sub(fee)
                .context("0x sell-side fee exceeds sell amount")?;
            if routed_sell == U256::ZERO {
                bail!("0x sell-side fee consumes the full sell amount")
            }
            Ok((routed_sell, buy))
        }
    }
}

fn fee_neutral_execution(
    received: U256,
    quoted_buy: U256,
    quoted_gross: U256,
) -> anyhow::Result<U256> {
    muldiv(received, quoted_gross, quoted_buy).context("normalizing executed 0x buy-side fee")
}

struct Case {
    label: String,
    token_in: Address,
    token_out: Address,
    amount: U256,
}

fn case(label: &str, token_in: Address, token_out: Address, amount: U256) -> Case {
    Case {
        label: label.to_string(),
        token_in,
        token_out,
        amount,
    }
}

/// The canonical fork-executed set. Display-only tokens remain useful in
/// quote sweeps, but are excluded here because the execution harness must obey
/// the same explicit transfer-safety policy as `/quote`.
fn exec_cases(profile: &ChainProfile) -> anyhow::Result<Vec<Case>> {
    match profile.key {
        "robinhood" => Ok(robinhood_exec_cases()),
        "bsc" => Ok(bsc_exec_cases()),
        key => bail!("no exec cases for chain {key}"),
    }
}

fn robinhood_exec_cases() -> Vec<Case> {
    vec![
        case("WETH→USDG 1", WETH, USDG, pow10(18)),
        case("WETH→USDG 100", WETH, USDG, U256::from(100) * pow10(18)),
        case("WETH→USDG 500", WETH, USDG, U256::from(500) * pow10(18)),
        case("USDG→WETH 100k", USDG, WETH, U256::from(100_000) * pow10(6)),
        case("WETH→UP 10", WETH, UP, U256::from(10) * pow10(18)),
        case("UP→WETH 200k", UP, WETH, U256::from(200_000) * pow10(18)),
        case("ETH→USDG 5", NATIVE, USDG, U256::from(5) * pow10(18)),
        case("USDG→ETH 5k", USDG, NATIVE, U256::from(5_000) * pow10(6)),
        case("WETH→CASHCAT 1", WETH, CASHCAT, pow10(18)),
        case("WETH→CASHCAT 20", WETH, CASHCAT, U256::from(20) * pow10(18)),
        case(
            "CASHCAT→WETH 30k",
            CASHCAT,
            WETH,
            U256::from(30_000) * pow10(18),
        ),
        case(
            "CASHCAT→WETH 600k",
            CASHCAT,
            WETH,
            U256::from(600_000) * pow10(18),
        ),
        case("ETH→CASHCAT 0.1", NATIVE, CASHCAT, pow10(17)),
        case("ETH→CASHCAT 1", NATIVE, CASHCAT, pow10(18)),
        case(
            "ETH→CASHCAT 20",
            NATIVE,
            CASHCAT,
            U256::from(20) * pow10(18),
        ),
        case(
            "CASHCAT→ETH 3k",
            CASHCAT,
            NATIVE,
            U256::from(3_000) * pow10(18),
        ),
        case(
            "CASHCAT→ETH 30k",
            CASHCAT,
            NATIVE,
            U256::from(30_000) * pow10(18),
        ),
        case(
            "CASHCAT→ETH 600k",
            CASHCAT,
            NATIVE,
            U256::from(600_000) * pow10(18),
        ),
        case(
            "USDG→CASHCAT 200",
            USDG,
            CASHCAT,
            U256::from(200) * pow10(6),
        ),
        case(
            "USDG→CASHCAT 2k",
            USDG,
            CASHCAT,
            U256::from(2_000) * pow10(6),
        ),
        case(
            "USDG→CASHCAT 40k",
            USDG,
            CASHCAT,
            U256::from(40_000) * pow10(6),
        ),
        case(
            "CASHCAT→USDG 3k",
            CASHCAT,
            USDG,
            U256::from(3_000) * pow10(18),
        ),
        case(
            "CASHCAT→USDG 30k",
            CASHCAT,
            USDG,
            U256::from(30_000) * pow10(18),
        ),
        case(
            "CASHCAT→USDG 600k",
            CASHCAT,
            USDG,
            U256::from(600_000) * pow10(18),
        ),
        case("WETH→SLVR 0.1", WETH, SLVR, pow10(17)),
        case("SLVR→WETH 0.3", SLVR, WETH, U256::from(3) * pow10(17)),
        case("ETH→SLVR 0.1", NATIVE, SLVR, pow10(17)),
        case("SLVR→ETH 0.3", SLVR, NATIVE, U256::from(3) * pow10(17)),
        case("USDG→SLVR 200", USDG, SLVR, U256::from(200) * pow10(6)),
        case("SLVR→USDG 0.3", SLVR, USDG, U256::from(3) * pow10(17)),
    ]
}

/// Canonical BSC set: blue-chip BEP-20s only, sized so both routers stay
/// inside executable liquidity. Stable↔stable and wrapped-asset pairs are the
/// shapes where production adjacency + ranked connectors matter most.
fn bsc_exec_cases() -> Vec<Case> {
    vec![
        case("WBNB→USDT 1", WBNB, BSC_USDT, pow10(18)),
        case("WBNB→USDT 10", WBNB, BSC_USDT, U256::from(10) * pow10(18)),
        case("WBNB→USDT 100", WBNB, BSC_USDT, U256::from(100) * pow10(18)),
        case(
            "USDT→WBNB 1k",
            BSC_USDT,
            WBNB,
            U256::from(1_000) * pow10(18),
        ),
        case(
            "USDT→WBNB 30k",
            BSC_USDT,
            WBNB,
            U256::from(30_000) * pow10(18),
        ),
        case("BNB→USDT 1", NATIVE, BSC_USDT, pow10(18)),
        case(
            "USDT→BNB 1k",
            BSC_USDT,
            NATIVE,
            U256::from(1_000) * pow10(18),
        ),
        case("WBNB→USDC 10", WBNB, BSC_USDC, U256::from(10) * pow10(18)),
        case(
            "USDC→WBNB 10k",
            BSC_USDC,
            WBNB,
            U256::from(10_000) * pow10(18),
        ),
        case(
            "USDT→USDC 10k",
            BSC_USDT,
            BSC_USDC,
            U256::from(10_000) * pow10(18),
        ),
        case(
            "USDC→USDT 10k",
            BSC_USDC,
            BSC_USDT,
            U256::from(10_000) * pow10(18),
        ),
        case("WBNB→USD1 10", WBNB, BSC_USD1, U256::from(10) * pow10(18)),
        case(
            "USD1→USDT 1k",
            BSC_USD1,
            BSC_USDT,
            U256::from(1_000) * pow10(18),
        ),
        case("WBNB→BTCB 10", WBNB, BSC_BTCB, U256::from(10) * pow10(18)),
        case("BTCB→WBNB 0.5", BSC_BTCB, WBNB, U256::from(5) * pow10(17)),
        case(
            "USDT→BTCB 30k",
            BSC_USDT,
            BSC_BTCB,
            U256::from(30_000) * pow10(18),
        ),
        case("WBNB→ETH 5", WBNB, BSC_ETH, U256::from(5) * pow10(18)),
        case("ETH→WBNB 1", BSC_ETH, WBNB, pow10(18)),
        case("WBNB→XRP 100", WBNB, BSC_XRP, U256::from(100) * pow10(18)),
        case(
            "XRP→WBNB 100k",
            BSC_XRP,
            WBNB,
            U256::from(100_000) * pow10(18),
        ),
        case("WBNB→CAKE 10", WBNB, BSC_CAKE, U256::from(10) * pow10(18)),
        case(
            "CAKE→WBNB 10k",
            BSC_CAKE,
            WBNB,
            U256::from(10_000) * pow10(18),
        ),
    ]
}

/// Broad quote-only matrix: size ladders per pair, to find where either side
/// systematically wins before paying for fork execution.
fn sweep_cases(profile: &ChainProfile) -> anyhow::Result<Vec<Case>> {
    match profile.key {
        "robinhood" => Ok(robinhood_sweep_cases()),
        "bsc" => Ok(bsc_sweep_cases()),
        key => bail!("no sweep cases for chain {key}"),
    }
}

fn robinhood_sweep_cases() -> Vec<Case> {
    let mut v = Vec::new();
    for (label, n) in [
        ("0.1", 1u64),
        ("1", 10),
        ("10", 100),
        ("100", 1000),
        ("500", 5000),
    ] {
        v.push(case(
            &format!("WETH→USDG {label}"),
            WETH,
            USDG,
            U256::from(n) * pow10(17),
        ));
    }
    for (label, n) in [
        ("100", 100u64),
        ("1k", 1_000),
        ("10k", 10_000),
        ("100k", 100_000),
        ("500k", 500_000),
    ] {
        v.push(case(
            &format!("USDG→WETH {label}"),
            USDG,
            WETH,
            U256::from(n) * pow10(6),
        ));
    }
    for (label, n) in [("0.1", 1u64), ("1", 10), ("10", 100), ("100", 1000)] {
        v.push(case(
            &format!("WETH→UP {label}"),
            WETH,
            UP,
            U256::from(n) * pow10(17),
        ));
    }
    for n in [1_000u64, 10_000, 200_000, 1_000_000] {
        v.push(case(
            &format!("UP→WETH {n}"),
            UP,
            WETH,
            U256::from(n) * pow10(18),
        ));
    }
    v.push(case("ETH→USDG 5", NATIVE, USDG, U256::from(5) * pow10(18)));
    v.push(case(
        "USDG→ETH 5k",
        USDG,
        NATIVE,
        U256::from(5_000) * pow10(6),
    ));
    for n in [10_000u64, 100_000] {
        v.push(case(
            &format!("UP→USDG {n}"),
            UP,
            USDG,
            U256::from(n) * pow10(18),
        ));
    }
    for n in [1_000u64, 10_000] {
        v.push(case(
            &format!("USDG→UP {n}"),
            USDG,
            UP,
            U256::from(n) * pow10(6),
        ));
    }
    // ~{0.1, 1, 5, 20, 50} WETH worth at ~28k CASHCAT/WETH
    for (label, n) in [
        ("0.1", 1u64),
        ("1", 10),
        ("5", 50),
        ("20", 200),
        ("50", 500),
    ] {
        v.push(case(
            &format!("WETH→CASHCAT {label}"),
            WETH,
            CASHCAT,
            U256::from(n) * pow10(17),
        ));
    }
    for n in [3u64, 30, 150, 600, 1_500] {
        v.push(case(
            &format!("CASHCAT→WETH {n}k"),
            CASHCAT,
            WETH,
            U256::from(n * 1_000) * pow10(18),
        ));
    }
    for (label, n) in [
        ("0.1", 1u64),
        ("1", 10),
        ("5", 50),
        ("20", 200),
        ("50", 500),
    ] {
        v.push(case(
            &format!("ETH→CASHCAT {label}"),
            NATIVE,
            CASHCAT,
            U256::from(n) * pow10(17),
        ));
    }
    for n in [3u64, 30, 150, 600, 1_500] {
        v.push(case(
            &format!("CASHCAT→ETH {n}k"),
            CASHCAT,
            NATIVE,
            U256::from(n * 1_000) * pow10(18),
        ));
    }
    // Approximately {0.1, 1, 5, 20, 50} WETH at the current USDG/WETH price.
    for n in [200u64, 2_000, 10_000, 40_000, 100_000] {
        v.push(case(
            &format!("USDG→CASHCAT {n}"),
            USDG,
            CASHCAT,
            U256::from(n) * pow10(6),
        ));
    }
    for n in [3u64, 30, 150, 600, 1_500] {
        v.push(case(
            &format!("CASHCAT→USDG {n}k"),
            CASHCAT,
            USDG,
            U256::from(n * 1_000) * pow10(18),
        ));
    }
    // These tokens have not passed the executable transfer-policy audit.
    // Keep comparing their display quotes, but never fork-execute them.
    v.extend([
        case("WETH→PONS 0.1", WETH, PONS, pow10(17)),
        case("PONS→WETH 12k", PONS, WETH, U256::from(12_000) * pow10(18)),
        case("WETH→TENDIES 0.1", WETH, TENDIES, pow10(17)),
        case(
            "TENDIES→WETH 10k",
            TENDIES,
            WETH,
            U256::from(10_000) * pow10(18),
        ),
        case("WETH→INDEX 0.1", WETH, INDEX, pow10(17)),
        case(
            "INDEX→WETH 12k",
            INDEX,
            WETH,
            U256::from(12_000) * pow10(18),
        ),
    ]);
    v
}

/// BSC quote-only matrix: size ladders over the same pairs the exec set
/// covers, plus the stable↔stable and connector-heavy shapes.
fn bsc_sweep_cases() -> Vec<Case> {
    let mut v = Vec::new();
    for (label, n) in [
        ("0.1", 1u64),
        ("1", 10),
        ("10", 100),
        ("100", 1_000),
        ("500", 5_000),
    ] {
        v.push(case(
            &format!("WBNB→USDT {label}"),
            WBNB,
            BSC_USDT,
            U256::from(n) * pow10(17),
        ));
    }
    for n in [100u64, 1_000, 10_000, 30_000, 100_000] {
        v.push(case(
            &format!("USDT→WBNB {n}"),
            BSC_USDT,
            WBNB,
            U256::from(n) * pow10(18),
        ));
    }
    for (label, n) in [("1", 1u64), ("10", 10), ("100", 100)] {
        v.push(case(
            &format!("WBNB→USDC {label}"),
            WBNB,
            BSC_USDC,
            U256::from(n) * pow10(18),
        ));
    }
    for n in [1_000u64, 10_000, 100_000] {
        v.push(case(
            &format!("USDC→WBNB {n}"),
            BSC_USDC,
            WBNB,
            U256::from(n) * pow10(18),
        ));
    }
    v.push(case("BNB→USDT 1", NATIVE, BSC_USDT, pow10(18)));
    v.push(case(
        "USDT→BNB 1k",
        BSC_USDT,
        NATIVE,
        U256::from(1_000) * pow10(18),
    ));
    for n in [1_000u64, 10_000, 100_000] {
        v.push(case(
            &format!("USDT→USDC {n}"),
            BSC_USDT,
            BSC_USDC,
            U256::from(n) * pow10(18),
        ));
        v.push(case(
            &format!("USDC→USDT {n}"),
            BSC_USDC,
            BSC_USDT,
            U256::from(n) * pow10(18),
        ));
    }
    for (label, n) in [("1", 1u64), ("10", 10), ("100", 100)] {
        v.push(case(
            &format!("WBNB→USD1 {label}"),
            WBNB,
            BSC_USD1,
            U256::from(n) * pow10(18),
        ));
    }
    for n in [100u64, 1_000, 10_000] {
        v.push(case(
            &format!("USD1→USDT {n}"),
            BSC_USD1,
            BSC_USDT,
            U256::from(n) * pow10(18),
        ));
    }
    for (label, n) in [("1", 1u64), ("10", 10), ("100", 100)] {
        v.push(case(
            &format!("WBNB→BTCB {label}"),
            WBNB,
            BSC_BTCB,
            U256::from(n) * pow10(18),
        ));
    }
    for (label, n) in [("0.1", 1u64), ("0.5", 5), ("1", 10)] {
        v.push(case(
            &format!("BTCB→WBNB {label}"),
            BSC_BTCB,
            WBNB,
            U256::from(n) * pow10(17),
        ));
    }
    for n in [3_000u64, 30_000] {
        v.push(case(
            &format!("USDT→BTCB {n}"),
            BSC_USDT,
            BSC_BTCB,
            U256::from(n) * pow10(18),
        ));
    }
    for n in [100u64, 1_000, 100_000] {
        v.push(case(
            &format!("XRP→WBNB {n}"),
            BSC_XRP,
            WBNB,
            U256::from(n) * pow10(18),
        ));
    }
    for (label, n) in [("10", 10u64), ("100", 100)] {
        v.push(case(
            &format!("WBNB→XRP {label}"),
            WBNB,
            BSC_XRP,
            U256::from(n) * pow10(18),
        ));
    }
    v
}

fn hop_protocol(h: &HopJson) -> &'static str {
    match h {
        HopJson::NativeRfq { protocol, .. }
        | HopJson::V3 { protocol, .. }
        | HopJson::V2 { protocol, .. }
        | HopJson::Ekubo { protocol, .. } => protocol,
    }
}

fn legs_of(q: &QuoteResponse) -> String {
    q.route
        .iter()
        .map(|l| {
            let protos: Vec<&str> = l.hops.iter().map(hop_protocol).collect();
            format!("{}×{}", l.share_bps, protos.join("→"))
        })
        .collect::<Vec<_>>()
        .join(" + ")
}

// ---- 0x ----

struct Zx {
    block: u64,
    routed_sell: U256,
    gross: U256,
    buy: U256,
    minbuy: U256,
    fee_label: String,
    sources: String,
    to: Address,
    data: Vec<u8>,
    value: U256,
    spender: Option<Address>,
}

/// One 0x allowance-holder quote. `gross` removes zeroExFee for capability
/// comparison; `buy` remains the expected user receipt for fork validation.
/// Ok(Err(reason)) = the API answered but has no usable quote; Err =
/// infrastructure failure.
async fn zx_quote(
    client: &reqwest::Client,
    key: &str,
    chain_id: u64,
    c: &Case,
) -> anyhow::Result<Result<Zx, String>> {
    let url = format!(
        "https://api.0x.org/swap/allowance-holder/quote?chainId={chain_id}&sellToken={}&buyToken={}&sellAmount={}&taker={}&slippageBps=100",
        addrhex(c.token_in),
        addrhex(c.token_out),
        c.amount,
        addrhex(TAKER)
    );
    let mut response = None;
    for attempt in 0..4 {
        let r = client
            .get(&url)
            .header("0x-api-key", key)
            .header("0x-version", "v2")
            .send()
            .await
            .context("0x api request")?;
        let status = r.status().as_u16();
        let body = r.text().await.context("0x api body")?;
        if status == 429 {
            if attempt == 3 {
                return Ok(Err("http 429 after 4 attempts".into()));
            }
            tokio::time::sleep(std::time::Duration::from_millis(1500 * (attempt + 1))).await;
            continue;
        }
        if status != 200 {
            let msg: String = body.chars().take(200).collect();
            return Ok(Err(format!("http {status}: {msg}")));
        }
        response = Some(serde_json::from_str(&body).context("0x api json")?);
        break;
    }
    let j: Value = response.context("0x request loop ended without a response")?;
    if !j["liquidityAvailable"]
        .as_bool()
        .context("0x liquidityAvailable boolean")?
    {
        return Ok(Err("no liquidity".into()));
    }
    let amount_at =
        |v: &Value| -> anyhow::Result<U256> { ubig(v.as_str().context("amount string")?) };
    let buy = amount_at(&j["buyAmount"])?;
    let (fee, fee_side) = match &j["fees"]["zeroExFee"] {
        Value::Null => (U256::ZERO, FeeSide::None),
        f => {
            let token = f["token"]
                .as_str()
                .context("0x zeroExFee.token string")?
                .to_lowercase();
            let side = if token == addrhex(c.token_in) {
                FeeSide::Sell
            } else if token == addrhex(c.token_out) {
                FeeSide::Buy
            } else {
                bail!("0x fee token is neither sell nor buy token: {token}")
            };
            let amount = amount_at(&f["amount"])?;
            (amount, side)
        }
    };
    let (routed_sell, gross) = fee_neutral_terms(buy, c.amount, fee, fee_side)?;
    let block = j["blockNumber"]
        .as_str()
        .context("0x blockNumber string")?
        .parse::<u64>()
        .context("0x blockNumber decimal")?;
    let fee_label = match fee_side {
        FeeSide::None => "none".to_string(),
        FeeSide::Sell => format!("sell:{fee}"),
        FeeSide::Buy => format!("buy:{fee}"),
    };
    let fills = j["route"]["fills"]
        .as_array()
        .context("0x route.fills array")?;
    let mut sources: Vec<String> = Vec::new();
    for fill in fills {
        let source = fill["source"]
            .as_str()
            .context("0x route fill source string")?
            .to_string();
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    anyhow::ensure!(!sources.is_empty(), "0x route has no fills");
    let transaction = j["transaction"]
        .as_object()
        .context("0x transaction object")?;
    let to = transaction
        .get("to")
        .and_then(Value::as_str)
        .context("0x transaction.to string")?
        .parse()
        .context("0x transaction.to address")?;
    let data = hexbytes(
        transaction
            .get("data")
            .and_then(Value::as_str)
            .context("0x transaction.data string")?,
    )
    .context("0x transaction.data hex")?;
    let value = amount_at(transaction.get("value").context("0x transaction.value")?)
        .context("0x transaction.value amount")?;
    let spender = if c.token_in == NATIVE {
        None
    } else {
        Some(
            j["issues"]["allowance"]["spender"]
                .as_str()
                .context("0x issues.allowance.spender string")?
                .parse()
                .context("0x allowance spender address")?,
        )
    };
    Ok(Ok(Zx {
        block,
        routed_sell,
        gross,
        buy,
        minbuy: amount_at(&j["minBuyAmount"])?,
        fee_label,
        sources: sources.join("+"),
        to,
        data,
        value,
        spender,
    }))
}

async fn ours_quote(
    cfg: &Config,
    engine: &Arc<Engine>,
    c: &Case,
    amount: U256,
    build_tx: bool,
) -> anyhow::Result<QuoteResponse> {
    let req = QuoteRequest {
        chain_id: cfg.profile.chain_id,
        token_in: addrhex(c.token_in),
        token_out: addrhex(c.token_out),
        amount_in: AmountIn::Str(amount.to_string()),
        slippage_bps: 100,
        recipient: build_tx.then(|| addrhex(TAKER)),
        sender: build_tx.then(|| addrhex(TAKER)),
        tx_origin: None,
        deadline_seconds: 600,
        fee_bps: None,
    };
    quote_swap(cfg, engine, req).await
}

// ---- fork execution ----

/// Anvil stamps locally mined blocks with WALL-CLOCK time, but cold-fork
/// execution runs many minutes after the quotes were issued — that would
/// unfairly expire the deadlines embedded in either side's calldata. Pin every
/// mined block to just after the forked block's chain timestamp instead.
struct Fork {
    rpc: Rpc,
    _anvil: ManagedAnvil,
    timestamp: u64,
}

struct Execution {
    success: bool,
    block: u64,
    raw_received: U256,
    actual_spent: U256,
    gas_used: U256,
    effective_gas_price: U256,
    wall_us: u128,
    revert: Option<String>,
}

impl Execution {
    fn gas_cost(&self) -> anyhow::Result<U256> {
        self.gas_used
            .checked_mul(self.effective_gas_price)
            .context("execution gas cost overflow")
    }
}

impl Fork {
    async fn start(fork_url: &str, block: u64) -> anyhow::Result<Fork> {
        let anvil = ManagedAnvil::spawn(fork_url, block, ANVIL_PORT)?;
        let rpc = Rpc::connect(&format!("http://127.0.0.1:{ANVIL_PORT}"))?;
        let mut fork = Fork {
            rpc,
            _anvil: anvil,
            timestamp: 0,
        };
        for _ in 0..600 {
            fork._anvil.ensure_running()?;
            if let Ok(head) = fork
                .rpc
                .request("eth_getBlockByNumber", json!(["latest", false]))
                .await
                && head["number"].as_str().and_then(|number| {
                    u64::from_str_radix(number.trim_start_matches("0x"), 16).ok()
                }) == Some(block)
                && let Some(ts) = head["timestamp"].as_str()
            {
                let ts = u64::from_str_radix(ts.trim_start_matches("0x"), 16)?;
                fork.timestamp = ts;
                return Ok(fork);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        fork.stop(); // a late-arriving anvil must not squat on the port
        bail!("anvil did not come up")
    }

    /// ManagedAnvil's Drop sends SIGINT and waits, including on every `?` path.
    fn stop(self) {
        drop(self);
    }

    async fn send_at(
        &self,
        from: Address,
        to: &str,
        value: U256,
        data: &[u8],
        timestamp: u64,
    ) -> anyhow::Result<Value> {
        self.rpc
            .request("evm_setNextBlockTimestamp", json!([timestamp]))
            .await?;
        let txhash = self
            .rpc
            .request(
                "eth_sendTransaction",
                json!([{ "from": addrhex(from), "to": to, "value": hexu(value), "data": tohex(data), "gas": GAS }]),
            )
            .await?;
        // cold fork state: anvil fetches remote slots during execution — be patient
        for _ in 0..1200 {
            let r = self
                .rpc
                .request("eth_getTransactionReceipt", json!([txhash]))
                .await?;
            if !r.is_null() {
                return Ok(r);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        bail!("no receipt after 10min")
    }

    async fn balance_of(&self, token: Address, owner: Address) -> anyhow::Result<U256> {
        let ret = self
            .rpc
            .eth_call(
                token,
                balanceOfCall { owner }.abi_encode(),
                BlockId::latest(),
            )
            .await?;
        read_word(&ret, 0)
    }

    async fn allowance(
        &self,
        token: Address,
        owner: Address,
        spender: Address,
    ) -> anyhow::Result<U256> {
        let ret = self
            .rpc
            .eth_call(
                token,
                allowanceCall { owner, spender }.abi_encode(),
                BlockId::latest(),
            )
            .await?;
        read_word(&ret, 0)
    }

    /// Fund by writing the balances-mapping slot directly. Failure is explicit:
    /// using a holder transfer would execute token behavior outside the quote.
    async fn fund(&self, token: Address, amount: U256) -> anyhow::Result<u64> {
        let token_hex = addrhex(token);
        for slot in 0u64..=64 {
            let mut preimage = [0u8; 64];
            preimage[12..32].copy_from_slice(TAKER.as_slice());
            preimage[32..64].copy_from_slice(&B256::from(U256::from(slot)).0);
            let key = format!("{:#x}", keccak256(preimage));
            let old = self
                .rpc
                .request("eth_getStorageAt", json!([token_hex, key, "latest"]))
                .await?;
            self.rpc
                .request(
                    "anvil_setStorageAt",
                    json!([token_hex, key, format!("0x{:064x}", amount)]),
                )
                .await?;
            if self.balance_of(token, TAKER).await? == amount {
                return Ok(slot);
            }
            self.rpc
                .request("anvil_setStorageAt", json!([token_hex, key, old]))
                .await?;
        }
        bail!("cannot fund {token_hex}: balances mapping slot not found in 0..=64")
    }

    /// Set one standard nested allowances mapping entry without mining a setup
    /// block. This keeps both executions exactly one block after their quote.
    async fn set_allowance(
        &self,
        token: Address,
        spender: Address,
        amount: U256,
    ) -> anyhow::Result<u64> {
        let token_hex = addrhex(token);
        for slot in 0u64..=64 {
            let mut owner_preimage = [0u8; 64];
            owner_preimage[12..32].copy_from_slice(TAKER.as_slice());
            owner_preimage[32..64].copy_from_slice(&B256::from(U256::from(slot)).0);
            let owner_slot = keccak256(owner_preimage);

            let mut spender_preimage = [0u8; 64];
            spender_preimage[12..32].copy_from_slice(spender.as_slice());
            spender_preimage[32..64].copy_from_slice(owner_slot.as_slice());
            let key = format!("{:#x}", keccak256(spender_preimage));
            let old = self
                .rpc
                .request("eth_getStorageAt", json!([token_hex, key, "latest"]))
                .await?;
            self.rpc
                .request(
                    "anvil_setStorageAt",
                    json!([token_hex, key, format!("0x{:064x}", amount)]),
                )
                .await?;
            if self.allowance(token, TAKER, spender).await? == amount {
                return Ok(slot);
            }
            self.rpc
                .request("anvil_setStorageAt", json!([token_hex, key, old]))
                .await?;
        }
        bail!(
            "cannot set allowance for {token_hex} spender {}: nested mapping slot not found in 0..=64",
            addrhex(spender)
        )
    }

    async fn eth_balance(&self, owner: Address) -> anyhow::Result<U256> {
        let v = self
            .rpc
            .request("eth_getBalance", json!([addrhex(owner), "latest"]))
            .await?;
        let s = v.as_str().context("eth_getBalance hex")?;
        U256::from_str_radix(s.trim_start_matches("0x"), 16).context("bad balance hex")
    }

    async fn asset_balance(&self, token: Address, owner: Address) -> anyhow::Result<U256> {
        if token == NATIVE {
            self.eth_balance(owner).await
        } else {
            self.balance_of(token, owner).await
        }
    }

    /// Execute inside an evm_snapshot/evm_revert bubble. Native balance deltas
    /// exclude gas, so `actual_spent` and `raw_received` stay comparable to
    /// ERC-20 deltas.
    async fn execute(
        &self,
        to: &str,
        value: U256,
        data: &[u8],
        sell_token: Address,
        buy_token: Address,
        timestamp: u64,
    ) -> anyhow::Result<Execution> {
        let wall = Instant::now();
        let snap = self.rpc.request("evm_snapshot", json!([])).await?;
        let result = async {
            let before_sell = self.asset_balance(sell_token, TAKER).await?;
            let before_buy = self.asset_balance(buy_token, TAKER).await?;
            let rc = self.send_at(TAKER, to, value, data, timestamp).await?;
            let success = match rc["status"].as_str().context("receipt status string")? {
                "0x1" => true,
                "0x0" => false,
                status => bail!("unexpected receipt status {status}"),
            };
            let gas_used = ubig_hex(&rc["gasUsed"]).context("receipt gasUsed")?;
            let effective_gas_price =
                ubig_hex(&rc["effectiveGasPrice"]).context("receipt effectiveGasPrice")?;
            let block = u64::try_from(ubig_hex(&rc["blockNumber"]).context("receipt blockNumber")?)
                .context("receipt blockNumber exceeds u64")?;
            let gas_cost = gas_used
                .checked_mul(effective_gas_price)
                .context("execution gas cost overflow")?;
            let after_sell = self.asset_balance(sell_token, TAKER).await?;
            let after_buy = self.asset_balance(buy_token, TAKER).await?;
            let raw_received = if buy_token == NATIVE {
                after_buy
                    .checked_add(gas_cost)
                    .context("native received gas adjustment overflow")?
                    .checked_sub(before_buy)
                    .context("native buy balance decreased after gas adjustment")?
            } else {
                after_buy
                    .checked_sub(before_buy)
                    .context("buy-token balance decreased")?
            };
            let actual_spent = if sell_token == NATIVE {
                before_sell
                    .checked_sub(after_sell)
                    .context("native sell balance increased")?
                    .checked_sub(gas_cost)
                    .context("native sell delta below gas cost")?
            } else {
                before_sell
                    .checked_sub(after_sell)
                    .context("sell-token balance increased")?
            };
            let revert = if success {
                None
            } else {
                Some(
                    match self
                        .rpc
                        .request(
                            "eth_call",
                            json!([{ "from": addrhex(TAKER), "to": to, "value": hexu(value), "data": tohex(data), "gas": GAS }, "latest"]),
                        )
                        .await
                    {
                        Ok(_) => "replay succeeded — nondeterministic?".to_string(),
                        Err(e) => {
                            let message = format!("{e:#}");
                            if message.contains("cd21db4f") {
                                "SignatureExpired".to_string()
                            } else {
                                message.chars().take(200).collect()
                            }
                        }
                    }
                )
            };
            Ok::<_, anyhow::Error>(Execution {
                success,
                block,
                raw_received,
                actual_spent,
                gas_used,
                effective_gas_price,
                wall_us: 0,
                revert,
            })
        };
        let result = result.await;
        let reverted = self.rpc.request("evm_revert", json!([snap])).await?;
        if reverted.as_bool() != Some(true) {
            bail!("evm_revert did not return true")
        }
        let mut execution = result?;
        execution.wall_us = wall.elapsed().as_micros();
        Ok(execution)
    }
}

// ---- modes ----

struct Row {
    label: String,
    ours_raw: String,
    zx_raw: String,
    actual_price_bps: String,
    routing_bps: String,
    ours_gas: String,
    zx_gas: String,
    sources: String,
}

struct ForkRun {
    setup_us: u128,
    timestamp: u64,
    ours: Execution,
    zx: (Execution, Option<U256>),
}

async fn sweep(
    cfg: &Config,
    engine: &Arc<Engine>,
    client: &reqwest::Client,
    key: &str,
    cases: &[Case],
) -> anyhow::Result<()> {
    println!(
        "{:<18} {:>26} {:>26} {:>9} {:>13} {:>7} {:>7} {:>7} {:>7} {:>7} {:>11}  route vs sources",
        "case",
        "ours (gross)",
        "0x (fee-neutral)",
        "quote bps",
        "ours total_us",
        "snap ms",
        "solve",
        "encode",
        "rpc",
        "source",
        "0x total_us"
    );
    let mut edges: Vec<f64> = Vec::new();
    let (mut wins, mut losses, mut ties) = (0, 0, 0);
    for c in cases {
        let t1 = Instant::now();
        let zx = zx_quote(client, key, cfg.profile.chain_id, c).await?;
        let zx_us = t1.elapsed().as_micros();
        let routed_sell = match &zx {
            Ok(z) => z.routed_sell,
            Err(_) => c.amount,
        };
        let t0 = Instant::now();
        let q = ours_quote(cfg, engine, c, routed_sell, false).await;
        let ours_us = t0.elapsed().as_micros();
        match (&q, &zx) {
            (Ok(q), Ok(z)) => {
                let ours: U256 = q.amount_out_gross.parse()?;
                let e = bps(ours, z.gross)?;
                edges.push(e);
                if e > 1.0 {
                    wins += 1;
                } else if e < -1.0 {
                    losses += 1;
                } else {
                    ties += 1;
                }
                println!(
                    "{:<18} {:>26} {:>26} {:>9.2} {:>13} {:>7} {:>7} {:>7} {:>7} {:>7} {:>11}  [{}] vs [{}] fee={} routed_sell={}",
                    c.label,
                    ours,
                    z.gross,
                    e,
                    ours_us,
                    q.meta.snapshot_ms,
                    q.meta.solve_ms,
                    q.meta.encode_ms,
                    q.meta.snapshot_rpc_calls,
                    q.meta.source,
                    zx_us,
                    legs_of(q),
                    z.sources,
                    z.fee_label,
                    z.routed_sell
                );
            }
            (Ok(q), Err(msg)) => {
                println!(
                    "{:<18} {:>26} {:>26} {:>9} {:>13} {:>7} {:>7} {:>7} {:>7} {:>7} {:>11}  [{}] vs 0x: {}",
                    c.label,
                    q.amount_out_gross,
                    "-",
                    "-",
                    ours_us,
                    q.meta.snapshot_ms,
                    q.meta.solve_ms,
                    q.meta.encode_ms,
                    q.meta.snapshot_rpc_calls,
                    q.meta.source,
                    zx_us,
                    legs_of(q),
                    msg
                );
            }
            (Err(e), _) => {
                let zs = match &zx {
                    Ok(z) => z.gross.to_string(),
                    Err(m) => format!("0x: {m}"),
                };
                println!(
                    "{:<18} OURS FAILED after {ours_us}us: {} (0x after {zx_us}us: {zs})",
                    c.label,
                    redacted_error(e, &cfg.rpc_url)
                );
            }
        }
        // polite pacing for the 0x api
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    }
    if !edges.is_empty() {
        edges.sort_by(f64::total_cmp);
        let median = edges[edges.len() / 2];
        println!(
            "\nquote-only screening (not ranking): {wins} positive / {ties} flat(±1bps) / {losses} negative of {}   median {median:+.2}bps   worst {:+.2}bps   best {:+.2}bps",
            edges.len(),
            edges.first().unwrap(),
            edges.last().unwrap()
        );
    }
    Ok(())
}

async fn exec(
    cfg: &Config,
    client: &reqwest::Client,
    key: &str,
    cases: &[Case],
    indexer: &Option<Arc<IndexerClient>>,
) -> anyhow::Result<()> {
    let mut rows: Vec<Row> = Vec::new();
    for c in cases {
        println!("\n=== {} ===", c.label);
        match exec_case(cfg, client, key, c, indexer).await {
            Ok(row) => rows.push(row),
            Err(e) => {
                println!("CASE FAILED: {}", redacted_error(&e, &cfg.rpc_url));
                rows.push(Row {
                    label: c.label.clone(),
                    ours_raw: "FAILED".into(),
                    zx_raw: "n/a".into(),
                    actual_price_bps: String::new(),
                    routing_bps: String::new(),
                    ours_gas: "-".into(),
                    zx_gas: "-".into(),
                    sources: String::new(),
                });
            }
        }
    }
    println!("\n{}", "=".repeat(100));
    println!(
        "{:<18} {:<24} {:<24} {:>10} {:>12} {:>12} {:>12}  0x sources",
        "case", "ours raw", "0x raw", "price bps", "routing bps", "ours gas", "0x gas"
    );
    for r in rows {
        println!(
            "{:<18} {:<24} {:<24} {:>10} {:>12} {:>12} {:>12}  {}",
            r.label,
            r.ours_raw,
            r.zx_raw,
            r.actual_price_bps,
            r.routing_bps,
            r.ours_gas,
            r.zx_gas,
            r.sources
        );
    }
    Ok(())
}

async fn exec_case(
    cfg: &Config,
    client: &reqwest::Client,
    key: &str,
    c: &Case,
    indexer: &Option<Arc<IndexerClient>>,
) -> anyhow::Result<Row> {
    let zx_started = Instant::now();
    let zx = zx_quote(client, key, cfg.profile.chain_id, c)
        .await?
        .map_err(|reason| anyhow::anyhow!("0x quote unavailable: {reason}"))?;
    let zx_quote_us = zx_started.elapsed().as_micros();

    let pinned_engine = Engine::for_profile_pinned(
        Rpc::connect(&cfg.rpc_url)?,
        cfg.profile,
        indexer.clone(),
        zx.block,
    );
    let ours_started = Instant::now();
    let q = ours_quote(cfg, &pinned_engine, c, zx.routed_sell, true).await?;
    let ours_quote_us = ours_started.elapsed().as_micros();
    anyhow::ensure!(
        q.block == zx.block,
        "solver quote block {} differs from 0x block {}",
        q.block,
        zx.block
    );
    let ours: U256 = q.amount_out_gross.parse()?;
    let tx = q.tx.as_ref().context("quote built no tx")?;
    println!(
        "quote ours: fee-neutral={ours} min_out={} routed_sell={} block={} route={}",
        q.min_amount_out_net,
        zx.routed_sell,
        q.block,
        legs_of(&q)
    );
    println!(
        "quote perf: ours_quote_wall_us={ours_quote_us} snapshot_ms={} solve_ms={} encode_ms={} source={} snapshot_rpc_calls={} zeroex_quote_wall_us={zx_quote_us}",
        q.meta.snapshot_ms,
        q.meta.solve_ms,
        q.meta.encode_ms,
        q.meta.source,
        q.meta.snapshot_rpc_calls
    );
    let print_calldata = std::env::var("COMPARE0X_PRINT_CALLDATA").as_deref() == Ok("1");
    if print_calldata {
        println!(
            "calldata ours: to={} value={} data={}",
            tx.to, tx.value, tx.data
        );
        println!(
            "calldata 0x: to={} value={} data={}",
            zx.to,
            zx.value,
            tohex(&zx.data)
        );
    }
    println!(
        "quote 0x: fee-neutral={} raw_buy={} min_out={} fee={} block={} sources={}",
        zx.gross, zx.buy, zx.minbuy, zx.fee_label, zx.block, zx.sources
    );
    println!("quote gap: ours-vs-0x={:+.2}bps", bps(ours, zx.gross)?);

    let fork_started = Instant::now();
    let fork = Fork::start(&cfg.rpc_url, zx.block).await?;
    let fork_start_us = fork_started.elapsed().as_micros();
    let allowance_holder = cfg
        .profile
        .settler
        .context("profile has no execution adapter")?
        .allowance_holder;
    let result = exec_on_fork(&fork, c, &q, &zx, allowance_holder).await;
    fork.stop();
    let run = result?;
    println!(
        "fork perf: start_us={fork_start_us} setup_us={} execution_block={} execution_timestamp={}",
        run.setup_us, run.ours.block, run.timestamp
    );

    let ours_ok = run.ours.success && run.ours.raw_received == ours;
    println!(
        "ours execution: success={} quote_exact={} block={} raw_received={} actual_spent={} wall_us={} gas_used={} effective_gas_price={} gas_cost={} revert={}",
        run.ours.success,
        ours_ok,
        run.ours.block,
        run.ours.raw_received,
        run.ours.actual_spent,
        run.ours.wall_us,
        run.ours.gas_used,
        run.ours.effective_gas_price,
        run.ours.gas_cost()?,
        run.ours.revert.as_deref().unwrap_or("-")
    );
    if run.ours.success {
        anyhow::ensure!(ours_ok, "solver execution differs from its pinned quote");
        anyhow::ensure!(
            run.ours.actual_spent == zx.routed_sell,
            "solver spent {} instead of routed sell {}",
            run.ours.actual_spent,
            zx.routed_sell
        );
    }

    let (zx_execution, fee_neutral) = &run.zx;
    let zx_min_out_ok = zx_execution.success && zx_execution.raw_received >= zx.minbuy;
    println!(
        "0x execution: success={} min_out_ok={} block={} raw_received={} actual_spent={} fee_neutral={} wall_us={} gas_used={} effective_gas_price={} gas_cost={} revert={}",
        zx_execution.success,
        zx_min_out_ok,
        zx_execution.block,
        zx_execution.raw_received,
        zx_execution.actual_spent,
        fee_neutral.map_or_else(|| "n/a".to_string(), |amount| amount.to_string()),
        zx_execution.wall_us,
        zx_execution.gas_used,
        zx_execution.effective_gas_price,
        zx_execution.gas_cost()?,
        zx_execution.revert.as_deref().unwrap_or("-")
    );
    if zx_execution.success {
        anyhow::ensure!(
            zx_min_out_ok,
            "0x execution returned less than minBuyAmount"
        );
        anyhow::ensure!(
            zx_execution.actual_spent == c.amount,
            "0x spent {} instead of requested sell {}",
            zx_execution.actual_spent,
            c.amount
        );
    }

    let mut actual_price_edge = String::new();
    let mut routing_edge = String::new();
    if run.ours.success && zx_execution.success {
        let price = execution_price_bps(&run.ours, zx_execution)?;
        actual_price_edge = format!("{price:+.2}");
        if let Some(fee_neutral) = fee_neutral {
            let routing = bps(run.ours.raw_received, *fee_neutral)?;
            routing_edge = format!("{routing:+.2}");
            println!(
                "execution gap: actual_price_bps={price:+.2} routing_bps={routing:+.2} 0x_fee_neutral={fee_neutral}"
            );
        }
    }
    if actual_price_edge.is_empty() {
        println!("execution gap: n/a");
    }
    Ok(Row {
        label: c.label.clone(),
        ours_raw: if run.ours.success {
            run.ours.raw_received.to_string()
        } else {
            "REVERTED".into()
        },
        zx_raw: if zx_execution.success {
            zx_execution.raw_received.to_string()
        } else {
            "REVERTED".into()
        },
        actual_price_bps: actual_price_edge,
        routing_bps: routing_edge,
        ours_gas: run.ours.gas_used.to_string(),
        zx_gas: zx_execution.gas_used.to_string(),
        sources: zx.sources,
    })
}

async fn exec_on_fork(
    fork: &Fork,
    c: &Case,
    q: &QuoteResponse,
    zx: &Zx,
    allowance_holder: Address,
) -> anyhow::Result<ForkRun> {
    let setup_started = Instant::now();
    fork.rpc
        .request(
            "anvil_setBalance",
            json!([addrhex(TAKER), hexu(U256::from(10_000) * pow10(18))]),
        )
        .await?;
    if c.token_in != NATIVE {
        let balance_slot = fork.fund(c.token_in, U256::from(2) * c.amount).await?;
        let solver_allowance_slot = fork
            .set_allowance(c.token_in, allowance_holder, U256::MAX)
            .await?;
        let mut zeroex_allowance_slot = solver_allowance_slot;
        if let Some(spender) = zx.spender
            && spender != allowance_holder
        {
            zeroex_allowance_slot = fork.set_allowance(c.token_in, spender, U256::MAX).await?;
        }
        println!(
            "funded via balance_slot={balance_slot} solver_allowance_slot={solver_allowance_slot} zeroex_allowance_slot={zeroex_allowance_slot}"
        );
    }
    let setup_us = setup_started.elapsed().as_micros();
    let timestamp = fork.timestamp + 1;

    let zx_execution = fork
        .execute(
            &addrhex(zx.to),
            zx.value,
            &zx.data,
            c.token_in,
            c.token_out,
            timestamp,
        )
        .await?;
    let fee_neutral = zx_execution
        .success
        .then(|| fee_neutral_execution(zx_execution.raw_received, zx.buy, zx.gross))
        .transpose()?;
    let tx = q.tx.as_ref().context("quote built no tx")?;
    let ours = fork
        .execute(
            &tx.to,
            tx.value.parse()?,
            &hexbytes(&tx.data)?,
            c.token_in,
            c.token_out,
            timestamp,
        )
        .await?;
    anyhow::ensure!(
        ours.block == zx_execution.block,
        "execution blocks differ: solver={} 0x={}",
        ours.block,
        zx_execution.block
    );
    let expected_block = zx.block.checked_add(1).context("0x blockNumber overflow")?;
    anyhow::ensure!(
        ours.block == expected_block,
        "execution block {} is not quote block {} + 1",
        ours.block,
        zx.block
    );
    Ok(ForkRun {
        setup_us,
        timestamp,
        ours,
        zx: (zx_execution, fee_neutral),
    })
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let message = std::env::var("SOLVER_RPC")
            .ok()
            .filter(|rpc_url| !rpc_url.is_empty())
            .map_or_else(
                || format!("{error:#}"),
                |rpc_url| redacted_error(&error, &rpc_url),
            );
        eprintln!("{message}");
        std::process::exit(1);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Cli {
    sweep: bool,
    chain: Option<String>,
    exact_cases: Vec<String>,
    substring_filters: Vec<String>,
}

fn parse_cli(args: &[String]) -> anyhow::Result<Cli> {
    let sweep = args.first().is_some_and(|arg| arg == "sweep");
    let mut chain = None;
    let mut exact_cases = Vec::new();
    let mut substring_filters = Vec::new();
    let mut index = usize::from(sweep);
    while index < args.len() {
        if args[index] == "--case" {
            let label = args
                .get(index + 1)
                .context("--case requires an exact label")?;
            if label.is_empty() {
                bail!("--case requires a non-empty exact label")
            }
            exact_cases.push(label.clone());
            index += 2;
        } else if args[index] == "--chain" {
            let key = args
                .get(index + 1)
                .context("--chain requires a chain key")?;
            if key.is_empty() {
                bail!("--chain requires a non-empty chain key")
            }
            if chain.replace(key.clone()).is_some() {
                bail!("--chain given more than once")
            }
            index += 2;
        } else {
            substring_filters.push(args[index].clone());
            index += 1;
        }
    }
    Ok(Cli {
        sweep,
        chain,
        exact_cases,
        substring_filters,
    })
}

fn filter_cases(mut cases: Vec<Case>, cli: &Cli) -> anyhow::Result<Vec<Case>> {
    for label in &cli.exact_cases {
        if !cases.iter().any(|case| case.label == *label) {
            bail!("unknown case label: {label}")
        }
    }
    if !cli.exact_cases.is_empty() || !cli.substring_filters.is_empty() {
        cases.retain(|case| {
            cli.exact_cases.contains(&case.label)
                || cli
                    .substring_filters
                    .iter()
                    .any(|filter| case.label.contains(filter))
        });
    }
    Ok(cases)
}

async fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = parse_cli(&args)?;

    let chain_key = cli
        .chain
        .clone()
        .or_else(|| std::env::var("SOLVER_CHAIN").ok())
        .filter(|key| !key.trim().is_empty())
        .unwrap_or_else(|| "robinhood".to_string());
    let profile = profile_by_key(&chain_key)?;
    anyhow::ensure!(
        profile.execution_enabled(),
        "chain {chain_key} has no execution adapter"
    );

    let rpc_url = std::env::var("SOLVER_RPC").context("SOLVER_RPC must point at the real chain")?;
    let cfg = Config {
        profile,
        rpc_url: rpc_url.clone(),
        logs_rpc_url: rpc_url.clone(),
        indexer_url: std::env::var("SOLVER_INDEXER_URL").ok(),
        native_rfq: None,
        fee_bps: 0,
        fee_receiver: None,
        positive_slippage_max_bps: 0,
        positive_slippage_recipient: None,
        port: 0,
        quote_timeout: 300,
    };
    // Indexer-backed profiles (BSC) must quote against the same discovery
    // client production uses, or the comparison measures a different universe.
    // A profile whose factories name its pools takes none.
    let indexer = sextant::server::configured_indexer(&cfg)?;
    let key = std::env::var("ZEROEX_API_KEY").context("ZEROEX_API_KEY must be set")?;
    if key.is_empty() {
        bail!("ZEROEX_API_KEY must be non-empty")
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let cases = if cli.sweep {
        sweep_cases(cfg.profile)?
    } else {
        exec_cases(cfg.profile)?
    };
    let cases = filter_cases(cases, &cli)?;
    if cli.sweep {
        let engine =
            Engine::for_profile_with_indexer(Rpc::connect(&rpc_url)?, cfg.profile, indexer);
        sweep(&cfg, &engine, &client, &key, &cases).await
    } else {
        exec(&cfg, &client, &key, &cases, &indexer).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_rpc_url_from_recorded_errors() {
        let rpc_url = "https://secret.example/rpc-key";
        let error = anyhow::anyhow!("failed to connect to {rpc_url}");

        assert_eq!(
            redacted_error(&error, rpc_url),
            "failed to connect to <RPC>"
        );
    }

    #[test]
    fn aligns_routed_input_and_output_for_fee_neutral_comparison() {
        let buy = U256::from(9_985);
        let sell = U256::from(10_000);
        let fee = U256::from(15);

        assert_eq!(
            fee_neutral_terms(buy, sell, fee, FeeSide::Buy).unwrap(),
            (sell, U256::from(10_000))
        );
        assert_eq!(
            fee_neutral_terms(buy, sell, fee, FeeSide::Sell).unwrap(),
            (U256::from(9_985), buy)
        );
        assert_eq!(
            fee_neutral_terms(buy, sell, U256::ZERO, FeeSide::None).unwrap(),
            (sell, buy)
        );
        assert_eq!(
            fee_neutral_execution(U256::from(19_970), buy, U256::from(10_000)).unwrap(),
            U256::from(20_000)
        );
        assert_eq!(
            fee_neutral_execution(U256::from(9_970), buy, buy).unwrap(),
            U256::from(9_970)
        );
    }

    #[test]
    fn supports_repeated_exact_cases_and_legacy_substring_filters() {
        let args = vec![
            "sweep".to_string(),
            "--case".to_string(),
            "WETH→USDG 1".to_string(),
            "--case".to_string(),
            "WETH→UP 10".to_string(),
            "CASHCAT→WETH".to_string(),
        ];
        let cli = parse_cli(&args).unwrap();
        assert_eq!(
            cli,
            Cli {
                sweep: true,
                chain: None,
                exact_cases: vec!["WETH→USDG 1".into(), "WETH→UP 10".into()],
                substring_filters: vec!["CASHCAT→WETH".into()],
            }
        );
        let labels: Vec<String> = filter_cases(
            sweep_cases(profile_by_key("robinhood").unwrap()).unwrap(),
            &cli,
        )
        .unwrap()
        .into_iter()
        .map(|case| case.label)
        .collect();
        assert!(labels.contains(&"WETH→USDG 1".to_string()));
        assert!(labels.contains(&"WETH→UP 10".to_string()));
        assert!(labels.iter().any(|label| label == "CASHCAT→WETH 3k"));
        assert!(!labels.contains(&"WETH→USDG 10".to_string()));
    }

    #[test]
    fn parses_chain_flag() {
        let cli = parse_cli(&["--chain".to_string(), "bsc".to_string()]).unwrap();
        assert_eq!(
            cli,
            Cli {
                sweep: false,
                chain: Some("bsc".into()),
                exact_cases: vec![],
                substring_filters: vec![],
            }
        );

        let missing = parse_cli(&["--chain".to_string()]).unwrap_err();
        assert!(missing.to_string().contains("requires a chain key"));

        let repeated = parse_cli(&[
            "--chain".to_string(),
            "bsc".to_string(),
            "--chain".to_string(),
            "robinhood".to_string(),
        ])
        .unwrap_err();
        assert!(repeated.to_string().contains("more than once"));

        let labels: Vec<String> = exec_cases(profile_by_key("bsc").unwrap())
            .unwrap()
            .into_iter()
            .map(|case| case.label)
            .collect();
        assert!(labels.contains(&"WBNB→USDT 1".to_string()));
        assert!(labels.contains(&"BNB→USDT 1".to_string()));
    }

    #[test]
    fn exact_case_requires_a_known_full_label() {
        let missing_value = parse_cli(&["--case".to_string()]).unwrap_err();
        assert!(
            missing_value
                .to_string()
                .contains("requires an exact label")
        );

        let cli = parse_cli(&["--case".to_string(), "WETH→USDG".to_string()]).unwrap();
        let unknown = match filter_cases(
            exec_cases(profile_by_key("robinhood").unwrap()).unwrap(),
            &cli,
        ) {
            Ok(_) => panic!("partial label unexpectedly accepted as exact"),
            Err(error) => error,
        };
        assert_eq!(unknown.to_string(), "unknown case label: WETH→USDG");
    }

    #[test]
    fn actual_price_comparison_uses_each_execution_input() {
        let execution = |received, spent| Execution {
            success: true,
            block: 1,
            raw_received: U256::from(received),
            actual_spent: U256::from(spent),
            gas_used: U256::ZERO,
            effective_gas_price: U256::ZERO,
            wall_us: 0,
            revert: None,
        };
        let ours = execution(100, 10);
        let zeroex = execution(108, 12);
        let edge = execution_price_bps(&ours, &zeroex).unwrap();
        assert!((edge - 1_111.111_111).abs() < 1e-6);
    }
}
