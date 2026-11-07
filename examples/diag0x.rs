// Decode a 0x quote's Settler actions, match every fill against our pool
// universe, and replay their exact allocation through our simulator.
//
// This is the decisive experiment for any quote gap. Every fill lands in one
// of three buckets and each bucket names the fix:
//   - fill matches NO pool of ours              → universe gap (grow discovery)
//   - replay ≈ their gross, all pools known     → allocator gap (their plan is
//     inside our search space and scores higher than what our optimizer chose)
//   - replay ≪ their gross, all pools known     → simulator gap on some venue
//
//   cargo run --release --example diag0x -- WETH USDG 500
//   cargo run --release --example diag0x -- USDG WETH 100000
// Env: SOLVER_RPC, ZEROEX_API_KEY, and SOLVER_CHAIN when it is not robinhood.

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use anyhow::{Context, bail, ensure};
use serde_json::Value;
use sextant::abi::{self, addrhex, hexbytes};
use sextant::chain::{ALLOWANCE_HOLDER, CHAIN_ID, NATIVE, ROBINHOOD_PROFILE, UP, USDG, WETH};
use sextant::ekubo::{EkuboState, commit_ekubo, sim_ekubo};
use sextant::pools::{V2State, V3State, commit_v2, commit_v3, sim_v2, sim_v3};
use sextant::route::{ALLOC_CHUNKS, MIN_SHARE_BPS, Plan, PreparedRoutes, quantized_plan};
use sextant::rpc::Rpc;
use sextant::settler::BPS_BASE;
use sextant::state::{Snapshot, snapshot_at_for};
use sextant::v3math::muldiv;
use std::collections::BTreeMap;

const TAKER: Address = Address::new([0x11; 20]);

fn share(x: U256, bps: u32) -> anyhow::Result<U256> {
    muldiv(x, U256::from(bps), U256::from(BPS_BASE))
}

fn sym(t: Address) -> String {
    match t {
        t if t == WETH => "WETH".into(),
        t if t == USDG => "USDG".into(),
        t if t == UP => "UP".into(),
        t if t == NATIVE => "ETH".into(),
        t => addrhex(t)[..10].to_string(),
    }
}

// ---- decoded 0x wire formats ----

#[derive(Debug)]
struct PathHop {
    fork: u8,
    pool_id: u32,
    tin: Address,
    tout: Address,
}

/// Settler fork path: token | uint8 forkId | uint24 poolId | uint160 sqrtLimit | token | …
fn parse_v3_path(p: &[u8]) -> anyhow::Result<Vec<PathHop>> {
    ensure!(
        p.len() >= 64 && (p.len() - 20).is_multiple_of(44),
        "bad v3 path length {}",
        p.len()
    );
    let mut tin = Address::from_slice(&p[..20]);
    let mut hops = Vec::new();
    let mut i = 20;
    while i < p.len() {
        let fork = p[i];
        let pool_id = u32::from_be_bytes([0, p[i + 1], p[i + 2], p[i + 3]]);
        let tout = Address::from_slice(&p[i + 24..i + 44]);
        hops.push(PathHop {
            fork,
            pool_id,
            tin,
            tout,
        });
        tin = tout;
        i += 44;
    }
    Ok(hops)
}

#[derive(Debug)]
struct V4Fill {
    bps: u32,
    sell: Address,
    buy: Address,
    fee: u32,
    spacing: i32,
    hooks: Address,
    hookdata: usize,
}

fn take<'a>(d: &'a [u8], i: &mut usize, n: usize) -> anyhow::Result<&'a [u8]> {
    let s = d.get(*i..*i + n).context("v4 fills truncated")?;
    *i += n;
    Ok(s)
}

/// V4 fills stream: bps 2B | sqrtLimit 20B | packing key 1B | 0..2 tokens 20B |
/// fee 3B | tickSpacing 3B | hooks 20B | hookData len 3B | hookData.
/// Packing: 0 = both repeat, 1 = buy encoded, 2 = sell:=prev buy + buy encoded,
/// 3 = both encoded. First fill must be key 1 (sell = the action's sellToken).
fn parse_v4_fills(d: &[u8], action_sell: Address) -> anyhow::Result<Vec<V4Fill>> {
    let (mut sell, mut buy) = (action_sell, Address::ZERO);
    let mut fills = Vec::new();
    let mut i = 0usize;
    while i < d.len() {
        let bps = u32::from(u16::from_be_bytes(
            take(d, &mut i, 2)?.try_into().expect("2B"),
        ));
        take(d, &mut i, 20)?; // sqrtPriceLimit — replay swaps to completion
        let key = take(d, &mut i, 1)?[0];
        match key {
            0 => {}
            1 => buy = Address::from_slice(take(d, &mut i, 20)?),
            2 => {
                sell = buy;
                buy = Address::from_slice(take(d, &mut i, 20)?);
            }
            3 => {
                sell = Address::from_slice(take(d, &mut i, 20)?);
                buy = Address::from_slice(take(d, &mut i, 20)?);
            }
            k => bail!("bad v4 packing key {k}"),
        }
        let fee = u32::from_be_bytes([0, d[i], d[i + 1], d[i + 2]]);
        i += 3;
        let spacing = i32::from_be_bytes([0, d[i], d[i + 1], d[i + 2]]);
        i += 3;
        let hooks = Address::from_slice(take(d, &mut i, 20)?);
        let hookdata = usize::from_be_bytes({
            let mut b = [0u8; 8];
            b[5..8].copy_from_slice(take(d, &mut i, 3)?);
            b
        });
        take(d, &mut i, hookdata)?;
        fills.push(V4Fill {
            bps,
            sell,
            buy,
            fee,
            spacing,
            hooks,
            hookdata,
        });
    }
    Ok(fills)
}

// ---- pool matching against our universe ----

fn find_v3(snap: &Snapshot, fork: u8, pool_id: u32, a: Address, b: Address) -> Option<usize> {
    snap.v3.iter().position(|(p, _)| {
        p.v4.is_none()
            && p.execution
                .is_some_and(|execution| execution.fork_id == fork && execution.pool_id == pool_id)
            && ((p.token0 == a && p.token1 == b) || (p.token0 == b && p.token1 == a))
    })
}

fn find_v4(snap: &Snapshot, f: &V4Fill) -> Option<usize> {
    if f.hooks != Address::ZERO {
        return None; // we only model hookless pools
    }
    let native = f.sell == NATIVE || f.buy == NATIVE;
    let (a, b) = (
        ROBINHOOD_PROFILE.erc20_of(f.sell),
        ROBINHOOD_PROFILE.erc20_of(f.buy),
    );
    snap.v3.iter().position(|(p, _)| match &p.v4 {
        Some(m) => {
            m.native == native
                && p.fee_ppm == f.fee
                && p.tick_spacing == f.spacing
                && ((p.token0 == a && p.token1 == b) || (p.token0 == b && p.token1 == a))
        }
        None => false,
    })
}

fn find_v2(snap: &Snapshot, pool: Address) -> Option<usize> {
    snap.v2.iter().position(|(p, _)| p.address == pool)
}

fn pool_label(snap: &Snapshot, kind: char, idx: usize) -> String {
    if kind == '2' {
        let p = &snap.v2[idx].0;
        return format!(
            "{} {} {}",
            p.protocol.as_str(),
            p.fee_bps,
            &addrhex(p.address)[..10]
        );
    }
    if kind == 'e' {
        let p = &snap.ekubo[idx].0;
        return format!("ekubov3 {}", &format!("{:#x}", p.pool_id)[..10]);
    }
    let p = &snap.v3[idx].0;
    match &p.v4 {
        Some(m) => format!(
            "univ4 {}/{}{} {}",
            p.fee_ppm,
            p.tick_spacing,
            if m.native { " native" } else { "" },
            &format!("{:#x}", m.pool_id)[..10]
        ),
        None => format!(
            "{} {}/{} {}",
            p.protocol.as_str(),
            p.fee_ppm,
            p.tick_spacing,
            &addrhex(p.address)[..10]
        ),
    }
}

// ---- replay ledger ----

struct Ledger<'a> {
    snap: &'a Snapshot,
    v3s: Vec<V3State>,
    v2s: Vec<V2State>,
    ekubos: Vec<EkuboState>,
    /// settler-visible balances (ETH under the 0xeeee… sentinel)
    bal: BTreeMap<Address, U256>,
    /// per-pool input totals
    used: BTreeMap<String, U256>,
    unsim: Vec<String>,
}

impl<'a> Ledger<'a> {
    fn new(snap: &'a Snapshot) -> Self {
        Ledger {
            snap,
            v3s: snap.v3.iter().map(|(_, s)| s.clone()).collect(),
            v2s: snap.v2.iter().map(|(_, s)| s.clone()).collect(),
            ekubos: snap.ekubo.iter().map(|(_, s)| *s).collect(),
            bal: BTreeMap::new(),
            used: BTreeMap::new(),
            unsim: Vec::new(),
        }
    }

    fn credit(&mut self, t: Address, x: U256) {
        *self.bal.entry(t).or_default() += x;
    }

    fn debit(&mut self, t: Address, x: U256) -> anyhow::Result<()> {
        let b = self.bal.entry(t).or_default();
        ensure!(*b >= x, "ledger underflow: {} has {b}, need {x}", sym(t));
        *b -= x;
        Ok(())
    }

    fn swap_v3(&mut self, idx: usize, tin: Address, amt: U256) -> anyhow::Result<U256> {
        let pool = &self.snap.v3[idx].0;
        let zf1 = ROBINHOOD_PROFILE.erc20_of(tin) == pool.token0;
        let r = sim_v3(pool, &self.v3s[idx], zf1, amt)?;
        ensure!(
            r.consumed == amt,
            "{} cannot absorb {amt}",
            pool_label(self.snap, '3', idx)
        );
        commit_v3(&mut self.v3s[idx], &r);
        *self
            .used
            .entry(pool_label(self.snap, '3', idx))
            .or_default() += amt;
        Ok(r.amount_out)
    }

    fn swap_v2(&mut self, idx: usize, tin: Address, amt: U256) -> anyhow::Result<U256> {
        let pool = &self.snap.v2[idx].0;
        let zf1 = ROBINHOOD_PROFILE.erc20_of(tin) == pool.token0;
        let r = sim_v2(pool, &self.v2s[idx], zf1, amt)?;
        commit_v2(&mut self.v2s[idx], &r);
        *self
            .used
            .entry(pool_label(self.snap, '2', idx))
            .or_default() += amt;
        Ok(r.amount_out)
    }

    fn swap_ekubo(&mut self, idx: usize, tin: Address, amt: U256) -> anyhow::Result<U256> {
        let pool = &self.snap.ekubo[idx].0;
        let r = sim_ekubo(
            pool,
            &self.ekubos[idx],
            ROBINHOOD_PROFILE.erc20_of(tin) == pool.token0,
            amt,
        )?;
        ensure!(
            r.consumed == amt,
            "{} cannot absorb {amt}",
            pool_label(self.snap, 'e', idx)
        );
        commit_ekubo(&mut self.ekubos[idx], &r);
        *self
            .used
            .entry(pool_label(self.snap, 'e', idx))
            .or_default() += amt;
        Ok(r.amount_out)
    }
}

// ---- decode + replay one 0x transaction ----

fn replay_zx<'a>(snap: &'a Snapshot, to: Address, data: &[u8]) -> anyhow::Result<Ledger<'a>> {
    let exec_data = if to == ALLOWANCE_HOLDER {
        abi::execCall::abi_decode(data)
            .context("AllowanceHolder exec")?
            .data
            .to_vec()
    } else {
        data.to_vec()
    };
    let call = abi::executeCall::abi_decode(&exec_data).context("settler execute")?;
    println!(
        "0x actions ({}), slippage: buyToken={} minOut={}",
        call.actions.len(),
        sym(call.slippage.buyToken),
        call.slippage.minAmountOut
    );

    let mut led = Ledger::new(snap);
    for (ai, action) in call.actions.iter().enumerate() {
        ensure!(action.len() >= 4, "action {ai} too short");
        let sel: [u8; 4] = action[..4].try_into().expect("4B");
        let args = &action[4..];
        match sel {
            s if s == abi::TRANSFER_FROMCall::SELECTOR => {
                let a = abi::TRANSFER_FROMCall::abi_decode_raw(args)?;
                let (t, amt) = (a.permit.permitted.token, a.permit.permitted.amount);
                println!("  [{ai}] TRANSFER_FROM {} {}", amt, sym(t));
                ensure!(
                    Some(a.recipient) == snap.settler,
                    "TRANSFER_FROM to non-settler {}",
                    a.recipient
                );
                led.credit(t, amt);
            }
            s if s == abi::NATIVE_CHECKCall::SELECTOR => println!("  [{ai}] NATIVE_CHECK"),
            s if s == abi::UNISWAPV3Call::SELECTOR || s == abi::UNISWAPV3_VIPCall::SELECTOR => {
                let (bps, path, amt) = if s == abi::UNISWAPV3Call::SELECTOR {
                    let a = abi::UNISWAPV3Call::abi_decode_raw(args)?;
                    let bps = u32::try_from(a.ppm).context("bps")?;
                    let tin = Address::from_slice(&a.path[..20]);
                    (
                        bps,
                        a.path.to_vec(),
                        share(*led.bal.entry(tin).or_default(), bps)?,
                    )
                } else {
                    let a = abi::UNISWAPV3_VIPCall::abi_decode_raw(args)?;
                    led.credit(a.permit.permitted.token, a.permit.permitted.amount);
                    (BPS_BASE, a.path.to_vec(), a.permit.permitted.amount)
                };
                let hops = parse_v3_path(&path)?;
                led.debit(hops[0].tin, amt)?;
                let mut x = amt;
                let mut labels = Vec::new();
                for h in &hops {
                    match find_v3(snap, h.fork, h.pool_id, h.tin, h.tout) {
                        Some(idx) => {
                            labels.push(pool_label(snap, '3', idx));
                            x = led.swap_v3(idx, h.tin, x)?;
                        }
                        None => {
                            let miss = format!(
                                "UNKNOWN v3 fork={} poolId={} {}→{}",
                                h.fork,
                                h.pool_id,
                                sym(h.tin),
                                sym(h.tout)
                            );
                            labels.push(miss.clone());
                            led.unsim.push(format!("{miss} carrying {x}"));
                            x = U256::ZERO;
                        }
                    }
                    if x.is_zero() {
                        break;
                    }
                }
                led.credit(hops.last().expect("hops").tout, x);
                println!(
                    "  [{ai}] UNISWAPV3 bps={bps} in={amt} out={x}  {}",
                    labels.join(" → ")
                );
            }
            s if s == abi::UNISWAPV2Call::SELECTOR => {
                let a = abi::UNISWAPV2Call::abi_decode_raw(args)?;
                let bps = u32::try_from(a.ppm).context("bps")?;
                let amt = share(*led.bal.entry(a.sellToken).or_default(), bps)?;
                led.debit(a.sellToken, amt)?;
                let (out, label) = match find_v2(snap, a.pool) {
                    Some(idx) => {
                        let out = led.swap_v2(idx, a.sellToken, amt)?;
                        let l = pool_label(snap, '2', idx);
                        let tout =
                            if snap.v2[idx].0.token0 == ROBINHOOD_PROFILE.erc20_of(a.sellToken) {
                                snap.v2[idx].0.token1
                            } else {
                                snap.v2[idx].0.token0
                            };
                        led.credit(tout, out);
                        (out, l)
                    }
                    None => {
                        led.unsim.push(format!(
                            "UNKNOWN v2 pool {} carrying {amt}",
                            addrhex(a.pool)
                        ));
                        (U256::ZERO, format!("UNKNOWN v2 {}", addrhex(a.pool)))
                    }
                };
                println!("  [{ai}] UNISWAPV2 bps={bps} in={amt} out={out}  {label}");
            }
            s if s == abi::UNISWAPV4Call::SELECTOR => {
                let a = abi::UNISWAPV4Call::abi_decode_raw(args)?;
                let bps = u32::try_from(a.ppm).context("bps")?;
                let amt = share(*led.bal.entry(a.sellToken).or_default(), bps)?;
                led.debit(a.sellToken, amt)?;
                let fills = parse_v4_fills(&a.fills, a.sellToken)?;
                println!(
                    "  [{ai}] UNISWAPV4 bps={bps} in={amt} sell={} fills={}",
                    sym(a.sellToken),
                    fills.len()
                );
                let mut note: BTreeMap<Address, U256> = BTreeMap::new();
                note.insert(a.sellToken, amt);
                for f in &fills {
                    let avail = *note.entry(f.sell).or_default();
                    let famt = share(avail, f.bps)?;
                    let (out, label) = match find_v4(snap, f) {
                        Some(idx) => (led.swap_v3(idx, f.sell, famt)?, pool_label(snap, '3', idx)),
                        None => {
                            let miss = format!(
                                "UNKNOWN v4 {}→{} fee={} spacing={} hooks={}",
                                sym(f.sell),
                                sym(f.buy),
                                f.fee,
                                f.spacing,
                                addrhex(f.hooks)
                            );
                            led.unsim.push(format!("{miss} carrying {famt}"));
                            (U256::ZERO, miss)
                        }
                    };
                    *note.entry(f.sell).or_default() -= famt;
                    *note.entry(f.buy).or_default() += out;
                    println!(
                        "        fill bps={} in={famt} out={out} hookdata={}  {label}",
                        f.bps, f.hookdata
                    );
                }
                for (t, x) in note {
                    led.credit(t, x);
                }
            }
            s if s == abi::BASICCall::SELECTOR => {
                let a = abi::BASICCall::abi_decode_raw(args)?;
                let bps = u32::try_from(a.ppm).context("bps")?;
                let amt = share(*led.bal.entry(a.sellToken).or_default(), bps)?;
                if a.sellToken == NATIVE && a.pool == WETH && a.offset.is_zero() {
                    led.debit(NATIVE, amt)?;
                    led.credit(WETH, amt);
                    println!("  [{ai}] BASIC wrap {amt}");
                } else if a.sellToken == WETH && a.pool == WETH && a.offset == U256::from(4) {
                    led.debit(WETH, amt)?;
                    led.credit(NATIVE, amt);
                    println!("  [{ai}] BASIC unwrap {amt}");
                } else if a.data.len() >= 4 && a.data[..4] == abi::transferCall::SELECTOR {
                    // fee transfer — keep the amount in the ledger: we compare gross
                    println!(
                        "  [{ai}] BASIC fee-transfer bps={bps} of {} (kept for gross)",
                        sym(a.sellToken)
                    );
                } else {
                    led.debit(a.sellToken, amt)?;
                    // offset 132 = amountIn of a SwapRouter02-shaped exactInputSingle
                    // (tokenIn, tokenOut, fee|tickSpacing, recipient, amountIn, …)
                    let detail = if a.offset == U256::from(132) && a.data.len() >= 100 {
                        format!(
                            " exactInputSingle sel=0x{} {}→{} fee/ts={}",
                            alloy_primitives::hex::encode(&a.data[..4]),
                            sym(Address::from_slice(&a.data[16..36])),
                            sym(Address::from_slice(&a.data[48..68])),
                            U256::from_be_slice(&a.data[68..100]),
                        )
                    } else {
                        String::new()
                    };
                    led.unsim.push(format!(
                        "BASIC pool={} offset={} carrying {amt}{detail}",
                        addrhex(a.pool),
                        a.offset
                    ));
                    println!(
                        "  [{ai}] BASIC UNKNOWN pool={} offset={} in={amt}{detail}",
                        addrhex(a.pool),
                        a.offset
                    );
                }
            }
            s if s == abi::POSITIVE_SLIPPAGECall::SELECTOR => {
                let a = abi::POSITIVE_SLIPPAGECall::abi_decode_raw(args)?;
                println!(
                    "  [{ai}] POSITIVE_SLIPPAGE token={} expected={} maxPpm={} (kept for gross)",
                    sym(a.token),
                    a.expectedAmount,
                    a.maxPpm
                );
            }
            s => {
                led.unsim.push(format!(
                    "unknown action selector 0x{}",
                    alloy_primitives::hex::encode(s)
                ));
                println!(
                    "  [{ai}] UNKNOWN selector 0x{} ({} bytes)",
                    alloy_primitives::hex::encode(s),
                    args.len()
                );
            }
        }
    }
    Ok(led)
}

// ---- our side ----

fn replay_ours<'a>(snap: &'a Snapshot, plan: &Plan) -> anyhow::Result<Ledger<'a>> {
    let mut led = Ledger::new(snap);
    for leg in &plan.legs {
        let mut x = leg.amount_in;
        for h in &leg.path {
            x = match h.kind {
                sextant::route::HopKind::V3 => led.swap_v3(h.index, h.token_in, x)?,
                sextant::route::HopKind::V2 => led.swap_v2(h.index, h.token_in, x)?,
                sextant::route::HopKind::Ekubo => led.swap_ekubo(h.index, h.token_in, x)?,
            };
        }
        led.credit(
            ROBINHOOD_PROFILE.erc20_of(leg.path.last().expect("hops").token_out),
            x,
        );
    }
    Ok(led)
}

// ---- 0x api ----

async fn zx_quote_raw(
    client: &reqwest::Client,
    key: &str,
    tin: Address,
    tout: Address,
    amount: U256,
) -> anyhow::Result<Value> {
    let url = format!(
        "https://api.0x.org/swap/allowance-holder/quote?chainId={CHAIN_ID}&sellToken={}&buyToken={}&sellAmount={}&taker={}&slippageBps=100",
        addrhex(tin),
        addrhex(tout),
        amount,
        addrhex(TAKER)
    );
    for attempt in 0..5 {
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
            tokio::time::sleep(std::time::Duration::from_millis(1500 * (attempt + 1))).await;
            continue;
        }
        ensure!(
            status == 200,
            "0x api http {status}: {}",
            body.chars().take(200).collect::<String>()
        );
        return serde_json::from_str(&body).context("0x api json");
    }
    bail!("0x api rate-limited after retries")
}

fn ubig(v: &Value) -> anyhow::Result<U256> {
    U256::from_str_radix(v.as_str().context("amount string")?, 10).context("decimal amount")
}

fn f64_of(x: U256) -> f64 {
    x.to_string().parse().unwrap_or(f64::NAN)
}

fn bps_edge(a: U256, b: U256) -> f64 {
    ((f64_of(a) / f64_of(b)) - 1.0) * 10_000.0
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let named = |s: &str| -> anyhow::Result<(Address, u32)> {
        Ok(match s {
            "WETH" => (WETH, 18),
            "ETH" => (NATIVE, 18),
            "USDG" => (USDG, 6),
            "UP" => (UP, 18),
            _ => bail!("unknown token {s} (WETH|ETH|USDG|UP)"),
        })
    };
    let (tin, din) = named(args.first().map_or("WETH", |s| s))?;
    let (tout, _) = named(args.get(1).map_or("USDG", |s| s))?;
    let human: u64 = args.get(2).map_or(Ok(500), |s| s.parse())?;
    let amount = U256::from(human) * U256::from(10).pow(U256::from(din));

    let rpc_url = std::env::var("SOLVER_RPC").context("SOLVER_RPC must point at the real chain")?;
    let key = std::env::var("ZEROEX_API_KEY").context("ZEROEX_API_KEY required")?;
    let rpc = Rpc::connect(&rpc_url)?;
    rpc.verify_chain_id(ROBINHOOD_PROFILE.chain_id, "SOLVER_RPC")
        .await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let (a, b) = (
        ROBINHOOD_PROFILE.erc20_of(tin),
        ROBINHOOD_PROFILE.erc20_of(tout),
    );
    let snap = snapshot_at_for(&ROBINHOOD_PROFILE, &rpc, None, a, b, None).await?;
    println!(
        "snapshot @block {}: {} v3-family pools, {} v2 pools",
        snap.block,
        snap.v3.len(),
        snap.v2.len()
    );
    println!("\n=== our pool universe for {}/{} ===", sym(a), sym(b));
    for i in 0..snap.v3.len() {
        println!("  {}", pool_label(&snap, '3', i));
    }
    for i in 0..snap.v2.len() {
        println!("  {}", pool_label(&snap, '2', i));
    }

    let plan = quantized_plan(
        &snap,
        &PreparedRoutes::for_profile(&snap, &ROBINHOOD_PROFILE, a, b)?.solve(
            amount,
            *ALLOC_CHUNKS,
            *MIN_SHARE_BPS,
        )?,
        amount,
    )?;
    println!(
        "\n=== our plan: {} {} → {} ===",
        amount,
        sym(tin),
        sym(tout)
    );
    for leg in &plan.legs {
        let hops: Vec<String> = leg
            .path
            .iter()
            .map(|h| match h.kind {
                sextant::route::HopKind::V3 => pool_label(&snap, '3', h.index),
                sextant::route::HopKind::V2 => pool_label(&snap, '2', h.index),
                sextant::route::HopKind::Ekubo => pool_label(&snap, 'e', h.index),
            })
            .collect();
        println!(
            "  slice_bps={:<5} in={} out={}  {}",
            leg.slice_bps,
            leg.amount_in,
            leg.amount_out,
            hops.join(" → ")
        );
    }
    println!("  total out: {}", plan.amount_out);

    let zx = zx_quote_raw(&client, &key, tin, tout, amount).await?;
    ensure!(
        zx["liquidityAvailable"].as_bool().unwrap_or(true),
        "0x: no liquidity"
    );
    let buy = ubig(&zx["buyAmount"])?;
    let fee = match &zx["fees"]["zeroExFee"] {
        Value::Null => U256::ZERO,
        f if f["token"].as_str().map(str::to_lowercase)
            == Some(addrhex(ROBINHOOD_PROFILE.erc20_of(tout))) =>
        {
            ubig(&f["amount"])?
        }
        _ => U256::ZERO,
    };
    let zx_gross = buy + fee;
    println!("\n=== 0x quote: gross={} (fee={}) ===", zx_gross, fee);
    if let Some(fills) = zx["route"]["fills"].as_array() {
        for f in fills {
            println!(
                "  api fill: {} {} → {} proportion={}bps",
                f["source"].as_str().unwrap_or("?"),
                f["from"].as_str().unwrap_or("?"),
                f["to"].as_str().unwrap_or("?"),
                f["proportionBps"]
                    .as_str()
                    .or(f["proportionBps"].as_i64().map(|_| ""))
                    .unwrap_or("?"),
            );
        }
    }

    let to: Address = zx["transaction"]["to"].as_str().context("tx.to")?.parse()?;
    let data = hexbytes(zx["transaction"]["data"].as_str().context("tx.data")?)?;
    println!();
    let zx_led = replay_zx(&snap, to, &data)?;

    let ours_led = replay_ours(&snap, &plan)?;

    println!("\n=== per-pool input totals ===");
    let mut all: Vec<&String> = ours_led.used.keys().chain(zx_led.used.keys()).collect();
    all.sort();
    all.dedup();
    println!("{:<40} {:>26} {:>26}", "pool", "ours in", "0x in");
    for k in all {
        println!(
            "{:<40} {:>26} {:>26}",
            k,
            ours_led
                .used
                .get(k)
                .copied()
                .unwrap_or_default()
                .to_string(),
            zx_led.used.get(k).copied().unwrap_or_default().to_string()
        );
    }

    let out_token = ROBINHOOD_PROFILE.erc20_of(tout);
    let replayed = zx_led.bal.get(&out_token).copied().unwrap_or_default()
        + if tout == NATIVE {
            zx_led.bal.get(&NATIVE).copied().unwrap_or_default()
        } else {
            U256::ZERO
        };
    println!("\n=== verdict ===");
    println!("ours quoted          : {}", plan.amount_out);
    println!(
        "0x quoted (gross)    : {}   edge {:+.2}bps",
        zx_gross,
        bps_edge(plan.amount_out, zx_gross)
    );
    println!(
        "0x replayed (our sim): {}   replay-vs-quote {:+.2}bps",
        replayed,
        bps_edge(replayed, zx_gross)
    );
    if !zx_led.unsim.is_empty() {
        println!("unsimulatable flows:");
        for u in &zx_led.unsim {
            println!("  - {u}");
        }
        println!("→ UNIVERSE GAP: the flows above are outside our pool universe/simulator.");
    } else if bps_edge(replayed, zx_gross).abs() < 2.0 && replayed > plan.amount_out {
        println!(
            "→ ALLOCATOR GAP: their plan lives inside our search space and beats our optimizer."
        );
    } else if bps_edge(replayed, zx_gross) < -2.0 {
        println!(
            "→ SIMULATOR GAP: we know every pool but undervalue their route — check venue math/fees."
        );
    } else {
        println!("→ no gap on their side; our quote stands.");
    }
    Ok(())
}
