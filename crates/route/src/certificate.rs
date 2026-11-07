// W1 — the routing dual, evaluated as a machine-rigorous optimality certificate.
//
// THE BOUND. Write the quote as the convex program the router actually solves:
// spend at most `amount_in` of the input token, route arbitrary flows through
// every pool in the snapshot, deliver as much of the output token as possible,
// creating no token out of nothing. Attaching prices ν ≥ 0 (in output-token
// units, ν_out = 1) to the per-token conservation constraints and maximizing
// the Lagrangian pool by pool gives, for EVERY such ν,
//
//     OPT  ≤  g(ν)  =  ν_in · X  +  Σ_p arb_p(ν),
//
// where arb_p(ν) = sup { ν·δ : δ ∈ T_p } is pool p's optimal-arbitrage value at
// linear prices ν over its feasible trade set T_p, and OPT is the best output
// any router could extract from this snapshot — over arbitrary splits, arbitrary
// path counts, arbitrary depth, including flows no path enumeration would ever
// list. `gap = g(ν) − achieved` is therefore an upper bound on everything the
// solver left on the table: allocation regret, coverage regret and free
// arbitrage, all in one number, priced in output wei.
//
// WHY IT IS TIGHT. arb_p ≥ 0 always (0 ∈ T_p), so a bad ν gives a useless-but-
// valid bound. The dual optimum is attained at the POST-trade marginal prices:
// for a single pool taking the whole trade, the arbitrage that ν admits is
// exactly the trade we executed, and the bound collapses onto the achieved
// output — gap 0. `dual_prices` therefore reads marginal prices off the pool
// states AFTER the plan executes, and propagates them to every other token by
// max-product (Bellman–Ford) over the token graph. A pool the plan never
// touched contributes arb_p > 0 exactly when it could still have improved the
// quote at those prices, which is the regret we want to see.
//
// WHY IT IS RIGOROUS. Weak duality holds for any ν ≥ 0: validity does not
// depend on how ν was produced, only tightness does. So the price search may be
// as heuristic as it likes, and the CHECK — the evaluation of g(ν) — is what
// must be sound. Every term below is evaluated in exact integer arithmetic with
// outward-directed rounding (output legs rounded up, input legs rounded down,
// square-root brackets rounded away from each other), in ≤512 bits with checked
// overflow. No floating point is involved anywhere in this file. The emitted
// bound is thus valid against the arithmetic itself, not merely against a
// convergence argument — which is the property no production router and, as of
// 2026, no first-order optimization solver publishes. See
// the maintainers' research notes §4.6.
//
// SCOPE, STATED HONESTLY. T_p is the pool's trade set AS MODELLED BY THE
// SNAPSHOT: the concentrated-liquidity walk stops at the edge of the tick
// window the snapshot covers. That wall sits at or beyond where `sim_v3`
// stops — `sim_v3` refuses a step whose boundary tick falls outside the
// window, this walk trades up to the window edge itself — so the difference
// only ever enlarges the bound, which is the safe direction. The certificate
// therefore bounds the optimum over the liquidity the solver can actually
// see: it is an allocation/coverage certificate, not a claim about liquidity
// outside the snapshot window. Widening that window is W4's job, not W1's;
// the fidelity of the window is measured by the executable comparison, not
// asserted here.

use crate::budget::SolverBudget;
#[cfg(any(test, feature = "testing"))]
use crate::chain::ChainProfile;
use crate::depth::next_stop;
use crate::pools::{V2Pool, V2State, V3Pool, V3State, cross_liquidity};
use crate::route::{Hop, HopKind, Plan, PlanStates, hops_between};
use crate::snapshot::{ScreeningPools, Snapshot};
use crate::universe::RouteUniverse;
use crate::v3math::{Q96, muldiv};
use alloy_primitives::{Address, U256, U512};
use anyhow::{Context, ensure};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// SOLVER_CERTIFICATE=0 turns the per-quote dual pass off.
///
/// This module only computes the proof, and a failure to certify never invalidates
/// an otherwise executable quote. Quote assembly may use a successful certified
/// gap to trigger its explicit allocator-escalation tier. With the default
/// tighten budget the pass costs ~3.5ms p50 / 7.7ms max on the ladder — real
/// money against a 2ms hot quote, but still invisible under any caller's network
/// path, so the default stays on.
pub static ENABLED: LazyLock<bool> =
    LazyLock::new(|| read_enabled().unwrap_or_else(|error| panic!("{error:#}")));

/// The same parse as `ENABLED`, as a `Result` so startup validation can reject
/// a setting that depends on it without tripping the LazyLock's panic.
pub fn read_enabled() -> anyhow::Result<bool> {
    match std::env::var("SOLVER_CERTIFICATE") {
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        Ok(value) => anyhow::bail!("SOLVER_CERTIFICATE must be 0 or 1, got {value:?}"),
        Err(std::env::VarError::NotPresent) => Ok(true),
        Err(error) => anyhow::bail!("SOLVER_CERTIFICATE is not valid Unicode: {error}"),
    }
}

/// SOLVER_CERTIFICATE_TIGHTEN: evaluations of `g` the dual point may spend
/// being minimized. Zero reports the anchored starting point.
///
/// The default is 128 — a ceiling, not a spend target. The damped Newton
/// search converges or gives up in far fewer evaluations: ladder at block
/// 25133547, p50 0.049 / p95 10.6 / max 11.3 bps at 3.5ms p50 / 7.7ms max of
/// certificate wall time. The BFGS it replaced needed twice the time for
/// p95 17 bps and froze on SLVR pairs at 21.7 bps regardless of budget. How
/// 128 was picked, the BFGS-era pathologies, and the seed fix that preceded
/// this: `certificate-tighten-budget-2026-08-01.md`.
static TIGHTEN_BUDGET: LazyLock<usize> =
    LazyLock::new(|| read_tighten_budget().unwrap_or_else(|error| panic!("{error:#}")));

/// `SOLVER_CERTIFICATE_TIGHTEN`, as a `Result` so startup can reject a typo
/// instead of the first quote that certifies tripping the `LazyLock`.
pub fn read_tighten_budget() -> anyhow::Result<usize> {
    match std::env::var("SOLVER_CERTIFICATE_TIGHTEN") {
        Ok(value) => parse_tighten_budget(Some(&value)),
        Err(std::env::VarError::NotPresent) => parse_tighten_budget(None),
        Err(error) => anyhow::bail!("SOLVER_CERTIFICATE_TIGHTEN is not valid Unicode: {error}"),
    }
}

fn parse_tighten_budget(value: Option<&str>) -> anyhow::Result<usize> {
    match value {
        Some(value) => value
            .parse()
            .with_context(|| format!("SOLVER_CERTIFICATE_TIGHTEN must be a count, got {value:?}")),
        None => Ok(128),
    }
}

/// The same ceiling, for the one bound evaluated outside this module. A second
/// knob would let the coverage bound and the served certificate disagree about
/// how hard they searched, and their numbers are meant to be compared.
pub fn tighten_budget() -> usize {
    *TIGHTEN_BUDGET
}

/// Relative precision carried by a dual price. 64 bits is ~5e-20 — twelve
/// orders below the 1e-8 resolution `gap_bps` reports — and it keeps every
/// product in this file inside 512 bits.
const PRICE_BITS: usize = 64;
/// Fixed-point scale for square-root brackets: √x is bracketed as an integer
/// multiple of 2^-SQRT_SHIFT, rounded away from the value it is subtracted
/// from.
const SQRT_SHIFT: usize = 64;
const PPM: u32 = 1_000_000;
const BPS: u32 = 10_000;

fn wide(x: U256) -> U512 {
    U512::from(x)
}

fn narrow(x: U512) -> anyhow::Result<U256> {
    ensure!(
        x >> 256usize == U512::ZERO,
        "certificate term exceeds 256 bits"
    );
    Ok(U256::from_limbs(
        x.as_limbs()[..4].try_into().expect("4 low limbs"),
    ))
}

/// The exact product of two 256-bit values: it cannot overflow 512 bits.
fn wmul(a: U256, b: U256) -> U512 {
    a.widening_mul(b)
}

fn mul(a: U512, b: U512) -> anyhow::Result<U512> {
    a.checked_mul(b).context("certificate arithmetic overflow")
}

fn add(a: U512, b: U512) -> anyhow::Result<U512> {
    a.checked_add(b).context("certificate arithmetic overflow")
}

fn div_floor(a: U512, b: U512) -> anyhow::Result<U512> {
    ensure!(!b.is_zero(), "certificate division by zero");
    Ok(a / b)
}

fn div_ceil(a: U512, b: U512) -> anyhow::Result<U512> {
    ensure!(!b.is_zero(), "certificate division by zero");
    let (q, r) = a.div_rem(b);
    Ok(if r.is_zero() { q } else { q + U512::ONE })
}

fn sqrt_floor(x: U512) -> U512 {
    x.root(2)
}

fn sqrt_ceil(x: U512) -> U512 {
    let r = x.root(2);
    match r.checked_mul(r) {
        Some(square) if square == x => r,
        _ => r + U512::ONE,
    }
}

/// A non-negative price, exactly `num / den`, in output-token wei per wei of
/// the token it prices.
///
/// Prices are DATA, not derivation: the bound is valid for any non-negative ν,
/// so a checker never has to reproduce how these were chosen — it re-evaluates
/// `bound_at` and compares. That separation is the whole point of emitting a
/// certificate rather than a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Price {
    pub num: U256,
    pub den: U256,
}

impl Price {
    pub const ONE: Price = Price {
        num: U256::ONE,
        den: U256::ONE,
    };
    pub const ZERO: Price = Price {
        num: U256::ZERO,
        den: U256::ONE,
    };

    /// `num/den`, renormalized to PRICE_BITS of relative precision. A live
    /// price never normalizes to zero: rounding it up keeps the bound valid
    /// (any ν is) and keeps it finite (ν_t = 0 would price token t's whole
    /// reserve as free).
    fn from_ratio(num: U512, den: U512) -> anyhow::Result<Price> {
        ensure!(!den.is_zero(), "price with zero denominator");
        if num.is_zero() {
            return Ok(Price::ZERO);
        }
        let bits = num.bit_len().max(den.bit_len());
        let shift = bits.saturating_sub(PRICE_BITS);
        let scaled = |x: U512| -> U512 {
            let y = x >> shift;
            if y.is_zero() { U512::ONE } else { y }
        };
        Ok(Price {
            num: narrow(scaled(num))?,
            den: narrow(scaled(den))?,
        })
    }

    fn is_zero(self) -> bool {
        self.num.is_zero()
    }

    /// Chained rate: the value of one wei of this token's input token.
    fn compose(self, other: Price) -> anyhow::Result<Price> {
        Price::from_ratio(wmul(self.num, other.num), wmul(self.den, other.den))
    }

    fn greater(self, other: Price) -> anyhow::Result<bool> {
        Ok(wmul(self.num, other.den) > wmul(other.num, self.den))
    }

    /// `self · amount`, rounded up — used where the term ADDS to the bound.
    fn value_up(self, amount: U256) -> anyhow::Result<U512> {
        div_ceil(wmul(self.num, amount), wide(self.den))
    }

    /// `self · amount`, rounded down — used where the term SUBTRACTS from it.
    fn value_down(self, amount: U256) -> anyhow::Result<U512> {
        div_floor(wmul(self.num, amount), wide(self.den))
    }
}

// ---- marginal prices (the heuristic half: choosing ν) ----

/// Slope of the swap curve at the trade that produced this state — the rate one
/// more wei of input would have earned, on the SAME swap.
///
/// Not the post-trade spot rate: a v2 fee stays in the reserves, so a follow-up
/// swap is quoted worse than the marginal wei of the swap that just ran. With
/// out(δ) = fδC/(10⁴R_in + fδ), the slope at the executed δ is
/// f·R_out'/(10⁴·R_in' − fee·δ), which reduces to the plain spot rate on a pool
/// the plan never touched. Getting this exactly right is what collapses the
/// certified gap onto the achieved output rather than onto its square.
///
/// `None` for a state that cannot quote a rate (an empty reserve); such a pool
/// contributes no edge to the price graph, which costs tightness and never
/// validity.
fn marginal_v2(
    pool: &V2Pool,
    state: &V2State,
    zero_for_one: bool,
    input: U256,
) -> anyhow::Result<Option<Price>> {
    let fee_bps = pool.fee_bps;
    let (rin, rout) = if zero_for_one {
        (state.reserve0, state.reserve1)
    } else {
        (state.reserve1, state.reserve0)
    };
    if rin.is_zero() || rout.is_zero() || fee_bps >= BPS {
        return Ok(None);
    }
    let den = wmul(U256::from(BPS), rin)
        .checked_sub(wmul(U256::from(fee_bps), input.min(rin)))
        .context("v2 marginal denominator underflow")?;
    Ok(Some(Price::from_ratio(
        wmul(U256::from(BPS - fee_bps), rout),
        den,
    )?))
}

fn marginal_v3(
    pool: &V3Pool,
    state: &V3State,
    zero_for_one: bool,
) -> anyhow::Result<Option<Price>> {
    let fee = pool.fee_ppm_for(zero_for_one)?;
    if fee >= PPM || state.sqrt_price.is_zero() || state.liquidity.is_zero() {
        return Ok(None);
    }
    let square = wmul(state.sqrt_price, state.sqrt_price);
    let q192 = wmul(Q96, Q96);
    let net = wide(U256::from(PPM - fee));
    let ppm = wide(U256::from(PPM));
    Ok(Some(if zero_for_one {
        // one wei of token0 buys γ·(√P/2^96)² wei of token1
        Price::from_ratio(mul(net, square)?, mul(ppm, q192)?)?
    } else {
        Price::from_ratio(mul(net, q192)?, mul(ppm, square)?)?
    }))
}

/// The virtual out-side reserve of a v3 position: y = L·√P/2⁹⁶ when selling
/// token0, x = L·2⁹⁶/√P when selling token1 — the same units as a v2 reserve,
/// which is what lets the spare-edge dedup below compare a concentrated
/// position against a constant-product pool quoting the same pair.
fn v3_virtual_out(state: &V3State, zero_for_one: bool) -> U256 {
    if state.sqrt_price.is_zero() {
        return U256::ZERO;
    }
    let result = if zero_for_one {
        muldiv(state.liquidity, state.sqrt_price, Q96)
    } else {
        muldiv(state.liquidity, Q96, state.sqrt_price)
    };
    result.unwrap_or(U256::ZERO)
}

/// Post-trade dual prices for every token in the snapshot, denominated in
/// `token_out`.
///
/// Max-product Bellman–Ford: ν_t is the best rate at which one wei of t can be
/// turned into the output token through at most |V|−1 hops at post-trade
/// marginal prices. The fixpoint of that recursion is exactly the condition
/// "no pool is arbitrageable at the margin", which is what drives the arb terms
/// — and the bound — down. The hop cap also makes an arbitrage cycle in the
/// snapshot terminate instead of diverging; the leftover cycle profit then
/// shows up honestly as a positive arb term.
pub fn dual_prices(
    snap: &Snapshot,
    token_out: Address,
    states: &PlanStates,
    routed: &PoolSet,
) -> anyhow::Result<HashMap<Address, Price>> {
    let (v3s, v2s) = (&states.v3, &states.v2);
    // Edges from pools the PLAN used come first, and the relaxation below
    // takes the best it can reach on those before it will look at the rest.
    //
    // Anchoring on the executed route is what keeps the starting point sane.
    // A max over every pool prices each token at the best marginal rate ANY
    // pool advertises, and one thin pool can win that maximum for a whole
    // token — after which every deep pool priced against it reports arbitrage
    // bounded by its own depth. Measured on live WETH→USDG, the all-pool
    // maximum started the search at 7866 bps; anchored on the plan's own
    // marginal rates it starts near the answer, which matters because `g` is
    // too sharply conditioned near its minimum to search down from far away
    // on a quote's time budget.
    let mut edges: Vec<(Address, Address, Price)> = Vec::new();
    let mut spare: Vec<(Address, Address, Price, U256)> = Vec::new();
    let mut tokens: Vec<Address> = vec![token_out];
    let note = |tokens: &mut Vec<Address>, t: Address| {
        if !tokens.contains(&t) {
            tokens.push(t);
        }
    };
    for (i, (pool, _)) in snap.v3.iter().enumerate() {
        note(&mut tokens, pool.token0);
        note(&mut tokens, pool.token1);
        if let Some(rate) = marginal_v3(pool, &v3s[i], true)? {
            if routed.v3(i) {
                edges.push((pool.token0, pool.token1, rate));
            } else {
                spare.push((
                    pool.token0,
                    pool.token1,
                    rate,
                    v3_virtual_out(&v3s[i], true),
                ));
            }
        }
        if let Some(rate) = marginal_v3(pool, &v3s[i], false)? {
            if routed.v3(i) {
                edges.push((pool.token1, pool.token0, rate));
            } else {
                spare.push((
                    pool.token1,
                    pool.token0,
                    rate,
                    v3_virtual_out(&v3s[i], false),
                ));
            }
        }
    }
    for (i, (pool, _)) in snap.v2.iter().enumerate() {
        note(&mut tokens, pool.token0);
        note(&mut tokens, pool.token1);
        let input = states.v2_input[i];
        if let Some(rate) = marginal_v2(pool, &v2s[i], true, input[0])? {
            if routed.v2(i) {
                edges.push((pool.token0, pool.token1, rate));
            } else {
                spare.push((pool.token0, pool.token1, rate, v2s[i].reserve1));
            }
        }
        if let Some(rate) = marginal_v2(pool, &v2s[i], false, input[1])? {
            if routed.v2(i) {
                edges.push((pool.token1, pool.token0, rate));
            } else {
                spare.push((pool.token1, pool.token0, rate, v2s[i].reserve0));
            }
        }
    }

    let mut prices: HashMap<Address, Price> = tokens.iter().map(|&t| (t, Price::ZERO)).collect();
    prices.insert(token_out, Price::ONE);
    relax(&mut prices, &edges, token_out, tokens.len())?;
    // Tokens the plan never touched still need a price, or a pool holding one
    // would be valued as free. Those fall back to the catalog — but only the
    // DEEPEST pool of each directed pair gets to vote. A max over parallel
    // edges lets one thin pool set a whole token's rate (measured on live
    // WETH→NVDA: a thin pool priced VIRTUAL ~12× off the deep market, and the
    // deep WETH/VIRTUAL pool then carried 2.77e23 of phantom arbitrage the
    // optimizer had to walk back across a kink field it stalls in). Depth is
    // the out-side virtual reserve, the one measure a v2 reserve and a v3
    // in-range position share. Seeding affects only tightness, never validity.
    if prices.values().any(|price| price.is_zero()) {
        let mut deepest: HashMap<(Address, Address), (Price, U256)> = HashMap::new();
        for (from, to, rate, depth) in spare {
            match deepest.get(&(from, to)) {
                Some((_, held)) if *held >= depth => {}
                _ => {
                    deepest.insert((from, to), (rate, depth));
                }
            }
        }
        let mut fallback: Vec<((Address, Address), (Price, U256))> = deepest.into_iter().collect();
        // Deterministic relax order — HashMap iteration must not decide
        // anything, even something as inert as an edge ordering.
        fallback.sort_unstable_by_key(|((from, to), _)| (*from, *to));
        edges.extend(
            fallback
                .into_iter()
                .map(|((from, to), (rate, _))| (from, to, rate)),
        );
        relax(&mut prices, &edges, token_out, tokens.len())?;
    }
    Ok(prices)
}

fn relax(
    prices: &mut HashMap<Address, Price>,
    edges: &[(Address, Address, Price)],
    token_out: Address,
    tokens: usize,
) -> anyhow::Result<()> {
    for _ in 1..tokens.max(1) {
        let mut changed = false;
        for &(from, to, rate) in edges {
            // The numeraire is PINNED. ν_out = 1 is the normalization the
            // whole bound is denominated in, and relaxing it is not a better
            // price — it is a change of units, silently rescaling `bound`
            // away from the wei `achieved` is measured in. An arbitrage cycle
            // through the output token will try: on a real catalog it drove
            // ν_out to ~2^38 and the bound with it. Weak duality survives
            // that (ν_out ≥ 1 is still dual-feasible, so the bound stayed
            // valid and nothing read "inconsistent") — which is exactly why
            // it had to be caught by measurement rather than by a soundness
            // check.
            if from == token_out {
                continue;
            }
            let value = prices.get(&to).copied().unwrap_or(Price::ZERO);
            if value.is_zero() {
                continue;
            }
            let candidate = rate.compose(value)?;
            let current = prices.get(&from).copied().unwrap_or(Price::ZERO);
            if candidate.greater(current)? {
                prices.insert(from, candidate);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(())
}

// ---- arbitrage values (the rigorous half: evaluating g(ν)) ----

/// `sup { ν·δ : δ ∈ T_p }` for a constant-product pool, rounded up.
///
/// With A = 10⁴·R_in, B = 10⁴−fee_bps, C = R_out, the profit at input δ is
/// ν_out·BδC/(A+Bδ) − ν_in·δ, concave, and its unconstrained maximum is
///
/// `(√(ν_out·C) − √(ν_in·A/B))²` when `ν_out·C·B ≥ ν_in·A`, else zero.
///
/// Both roots are bracketed in fixed point AWAY from each other — the
/// subtrahend down, the minuend up — so the squared difference can only
/// overstate the true value.
fn arb_v2(pool: &V2Pool, state: &V2State, p0: Price, p1: Price) -> anyhow::Result<U256> {
    Ok(arb_v2_toward(pool, state, true, p0, p1)?.max(arb_v2_toward(pool, state, false, p0, p1)?))
}

/// `arb_v2` with the router selling token0 (`zero_for_one`) or token1 only.
fn arb_v2_toward(
    pool: &V2Pool,
    state: &V2State,
    zero_for_one: bool,
    p0: Price,
    p1: Price,
) -> anyhow::Result<U256> {
    let (reserve_in, reserve_out, price_in, price_out) = if zero_for_one {
        (state.reserve0, state.reserve1, p0, p1)
    } else {
        (state.reserve1, state.reserve0, p1, p0)
    };
    arb_v2_side(reserve_in, reserve_out, pool.fee_bps, price_in, price_out)
}

fn arb_v2_side(
    reserve_in: U256,
    reserve_out: U256,
    fee_bps: u32,
    price_in: Price,
    price_out: Price,
) -> anyhow::Result<U256> {
    if price_out.is_zero() || reserve_out.is_zero() || fee_bps >= BPS {
        return Ok(U256::ZERO);
    }
    let scale = U512::ONE << (2 * SQRT_SHIFT);
    // ⌈√(ν_out·C)·2^SQRT_SHIFT⌉
    let minuend = sqrt_ceil(div_ceil(
        mul(wmul(price_out.num, reserve_out), scale)?,
        wide(price_out.den),
    )?);
    // ⌊√(ν_in·A/B)·2^SQRT_SHIFT⌋
    let subtrahend = sqrt_floor(div_floor(
        mul(
            mul(wmul(price_in.num, reserve_in), wide(U256::from(BPS)))?,
            scale,
        )?,
        wmul(price_in.den, U256::from(BPS - fee_bps)),
    )?);
    if minuend <= subtrahend {
        return Ok(U256::ZERO);
    }
    let root = minuend - subtrahend;
    narrow(div_ceil(mul(root, root)?, scale)?)
}

/// `sup { ν·δ : δ ∈ T_p }` for a concentrated-liquidity pool, rounded up,
/// over the tick window the snapshot covers.
fn arb_v3(pool: &V3Pool, state: &V3State, p0: Price, p1: Price) -> anyhow::Result<U256> {
    arb_v3_below(pool, state, p0, p1, None)?.context("an uncapped arbitrage walk ended early")
}

/// `arb_v3`, or `None` once it is certain to be at least `cap`.
fn arb_v3_below(
    pool: &V3Pool,
    state: &V3State,
    p0: Price,
    p1: Price,
    cap: Option<U512>,
) -> anyhow::Result<Option<U256>> {
    // A net trade is one-directional, so the pool's arbitrage value is the
    // better of the two walks — never their sum.
    let Some(down) = arb_v3_side(pool, state, true, p0, p1, cap)? else {
        return Ok(None);
    };
    let Some(up) = arb_v3_side(pool, state, false, p0, p1, cap)? else {
        return Ok(None);
    };
    Ok(Some(down.max(up)))
}

/// Is trading still profitable when the price has reached `sqrt_price`?
///
/// Selling token0 the marginal rate is γ·(√P/2^96)², so the walk continues
/// while γ·ν_1·√P² > ν_0·2^192. Exact integers on both sides: no rounding
/// decision is taken here, which is what lets the closed-form term below be
/// attached at a boundary the walk provably has not passed.
fn profitable_at(
    sqrt_price: U256,
    zero_for_one: bool,
    fee_ppm: u32,
    p0: Price,
    p1: Price,
) -> anyhow::Result<bool> {
    let square = wmul(sqrt_price, sqrt_price);
    let q192 = wmul(Q96, Q96);
    let net = wide(U256::from(PPM - fee_ppm));
    let ppm = wide(U256::from(PPM));
    if zero_for_one {
        let gain = mul(mul(net, wmul(p1.num, p0.den))?, square)?;
        let cost = mul(mul(ppm, wmul(p0.num, p1.den))?, q192)?;
        Ok(gain > cost)
    } else {
        let gain = mul(mul(net, wmul(p0.num, p1.den))?, q192)?;
        let cost = mul(mul(ppm, wmul(p1.num, p0.den))?, square)?;
        Ok(gain > cost)
    }
}

/// The maximum still available from `sqrt_entry` at constant liquidity `l`,
/// in closed form.
///
/// Selling token0 with x = √P/2^96 the profit peaks at x* = √(ν_0/(γ·ν_1))
/// with value l·(√(ν_1·x_e) − √(ν_0/(γ·x_e)))². The caller attaches this only
/// at a boundary where `profitable_at` is already false, i.e. where the peak
/// provably lies inside the current constant-liquidity range — so no deeper
/// range can contribute, and relaxing the range's far edge can only overstate.
fn arb_v3_peak(
    sqrt_entry: U256,
    liquidity: U256,
    zero_for_one: bool,
    fee_ppm: u32,
    p0: Price,
    p1: Price,
) -> anyhow::Result<U512> {
    if liquidity.is_zero() || sqrt_entry.is_zero() {
        return Ok(U512::ZERO);
    }
    let scale = U512::ONE << (2 * SQRT_SHIFT);
    let net = wide(U256::from(PPM - fee_ppm));
    let ppm = wide(U256::from(PPM));
    let (minuend, subtrahend) = if zero_for_one {
        if p1.is_zero() {
            return Ok(U512::ZERO);
        }
        // ⌈√(ν_1·x_e)⌉ and ⌊√(ν_0/(γ·x_e))⌋
        (
            sqrt_ceil(div_ceil(
                mul(wmul(p1.num, sqrt_entry), scale)?,
                wmul(p1.den, Q96),
            )?),
            sqrt_floor(div_floor(
                mul(mul(mul(wide(p0.num), ppm)?, wide(Q96))?, scale)?,
                mul(mul(wide(p0.den), net)?, wide(sqrt_entry))?,
            )?),
        )
    } else {
        if p0.is_zero() {
            return Ok(U512::ZERO);
        }
        // ⌈√(ν_0/x_e)⌉ and ⌊√(ν_1·x_e/γ)⌋
        (
            sqrt_ceil(div_ceil(
                mul(wmul(p0.num, Q96), scale)?,
                wmul(p0.den, sqrt_entry),
            )?),
            sqrt_floor(div_floor(
                mul(mul(wmul(p1.num, sqrt_entry), ppm)?, scale)?,
                mul(wmul(p1.den, Q96), net)?,
            )?),
        )
    };
    if minuend <= subtrahend {
        return Ok(U512::ZERO);
    }
    let root = minuend - subtrahend;
    div_ceil(mul(mul(root, root)?, wide(liquidity))?, scale)
}

/// One direction of `arb_v3`: walk while trading still pays at the dual
/// prices, then add the closed-form peak of the range it stopped in.
///
/// With a `cap`, `None` once the walk is certain to be worth at least `cap`.
fn arb_v3_side(
    pool: &V3Pool,
    state: &V3State,
    zero_for_one: bool,
    p0: Price,
    p1: Price,
    cap: Option<U512>,
) -> anyhow::Result<Option<U256>> {
    let fee = pool.fee_ppm_for(zero_for_one)?;
    if fee >= PPM || state.sqrt_price.is_zero() {
        return Ok(Some(U256::ZERO));
    }
    let (price_in, price_out) = if zero_for_one { (p0, p1) } else { (p1, p0) };
    if price_out.is_zero() {
        return Ok(Some(U256::ZERO));
    }
    // The LP fee is charged on input: paying `in_curve` to the curve costs
    // in_curve·10⁶/(10⁶−fee) at the door. Rounded DOWN, because it is
    // subtracted.
    let at_the_door = |in_curve: U256| {
        narrow(div_floor(
            wmul(in_curve, U256::from(PPM)),
            wide(U256::from(PPM - fee)),
        )?)
    };
    // Every range the walk takes whole is profitable, so the value of the
    // ranges walked so far can only grow — less the rounding of the sums,
    // which costs at most one input wei at ν and two output wei. Past
    // `cap` plus that slack, the walk's value is at least `cap`.
    let slack = match cap {
        Some(cap) => Some(add(
            add(cap, price_in.value_up(U256::ONE)?)?,
            wide(U256::from(2)),
        )?),
        None => None,
    };
    let enough = |out_up: U256, in_down: U256| -> anyhow::Result<bool> {
        let Some(slack) = slack else {
            return Ok(false);
        };
        let gained = price_out.value_up(out_up)?;
        let spent = price_in.value_down(at_the_door(in_down)?)?;
        Ok(gained.saturating_sub(spent) >= slack)
    };
    // Whole ranges while each next stop is still profitable; where it is not,
    // the peak lies inside the range just entered, at constant liquidity, so
    // no deeper range can contribute. The ranges are the state's own and are
    // shared by every walk of it at any prices (`V3State::depth_walk`).
    let Some(walk) = state.depth_walk(
        zero_for_one,
        |stop| profitable_at(stop, zero_for_one, fee, p0, p1),
        enough,
    )?
    else {
        return Ok(None);
    };
    let peak = match walk.stopped_in {
        Some((entry, liquidity)) => arb_v3_peak(entry, liquidity, zero_for_one, fee, p0, p1)?,
        None => U512::ZERO,
    };
    // The ranges are priced once, on their sums: rounding the sums is no
    // looser than rounding each range, and still never understates.
    let gained = add(price_out.value_up(walk.out_up)?, peak)?;
    let spent = price_in.value_down(at_the_door(walk.in_down)?)?;
    narrow(gained.saturating_sub(spent)).map(Some)
}

// ---- the certificate ----

#[derive(Clone, Debug)]
pub struct Certificate {
    /// Rigorous upper bound on the best output obtainable from the venues this
    /// pair can reach — the allocation question. Output-token wei.
    pub bound: U256,
    /// The quote's own gross output.
    pub achieved: U256,
    /// `bound − achieved`, saturating at zero.
    pub gap: U256,
    /// `gap / achieved`, in basis points scaled by 10⁴ (so 1 unit = 0.0001 bp).
    pub gap_bps_e4: U256,
    /// The same bound over EVERY pool in the snapshot. Its optimum ranges over
    /// arbitrary flows, so it also prices triangular inconsistencies among
    /// pools this trade never touches; on a live catalog that term dominates.
    /// It is a market-condition signal, not a verdict on the allocator.
    pub catalog_bound: U256,
    pub catalog_gap_bps_e4: U256,
    /// The catalog bound widened to the pools the pair budget declined to buy.
    /// Equal to `catalog_bound` when screening is off, which is the only case
    /// where the coverage question goes unmeasured rather than answered.
    pub graph_bound: U256,
    pub graph_gap_bps_e4: U256,
    /// Screened pools evaluated, and those skipped for want of a price. A
    /// skipped pool has no path back to the numeraire through what was loaded,
    /// so it cannot carry a route this quote missed; the count ships anyway,
    /// because a partial measurement that looks total is worse than no
    /// measurement.
    pub screened_pools: usize,
    pub screened_unpriced: usize,
    /// What each screened connector was worth at ν, most valuable first. This
    /// is the attribution that ranks connectors by evidence instead of by edge
    /// count.
    pub screened_value: Vec<ScreenedValue>,
    /// Pools the plan never routed through that still carry arbitrage value at
    /// ν — the venues the bound says were worth something and were not used.
    /// A routed pool always carries positive arb (that is how the bound
    /// reconstructs the achieved output), so counting those would say nothing.
    pub unrouted_pools: usize,
    pub scanned_pools: usize,
    /// The dual point itself — the checkable half of the certificate.
    pub prices: Vec<(Address, Price)>,
    /// False when the bound came out below the achieved output, which weak
    /// duality forbids: a defect signal, never a normal outcome.
    pub consistent: bool,
}

/// A subset of the snapshot's pools.
#[derive(Clone, Debug, Default)]
pub struct PoolSet {
    v3: Vec<bool>,
    v2: Vec<bool>,
    ekubo: Vec<bool>,
}

impl PoolSet {
    fn empty(snap: &Snapshot) -> PoolSet {
        PoolSet {
            v3: vec![false; snap.v3.len()],
            v2: vec![false; snap.v2.len()],
            ekubo: vec![false; snap.ekubo.len()],
        }
    }

    fn add(&mut self, hop: &Hop) {
        match hop.kind {
            HopKind::V3 => self.v3[hop.index] = true,
            HopKind::V2 => self.v2[hop.index] = true,
            HopKind::Ekubo => self.ekubo[hop.index] = true,
        }
    }

    /// The pools a plan actually routed through.
    pub fn of(snap: &Snapshot, plan: &Plan) -> PoolSet {
        let mut set = PoolSet::empty(snap);
        for hop in plan.legs.iter().flat_map(|leg| &leg.path) {
            set.add(hop);
        }
        set
    }

    /// Every pool the router could have reached for this pair — the venue set
    /// the allocator chose from.
    ///
    /// Restricting the bound to this set answers a DIFFERENT question from the
    /// full-catalog bound, and the difference is the whole point. The full
    /// catalog's optimum ranges over arbitrary flows, so it includes every
    /// triangular inconsistency among pools that have nothing to do with this
    /// trade; on the live chain that term dominates, and reading it as
    /// allocation regret would be wrong. Scoped to the reachable venues, the
    /// gap is the quantity W1 actually wants: what a perfect allocator could
    /// have squeezed from the venues this quote was choosing between.
    pub fn reachable_in_universe(snap: &Snapshot, universe: &RouteUniverse) -> PoolSet {
        PoolSet::reachable_over_paths(snap, universe.token_paths())
    }

    /// The same set, for a token skeleton that has no `RouteUniverse` — the
    /// counterfactual's widened path list, which exists only inside one
    /// measurement and is deliberately never made into a servable universe.
    pub fn reachable_over_paths(snap: &Snapshot, token_paths: &[Vec<Address>]) -> PoolSet {
        let mut set = PoolSet::empty(snap);
        for tokens in token_paths {
            let edge_hops: Vec<Vec<Hop>> = tokens
                .windows(2)
                .map(|edge| hops_between(snap, edge[0], edge[1]))
                .collect();
            if edge_hops.iter().any(Vec::is_empty) {
                continue;
            }
            for hops in edge_hops {
                for hop in hops {
                    set.add(&hop);
                }
            }
        }
        set
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn reachable(
        profile: &ChainProfile,
        snap: &Snapshot,
        token_in: Address,
        token_out: Address,
    ) -> PoolSet {
        let universe =
            RouteUniverse::profile_only(profile, token_in, token_out).expect("test route universe");
        Self::reachable_in_universe(snap, &universe)
    }

    fn v3(&self, index: usize) -> bool {
        self.v3.get(index).copied().unwrap_or(false)
    }

    fn v2(&self, index: usize) -> bool {
        self.v2.get(index).copied().unwrap_or(false)
    }
}

/// `g(ν)` for a given dual point: the rigorous upper bound, and how many
/// unrouted pools contributed to it. This is the whole checkable claim — a
/// verifier needs only the snapshot, ν, and this function.
/// `scope` restricts which pools may trade — `None` is the whole catalog. A
/// restricted scope is the dual of a restricted primal, so the result is a
/// rigorous bound for that smaller problem, not an approximation of the
/// larger one. `routed` only attributes; it never changes the bound.
pub fn bound_at(
    snap: &Snapshot,
    token_in: Address,
    amount_in: U256,
    prices: &HashMap<Address, Price>,
    scope: Option<&PoolSet>,
    routed: &PoolSet,
) -> anyhow::Result<(U256, usize)> {
    bound_below(snap, token_in, amount_in, prices, scope, routed, None)?
        .context("an uncapped bound ended early")
}

/// `bound_at`, or `None` as soon as the bound is certain to be at least
/// `cap`. Every term is non-negative, so a search that only keeps points
/// below its best need not finish pricing one that is not.
fn bound_below(
    snap: &Snapshot,
    token_in: Address,
    amount_in: U256,
    prices: &HashMap<Address, Price>,
    scope: Option<&PoolSet>,
    routed: &PoolSet,
    cap: Option<U256>,
) -> anyhow::Result<Option<(U256, usize)>> {
    let price_in = prices
        .get(&token_in)
        .copied()
        .context("no dual price for the input token")?;
    let mut total = price_in.value_up(amount_in)?;
    let cap = cap.map(wide);
    // What the pools still to come may add before the bound reaches `cap`.
    let left = |total: U512| -> Option<Option<U512>> {
        match cap {
            Some(cap) if total >= cap => None,
            Some(cap) => Some(Some(cap - total)),
            None => Some(None),
        }
    };
    let mut unrouted = 0usize;
    for (i, (pool, state)) in snap.v3.iter().enumerate() {
        if scope.is_some_and(|scope| !scope.v3(i)) {
            continue;
        }
        let Some(remaining) = left(total) else {
            return Ok(None);
        };
        let p0 = prices.get(&pool.token0).copied().unwrap_or(Price::ZERO);
        let p1 = prices.get(&pool.token1).copied().unwrap_or(Price::ZERO);
        let Some(arb) = arb_v3_below(pool, state, p0, p1, remaining)? else {
            return Ok(None);
        };
        if !arb.is_zero() && !routed.v3(i) {
            unrouted += 1;
        }
        total = add(total, wide(arb))?;
    }
    for (i, (pool, state)) in snap.v2.iter().enumerate() {
        if scope.is_some_and(|scope| !scope.v2(i)) {
            continue;
        }
        let p0 = prices.get(&pool.token0).copied().unwrap_or(Price::ZERO);
        let p1 = prices.get(&pool.token1).copied().unwrap_or(Price::ZERO);
        let arb = arb_v2(pool, state, p0, p1)?;
        if !arb.is_zero() && !routed.v2(i) {
            unrouted += 1;
        }
        total = add(total, wide(arb))?;
    }
    if left(total).is_none() {
        return Ok(None);
    }
    Ok(Some((narrow(total)?, unrouted)))
}

// ---- the third scope: what the pair budget declined to buy ----
//
// `bound` asks what a perfect allocator could have taken from the venues this
// pair's skeletons reach. `catalog_bound` asks it of every pool in the
// snapshot. Neither can see a token the universe never named, because the
// snapshot holds no state for it — so the coverage a tight pair budget
// declined to buy is invisible to both, at any gap.
//
// Screened pools close that. They are read at the same canonical block, never
// enter `Snapshot`, and are priced at a dual point that EXTENDS the certified
// one: every token the quote already priced keeps its price exactly, so
// `bound` and `gap_bps` are bit-identical whether screening ran or not. A
// diagnostic that moved the number it diagnoses would be worthless.
//
// Pinning costs tightness, never validity — weak duality holds for any ν ≥ 0.
// And a loose screen OVERSTATES what a connector is worth, which is the safe
// direction for a test whose failure mode is discarding a connector that could
// have helped.

/// One screened connector's contribution to the graph bound, in output wei.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScreenedValue {
    pub connector: Address,
    /// `Σ arb_p(ν)` over the screened pools touching this token. Zero means the
    /// token is provably worthless to this quote at these prices.
    pub arb: U256,
    /// The EXTENDED price this connector was valued at — the relaxation's
    /// output, absent from `Certificate::prices` because that field carries the
    /// certified dual point alone.
    ///
    /// Publishing it is what makes `graph_bound` re-evaluatable. `bound` and
    /// `catalog_bound` can already be recomputed by a holder from `prices` and
    /// the block's pool states; without this field `graph_bound` was the one
    /// number in the certificate that had to be taken on trust.
    ///
    /// It is also the term that decides `arb`. A relaxed price overstated by κ
    /// inflates this connector's arb by roughly `½·TVL·(√κ−1)²`, so comparing
    /// it against any independent reference reads κ off directly — see
    /// `the maintainers' research notes` §11. The solver forms no opinion
    /// about which reference is right; it publishes the number it used.
    pub price: Price,
    /// The same sum, at the price that MINIMISES it rather than the one the
    /// relaxation produced.
    ///
    /// Weak duality holds at every `ν ≥ 0`, and no pool in the served universe
    /// touches a screened connector, so this token's coordinate is free. `arb`
    /// takes the max-product relaxation's answer, which is an upper bound on the
    /// price by construction; this takes the argmin. The gap between the two is
    /// §11's κ, priced in output wei rather than inverted from a TVL ratio.
    ///
    /// Zero here is a **proof**: it says a price exists at which no screened pool
    /// touching this connector is arbitrageable, so routing through it cannot
    /// beat the served quote by more than the certified gap. See
    /// `the maintainers' research notes`.
    pub min_arb: U256,
    /// The price `min_arb` was evaluated at, so the minimum is checkable by the
    /// same holder who can re-evaluate `arb` from `price`.
    pub min_price: Price,
}

/// Every token any snapshot pool touches, priced or not.
///
/// This is the pin set that makes `catalog_bound` reusable at the extended
/// point. Without it the pin is "already priced", which leaves a snapshot
/// token that `dual_prices` left at zero free to acquire a price here — and a
/// token going from zero to positive SHRINKS its pools' arb, because a zero
/// price values that side's whole reserve as free. `catalog_bound` would then
/// be wrong for the extended vector and the two scopes would stop nesting.
fn snapshot_tokens(snap: &Snapshot) -> HashSet<Address> {
    let mut tokens = HashSet::with_capacity(2 * (snap.v3.len() + snap.v2.len()));
    for (pool, _) in &snap.v3 {
        tokens.insert(pool.token0);
        tokens.insert(pool.token1);
    }
    for (pool, _) in &snap.v2 {
        tokens.insert(pool.token0);
        tokens.insert(pool.token1);
    }
    tokens
}

/// Prices for tokens that appear only on screened pools, with every price the
/// quote already carries — and every token the snapshot holds — left exactly
/// as it was.
///
/// Relaxation is max-product over screened edges, the same rule `dual_prices`
/// uses, restricted so a pinned token can be read but never written.
fn extend_prices_to_screened(
    screening: &ScreeningPools,
    prices: &HashMap<Address, Price>,
    pinned: &HashSet<Address>,
) -> anyhow::Result<HashMap<Address, Price>> {
    let mut edges: Vec<(Address, Address, Price)> = Vec::new();
    let mut tokens: Vec<Address> = Vec::new();
    let note = |token: Address, tokens: &mut Vec<Address>| {
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    };
    for (pool, state) in &screening.v3 {
        note(pool.token0, &mut tokens);
        note(pool.token1, &mut tokens);
        if let Some(rate) = marginal_v3(pool, state, true)? {
            edges.push((pool.token0, pool.token1, rate));
        }
        if let Some(rate) = marginal_v3(pool, state, false)? {
            edges.push((pool.token1, pool.token0, rate));
        }
    }
    for (pool, state) in &screening.v2 {
        note(pool.token0, &mut tokens);
        note(pool.token1, &mut tokens);
        // A screened pool is never traded, so its marginal rate is its spot
        // rate: the zero-input form of the same slope the routed pools use.
        if let Some(rate) = marginal_v2(pool, state, true, U256::ZERO)? {
            edges.push((pool.token0, pool.token1, rate));
        }
        if let Some(rate) = marginal_v2(pool, state, false, U256::ZERO)? {
            edges.push((pool.token1, pool.token0, rate));
        }
    }

    let mut extended = prices.clone();
    // Deterministic relaxation order: HashMap iteration decides nothing here
    // either, for the same reason it decides nothing in `dual_prices`.
    edges.sort_unstable_by_key(|&(from, to, _)| (from, to));
    for _ in 0..tokens.len().max(1) {
        let mut changed = false;
        for &(from, to, rate) in &edges {
            // PINNED: a token the quote already priced, or one any snapshot
            // pool touches, keeps whatever the certified point gave it. These
            // two lines are what make the extension non-perturbing — the first
            // for the numbers already reported, the second for `catalog_bound`.
            if prices.contains_key(&from) || pinned.contains(&from) {
                continue;
            }
            let value = extended.get(&to).copied().unwrap_or(Price::ZERO);
            if value.is_zero() {
                continue;
            }
            let candidate = rate.compose(value)?;
            let current = extended.get(&from).copied().unwrap_or(Price::ZERO);
            if candidate.greater(current)? {
                extended.insert(from, candidate);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(extended)
}

/// `Σ arb_p(ν)` over screened pools, attributed to the connector each pool
/// hangs off.
///
/// A pool whose token never received a price is SKIPPED and counted, never
/// valued at zero: `ν_t = 0` would price that token's whole reserve as free and
/// blow the bound up. An unpriced screened token is one with no path back to
/// the numeraire through the pools that were loaded, so no route through it
/// exists to be missed — but the count ships so the number is never silently
/// partial.
/// The arb every screened pool touching `connector` contributes when that
/// connector is priced at `z` and everything else keeps `prices`.
///
/// Convex in `z`: each `arb_p` is a supremum of linear functions of ν, so it is
/// convex in any single coordinate, and a sum of convex functions is convex.
/// Each pool is also identically zero on its own fee band, so the objective has
/// a flat floor wherever those bands overlap.
fn connector_arb_at(
    screening: &ScreeningPools,
    prices: &HashMap<Address, Price>,
    connector: Address,
    z: Price,
) -> anyhow::Result<U256> {
    let priced = |token: Address| -> Price {
        if token == connector {
            z
        } else {
            prices.get(&token).copied().unwrap_or(Price::ZERO)
        }
    };
    let mut total = U256::ZERO;
    for (pool, state) in &screening.v3 {
        if pool.token0 != connector && pool.token1 != connector {
            continue;
        }
        let (p0, p1) = (priced(pool.token0), priced(pool.token1));
        if p0.is_zero() || p1.is_zero() {
            continue;
        }
        total = total.saturating_add(arb_v3(pool, state, p0, p1)?);
    }
    for (pool, state) in &screening.v2 {
        if pool.token0 != connector && pool.token1 != connector {
            continue;
        }
        let (p0, p1) = (priced(pool.token0), priced(pool.token1));
        if p0.is_zero() || p1.is_zero() {
            continue;
        }
        total = total.saturating_add(arb_v2(pool, state, p0, p1)?);
    }
    Ok(total)
}

/// Price each screened connector to MINIMISE what it contributes, instead of
/// relaxing it upward.
///
/// `extend_prices_to_screened` runs a max-product relaxation — an upper bound on
/// a token's price by construction — and §11 inverted the resulting arb terms to
/// implied errors of κ = 1.22 to 2.48 on tokens the quote never touched. Weak
/// duality holds at every `ν ≥ 0`, so those coordinates are free and the
/// tightest statement available at fixed `prices` takes the argmin.
///
/// **Separable, one scalar per connector.** A screened connector attaches only
/// to the endpoints; no `(c, c′)` pool exists, because no connector mesh does.
/// So minimising each coordinate independently is minimising jointly, and this
/// is `|screened|` one-dimensional convex problems rather than one large one.
///
/// The bracket is the interval spanned by the spot price each touching pool
/// implies for the connector: outside it every pool is arbitrageable in the same
/// direction, so the objective is monotone there and the minimum is interior or
/// at an edge. The search is geometric bisection on that bracket for a fixed
/// iteration count — any `z` yields a valid bound, so this trades no soundness
/// for its termination, only tightness.
fn minimising_prices_for_screened(
    screening: &ScreeningPools,
    prices: &HashMap<Address, Price>,
    screened: &[Address],
) -> anyhow::Result<HashMap<Address, Price>> {
    /// Enough to place the minimum of a smooth convex function to well past the
    /// precision `Price` carries, and a hard bound on the work per connector.
    const STEPS: usize = 48;
    let mut chosen = HashMap::new();
    for &connector in screened {
        // Every rate out of this connector, composed with its counterparty's
        // certified price: the same construction the relaxation uses, before it
        // takes the maximum.
        let mut implied: Vec<Price> = Vec::new();
        let mut note = |from: Address, rate: Option<Price>, to: Address| {
            if from != connector {
                return;
            }
            let (Some(rate), Some(&value)) = (rate, prices.get(&to)) else {
                return;
            };
            if let Ok(price) = rate.compose(value)
                && !price.is_zero()
            {
                implied.push(price);
            }
        };
        for (pool, state) in &screening.v3 {
            note(pool.token0, marginal_v3(pool, state, true)?, pool.token1);
            note(pool.token1, marginal_v3(pool, state, false)?, pool.token0);
        }
        for (pool, state) in &screening.v2 {
            note(
                pool.token0,
                marginal_v2(pool, state, true, U256::ZERO)?,
                pool.token1,
            );
            note(
                pool.token1,
                marginal_v2(pool, state, false, U256::ZERO)?,
                pool.token0,
            );
        }
        let Some(&first) = implied.first() else {
            continue;
        };
        let mut lo = first;
        let mut hi = first;
        for &price in &implied[1..] {
            if price.greater(hi)? {
                hi = price;
            } else if lo.greater(price)? {
                lo = price;
            }
        }
        // Geometric midpoints, so the search is scale-free the way prices are.
        let midpoint = |a: Price, b: Price| -> anyhow::Result<Price> {
            Price::from_ratio(
                sqrt_floor(wmul(a.num, b.num)),
                sqrt_ceil(wmul(a.den, b.den)),
            )
        };
        for _ in 0..STEPS {
            let mid = midpoint(lo, hi)?;
            let left = midpoint(lo, mid)?;
            let right = midpoint(mid, hi)?;
            if !right.greater(left)? {
                break;
            }
            if connector_arb_at(screening, prices, connector, left)?
                <= connector_arb_at(screening, prices, connector, right)?
            {
                hi = right;
            } else {
                lo = left;
            }
        }
        let mid = midpoint(lo, hi)?;
        let mut best = (connector_arb_at(screening, prices, connector, mid)?, mid);
        // The bracket edges are where a band boundary sits, and a piecewise
        // objective can put its floor exactly there. Checking them costs two
        // evaluations and removes the one case bisection can walk past.
        for edge in [lo, hi] {
            let value = connector_arb_at(screening, prices, connector, edge)?;
            if value < best.0 {
                best = (value, edge);
            }
        }
        chosen.insert(connector, best.1);
    }
    Ok(chosen)
}

fn screened_arb(
    screening: &ScreeningPools,
    prices: &HashMap<Address, Price>,
    screened: &[Address],
) -> anyhow::Result<(U512, Vec<ScreenedValue>, usize)> {
    let mut total = U512::ZERO;
    let mut unpriced = 0usize;
    let mut values: Vec<ScreenedValue> = screened
        .iter()
        .map(|&connector| ScreenedValue {
            connector,
            arb: U256::ZERO,
            // Zero for a connector the extension never priced, which is the
            // same condition that makes every pool touching it skip into
            // `unpriced` below. The pair reads consistently either way.
            price: prices.get(&connector).copied().unwrap_or(Price::ZERO),
            min_arb: U256::ZERO,
            min_price: Price::ZERO,
        })
        .collect();
    let mut credit = |token0: Address, token1: Address, arb: U256| {
        if let Some(value) = values
            .iter_mut()
            .find(|value| value.connector == token0 || value.connector == token1)
        {
            value.arb = value.arb.saturating_add(arb);
        }
    };
    for (pool, state) in &screening.v3 {
        let p0 = prices.get(&pool.token0).copied().unwrap_or(Price::ZERO);
        let p1 = prices.get(&pool.token1).copied().unwrap_or(Price::ZERO);
        if p0.is_zero() || p1.is_zero() {
            unpriced += 1;
            continue;
        }
        let arb = arb_v3(pool, state, p0, p1)?;
        credit(pool.token0, pool.token1, arb);
        total = add(total, wide(arb))?;
    }
    for (pool, state) in &screening.v2 {
        let p0 = prices.get(&pool.token0).copied().unwrap_or(Price::ZERO);
        let p1 = prices.get(&pool.token1).copied().unwrap_or(Price::ZERO);
        if p0.is_zero() || p1.is_zero() {
            unpriced += 1;
            continue;
        }
        let arb = arb_v2(pool, state, p0, p1)?;
        credit(pool.token0, pool.token1, arb);
        total = add(total, wide(arb))?;
    }
    // The same sum at the price that minimises it. Published beside `arb` rather
    // than replacing it: `graph_bound` keeps the relaxation's answer, and the
    // pair is what makes the difference between the two measurable before
    // anything is decided on it.
    let minimised = minimising_prices_for_screened(screening, prices, screened)?;
    for value in &mut values {
        let Some(&price) = minimised.get(&value.connector) else {
            continue;
        };
        value.min_price = price;
        value.min_arb = connector_arb_at(screening, prices, value.connector, price)?;
    }
    values.sort_unstable_by_key(|value| (std::cmp::Reverse(value.arb), value.connector));
    Ok((total, values, unpriced))
}

/// `g(ν')` over the snapshot AND the screened pools.
///
/// The snapshot term is `catalog_bound` verbatim, and that reuse is a theorem
/// rather than an approximation: `extend_prices_to_screened` pins every token
/// any snapshot pool touches, so the extended vector agrees with `prices` on
/// every input `bound_at` would read. Re-evaluating it would return the same
/// number for a second full pass over the catalog on the quote path.
fn graph_bound_at(
    catalog: U256,
    screening: &ScreeningPools,
    prices: &HashMap<Address, Price>,
    screened: &[Address],
) -> anyhow::Result<(U256, Vec<ScreenedValue>, usize)> {
    let (screened_total, values, unpriced) = screened_arb(screening, prices, screened)?;
    Ok((
        narrow(add(wide(catalog), screened_total)?)?,
        values,
        unpriced,
    ))
}

// ---- the gradient (the steering half: choosing ν) ----
//
// Everything from here to `tighten` is FLOATING POINT ON PURPOSE, and none of
// it touches the bound. It decides where to look next; `bound_at` re-derives
// the number in exact integers at whatever point the search lands on. A wrong
// gradient costs iterations. It cannot cost validity. That asymmetry is what
// lets the search be fast and the claim be rigorous at the same time.

fn to_f64(x: U256) -> f64 {
    let bits = x.bit_len();
    if bits <= 64 {
        return x.as_limbs()[0] as f64;
    }
    let shift = bits - 53;
    (x >> shift).as_limbs()[0] as f64 * (shift as f64).exp2()
}

impl Price {
    fn to_f64(self) -> f64 {
        to_f64(self.num) / to_f64(self.den)
    }
}

/// The optimal arbitrage trade against a constant-product pool: what it hands
/// the router, per token, negative where the router pays — plus the pool's
/// CONDUCTANCE at that maximizer, ∂(ν·flow)/∂log ν along the pool's edge.
///
/// Same maximizer `arb_v2_side` bounds the value of — u\* = √(ν_out·C·A·B/ν_in),
/// spending (u\*−A)/B to receive C·(u\*−A)/u\*. Differentiating at the stopping
/// condition ν_out·C·A·B = ν_in·u\*² gives the symmetric weight
/// w = ν_out·C·A/(2u\*): the Hessian of `g` restricted to this pool is the
/// edge Laplacian w·[[1,−1],[−1,1]] in log-price coordinates.
fn flow_v2(pool: &V2Pool, state: &V2State, p0: Price, p1: Price) -> ([f64; 2], f64) {
    let side = |reserve_in: U256, reserve_out: U256, price_in: Price, price_out: Price| {
        let fee_bps = pool.fee_bps.min(BPS);
        let (a, b, c) = (
            to_f64(reserve_in) * f64::from(BPS),
            f64::from(BPS - fee_bps),
            to_f64(reserve_out),
        );
        let (nu_in, nu_out) = (price_in.to_f64(), price_out.to_f64());
        if nu_in <= 0.0 || nu_out * c * b <= nu_in * a {
            return None; // inside the no-trade band
        }
        let peak = (nu_out * c * a * b / nu_in).sqrt();
        Some((
            (peak - a) / b,
            c * (peak - a) / peak,
            nu_out * c * a / (2.0 * peak),
        ))
    };
    if let Some((spent, received, weight)) = side(state.reserve0, state.reserve1, p0, p1) {
        ([-spent, received], weight)
    } else if let Some((spent, received, weight)) = side(state.reserve1, state.reserve0, p1, p0) {
        ([received, -spent], weight)
    } else {
        ([0.0, 0.0], 0.0)
    }
}

/// The same, for concentrated liquidity: walk to the price at which the
/// marginal trade stops paying, accumulating what changes hands — plus the
/// conductance at the stop, ∂(ν·flow)/∂log ν along the pool's edge.
///
/// This mirrors `arb_v3_side`'s walk rather than sharing it, because the two
/// want different things from the same traversal — that one must round every
/// step outward to stay a bound, this one wants the amounts themselves.
///
/// Conductance is read at the stopping point: w = ν₁·L·√P\*/2 (selling
/// token0) or ν₀·L/(2·√P\*) (selling token1), with L the liquidity of the
/// stopping segment and √P\* in Q96. When the walk stops at the INTERIOR
/// price target this is the exact curvature. When it ends pinned at a tick
/// wall or the coverage edge, the same formula at the wall is the one-sided
/// (semismooth) element — the curvature the pool presents to a *retreating*
/// price. The two-sided derivative there is genuinely kinked (zero on the
/// pinned side), and emitting the positive side is what lets Newton back out
/// of a kink instead of stalling against its zero face; a step that goes the
/// wrong way is caught by the accept/reject loop upstairs.
fn flow_v3(
    pool: &V3Pool,
    state: &V3State,
    p0: Price,
    p1: Price,
) -> anyhow::Result<([f64; 2], f64)> {
    let mut flow = [0.0f64; 2];
    let mut weight = 0.0f64;
    for zero_for_one in [true, false] {
        let fee = pool.fee_ppm_for(zero_for_one)?;
        if fee >= PPM || state.sqrt_price.is_zero() {
            continue;
        }
        let net = f64::from(PPM - fee) / f64::from(PPM);
        let (nu0, nu1) = (p0.to_f64(), p1.to_f64());
        if nu0 <= 0.0 || nu1 <= 0.0 {
            continue;
        }
        // Selling token0 the marginal rate is γ·(√P)², so the trade stops at
        // √P = √(ν_0/(γ·ν_1)); selling token1, at √(γ·ν_0/ν_1).
        let target = if zero_for_one {
            (nu0 / (net * nu1)).sqrt()
        } else {
            (net * nu0 / nu1).sqrt()
        } * to_f64(Q96);
        let mut sqrt_price = to_f64(state.sqrt_price);
        if (zero_for_one && target >= sqrt_price) || (!zero_for_one && target <= sqrt_price) {
            continue; // this direction is inside the band
        }
        // Liquidity stays exact across crossings and is only widened for the
        // arithmetic — a round trip through f64 would lose the low bits of a
        // 2^96 tick delta and quietly corrupt every range below it.
        let (mut depth, mut pos) = (state.liquidity, state.pos);
        let (mut zero, mut one) = (0.0f64, 0.0f64);
        let mut side_weight = 0.0f64;
        for _ in 0..=state.ticks.len() {
            let (stop, crosses) = next_stop(state, zero_for_one, pos)?;
            let wall = to_f64(stop);
            let reached = if zero_for_one {
                wall.max(target)
            } else {
                wall.min(target)
            };
            if (zero_for_one && reached >= sqrt_price) || (!zero_for_one && reached <= sqrt_price) {
                break;
            }
            let (lo, hi) = if zero_for_one {
                (reached, sqrt_price)
            } else {
                (sqrt_price, reached)
            };
            let q96 = to_f64(Q96);
            let liquidity = to_f64(depth);
            let amount1 = liquidity * (hi - lo) / q96;
            let amount0 = liquidity * q96 * (hi - lo) / (lo * hi);
            if zero_for_one {
                zero -= amount0 / net;
                one += amount1;
            } else {
                zero += amount0;
                one -= amount1 / net;
            }
            sqrt_price = reached;
            // A later segment overwrites an earlier one, so the value that
            // survives belongs to the stopping segment — exact at an interior
            // stop, the one-sided element at a wall (zero across a gap, where
            // there is no liquidity on the retreat side either).
            side_weight = if zero_for_one {
                nu1 * liquidity * reached / (2.0 * q96)
            } else {
                nu0 * liquidity * q96 / (2.0 * reached)
            };
            if !crosses || reached == target {
                break;
            }
            let delta = state.ticks[if zero_for_one { pos - 1 } else { pos }].liquidity_net;
            depth = cross_liquidity(depth, delta, zero_for_one)?;
            if zero_for_one {
                pos -= 1;
            } else {
                pos += 1;
            }
        }
        // A pool trades one way at a time; the profitable direction wins.
        if zero * p0.to_f64() + one * p1.to_f64() > flow[0] * p0.to_f64() + flow[1] * p1.to_f64() {
            flow = [zero, one];
            weight = side_weight;
        }
    }
    Ok((flow, weight))
}

/// ∂g/∂(log ν): how much value the router is left holding in each token once
/// every pool has been arbitraged at ν.
///
/// Danskin's theorem does the work — the derivative of a supremum is taken at
/// the maximizer, so ∇g is simply the arbitrage flow, and ∇g = 0 says those
/// flows clear every token except the one being bought. The dual of routing is
/// a market-clearing problem, which is the semi-discrete transport structure
/// §5.1 of the frontier survey identifies.
///
/// LOG coordinates, i.e. each component multiplied by its own ν, so every
/// entry is denominated in output-token units and coordinates become
/// comparable. That is not a nicety: ν spans 2^-41 to 2^44 on a live snapshot,
/// and any method stepping in ν directly is hopeless across that spread.
fn log_gradient(
    snap: &Snapshot,
    token_in: Address,
    amount_in: U256,
    prices: &HashMap<Address, Price>,
    scope: Option<&PoolSet>,
) -> anyhow::Result<HashMap<Address, f64>> {
    Ok(model(snap, token_in, amount_in, prices, scope)?.1)
}

/// One pool edge of the model Hessian: the two tokens and the conductance at
/// the pool's arbitrage stopping point.
type CurvatureEdge = (Address, Address, f64);

/// `g(ν)` and its log-gradient in one pass, both in floating point.
///
/// The search runs entirely on THIS, not on `bound_at`. Every trial point a
/// line search rejects is a point whose exact-integer bound nobody ever needed,
/// and paying 512-bit arithmetic for rejected points is what made the search
/// expensive enough to have to ration. `bound_at` is called once, on the point
/// the search settles at, and that call is what the certificate reports.
///
/// The two agree to dust — same maximizers, same fee arithmetic — but nothing
/// depends on them agreeing. A model that lies merely picks a worse ν, and a
/// worse ν is a looser bound, never an invalid one.
fn model(
    snap: &Snapshot,
    token_in: Address,
    amount_in: U256,
    prices: &HashMap<Address, Price>,
    scope: Option<&PoolSet>,
) -> anyhow::Result<(f64, HashMap<Address, f64>, Vec<CurvatureEdge>)> {
    let price_of =
        |token: &Address| -> f64 { prices.get(token).copied().unwrap_or(Price::ZERO).to_f64() };
    let mut leftover: HashMap<Address, f64> = HashMap::new();
    *leftover.entry(token_in).or_default() += to_f64(amount_in);
    let mut objective = to_f64(amount_in) * price_of(&token_in);
    let mut edges: Vec<CurvatureEdge> = Vec::new();
    let mut charge = |leftover: &mut HashMap<Address, f64>,
                      edges: &mut Vec<CurvatureEdge>,
                      token0: Address,
                      token1: Address,
                      flow: [f64; 2],
                      weight: f64| {
        *leftover.entry(token0).or_default() += flow[0];
        *leftover.entry(token1).or_default() += flow[1];
        // arb_p(ν) evaluated at its own maximizer is just ν·δ*.
        objective += (flow[0] * price_of(&token0) + flow[1] * price_of(&token1)).max(0.0);
        if weight > 0.0 && weight.is_finite() {
            edges.push((token0, token1, weight));
        }
    };
    for (i, (pool, state)) in snap.v3.iter().enumerate() {
        if scope.is_some_and(|scope| !scope.v3(i)) {
            continue;
        }
        let p0 = prices.get(&pool.token0).copied().unwrap_or(Price::ZERO);
        let p1 = prices.get(&pool.token1).copied().unwrap_or(Price::ZERO);
        let (flow, weight) = flow_v3(pool, state, p0, p1)?;
        charge(
            &mut leftover,
            &mut edges,
            pool.token0,
            pool.token1,
            flow,
            weight,
        );
    }
    for (i, (pool, state)) in snap.v2.iter().enumerate() {
        if scope.is_some_and(|scope| !scope.v2(i)) {
            continue;
        }
        let p0 = prices.get(&pool.token0).copied().unwrap_or(Price::ZERO);
        let p1 = prices.get(&pool.token1).copied().unwrap_or(Price::ZERO);
        let (flow, weight) = flow_v2(pool, state, p0, p1);
        charge(
            &mut leftover,
            &mut edges,
            pool.token0,
            pool.token1,
            flow,
            weight,
        );
    }
    let gradient = leftover
        .into_iter()
        .map(|(token, amount)| {
            let value = price_of(&token);
            (token, amount * value)
        })
        .collect();
    Ok((objective, gradient, edges))
}

/// Solve a small dense linear system by Gaussian elimination with partial
/// pivoting. `None` when numerically singular. The systems here are (movable
/// tokens)² — single digits on this chain — so dense and direct is the tool.
fn solve_dense(mut a: Vec<Vec<f64>>, mut b: Vec<f64>) -> Option<Vec<f64>> {
    let n = b.len();
    for col in 0..n {
        let pivot = (col..n).max_by(|&x, &y| {
            a[x][col]
                .abs()
                .partial_cmp(&a[y][col].abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        })?;
        if !a[pivot][col].is_finite() || a[pivot][col].abs() <= f64::MIN_POSITIVE {
            return None;
        }
        a.swap(col, pivot);
        b.swap(col, pivot);
        for row in col + 1..n {
            let (head, tail) = a.split_at_mut(row);
            let pivot_row = &head[col];
            let target = &mut tail[0];
            let factor = target[col] / pivot_row[col];
            for (entry, above) in target[col..].iter_mut().zip(&pivot_row[col..]) {
                *entry -= factor * above;
            }
            b[row] -= factor * b[col];
        }
    }
    let mut x = vec![0.0f64; n];
    for col in (0..n).rev() {
        let mut sum = b[col];
        for k in col + 1..n {
            sum -= a[col][k] * x[k];
        }
        x[col] = sum / a[col][col];
        if !x[col].is_finite() {
            return None;
        }
    }
    Some(x)
}

/// Minimize `g` over the dual point, in log-price coordinates.
///
/// This pass has NO correctness stake. `g` is convex and every evaluation of
/// it is already a valid bound, so the search may stop anywhere, take any
/// step, and run to any budget — the emitted number stays rigorous. That is
/// the practical cash value of "validity does not depend on how ν was chosen":
/// the search can be as crude as the latency budget wants.
///
/// Why it is needed. The starting point prices each token at the best marginal
/// rate its pools offer, and one thin pool can set that rate for a whole
/// token. Every deep pool priced against it then reports arbitrage bounded by
/// ITS OWN depth rather than by the thin pool's — a large number standing for
/// an opportunity that does not exist at size. On the live catalog that is the
/// difference between certifying WETH→USDG at 205536 bps and at 0.0028.
///
/// Steps are multiplicative, which suits a price: the natural geometry here is
/// ratio, not difference. The numeraire never moves — see `dual_prices`.
#[allow(clippy::too_many_arguments)] // dual point, problem, scope, budget
pub fn tighten(
    snap: &Snapshot,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    prices: &mut HashMap<Address, Price>,
    scope: Option<&PoolSet>,
    routed: &PoolSet,
    budget: usize,
) -> anyhow::Result<U256> {
    tighten_with_solver_budget(
        snap,
        token_in,
        token_out,
        amount_in,
        prices,
        scope,
        routed,
        budget,
        &SolverBudget::unlimited(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn tighten_with_solver_budget(
    snap: &Snapshot,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    prices: &mut HashMap<Address, Price>,
    scope: Option<&PoolSet>,
    routed: &PoolSet,
    iteration_budget: usize,
    solver_budget: &SolverBudget,
) -> anyhow::Result<U256> {
    solver_budget.checkpoint("certificate tightening")?;
    let mut best = bound_at(snap, token_in, amount_in, prices, scope, routed)?.0;
    let mut movable: Vec<Address> = prices
        .iter()
        .filter(|(token, price)| **token != token_out && !price.is_zero())
        .map(|(token, _)| *token)
        .collect();
    movable.sort_unstable();
    if movable.is_empty() {
        return Ok(best);
    }
    let start: Vec<Price> = movable.iter().map(|token| prices[token]).collect();
    // Damped Newton on the float model — ledger item 9 of the frontier survey
    // (§5.1). The dual shares the semi-discrete transport structure, so its
    // Hessian in log-price coordinates is a conductance-weighted graph
    // Laplacian: one edge per pool whose arbitrage stops at an interior
    // price, weighted by the marginal liquidity there, with the gauge
    // direction killed by the pinned numeraire. The model walk computes those
    // weights for free. Levenberg damping stands in for KMT's two-invariant
    // backtracking: a rejected step multiplies λ — toward a short gradient
    // step, safe at the kinks where the Laplacian understates curvature —
    // and an accepted one divides it, toward the pure Newton step that
    // converges quadratically. BFGS sat here before and stalled exactly at
    // those kinks: secant curvature went wrong, the line search failed twice,
    // and the search exited with budget unspent — SLVR→USDG froze at 21.7 bps
    // at every budget from 128 to 2048.
    //
    // Only tightness rides on any of this. The search runs entirely on the
    // floating-point model; `bound_at` is called once at the end, on the point
    // it settles at, and THAT is the certificate. Rejected trial points never
    // cost exact-integer arithmetic, which is what makes the budget buy
    // iterations instead of precision nobody reads.
    let n = movable.len();
    let index: HashMap<Address, usize> = movable
        .iter()
        .enumerate()
        .map(|(i, token)| (*token, i))
        .collect();
    let evaluate =
        |prices: &HashMap<Address, Price>| -> anyhow::Result<(f64, Vec<f64>, Vec<CurvatureEdge>)> {
            let (value, gradient, edges) = model(snap, token_in, amount_in, prices, scope)?;
            Ok((
                value,
                movable
                    .iter()
                    .map(|token| gradient.get(token).copied().unwrap_or(0.0))
                    .collect(),
                edges,
            ))
        };
    let rescale = |prices: &mut HashMap<Address, Price>,
                   base: &[Price],
                   push: &[f64]|
     -> anyhow::Result<()> {
        for ((token, price), factor) in movable.iter().zip(base).zip(push) {
            // Rationalize the FACTOR, not ν: the numerator then carries the
            // whole step and a coordinate can move by one part in a billion
            // without its magnitude being rounded away.
            let scaled = (factor.exp() * 1e9) as u128;
            if scaled == 0 {
                continue;
            }
            prices.insert(
                *token,
                Price::from_ratio(
                    wmul(price.num, U256::from(scaled)),
                    wmul(price.den, U256::from(1_000_000_000u64)),
                )?,
            );
        }
        Ok(())
    };

    let (mut objective, mut gradient, mut edges) = evaluate(prices)?;
    let mut settled: Vec<Price> = movable.iter().map(|token| prices[token]).collect();
    let mut spent = 0usize;
    let mut lambda = 1e-4f64;
    while spent < iteration_budget {
        solver_budget.checkpoint("certificate tightening")?;
        let norm = gradient.iter().fold(0.0f64, |acc, g| acc.max(g.abs()));
        if norm.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) || !norm.is_finite() {
            break; // the flows already clear: this IS the minimum
        }
        // Assemble the Laplacian over the movable coordinates. An edge into
        // the numeraire (or an unpriced token) grounds its movable end — only
        // the diagonal survives — which is what makes the damped system
        // positive definite whenever anything connects to the numeraire.
        let mut hessian = vec![vec![0.0f64; n]; n];
        for (token0, token1, weight) in &edges {
            match (index.get(token0), index.get(token1)) {
                (Some(&i), Some(&j)) => {
                    hessian[i][i] += weight;
                    hessian[j][j] += weight;
                    hessian[i][j] -= weight;
                    hessian[j][i] -= weight;
                }
                (Some(&i), None) => hessian[i][i] += weight,
                (None, Some(&j)) => hessian[j][j] += weight,
                (None, None) => {}
            }
        }
        // The ridge is gradient-regularized Newton (arXiv:2112.02089): damping
        // ∝ √‖∇G‖ shrinks with the gradient itself, so the superlinear tail
        // switches on without waiting for an accept streak to grind λ down;
        // λ remains the adaptive constant (×16 on reject, ÷4 on accept). The
        // √(scale·norm) geometric mean keeps the ridge in Hessian units, and
        // when every pool sits on a kink the Laplacian is empty, scale = norm,
        // and the system degrades to a capped gradient step as before.
        let scale = (0..n)
            .map(|i| hessian[i][i])
            .fold(0.0f64, f64::max)
            .max(norm);
        let ridge = lambda * (scale * norm).sqrt();
        let mut system = hessian;
        for (i, row) in system.iter_mut().enumerate() {
            row[i] += ridge;
        }
        let Some(mut direction) = solve_dense(system, gradient.iter().map(|g| -g).collect()) else {
            break; // singular even damped: nothing usable left to do
        };
        let step_norm = direction.iter().fold(0.0f64, |acc, d| acc.max(d.abs()));
        if !step_norm.is_finite() || step_norm <= 0.0 {
            break;
        }
        // Cap at a factor of ~2 per coordinate. Newton directions are
        // scale-free and an unclipped one can propose e^40.
        if step_norm > 0.7 {
            for step in &mut direction {
                *step *= 0.7 / step_norm;
            }
        }
        let base: Vec<Price> = movable.iter().map(|token| prices[token]).collect();
        rescale(prices, &base, &direction)?;
        spent += 1;
        let (value, next_gradient, next_edges) = evaluate(prices)?;
        if value < objective {
            objective = value;
            gradient = next_gradient;
            edges = next_edges;
            settled = movable.iter().map(|token| prices[token]).collect();
            lambda = (lambda / 4.0).max(1e-12);
        } else {
            for (token, price) in movable.iter().zip(&base) {
                prices.insert(*token, *price);
            }
            lambda *= 16.0;
            if lambda > 1e18 {
                break; // even a vanishing step does not descend: a kink bottom
            }
        }
    }
    // The model chose the point; the certificate is what exact arithmetic says
    // about it. Keep whichever of the two is actually smaller — the starting
    // point is a valid bound too, and a model that wandered must not be able
    // to make the reported number worse.
    for (token, price) in movable.iter().zip(&settled) {
        prices.insert(*token, *price);
    }
    // Only a point below `best` is kept, so one that is not need not be
    // priced to the end: a wandered model point can sit where every pool
    // walks to its coverage wall.
    if let Some((candidate, _)) =
        bound_below(snap, token_in, amount_in, prices, scope, routed, Some(best))?
    {
        best = candidate;
    } else {
        for (token, price) in movable.iter().zip(&start) {
            prices.insert(*token, *price);
        }
    }

    // Then a short descent judged on the BOUND ITSELF. The model and the bound
    // agree to dust on most catalogs, but where they do not, only this loop can
    // tell — it accepts a step when the exact number falls, so it closes
    // whatever the model was blind to. Deliberately a small tail of the budget:
    // these steps cost 512-bit arithmetic, which is what the model exists to
    // avoid paying on rejected points.
    let mut step = 0.25f64;
    let mut polish = (iteration_budget / 4).min(32);
    while polish > 0 && step > 1e-6 {
        solver_budget.checkpoint("certificate polish")?;
        let gradient = log_gradient(snap, token_in, amount_in, prices, scope)?;
        let scale = movable
            .iter()
            .map(|token| gradient.get(token).copied().unwrap_or(0.0).abs())
            .fold(0.0f64, f64::max);
        if scale.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) || !scale.is_finite() {
            break;
        }
        let base: Vec<Price> = movable.iter().map(|token| prices[token]).collect();
        let push: Vec<f64> = movable
            .iter()
            .map(|token| -gradient.get(token).copied().unwrap_or(0.0) / scale * step)
            .collect();
        rescale(prices, &base, &push)?;
        polish -= 1;
        if let Some((value, _)) =
            bound_below(snap, token_in, amount_in, prices, scope, routed, Some(best))?
        {
            best = value;
        } else {
            for (token, price) in movable.iter().zip(&base) {
                prices.insert(*token, *price);
            }
            step *= 0.5;
        }
    }
    Ok(best)
}

/// Per-pool arbitrage value at a dual point, largest first — the bound's own
/// itemization. Tooling only: `bound_at` stays allocation-free for the hot
/// path, so this repeats its loop rather than complicating it.
pub fn attribution(
    snap: &Snapshot,
    prices: &HashMap<Address, Price>,
) -> anyhow::Result<Vec<(String, Address, Address, U256)>> {
    let mut items = Vec::with_capacity(snap.v3.len() + snap.v2.len());
    for (pool, state) in &snap.v3 {
        let p0 = prices.get(&pool.token0).copied().unwrap_or(Price::ZERO);
        let p1 = prices.get(&pool.token1).copied().unwrap_or(Price::ZERO);
        items.push((
            format!("{} {:#x}", pool.protocol.as_str(), pool.address),
            pool.token0,
            pool.token1,
            arb_v3(pool, state, p0, p1)?,
        ));
    }
    for (pool, state) in &snap.v2 {
        let p0 = prices.get(&pool.token0).copied().unwrap_or(Price::ZERO);
        let p1 = prices.get(&pool.token1).copied().unwrap_or(Price::ZERO);
        items.push((
            format!("{} {:#x}", pool.protocol.as_str(), pool.address),
            pool.token0,
            pool.token1,
            arb_v2(pool, state, p0, p1)?,
        ));
    }
    items.sort_by_key(|item| std::cmp::Reverse(item.3));
    Ok(items)
}

/// Certify a quote: choose a dual point from the plan's post-trade marginal
/// prices, then evaluate the bound rigorously against the snapshot the plan
/// was solved on.
fn validate_plan_universe_membership(
    universe: &RouteUniverse,
    token_in: Address,
    token_out: Address,
    plan: &Plan,
) -> anyhow::Result<()> {
    ensure!(!plan.legs.is_empty(), "certificate plan has no legs");
    for leg in &plan.legs {
        let first = leg
            .path
            .first()
            .context("certificate plan contains an empty leg")?;
        let mut skeleton = Vec::with_capacity(leg.path.len() + 1);
        skeleton.push(first.token_in);
        for hop in &leg.path {
            ensure!(
                skeleton.last() == Some(&hop.token_in),
                "certificate plan contains a discontinuous token skeleton"
            );
            skeleton.push(hop.token_out);
        }
        ensure!(
            skeleton.first() == Some(&token_in) && skeleton.last() == Some(&token_out),
            "certificate plan leg endpoints do not match the route universe"
        );
        ensure!(
            universe
                .token_paths()
                .iter()
                .any(|candidate| candidate == &skeleton),
            "certificate plan token skeleton is outside the route universe"
        );
    }
    Ok(())
}

/// Certify without screening: the bound covers exactly the loaded snapshot, and
/// `graph_bound` equals `catalog_bound` because nothing wider was measured.
pub fn certify_in_universe(
    universe: &RouteUniverse,
    snap: &Snapshot,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    plan: &Plan,
) -> anyhow::Result<Certificate> {
    certify_in_universe_with_budget(
        universe,
        snap,
        &ScreeningPools::default(),
        (token_in, token_out),
        amount_in,
        plan,
        &SolverBudget::unlimited(),
    )
}

pub fn certify_in_universe_with_budget(
    universe: &RouteUniverse,
    snap: &Snapshot,
    screening: &ScreeningPools,
    endpoints: (Address, Address),
    amount_in: U256,
    plan: &Plan,
    solver_budget: &SolverBudget,
) -> anyhow::Result<Certificate> {
    let (token_in, token_out) = endpoints;
    solver_budget.checkpoint("certificate validation")?;
    ensure!(snap.ekubo.is_empty(), "model_unsupported: ekubov3");
    ensure!(
        universe.endpoints() == (token_in, token_out),
        "certificate endpoints do not match the route universe"
    );
    ensure!(
        plan.universe_id == Some(universe.fingerprint()),
        "plan was not solved against the certificate route universe"
    );
    validate_plan_universe_membership(universe, token_in, token_out, plan)?;
    let routed_input = plan.legs.iter().try_fold(U256::ZERO, |total, leg| {
        total
            .checked_add(leg.amount_in)
            .context("certificate plan input overflow")
    })?;
    ensure!(
        routed_input == amount_in,
        "certificate plan inputs do not match the requested amount"
    );
    ensure!(!plan.amount_out.is_zero(), "cannot certify a zero quote");
    let states = crate::route::plan_states(snap, plan)?;
    solver_budget.checkpoint("certificate dual construction")?;
    let routed = PoolSet::of(snap, plan);
    let prices = dual_prices(snap, token_out, &states, &routed)?;
    let reachable = PoolSet::reachable_in_universe(snap, universe);
    let mut prices = prices;
    if *TIGHTEN_BUDGET > 0 {
        tighten_with_solver_budget(
            snap,
            token_in,
            token_out,
            amount_in,
            &mut prices,
            Some(&reachable),
            &routed,
            *TIGHTEN_BUDGET,
            solver_budget,
        )?;
    }
    solver_budget.checkpoint("certificate bound")?;
    let (bound, unrouted_pools) = bound_at(
        snap,
        token_in,
        amount_in,
        &prices,
        Some(&reachable),
        &routed,
    )?;
    solver_budget.checkpoint("certificate catalog bound")?;
    let (catalog_bound, _) = bound_at(snap, token_in, amount_in, &prices, None, &routed)?;
    // Screening is priced last and changes nothing above it: `prices` is read,
    // never written, so every number already computed stands as it would have
    // without it.
    //
    // Attribution runs over the connectors that actually contributed a pricing
    // pair, not the whole ranking. A connector the universe already routes
    // through contributes none and would otherwise ship as a zero — which the
    // `screenedValue` contract reads as "provably worthless", the exact
    // opposite of "already in the plan".
    let (graph_bound, screened_value, screened_unpriced) = if screening.is_empty() {
        (catalog_bound, Vec::new(), 0)
    } else {
        solver_budget.checkpoint("certificate graph bound")?;
        let extended = extend_prices_to_screened(screening, &prices, &snapshot_tokens(snap))?;
        graph_bound_at(
            catalog_bound,
            screening,
            &extended,
            &universe.priced_beyond_universe(),
        )?
    };
    let achieved = plan.amount_out;
    // gap/achieved in bps, ×10⁴, rounded up: the reported number never
    // understates the certified gap.
    //
    // The ratio stays U256 all the way to the formatter. Narrowing it to `u64`
    // with a `u64::MAX` fallback published 1844674407370955.1615 — `u64::MAX/10⁴`
    // — as though it were a measurement, which is exactly what `graph_gap_bps`
    // returned for WBNB→ZEC on 2026-08-05. A screened bound is loose by
    // TVL/amount (see `the maintainers' research notes` §11), so this range
    // is reachable in normal operation rather than only under a defect.
    let bps_e4 = |bound: U256| ratio_bps_e4(bound.saturating_sub(achieved), achieved);
    let mut prices: Vec<(Address, Price)> = prices.into_iter().collect();
    prices.sort_by_key(|(token, _)| *token);
    Ok(Certificate {
        bound,
        achieved,
        gap: bound.saturating_sub(achieved),
        gap_bps_e4: bps_e4(bound)?,
        catalog_gap_bps_e4: bps_e4(catalog_bound)?,
        catalog_bound,
        graph_gap_bps_e4: bps_e4(graph_bound)?,
        graph_bound,
        screened_pools: screening.len(),
        screened_unpriced,
        screened_value,
        unrouted_pools,
        scanned_pools: reachable.v3.iter().filter(|hit| **hit).count()
            + reachable.v2.iter().filter(|hit| **hit).count(),
        prices,
        consistent: bound >= achieved,
    })
}

#[cfg(any(test, feature = "testing"))]
pub fn certify(
    profile: &ChainProfile,
    snap: &Snapshot,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    plan: &Plan,
) -> anyhow::Result<Certificate> {
    let universe = RouteUniverse::profile_only(profile, token_in, token_out)?;
    certify_in_universe(&universe, snap, token_in, token_out, amount_in, plan)
}

/// A wei ratio as basis points × 10⁴ — the unit `format_bps_e4` prints, and the
/// one every ratio the API reports is carried in.
///
/// Full width the whole way. Narrowing the ratio to `u64` is what published
/// `u64::MAX/10⁴` as though it were a measurement, and a screened bound reaches
/// that range in normal operation rather than only under a defect
/// (`the maintainers' research notes` §11).
///
/// Rounds up, so a reported ratio never understates what was left on the table.
///
/// Errors on a zero denominator rather than producing a ratio, because every
/// caller's denominator is an achieved output: a zero there means there was no
/// trade to take a ratio against.
pub fn ratio_bps_e4(numerator: U256, denominator: U256) -> anyhow::Result<U256> {
    narrow(div_ceil(
        wmul(numerator, U256::from(100_000_000u64)),
        wide(denominator),
    )?)
}

/// `gap_bps_e4` as the decimal basis-point string the API reports.
///
/// Takes the full-width ratio so a loose screened bound prints its real value.
/// The string grows instead of the number wrapping to a plausible-looking one.
pub fn format_bps_e4(value: U256) -> String {
    let scale = U256::from(10_000u64);
    // `value % scale` is below 10⁴ by construction, so this narrowing is total.
    let fraction = u64::try_from(value % scale).unwrap_or_default();
    format!("{}.{fraction:04}", value / scale)
}

#[cfg(any(test, feature = "testing"))]
pub fn certify_screened(
    universe: &RouteUniverse,
    snap: &Snapshot,
    screening: &ScreeningPools,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    plan: &Plan,
) -> anyhow::Result<Certificate> {
    certify_in_universe_with_budget(
        universe,
        snap,
        screening,
        (token_in, token_out),
        amount_in,
        plan,
        &SolverBudget::unlimited(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{
        BSC_PROFILE, BSC_USDT, FORK_UNIV3, ROBINHOOD_PROFILE, SLVR, USDG, WBNB, WETH,
    };
    use crate::pools::{TickInfo, V2Protocol, V3Protocol};
    use crate::route::{PreparedRoutes, best_plan};
    use crate::v3math::sqrt_ratio_at_tick;
    use alloy_primitives::I256;

    fn v2_pool(
        id: u8,
        token0: Address,
        token1: Address,
        reserve0: u128,
        reserve1: u128,
    ) -> (V2Pool, V2State) {
        (
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: Address::repeat_byte(id),
                token0,
                token1,
                fee_bps: 30,
            },
            V2State {
                reserve0: U256::from(reserve0),
                reserve1: U256::from(reserve1),
            },
        )
    }

    fn v3_pool(
        id: u8,
        token0: Address,
        token1: Address,
        liquidity: u128,
        fee_ppm: u32,
    ) -> (V3Pool, V3State) {
        (
            V3Pool {
                protocol: V3Protocol::UNIV3,
                address: Address::repeat_byte(id),
                token0,
                token1,
                fee_ppm,
                tick_spacing: 1,
                verify_pool_spacing: false,
                execution: Some(crate::pools::V3ExecutionMeta {
                    fork_id: FORK_UNIV3,
                    pool_id: fee_ppm,
                }),
                v4: None,
                algebra: None,
            },
            V3State {
                sqrt_price: U256::ONE << 96usize,
                tick: 0,
                liquidity: U256::from(liquidity),
                ticks: vec![
                    TickInfo {
                        tick: -60_000,
                        liquidity_net: I256::try_from(liquidity as i128).expect("net fits"),
                    },
                    TickInfo {
                        tick: 60_000,
                        liquidity_net: I256::try_from(-(liquidity as i128)).expect("net fits"),
                    },
                ]
                .into(),
                pos: 1,
                lo_cover: -120_000,
                hi_cover: 120_000,
            },
        )
    }

    fn snapshot(v3: Vec<(V3Pool, V3State)>, v2: Vec<(V2Pool, V2State)>) -> Snapshot {
        Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3,
            v2,
            ekubo: vec![],
        }
    }

    /// A profile-only universe plus a screened connector, with the pools to
    /// price it: `token_in -> connector -> token_out` sitting outside the
    /// snapshot entirely.
    fn screened_fixture(
        connector: Address,
        inbound: (u128, u128),
        outbound: (u128, u128),
    ) -> (RouteUniverse, Snapshot, ScreeningPools, Plan, U256) {
        let (token_in, token_out) = (SLVR, USDG);
        let amount_in = U256::from(1_000_000u64);
        let snap = snapshot(
            Vec::new(),
            vec![v2_pool(
                1,
                token_in,
                token_out,
                1_000_000_000,
                1_000_000_000,
            )],
        );
        let universe = RouteUniverse::profile_only_shadow_complete(
            &ROBINHOOD_PROFILE,
            token_in,
            token_out,
            crate::topology::ConnectorSelection {
                fences: crate::topology::CatalogFences {
                    v23: crate::topology::V23Fence {
                        seq: 1,
                        generation: 1,
                    },
                    v4: None,
                },
                protocols: vec![crate::topology::Protocol::UNIV2],
                connectors: Vec::new(),
                screened: vec![connector],
                eligible_count: 1,
                shortlist_truncated: false,
                selector: crate::topology::ConnectorSelector::AdjacencyWalk,
            },
        )
        .expect("screened universe");
        let plan = PreparedRoutes::for_universe(&snap, &universe)
            .expect("routes")
            .try_solve_quantized(amount_in, 256, 50)
            .expect("solve")
            .expect("plan exists");
        let screening = ScreeningPools {
            v3: Vec::new(),
            v2: vec![
                v2_pool(0x21, token_in, connector, inbound.0, inbound.1),
                v2_pool(0x22, connector, token_out, outbound.0, outbound.1),
            ],
        };
        (universe, snap, screening, plan, amount_in)
    }

    /// The property the whole design rests on: reading state for tokens the
    /// router cannot reach must leave every number the quote already reports
    /// exactly where it was. A diagnostic that moves its own subject is worse
    /// than no diagnostic.
    #[test]
    fn screening_cannot_move_the_certified_bound() {
        let connector = Address::repeat_byte(0x77);
        // Priced richly enough that it would move the bound if it could reach
        // it: the point is that it cannot.
        let (universe, snap, screening, plan, amount_in) = screened_fixture(
            connector,
            (1_000_000_000_000, 2_000_000_000_000),
            (1_000_000_000_000, 1_000_000_000_000),
        );
        let bare = certify_screened(
            &universe,
            &snap,
            &ScreeningPools::default(),
            SLVR,
            USDG,
            amount_in,
            &plan,
        )
        .expect("bare certificate");
        let screened = certify_screened(&universe, &snap, &screening, SLVR, USDG, amount_in, &plan)
            .expect("screened certificate");

        assert_eq!(screened.bound, bare.bound);
        assert_eq!(screened.gap_bps_e4, bare.gap_bps_e4);
        assert_eq!(screened.catalog_bound, bare.catalog_bound);
        assert_eq!(screened.catalog_gap_bps_e4, bare.catalog_gap_bps_e4);
        assert_eq!(screened.achieved, bare.achieved);
        assert_eq!(screened.prices, bare.prices);
        assert!(screened.consistent && bare.consistent);
        // Only the new scope reports anything new.
        assert_eq!(bare.screened_pools, 0);
        assert_eq!(bare.graph_bound, bare.catalog_bound);
        assert_eq!(screened.screened_pools, 2);
        assert_eq!(screened.screened_unpriced, 0);
    }

    /// A screened connector offering a BETTER PRICE than the routed pool has to
    /// show up as value the quote left on the table, attributed to that token.
    /// Depth alone buys nothing: an extra hop costs an extra LP fee, so a
    /// deeper route at the same price is strictly worse.
    #[test]
    fn a_better_priced_screened_connector_widens_the_graph_bound() {
        let connector = Address::repeat_byte(0x77);
        // One SLVR buys two connector, one connector buys one USDG — twice
        // what the routed pool pays, less two LP fees.
        let (universe, snap, screening, plan, amount_in) = screened_fixture(
            connector,
            (1_000_000_000_000, 2_000_000_000_000),
            (1_000_000_000_000, 1_000_000_000_000),
        );
        let cert = certify_screened(&universe, &snap, &screening, SLVR, USDG, amount_in, &plan)
            .expect("screened certificate");

        assert!(
            cert.graph_bound > cert.catalog_bound,
            "graph {} catalog {}",
            cert.graph_bound,
            cert.catalog_bound
        );
        assert!(cert.graph_gap_bps_e4 > cert.catalog_gap_bps_e4);
        assert_eq!(cert.screened_value.len(), 1);
        assert_eq!(cert.screened_value[0].connector, connector);
        assert!(!cert.screened_value[0].arb.is_zero());
        // The bound stays a bound.
        assert!(cert.graph_bound >= cert.achieved);
    }

    /// The minimising price against the relaxation's, on both fixtures.
    ///
    /// A screened token's own dual coordinate is free — no pool in the served
    /// universe touches it — so weak duality lets the bound be evaluated at the
    /// price that minimises it rather than at a max-product relaxation's upward
    /// answer. §11 read implied errors of κ = 1.22 to 2.48 off that relaxation
    /// and concluded the bound cannot rank. This is the other choice, measured:
    /// `the maintainers' research notes`.
    #[test]
    fn the_minimising_price_prices_a_worthless_connector_at_zero() {
        let connector = Address::repeat_byte(0x77);

        // Market-priced: a route through it is at parity with the routed pool,
        // so the two legs' fee bands overlap and a consistent price exists at
        // which neither is arbitrageable. That is a proof of worthlessness, and
        // it must come out EXACTLY zero rather than within a rounding wei.
        let (universe, snap, screening, plan, amount_in) = screened_fixture(
            connector,
            (1_000_000_000, 1_000_000_000),
            (1_000_000_000, 1_000_000_000),
        );
        let flat = certify_screened(&universe, &snap, &screening, SLVR, USDG, amount_in, &plan)
            .expect("screened certificate");
        let value = flat.screened_value[0];
        println!(
            "market-priced: arb {} minArb {} price {}/{} minPrice {}/{}",
            value.arb,
            value.min_arb,
            value.price.num,
            value.price.den,
            value.min_price.num,
            value.min_price.den
        );
        assert!(
            value.min_arb <= U256::from(2u8),
            "a price inside both legs' bands exists, so the minimum is a proof \
             down to the wei the outward rounding costs, got {}",
            value.min_arb
        );

        // Genuinely better priced: one SLVR buys two connector. No price makes
        // both legs idle, so the minimum is positive — and still below what the
        // relaxation charged, because the relaxation prices the connector high.
        let (universe, snap, screening, plan, amount_in) = screened_fixture(
            connector,
            (1_000_000_000_000, 2_000_000_000_000),
            (1_000_000_000_000, 1_000_000_000_000),
        );
        let rich = certify_screened(&universe, &snap, &screening, SLVR, USDG, amount_in, &plan)
            .expect("screened certificate");
        let value = rich.screened_value[0];
        println!(
            "better-priced: arb {} minArb {} price {}/{} minPrice {}/{}",
            value.arb,
            value.min_arb,
            value.price.num,
            value.price.den,
            value.min_price.num,
            value.min_price.den
        );
        assert!(
            !value.min_arb.is_zero(),
            "a connector that really is better cannot be priced away"
        );
        // Measured 170,640,584,654 against 56,994,183,253 — the relaxation
        // charges three times what the minimum does, and the whole of that
        // difference is the price choice.
        assert!(
            value.min_arb.saturating_mul(U256::from(2u8)) < value.arb,
            "the minimising price must beat the relaxation by more than rounding: \
             min {} arb {}",
            value.min_arb,
            value.arb
        );
        // And what it does NOT fix, stated where it can be checked. This fixture
        // trades 10⁶ against pools holding 10¹², and §11's requirement scales as
        // √(x/TVL): a bound that is 57,000× the quote's own output is the dust
        // end of that ratio, not evidence about production sizes where x/TVL is
        // of order one. Three times better is still three times better.
        assert!(value.min_arb > rich.achieved);

        // And the published bound is untouched by any of it. `graph_bound` still
        // uses the relaxation, so this ships as a measurement rather than as a
        // change to a number anything already reads.
        assert!(rich.graph_bound > rich.catalog_bound);
    }

    /// `bound` and `catalog_bound` are re-evaluatable by a holder from `prices`
    /// and the block's pool states. `graph_bound` was not: the relaxation prices
    /// tokens the certified dual point never names, so the one number measuring
    /// coverage was the one number that had to be taken on trust.
    ///
    /// This rebuilds it from the published artifact alone.
    #[test]
    fn the_published_artifact_reconstructs_the_graph_bound() {
        let connector = Address::repeat_byte(0x77);
        let (universe, snap, screening, plan, amount_in) = screened_fixture(
            connector,
            (1_000_000_000_000, 2_000_000_000_000),
            (1_000_000_000_000, 1_000_000_000_000),
        );
        let cert = certify_screened(&universe, &snap, &screening, SLVR, USDG, amount_in, &plan)
            .expect("screened certificate");

        // The premise: the connector carries a price the extension produced, and
        // the certified dual point does not name it. That gap is what made
        // `graph_bound` unverifiable.
        assert!(!cert.screened_value[0].price.is_zero());
        assert!(
            cert.prices.iter().all(|(token, _)| *token != connector),
            "connector must be absent from the certified dual point"
        );

        // A holder's whole view: the certified prices plus the published
        // extended price for each screened connector.
        let mut published: HashMap<Address, Price> = cert.prices.iter().copied().collect();
        for value in &cert.screened_value {
            published.insert(value.connector, value.price);
        }
        let connectors: Vec<Address> = cert
            .screened_value
            .iter()
            .map(|value| value.connector)
            .collect();

        let (rebuilt, values, unpriced) =
            screened_arb(&screening, &published, &connectors).expect("rebuild from the artifact");

        assert_eq!(unpriced, 0, "the artifact priced every screened pool");
        assert_eq!(values[0].arb, cert.screened_value[0].arb);
        assert_eq!(
            narrow(add(wide(cert.catalog_bound), rebuilt).expect("add")).expect("narrow"),
            cert.graph_bound,
            "catalog_bound + rebuilt screened arb must reproduce graph_bound"
        );
    }

    /// The screen has to be able to say "provably worthless", or it cannot
    /// retire a candidate. A connector quoting the same price as the routed
    /// pool leaves nothing on the table at any depth.
    #[test]
    fn a_market_priced_screened_connector_is_provably_worthless() {
        let connector = Address::repeat_byte(0x77);
        let (universe, snap, screening, plan, amount_in) = screened_fixture(
            connector,
            (1_000_000_000, 1_000_000_000),
            (1_000_000_000, 1_000_000_000),
        );
        let cert = certify_screened(&universe, &snap, &screening, SLVR, USDG, amount_in, &plan)
            .expect("screened certificate");

        assert_eq!(cert.screened_pools, 2);
        assert_eq!(cert.screened_unpriced, 0);
        // Every term in the bound rounds outward, so a pool sitting exactly on
        // its fee band contributes a wei rather than a zero — the arithmetic
        // never reports less than the truth. What "worthless" has to mean is
        // bounded by the rounding itself. This fixture quotes 996008 wei, so a
        // wei is 0.01 bp and visible at the e4 resolution `gap_bps_e4` carries;
        // on the 1e18-scale amounts production quotes it is twelve orders below
        // anything reported.
        assert!(cert.screened_value[0].arb <= U256::from(2u8));
        assert!(cert.graph_bound >= cert.catalog_bound);
        assert!(cert.graph_bound - cert.catalog_bound <= U256::from(2u8));
    }

    /// A connector the plan already routes through must not appear in the
    /// attribution at all.
    ///
    /// It contributes no screening pair — its edges are routable, so there is
    /// nothing to price separately — and would therefore accumulate exactly
    /// zero. Shipping that zero beside the unroutable candidates would say
    /// "provably worth nothing to this quote" about the connector the quote is
    /// USING, which is the reading `screenedValue` publishes and the ranking
    /// P2 would consume.
    #[test]
    fn an_admitted_connector_is_absent_from_the_attribution() {
        let (token_in, token_out) = (SLVR, USDG);
        let admitted = Address::repeat_byte(0x55);
        let extra = Address::repeat_byte(0x77);
        let amount_in = U256::from(1_000_000u64);
        let snap = snapshot(
            Vec::new(),
            vec![v2_pool(
                1,
                token_in,
                token_out,
                1_000_000_000,
                1_000_000_000,
            )],
        );
        let universe = RouteUniverse::adjacency_complete(
            &ROBINHOOD_PROFILE,
            token_in,
            token_out,
            crate::topology::ConnectorSelection {
                fences: crate::topology::CatalogFences {
                    v23: crate::topology::V23Fence {
                        seq: 1,
                        generation: 1,
                    },
                    v4: None,
                },
                protocols: vec![crate::topology::Protocol::UNIV2],
                connectors: vec![admitted],
                screened: vec![admitted, extra],
                eligible_count: 2,
                shortlist_truncated: true,
                selector: crate::topology::ConnectorSelector::AdjacencyWalk,
            },
        )
        .expect("adjacency universe");
        let plan = PreparedRoutes::for_universe(&snap, &universe)
            .expect("routes")
            .try_solve_quantized(amount_in, 256, 50)
            .expect("solve")
            .expect("plan exists");
        // Only `extra` got screening pairs, so only `extra` has screened pools.
        let screening = ScreeningPools {
            v3: Vec::new(),
            v2: vec![
                v2_pool(0x21, token_in, extra, 1_000_000_000_000, 2_000_000_000_000),
                v2_pool(0x22, extra, token_out, 1_000_000_000_000, 1_000_000_000_000),
            ],
        };
        let cert = certify_screened(
            &universe, &snap, &screening, token_in, token_out, amount_in, &plan,
        )
        .expect("screened certificate");

        assert_eq!(universe.screened(), &[admitted, extra]);
        assert_eq!(cert.screened_value.len(), 1);
        assert_eq!(cert.screened_value[0].connector, extra);
        assert!(!cert.screened_value[0].arb.is_zero());
        assert!(
            cert.screened_value
                .iter()
                .all(|value| value.connector != admitted)
        );
    }

    /// The pin that makes `catalog_bound` reusable at the extended point.
    ///
    /// A token any snapshot pool touches keeps whatever the certified point
    /// gave it, including a zero. Letting the screened graph write one would
    /// SHRINK that pool's arb — a zero price values its whole reserve as free
    /// — so `catalog_bound` would no longer be the snapshot term of
    /// `graph_bound` and the two scopes would stop nesting.
    #[test]
    fn the_extension_never_reprices_a_token_the_snapshot_holds() {
        let orphan = Address::repeat_byte(0x66);
        let screened = Address::repeat_byte(0x77);
        // `orphan` sits in the snapshot with no path to the numeraire, so
        // `dual_prices` leaves it out; the screened pool beside it offers one.
        let snap = snapshot(
            Vec::new(),
            vec![
                v2_pool(1, SLVR, USDG, 1_000_000_000, 1_000_000_000),
                v2_pool(2, orphan, Address::repeat_byte(0x65), 1_000_000, 1_000_000),
            ],
        );
        let screening = ScreeningPools {
            v3: Vec::new(),
            v2: vec![v2_pool(0x21, orphan, USDG, 1_000_000_000, 1_000_000_000)],
        };
        let mut prices = HashMap::new();
        prices.insert(USDG, Price::ONE);

        let pinned = snapshot_tokens(&snap);
        assert!(pinned.contains(&orphan));
        let extended = extend_prices_to_screened(&screening, &prices, &pinned).expect("extend");
        assert!(
            !extended.contains_key(&orphan),
            "a snapshot token was repriced by the screened graph"
        );
        // Without the pin the same edge would have written one, which is what
        // makes this a guard rather than a restatement of the relaxation.
        let unpinned =
            extend_prices_to_screened(&screening, &prices, &HashSet::new()).expect("extend");
        assert!(unpinned.contains_key(&orphan));
        // And a token no snapshot pool touches is still free to be priced.
        assert!(pinned.contains(&USDG) && !pinned.contains(&screened));
    }

    /// A screened token with no loaded path back to the numeraire gets no
    /// price. Valuing it at zero would price its whole reserve as free, so it
    /// is skipped — and counted, so the measurement never looks complete when
    /// it is partial.
    ///
    /// Note how hard this is to provoke: a connector attached to either
    /// endpoint is priced through that edge, inbound or outbound, because the
    /// relaxation walks the graph in both directions. It takes a pool touching
    /// no priced token at all, which the screening-pair construction cannot
    /// produce — the guard exists for the malformed case, not the normal one.
    #[test]
    fn a_disconnected_screened_pool_is_skipped_and_counted() {
        let connector = Address::repeat_byte(0x77);
        let (universe, snap, _, plan, amount_in) = screened_fixture(
            connector,
            (1_000_000_000, 1_000_000_000),
            (1_000_000_000, 1_000_000_000),
        );
        let orphan = Address::repeat_byte(0x66);
        let screening = ScreeningPools {
            v3: Vec::new(),
            v2: vec![v2_pool(
                0x21,
                orphan,
                Address::repeat_byte(0x65),
                10_000_000,
                10_000_000,
            )],
        };
        let cert = certify_screened(&universe, &snap, &screening, SLVR, USDG, amount_in, &plan)
            .expect("screened certificate");

        assert_eq!(cert.screened_pools, 1);
        assert_eq!(cert.screened_unpriced, 1);
        assert_eq!(cert.graph_bound, cert.catalog_bound);
        assert!(orphan != connector);
    }

    fn certify_best(snap: &Snapshot, amount_in: u128, token_out: Address) -> Certificate {
        let plan =
            best_plan(snap, SLVR, token_out, U256::from(amount_in), 256, 50).expect("plan exists");
        certify(
            &ROBINHOOD_PROFILE,
            snap,
            SLVR,
            token_out,
            U256::from(amount_in),
            &plan,
        )
        .expect("certificate")
    }

    /// The dual is a CONTINUOUS relaxation of an integer-rounded simulator, so
    /// a perfectly allocated quote still certifies a few wei short of exact.
    /// Bounding that in wei rather than in bps is what keeps the assertion
    /// meaningful at every trade size.
    const ROUNDING_WEI: u64 = 8;

    #[test]
    fn bsc_reachable_scope_uses_profile_connectors_and_includes_three_hop_edges() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x22);
        let snap = snapshot(
            vec![],
            vec![
                v2_pool(11, token_in, WBNB, 1_000_000_000, 1_000_000_000),
                v2_pool(12, WBNB, BSC_USDT, 1_000_000_000, 1_000_000_000),
                v2_pool(13, BSC_USDT, token_out, 1_000_000_000, 1_000_000_000),
                // A Robinhood-only connector must not leak into BSC's scope.
                v2_pool(14, token_in, WETH, 1_000_000_000, 1_000_000_000),
            ],
        );

        let reachable = PoolSet::reachable(&BSC_PROFILE, &snap, token_in, token_out);
        assert!(reachable.v2(0));
        assert!(reachable.v2(1), "connector-to-connector edge was omitted");
        assert!(reachable.v2(2));
        assert!(!reachable.v2(3), "Robinhood connector leaked into BSC");

        let amount = U256::from(100_000u64);
        let plan = PreparedRoutes::for_profile(&snap, &BSC_PROFILE, token_in, token_out)
            .expect("BSC routes")
            .try_solve_quantized(amount, 64, 0)
            .expect("solve")
            .expect("three-hop route");
        assert_eq!(plan.legs.len(), 1);
        assert_eq!(plan.legs[0].path.len(), 3);

        let cert = certify(&BSC_PROFILE, &snap, token_in, token_out, amount, &plan)
            .expect("BSC certificate");
        assert!(
            cert.consistent,
            "bound {} < achieved {}",
            cert.bound, cert.achieved
        );
        assert!(cert.bound >= plan.amount_out);
        assert_eq!(cert.scanned_pools, 3);
    }

    #[test]
    fn certificate_rejects_the_same_paths_with_different_universe_provenance() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x99);
        let snap = snapshot(
            vec![],
            vec![v2_pool(
                1,
                token_in,
                token_out,
                1_000_000_000,
                1_000_000_000,
            )],
        );
        let amount = U256::from(100_000u64);
        let plan = PreparedRoutes::for_profile(&snap, &ROBINHOOD_PROFILE, token_in, token_out)
            .unwrap()
            .try_solve_quantized(amount, 64, 0)
            .unwrap()
            .unwrap();
        let dynamic_empty = RouteUniverse::adjacency_complete(
            &ROBINHOOD_PROFILE,
            token_in,
            token_out,
            crate::topology::ConnectorSelection {
                fences: crate::topology::CatalogFences {
                    v23: crate::topology::V23Fence {
                        seq: 7,
                        generation: 9,
                    },
                    v4: None,
                },
                protocols: vec![crate::topology::Protocol::UNIV2],
                connectors: vec![],
                screened: vec![],
                eligible_count: 0,
                shortlist_truncated: false,
                selector: crate::topology::ConnectorSelector::AdjacencyWalk,
            },
        )
        .unwrap();
        assert_eq!(
            dynamic_empty.token_paths(),
            RouteUniverse::profile_only(&ROBINHOOD_PROFILE, token_in, token_out)
                .unwrap()
                .token_paths()
        );
        let error = certify_in_universe(&dynamic_empty, &snap, token_in, token_out, amount, &plan)
            .unwrap_err();
        assert!(error.to_string().contains("route universe"));
    }

    #[test]
    fn certificate_rejects_a_forged_id_on_an_out_of_universe_skeleton() {
        let token_in = Address::repeat_byte(0x11);
        let connector = Address::repeat_byte(0x44);
        let token_out = Address::repeat_byte(0x99);
        let snap = snapshot(
            vec![],
            vec![
                v2_pool(1, token_in, connector, 1_000_000_000, 1_000_000_000),
                v2_pool(2, connector, token_out, 1_000_000_000, 1_000_000_000),
            ],
        );
        let selection = crate::topology::ConnectorSelection {
            fences: crate::topology::CatalogFences {
                v23: crate::topology::V23Fence {
                    seq: 7,
                    generation: 9,
                },
                v4: None,
            },
            protocols: vec![crate::topology::Protocol::UNIV2],
            connectors: vec![connector],
            screened: vec![connector],
            eligible_count: 1,
            shortlist_truncated: false,
            selector: crate::topology::ConnectorSelector::AdjacencyWalk,
        };
        let dynamic =
            RouteUniverse::adjacency_complete(&ROBINHOOD_PROFILE, token_in, token_out, selection)
                .unwrap();
        let amount = U256::from(100_000u64);
        let mut plan = PreparedRoutes::for_universe(&snap, &dynamic)
            .unwrap()
            .try_solve_quantized(amount, 64, 0)
            .unwrap()
            .unwrap();
        let profile_only =
            RouteUniverse::profile_only(&ROBINHOOD_PROFILE, token_in, token_out).unwrap();
        plan.universe_id = Some(profile_only.fingerprint());

        let error = certify_in_universe(&profile_only, &snap, token_in, token_out, amount, &plan)
            .unwrap_err();
        assert!(error.to_string().contains("skeleton is outside"));
    }

    fn direct_certificate_fixture() -> (Snapshot, RouteUniverse, Address, Address, U256, Plan) {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x99);
        let snap = snapshot(
            vec![],
            vec![
                v2_pool(1, token_in, token_out, 1_000_000_000, 1_000_000_000),
                v2_pool(
                    2,
                    Address::repeat_byte(0x55),
                    Address::repeat_byte(0x66),
                    1_000_000_000,
                    1_000_000_000,
                ),
            ],
        );
        let amount = U256::from(100_000u64);
        let universe =
            RouteUniverse::profile_only(&ROBINHOOD_PROFILE, token_in, token_out).unwrap();
        let plan = PreparedRoutes::for_universe(&snap, &universe)
            .unwrap()
            .try_solve_quantized(amount, 64, 0)
            .unwrap()
            .unwrap();
        (snap, universe, token_in, token_out, amount, plan)
    }

    #[test]
    fn certificate_rejects_an_out_of_range_pool_index_without_panicking() {
        let (snap, universe, token_in, token_out, amount, mut plan) = direct_certificate_fixture();
        plan.legs[0].path[0].index = snap.v2.len();

        let error =
            certify_in_universe(&universe, &snap, token_in, token_out, amount, &plan).unwrap_err();
        assert!(error.to_string().contains("missing v2 pool index"));
    }

    #[test]
    fn certificate_rejects_a_pool_index_with_different_physical_tokens() {
        let (snap, universe, token_in, token_out, amount, mut plan) = direct_certificate_fixture();
        plan.legs[0].path[0].index = 1;

        let error =
            certify_in_universe(&universe, &snap, token_in, token_out, amount, &plan).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("tokens/direction do not match v2 pool")
        );
    }

    #[test]
    fn certificate_rejects_a_forged_pool_direction() {
        let (snap, universe, token_in, token_out, amount, mut plan) = direct_certificate_fixture();
        plan.legs[0].path[0].zero_for_one = !plan.legs[0].path[0].zero_for_one;

        let error =
            certify_in_universe(&universe, &snap, token_in, token_out, amount, &plan).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("tokens/direction do not match v2 pool")
        );
    }

    #[test]
    fn certificate_rejects_stale_leg_or_plan_output() {
        let (snap, universe, token_in, token_out, amount, plan) = direct_certificate_fixture();
        let mut stale_leg = plan.clone();
        stale_leg.legs[0].amount_out = stale_leg.legs[0].amount_out.checked_add(U256::ONE).unwrap();
        let error = certify_in_universe(&universe, &snap, token_in, token_out, amount, &stale_leg)
            .unwrap_err();
        assert!(error.to_string().contains("leg output does not match"));

        let mut stale_plan = plan;
        stale_plan.amount_out = stale_plan.amount_out.checked_add(U256::ONE).unwrap();
        let error = certify_in_universe(&universe, &snap, token_in, token_out, amount, &stale_plan)
            .unwrap_err();
        assert!(error.to_string().contains("plan output does not match"));
    }

    #[test]
    fn certificate_rejects_inconsistent_leg_input_total() {
        let (snap, universe, token_in, token_out, amount, mut plan) = direct_certificate_fixture();
        plan.legs[0].amount_in -= U256::ONE;

        let error =
            certify_in_universe(&universe, &snap, token_in, token_out, amount, &plan).unwrap_err();
        assert!(error.to_string().contains("inputs do not match"));
    }

    #[test]
    fn reachable_scope_excludes_incomplete_connector_skeletons() {
        let token_in = Address::repeat_byte(0x11);
        let token_out = Address::repeat_byte(0x22);
        let snap = snapshot(
            vec![],
            vec![v2_pool(
                15,
                token_in,
                crate::chain::BSC_USD1,
                1_000_000_000,
                1_000_000_000,
            )],
        );

        let reachable = PoolSet::reachable(&BSC_PROFILE, &snap, token_in, token_out);
        assert!(!reachable.v2(0), "incomplete skeleton entered the scope");
    }

    #[test]
    fn spare_seeding_prices_an_untouched_token_at_its_deepest_market() {
        let out = Address::repeat_byte(0xb7);
        let x = Address::repeat_byte(0xcc);
        // The plan trades SLVR→OUT and never touches X. X is quoted by two
        // parallel pools: a deep one at 0.001 OUT and a thin one at 12× that.
        // A max over parallel edges would let the thin pool price X for the
        // whole catalog; the seed must take the deepest market instead.
        let snap = snapshot(
            vec![],
            vec![
                v2_pool(
                    11,
                    SLVR,
                    out,
                    5_000_000_000_000_000_000_000,
                    6_000_000_000_000_000_000_000,
                ),
                v2_pool(
                    12,
                    x,
                    out,
                    1_000_000_000_000_000_000_000_000,
                    1_000_000_000_000_000_000_000,
                ),
                v2_pool(
                    13,
                    x,
                    out,
                    1_000_000_000_000_000_000_000,
                    12_000_000_000_000_000_000,
                ),
            ],
        );
        let amount = U256::from(100_000_000_000_000_000_000u128);
        let plan = best_plan(&snap, SLVR, out, amount, 256, 50).expect("plan exists");
        let states = crate::route::plan_states(&snap, &plan).expect("states");
        let routed = PoolSet::of(&snap, &plan);
        let prices = dual_prices(&snap, out, &states, &routed).expect("prices");
        let seeded = prices[&x];
        assert!(
            seeded.greater(Price::ZERO).expect("comparable"),
            "untouched token must still be priced"
        );
        // Deep spot net of fee is ~0.000997 OUT; the thin pool advertises
        // ~0.011964. Anything above 0.002 means the thin pool won.
        let ceiling =
            Price::from_ratio(wide(U256::from(2u64)), wide(U256::from(1_000u64))).expect("ceiling");
        assert!(
            ceiling.greater(seeded).expect("comparable"),
            "seed took the thin pool's rate"
        );
        let floor =
            Price::from_ratio(wide(U256::from(5u64)), wide(U256::from(10_000u64))).expect("floor");
        assert!(
            seeded.greater(floor).expect("comparable"),
            "seed fell below every market"
        );
    }

    #[test]
    fn one_pool_taking_the_whole_trade_certifies_at_zero_gap() {
        let out = Address::repeat_byte(0xb7);
        let snap = snapshot(
            vec![],
            vec![v2_pool(
                11,
                SLVR,
                out,
                5_000_000_000_000_000_000_000,
                6_000_000_000_000_000_000_000,
            )],
        );
        let cert = certify_best(&snap, 100_000_000_000_000_000_000, out);
        assert!(
            cert.consistent,
            "bound {} < achieved {}",
            cert.bound, cert.achieved
        );
        // Post-trade marginal prices make the dual tight: the arbitrage the
        // dual admits is exactly the trade that was executed.
        assert!(
            cert.gap <= U256::from(ROUNDING_WEI),
            "gap {} wei on a single-pool quote",
            cert.gap
        );
        assert!(cert.gap_bps_e4 <= 1, "{} e-4 bps", cert.gap_bps_e4);
    }

    #[test]
    fn a_split_across_equals_certifies_at_zero_gap() {
        let out = Address::repeat_byte(0xb7);
        let pool = |id| {
            v2_pool(
                id,
                SLVR,
                out,
                5_000_000_000_000_000_000_000,
                6_000_000_000_000_000_000_000,
            )
        };
        let snap = snapshot(vec![], vec![pool(11), pool(12)]);
        let cert = certify_best(&snap, 200_000_000_000_000_000_000, out);
        assert!(cert.consistent);
        assert!(
            cert.gap <= U256::from(ROUNDING_WEI),
            "gap {} wei on a symmetric split",
            cert.gap
        );
        assert!(cert.gap_bps_e4 <= 1, "{} e-4 bps", cert.gap_bps_e4);
    }

    /// The gradient against the bound it claims to be the gradient OF.
    ///
    /// `log_gradient` is derived from Danskin rather than from differentiating
    /// `bound_at`, so nothing structural forces the two to agree — and a
    /// gradient that is merely plausible sends the search off in a direction
    /// the line search then rejects, which looks exactly like convergence.
    /// Central differences in log coordinates are the check.
    #[test]
    fn the_gradient_agrees_with_a_finite_difference_of_the_bound() {
        let out = Address::repeat_byte(0xb7);
        let snap = snapshot(
            vec![
                v3_pool(21, SLVR, WETH, 900_000_000_000_000_000_000, 3_000),
                v3_pool(22, WETH, out, 700_000_000_000_000_000_000, 500),
            ],
            vec![
                v2_pool(
                    11,
                    SLVR,
                    out,
                    5_000_000_000_000_000_000_000,
                    6_000_000_000_000_000_000_000,
                ),
                v2_pool(
                    12,
                    SLVR,
                    WETH,
                    3_000_000_000_000_000_000_000,
                    4_000_000_000_000_000_000_000,
                ),
            ],
        );
        let amount = U256::from(10u64).pow(U256::from(20u64));
        let plan = best_plan(&snap, SLVR, out, amount, 256, 50).expect("plan");
        let states = crate::route::plan_states(&snap, &plan).expect("states");
        let routed = PoolSet::of(&snap, &plan);
        let prices = dual_prices(&snap, out, &states, &routed).expect("prices");
        let gradient = log_gradient(&snap, SLVR, amount, &prices, None).expect("gradient");

        // 0.1% either way: wide enough to clear integer dust, narrow enough
        // that the secant still tracks the derivative.
        for (token, analytic) in &gradient {
            if *token == out || prices.get(token).is_none_or(|price| price.is_zero()) {
                continue;
            }
            let at = |num: u64, den: u64| -> f64 {
                let mut probe = prices.clone();
                let base = probe[token];
                probe.insert(
                    *token,
                    Price::from_ratio(
                        wide(base.num) * U512::from(num),
                        wide(base.den) * U512::from(den),
                    )
                    .expect("price"),
                );
                to_f64(
                    bound_at(&snap, SLVR, amount, &probe, None, &routed)
                        .expect("bound")
                        .0,
                )
            };
            let (up, down) = (at(1_001, 1_000), at(999, 1_000));
            let secant = (up - down) / (2.0 * 0.001);
            let scale = analytic.abs().max(secant.abs()).max(1.0);
            assert!(
                (analytic - secant).abs() / scale < 0.05,
                "{token:#x}: analytic {analytic:.6e} vs finite difference {secant:.6e}"
            );
        }
    }

    /// A capped bound decides exactly what the full bound decides: `None`
    /// precisely when the bound is at least the cap, the bound itself
    /// otherwise — at dual points near the optimum and far from it, where
    /// walks run deep and the cap ends them early.
    #[test]
    fn a_capped_bound_decides_as_the_full_bound_does() {
        let out = Address::repeat_byte(0xb7);
        let snap = snapshot(
            vec![
                v3_pool(21, SLVR, WETH, 900_000_000_000_000_000_000, 3_000),
                v3_pool(22, WETH, out, 700_000_000_000_000_000_000, 500),
                v3_pool(23, SLVR, out, 400_000_000_000_000_000_000, 3_000),
            ],
            vec![v2_pool(
                11,
                SLVR,
                out,
                5_000_000_000_000_000_000_000,
                6_000_000_000_000_000_000_000,
            )],
        );
        let amount = U256::from(10u64).pow(U256::from(20u64));
        let plan = best_plan(&snap, SLVR, out, amount, 256, 50).expect("plan");
        let states = crate::route::plan_states(&snap, &plan).expect("states");
        let routed = PoolSet::of(&snap, &plan);
        let prices = dual_prices(&snap, out, &states, &routed).expect("prices");
        for (num, den) in [(1u64, 1u64), (1, 1_000_000_000), (3, 4), (4, 3), (1_000, 1)] {
            let mut probe = prices.clone();
            for token in [SLVR, WETH] {
                let base = probe[&token];
                probe.insert(
                    token,
                    Price::from_ratio(
                        wide(base.num) * U512::from(num),
                        wide(base.den) * U512::from(den),
                    )
                    .expect("price"),
                );
            }
            let full = bound_at(&snap, SLVR, amount, &probe, None, &routed).expect("bound");
            for cap in [
                U256::ZERO,
                U256::ONE,
                full.0 / U256::from(2),
                full.0.saturating_sub(U256::ONE),
                full.0,
                full.0 + U256::ONE,
                full.0 * U256::from(2),
            ] {
                let capped = bound_below(&snap, SLVR, amount, &probe, None, &routed, Some(cap))
                    .expect("capped bound");
                if full.0 >= cap {
                    assert_eq!(capped, None, "{num}/{den}: cap {cap} under {}", full.0);
                } else {
                    assert_eq!(capped, Some(full), "{num}/{den}: cap {cap}");
                }
            }
        }
    }

    /// `arb_p` against the simulator it is supposed to bound.
    ///
    /// The closed forms claim to be `sup { ν·δ : δ ∈ T_p }`. This scans δ
    /// through the EXACT simulator and demands the closed form dominate every
    /// sample (it is an upper bound) while staying close to the best one (it
    /// is meant to be tight). Nothing else in this file checks the arithmetic
    /// against an independent computation of the same quantity.
    fn brute_force_arb(
        sim: impl Fn(U256) -> Option<U256>,
        price_in: Price,
        price_out: Price,
        scale: U256,
    ) -> U256 {
        let mut best = U256::ZERO;
        // Geometric ladder, then a linear refinement around the winner.
        let mut coarse = U256::ZERO;
        for step in 0..64 {
            let delta = scale * U256::from(2u64).pow(U256::from(step)) / U256::from(1u64 << 20);
            if delta.is_zero() {
                continue;
            }
            let Some(out) = sim(delta) else { continue };
            let gain = price_out.value_down(out).expect("gain");
            let cost = price_in.value_up(delta).expect("cost");
            let profit = narrow(gain.saturating_sub(cost)).expect("profit");
            if profit > best {
                best = profit;
                coarse = delta;
            }
        }
        for step in 1..64u64 {
            for delta in [
                coarse * U256::from(step) / U256::from(32u64),
                coarse * U256::from(32u64 + step) / U256::from(32u64),
            ] {
                if delta.is_zero() {
                    continue;
                }
                let Some(out) = sim(delta) else { continue };
                let gain = price_out.value_down(out).expect("gain");
                let cost = price_in.value_up(delta).expect("cost");
                let profit = narrow(gain.saturating_sub(cost)).expect("profit");
                best = best.max(profit);
            }
        }
        best
    }

    #[test]
    fn constant_product_arb_matches_a_scan_of_the_simulator() {
        let out = Address::repeat_byte(0xb7);
        let (pool, state) = v2_pool(
            11,
            SLVR,
            out,
            5_000_000_000_000_000_000_000,
            6_000_000_000_000_000_000_000,
        );
        for (num, den) in [(1u64, 1u64), (11, 10), (5, 4), (2, 1), (9, 10), (1, 2)] {
            let price_in = Price::from_ratio(U512::from(num), U512::from(den)).expect("price");
            let closed = arb_v2_side(
                state.reserve0,
                state.reserve1,
                pool.fee_bps,
                price_in,
                Price::ONE,
            )
            .expect("arb");
            let scanned = brute_force_arb(
                |delta| {
                    crate::pools::sim_v2(&pool, &state, true, delta)
                        .ok()
                        .map(|sim| sim.amount_out)
                },
                price_in,
                Price::ONE,
                state.reserve0,
            );
            assert!(
                closed >= scanned,
                "{num}/{den}: closed form {closed} below a reachable {scanned}"
            );
            // Within 0.1% of the best sample: the scan is a grid, so it lands
            // near the peak rather than on it.
            assert!(
                closed <= scanned + scanned / U256::from(1_000u64) + U256::from(1_000u64),
                "{num}/{den}: closed form {closed} far above the best reachable {scanned}"
            );
        }
    }

    #[test]
    fn concentrated_liquidity_arb_matches_a_scan_of_the_simulator() {
        let out = Address::repeat_byte(0xb7);
        let (pool, state) = v3_pool(21, SLVR, out, 5_000_000_000_000_000_000, 3_000);
        for (num, den) in [(1u64, 1u64), (11, 10), (5, 4), (2, 1), (9, 10), (1, 2)] {
            let price_in = Price::from_ratio(U512::from(num), U512::from(den)).expect("price");
            let closed = arb_v3_side(&pool, &state, true, price_in, Price::ONE, None)
                .expect("arb")
                .expect("uncapped");
            let scanned = brute_force_arb(
                |delta| {
                    crate::pools::sim_v3(&pool, &state, true, delta)
                        .ok()
                        .filter(|sim| sim.consumed == delta)
                        .map(|sim| sim.amount_out)
                },
                price_in,
                Price::ONE,
                state.liquidity,
            );
            assert!(
                closed >= scanned,
                "{num}/{den}: closed form {closed} below a reachable {scanned}"
            );
            assert!(
                closed <= scanned + scanned / U256::from(1_000u64) + U256::from(1_000u64),
                "{num}/{den}: closed form {closed} far above the best reachable {scanned}"
            );
        }
    }

    /// The one property that must never break: a certificate that reads below
    /// what the quote actually delivered is a false certificate, and a false
    /// certificate is worse than none. Swept over randomized catalogs — mixed
    /// pool families, fee tiers, depths, price offsets and trade sizes,
    /// including sizes far past the modelled depth.
    #[test]
    fn the_bound_never_falls_below_what_a_plan_delivered() {
        let out = Address::repeat_byte(0xb7);
        // Deterministic LCG: a fixed sweep beats a flaky random one, and a
        // failure is reproducible from the case index alone.
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move |bound: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % bound
        };
        let mut certified = 0usize;
        for case in 0..400 {
            let mut v2 = Vec::new();
            let mut v3 = Vec::new();
            for slot in 0..1 + next(4) as usize {
                let tokens = match next(3) {
                    0 => (SLVR, out),
                    1 => (SLVR, WETH),
                    _ => (WETH, out),
                };
                let depth = U256::from(10u64).pow(U256::from(15 + next(8)));
                if next(2) == 0 {
                    let (mut pool, mut state) = v3_pool(
                        slot as u8,
                        tokens.0,
                        tokens.1,
                        1,
                        [100, 500, 3_000][next(3) as usize],
                    );
                    state.liquidity = depth;
                    // Offset the price so pools disagree and arbitrage is live.
                    let tick = next(20_000) as i32 - 10_000;
                    state.sqrt_price = sqrt_ratio_at_tick(tick).expect("sqrt price");
                    state.tick = tick;
                    state.pos = state.ticks.partition_point(|info| info.tick <= tick);
                    pool.address = Address::repeat_byte(0x30 + slot as u8);
                    v3.push((pool, state));
                } else {
                    let skew = 1 + next(4);
                    v2.push(v2_pool(
                        0x40 + slot as u8,
                        tokens.0,
                        tokens.1,
                        u128::try_from(depth).expect("depth fits"),
                        u128::try_from(depth * U256::from(skew)).expect("depth fits"),
                    ));
                }
            }
            let snap = snapshot(v3, v2);
            let amount = U256::from(10u64).pow(U256::from(12 + next(11)));
            let Ok(plan) = best_plan(&snap, SLVR, out, amount, 64, 50) else {
                continue; // no route through this catalog
            };
            if plan.amount_out.is_zero() {
                continue;
            }
            let cert = certify(&ROBINHOOD_PROFILE, &snap, SLVR, out, amount, &plan)
                .unwrap_or_else(|error| panic!("case {case}: {error:#}"));
            assert!(
                cert.consistent,
                "case {case}: bound {} below achieved {} (amount {amount})",
                cert.bound, cert.achieved
            );
            certified += 1;
        }
        assert!(certified > 100, "only {certified} cases produced a route");
    }

    /// Tightness in the regime production actually runs in: several venues,
    /// mixed families and depths, all quoting the SAME price — so the catalog
    /// holds no cycle arbitrage and the whole gap is allocation regret. What
    /// is left is the allocator's own chunk granularity, which is exactly what
    /// the certificate is supposed to be able to see.
    #[test]
    fn an_arbitrage_free_catalog_certifies_within_a_basis_point() {
        let out = Address::repeat_byte(0xb7);
        let unit = U256::from(10u64).pow(U256::from(20u64));
        let snap = snapshot(
            vec![
                v3_pool(21, SLVR, out, 4_000_000_000_000_000_000_000, 500),
                v3_pool(22, SLVR, out, 9_000_000_000_000_000_000_000, 3_000),
            ],
            vec![
                v2_pool(
                    11,
                    SLVR,
                    out,
                    6_000_000_000_000_000_000_000,
                    6_000_000_000_000_000_000_000,
                ),
                v2_pool(
                    12,
                    SLVR,
                    out,
                    2_000_000_000_000_000_000_000,
                    2_000_000_000_000_000_000_000,
                ),
            ],
        );
        for size in [1u64, 10, 100, 1_000] {
            let amount = unit * U256::from(size);
            let plan = best_plan(&snap, SLVR, out, amount, 256, 50).expect("plan");
            let cert =
                certify(&ROBINHOOD_PROFILE, &snap, SLVR, out, amount, &plan).expect("certificate");
            assert!(
                cert.consistent,
                "size {size}: bound {} < achieved {}",
                cert.bound, cert.achieved
            );
            // Measured 0.0032 / 0.060 / 0.58 / 0.42 bp at the four sizes:
            // small trades allocate almost perfectly, and the residual grows
            // with size as chunk granularity starts to matter. One basis point
            // is the program's stated p95 target for this number.
            assert!(
                cert.gap_bps_e4 <= 10_000,
                "size {size}: {} e-4 bps of certified regret on an arbitrage-free catalog",
                cert.gap_bps_e4
            );
        }
    }

    #[test]
    fn a_pool_the_plan_never_used_shows_up_as_gap() {
        let out = Address::repeat_byte(0xb7);
        let thin = snapshot(vec![], vec![v2_pool(11, SLVR, out, 5_000_000, 6_000_000)]);
        let plan = best_plan(&thin, SLVR, out, U256::from(200_000u64), 256, 50).expect("plan");
        // The same plan, certified against a snapshot that also contains a
        // second pool: the dual prices the missed venue and the gap opens.
        let full = snapshot(
            vec![],
            vec![
                v2_pool(11, SLVR, out, 5_000_000, 6_000_000),
                v2_pool(12, SLVR, out, 5_000_000, 6_000_000),
            ],
        );
        let cert = certify(
            &ROBINHOOD_PROFILE,
            &full,
            SLVR,
            out,
            U256::from(200_000u64),
            &plan,
        )
        .expect("certificate");
        assert!(cert.consistent);
        assert!(cert.unrouted_pools >= 1);
        assert!(
            cert.gap_bps_e4 > 1_000,
            "an unrouted equal-depth pool must open a visible gap, got {} e-4 bps",
            cert.gap_bps_e4
        );
    }

    #[test]
    fn the_bound_dominates_a_plan_that_missed_the_deep_pool() {
        let out = Address::repeat_byte(0xb7);
        let amount = U256::from(300_000u64);
        // Solve against the shallow pool alone, then certify that plan against
        // the snapshot where the deep pool also exists. Index 0 is the same
        // pool in both, so the plan's hops stay valid.
        let shallow = v2_pool(12, SLVR, out, 1_000_000, 1_000_000);
        let thin = snapshot(vec![], vec![shallow.clone()]);
        let plan = best_plan(&thin, SLVR, out, amount, 256, 50).expect("plan");
        let full = snapshot(
            vec![],
            vec![shallow, v2_pool(11, SLVR, out, 9_000_000, 9_000_000)],
        );
        let cert =
            certify(&ROBINHOOD_PROFILE, &full, SLVR, out, amount, &plan).expect("certificate");
        assert!(
            cert.consistent,
            "bound {} < achieved {}",
            cert.bound, cert.achieved
        );
        let better = best_plan(&full, SLVR, out, amount, 256, 50).expect("plan");
        assert!(better.amount_out > plan.amount_out);
        assert!(
            cert.bound >= better.amount_out,
            "bound {} must dominate the better plan's {}",
            cert.bound,
            better.amount_out
        );
    }

    #[test]
    fn a_concentrated_liquidity_quote_certifies_tightly() {
        let out = Address::repeat_byte(0xb7);
        let snap = snapshot(vec![v3_pool(21, SLVR, out, 5_000_000_000_000, 500)], vec![]);
        let cert = certify_best(&snap, 1_000_000_000, out);
        assert!(
            cert.consistent,
            "bound {} < achieved {}",
            cert.bound, cert.achieved
        );
        assert!(
            cert.gap_bps_e4 <= 200,
            "gap {} e-4 bps on a single-range CL quote",
            cert.gap_bps_e4
        );
    }

    #[test]
    fn the_bound_dominates_every_plan_on_a_mixed_snapshot() {
        let out = Address::repeat_byte(0xb7);
        let (v3, v3_state) = v3_pool(21, SLVR, WETH, 900_000_000_000, 3_000);
        let snap = snapshot(
            vec![(v3, v3_state)],
            vec![
                v2_pool(11, SLVR, out, 5_000_000_000, 6_000_000_000),
                v2_pool(12, WETH, out, 8_000_000_000, 7_000_000_000),
                v2_pool(13, SLVR, USDG, 4_000_000_000, 5_000_000_000),
                v2_pool(14, USDG, out, 6_000_000_000, 6_500_000_000),
            ],
        );
        for size in [1_000_000u128, 50_000_000, 900_000_000] {
            let cert = certify_best(&snap, size, out);
            assert!(
                cert.consistent,
                "size {size}: bound {} < achieved {}",
                cert.bound, cert.achieved
            );
        }
    }

    #[test]
    fn prices_normalize_without_collapsing_to_zero() {
        let tiny = Price::from_ratio(U512::ONE, U512::ONE << 200usize).expect("price");
        assert!(!tiny.is_zero());
        let one = Price::from_ratio(U512::from(7u64), U512::from(7u64)).expect("price");
        assert!(!one.greater(Price::ONE).expect("compare"));
        assert!(!Price::ONE.greater(one).expect("compare"));
    }

    #[test]
    fn bps_formatting_keeps_four_decimals() {
        assert_eq!(format_bps_e4(U256::ZERO), "0.0000");
        assert_eq!(format_bps_e4(U256::from(12_345u64)), "1.2345");
        assert_eq!(format_bps_e4(U256::from(10_000u64)), "1.0000");
    }

    /// A ratio past `u64` used to be published as `u64::MAX/10⁴`, which reads as
    /// a measurement and is not one. Two properties pin the fix: the value that
    /// used to be invented is now reachable only by actually being that value,
    /// and a ratio beyond `u64` prints its own magnitude.
    #[test]
    fn a_bps_ratio_past_u64_prints_itself_instead_of_a_sentinel() {
        let fabricated = format_bps_e4(U256::from(u64::MAX));
        assert_eq!(fabricated, "1844674407370955.1615");

        // One unit past the old ceiling: previously indistinguishable from every
        // larger value, now distinct from all of them.
        let past = format_bps_e4(U256::from(u64::MAX) + U256::ONE);
        assert_eq!(past, "1844674407370955.1616");
        assert_ne!(past, fabricated);

        // Far past it, at a magnitude `u64` cannot hold at all.
        let huge = U256::from(u64::MAX) * U256::from(1_000_000u64);
        assert_eq!(format_bps_e4(huge), "1844674407370955161500.0000");

        // The escalation comparison in `quotes.rs` is `U256 > u64` — a MIXED
        // type form. Widening `gap_bps_e4` silently changed which `PartialOrd`
        // it resolves to, and a wide value truncating into the comparison would
        // stop escalation firing on exactly the loosest quotes it exists for.
        let threshold: u64 = 10_000;
        assert!(huge > threshold);
        assert!(U256::from(u64::MAX) + U256::ONE > threshold);
        assert!(U256::from(u64::MAX) > threshold);
        assert!(U256::from(9_999u64) < threshold);
        assert!(U256::from(10_000u64) == threshold);
    }
}
