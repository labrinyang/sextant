// Plan → 0x Settler `bytes[] actions` → transaction.
//
// Ground truth: the 0x Settler builds each chain profile reviews
// (`SettlerProfile`); `SettlerEncoding` names the calldata semantics of each.
// Invariants:
//   - tokens are NEVER approved to the Settler; ERC20 input flows through
//     AllowanceHolder.exec's ephemeral permit,
//   - the Settler address comes from the selected profile's registry snapshot
//     (ownerOf(profile.settler.registry_token_id)); this encoder consumes the
//     already-resolved Snapshot::settler,
//   - permit.deadline (or NATIVE_CHECK for native input) enforces expiry,
//   - actions run in topological order over the Settler's live balances; the
//     last action selling a token sells all of it,
//   - output custody stays in the Settler until the terminal fee and optional
//     positive-slippage actions run; every other token the route touched is
//     then returned to the recipient with POSITIVE_SLIPPAGE, and execute() pays
//     the output to the recipient and enforces the net minimum on-chain.

use crate::abi::{self, be_bytes};
#[cfg(any(test, feature = "testing"))]
use crate::chain::ROBINHOOD_PROFILE;
use crate::chain::{ChainProfile, NATIVE, SettlerEncoding, V4_DYNAMIC_FEE_FLAG, V4_MAX_FEE_PPM};
use crate::ekubo::EkuboPool;
use crate::plan::{Hop, HopKind, Plan};
use crate::rfq::{NativeBeneficiaryAuthorizer, ValidatedFirmQuote};
use crate::snapshot::Snapshot;
use crate::v3math::sqrt_limit;
use alloy_primitives::{Address, B256, Bytes, U256, aliases::U24};
use alloy_sol_types::SolCall;
use anyhow::{Context, ensure};

pub use crate::plan::BPS_BASE;

/// Balance-funded Settler fork path:
/// token | uint8 forkId | uint24 poolId | uint160 sqrtLimit | token | …
pub fn v3_path(snap: &Snapshot, hops: &[Hop]) -> anyhow::Result<Vec<u8>> {
    let first = hops.first().context("empty V3 path")?;
    let mut buf = first.token_in.to_vec();
    for h in hops {
        ensure!(h.kind == HopKind::V3, "non-V3 hop in V3 path");
        let pool = &snap.v3[h.index].0;
        ensure!(pool.v4.is_none(), "V4 hop in V3 fork path");
        let execution = pool
            .execution
            .context("V3 pool has no execution metadata")?;
        buf.extend_from_slice(&be_bytes(U256::from(execution.fork_id), 1)?);
        buf.extend_from_slice(&be_bytes(U256::from(execution.pool_id), 3)?);
        buf.extend_from_slice(&be_bytes(sqrt_limit(h.zero_for_one), 20)?);
        buf.extend_from_slice(h.token_out.as_slice());
    }
    Ok(buf)
}

fn v3_vip_path(
    encoding: SettlerEncoding,
    snap: &Snapshot,
    hops: &[Hop],
) -> anyhow::Result<Vec<u8>> {
    let path = v3_path(snap, hops)?;
    match encoding {
        SettlerEncoding::LegacyBpsVipPathWithSellToken => Ok(path),
        // New runtimes recover the sell token from the PermitTransferFrom and
        // start decoding the path at forkId. Every remaining hop is 44 bytes.
        SettlerEncoding::PpmVipPathFromPermit => Ok(path[Address::len_bytes()..].to_vec()),
    }
}

/// Convert API-facing basis points to the proportional unit read by a Settler runtime.
pub fn settler_proportion(encoding: SettlerEncoding, bps: u32) -> U256 {
    let bps = U256::from(bps);
    match encoding {
        SettlerEncoding::LegacyBpsVipPathWithSellToken => bps,
        SettlerEncoding::PpmVipPathFromPermit => bps * U256::from(100u8),
    }
}

fn packed_proportion(encoding: SettlerEncoding, bps: u32) -> anyhow::Result<Vec<u8>> {
    let width = match encoding {
        SettlerEncoding::LegacyBpsVipPathWithSellToken => 2,
        SettlerEncoding::PpmVipPathFromPermit => 3,
    };
    be_bytes(settler_proportion(encoding, bps), width)
}

/// Split a path into runs encodable as one action each. Uniswap-V3-style
/// hops (every V3 fork, each with its own fork id) and Ekubo
/// hops each chain within their own packed action; V4 and V2 stand alone.
/// Sequential actions drain the intermediate token fully (bps = 10⁴).
pub fn segments(snap: &Snapshot, path: &[Hop]) -> anyhow::Result<Vec<Vec<Hop>>> {
    let classic_v3 = |h: &Hop| h.kind == HopKind::V3 && snap.v3[h.index].0.v4.is_none();
    let chains = |left: &Hop, right: &Hop| {
        (classic_v3(left) && classic_v3(right))
            || (left.kind == HopKind::Ekubo && right.kind == HopKind::Ekubo)
    };
    let mut segs: Vec<Vec<Hop>> = Vec::new();
    for hop in path {
        if classic_v3(hop) {
            snap.v3[hop.index]
                .0
                .execution
                .context("V3 pool has no execution metadata")?;
        }
        match segs.last_mut() {
            Some(last) if chains(last.last().expect("nonempty"), hop) => {
                last.push(hop.clone());
            }
            _ => segs.push(vec![hop.clone()]),
        }
    }
    Ok(segs)
}

/// Perfect-hash parameters for a flash-accounting action's token notes table. The
/// contract scales BOTH arguments by 96 (the Note size) itself, then indexes
/// `mod(mulmod(token, 96·hashMul, 96·hashMod), 96·8)` — the 96 factors out
/// exactly, so the slot index is `((token·hashMul) mod hashMod) mod 8` and a
/// tiny search over the involved tokens suffices. Passing pre-scaled values
/// would double-scale and collide every token (TokenHashCollision).
fn note_perfect_hash(tokens: &[Address]) -> anyhow::Result<(U256, U256)> {
    let mut ts: Vec<U256> = tokens
        .iter()
        .map(|t| U256::from_be_slice(t.as_slice()))
        .collect();
    ts.sort();
    ts.dedup();
    for b in 1u64..=4096 {
        let bu = U256::from(b);
        for a in 1..=b {
            let mut slots: Vec<u8> = ts
                .iter()
                .map(|t| {
                    u8::try_from((t % bu * U256::from(a) % bu) % U256::from(8u8)).expect("mod 8")
                })
                .collect();
            slots.sort_unstable();
            slots.dedup();
            if slots.len() == ts.len() {
                return Ok((U256::from(a), U256::from(b)));
            }
        }
    }
    anyhow::bail!("no note hash for {} tokens", ts.len())
}

/// One V4 fill in the selected Settler runtime's packed format: proportion
/// (2-byte bps or 3-byte ppm) | sqrtLimit 20B | packing key 1B (1 = buy token
/// only) | buyToken 20B | fee 3B | tickSpacing 3B | hooks 20B | hookData length
/// 3B. `buy` is the token as the SETTLER sees it — the ETH sentinel for the
/// native side of a native pool.
fn v4_fill(
    encoding: SettlerEncoding,
    snap: &Snapshot,
    hop: &Hop,
    buy: Address,
) -> anyhow::Result<Vec<u8>> {
    let pool = &snap.v3[hop.index].0;
    ensure!(
        pool.protocol.core() == crate::venue::Core::UniV4,
        "V4 metadata is attached to a non-Univ4 pool"
    );
    ensure!(
        pool.fee_ppm <= V4_MAX_FEE_PPM || pool.fee_ppm == V4_DYNAMIC_FEE_FLAG,
        "V4 PoolKey fee is unresolved or unsupported"
    );
    let hooks = pool
        .v4
        .as_ref()
        .context("v4 fill for a pool without V4Meta")?
        .hooks;
    let mut fill = packed_proportion(encoding, BPS_BASE)?;
    fill.extend_from_slice(&be_bytes(sqrt_limit(hop.zero_for_one), 20)?);
    fill.push(1);
    fill.extend_from_slice(buy.as_slice());
    // The PoolKey fee — V4_DYNAMIC_FEE_FLAG (0x800000) for dynamic pools —
    // and the real hooks address: the PoolManager looks the pool up by the
    // exact key, so identity fields are never substituted. Admitted hooks
    // take no hook data (they are never called during the swap).
    fill.extend_from_slice(&be_bytes(U256::from(pool.fee_ppm), 3)?);
    fill.extend_from_slice(&be_bytes(U256::from(u32::try_from(pool.tick_spacing)?), 3)?);
    fill.extend_from_slice(hooks.as_slice());
    fill.extend_from_slice(&be_bytes(U256::ZERO, 3)?);
    Ok(fill)
}

const EKUBO_MIN_SQRT_RATIO: u128 = 4_611_797_791_050_542_631;
const EKUBO_MAX_SQRT_RATIO: u128 = 79_227_682_466_138_141_934_206_691_491;

fn ekubo_token(pool: &EkuboPool, zero_for_one: bool, buy: bool) -> Address {
    let token = match (zero_for_one, buy) {
        (true, false) | (false, true) => pool.core_token0,
        (true, true) | (false, false) => pool.core_token1,
    };
    if token == Address::ZERO {
        NATIVE
    } else {
        token
    }
}

/// Linear Ekubo run: each hop spends the preceding hop's output. The first
/// packing key encodes only its buy token; later key 2 reuses the prior buy as
/// the next sell. Config retains the exact Core pool identity, including Ve33.
fn ekubo_fills(
    encoding: SettlerEncoding,
    snap: &Snapshot,
    hops: &[Hop],
) -> anyhow::Result<Vec<u8>> {
    let mut fills = Vec::new();
    for (index, hop) in hops.iter().enumerate() {
        ensure!(hop.kind == HopKind::Ekubo, "non-Ekubo hop in Ekubo fills");
        let pool = &snap.ekubo[hop.index].0;
        let expected = if hop.zero_for_one {
            (pool.token0, pool.token1)
        } else {
            (pool.token1, pool.token0)
        };
        ensure!(
            (hop.token_in, hop.token_out) == expected,
            "Ekubo hop tokens/direction do not match its pool"
        );
        let mut proportion = packed_proportion(encoding, BPS_BASE)?;
        if pool.extension.requires_forward() {
            // Both packed formats reserve the high bit for Ekubo's forward call.
            proportion[0] |= 0x80;
        }
        fills.extend_from_slice(&proportion);
        fills.extend_from_slice(&be_bytes(
            U256::from(if hop.zero_for_one {
                EKUBO_MIN_SQRT_RATIO
            } else {
                EKUBO_MAX_SQRT_RATIO
            }),
            12,
        )?);
        fills.push(if index == 0 { 1 } else { 2 });
        fills.extend_from_slice(ekubo_token(pool, hop.zero_for_one, true).as_slice());
        fills.extend_from_slice(pool.config.as_slice());
    }
    Ok(fills)
}

#[derive(Clone, Debug)]
pub struct BuiltTx {
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
    pub allowance_target: Option<Address>,
    pub settler: Address,
}

/// Positive-slippage capture: everything above `expected_amount`, up to
/// `max_bps` of the output, goes to `recipient`. Off by default; at launch all
/// positive slippage stays with the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PositiveSlippage {
    pub recipient: Address,
    pub expected_amount: U256,
    pub max_bps: u32,
}

/// One ordered liquidity stage in a transaction containing a Native.org RFQ.
///
/// AMM plans remain the snapshot-bound, synchronous domain owned by `route`;
/// the external firm quote is kept as a separate stage so it cannot accidentally
/// enter AMM simulation or certification. A composed transaction may contain a
/// single stage (direct Native) or two stages (AMM -> Native / Native -> AMM).
#[derive(Clone, Copy, Debug)]
pub enum ComposedSwapStage<'a> {
    Amm {
        plan: &'a Plan,
    },
    NativeRfq {
        quote: &'a ValidatedFirmQuote,
        token_in: Address,
        token_out: Address,
    },
}

#[derive(Clone, Copy, Debug)]
struct StageShape {
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    amount_out: U256,
}

fn permit_tuple(token: Address, amount: U256, deadline: u64) -> abi::PermitTransferFrom {
    abi::PermitTransferFrom {
        permitted: abi::TokenPermissions { token, amount },
        nonce: U256::ZERO,
        deadline: U256::from(deadline),
    }
}

fn single_v3(snap: &Snapshot, plan: &Plan) -> bool {
    plan.legs.len() == 1
        && plan.legs[0]
            .path
            .iter()
            .all(|h| h.kind == HopKind::V3 && snap.v3[h.index].0.v4.is_none())
}

fn ensure_external_recipient(
    recipient: Address,
    settler: Address,
    boundary: &str,
) -> anyhow::Result<()> {
    ensure!(recipient != Address::ZERO, "{boundary} must not be zero");
    ensure!(recipient != settler, "{boundary} must not be the Settler");
    Ok(())
}

/// Request-level sanity checks for a transaction-bearing quote: nonzero
/// sender, external recipients, and a configured receiver whenever a fee or
/// positive-slippage action will run. Token transfer behavior is deliberately
/// NOT validated: the solver treats every token uniformly and encodes
/// settlement so the Settler measures actual credited balances instead of
/// predicting them.
pub fn validate_recipients(
    settler: Address,
    fee_bps: u32,
    fee_receiver: Option<Address>,
    positive_slippage: Option<PositiveSlippage>,
    sender: Address,
    recipient: Address,
) -> anyhow::Result<()> {
    ensure!(sender != Address::ZERO, "sender must not be zero");
    ensure_external_recipient(recipient, settler, "recipient")?;
    match fee_receiver {
        Some(receiver) => ensure_external_recipient(receiver, settler, "fee receiver")?,
        None => ensure!(fee_bps == 0, "fee receiver is not configured"),
    }
    if let Some(positive_slippage) = positive_slippage {
        ensure_external_recipient(
            positive_slippage.recipient,
            settler,
            "positive slippage recipient",
        )?;
        ensure!(
            (1..=BPS_BASE).contains(&positive_slippage.max_bps),
            "positive slippage max bps out of range"
        );
    }
    Ok(())
}

fn amm_stage_shape(plan: &Plan) -> anyhow::Result<StageShape> {
    let first_leg = plan.legs.first().context("AMM stage has no legs")?;
    let first_hop = first_leg
        .path
        .first()
        .context("AMM stage contains an empty leg")?;
    let token_in = first_hop.token_in;
    let token_out = first_leg.path.last().expect("first hop checked").token_out;
    let mut amount_in = U256::ZERO;
    let mut amount_out = U256::ZERO;

    for (leg_index, leg) in plan.legs.iter().enumerate() {
        ensure!(
            !leg.amount_in.is_zero(),
            "AMM stage contains a zero-input leg"
        );
        ensure!(
            !leg.amount_out.is_zero(),
            "AMM stage contains a zero-output leg"
        );
        ensure!(
            (1..=BPS_BASE).contains(&leg.slice_bps),
            "AMM stage is not quantized"
        );
        if leg_index + 1 == plan.legs.len() {
            ensure!(
                leg.slice_bps == BPS_BASE,
                "AMM stage final leg must drain its remaining input"
            );
        }
        let first = leg
            .path
            .first()
            .context("AMM stage contains an empty leg")?;
        let mut current = first.token_in;
        for hop in &leg.path {
            ensure!(
                hop.token_in == current,
                "AMM stage contains a discontinuous leg"
            );
            current = hop.token_out;
        }
        ensure!(
            first.token_in == token_in && current == token_out,
            "AMM stage legs do not share endpoints"
        );
        amount_in = amount_in
            .checked_add(leg.amount_in)
            .context("AMM stage input overflow")?;
        amount_out = amount_out
            .checked_add(leg.amount_out)
            .context("AMM stage output overflow")?;
    }
    ensure!(
        amount_out == plan.amount_out,
        "AMM stage output does not match its plan"
    );
    Ok(StageShape {
        token_in,
        token_out,
        amount_in,
        amount_out,
    })
}

const NATIVE_V6_AMOUNT_IN_OFFSET: usize = 36;
const NATIVE_V6_AMOUNT_OUT_MINIMUM_OFFSET: usize = 68;
const NATIVE_V6_QUOTE_OFFSET: usize = 96;
const ABI_WORD_BYTES: usize = 32;

fn calldata_word(calldata: &[u8], offset: usize) -> anyhow::Result<U256> {
    let end = offset
        .checked_add(ABI_WORD_BYTES)
        .context("Native RFQ calldata offset overflow")?;
    let word = calldata
        .get(offset..end)
        .context("Native RFQ calldata is truncated")?;
    Ok(U256::from_be_slice(word))
}

fn native_quote_word(calldata: &[u8], index: usize) -> anyhow::Result<U256> {
    let quote_start = 4usize
        .checked_add(NATIVE_V6_QUOTE_OFFSET)
        .context("Native RFQ calldata offset overflow")?;
    let offset = index
        .checked_mul(ABI_WORD_BYTES)
        .and_then(|offset| quote_start.checked_add(offset))
        .context("Native RFQ calldata offset overflow")?;
    calldata_word(calldata, offset)
}

fn native_quote_address(calldata: &[u8], index: usize) -> anyhow::Result<Address> {
    let word = native_quote_word(calldata, index)?;
    let bytes = word.to_be_bytes::<32>();
    ensure!(
        bytes[..12].iter().all(|byte| *byte == 0),
        "Native RFQ calldata contains a non-canonical address"
    );
    Ok(Address::from_slice(&bytes[12..]))
}

fn native_stage_shape(
    profile: &ChainProfile,
    settler: Address,
    quote: &ValidatedFirmQuote,
    token_in: Address,
    token_out: Address,
) -> anyhow::Result<StageShape> {
    let native = profile
        .native_rfq
        .context("chain profile has no Native RFQ adapter")?;
    ensure!(
        token_in != NATIVE && token_out != NATIVE,
        "Native RFQ stages support ERC20 pairs only"
    );
    ensure!(
        token_in != Address::ZERO && token_out != Address::ZERO && token_in != token_out,
        "Native RFQ stage has an invalid token pair"
    );
    ensure!(
        quote.target() == native.router
            && quote.pool() == native.pool
            && quote.router_version() == native.router_version,
        "Native RFQ identity does not match the chain profile"
    );
    ensure!(
        quote.amount_in_offset() == NATIVE_V6_AMOUNT_IN_OFFSET
            && quote.amount_out_minimum_offset() == NATIVE_V6_AMOUNT_OUT_MINIMUM_OFFSET,
        "Native RFQ calldata offsets do not match Router v6"
    );
    ensure!(
        !quote.amount_in().is_zero() && !quote.amount_out().is_zero(),
        "Native RFQ stage has a zero amount"
    );
    ensure!(
        quote.observation().is_some(),
        "Native RFQ quote has no canonical on-chain observation"
    );

    let calldata = quote.calldata();
    ensure!(
        calldata.get(..4) == Some(native.trade_selector.as_slice()),
        "Native RFQ calldata selector does not match the chain profile"
    );
    ensure!(
        calldata_word(calldata, 4)? == U256::from(NATIVE_V6_QUOTE_OFFSET),
        "Native RFQ calldata quote offset does not match Router v6"
    );
    ensure!(
        calldata_word(calldata, NATIVE_V6_AMOUNT_IN_OFFSET)?.is_zero()
            && calldata_word(calldata, NATIVE_V6_AMOUNT_OUT_MINIMUM_OFFSET)?.is_zero(),
        "Native RFQ calldata already overrides dynamic amounts"
    );
    ensure!(
        native_quote_address(calldata, 0)? == native.pool,
        "Native RFQ calldata pool does not match the chain profile"
    );
    ensure!(
        native_quote_address(calldata, 2)? == settler
            && native_quote_address(calldata, 14)? == settler,
        "Native RFQ calldata is bound to a different Settler"
    );
    ensure!(
        native_quote_address(calldata, 3)? == token_in
            && native_quote_address(calldata, 4)? == token_out,
        "Native RFQ calldata token pair does not match its stage"
    );
    ensure!(
        native_quote_word(calldata, 5)? == quote.amount_in()
            && native_quote_word(calldata, 6)? == quote.amount_out(),
        "Native RFQ calldata amounts do not match the validated quote"
    );
    ensure!(
        native_quote_word(calldata, 8)? == U256::from(quote.deadline()),
        "Native RFQ calldata deadline does not match the validated quote"
    );
    Ok(StageShape {
        token_in,
        token_out,
        amount_in: quote.amount_in(),
        amount_out: quote.amount_out(),
    })
}

fn v2_action(
    profile: &ChainProfile,
    snap: &Snapshot,
    hop: &Hop,
    bps: u32,
) -> anyhow::Result<Bytes> {
    ensure!(hop.kind == HopKind::V2, "expected reserve-pool hop");
    let (pool, _) = snap.v2.get(hop.index).context("missing reserve pool")?;
    let expected = if hop.zero_for_one {
        (pool.token0, pool.token1)
    } else {
        (pool.token1, pool.token0)
    };
    ensure!(
        (hop.token_in, hop.token_out) == expected,
        "reserve-pool hop tokens/direction mismatch"
    );
    let settler = snap.settler.context("snapshot has no Settler")?;
    let encoding = profile
        .settler
        .context("execution profile missing")?
        .encoding;
    // swapInfo: fee in bps above bit 8, bit 1 = measure the input from the
    // pool's balance (sellTokenHasFee), bit 0 = zeroForOne. Measuring the
    // credited balance makes taxed and plain tokens settle alike.
    let swap_info = |fee_bps: u32| -> anyhow::Result<U24> {
        ensure!(fee_bps < 10_000, "reserve-pool fee is out of range");
        Ok(U24::from(
            (fee_bps << 8) | (1u32 << 1) | u32::from(hop.zero_for_one),
        ))
    };
    Ok(abi::UNISWAPV2Call {
        recipient: settler,
        sellToken: hop.token_in,
        ppm: settler_proportion(encoding, bps),
        pool: pool.address,
        swapInfo: swap_info(pool.fee_bps)?,
        amountOutMin: U256::ZERO,
    }
    .abi_encode()
    .into())
}

/// One Settler action's worth of a plan: a run of hops that a single action
/// executes, selling `bps` of the Settler's live balance of its first token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramStep {
    pub hops: Vec<Hop>,
    pub bps: u32,
}

/// Lower a plan into actions in topological order. Each leg's first run takes
/// its `slice_bps` share of what is left of the input; every later run sells
/// all of its token, because that run is the token's last use within the leg
/// and no other leg is holding any of it at that moment.
pub fn program(snap: &Snapshot, plan: &Plan) -> anyhow::Result<Vec<ProgramStep>> {
    let mut steps = Vec::new();
    for leg in &plan.legs {
        for (index, seg) in segments(snap, &leg.path)?.into_iter().enumerate() {
            let bps = if index == 0 { leg.slice_bps } else { BPS_BASE };
            steps.push(ProgramStep { hops: seg, bps });
        }
    }
    check_program(&steps, plan.legs.first().and_then(|leg| leg.path.first()))?;
    Ok(steps)
}

/// A program may only sell a token the Settler can hold at that point, and
/// the last step that sells a token must sell all of it; otherwise the rest
/// would sit idle until the refunds and the route would not be the one quoted.
pub fn check_program(steps: &[ProgramStep], first: Option<&Hop>) -> anyhow::Result<()> {
    let Some(first) = first else {
        ensure!(steps.is_empty(), "a program without input has steps");
        return Ok(());
    };
    let mut held = vec![first.token_in];
    for (index, step) in steps.iter().enumerate() {
        let sell = step.hops.first().context("empty program step")?.token_in;
        ensure!(
            held.contains(&sell),
            "program step {index} sells a token the Settler does not hold"
        );
        ensure!(
            (1..=BPS_BASE).contains(&step.bps),
            "program step {index} has an invalid proportion"
        );
        let mut current = sell;
        for hop in &step.hops {
            ensure!(
                hop.token_in == current,
                "program step {index} is discontinuous"
            );
            current = hop.token_out;
        }
        let last_sale = steps[index + 1..]
            .iter()
            .all(|later| later.hops.first().map(|hop| hop.token_in) != Some(sell));
        ensure!(
            !last_sale || step.bps == BPS_BASE,
            "program step {index} is the last sale of its token but leaves some behind"
        );
        if !held.contains(&current) {
            held.push(current);
        }
    }
    Ok(())
}

fn append_amm_plan_actions(
    profile: &ChainProfile,
    snap: &Snapshot,
    plan: &Plan,
    actions: &mut Vec<Bytes>,
) -> anyhow::Result<bool> {
    let settler = snap
        .settler
        .context("snapshot has no Settler execution identity")?;
    let wrapped_native = profile.wrapped_native;
    let settler_profile = profile
        .settler
        .context("chain profile has no Settler execution adapter")?;
    let encoding = settler_profile.encoding;
    let mut bought_native = false;

    let steps = program(snap, plan)?;
    for (step_index, step) in steps.iter().enumerate() {
        let seg = &step.hops;
        let mut bps = step.bps;
        // A V4/Ekubo native-currency output is wrapped again before the next
        // step only when that step continues the same leg.
        let continues = steps.get(step_index + 1).is_some_and(|next| {
            next.bps == BPS_BASE && next.hops[0].token_in == seg[seg.len() - 1].token_out
        });
        if seg[0].kind == HopKind::V3 && snap.v3[seg[0].index].0.v4.is_some() {
            let hop = &seg[0];
            let pool = &snap.v3[hop.index].0;
            let expected_manager = profile
                .settler
                .and_then(|settler| settler.univ4_pool_manager)
                .context("chain profile has no Settler Uniswap V4 binding")?;
            ensure!(
                pool.address == expected_manager,
                "V4 pool does not match the Settler PoolManager binding"
            );
            let native_pool = pool.v4.as_ref().expect("v4").native;
            let mut sell = hop.token_in;
            let mut buy = hop.token_out;
            if native_pool && hop.token_in == wrapped_native {
                // unwrap this leg's slice, then sell native currency
                actions.push(
                    abi::BASICCall {
                        sellToken: wrapped_native,
                        ppm: settler_proportion(encoding, bps),
                        pool: wrapped_native,
                        offset: U256::from(4),
                        data: abi::withdrawCall { amount: U256::ZERO }.abi_encode().into(),
                    }
                    .abi_encode()
                    .into(),
                );
                sell = NATIVE;
                bps = BPS_BASE; // the unwrap already took the slice
            } else if native_pool {
                // native currency comes out; wrap it after this step (mid-leg)
                // or once after all steps (final hop)
                buy = NATIVE;
                bought_native = true;
            }
            let (hash_mul, hash_mod) = note_perfect_hash(&[sell, buy])?;
            let fills: Bytes = v4_fill(encoding, snap, hop, buy)?.into();
            // ERC20 sells settle transfer-first so the pool manager credits
            // the actual received amount. Native currency cannot tax.
            let fee_on_transfer = sell != NATIVE;
            actions.push(
                match settler_profile.univ4_fork_id {
                    Some(fork_id) => abi::forked_v4::UNISWAPV4Call {
                        recipient: settler,
                        sellToken: sell,
                        ppm: settler_proportion(encoding, bps),
                        forkId: fork_id,
                        feeOnTransfer: fee_on_transfer,
                        hashMul: hash_mul,
                        hashMod: hash_mod,
                        fills,
                        amountOutMin: U256::ZERO,
                    }
                    .abi_encode(),
                    None => abi::UNISWAPV4Call {
                        recipient: settler,
                        sellToken: sell,
                        ppm: settler_proportion(encoding, bps),
                        feeOnTransfer: fee_on_transfer,
                        hashMul: hash_mul,
                        hashMod: hash_mod,
                        fills,
                        amountOutMin: U256::ZERO,
                    }
                    .abi_encode(),
                }
                .into(),
            );
            if buy == NATIVE && continues {
                actions.push(wrap_all_native(encoding, wrapped_native));
            }
        } else if seg[0].kind == HopKind::Ekubo {
            let first = &seg[0];
            let first_pool = &snap.ekubo[first.index].0;
            let sell = ekubo_token(first_pool, first.zero_for_one, false);
            if sell == NATIVE {
                actions.push(
                    abi::BASICCall {
                        sellToken: wrapped_native,
                        ppm: settler_proportion(encoding, bps),
                        pool: wrapped_native,
                        offset: U256::from(4),
                        data: abi::withdrawCall { amount: U256::ZERO }.abi_encode().into(),
                    }
                    .abi_encode()
                    .into(),
                );
                bps = BPS_BASE;
            }

            let mut tokens = Vec::with_capacity(seg.len() + 1);
            tokens.push(sell);
            for hop in seg {
                let pool = &snap.ekubo[hop.index].0;
                tokens.push(ekubo_token(pool, hop.zero_for_one, true));
            }
            let buy = *tokens.last().expect("Ekubo run has a buy token");
            let (hash_mul, hash_mod) = note_perfect_hash(&tokens)?;
            actions.push(
                abi::EKUBOV3Call {
                    recipient: settler,
                    sellToken: sell,
                    ppm: settler_proportion(encoding, bps),
                    feeOnTransfer: sell != NATIVE,
                    hashMul: hash_mul,
                    hashMod: hash_mod,
                    fills: ekubo_fills(encoding, snap, seg)?.into(),
                    amountOutMin: U256::ZERO,
                }
                .abi_encode()
                .into(),
            );
            if buy == NATIVE {
                bought_native = true;
                if continues {
                    actions.push(wrap_all_native(encoding, wrapped_native));
                }
            }
        } else if seg[0].kind == HopKind::V3 {
            actions.push(
                abi::UNISWAPV3Call {
                    recipient: settler,
                    ppm: settler_proportion(encoding, bps),
                    path: v3_path(snap, seg)?.into(),
                    amountOutMin: U256::ZERO,
                }
                .abi_encode()
                .into(),
            );
        } else {
            actions.push(v2_action(profile, snap, &seg[0], bps)?);
        }
    }
    Ok(bought_native)
}

fn wrap_all_native(encoding: SettlerEncoding, wrapped_native: Address) -> Bytes {
    // An empty call sends the ETH to WETH's receive, which deposits it.
    abi::BASICCall {
        sellToken: NATIVE,
        ppm: settler_proportion(encoding, BPS_BASE),
        pool: wrapped_native,
        offset: U256::ZERO,
        data: Bytes::new(),
    }
    .abi_encode()
    .into()
}

fn unwrap_all_wrapped(encoding: SettlerEncoding, wrapped_native: Address) -> Bytes {
    // BASIC writes the Settler's WETH balance into withdraw's argument.
    abi::BASICCall {
        sellToken: wrapped_native,
        ppm: settler_proportion(encoding, BPS_BASE),
        pool: wrapped_native,
        offset: U256::from(4),
        data: abi::withdrawCall { amount: U256::ZERO }.abi_encode().into(),
    }
    .abi_encode()
    .into()
}

fn refund_all(recipient: Address, token: Address) -> Bytes {
    // Expected amount zero with full shares returns the whole balance, and
    // does nothing at a zero balance.
    abi::POSITIVE_SLIPPAGECall {
        recipient,
        token,
        expectedAmount: U256::ZERO,
        surplusPpm: U256::from(PPM_BASE),
        maxPpm: U256::from(PPM_BASE),
    }
    .abi_encode()
    .into()
}

const PPM_BASE: u32 = 1_000_000;

/// The first actions of every transaction: they bring the input into the
/// Settler (or, for one pure V3 leg, into its first pool) and fix the deadline.
#[allow(clippy::too_many_arguments)]
fn entry_actions(
    encoding: SettlerEncoding,
    wrapped_native: Address,
    settler: Address,
    snap: &Snapshot,
    vip_path: Option<&[Hop]>,
    native_in: bool,
    tin: Address,
    amount_in: U256,
    deadline: u64,
) -> anyhow::Result<Vec<Bytes>> {
    Ok(if native_in {
        vec![
            abi::NATIVE_CHECKCall {
                deadline: U256::from(deadline),
                amount: amount_in,
            }
            .abi_encode()
            .into(),
            wrap_all_native(encoding, wrapped_native),
        ]
    } else if let Some(path) = vip_path {
        vec![
            abi::UNISWAPV3_VIPCall {
                recipient: settler,
                permit: permit_tuple(tin, amount_in, deadline),
                path: v3_vip_path(encoding, snap, path)?.into(),
                sig: Bytes::new(),
                amountOutMin: U256::ZERO,
            }
            .abi_encode()
            .into(),
        ]
    } else {
        vec![
            abi::TRANSFER_FROMCall {
                recipient: settler,
                permit: permit_tuple(tin, amount_in, deadline),
                sig: Bytes::new(),
            }
            .abi_encode()
            .into(),
        ]
    })
}

/// Everything after the swaps: wrap or unwrap the output, take the fee and
/// any configured positive slippage, then return every other token the route
/// touched to the recipient. An ETH input's leftover WETH goes back as ETH.
#[allow(clippy::too_many_arguments)]
fn settlement_actions(
    profile: &ChainProfile,
    encoding: SettlerEncoding,
    touched: &[Address],
    bought_native: bool,
    native_in: bool,
    native_out: bool,
    tout: Address,
    fee_bps: u32,
    fee_receiver: Option<Address>,
    positive_slippage: Option<PositiveSlippage>,
    recipient: Address,
) -> anyhow::Result<Vec<Bytes>> {
    let wrapped_native = profile.wrapped_native;
    let mut actions = Vec::new();
    if bought_native && !native_out {
        // Native currency bought through native V4/Ekubo pools becomes the
        // wrapped token the settlement expects.
        actions.push(wrap_all_native(encoding, wrapped_native));
    }
    if native_out {
        // Legs that end in the wrapped token pay out as ETH. Withdrawing a
        // zero balance is harmless when every leg already ended in ETH.
        actions.push(unwrap_all_wrapped(encoding, wrapped_native));
    }
    if fee_bps > 0 {
        let receiver = fee_receiver.context("fee receiver is not configured")?;
        actions.push(if native_out {
            abi::BASICCall {
                sellToken: NATIVE,
                ppm: settler_proportion(encoding, fee_bps),
                pool: receiver,
                offset: U256::ZERO,
                data: Bytes::new(),
            }
            .abi_encode()
            .into()
        } else {
            abi::BASICCall {
                sellToken: tout,
                ppm: settler_proportion(encoding, fee_bps),
                pool: tout,
                offset: U256::from(0x24),
                data: abi::transferCall {
                    to: receiver,
                    amount: U256::ZERO,
                }
                .abi_encode()
                .into(),
            }
            .abi_encode()
            .into()
        });
    }
    if let Some(positive_slippage) = positive_slippage {
        actions.push(
            abi::POSITIVE_SLIPPAGECall {
                recipient: positive_slippage.recipient,
                token: if native_out { NATIVE } else { tout },
                expectedAmount: positive_slippage.expected_amount,
                surplusPpm: U256::from(PPM_BASE),
                maxPpm: settler_proportion(encoding, positive_slippage.max_bps),
            }
            .abi_encode()
            .into(),
        );
    }
    let mut refunded = Vec::new();
    for &token in touched {
        if token == tout || token == NATIVE || refunded.contains(&token) {
            continue;
        }
        refunded.push(token);
        if native_in && token == wrapped_native {
            actions.push(unwrap_all_wrapped(encoding, wrapped_native));
            actions.push(refund_all(recipient, NATIVE));
        } else {
            actions.push(refund_all(recipient, token));
        }
    }
    Ok(actions)
}

/// Every token a plan's hops move, in first-seen order.
fn plan_tokens(plans: &[&Plan], tokens: &mut Vec<Address>) {
    for hop in plans
        .iter()
        .flat_map(|plan| &plan.legs)
        .flat_map(|leg| &leg.path)
    {
        for token in [hop.token_in, hop.token_out] {
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
    }
}

fn wrap_execution(
    allowance_holder: Address,
    settler: Address,
    native_in: bool,
    tin: Address,
    amount_in: U256,
    execute: Vec<u8>,
) -> BuiltTx {
    if native_in {
        BuiltTx {
            to: settler,
            value: amount_in,
            data: execute,
            allowance_target: None,
            settler,
        }
    } else {
        let data = abi::execCall {
            operator: settler,
            token: tin,
            amount: amount_in,
            target: settler,
            data: execute.into(),
        }
        .abi_encode();
        BuiltTx {
            to: allowance_holder,
            value: U256::ZERO,
            data,
            allowance_target: Some(allowance_holder),
            settler,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
#[allow(clippy::too_many_arguments)]
pub fn build_swap_tx(
    fee_bps: u32,
    fee_receiver: Option<Address>,
    positive_slippage: Option<PositiveSlippage>,
    snap: &Snapshot,
    plan: &Plan,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    min_out_net: U256,
    recipient: Address,
    deadline: u64,
) -> anyhow::Result<BuiltTx> {
    build_swap_tx_for_profile(
        &ROBINHOOD_PROFILE,
        fee_bps,
        fee_receiver,
        positive_slippage,
        snap,
        plan,
        token_in,
        token_out,
        amount_in,
        min_out_net,
        recipient,
        deadline,
    )
}

/// Profile-aware Settler encoder. The capability check is repeated here, not
/// left solely to the HTTP gate: library callers must not turn a quote-only
/// profile into an execution path by calling the encoder directly.
#[allow(clippy::too_many_arguments)]
pub fn build_swap_tx_for_profile(
    profile: &ChainProfile,
    fee_bps: u32,
    fee_receiver: Option<Address>,
    positive_slippage: Option<PositiveSlippage>,
    snap: &Snapshot,
    plan: &Plan,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    min_out_net: U256,
    recipient: Address,
    deadline: u64,
) -> anyhow::Result<BuiltTx> {
    ensure!(
        profile.execution_enabled(),
        "transaction execution is not enabled for {}",
        profile.name
    );
    let settler = snap
        .settler
        .context("snapshot has no Settler execution identity")?;
    ensure!(
        settler != Address::ZERO,
        "snapshot Settler must not be zero"
    );
    let settler_profile = profile
        .settler
        .context("chain profile has no Settler execution adapter")?;
    let encoding = settler_profile.encoding;
    if plan
        .legs
        .iter()
        .flat_map(|leg| &leg.path)
        .any(|hop| hop.kind == HopKind::Ekubo)
    {
        ensure!(
            !settler_profile.ekubo_v3_runtimes.is_empty(),
            "chain profile has no Settler EKUBOV3 binding"
        );
    }
    ensure_external_recipient(recipient, settler, "recipient")?;
    match fee_receiver {
        Some(receiver) => ensure_external_recipient(receiver, settler, "fee receiver")?,
        None => ensure!(fee_bps == 0, "SOLVER_FEE_RECEIVER is not configured"),
    }
    if let Some(positive_slippage) = positive_slippage {
        ensure_external_recipient(
            positive_slippage.recipient,
            settler,
            "positive slippage recipient",
        )?;
        ensure!(
            (1..=BPS_BASE).contains(&positive_slippage.max_bps),
            "positive slippage max bps out of range"
        );
    }
    ensure!(!min_out_net.is_zero(), "minimum output must be positive");
    let native_in = token_in == NATIVE;
    let native_out = token_out == NATIVE;
    let (tin, tout) = (profile.erc20_of(token_in), profile.erc20_of(token_out));
    ensure!(tin != tout, "transaction endpoints are the same asset");
    let shape = amm_stage_shape(plan)?;
    ensure!(
        shape.token_in == tin && shape.token_out == tout && shape.amount_in == amount_in,
        "plan does not match the transaction endpoints"
    );

    let vip = !native_in && single_v3(snap, plan);
    let mut actions = entry_actions(
        encoding,
        profile.wrapped_native,
        settler,
        snap,
        vip.then(|| plan.legs[0].path.as_slice()),
        native_in,
        tin,
        amount_in,
        deadline,
    )?;
    let bought_native = if vip {
        // The VIP action already ran the whole V3 leg.
        program(snap, plan)?;
        false
    } else {
        append_amm_plan_actions(profile, snap, plan, &mut actions)?
    };
    let mut touched = vec![tin];
    plan_tokens(&[plan], &mut touched);
    if vip {
        // AllowanceHolder pays the first pool directly; the Settler never
        // holds the input.
        touched.retain(|token| *token != tin);
    }
    actions.extend(settlement_actions(
        profile,
        encoding,
        &touched,
        bought_native,
        native_in,
        native_out,
        tout,
        fee_bps,
        fee_receiver,
        positive_slippage,
        recipient,
    )?);

    let slippage = abi::AllowedSlippage {
        recipient,
        buyToken: if native_out { NATIVE } else { tout },
        minAmountOut: min_out_net,
    };
    let execute = abi::executeCall {
        slippage,
        actions,
        zid: B256::ZERO,
    }
    .abi_encode();
    Ok(wrap_execution(
        settler_profile.allowance_holder,
        settler,
        native_in,
        tin,
        amount_in,
        execute,
    ))
}

/// Encode one reviewed Native.org stage composed with at most one AMM stage.
///
/// The supported shapes are direct Native, AMM -> Native, and Native -> AMM.
/// Every stage is balance-funded inside the Settler; the Native `BASIC` action
/// therefore consumes 100% of its live input-token balance and writes that
/// runtime amount only at Router v6's validated `actualSellerAmount` offset.
/// Fees, positive slippage, and `AllowedSlippage` are appended only after the
/// final stage. The beneficiary authorization commits the complete action list.
#[allow(clippy::too_many_arguments)]
pub fn build_composed_native_rfq_tx_for_profile(
    profile: &ChainProfile,
    authorizer: &NativeBeneficiaryAuthorizer,
    taker: Address,
    fee_bps: u32,
    fee_receiver: Option<Address>,
    positive_slippage: Option<PositiveSlippage>,
    snap: &Snapshot,
    stages: &[ComposedSwapStage<'_>],
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    min_out_net: U256,
    recipient: Address,
    now: u64,
    deadline: u64,
) -> anyhow::Result<BuiltTx> {
    ensure!(
        profile.execution_enabled(),
        "transaction execution is not enabled for {}",
        profile.name
    );
    ensure!(!amount_in.is_zero(), "transaction input must be positive");
    ensure!(
        (1..=2).contains(&stages.len()),
        "Native composition supports one or two stages"
    );
    let native_count = stages
        .iter()
        .filter(|stage| matches!(stage, ComposedSwapStage::NativeRfq { .. }))
        .count();
    ensure!(
        native_count == 1,
        "Native composition must contain exactly one Native RFQ stage"
    );
    if stages.len() == 2 {
        ensure!(
            matches!(
                stages,
                [
                    ComposedSwapStage::Amm { .. },
                    ComposedSwapStage::NativeRfq { .. }
                ] | [
                    ComposedSwapStage::NativeRfq { .. },
                    ComposedSwapStage::Amm { .. }
                ]
            ),
            "unsupported Native composition stage order"
        );
    }

    let settler = snap
        .settler
        .context("snapshot has no Settler execution identity")?;
    ensure!(
        settler != Address::ZERO,
        "snapshot Settler must not be zero"
    );
    let settler_profile = profile
        .settler
        .context("chain profile has no Settler execution adapter")?;
    let native = profile
        .native_rfq
        .context("chain profile has no Native RFQ adapter")?;
    let encoding = settler_profile.encoding;
    let wrapped_native = profile.wrapped_native;
    let native_in = token_in == NATIVE;
    let native_out = token_out == NATIVE;
    let (tin, tout) = (profile.erc20_of(token_in), profile.erc20_of(token_out));
    ensure!(tin != tout, "transaction endpoints are the same asset");
    validate_recipients(
        settler,
        fee_bps,
        fee_receiver,
        positive_slippage,
        taker,
        recipient,
    )?;

    let mut shapes = Vec::with_capacity(stages.len());
    let mut native_quote = None;
    for stage in stages {
        match *stage {
            ComposedSwapStage::Amm { plan } => {
                if plan
                    .legs
                    .iter()
                    .flat_map(|leg| &leg.path)
                    .any(|hop| hop.kind == HopKind::Ekubo)
                {
                    ensure!(
                        !settler_profile.ekubo_v3_runtimes.is_empty(),
                        "chain profile has no Settler EKUBOV3 binding"
                    );
                }
                shapes.push(amm_stage_shape(plan)?);
            }
            ComposedSwapStage::NativeRfq {
                quote,
                token_in,
                token_out,
            } => {
                shapes.push(native_stage_shape(
                    profile, settler, quote, token_in, token_out,
                )?);
                native_quote = Some(quote);
            }
        }
    }
    ensure!(
        shapes
            .first()
            .is_some_and(|stage| { stage.token_in == tin && stage.amount_in == amount_in }),
        "first stage does not match the transaction input"
    );
    ensure!(
        shapes
            .windows(2)
            .all(|pair| pair[0].token_out == pair[1].token_in
                && pair[0].amount_out == pair[1].amount_in),
        "composed stages are not token-and-amount continuous"
    );
    let final_shape = shapes.last().expect("nonempty stages checked");
    ensure!(
        final_shape.token_out == tout,
        "final stage does not match the transaction output"
    );
    ensure!(
        !min_out_net.is_zero() && final_shape.amount_out >= min_out_net,
        "composed output is below the settlement minimum"
    );

    let quote = native_quote.expect("exactly one Native stage checked");
    ensure!(
        quote.beneficiary() == recipient,
        "Native RFQ beneficiary does not match the settlement recipient"
    );
    let minimum_live_deadline = now
        .checked_add(quote.min_ttl_seconds)
        .context("Native RFQ minimum TTL deadline overflow")?;
    ensure!(
        quote.is_live_at(now),
        "Native RFQ quote lost its minimum TTL before encoding"
    );
    ensure!(
        deadline >= minimum_live_deadline,
        "request deadline is below the Native RFQ minimum TTL"
    );
    let execution_deadline = deadline.min(quote.deadline());

    let vip_first_amm = !native_in
        && matches!(stages.first(), Some(ComposedSwapStage::Amm { plan }) if single_v3(snap, plan));
    let vip_path = match stages.first() {
        Some(ComposedSwapStage::Amm { plan }) if vip_first_amm => {
            Some(plan.legs[0].path.as_slice())
        }
        _ => None,
    };
    let mut actions = entry_actions(
        encoding,
        wrapped_native,
        settler,
        snap,
        vip_path,
        native_in,
        tin,
        amount_in,
        execution_deadline,
    )?;

    // Native's calldata is forwarded byte-for-byte; BASIC overwrites only
    // `actualSellerAmount` at the validated offset. The zero
    // `actualMinOutputAmount` stays: Router v6 treats it as a sentinel and
    // scales word 7 `amountOutMinimum` by the effective input ratio. Word 7 is
    // outside the pool's EIP-712 signer hash, but the Native authorization
    // commits the whole execution calldata, and `AllowedSlippage` remains an
    // independent whole-transaction minimum.
    let mut final_bought_native = false;
    let mut touched = vec![tin];
    for (index, stage) in stages.iter().enumerate() {
        match *stage {
            ComposedSwapStage::Amm { plan } => {
                plan_tokens(&[plan], &mut touched);
                let bought_native = if index == 0 && vip_first_amm {
                    // The VIP entry action already ran the whole V3 leg.
                    program(snap, plan)?;
                    false
                } else {
                    append_amm_plan_actions(profile, snap, plan, &mut actions)?
                };
                if index + 1 < stages.len() && bought_native {
                    actions.push(wrap_all_native(encoding, wrapped_native));
                } else if index + 1 == stages.len() {
                    final_bought_native = bought_native;
                }
            }
            ComposedSwapStage::NativeRfq {
                quote,
                token_in,
                token_out,
            } => {
                for token in [token_in, token_out] {
                    if !touched.contains(&token) {
                        touched.push(token);
                    }
                }
                actions.push(
                    abi::BASICCall {
                        sellToken: token_in,
                        ppm: settler_proportion(encoding, BPS_BASE),
                        pool: native.router,
                        offset: U256::from(quote.amount_in_offset()),
                        data: quote.calldata().clone(),
                    }
                    .abi_encode()
                    .into(),
                );
            }
        }
    }
    if vip_first_amm {
        touched.retain(|token| *token != tin);
    }
    actions.extend(settlement_actions(
        profile,
        encoding,
        &touched,
        final_bought_native,
        native_in,
        native_out,
        tout,
        fee_bps,
        fee_receiver,
        positive_slippage,
        recipient,
    )?);

    let slippage = abi::AllowedSlippage {
        recipient,
        buyToken: if native_out { NATIVE } else { tout },
        minAmountOut: min_out_net,
    };
    // The canonical, signature-free execution payload the authorization
    // commits, including execute(...)'s four-byte selector.
    let canonical_execute = abi::executeCall {
        slippage: slippage.clone(),
        actions: actions.clone(),
        zid: B256::ZERO,
    }
    .abi_encode();
    let typehash = profile
        .settler
        .and_then(|settler| settler.native_authorization_typehash)
        .context("this chain's Settler has no Native authorization entry")?;
    let authorization = authorizer.authorize(
        typehash,
        profile.chain_id,
        settler,
        taker,
        quote.beneficiary(),
        &canonical_execute,
        execution_deadline,
    )?;
    let execute = abi::executeWithNativeAuthorizationCall {
        slippage,
        actions,
        zid: B256::ZERO,
        authorizationDeadline: U256::from(execution_deadline),
        r: authorization.r,
        vs: authorization.vs,
    }
    .abi_encode();
    Ok(wrap_execution(
        settler_profile.allowance_holder,
        settler,
        native_in,
        tin,
        amount_in,
        execute,
    ))
}

#[cfg(test)]
mod native_quote_tests {
    use super::*;
    use crate::chain::FIXTURE_NATIVE_RFQ;
    use alloy_primitives::Signature;
    use alloy_sol_types::SolCall;
    use sextant_rfq::rfq::validation_support::*;

    #[test]
    fn settler_wraps_v6_quote_in_transfer_basic_fee_slippage_order() {
        use crate::chain::{FIXTURE_PROFILE, ROBINHOOD_SETTLER, SettlerEncoding, SettlerProfile};
        use crate::rfq::NativeBeneficiaryAuthorizer;
        use crate::settler::{
            ComposedSwapStage, PositiveSlippage, build_composed_native_rfq_tx_for_profile,
        };
        use crate::snapshot::Snapshot;

        let allowance_holder = Address::repeat_byte(0xa1);
        let mut profile = FIXTURE_PROFILE;
        // Encoder fixture: a Native-capable Settler build.
        profile.native_rfq = Some(crate::chain::FIXTURE_NATIVE_RFQ);
        profile.settler = Some(SettlerProfile {
            allowance_holder,
            encoding: SettlerEncoding::PpmVipPathFromPermit,
            ..crate::chain::with_native_entry(*ROBINHOOD_SETTLER)
        });
        let snapshot = Snapshot {
            block: 123,
            settler: Some(settler()),
            v3: Vec::new(),
            v2: Vec::new(),
            ekubo: Vec::new(),
        };
        let mut validated = validated();
        validated.record_observation(123, B256::repeat_byte(0x77));
        assert_eq!(
            validated.observation(),
            Some(crate::rfq::NativeQuoteObservation {
                number: 123,
                hash: B256::repeat_byte(0x77),
            })
        );
        let original_calldata = validated.calldata().clone();
        let fee_receiver = Address::repeat_byte(0xa2);
        let surplus_receiver = Address::repeat_byte(0xa3);
        let recipient = request().beneficiary;
        let taker = Address::repeat_byte(0xa4);
        let authorizer = NativeBeneficiaryAuthorizer::from_secret(
            "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d",
        )
        .unwrap();

        let stages = [ComposedSwapStage::NativeRfq {
            quote: &validated,
            token_in: token_in(),
            token_out: token_out(),
        }];
        let tx = build_composed_native_rfq_tx_for_profile(
            &profile,
            &authorizer,
            taker,
            9,
            Some(fee_receiver),
            Some(PositiveSlippage {
                recipient: surplus_receiver,
                expected_amount: U256::from(1_850u64),
                max_bps: 5_000,
            }),
            &snapshot,
            &stages,
            token_in(),
            token_out(),
            U256::from(1_000u64),
            U256::from(1_800u64),
            recipient,
            NOW + 50,
            NOW + 60,
        )
        .unwrap();

        assert_eq!(tx.to, allowance_holder);
        assert_eq!(tx.allowance_target, Some(allowance_holder));
        assert_eq!(tx.value, U256::ZERO);
        assert_eq!(tx.settler, settler());

        let holder = abi::execCall::abi_decode(&tx.data).unwrap();
        assert_eq!(holder.operator, settler());
        assert_eq!(holder.target, settler());
        assert_eq!(holder.token, token_in());
        assert_eq!(holder.amount, U256::from(1_000u64));

        let execute = abi::executeWithNativeAuthorizationCall::abi_decode(&holder.data).unwrap();
        assert_eq!(execute.slippage.recipient, recipient);
        assert_eq!(execute.slippage.buyToken, token_out());
        assert_eq!(execute.slippage.minAmountOut, U256::from(1_800u64));
        assert_eq!(execute.authorizationDeadline, U256::from(NOW + 60));
        assert_eq!(execute.actions.len(), 5);
        assert_eq!(execute.actions[0][..4], abi::TRANSFER_FROMCall::SELECTOR);
        assert_eq!(execute.actions[1][..4], abi::BASICCall::SELECTOR);
        assert_eq!(execute.actions[2][..4], abi::BASICCall::SELECTOR);
        assert_eq!(
            execute.actions[3][..4],
            abi::POSITIVE_SLIPPAGECall::SELECTOR
        );
        // Whatever input Native leaves behind goes back to the recipient.
        let refund = abi::POSITIVE_SLIPPAGECall::abi_decode(&execute.actions[4]).unwrap();
        assert_eq!(refund.recipient, recipient);
        assert_eq!(refund.token, token_in());
        assert_eq!(refund.expectedAmount, U256::ZERO);
        assert_eq!(refund.maxPpm, U256::from(1_000_000u64));

        let transfer = abi::TRANSFER_FROMCall::abi_decode(&execute.actions[0]).unwrap();
        assert_eq!(transfer.recipient, settler());
        assert_eq!(transfer.permit.permitted.token, token_in());
        assert_eq!(transfer.permit.permitted.amount, U256::from(1_000u64));
        assert_eq!(transfer.permit.deadline, U256::from(NOW + 60));
        assert_eq!(transfer.permit.nonce, U256::ZERO);
        assert!(transfer.sig.is_empty());

        let native = abi::BASICCall::abi_decode(&execute.actions[1]).unwrap();
        assert_eq!(native.sellToken, token_in());
        assert_eq!(native.ppm, U256::from(1_000_000u64));
        assert_eq!(native.pool, FIXTURE_NATIVE_RFQ.router);
        assert_eq!(native.offset, U256::from(AMOUNT_IN_OFFSET));
        assert_eq!(native.data, original_calldata);
        assert_eq!(
            U256::from_be_slice(
                &native.data[AMOUNT_OUT_MINIMUM_OFFSET..AMOUNT_OUT_MINIMUM_OFFSET + WORD_BYTES]
            ),
            U256::ZERO,
            "actualMinOutputAmount must remain Native's zero sentinel"
        );

        let fee = abi::BASICCall::abi_decode(&execute.actions[2]).unwrap();
        assert_eq!(fee.sellToken, token_out());
        assert_eq!(fee.ppm, U256::from(900u64));
        assert_eq!(fee.pool, token_out());
        assert_eq!(fee.offset, U256::from(0x24u64));
        let transfer_fee = abi::transferCall::abi_decode(&fee.data).unwrap();
        assert_eq!(transfer_fee.to, fee_receiver);
        assert_eq!(transfer_fee.amount, U256::ZERO);

        let surplus = abi::POSITIVE_SLIPPAGECall::abi_decode(&execute.actions[3]).unwrap();
        assert_eq!(surplus.recipient, surplus_receiver);
        assert_eq!(surplus.token, token_out());
        assert_eq!(surplus.expectedAmount, U256::from(1_850u64));
        assert_eq!(surplus.surplusPpm, U256::from(1_000_000u64));
        assert_eq!(surplus.maxPpm, U256::from(500_000u64));

        let canonical_execute = abi::executeCall {
            slippage: execute.slippage,
            actions: execute.actions,
            zid: execute.zid,
        }
        .abi_encode();
        let struct_hash = NativeBeneficiaryAuthorizer::struct_hash(
            crate::chain::FIXTURE_NATIVE_AUTHORIZATION_TYPEHASH,
            profile.chain_id,
            settler(),
            taker,
            recipient,
            &canonical_execute,
            NOW + 60,
        );
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(execute.r.as_slice());
        compact[32..].copy_from_slice(execute.vs.as_slice());
        assert_eq!(
            Signature::from_erc2098(&compact)
                .recover_address_from_msg(struct_hash.as_slice())
                .unwrap(),
            authorizer.address()
        );

        let error = build_composed_native_rfq_tx_for_profile(
            &profile,
            &authorizer,
            taker,
            0,
            None,
            None,
            &snapshot,
            &stages,
            token_in(),
            token_out(),
            U256::from(1_000u64),
            U256::from(1_800u64),
            Address::repeat_byte(0xff),
            NOW,
            NOW + 120,
        )
        .unwrap_err();
        assert!(error.to_string().contains("beneficiary does not match"));

        let error = build_composed_native_rfq_tx_for_profile(
            &profile,
            &authorizer,
            taker,
            0,
            None,
            None,
            &snapshot,
            &stages,
            token_in(),
            token_out(),
            U256::from(1_000u64),
            U256::from(1_800u64),
            recipient,
            NOW + 51,
            NOW + 120,
        )
        .unwrap_err();
        assert!(error.to_string().contains("lost its minimum TTL"));

        let error = build_composed_native_rfq_tx_for_profile(
            &profile,
            &authorizer,
            taker,
            0,
            None,
            None,
            &snapshot,
            &stages,
            token_in(),
            token_out(),
            U256::from(1_000u64),
            U256::from(1_800u64),
            recipient,
            NOW,
            NOW + 9,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("request deadline is below the Native RFQ minimum TTL")
        );
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    /// A plan through three hops (in -> USDG -> WETH -> out) encodes.
    #[test]
    fn a_three_hop_plan_encodes() {
        use crate::chain::{USDG, WETH};
        use crate::pools::{V2Pool, V2Protocol, V2State};
        use sextant_route::route::{best_plan, quantized_plan};
        let v2_pool = |id: u8, token0: Address, token1: Address| {
            (
                V2Pool {
                    protocol: V2Protocol::UNIV2,
                    address: Address::repeat_byte(id),
                    token0,
                    token1,
                    fee_bps: 30,
                },
                V2State {
                    reserve0: U256::from(1_000_000u64),
                    reserve1: U256::from(1_000_000u64),
                },
            )
        };
        let token_in = Address::repeat_byte(0xa1);
        let token_out = Address::repeat_byte(0xb1);
        let snap = Snapshot {
            block: 1,
            settler: Some(Address::repeat_byte(0xfe)),
            v3: vec![],
            v2: vec![
                v2_pool(1, token_in, USDG),
                v2_pool(2, WETH, USDG),
                v2_pool(3, WETH, token_out),
            ],
            ekubo: vec![],
        };
        let plan = best_plan(&snap, token_in, token_out, U256::from(1_000), 64, 50).unwrap();
        let executable = quantized_plan(&snap, &plan, U256::from(1_000)).unwrap();
        assert_eq!(executable.legs[0].path.len(), 3);
        let tx = build_swap_tx(
            0,
            None,
            None,
            &snap,
            &executable,
            token_in,
            token_out,
            U256::from(1_000),
            executable.amount_out,
            Address::repeat_byte(0xcc),
            1_800_000_000,
        )
        .unwrap();
        assert!(!tx.data.is_empty());
    }
}

#[cfg(test)]
mod composed_native_tests {
    use super::*;
    use crate::chain::{FIXTURE_PROFILE, ROBINHOOD_SETTLER, SettlerProfile};
    use crate::plan::Leg;
    use crate::pools::{V2Pool, V2Protocol, V2State, V3Pool, V3Protocol, V3State, V4Meta};
    use crate::rfq::NativeQuoteObservation;
    use alloy_primitives::Signature;

    const NOW: u64 = 1_800_000_000;
    const DEADLINE: u64 = NOW + 60;
    const TEST_SIGNING_KEY: &str =
        "0x59c6995e998f97a5a0044976f0945389dc9e86dae88c7a8412f4603b6b78690d";

    const SETTLER: Address = Address::repeat_byte(0x51);
    const RECIPIENT: Address = Address::repeat_byte(0x52);
    const TAKER: Address = Address::repeat_byte(0x53);
    const FEE_RECEIVER: Address = Address::repeat_byte(0x54);
    const SURPLUS_RECEIVER: Address = Address::repeat_byte(0x55);
    const ALLOWANCE_HOLDER: Address = Address::repeat_byte(0x56);
    const AMM_POOL: Address = Address::repeat_byte(0x57);
    const TOKEN_A: Address = Address::repeat_byte(0x61);
    const BRIDGE: Address = Address::repeat_byte(0x62);
    const TOKEN_C: Address = Address::repeat_byte(0x63);

    fn profile() -> ChainProfile {
        ChainProfile {
            // Isolated encoder fixture: a Native-capable Settler build.
            native_rfq: Some(crate::chain::FIXTURE_NATIVE_RFQ),
            settler: Some(SettlerProfile {
                allowance_holder: ALLOWANCE_HOLDER,
                encoding: SettlerEncoding::PpmVipPathFromPermit,
                ekubo_v3_runtimes: &[],
                indexed_v3: &[],
                univ4_pool_manager: Some(AMM_POOL),
                univ4_fork_id: None,
                ..crate::chain::with_native_entry(*ROBINHOOD_SETTLER)
            }),
            ..FIXTURE_PROFILE
        }
    }

    fn empty_snapshot() -> Snapshot {
        Snapshot {
            block: 123,
            settler: Some(SETTLER),
            v3: Vec::new(),
            v2: Vec::new(),
            ekubo: Vec::new(),
        }
    }

    fn v2_stage(
        token_in: Address,
        token_out: Address,
        amount_in: u64,
        amount_out: u64,
    ) -> (Snapshot, Plan) {
        let snapshot = Snapshot {
            v2: vec![(
                V2Pool {
                    protocol: V2Protocol::UNIV2,
                    address: AMM_POOL,
                    token0: token_in,
                    token1: token_out,
                    fee_bps: 30,
                },
                V2State {
                    reserve0: U256::from(10_000_000u64),
                    reserve1: U256::from(20_000_000u64),
                },
            )],
            ..empty_snapshot()
        };
        let plan = Plan {
            legs: vec![Leg {
                path: vec![Hop {
                    kind: HopKind::V2,
                    index: 0,
                    zero_for_one: true,
                    token_in,
                    token_out,
                }],
                amount_in: U256::from(amount_in),
                amount_out: U256::from(amount_out),
                losses: Vec::new(),
                slice_bps: BPS_BASE,
            }],
            amount_out: U256::from(amount_out),
            universe_id: None,
        };
        (snapshot, plan)
    }

    fn v4_native_output_stage(amount_in: u64, amount_out: u64) -> (Snapshot, Plan) {
        let wrapped_native = FIXTURE_PROFILE.wrapped_native;
        let snapshot = Snapshot {
            v3: vec![(
                V3Pool {
                    protocol: V3Protocol::UNIV4,
                    address: AMM_POOL,
                    token0: BRIDGE,
                    token1: wrapped_native,
                    fee_ppm: 500,
                    tick_spacing: 10,
                    verify_pool_spacing: false,
                    execution: None,
                    v4: Some(V4Meta {
                        pool_id: B256::repeat_byte(0x44),
                        state_slot: B256::repeat_byte(0x45),
                        native: true,
                        hooks: Address::ZERO,
                        swap_fee_0to1_ppm: 500,
                        swap_fee_1to0_ppm: 500,
                    }),
                    algebra: None,
                },
                V3State {
                    sqrt_price: U256::ONE << 96usize,
                    tick: 0,
                    liquidity: U256::from(1_000_000u64),
                    ticks: Vec::new().into(),
                    pos: 0,
                    lo_cover: -120_000,
                    hi_cover: 120_000,
                },
            )],
            ..empty_snapshot()
        };
        let plan = Plan {
            legs: vec![Leg {
                path: vec![Hop {
                    kind: HopKind::V3,
                    index: 0,
                    zero_for_one: true,
                    token_in: BRIDGE,
                    token_out: wrapped_native,
                }],
                amount_in: U256::from(amount_in),
                amount_out: U256::from(amount_out),
                losses: Vec::new(),
                slice_bps: BPS_BASE,
            }],
            amount_out: U256::from(amount_out),
            universe_id: None,
        };
        (snapshot, plan)
    }

    fn write_word(calldata: &mut [u8], offset: usize, word: U256) {
        calldata[offset..offset + ABI_WORD_BYTES].copy_from_slice(&word.to_be_bytes::<32>());
    }

    fn write_quote_word(calldata: &mut [u8], index: usize, word: U256) {
        write_word(
            calldata,
            4 + NATIVE_V6_QUOTE_OFFSET + index * ABI_WORD_BYTES,
            word,
        );
    }

    fn write_quote_address(calldata: &mut [u8], index: usize, address: Address) {
        write_quote_word(calldata, index, U256::from_be_slice(address.as_slice()));
    }

    fn validated_quote(
        token_in: Address,
        token_out: Address,
        amount_in: u64,
        amount_out: u64,
    ) -> ValidatedFirmQuote {
        let native = crate::chain::FIXTURE_NATIVE_RFQ;
        let mut calldata = vec![0u8; 4 + NATIVE_V6_QUOTE_OFFSET + 27 * ABI_WORD_BYTES];
        calldata[..4].copy_from_slice(&native.trade_selector);
        write_word(&mut calldata, 4, U256::from(NATIVE_V6_QUOTE_OFFSET));
        write_quote_address(&mut calldata, 0, native.pool);
        write_quote_address(&mut calldata, 1, Address::repeat_byte(0x70));
        write_quote_address(&mut calldata, 2, SETTLER);
        write_quote_address(&mut calldata, 3, token_in);
        write_quote_address(&mut calldata, 4, token_out);
        write_quote_word(&mut calldata, 5, U256::from(amount_in));
        write_quote_word(&mut calldata, 6, U256::from(amount_out));
        write_quote_word(&mut calldata, 7, U256::from(amount_out.saturating_sub(100)));
        write_quote_word(&mut calldata, 8, U256::from(NOW + 120));
        write_quote_word(&mut calldata, 9, U256::from(7u64));
        write_quote_address(&mut calldata, 14, SETTLER);
        write_quote_address(&mut calldata, 15, TAKER);

        ValidatedFirmQuote {
            target: native.router,
            pool: native.pool,
            calldata: calldata.into(),
            token_in,
            token_out,
            settler: SETTLER,
            expected_origin: TAKER,
            amount_in: U256::from(amount_in),
            amount_out: U256::from(amount_out),
            signer: Address::repeat_byte(0x70),
            nonce: U256::from(7u64),
            beneficiary: RECIPIENT,
            deadline: NOW + 120,
            min_ttl_seconds: 10,
            amount_in_offset: NATIVE_V6_AMOUNT_IN_OFFSET,
            amount_out_minimum_offset: NATIVE_V6_AMOUNT_OUT_MINIMUM_OFFSET,
            router_version: native.router_version,
            observation: Some(NativeQuoteObservation {
                number: 123,
                hash: B256::repeat_byte(0x71),
            }),
        }
    }

    fn build(
        snapshot: &Snapshot,
        stages: &[ComposedSwapStage<'_>],
        token_in: Address,
        token_out: Address,
        amount_in: u64,
        min_out: u64,
    ) -> (
        ChainProfile,
        NativeBeneficiaryAuthorizer,
        abi::executeWithNativeAuthorizationCall,
    ) {
        let profile = profile();
        let authorizer = NativeBeneficiaryAuthorizer::from_secret(TEST_SIGNING_KEY).unwrap();
        let tx = build_composed_native_rfq_tx_for_profile(
            &profile,
            &authorizer,
            TAKER,
            9,
            Some(FEE_RECEIVER),
            Some(PositiveSlippage {
                recipient: SURPLUS_RECEIVER,
                expected_amount: U256::from(min_out + 50),
                max_bps: 5_000,
            }),
            snapshot,
            stages,
            token_in,
            token_out,
            U256::from(amount_in),
            U256::from(min_out),
            RECIPIENT,
            NOW,
            DEADLINE,
        )
        .unwrap();

        assert_eq!(tx.to, ALLOWANCE_HOLDER);
        assert_eq!(tx.allowance_target, Some(ALLOWANCE_HOLDER));
        assert_eq!(tx.value, U256::ZERO);
        assert_eq!(tx.settler, SETTLER);

        let holder = abi::execCall::abi_decode(&tx.data).unwrap();
        assert_eq!(holder.operator, SETTLER);
        assert_eq!(holder.target, SETTLER);
        assert_eq!(holder.token, token_in);
        assert_eq!(holder.amount, U256::from(amount_in));

        let execute = abi::executeWithNativeAuthorizationCall::abi_decode(&holder.data).unwrap();
        assert_eq!(execute.slippage.recipient, RECIPIENT);
        assert_eq!(execute.slippage.buyToken, token_out);
        assert_eq!(execute.slippage.minAmountOut, U256::from(min_out));
        assert_eq!(execute.authorizationDeadline, U256::from(DEADLINE));
        let transfer = abi::TRANSFER_FROMCall::abi_decode(&execute.actions[0]).unwrap();
        assert_eq!(transfer.recipient, SETTLER);
        assert_eq!(transfer.permit.permitted.token, token_in);
        assert_eq!(transfer.permit.permitted.amount, U256::from(amount_in));
        assert_eq!(transfer.permit.deadline, U256::from(DEADLINE));
        assert_eq!(transfer.permit.nonce, U256::ZERO);
        assert!(transfer.sig.is_empty());

        (profile, authorizer, execute)
    }

    fn selector(action: &Bytes) -> [u8; 4] {
        action[..4].try_into().unwrap()
    }

    fn assert_native_action(action: &Bytes, quote: &ValidatedFirmQuote, sell_token: Address) {
        assert_eq!(selector(action), abi::BASICCall::SELECTOR);
        let native = abi::BASICCall::abi_decode(action).unwrap();
        assert_eq!(native.sellToken, sell_token);
        assert_eq!(native.ppm, U256::from(1_000_000u64));
        assert_eq!(native.pool, crate::chain::FIXTURE_NATIVE_RFQ.router);
        assert_eq!(native.offset, U256::from(NATIVE_V6_AMOUNT_IN_OFFSET));
        assert_eq!(native.data.as_ref(), quote.calldata().as_ref());
        assert_eq!(
            calldata_word(&native.data, NATIVE_V6_AMOUNT_OUT_MINIMUM_OFFSET).unwrap(),
            U256::ZERO
        );
    }

    fn assert_single_terminal_policy(
        execute: &abi::executeWithNativeAuthorizationCall,
        token_out: Address,
        min_out: u64,
    ) {
        let positive_actions: Vec<_> = execute
            .actions
            .iter()
            .filter(|action| selector(action) == abi::POSITIVE_SLIPPAGECall::SELECTOR)
            .map(|action| abi::POSITIVE_SLIPPAGECall::abi_decode(action).unwrap())
            .filter(|positive| positive.recipient == SURPLUS_RECEIVER)
            .collect();
        assert_eq!(positive_actions.len(), 1);
        let positive = &positive_actions[0];
        assert_eq!(positive.token, token_out);
        assert_eq!(positive.expectedAmount, U256::from(min_out + 50));
        assert_eq!(positive.surplusPpm, U256::from(1_000_000u64));
        assert_eq!(positive.maxPpm, U256::from(500_000u64));

        let fees: Vec<_> = execute
            .actions
            .iter()
            .filter(|action| selector(action) == abi::BASICCall::SELECTOR)
            .map(|action| abi::BASICCall::abi_decode(action).unwrap())
            .filter(|basic| {
                basic.sellToken == token_out
                    && basic.pool == token_out
                    && basic.offset == U256::from(0x24u64)
            })
            .collect();
        assert_eq!(fees.len(), 1);
        assert_eq!(fees[0].ppm, U256::from(900u64));
        let fee_transfer = abi::transferCall::abi_decode(&fees[0].data).unwrap();
        assert_eq!(fee_transfer.to, FEE_RECEIVER);
        assert_eq!(fee_transfer.amount, U256::ZERO);
    }

    /// The trailing actions return each listed token's whole balance to the
    /// recipient.
    fn assert_refunds(execute: &abi::executeWithNativeAuthorizationCall, tokens: &[Address]) {
        let tail = &execute.actions[execute.actions.len() - tokens.len()..];
        for (action, token) in tail.iter().zip(tokens) {
            let refund = abi::POSITIVE_SLIPPAGECall::abi_decode(action).unwrap();
            assert_eq!(refund.recipient, RECIPIENT);
            assert_eq!(refund.token, *token);
            assert_eq!(refund.expectedAmount, U256::ZERO);
            assert_eq!(refund.surplusPpm, U256::from(1_000_000u64));
            assert_eq!(refund.maxPpm, U256::from(1_000_000u64));
        }
    }

    fn assert_authorizes_complete_actions(
        profile: &ChainProfile,
        authorizer: &NativeBeneficiaryAuthorizer,
        execute: &abi::executeWithNativeAuthorizationCall,
    ) {
        let canonical_execute = abi::executeCall {
            slippage: execute.slippage.clone(),
            actions: execute.actions.clone(),
            zid: execute.zid,
        }
        .abi_encode();
        let struct_hash = NativeBeneficiaryAuthorizer::struct_hash(
            crate::chain::FIXTURE_NATIVE_AUTHORIZATION_TYPEHASH,
            profile.chain_id,
            SETTLER,
            TAKER,
            RECIPIENT,
            &canonical_execute,
            DEADLINE,
        );
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(execute.r.as_slice());
        compact[32..].copy_from_slice(execute.vs.as_slice());
        let signer = Signature::from_erc2098(&compact)
            .recover_address_from_msg(struct_hash.as_slice())
            .unwrap();
        assert_eq!(signer, authorizer.address());

        let mut incomplete_actions = execute.actions.clone();
        incomplete_actions.pop();
        let incomplete_execute = abi::executeCall {
            slippage: execute.slippage.clone(),
            actions: incomplete_actions,
            zid: execute.zid,
        }
        .abi_encode();
        let incomplete_hash = NativeBeneficiaryAuthorizer::struct_hash(
            crate::chain::FIXTURE_NATIVE_AUTHORIZATION_TYPEHASH,
            profile.chain_id,
            SETTLER,
            TAKER,
            RECIPIENT,
            &incomplete_execute,
            DEADLINE,
        );
        let incomplete_signer = Signature::from_erc2098(&compact)
            .recover_address_from_msg(incomplete_hash.as_slice())
            .unwrap();
        assert_ne!(incomplete_signer, authorizer.address());
    }

    #[test]
    fn composed_native_only_encodes_one_terminal_policy_and_full_authorization() {
        let snapshot = empty_snapshot();
        let quote = validated_quote(TOKEN_A, TOKEN_C, 1_000, 1_800);
        let stages = [ComposedSwapStage::NativeRfq {
            quote: &quote,
            token_in: TOKEN_A,
            token_out: TOKEN_C,
        }];

        let (profile, authorizer, execute) =
            build(&snapshot, &stages, TOKEN_A, TOKEN_C, 1_000, 1_700);

        assert_eq!(execute.actions.len(), 5);
        assert_eq!(
            selector(&execute.actions[0]),
            abi::TRANSFER_FROMCall::SELECTOR
        );
        assert_native_action(&execute.actions[1], &quote, TOKEN_A);
        assert_eq!(selector(&execute.actions[2]), abi::BASICCall::SELECTOR);
        assert_eq!(
            selector(&execute.actions[3]),
            abi::POSITIVE_SLIPPAGECall::SELECTOR
        );
        assert_single_terminal_policy(&execute, TOKEN_C, 1_700);
        assert_refunds(&execute, &[TOKEN_A]);
        assert_authorizes_complete_actions(&profile, &authorizer, &execute);
    }

    #[test]
    fn composed_amm_then_native_keeps_stage_order_and_original_allowance_input() {
        let (snapshot, amm) = v2_stage(TOKEN_A, BRIDGE, 1_000, 900);
        let quote = validated_quote(BRIDGE, TOKEN_C, 900, 1_700);
        let stages = [
            ComposedSwapStage::Amm { plan: &amm },
            ComposedSwapStage::NativeRfq {
                quote: &quote,
                token_in: BRIDGE,
                token_out: TOKEN_C,
            },
        ];

        let (profile, authorizer, execute) =
            build(&snapshot, &stages, TOKEN_A, TOKEN_C, 1_000, 1_600);

        assert_eq!(execute.actions.len(), 7);
        assert_eq!(
            selector(&execute.actions[0]),
            abi::TRANSFER_FROMCall::SELECTOR
        );
        assert_eq!(selector(&execute.actions[1]), abi::UNISWAPV2Call::SELECTOR);
        let amm_action = abi::UNISWAPV2Call::abi_decode(&execute.actions[1]).unwrap();
        assert_eq!(amm_action.sellToken, TOKEN_A);
        assert_eq!(amm_action.ppm, U256::from(1_000_000u64));
        assert_eq!(amm_action.pool, AMM_POOL);
        assert_native_action(&execute.actions[2], &quote, BRIDGE);
        assert_eq!(selector(&execute.actions[3]), abi::BASICCall::SELECTOR);
        assert_eq!(
            selector(&execute.actions[4]),
            abi::POSITIVE_SLIPPAGECall::SELECTOR
        );
        assert_single_terminal_policy(&execute, TOKEN_C, 1_600);
        assert_refunds(&execute, &[TOKEN_A, BRIDGE]);
        assert_authorizes_complete_actions(&profile, &authorizer, &execute);
    }

    #[test]
    fn composed_native_then_amm_keeps_stage_order_and_original_allowance_input() {
        let (snapshot, amm) = v2_stage(BRIDGE, TOKEN_C, 1_800, 1_500);
        let quote = validated_quote(TOKEN_A, BRIDGE, 1_000, 1_800);
        let stages = [
            ComposedSwapStage::NativeRfq {
                quote: &quote,
                token_in: TOKEN_A,
                token_out: BRIDGE,
            },
            ComposedSwapStage::Amm { plan: &amm },
        ];

        let (profile, authorizer, execute) =
            build(&snapshot, &stages, TOKEN_A, TOKEN_C, 1_000, 1_400);

        assert_eq!(execute.actions.len(), 7);
        assert_eq!(
            selector(&execute.actions[0]),
            abi::TRANSFER_FROMCall::SELECTOR
        );
        assert_native_action(&execute.actions[1], &quote, TOKEN_A);
        assert_eq!(selector(&execute.actions[2]), abi::UNISWAPV2Call::SELECTOR);
        let amm_action = abi::UNISWAPV2Call::abi_decode(&execute.actions[2]).unwrap();
        assert_eq!(amm_action.sellToken, BRIDGE);
        assert_eq!(amm_action.ppm, U256::from(1_000_000u64));
        assert_eq!(amm_action.pool, AMM_POOL);
        assert_eq!(selector(&execute.actions[3]), abi::BASICCall::SELECTOR);
        assert_eq!(
            selector(&execute.actions[4]),
            abi::POSITIVE_SLIPPAGECall::SELECTOR
        );
        assert_single_terminal_policy(&execute, TOKEN_C, 1_400);
        assert_refunds(&execute, &[TOKEN_A, BRIDGE]);
        assert_authorizes_complete_actions(&profile, &authorizer, &execute);
    }

    #[test]
    fn composed_native_then_v4_native_output_pays_eth_and_unwraps_any_wrapped_rest() {
        let (snapshot, amm) = v4_native_output_stage(1_800, 1_500);
        let quote = validated_quote(TOKEN_A, BRIDGE, 1_000, 1_800);
        let stages = [
            ComposedSwapStage::NativeRfq {
                quote: &quote,
                token_in: TOKEN_A,
                token_out: BRIDGE,
            },
            ComposedSwapStage::Amm { plan: &amm },
        ];

        let (profile, authorizer, execute) =
            build(&snapshot, &stages, TOKEN_A, NATIVE, 1_000, 1_400);

        assert_eq!(execute.actions.len(), 8);
        assert_eq!(
            selector(&execute.actions[0]),
            abi::TRANSFER_FROMCall::SELECTOR
        );
        assert_native_action(&execute.actions[1], &quote, TOKEN_A);
        assert_eq!(selector(&execute.actions[2]), abi::UNISWAPV4Call::SELECTOR);
        let amm_action = abi::UNISWAPV4Call::abi_decode(&execute.actions[2]).unwrap();
        assert_eq!(amm_action.recipient, SETTLER);
        assert_eq!(amm_action.sellToken, BRIDGE);
        assert_eq!(amm_action.ppm, U256::from(1_000_000u64));
        assert_eq!(&amm_action.fills[24..44], NATIVE.as_slice());

        // A split leg ending in the wrapped token would still pay out as ETH.
        let unwrap = abi::BASICCall::abi_decode(&execute.actions[3]).unwrap();
        assert_eq!(unwrap.sellToken, profile.wrapped_native);
        assert_eq!(unwrap.pool, profile.wrapped_native);
        let native_fee = abi::BASICCall::abi_decode(&execute.actions[4]).unwrap();
        assert_eq!(native_fee.sellToken, NATIVE);
        assert_eq!(native_fee.ppm, U256::from(900u64));
        assert_eq!(native_fee.pool, FEE_RECEIVER);
        assert_eq!(native_fee.offset, U256::ZERO);
        assert!(native_fee.data.is_empty());
        assert_eq!(
            selector(&execute.actions[5]),
            abi::POSITIVE_SLIPPAGECall::SELECTOR
        );
        assert_refunds(&execute, &[TOKEN_A, BRIDGE]);

        let wrapped_native = profile.wrapped_native;
        let withdraws = execute
            .actions
            .iter()
            .filter(|action| selector(action) == abi::BASICCall::SELECTOR)
            .map(|action| abi::BASICCall::abi_decode(action).unwrap())
            .filter(|basic| {
                basic.sellToken == wrapped_native
                    && basic.pool == wrapped_native
                    && basic.offset == U256::from(4u64)
                    && basic.data.get(..4) == Some(abi::withdrawCall::SELECTOR.as_slice())
            })
            .count();
        assert_eq!(withdraws, 1);
        assert_authorizes_complete_actions(&profile, &authorizer, &execute);
    }

    #[test]
    fn composed_native_input_wraps_before_amm_then_runs_native_last() {
        let profile = profile();
        let wrapped_native = profile.wrapped_native;
        let (snapshot, amm) = v2_stage(wrapped_native, BRIDGE, 1_000, 900);
        let quote = validated_quote(BRIDGE, TOKEN_C, 900, 1_700);
        let stages = [
            ComposedSwapStage::Amm { plan: &amm },
            ComposedSwapStage::NativeRfq {
                quote: &quote,
                token_in: BRIDGE,
                token_out: TOKEN_C,
            },
        ];
        let authorizer = NativeBeneficiaryAuthorizer::from_secret(TEST_SIGNING_KEY).unwrap();

        let tx = build_composed_native_rfq_tx_for_profile(
            &profile,
            &authorizer,
            TAKER,
            0,
            None,
            None,
            &snapshot,
            &stages,
            NATIVE,
            TOKEN_C,
            U256::from(1_000u64),
            U256::from(1_600u64),
            RECIPIENT,
            NOW,
            DEADLINE,
        )
        .unwrap();

        assert_eq!(tx.to, SETTLER);
        assert_eq!(tx.value, U256::from(1_000u64));
        assert_eq!(tx.allowance_target, None);
        let execute = abi::executeWithNativeAuthorizationCall::abi_decode(&tx.data).unwrap();
        assert_eq!(execute.actions.len(), 7);
        let native_check = abi::NATIVE_CHECKCall::abi_decode(&execute.actions[0]).unwrap();
        assert_eq!(native_check.amount, U256::from(1_000u64));
        let wrap = abi::BASICCall::abi_decode(&execute.actions[1]).unwrap();
        assert_eq!(wrap.sellToken, NATIVE);
        assert_eq!(wrap.pool, wrapped_native);
        assert_eq!(wrap.offset, U256::ZERO);
        assert!(wrap.data.is_empty());
        let amm_action = abi::UNISWAPV2Call::abi_decode(&execute.actions[2]).unwrap();
        assert_eq!(amm_action.sellToken, wrapped_native);
        assert_native_action(&execute.actions[3], &quote, BRIDGE);
        // Leftover wrapped input goes back as ETH, then the bridge token.
        let unwrap = abi::BASICCall::abi_decode(&execute.actions[4]).unwrap();
        assert_eq!(unwrap.sellToken, wrapped_native);
        assert_eq!(unwrap.offset, U256::from(4u64));
        assert_refunds(&execute, &[NATIVE, BRIDGE]);
        assert_eq!(execute.slippage.buyToken, TOKEN_C);
        assert_eq!(execute.slippage.minAmountOut, U256::from(1_600u64));
        assert_authorizes_complete_actions(&profile, &authorizer, &execute);
    }

    #[test]
    fn composed_native_first_then_amm_unwraps_native_output_once() {
        let profile = profile();
        let wrapped_native = profile.wrapped_native;
        let (snapshot, amm) = v2_stage(BRIDGE, wrapped_native, 1_800, 1_500);
        let quote = validated_quote(TOKEN_A, BRIDGE, 1_000, 1_800);
        let stages = [
            ComposedSwapStage::NativeRfq {
                quote: &quote,
                token_in: TOKEN_A,
                token_out: BRIDGE,
            },
            ComposedSwapStage::Amm { plan: &amm },
        ];
        let authorizer = NativeBeneficiaryAuthorizer::from_secret(TEST_SIGNING_KEY).unwrap();

        let tx = build_composed_native_rfq_tx_for_profile(
            &profile,
            &authorizer,
            TAKER,
            0,
            None,
            None,
            &snapshot,
            &stages,
            TOKEN_A,
            NATIVE,
            U256::from(1_000u64),
            U256::from(1_400u64),
            RECIPIENT,
            NOW,
            DEADLINE,
        )
        .unwrap();

        assert_eq!(tx.to, ALLOWANCE_HOLDER);
        assert_eq!(tx.value, U256::ZERO);
        let holder = abi::execCall::abi_decode(&tx.data).unwrap();
        let execute = abi::executeWithNativeAuthorizationCall::abi_decode(&holder.data).unwrap();
        assert_eq!(execute.actions.len(), 6);
        assert_eq!(
            selector(&execute.actions[0]),
            abi::TRANSFER_FROMCall::SELECTOR
        );
        assert_native_action(&execute.actions[1], &quote, TOKEN_A);
        assert_refunds(&execute, &[TOKEN_A, BRIDGE]);
        let amm_action = abi::UNISWAPV2Call::abi_decode(&execute.actions[2]).unwrap();
        assert_eq!(amm_action.sellToken, BRIDGE);
        let unwrap = abi::BASICCall::abi_decode(&execute.actions[3]).unwrap();
        assert_eq!(unwrap.sellToken, wrapped_native);
        assert_eq!(unwrap.pool, wrapped_native);
        assert_eq!(unwrap.offset, U256::from(4u64));
        let withdraw = abi::withdrawCall::abi_decode(&unwrap.data).unwrap();
        assert_eq!(withdraw.amount, U256::ZERO);
        assert_eq!(execute.slippage.buyToken, NATIVE);
        assert_eq!(execute.slippage.minAmountOut, U256::from(1_400u64));
        assert_authorizes_complete_actions(&profile, &authorizer, &execute);
    }
}
