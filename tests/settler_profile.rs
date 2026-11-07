use alloy_primitives::{Address, B256, I256, U256, address};
use alloy_sol_types::SolCall;
use sextant::abi;
use sextant::chain::{
    BSC_PROFILE, BSC_UNIV4_POOL_MANAGER, ChainProfile, NATIVE, ROBINHOOD_PROFILE, SettlerEncoding,
    SettlerProfile,
};
use sextant::ekubo::{EkuboPoolKey, EkuboQuoteState, VE33, build_pool, sim_ekubo};
use sextant::pools::{
    TickInfo, V2Pool, V2Protocol, V2State, V3ExecutionMeta, V3Pool, V3Protocol, V3State, V4Meta,
};
use sextant::route::{Hop, HopKind, Leg, Plan, best_plan};
use sextant::settler::{BPS_BASE, PositiveSlippage, build_swap_tx_for_profile, segments, v3_path};
use sextant::state::Snapshot;

const SETTLER: Address = address!("0000000000000000000000000000000000000051");
const RECIPIENT: Address = address!("0000000000000000000000000000000000000052");
const TOKEN_OUT: Address = address!("0000000000000000000000000000000000000053");
const POOL: Address = address!("0000000000000000000000000000000000000054");
const PPM_EKUBO_RUNTIMES: &[B256] = &[B256::ZERO];

fn ekubo_pool(
    token0: Address,
    token1: Address,
    extension: Address,
) -> (sextant::ekubo::EkuboPool, sextant::ekubo::EkuboState) {
    use alloy_primitives::aliases::U96;
    use ekubo_sdk::{
        chain::evm::{
            EvmPoolConfig, EvmPoolKey, EvmPoolTypeConfig, fixed_sqrt_ratio_to_contract_sqrt_ratio,
        },
        quoting::pools::full_range::FullRangePoolTypeConfig,
    };

    let fee_x64 = ((3_000u128 << 64) / 1_000_000) as u64;
    let config = EvmPoolConfig {
        extension,
        fee: if extension == Address::ZERO {
            fee_x64
        } else {
            0
        },
        pool_type_config: EvmPoolTypeConfig::FullRange(FullRangePoolTypeConfig),
    };
    let key = EvmPoolKey {
        token0,
        token1,
        config,
    };
    build_pool(
        &EkuboPoolKey {
            pool_id: key.pool_id(),
            token0,
            token1,
            config: config.into(),
        },
        EkuboQuoteState {
            tick: 0,
            sqrt_ratio: {
                let encoded = fixed_sqrt_ratio_to_contract_sqrt_ratio(U256::ONE << 128usize);
                U96::from_be_slice(&encoded.to_be_bytes::<32>()[20..])
            },
            liquidity: 1_000_000_000_000,
            min_tick: 0,
            max_tick: 0,
            ticks: Vec::new(),
        },
        (extension == VE33).then_some(fee_x64),
        ROBINHOOD_PROFILE.wrapped_native,
    )
    .unwrap()
}

fn v2_fixture(token_in: Address) -> (Snapshot, Plan) {
    let snapshot = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: Vec::new(),
        v2: vec![(
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: POOL,
                token0: token_in,
                token1: TOKEN_OUT,
                fee_bps: 25,
            },
            V2State {
                reserve0: U256::from(1_000_000u64),
                reserve1: U256::from(2_000_000u64),
            },
        )],
        ekubo: vec![],
    };
    let plan = Plan {
        legs: vec![Leg {
            path: vec![Hop {
                kind: HopKind::V2,
                index: 0,
                zero_for_one: true,
                token_in,
                token_out: TOKEN_OUT,
            }],
            amount_in: U256::from(1_000u64),
            amount_out: U256::from(900u64),
            losses: Vec::new(),
            slice_bps: BPS_BASE,
        }],
        amount_out: U256::from(900u64),
        universe_id: None,
    };
    (snapshot, plan)
}

/// Turn a one-leg plan into two legs on the same path: the first sells
/// `first_slice_bps` of the input, the second drains the rest.
fn split_first_leg(plan: &mut Plan, first_slice_bps: u32) {
    let leg = plan.legs[0].clone();
    let first_in = leg.amount_in * U256::from(first_slice_bps) / U256::from(BPS_BASE);
    let first_out = leg.amount_out * U256::from(first_slice_bps) / U256::from(BPS_BASE);
    plan.legs = vec![
        Leg {
            amount_in: first_in,
            amount_out: first_out,
            slice_bps: first_slice_bps,
            ..leg.clone()
        },
        Leg {
            amount_in: leg.amount_in - first_in,
            amount_out: leg.amount_out - first_out,
            slice_bps: BPS_BASE,
            ..leg
        },
    ];
}

/// The trailing actions return each listed token's whole balance to RECIPIENT.
fn assert_refunds(actions: &[alloy_primitives::Bytes], tokens: &[Address]) {
    let tail = &actions[actions.len() - tokens.len()..];
    for (action, token) in tail.iter().zip(tokens) {
        let refund = abi::POSITIVE_SLIPPAGECall::abi_decode(action).unwrap();
        assert_eq!(refund.recipient, RECIPIENT);
        assert_eq!(refund.token, *token);
        assert!(refund.expectedAmount.is_zero());
        assert_eq!(refund.surplusPpm, U256::from(1_000_000));
        assert_eq!(refund.maxPpm, U256::from(1_000_000));
    }
}

fn v3_fixture(token_in: Address, token_out: Address, slice_bps: u32) -> (Snapshot, Plan) {
    let snapshot = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: vec![(
            V3Pool {
                protocol: V3Protocol::UNIV3,
                address: POOL,
                token0: token_in,
                token1: token_out,
                fee_ppm: 500,
                tick_spacing: 10,
                verify_pool_spacing: false,
                execution: Some(V3ExecutionMeta {
                    fork_id: 0,
                    pool_id: 500,
                }),
                v4: None,
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
        v2: Vec::new(),
        ekubo: Vec::new(),
    };
    let plan = Plan {
        legs: vec![Leg {
            path: vec![Hop {
                kind: HopKind::V3,
                index: 0,
                zero_for_one: true,
                token_in,
                token_out,
            }],
            amount_in: U256::from(1_000u64),
            amount_out: U256::from(900u64),
            losses: Vec::new(),
            slice_bps,
        }],
        amount_out: U256::from(900u64),
        universe_id: None,
    };
    (snapshot, plan)
}

/// Robinhood with a bps build's encoding: no shipped profile reads bps any
/// more, and the encoder still has to.
fn legacy_robinhood_profile() -> ChainProfile {
    let mut profile = *ROBINHOOD_PROFILE;
    let mut settler = profile.settler.expect("Robinhood Settler");
    settler.encoding = SettlerEncoding::LegacyBpsVipPathWithSellToken;
    settler.univ4_fork_id = None;
    profile.settler = Some(settler);
    profile
}

fn ppm_profile(wrapped_native: Address) -> ChainProfile {
    ChainProfile {
        wrapped_native,
        settler: Some(SettlerProfile {
            encoding: SettlerEncoding::PpmVipPathFromPermit,
            ekubo_v3_runtimes: &[],
            indexed_v3: &[],
            univ4_pool_manager: None,
            univ4_fork_id: None,
            ..ROBINHOOD_PROFILE.settler.unwrap()
        }),
        ..*ROBINHOOD_PROFILE
    }
}

fn ppm_v4_profile(wrapped_native: Address, pool_manager: Address) -> ChainProfile {
    let mut profile = ppm_profile(wrapped_native);
    let mut settler = profile.settler.unwrap();
    settler.univ4_pool_manager = Some(pool_manager);
    profile.settler = Some(settler);
    profile
}

fn ppm_ekubo_profile(wrapped_native: Address) -> ChainProfile {
    let mut profile = ppm_profile(wrapped_native);
    let mut settler = profile.settler.unwrap();
    settler.ekubo_v3_runtimes = PPM_EKUBO_RUNTIMES;
    profile.settler = Some(settler);
    profile
}

fn v4_fixture(
    pool_manager: Address,
    token0: Address,
    token1: Address,
    zero_for_one: bool,
    native: bool,
    slice_bps: u32,
) -> (Snapshot, Plan) {
    let (token_in, token_out) = if zero_for_one {
        (token0, token1)
    } else {
        (token1, token0)
    };
    let snapshot = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: vec![(
            V3Pool {
                protocol: V3Protocol::UNIV4,
                address: pool_manager,
                token0,
                token1,
                fee_ppm: 500,
                tick_spacing: 10,
                verify_pool_spacing: false,
                execution: None,
                v4: Some(V4Meta {
                    pool_id: B256::repeat_byte(0x44),
                    state_slot: B256::repeat_byte(0x55),
                    native,
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
        v2: Vec::new(),
        ekubo: vec![],
    };
    let plan = Plan {
        legs: vec![Leg {
            path: vec![Hop {
                kind: HopKind::V3,
                index: 0,
                zero_for_one,
                token_in,
                token_out,
            }],
            amount_in: U256::from(1_000u64),
            amount_out: U256::from(900u64),
            losses: Vec::new(),
            slice_bps,
        }],
        amount_out: U256::from(900u64),
        universe_id: None,
    };
    (snapshot, plan)
}

fn assert_v4_fill(fill: &[u8], buy_token: Address) {
    // The proportion leads the fill, two bytes in a bps build and three in
    // a ppm one (BSC's).
    let width = match BSC_PROFILE.settler.expect("BSC Settler").encoding {
        sextant::chain::SettlerEncoding::LegacyBpsVipPathWithSellToken => 2,
        sextant::chain::SettlerEncoding::PpmVipPathFromPermit => 3,
    };
    assert_eq!(fill.len(), 70 + width);
    assert_eq!(U256::from_be_slice(&fill[..width]), bsc_full_spend());
    let fill = &fill[width - 2..];
    assert_eq!(fill[22], 1, "buy-token packing key");
    assert_eq!(&fill[23..43], buy_token.as_slice());
    assert_eq!(U256::from_be_slice(&fill[43..46]), U256::from(500));
    assert_eq!(U256::from_be_slice(&fill[46..49]), U256::from(10));
    assert_eq!(&fill[49..69], Address::ZERO.as_slice());
    assert_eq!(U256::from_be_slice(&fill[69..72]), U256::ZERO);
}

#[test]
fn legacy_profile_keeps_sell_token_in_vip_path() {
    let token_in = Address::repeat_byte(0x61);
    let token_out = Address::repeat_byte(0x62);
    let (snapshot, plan) = v3_fixture(token_in, token_out, BPS_BASE);
    let tx = build_swap_tx_for_profile(
        &legacy_robinhood_profile(),
        0,
        None,
        None,
        &snapshot,
        &plan,
        token_in,
        token_out,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();

    let holder = abi::execCall::abi_decode(&tx.data).unwrap();
    let execute = abi::executeCall::abi_decode(&holder.data).unwrap();
    let vip = abi::UNISWAPV3_VIPCall::abi_decode(&execute.actions[0]).unwrap();
    assert_eq!(vip.path.len(), 64);
    assert_eq!(&vip.path[..20], token_in.as_slice());
    assert_eq!(vip.path[20], 0);
    assert_eq!(U256::from_be_slice(&vip.path[21..24]), U256::from(500));
    assert_eq!(&vip.path[44..64], token_out.as_slice());
}

#[test]
fn ppm_profile_uses_permit_token_vip_path_and_ppm_payouts() {
    let token_in = Address::repeat_byte(0x61);
    let token_out = Address::repeat_byte(0x62);
    let fee_receiver = Address::repeat_byte(0x63);
    let surplus_receiver = Address::repeat_byte(0x64);
    let profile = ppm_profile(token_in);
    let (snapshot, plan) = v3_fixture(token_in, token_out, BPS_BASE);
    let tx = build_swap_tx_for_profile(
        &profile,
        9,
        Some(fee_receiver),
        Some(PositiveSlippage {
            recipient: surplus_receiver,
            expected_amount: U256::from(850u64),
            max_bps: 5_000,
        }),
        &snapshot,
        &plan,
        token_in,
        token_out,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();

    let holder = abi::execCall::abi_decode(&tx.data).unwrap();
    let execute = abi::executeCall::abi_decode(&holder.data).unwrap();
    assert_eq!(execute.actions.len(), 3);

    let vip = abi::UNISWAPV3_VIPCall::abi_decode(&execute.actions[0]).unwrap();
    assert_eq!(vip.permit.permitted.token, token_in);
    assert_eq!(vip.path.len(), 44);
    assert_eq!(vip.path[0], 0, "the fixture V3 fork id");
    assert_eq!(U256::from_be_slice(&vip.path[1..4]), U256::from(500));
    assert_eq!(&vip.path[24..44], token_out.as_slice());

    let fee = abi::BASICCall::abi_decode(&execute.actions[1]).unwrap();
    assert_eq!(fee.ppm, U256::from(900));
    let surplus = abi::POSITIVE_SLIPPAGECall::abi_decode(&execute.actions[2]).unwrap();
    assert_eq!(surplus.maxPpm, U256::from(500_000));
}

#[test]
fn ppm_profile_keeps_full_non_vip_path_and_scales_action_shares() {
    let token_in = Address::repeat_byte(0x61);
    let token_out = Address::repeat_byte(0x62);
    let profile = ppm_profile(token_in);
    let (snapshot, plan) = v3_fixture(token_in, token_out, BPS_BASE);
    let native_tx = build_swap_tx_for_profile(
        &profile,
        0,
        None,
        None,
        &snapshot,
        &plan,
        NATIVE,
        token_out,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();

    let execute = abi::executeCall::abi_decode(&native_tx.data).unwrap();
    let wrap = abi::BASICCall::abi_decode(&execute.actions[1]).unwrap();
    assert_eq!(wrap.ppm, U256::from(1_000_000));
    let v3 = abi::UNISWAPV3Call::abi_decode(&execute.actions[2]).unwrap();
    assert_eq!(v3.ppm, U256::from(1_000_000));
    assert_eq!(v3.path.len(), 64);
    assert_eq!(&v3.path[..20], token_in.as_slice());
    assert_eq!(v3.path[20], 0);

    let (v2_snapshot, mut v2_plan) = v2_fixture(token_in);
    split_first_leg(&mut v2_plan, 4_000);
    let split_tx = build_swap_tx_for_profile(
        &profile,
        0,
        None,
        None,
        &v2_snapshot,
        &v2_plan,
        token_in,
        TOKEN_OUT,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();
    let holder = abi::execCall::abi_decode(&split_tx.data).unwrap();
    let execute = abi::executeCall::abi_decode(&holder.data).unwrap();
    let v2 = abi::UNISWAPV2Call::abi_decode(&execute.actions[1]).unwrap();
    assert_eq!(v2.ppm, U256::from(400_000));
    assert_eq!(
        v2.swapInfo,
        alloy_primitives::aliases::U24::from((25 << 8) | 3)
    );
    // The second leg drains what the first left.
    let rest = abi::UNISWAPV2Call::abi_decode(&execute.actions[2]).unwrap();
    assert_eq!(rest.ppm, U256::from(1_000_000));
    assert_refunds(&execute.actions, &[token_in]);
}

#[test]
fn ppm_profile_packs_v4_fill_proportion_as_three_bytes() {
    let token_in = Address::repeat_byte(0x61);
    let token_out = Address::repeat_byte(0x62);
    let profile = ppm_v4_profile(token_in, BSC_UNIV4_POOL_MANAGER);
    let (snapshot, plan) = v4_fixture(
        BSC_UNIV4_POOL_MANAGER,
        token_in,
        token_out,
        true,
        false,
        BPS_BASE,
    );

    let tx = build_swap_tx_for_profile(
        &profile,
        0,
        None,
        None,
        &snapshot,
        &plan,
        token_in,
        token_out,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();

    let holder = abi::execCall::abi_decode(&tx.data).unwrap();
    let execute = abi::executeCall::abi_decode(&holder.data).unwrap();
    let v4 = abi::UNISWAPV4Call::abi_decode(&execute.actions[1]).unwrap();
    assert_eq!(v4.ppm, U256::from(1_000_000));
    assert_eq!(v4.fills.len(), 73);
    assert_eq!(U256::from_be_slice(&v4.fills[..3]), U256::from(1_000_000));
    assert_eq!(v4.fills[23], 1, "buy-token packing key");
    assert_eq!(&v4.fills[24..44], token_out.as_slice());
    assert_eq!(U256::from_be_slice(&v4.fills[44..47]), U256::from(500));
    assert_eq!(U256::from_be_slice(&v4.fills[47..50]), U256::from(10));
    assert_eq!(&v4.fills[50..70], Address::ZERO.as_slice());
    assert_eq!(U256::from_be_slice(&v4.fills[70..73]), U256::ZERO);
}

#[test]
fn robinhood_ekubo_packs_extensionless_ve33_and_mixed_split_actions() {
    let token0 = Address::repeat_byte(0x11);
    let token1 = Address::repeat_byte(0x33);
    let token2 = Address::repeat_byte(0x22);
    let extensionless = ekubo_pool(token0, token1, Address::ZERO);
    let ve33 = ekubo_pool(token2, token1, VE33);
    let amount = U256::from(1_000_000u64);
    let core_sim = sim_ekubo(&extensionless.0, &extensionless.1, true, amount).unwrap();
    let ve33_sim = sim_ekubo(&ve33.0, &ve33.1, false, amount).unwrap();
    assert_eq!(core_sim.fee_loss.unwrap().0, amount);
    assert_eq!(ve33_sim.fee_loss.unwrap().1, ve33_sim.amount_out);
    let config0 = extensionless.0.config;
    let config1 = ve33.0.config;
    let snapshot = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: Vec::new(),
        v2: vec![(
            V2Pool {
                protocol: V2Protocol::UNIV2,
                address: POOL,
                token0,
                token1: token2,
                fee_bps: 30,
            },
            V2State {
                reserve0: U256::from(1_000_000u64),
                reserve1: U256::from(1_000_000u64),
            },
        )],
        ekubo: vec![extensionless, ve33],
    };
    let ekubo_path = vec![
        Hop {
            kind: HopKind::Ekubo,
            index: 0,
            zero_for_one: true,
            token_in: token0,
            token_out: token1,
        },
        Hop {
            kind: HopKind::Ekubo,
            index: 1,
            zero_for_one: false,
            token_in: token1,
            token_out: token2,
        },
    ];
    assert_eq!(
        segments(&snapshot, &ekubo_path).unwrap(),
        vec![ekubo_path.clone()]
    );
    let plan = Plan {
        legs: vec![
            Leg {
                path: ekubo_path,
                amount_in: U256::from(400u64),
                amount_out: U256::from(350u64),
                losses: Vec::new(),
                slice_bps: 4_000,
            },
            Leg {
                path: vec![Hop {
                    kind: HopKind::V2,
                    index: 0,
                    zero_for_one: true,
                    token_in: token0,
                    token_out: token2,
                }],
                amount_in: U256::from(600u64),
                amount_out: U256::from(500u64),
                losses: Vec::new(),
                slice_bps: BPS_BASE,
            },
        ],
        amount_out: U256::from(850u64),
        universe_id: None,
    };

    let tx = build_swap_tx_for_profile(
        &legacy_robinhood_profile(),
        0,
        None,
        None,
        &snapshot,
        &plan,
        token0,
        token2,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();
    let holder = abi::execCall::abi_decode(&tx.data).unwrap();
    let execute = abi::executeCall::abi_decode(&holder.data).unwrap();
    assert_eq!(execute.actions.len(), 5);
    assert_refunds(&execute.actions, &[token0, token1]);

    assert_eq!(&execute.actions[1][..4], &[0xf6, 0x14, 0x60, 0xf9]);
    let ekubo = abi::EKUBOV3Call::abi_decode(&execute.actions[1]).unwrap();
    assert_eq!(ekubo.sellToken, token0);
    assert_eq!(ekubo.ppm, U256::from(4_000));
    assert!(ekubo.feeOnTransfer);
    assert_eq!(ekubo.fills.len(), 134);
    for (offset, bps, sqrt_ratio, key, buy, config) in [
        (0, 10_000, 4_611_797_791_050_542_631u128, 1, token1, config0),
        (
            67,
            42_768,
            79_227_682_466_138_141_934_206_691_491u128,
            2,
            token2,
            config1,
        ),
    ] {
        assert_eq!(
            U256::from_be_slice(&ekubo.fills[offset..offset + 2]),
            U256::from(bps)
        );
        assert_eq!(
            U256::from_be_slice(&ekubo.fills[offset + 2..offset + 14]),
            U256::from(sqrt_ratio)
        );
        assert_eq!(ekubo.fills[offset + 14], key);
        assert_eq!(&ekubo.fills[offset + 15..offset + 35], buy.as_slice());
        assert_eq!(&ekubo.fills[offset + 35..offset + 67], config.as_slice());
    }

    let v2 = abi::UNISWAPV2Call::abi_decode(&execute.actions[2]).unwrap();
    assert_eq!(v2.ppm, U256::from(BPS_BASE));
}

#[test]
fn ppm_profile_packs_ekubo_proportions_and_forward_flag_as_three_bytes() {
    let token0 = Address::repeat_byte(0x11);
    let token1 = Address::repeat_byte(0x33);
    let token2 = Address::repeat_byte(0x22);
    let extensionless = ekubo_pool(token0, token1, Address::ZERO);
    let ve33 = ekubo_pool(token2, token1, VE33);
    let config0 = extensionless.0.config;
    let config1 = ve33.0.config;
    let snapshot = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: Vec::new(),
        v2: Vec::new(),
        ekubo: vec![extensionless, ve33],
    };
    let plan = Plan {
        legs: vec![Leg {
            path: vec![
                Hop {
                    kind: HopKind::Ekubo,
                    index: 0,
                    zero_for_one: true,
                    token_in: token0,
                    token_out: token1,
                },
                Hop {
                    kind: HopKind::Ekubo,
                    index: 1,
                    zero_for_one: false,
                    token_in: token1,
                    token_out: token2,
                },
            ],
            amount_in: U256::from(1_000u64),
            amount_out: U256::from(850u64),
            losses: Vec::new(),
            slice_bps: BPS_BASE,
        }],
        amount_out: U256::from(850u64),
        universe_id: None,
    };
    let profile = ppm_ekubo_profile(token0);

    let tx = build_swap_tx_for_profile(
        &profile,
        0,
        None,
        None,
        &snapshot,
        &plan,
        token0,
        token2,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();

    let holder = abi::execCall::abi_decode(&tx.data).unwrap();
    let execute = abi::executeCall::abi_decode(&holder.data).unwrap();
    let ekubo = abi::EKUBOV3Call::abi_decode(&execute.actions[1]).unwrap();
    assert_eq!(ekubo.ppm, U256::from(1_000_000));
    assert_eq!(ekubo.fills.len(), 136);
    for (offset, proportion, sqrt_ratio, key, buy, config) in [
        (
            0,
            1_000_000,
            4_611_797_791_050_542_631u128,
            1,
            token1,
            config0,
        ),
        (
            68,
            0x8f4240,
            79_227_682_466_138_141_934_206_691_491u128,
            2,
            token2,
            config1,
        ),
    ] {
        assert_eq!(
            U256::from_be_slice(&ekubo.fills[offset..offset + 3]),
            U256::from(proportion)
        );
        assert_eq!(
            U256::from_be_slice(&ekubo.fills[offset + 3..offset + 15]),
            U256::from(sqrt_ratio)
        );
        assert_eq!(ekubo.fills[offset + 15], key);
        assert_eq!(&ekubo.fills[offset + 16..offset + 36], buy.as_slice());
        assert_eq!(&ekubo.fills[offset + 36..offset + 68], config.as_slice());
    }
}

#[test]
fn bsc_v4_native_bnb_input_wraps_then_unwraps_only_the_leg_slice() {
    let amount_in = U256::from(1_000u64);
    let slice_bps = 4_000;
    let (snapshot, mut plan) = v4_fixture(
        BSC_UNIV4_POOL_MANAGER,
        BSC_PROFILE.wrapped_native,
        TOKEN_OUT,
        true,
        true,
        BPS_BASE,
    );
    split_first_leg(&mut plan, slice_bps);

    let tx = build_swap_tx_for_profile(
        &BSC_PROFILE,
        0,
        None,
        None,
        &snapshot,
        &plan,
        NATIVE,
        TOKEN_OUT,
        amount_in,
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();

    assert_eq!(tx.to, SETTLER);
    assert_eq!(tx.value, amount_in);
    assert_eq!(tx.allowance_target, None);
    let execute = abi::executeCall::abi_decode(&tx.data).unwrap();
    // NATIVE_CHECK, wrap, then per leg an unwrap of its slice and the V4
    // swap, then leftover WBNB unwrapped and returned as BNB.
    assert_eq!(execute.actions.len(), 8);
    let second_unwrap = abi::BASICCall::abi_decode(&execute.actions[4]).unwrap();
    assert_eq!(second_unwrap.ppm, bsc_full_spend());
    assert_eq!(
        &execute.actions[5][..4],
        abi::forked_v4::UNISWAPV4Call::SELECTOR.as_slice()
    );
    assert_refunds(&execute.actions, &[NATIVE]);

    let native_check = abi::NATIVE_CHECKCall::abi_decode(&execute.actions[0]).unwrap();
    assert_eq!(native_check.deadline, U256::from(1_800_000_000u64));
    assert_eq!(native_check.amount, amount_in);

    let wrap = abi::BASICCall::abi_decode(&execute.actions[1]).unwrap();
    assert_eq!(wrap.sellToken, NATIVE);
    assert_eq!(wrap.ppm, bsc_full_spend());
    assert_eq!(wrap.pool, BSC_PROFILE.wrapped_native);
    assert_eq!(wrap.offset, U256::ZERO);
    assert!(wrap.data.is_empty());

    let unwrap = abi::BASICCall::abi_decode(&execute.actions[2]).unwrap();
    assert_eq!(unwrap.sellToken, BSC_PROFILE.wrapped_native);
    assert_eq!(
        unwrap.ppm,
        sextant::settler::settler_proportion(
            BSC_PROFILE.settler.expect("BSC Settler").encoding,
            slice_bps,
        )
    );
    assert_eq!(unwrap.pool, BSC_PROFILE.wrapped_native);
    assert_eq!(unwrap.offset, U256::from(4));
    assert_eq!(
        abi::withdrawCall::abi_decode(&unwrap.data).unwrap().amount,
        U256::ZERO
    );

    let v4 = abi::forked_v4::UNISWAPV4Call::abi_decode(&execute.actions[3]).unwrap();
    assert_eq!(v4.recipient, SETTLER);
    assert_eq!(v4.forkId, 0, "Uniswap V4 is fork 0 in BSC's build");
    assert_eq!(v4.sellToken, NATIVE);
    assert_eq!(v4.ppm, bsc_full_spend());
    assert!(!v4.feeOnTransfer);
    assert!(v4.hashMul > U256::ZERO && v4.hashMod > U256::ZERO);
    assert_eq!(v4.amountOutMin, U256::ZERO);
    assert_v4_fill(&v4.fills, TOKEN_OUT);
}

#[test]
fn bsc_v4_wbnb_input_uses_allowance_holder_and_measured_transfer() {
    // ERC-20 V4 currencies retain canonical address order. WBNB is token1 in
    // this fixture, so the encoded hop is the reverse (one-for-zero) swap.
    let (snapshot, plan) = v4_fixture(
        BSC_UNIV4_POOL_MANAGER,
        TOKEN_OUT,
        BSC_PROFILE.wrapped_native,
        false,
        false,
        BPS_BASE,
    );
    let amount_in = U256::from(1_000u64);
    let holder = BSC_PROFILE.settler.unwrap().allowance_holder;

    let tx = build_swap_tx_for_profile(
        &BSC_PROFILE,
        0,
        None,
        None,
        &snapshot,
        &plan,
        BSC_PROFILE.wrapped_native,
        TOKEN_OUT,
        amount_in,
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();

    assert_eq!(tx.to, holder);
    assert_eq!(tx.value, U256::ZERO);
    assert_eq!(tx.allowance_target, Some(holder));
    let holder_exec = abi::execCall::abi_decode(&tx.data).unwrap();
    assert_eq!(holder_exec.operator, SETTLER);
    assert_eq!(holder_exec.target, SETTLER);
    assert_eq!(holder_exec.token, BSC_PROFILE.wrapped_native);
    assert_eq!(holder_exec.amount, amount_in);

    let execute = abi::executeCall::abi_decode(&holder_exec.data).unwrap();
    assert_eq!(execute.actions.len(), 3);
    assert_refunds(&execute.actions, &[BSC_PROFILE.wrapped_native]);
    let transfer = abi::TRANSFER_FROMCall::abi_decode(&execute.actions[0]).unwrap();
    assert_eq!(transfer.recipient, SETTLER);
    assert_eq!(transfer.permit.permitted.token, BSC_PROFILE.wrapped_native);
    assert_eq!(transfer.permit.permitted.amount, amount_in);
    assert_eq!(transfer.permit.deadline, U256::from(1_800_000_000u64));

    let v4 = abi::forked_v4::UNISWAPV4Call::abi_decode(&execute.actions[1]).unwrap();
    assert_eq!(v4.recipient, SETTLER);
    assert_eq!(v4.forkId, 0, "Uniswap V4 is fork 0 in BSC's build");
    assert_eq!(v4.sellToken, BSC_PROFILE.wrapped_native);
    assert_eq!(v4.ppm, bsc_full_spend());
    assert!(v4.feeOnTransfer);
    assert_eq!(v4.amountOutMin, U256::ZERO);
    assert_v4_fill(&v4.fills, TOKEN_OUT);
}

#[test]
fn bsc_v4_encoder_rejects_a_foreign_pool_manager_snapshot() {
    let foreign_manager = Address::repeat_byte(0x77);
    let (snapshot, plan) = v4_fixture(
        foreign_manager,
        TOKEN_OUT,
        BSC_PROFILE.wrapped_native,
        false,
        false,
        BPS_BASE,
    );

    let error = build_swap_tx_for_profile(
        &BSC_PROFILE,
        0,
        None,
        None,
        &snapshot,
        &plan,
        BSC_PROFILE.wrapped_native,
        TOKEN_OUT,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("Settler PoolManager binding"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn bsc_profile_encodes_native_and_erc20_transactions() {
    let (snapshot, plan) = v2_fixture(BSC_PROFILE.wrapped_native);
    let holder = BSC_PROFILE.settler.unwrap().allowance_holder;
    for (token_in, expected_to, expected_value, expected_allowance) in [
        (NATIVE, SETTLER, U256::from(1_000u64), None),
        (BSC_PROFILE.wrapped_native, holder, U256::ZERO, Some(holder)),
    ] {
        let tx = build_swap_tx_for_profile(
            &BSC_PROFILE,
            0,
            None,
            None,
            &snapshot,
            &plan,
            token_in,
            TOKEN_OUT,
            U256::from(1_000u64),
            U256::from(800u64),
            RECIPIENT,
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(tx.to, expected_to);
        assert_eq!(tx.value, expected_value);
        assert_eq!(tx.allowance_target, expected_allowance);
    }
}

#[test]
fn executable_profile_supplies_its_own_allowance_holder() {
    let (snapshot, plan) = v2_fixture(BSC_PROFILE.wrapped_native);

    // A synthetic reviewed execution profile proves the encoder reads the
    // instance profile rather than falling back to Robinhood globals.
    let custom_holder = address!("00000000000000000000000000000000000000a5");
    let custom_bsc = ChainProfile {
        settler: Some(SettlerProfile {
            allowance_holder: custom_holder,
            ..ROBINHOOD_PROFILE.settler.unwrap()
        }),
        ..*BSC_PROFILE
    };
    let custom_tx = build_swap_tx_for_profile(
        &custom_bsc,
        0,
        None,
        None,
        &snapshot,
        &plan,
        custom_bsc.wrapped_native,
        TOKEN_OUT,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap();
    assert_eq!(custom_tx.to, custom_holder);
    assert_eq!(custom_tx.allowance_target, Some(custom_holder));
    let holder_exec = abi::execCall::abi_decode(&custom_tx.data).unwrap();
    assert_eq!(holder_exec.token, custom_bsc.wrapped_native);
}

#[test]
fn transaction_encoding_requires_a_nonzero_settler_identity() {
    let (mut snapshot, plan) = v2_fixture(ROBINHOOD_PROFILE.wrapped_native);
    snapshot.settler = None;
    let missing = build_swap_tx_for_profile(
        &ROBINHOOD_PROFILE,
        0,
        None,
        None,
        &snapshot,
        &plan,
        ROBINHOOD_PROFILE.wrapped_native,
        TOKEN_OUT,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap_err();
    assert_eq!(
        missing.to_string(),
        "snapshot has no Settler execution identity"
    );

    snapshot.settler = Some(Address::ZERO);
    let zero = build_swap_tx_for_profile(
        &ROBINHOOD_PROFILE,
        0,
        None,
        None,
        &snapshot,
        &plan,
        ROBINHOOD_PROFILE.wrapped_native,
        TOKEN_OUT,
        U256::from(1_000u64),
        U256::from(800u64),
        RECIPIENT,
        1_800_000_000,
    )
    .unwrap_err();
    assert_eq!(zero.to_string(), "snapshot Settler must not be zero");
}

#[test]
fn executionless_v3_pool_can_quote_but_cannot_encode() {
    let token_in = Address::repeat_byte(0x61);
    let token_out = Address::repeat_byte(0x62);
    let liquidity = 1_000_000_000_000u64;
    let snapshot = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: vec![(
            V3Pool {
                protocol: V3Protocol::PANCAKEV3,
                address: Address::repeat_byte(0x63),
                token0: token_in,
                token1: token_out,
                fee_ppm: 500,
                tick_spacing: 10,
                verify_pool_spacing: false,
                execution: None,
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
                        liquidity_net: I256::try_from(liquidity).expect("fits"),
                    },
                    TickInfo {
                        tick: 60_000,
                        liquidity_net: -I256::try_from(liquidity).expect("fits"),
                    },
                ]
                .into(),
                pos: 1,
                lo_cover: -120_000,
                hi_cover: 120_000,
            },
        )],
        v2: Vec::new(),
        ekubo: vec![],
    };
    let mut plan = best_plan(&snapshot, token_in, token_out, U256::from(1_000u64), 8, 0)
        .expect("quote simulation does not need execution metadata");
    assert!(plan.amount_out > U256::ZERO);
    // One pool, one leg: quantized, it drains the input.
    assert_eq!(plan.legs.len(), 1);
    plan.legs[0].slice_bps = BPS_BASE;

    let path = &plan.legs[0].path;
    assert_eq!(
        v3_path(&snapshot, path).unwrap_err().to_string(),
        "V3 pool has no execution metadata"
    );
    assert_eq!(
        segments(&snapshot, path).unwrap_err().to_string(),
        "V3 pool has no execution metadata"
    );
    assert_eq!(
        build_swap_tx_for_profile(
            &ROBINHOOD_PROFILE,
            0,
            None,
            None,
            &snapshot,
            &plan,
            token_in,
            token_out,
            U256::from(1_000u64),
            U256::ONE,
            RECIPIENT,
            1_800_000_000,
        )
        .unwrap_err()
        .to_string(),
        "V3 pool has no execution metadata"
    );
}

/// The proportion that spends a whole balance in BSC's Settler build.
fn bsc_full_spend() -> U256 {
    sextant::settler::settler_proportion(
        BSC_PROFILE.settler.expect("BSC Settler").encoding,
        BPS_BASE,
    )
}
