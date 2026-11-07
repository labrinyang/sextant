// Port of solver/test/runtests.jl, section by section. All 0x-prefixed
// expectations were generated with foundry `cast sig` / `cast calldata` /
// `cast keccak` and are byte-for-byte ground truth (same vectors as Julia).

use alloy_primitives::{Address, B256, Bytes, I256, U256, address, keccak256};
use alloy_sol_types::SolCall;
use sextant::abi::{
    self, IMulticall3, IPoolState, ISettlerRegistry, IUp33ClFactory, hexbytes, read_word, tohex,
    untwos, word_address, word_i64,
};
use sextant::pools::{
    AlgebraMeta, TickInfo, V2Pool, V2Protocol, V2State, V3ExecutionMeta, V3Pool, V3Protocol,
    V3State, sim_v2, sim_v3,
};
use sextant::quotes::net_after_fee;
use sextant::route::{Hop, HopKind, Leg, Plan, best_plan};
use sextant::server::warmup;
use sextant::settler::{BPS_BASE, PositiveSlippage, build_swap_tx};
use sextant::state::Snapshot;
use sextant::v3math::{
    MAX_SQRT_RATIO, MAX_TICK, MIN_SQRT_RATIO, MIN_TICK, compute_swap_step, muldiv, muldiv_up,
    sqrt_ratio_at_tick,
};

const SETTLER: Address = address!("1d4b86491ec211257cbedd77a4380a7494624eff");
const WETH: Address = sextant::chain::WETH;
const USDG: Address = sextant::chain::USDG;

fn u(x: u64) -> U256 {
    U256::from(x)
}

fn pow10(n: u64) -> U256 {
    U256::from(10).pow(U256::from(n))
}

fn f64_of(x: U256) -> f64 {
    x.to_string().parse().expect("decimal")
}

fn isapprox(a: f64, b: f64, rtol: f64) -> bool {
    (a - b).abs() <= rtol * a.abs().max(b.abs())
}

fn i24(v: i32) -> alloy_primitives::aliases::I24 {
    alloy_primitives::aliases::I24::try_from(v).expect("fits int24")
}

// ---- keccak256 ----

#[test]
fn keccak_vectors() {
    assert_eq!(
        tohex(keccak256(b"").as_slice()),
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    assert_eq!(
        tohex(keccak256(b"abc").as_slice()),
        "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
    let long = format!(
        "SwapSolver keccak cross-check vector: {}",
        vec!["0123456789"; 13].join(" ")
    );
    assert!(long.len() > 136); // exercises multi-block absorb
    assert_eq!(
        tohex(keccak256(long.as_bytes()).as_slice()),
        "0x2ef7e5d93b1fab2a49189fb2fcadb3e44ca0d78a8c7eb94eb3aa5e040c4687ae"
    );
}

// ---- selectors (compile-time, must match `cast sig`) ----

#[test]
fn selectors() {
    assert_eq!(tohex(&abi::transferCall::SELECTOR), "0xa9059cbb");
    assert_eq!(tohex(&abi::TRANSFER_FROMCall::SELECTOR), "0xc1fb425e");
    assert_eq!(tohex(&abi::UNISWAPV3Call::SELECTOR), "0x8d68a156");
    assert_eq!(tohex(&abi::UNISWAPV3_VIPCall::SELECTOR), "0x3036d6a6");
    assert_eq!(tohex(&abi::UNISWAPV2Call::SELECTOR), "0x103b48be");
    assert_eq!(tohex(&abi::BASICCall::SELECTOR), "0x38c9c147");
    assert_eq!(tohex(&abi::POSITIVE_SLIPPAGECall::SELECTOR), "0x5f80abae");
    assert_eq!(tohex(&abi::VELODROMECall::SELECTOR), "0xf5b99189");
    assert_eq!(tohex(&abi::NATIVE_CHECKCall::SELECTOR), "0xbd01c226");
    assert_eq!(tohex(&abi::executeCall::SELECTOR), "0x1fff991f");
    assert_eq!(tohex(&abi::execCall::SELECTOR), "0x2213bc0b");
    assert_eq!(
        tohex(&ISettlerRegistry::ownerOfCall::SELECTOR),
        "0x6352211e"
    );
    assert_eq!(tohex(&IMulticall3::aggregate3Call::SELECTOR), "0x82ad56cb");
    assert_eq!(tohex(&IPoolState::tickBitmapCall::SELECTOR), "0x5339c296");
    assert_eq!(tohex(&IPoolState::ticksCall::SELECTOR), "0xf30dba93");
    assert_eq!(tohex(&abi::UNISWAPV4Call::SELECTOR), "0xaf72634f");
    // `cast sig 'UNISWAPV4(address,address,uint256,uint8,bool,uint256,uint256,bytes,uint256)'`
    assert_eq!(
        tohex(&abi::forked_v4::UNISWAPV4Call::SELECTOR),
        "0x68f5ee25"
    );
}

// ---- abi encode vs cast ----

fn permit(token: Address, amount: u64, deadline: u64) -> abi::PermitTransferFrom {
    abi::PermitTransferFrom {
        permitted: abi::TokenPermissions {
            token,
            amount: u(amount),
        },
        nonce: U256::ZERO,
        deadline: u(deadline),
    }
}

#[test]
fn abi_encode_vs_cast() {
    assert_eq!(
        tohex(
            &abi::transferCall {
                to: address!("00000000000000000000000000000000000000aa"),
                amount: U256::ZERO
            }
            .abi_encode()
        ),
        "0xa9059cbb00000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000"
    );

    assert_eq!(
        tohex(
            &abi::TRANSFER_FROMCall {
                recipient: SETTLER,
                permit: permit(WETH, 123456789, 1789000000),
                sig: Bytes::new()
            }
            .abi_encode()
        ),
        "0xc1fb425e0000000000000000000000001d4b86491ec211257cbedd77a4380a7494624eff0000000000000000000000000bd7d308f8e1639fab988df18a8011f41eacad7300000000000000000000000000000000000000000000000000000000075bcd150000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006aa1f94000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000"
    );

    assert_eq!(
        tohex(
            &abi::POSITIVE_SLIPPAGECall {
                recipient: address!("00000000000000000000000000000000000000fe"),
                token: USDG,
                expectedAmount: u(9991),
                surplusPpm: u(1_000_000),
                maxPpm: u(5000),
            }
            .abi_encode()
        ),
        "0x5f80abae00000000000000000000000000000000000000000000000000000000000000fe0000000000000000000000005fc5360d0400a0fd4f2af552add042d716f1d168000000000000000000000000000000000000000000000000000000000000270700000000000000000000000000000000000000000000000000000000000f42400000000000000000000000000000000000000000000000000000000000001388"
    );

    let path = hexbytes("0x0bd7d308f8e1639fab988df18a8011f41eacad73280000c800000000000000000000000000000001000276a45fc5360d0400a0fd4f2af552add042d716f1d168").unwrap();
    assert_eq!(path.len(), 64);
    assert_eq!(
        tohex(
            &abi::UNISWAPV3Call {
                recipient: SETTLER,
                ppm: u(10000),
                path: path.clone().into(),
                amountOutMin: U256::ZERO
            }
            .abi_encode()
        ),
        "0x8d68a1560000000000000000000000001d4b86491ec211257cbedd77a4380a7494624eff00000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400bd7d308f8e1639fab988df18a8011f41eacad73280000c800000000000000000000000000000001000276a45fc5360d0400a0fd4f2af552add042d716f1d168"
    );

    let inner = abi::transferCall {
        to: address!("000000000000000000000000000000000000dead"),
        amount: U256::ZERO,
    }
    .abi_encode();
    assert_eq!(
        tohex(
            &abi::executeCall {
                slippage: abi::AllowedSlippage {
                    recipient: address!("7665c425b5f3a0249644024bb32a179ab2d5e0a2"),
                    buyToken: USDG,
                    minAmountOut: u(987654321),
                },
                actions: vec![inner.into()],
                zid: B256::ZERO,
            }
            .abi_encode()
        ),
        "0x1fff991f0000000000000000000000007665c425b5f3a0249644024bb32a179ab2d5e0a20000000000000000000000005fc5360d0400a0fd4f2af552add042d716f1d168000000000000000000000000000000000000000000000000000000003ade68b100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000000000000000000000000000000000000000dead000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );

    assert_eq!(
        tohex(
            &IMulticall3::aggregate3Call {
                calls: vec![
                    IMulticall3::Call3 {
                        target: sextant::rpc::MULTICALL3,
                        allowFailure: true,
                        callData: hexbytes("0x4e487b71").unwrap().into()
                    },
                    IMulticall3::Call3 {
                        target: WETH,
                        allowFailure: false,
                        callData: Bytes::new()
                    },
                ],
            }
            .abi_encode()
        ),
        "0x82ad56cb00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000ca11bde05977b3631167028862be2a173976ca110000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000044e487b71000000000000000000000000000000000000000000000000000000000000000000000000000000000bd7d308f8e1639fab988df18a8011f41eacad73000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000"
    );

    assert_eq!(
        tohex(
            &abi::execCall {
                operator: SETTLER,
                token: WETH,
                amount: u(1000000),
                target: SETTLER,
                data: hexbytes("0x1fff991f").unwrap().into(),
            }
            .abi_encode()
        ),
        "0x2213bc0b0000000000000000000000001d4b86491ec211257cbedd77a4380a7494624eff0000000000000000000000000bd7d308f8e1639fab988df18a8011f41eacad7300000000000000000000000000000000000000000000000000000000000f42400000000000000000000000001d4b86491ec211257cbedd77a4380a7494624eff00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000041fff991f00000000000000000000000000000000000000000000000000000000"
    );

    assert_eq!(
        tohex(&IPoolState::ticksCall { tick: i24(-887220) }.abi_encode()),
        "0xf30dba93fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2764c"
    );
}

// ---- abi decode ----

#[test]
fn abi_decode() {
    // aggregate3 result envelope roundtrip
    let results = vec![
        IMulticall3::Result {
            success: true,
            returnData: hexbytes("0x1234").unwrap().into(),
        },
        IMulticall3::Result {
            success: false,
            returnData: Bytes::new(),
        },
    ];
    let enc = IMulticall3::aggregate3Call::abi_encode_returns(&results);
    let dec = IMulticall3::aggregate3Call::abi_decode_returns(&enc).unwrap();
    assert!(dec[0].success && dec[0].returnData.as_ref() == hexbytes("0x1234").unwrap().as_slice());
    assert!(!dec[1].success && dec[1].returnData.is_empty());

    // raw slot0-style word reads
    let mut slot0 = (U256::ONE << 96usize).to_be_bytes::<32>().to_vec();
    slot0.extend_from_slice(
        &I256::try_from(-100i64)
            .unwrap()
            .into_raw()
            .to_be_bytes::<32>(),
    );
    slot0.extend_from_slice(&u(7).to_be_bytes::<32>());
    assert_eq!(read_word(&slot0, 0).unwrap(), U256::ONE << 96usize);
    assert_eq!(word_i64(read_word(&slot0, 32).unwrap()).unwrap(), -100);
    assert_eq!(
        untwos(read_word(&slot0, 64).unwrap()),
        I256::try_from(7i64).unwrap()
    );

    // address return
    let enc = ISettlerRegistry::ownerOfCall::abi_encode_returns(&SETTLER);
    assert_eq!(word_address(&enc, 0).unwrap(), SETTLER);

    // int24[] return roundtrip
    let spacings = vec![i24(1), i24(50), i24(-200)];
    let enc = IUp33ClFactory::tickSpacingsCall::abi_encode_returns(&spacings);
    let dec = IUp33ClFactory::tickSpacingsCall::abi_decode_returns(&enc).unwrap();
    assert_eq!(
        dec.iter().map(|v| v.as_i32()).collect::<Vec<_>>(),
        vec![1, 50, -200]
    );
}

// ---- v3 math ----

#[test]
fn v3_math() {
    assert_eq!(sqrt_ratio_at_tick(0).unwrap(), U256::ONE << 96usize);
    assert_eq!(sqrt_ratio_at_tick(MIN_TICK).unwrap(), MIN_SQRT_RATIO);
    assert_eq!(sqrt_ratio_at_tick(MAX_TICK).unwrap(), MAX_SQRT_RATIO);
    assert!(sqrt_ratio_at_tick(MAX_TICK + 1).is_err());
    for t in [-500000i32, -100000, -1000, -1, 1, 1000, 100000, 500000] {
        let approx = f64_of(sqrt_ratio_at_tick(t).unwrap()) / 2f64.powi(96);
        assert!(
            isapprox(approx, 1.0001f64.powf(t as f64 / 2.0), 1e-9),
            "tick {t}"
        );
    }
    assert_eq!(muldiv(u(6), u(7), u(3)).unwrap(), u(14));
    assert_eq!(muldiv_up(u(1), u(1), u(3)).unwrap(), u(1));
    assert_eq!(muldiv(U256::MAX, u(1), u(1)).unwrap(), U256::MAX);
    assert!(muldiv(U256::MAX, U256::MAX, u(1)).is_err());

    // small in-range step: fee comes out of input, price falls for zeroForOne
    let l = pow10(21);
    let p0 = U256::ONE << 96usize;
    let (pn, ain, aout, fee) =
        compute_swap_step(p0, MIN_SQRT_RATIO + U256::ONE, l, pow10(15), 3000).unwrap();
    assert_eq!(ain + fee, pow10(15));
    assert!(pn < p0);
    assert!(isapprox(f64_of(aout), 0.997e15, 1e-3));
}

// ---- v2 sim ----

#[test]
fn v2_sim() {
    let p = V2Pool {
        protocol: V2Protocol::UNIV2,
        address: address!("00000000000000000000000000000000000000f2"),
        token0: address!("000000000000000000000000000000000000000a"),
        token1: address!("000000000000000000000000000000000000000b"),
        fee_bps: 30,
    };
    let s = V2State {
        reserve0: pow10(18),
        reserve1: u(2) * pow10(18),
    };
    let r = sim_v2(&p, &s, true, pow10(15)).unwrap();
    let xf = pow10(15) * u(9970);
    let expected = (xf * (u(2) * pow10(18))) / (xf + pow10(18) * u(10000));
    assert_eq!(r.amount_out, expected);
    assert_eq!(r.reserve0, pow10(18) + pow10(15));
    assert_eq!(r.reserve1, u(2) * pow10(18) - expected);
}

// ---- v3 sim ----

fn synthetic_v3(fee: u32) -> (V3Pool, V3State) {
    let l = pow10(21);
    let pool = V3Pool {
        protocol: V3Protocol::UP33CL,
        address: address!("1000000000000000000000000000000000000001"),
        token0: address!("0a00000000000000000000000000000000000001"),
        token1: address!("0b00000000000000000000000000000000000001"),
        fee_ppm: fee,
        tick_spacing: 200,
        verify_pool_spacing: false,
        execution: Some(V3ExecutionMeta {
            fork_id: 40,
            pool_id: 200,
        }),
        v4: None,
        algebra: None,
    };
    let ticks = vec![
        TickInfo {
            tick: -600,
            liquidity_net: I256::try_from(l).unwrap(),
        },
        TickInfo {
            tick: 600,
            liquidity_net: -I256::try_from(l).unwrap(),
        },
    ];
    let state = V3State {
        sqrt_price: U256::ONE << 96usize,
        tick: 0,
        liquidity: l,
        ticks: ticks.into(),
        pos: 1,
        lo_cover: -600 * 300,
        hi_cover: 600 * 300,
    };
    (pool, state)
}

#[test]
fn v3_sim() {
    let (pool, state) = synthetic_v3(3000);
    let working = state.clone();
    assert_eq!(
        state.ticks.as_ptr(),
        working.ticks.as_ptr(),
        "working states must share the immutable tick table"
    );
    // tiny swap ~ spot price 1, minus 0.3% fee
    let r = sim_v3(&pool, &state, true, pow10(15)).unwrap();
    assert_eq!(r.consumed, pow10(15));
    assert!(isapprox(f64_of(r.amount_out), 0.997e15, 1e-2));
    // huge swap exhausts the single position: partial consumption, not an error
    let big = pow10(24);
    let r2 = sim_v3(&pool, &state, true, big).unwrap();
    assert!(r2.consumed < big);
    assert!(r2.amount_out > U256::ZERO);
    assert!(r2.liquidity.is_zero()); // crossed below -600
    // state untouched by pure sims
    assert_eq!(state.sqrt_price, U256::ONE << 96usize);
}

// ---- greedy split across twin pools ----

#[test]
fn greedy_split_across_twin_pools() {
    let (pool_a, sa) = synthetic_v3(3000);
    let (_, sb) = synthetic_v3(3000);
    let pool_b = V3Pool {
        protocol: V3Protocol::UNIV3,
        address: address!("2000000000000000000000000000000000000002"),
        token0: pool_a.token0,
        token1: pool_a.token1,
        fee_ppm: 3000,
        tick_spacing: 60,
        verify_pool_spacing: false,
        execution: Some(V3ExecutionMeta {
            fork_id: 0,
            pool_id: 3000,
        }),
        v4: None,
        algebra: None,
    };
    let snap = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: vec![(pool_a.clone(), sa), (pool_b, sb)],
        v2: vec![],
        ekubo: vec![],
    };
    let amount = u(4) * pow10(19); // inside the twin pools' combined [-600,600] depth
    let plan = best_plan(&snap, pool_a.token0, pool_a.token1, amount, 64, 200).unwrap();
    assert_eq!(plan.legs.len(), 2);
    let mut shares: Vec<u64> = plan
        .legs
        .iter()
        .map(|leg| ((leg.amount_in * u(10_000)) / amount).to::<u64>())
        .collect();
    shares.sort();
    assert!(
        shares.iter().all(|s| (4000..=6000).contains(s)),
        "twins ⇒ ~50/50, got {shares:?}"
    );
    assert!(plan.amount_out > U256::ZERO);
}

// ---- settler encoding structure ----

#[test]
fn settler_encoding_structure() {
    let (pool, state) = synthetic_v3(3000);
    let snap = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: vec![(pool.clone(), state)],
        v2: vec![],
        ekubo: vec![],
    };
    let fee_receiver = address!("00000000000000000000000000000000000000fe");
    let hop = Hop {
        kind: HopKind::V3,
        index: 0,
        zero_for_one: true,
        token_in: pool.token0,
        token_out: pool.token1,
    };
    let plan = Plan {
        legs: vec![Leg {
            path: vec![hop],
            amount_in: pow10(18),
            amount_out: pow10(18),
            losses: vec![],
            slice_bps: 10000,
        }],
        amount_out: pow10(18),
        universe_id: None,
    };
    let user = address!("7665c425b5f3a0249644024bb32a179ab2d5e0a2");

    let zero_fee_receiver = build_swap_tx(
        0,
        Some(Address::ZERO),
        None,
        &snap,
        &plan,
        pool.token0,
        pool.token1,
        pow10(18),
        u(99),
        user,
        1789000000,
    )
    .unwrap_err();
    assert!(
        zero_fee_receiver
            .to_string()
            .contains("fee receiver must not be zero")
    );

    let self_recipient = build_swap_tx(
        0,
        None,
        None,
        &snap,
        &plan,
        pool.token0,
        pool.token1,
        pow10(18),
        u(99),
        SETTLER,
        1789000000,
    )
    .unwrap_err();
    assert!(
        self_recipient
            .to_string()
            .contains("recipient must not be the Settler")
    );

    let self_fee_receiver = build_swap_tx(
        0,
        Some(SETTLER),
        None,
        &snap,
        &plan,
        pool.token0,
        pool.token1,
        pow10(18),
        u(99),
        user,
        1789000000,
    )
    .unwrap_err();
    assert!(
        self_fee_receiver
            .to_string()
            .contains("fee receiver must not be the Settler")
    );

    let self_positive_recipient = build_swap_tx(
        0,
        None,
        Some(PositiveSlippage {
            recipient: SETTLER,
            expected_amount: plan.amount_out,
            max_bps: BPS_BASE,
        }),
        &snap,
        &plan,
        pool.token0,
        pool.token1,
        pow10(18),
        u(99),
        user,
        1789000000,
    )
    .unwrap_err();
    assert!(
        self_positive_recipient
            .to_string()
            .contains("positive slippage recipient must not be the Settler")
    );

    // ERC20 in, single v3 leg → AllowanceHolder.exec(VIP + fee BASIC)
    let tx = build_swap_tx(
        9,
        Some(fee_receiver),
        None,
        &snap,
        &plan,
        pool.token0,
        pool.token1,
        pow10(18),
        u(99),
        user,
        1789000000,
    )
    .unwrap();
    assert_eq!(tx.to, sextant::chain::ALLOWANCE_HOLDER);
    assert_eq!(tx.allowance_target, Some(sextant::chain::ALLOWANCE_HOLDER));
    assert!(tx.value.is_zero());
    assert_eq!(tohex(&tx.data[..4]), "0x2213bc0b");
    let ah = abi::execCall::abi_decode(&tx.data).unwrap();
    assert_eq!(ah.operator, SETTLER);
    assert_eq!(ah.target, SETTLER);
    assert_eq!(ah.token, pool.token0);
    assert_eq!(ah.amount, pow10(18));
    assert_eq!(tohex(&ah.data[..4]), "0x1fff991f");
    let ex = abi::executeCall::abi_decode(&ah.data).unwrap();
    assert_eq!(ex.slippage.recipient, user);
    assert_eq!(ex.slippage.buyToken, pool.token1);
    assert_eq!(ex.slippage.minAmountOut, u(99));
    assert_eq!(ex.actions.len(), 2);
    assert_eq!(tohex(&ex.actions[0][..4]), "0x3036d6a6"); // UNISWAPV3_VIP
    assert_eq!(tohex(&ex.actions[1][..4]), "0x38c9c147"); // BASIC fee
    // Robinhood's build reads ppm and takes the VIP path's sell token from
    // the permit: the path starts at the fork id, 0x28 | ts200 | limit | token1.
    let vip = abi::UNISWAPV3_VIPCall::abi_decode(&ex.actions[0]).unwrap();
    assert_eq!(vip.recipient, SETTLER);
    assert_eq!(vip.permit.permitted.token, pool.token0);
    assert_eq!(vip.permit.permitted.amount, pow10(18));
    assert_eq!(vip.permit.nonce, U256::ZERO);
    assert_eq!(vip.permit.deadline, u(1789000000));
    assert!(vip.sig.is_empty() && vip.amountOutMin.is_zero());
    let path = vip.path.as_ref();
    assert_eq!(path.len(), 44);
    assert_eq!(path[0], 0x28);
    assert_eq!(U256::from_be_slice(&path[1..4]), u(200));
    assert_eq!(&path[24..44], pool.token1.as_slice());

    let surplus_receiver = address!("00000000000000000000000000000000000000fd");
    let expected_amount = net_after_fee(plan.amount_out, 9).unwrap();
    let positive_slippage = PositiveSlippage {
        recipient: surplus_receiver,
        expected_amount,
        max_bps: 5_000,
    };
    let positive_tx = build_swap_tx(
        9,
        Some(fee_receiver),
        Some(positive_slippage),
        &snap,
        &plan,
        pool.token0,
        pool.token1,
        pow10(18),
        u(99),
        user,
        1789000000,
    )
    .unwrap();
    let positive_holder = abi::execCall::abi_decode(&positive_tx.data).unwrap();
    let positive_execute = abi::executeCall::abi_decode(&positive_holder.data).unwrap();
    assert_eq!(positive_execute.actions.len(), 3);
    assert_eq!(positive_execute.actions[1][..4], abi::BASICCall::SELECTOR);
    assert_eq!(
        positive_execute.actions[2][..4],
        abi::POSITIVE_SLIPPAGECall::SELECTOR
    );
    let positive_action =
        abi::POSITIVE_SLIPPAGECall::abi_decode(&positive_execute.actions[2]).unwrap();
    assert_eq!(positive_action.recipient, surplus_receiver);
    assert_eq!(positive_action.token, pool.token1);
    assert_eq!(positive_action.expectedAmount, expected_amount);
    assert_eq!(positive_action.maxPpm, robinhood_proportion(5_000));

    let no_fee_tx = build_swap_tx(
        0,
        None,
        Some(PositiveSlippage {
            expected_amount: plan.amount_out,
            ..positive_slippage
        }),
        &snap,
        &plan,
        pool.token0,
        pool.token1,
        pow10(18),
        u(99),
        user,
        1789000000,
    )
    .unwrap();
    let no_fee_holder = abi::execCall::abi_decode(&no_fee_tx.data).unwrap();
    let no_fee_execute = abi::executeCall::abi_decode(&no_fee_holder.data).unwrap();
    assert_eq!(no_fee_execute.actions.len(), 2);
    assert_eq!(
        no_fee_execute.actions[1][..4],
        abi::POSITIVE_SLIPPAGECall::SELECTOR
    );

    // ETH endpoints route through a wrapped-native pool.
    let (weth_pool, weth_state) = synthetic_v3(3000);
    let weth_pool = V3Pool {
        token1: sextant::chain::WETH,
        ..weth_pool
    };
    let weth_snap = Snapshot {
        v3: vec![(weth_pool.clone(), weth_state)],
        ..snap.clone()
    };
    let weth_plan = |sell_weth: bool| {
        let (token_in, token_out) = if sell_weth {
            (sextant::chain::WETH, weth_pool.token0)
        } else {
            (weth_pool.token0, sextant::chain::WETH)
        };
        Plan {
            legs: vec![Leg {
                path: vec![Hop {
                    kind: HopKind::V3,
                    index: 0,
                    zero_for_one: !sell_weth,
                    token_in,
                    token_out,
                }],
                amount_in: pow10(18),
                amount_out: pow10(18),
                losses: vec![],
                slice_bps: 10000,
            }],
            amount_out: pow10(18),
            universe_id: None,
        }
    };
    // A plan that does not start at the wrapped token cannot take ETH.
    assert!(
        build_swap_tx(
            9,
            Some(fee_receiver),
            None,
            &snap,
            &plan,
            sextant::chain::NATIVE,
            pool.token1,
            pow10(18),
            u(99),
            user,
            1789000000,
        )
        .unwrap_err()
        .to_string()
        .contains("plan does not match the transaction endpoints")
    );

    // native in → direct Settler call, NATIVE_CHECK + wrap first
    let txn = build_swap_tx(
        9,
        Some(fee_receiver),
        None,
        &weth_snap,
        &weth_plan(true),
        sextant::chain::NATIVE,
        weth_pool.token0,
        pow10(18),
        u(99),
        user,
        1789000000,
    )
    .unwrap();
    assert_eq!(txn.to, SETTLER);
    assert_eq!(txn.allowance_target, None);
    assert_eq!(txn.value, pow10(18));
    assert_eq!(tohex(&txn.data[..4]), "0x1fff991f");
    let exn = abi::executeCall::abi_decode(&txn.data).unwrap();
    assert_eq!(tohex(&exn.actions[0][..4]), "0xbd01c226"); // NATIVE_CHECK
    assert_eq!(tohex(&exn.actions[1][..4]), "0x38c9c147"); // BASIC wrap
    assert_eq!(tohex(&exn.actions[2][..4]), "0x8d68a156"); // UNISWAPV3 (balance-funded)
    // fee, then leftover WETH unwrapped and returned as ETH
    assert_eq!(exn.actions.len(), 6);
    let refund = abi::POSITIVE_SLIPPAGECall::abi_decode(&exn.actions[5]).unwrap();
    assert_eq!(refund.token, sextant::chain::NATIVE);
    assert_eq!(refund.recipient, user);

    // native out → unwrap + native fee + native slippage payout
    let txo = build_swap_tx(
        9,
        Some(fee_receiver),
        None,
        &weth_snap,
        &weth_plan(false),
        weth_pool.token0,
        sextant::chain::NATIVE,
        pow10(18),
        u(99),
        user,
        1789000000,
    )
    .unwrap();
    let aho = abi::execCall::abi_decode(&txo.data).unwrap();
    let exo = abi::executeCall::abi_decode(&aho.data).unwrap();
    assert_eq!(exo.slippage.buyToken, sextant::chain::NATIVE);
    assert_eq!(exo.actions.len(), 3); // VIP, unwrap, native fee (payout via slippage)

    let positive_native = build_swap_tx(
        9,
        Some(fee_receiver),
        Some(positive_slippage),
        &weth_snap,
        &weth_plan(false),
        weth_pool.token0,
        sextant::chain::NATIVE,
        pow10(18),
        u(99),
        user,
        1789000000,
    )
    .unwrap();
    let positive_native_holder = abi::execCall::abi_decode(&positive_native.data).unwrap();
    let positive_native_execute =
        abi::executeCall::abi_decode(&positive_native_holder.data).unwrap();
    assert_eq!(positive_native_execute.actions.len(), 4);
    assert_eq!(
        positive_native_execute.actions[1][..4],
        abi::BASICCall::SELECTOR
    ); // unwrap
    assert_eq!(
        positive_native_execute.actions[2][..4],
        abi::BASICCall::SELECTOR
    ); // fee
    let positive_native_action =
        abi::POSITIVE_SLIPPAGECall::abi_decode(&positive_native_execute.actions[3]).unwrap();
    assert_eq!(positive_native_action.token, sextant::chain::NATIVE);
    assert_eq!(positive_native_action.expectedAmount, expected_amount);
    assert_eq!(positive_native_action.maxPpm, robinhood_proportion(5_000));
}

// ---- universal V2 measured-input encoding ----

// The solver never classifies tokens: every UNISWAPV2 action sets the
// sellTokenHasFee bit so Settler computes the sell amount from the pool's
// actual balance delta. Identity tokens get identical amounts; fee-on-transfer
// tokens execute instead of reverting.
#[test]
fn v2_actions_always_measure_pool_input() {
    let pool = V2Pool {
        protocol: V2Protocol::UNIV2,
        address: address!("2000000000000000000000000000000000000002"),
        token0: address!("0a00000000000000000000000000000000000001"),
        token1: address!("0b00000000000000000000000000000000000001"),
        fee_bps: 30,
    };
    let state = V2State {
        reserve0: pow10(18),
        reserve1: pow10(18),
    };
    let snap = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: vec![],
        v2: vec![(pool.clone(), state)],
        ekubo: vec![],
    };
    let plan = Plan {
        legs: vec![Leg {
            path: vec![Hop {
                kind: HopKind::V2,
                index: 0,
                zero_for_one: true,
                token_in: pool.token0,
                token_out: pool.token1,
            }],
            amount_in: pow10(15),
            amount_out: u(1),
            losses: vec![],
            slice_bps: 10000,
        }],
        amount_out: u(1),
        universe_id: None,
    };
    let user = address!("7665c425b5f3a0249644024bb32a179ab2d5e0a2");
    let tx = build_swap_tx(
        0,
        None,
        None,
        &snap,
        &plan,
        pool.token0,
        pool.token1,
        pow10(15),
        u(1),
        user,
        1789000000,
    )
    .unwrap();
    let holder = abi::execCall::abi_decode(&tx.data).unwrap();
    let execute = abi::executeCall::abi_decode(&holder.data).unwrap();
    let v2 = execute
        .actions
        .iter()
        .find(|action| action[..4] == abi::UNISWAPV2Call::SELECTOR)
        .expect("a V2 action");
    let action = abi::UNISWAPV2Call::abi_decode(v2).unwrap();
    let swap_info = action.swapInfo.to::<u32>();
    assert_eq!(swap_info & 1, 1, "zeroForOne");
    assert_ne!(swap_info & 2, 0, "universal measured-input bit");
    assert_eq!(swap_info >> 8, 30, "pool fee bps");
}

// ---- fee math ----

#[test]
fn fee_math() {
    assert_eq!(net_after_fee(u(10_000), 9).unwrap(), u(9_991));
    assert_eq!(net_after_fee(U256::ZERO, 9).unwrap(), U256::ZERO);
    let _ = BPS_BASE;
}

// ---- depth exhaustion fails with the cause, not a quantization error ----

#[test]
fn depth_exhaustion_errors_cleanly() {
    let (pool, state) = synthetic_v3(3000);
    let snap = Snapshot {
        block: 1,
        settler: Some(SETTLER),
        v3: vec![(pool.clone(), state)],
        v2: vec![],
        ekubo: vec![],
    };
    // the [-600,600] position absorbs ~3e19 of token0; ask for far more
    let err = best_plan(&snap, pool.token0, pool.token1, pow10(21), 64, 200).unwrap_err();
    assert!(err.to_string().contains("modeled depth"), "got: {err:#}");
    // an amount no chunk of which fits fails with the no-route error instead
    let err = best_plan(&snap, pool.token0, pool.token1, pow10(27), 64, 200).unwrap_err();
    assert!(
        err.to_string().contains("no route can absorb"),
        "got: {err:#}"
    );
}

// ---- upstream failures carry the 502 marker ----

#[tokio::test]
async fn upstream_failures_carry_the_rpc_marker() {
    let rpc = sextant::rpc::Rpc::connect("http://127.0.0.1:9/").expect("connect is lazy");
    let err = rpc
        .block_number()
        .await
        .expect_err("nothing listens on port 9");
    assert!(
        err.downcast_ref::<sextant::rpc::RpcUnavailable>().is_some(),
        "missing marker: {err:#}"
    );
}

// ---- server warmup boots offline ----

#[test]
fn warmup_boots_offline() {
    warmup().unwrap();
}

#[test]
fn clone_pool_create2_derivation() {
    use sextant::chain::{
        GIGADEX_V3_DEPLOYER, GIGADEX_V3_INIT, PANCAKE_V3_DEPLOYER, PANCAKE_V3_INIT,
        ROBINSWAP_V3_DEPLOYER, ROBINSWAP_V3_INIT, SUSHI_V3_DEPLOYER, SUSHI_V3_INIT,
        SWAPHOOD_V3_DEPLOYER, SWAPHOOD_V3_INIT, USDG, WETH,
    };
    use sextant::state::clone_pool_addr;
    // chain-verified 2026-07-18: cast create2 + live slot0()/tickSpacing() answers
    assert_eq!(
        clone_pool_addr(PANCAKE_V3_DEPLOYER, PANCAKE_V3_INIT, WETH, USDG, 100),
        address!("4520F3f932AE530c58CC332b532951e5814e6CB8")
    );
    assert_eq!(
        clone_pool_addr(SWAPHOOD_V3_DEPLOYER, SWAPHOOD_V3_INIT, WETH, USDG, 500),
        address!("6356d82a3d7B9223764339B5F50E7ED01641FB30")
    );
    assert_eq!(
        clone_pool_addr(GIGADEX_V3_DEPLOYER, GIGADEX_V3_INIT, WETH, USDG, 500),
        address!("65Ce976B6ab72F9533B4dAF53C8dE15DfeCD408B")
    );
    assert_eq!(
        clone_pool_addr(SUSHI_V3_DEPLOYER, SUSHI_V3_INIT, WETH, USDG, 3000),
        address!("C5A01C57b2851202dCF8507a0F2Bd08a8025E2C8")
    );
    assert_eq!(
        clone_pool_addr(ROBINSWAP_V3_DEPLOYER, ROBINSWAP_V3_INIT, WETH, USDG, 500),
        address!("86D3E4447cbCDF6b12600D17F117d39BBCFa10a5")
    );
}

#[test]
fn v4_pool_meta_derivation() {
    use sextant::chain::{USDG, WETH};
    use sextant::state::v4_meta;
    // chain-verified 2026-07-18: cast keccak vectors; extsload(stateSlot) on
    // the PoolManager returned a live packed slot0 for this key
    let m = v4_meta(WETH, USDG, 3000, 60, Address::ZERO);
    assert_eq!(
        tohex(m.pool_id.as_slice()),
        "0x77c25b9386d47de62e0155c393696e9f43f7e6d036c6ca52f66735ccbb8808a7"
    );
    assert_eq!(
        tohex(m.state_slot.as_slice()),
        "0xaefb7f01ca3d94e49f8f168b305a3ed841cef2fa9bcf1a740fff43a4fded3a88"
    );
}

#[test]
fn v4_hooked_pool_meta_derivation() {
    use sextant::chain::USDG;
    use sextant::state::v4_meta;
    // Ground truth from the chain, 2026-08-01: the USDG/NVDA dynamic-fee
    // pool's Initialize event (PoolManager Initialize topic[1] IS the PoolKey
    // hash). A wrong hooks encoding cannot produce this id.
    let nvda = address!("d0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC");
    let hooks = address!("a0ce1df0191a66434fb04391161776c7814f8a80");
    let m = v4_meta(USDG, nvda, 0x80_0000, 60, hooks);
    assert_eq!(
        tohex(m.pool_id.as_slice()),
        "0x441d580dcf4b436956c6e297a62f5cd4a8cd34ea1aa5cc80fd6a9a0b08ef3429"
    );
}

// ---- Sheriff (Algebra Integral), forkId 41 ----

/// Ground truth from the pool ITSELF at block 15,553,467, via
/// Read at Robinhood block 15553467 with lens/AlgebraQuoter.sol against the real
/// swap() and reverts inside the pay-in callback, so these numbers carry the
/// pool's own rounding and the plugin's per-side fee.
const SHERIFF_POOL: Address = address!("536a7b19abb933bf6319e0b8817e733bba166674");
const SHERIFF_SQRT: &str = "3486750530250146723596078";
const SHERIFF_TICK: i32 = -200_633;
const SHERIFF_LIQ: u128 = 44_570_035_503_772_396;
const SHERIFF_BASE_FEE: u32 = 400; // pool fee(); NEITHER side actually pays this
const SHERIFF_FACTOR_0TO1: &str = "72450222395686186940779491495";
const SHERIFF_FACTOR_1TO0: &str = "86006102632842488246308409177";
const SHERIFF_FEE_0TO1: u32 = 365;
const SHERIFF_FEE_1TO0: u32 = 434;

/// Initialized ticks from the prev/next linked list, ascending; the outer pair
/// are Algebra's MIN/MAX list sentinels.
const SHERIFF_TICKS: &[(i32, i128)] = &[
    (-887272, 0),
    (-887220, 7_864_133_510_800),
    (-203160, 1_213_456_170_163_605),
    (-203040, 785_741_267_161_065),
    (-202980, 42_109_160_608_166),
    (-202860, 58_556_694_514_326),
    (-202800, 31_465_185_964_751),
    (-202620, 4_541_843_838_879),
    (-202560, 36_047_613_867_712),
    (-202500, 219_670_053_032_062),
    (-202440, 6_707_409_938_630),
    (-202380, 21_319_400_190_800),
    (-202260, 45_679_033_398_236),
    (-202140, 3_006_136_168_625_031),
    (-202080, 383_574_766_688_671),
    (-202020, 4_013_193_215_636_142),
    (-201960, 27_373_228_182_579),
    (-201900, 3_217_928_095_710_315),
    (-201720, 526_473_309_471),
    (-201660, 4_646_556_381_642_402),
    (-201600, 82_138_894_406_588),
    (-201480, 2_858_457_172_112_935),
    (-201420, 68_910_799_814_546),
    (-201360, 212_070_786_623_908),
    (-201300, 21_486_775_873_322_761),
    (-201180, 3_176_413_248_581_103),
    (-201060, 1_592_444_231_920_215),
    (-201000, -21_319_400_190_800),
    (-200850, 122_395_237_965_310),
    (-200820, -45_679_033_398_236),
    (-200760, 781_087_569_909_435),
    (-200700, -3_385_596_939_590_994),
    (-200660, -122_395_237_965_310),
    (-200640, -4_113_995_722_708),
    (-200580, -3_193_032_174_889_719),
    (-200550, -781_087_569_909_435),
    (-200460, -68_009_214_198_190),
    (-200400, -4_541_843_838_879),
    (-200340, -21_486_775_873_322_761),
    (-200280, -991_355_319_753_500),
    (-200220, -4_648_188_764_204_297),
    (-200160, -3_368_367_124_111_601),
    (-200100, -201_153_326_448_177),
    (-200040, -475_643_232_163_439),
    (-199980, -6_133_409_785_882_599),
    (-199920, -212_070_786_623_908),
    (-199800, -304_920_095_909_841),
    (-199740, -28_996_701_990_975),
    (-199500, -209_459_036_626_362),
    (-199320, -1_592_444_231_920_215),
    (-198840, -42_109_160_608_166),
    (-198660, -785_741_267_161_065),
    (-198240, -29_944_711_105_409),
    (-198060, -4_921_149_593_058),
    (887220, -7_864_133_510_800),
    (887272, 0),
];

/// (amount_in, zero_for_one, amount_out, sqrt_price after)
const SHERIFF_VECTORS: &[(&str, bool, &str, &str)] = &[
    (
        "1000000000000000",
        true,
        "1936081",
        "3486747088651578505219674",
    ),
    (
        "10000000000000000",
        true,
        "19360641",
        "3486716114570194641362887",
    ),
    (
        "100000000000000000",
        true,
        "193589221",
        "3486406404020648813114121",
    ),
    (
        "1000000000000000000",
        true,
        "1934174229",
        "3483312516421795876768022",
    ),
    (
        "5000000000000000000",
        true,
        "9633269849",
        "3470036007257219440923664",
    ),
    (
        "1000000",
        false,
        "516093833781900",
        "3486752307089150700386864",
    ),
    (
        "10000000",
        false,
        "5160914667932808",
        "3486768298640186491503940",
    ),
    (
        "100000000",
        false,
        "51606779810117279",
        "3486928214150544402674704",
    ),
    (
        "1000000000",
        false,
        "515831230528161954",
        "3488527369254123514382340",
    ),
];

fn sheriff_pool(fee_0to1_ppm: u32, fee_1to0_ppm: u32) -> (V3Pool, V3State) {
    let pool = V3Pool {
        protocol: V3Protocol::SHERIFF,
        address: SHERIFF_POOL,
        token0: WETH,
        token1: USDG,
        fee_ppm: SHERIFF_BASE_FEE,
        tick_spacing: 10,
        verify_pool_spacing: false,
        // Algebra poolId 0 makes the Settler use the 2-word salt.
        execution: Some(V3ExecutionMeta {
            fork_id: sextant::chain::FORK_SHERIFF,
            pool_id: 0,
        }),
        v4: None,
        algebra: Some(AlgebraMeta {
            fee_0to1_ppm,
            fee_1to0_ppm,
        }),
    };
    let ticks: Vec<TickInfo> = SHERIFF_TICKS
        .iter()
        .map(|&(tick, net)| TickInfo {
            tick,
            liquidity_net: I256::try_from(net).unwrap(),
        })
        .collect();
    let pos = ticks.partition_point(|x| x.tick <= SHERIFF_TICK);
    let state = V3State {
        sqrt_price: SHERIFF_SQRT.parse().unwrap(),
        tick: SHERIFF_TICK,
        liquidity: U256::from(SHERIFF_LIQ),
        ticks: ticks.into(),
        pos,
        lo_cover: MIN_TICK,
        hi_cover: MAX_TICK,
    };
    (pool, state)
}

fn stored_factor_fee(base_ppm: u32, factor: &str) -> u32 {
    let factor: U256 = factor.parse().unwrap();
    u32::try_from((U256::from(base_ppm) * factor) >> 96usize).unwrap()
}

#[test]
fn sheriff_stored_fee_factors_preserve_the_symmetric_invariant() {
    let f0 = SHERIFF_FACTOR_0TO1.parse::<U256>().unwrap();
    let f1 = SHERIFF_FACTOR_1TO0.parse::<U256>().unwrap();
    // The two Q96 factors are a symmetric split: they sum to exactly 2·2^96.
    assert_eq!(f0 + f1, U256::ONE << 97usize);
    // At this pinned block the stored factors happen to quantize to the same
    // fees beforeSwap returns. That is not generally true; the next test pins
    // a block where beforeSwap recalculates them across a ppm boundary.
    assert_eq!(
        stored_factor_fee(SHERIFF_BASE_FEE, SHERIFF_FACTOR_0TO1),
        SHERIFF_FEE_0TO1
    );
    assert_eq!(
        stored_factor_fee(SHERIFF_BASE_FEE, SHERIFF_FACTOR_1TO0),
        SHERIFF_FEE_1TO0
    );
}

#[test]
fn sheriff_sim_matches_the_pool_to_the_wei() {
    let (pool, state) = sheriff_pool(SHERIFF_FEE_0TO1, SHERIFF_FEE_1TO0);
    for &(amount_in, zero_for_one, out, sqrt_after) in SHERIFF_VECTORS {
        let amount_in: U256 = amount_in.parse().unwrap();
        let r = sim_v3(&pool, &state, zero_for_one, amount_in).unwrap();
        let dir = if zero_for_one { "0->1" } else { "1->0" };
        assert_eq!(
            r.consumed, amount_in,
            "{amount_in} {dir} partially consumed"
        );
        assert_eq!(
            r.amount_out,
            out.parse::<U256>().unwrap(),
            "{amount_in} {dir} amount_out"
        );
        // The post-swap price is the stronger assertion: it pins the whole tick
        // walk, not just the total.
        assert_eq!(
            r.sqrt_price,
            sqrt_after.parse::<U256>().unwrap(),
            "{amount_in} {dir} sqrt_price"
        );
    }
}

/// Quoting `fee()` to both sides — the obvious reading of an Algebra pool — is
/// wrong in BOTH directions, and wrong by far more than a rounding wobble.
/// This is the whole reason `AlgebraMeta` carries two fees.
#[test]
fn sheriff_base_fee_misquotes_both_directions() {
    let (pool, state) = sheriff_pool(SHERIFF_FEE_0TO1, SHERIFF_FEE_1TO0);
    let flat = V3Pool {
        algebra: Some(AlgebraMeta {
            fee_0to1_ppm: SHERIFF_BASE_FEE,
            fee_1to0_ppm: SHERIFF_BASE_FEE,
        }),
        ..pool.clone()
    };

    for &(amount_in, zero_for_one, out, _) in SHERIFF_VECTORS {
        let amount_in: U256 = amount_in.parse().unwrap();
        let truth: U256 = out.parse().unwrap();
        let got = sim_v3(&flat, &state, zero_for_one, amount_in)
            .unwrap()
            .amount_out;
        assert_ne!(got, truth, "base fee must not reproduce {amount_in}");
        // The base fee sits between the two sides, so it under-quotes the side
        // that pays less and over-quotes the side that pays more. Over-quoting
        // is the dangerous one: it would promise output the pool won't deliver.
        if zero_for_one {
            assert!(got < truth, "0->1 pays 365, base 400 must under-quote");
        } else {
            assert!(got > truth, "1->0 pays 434, base 400 must over-quote");
        }
    }
}

#[test]
fn sheriff_uses_before_swap_fee_not_stored_factors() {
    // Pool truth at block 15,633,596. Stored factors imply 366/433 ppm, but
    // beforeSwap first recalculates them and returns 367/432 ppm.
    let (pool, state) = (
        V3Pool {
            protocol: V3Protocol::SHERIFF,
            address: SHERIFF_POOL,
            token0: WETH,
            token1: USDG,
            fee_ppm: SHERIFF_BASE_FEE,
            tick_spacing: 10,
            verify_pool_spacing: false,
            execution: Some(V3ExecutionMeta {
                fork_id: sextant::chain::FORK_SHERIFF,
                pool_id: 0,
            }),
            v4: None,
            algebra: Some(AlgebraMeta {
                fee_0to1_ppm: 367,
                fee_1to0_ppm: 432,
            }),
        },
        V3State {
            sqrt_price: "3482455459334879050503501".parse().unwrap(),
            tick: -200_658,
            liquidity: U256::from(52_175_000_042_805_092u64),
            ticks: vec![
                TickInfo {
                    tick: -200_700,
                    liquidity_net: I256::try_from(-3_006_136_168_625_031i64).unwrap(),
                },
                TickInfo {
                    tick: -200_640,
                    liquidity_net: I256::try_from(-2_479_633_861_407_411i64).unwrap(),
                },
            ]
            .into(),
            pos: 1,
            lo_cover: MIN_TICK,
            hi_cover: MAX_TICK,
        },
    );
    let vectors = [
        (
            "1000000000000000",
            true,
            "1931310",
            "3482452526623541673344208",
        ),
        (
            "1000000",
            false,
            "517368736227211",
            "3482456977187028223217914",
        ),
    ];

    for (amount, zero_for_one, out, sqrt_after) in vectors {
        let amount: U256 = amount.parse().unwrap();
        let truth = sim_v3(&pool, &state, zero_for_one, amount).unwrap();
        assert_eq!(truth.amount_out, out.parse::<U256>().unwrap());
        assert_eq!(truth.sqrt_price, sqrt_after.parse::<U256>().unwrap());

        let stale = V3Pool {
            algebra: Some(AlgebraMeta {
                fee_0to1_ppm: 366,
                fee_1to0_ppm: 433,
            }),
            ..pool.clone()
        };
        let stale = sim_v3(&stale, &state, zero_for_one, amount).unwrap();
        assert_ne!(stale.amount_out, truth.amount_out);
        if zero_for_one {
            assert!(
                stale.amount_out > truth.amount_out,
                "stale fee must overquote 0->1"
            );
        }
    }

    assert!(
        sim_v3(
            &V3Pool {
                algebra: None,
                ..pool
            },
            &state,
            true,
            U256::ONE
        )
        .is_err()
    );
}

/// Algebra exposes no tick bitmap at all — the linked list is the only way to
/// learn where the initialized ticks are — so `sim_v3` must not invent word
/// boundaries from `tick_spacing`. On THIS pool the nearest word edge is ~1600
/// ticks past where even the largest pinned trade lands, so the two walks
/// happen to agree; the divergence needs ticks spaced more than one 256-slot
/// word apart, which is what this synthetic state builds.
#[test]
fn sheriff_linked_list_walk_skips_bitmap_word_edges() {
    let (pool, _) = sheriff_pool(3_000, 3_000);
    let l = pow10(18);
    // spacing 10 => one bitmap word spans 2560 ticks. A single position 40_000
    // ticks wide therefore hides ~15 word edges the v3 walk would stop at.
    let ticks = vec![
        TickInfo {
            tick: -40_000,
            liquidity_net: I256::try_from(l).unwrap(),
        },
        TickInfo {
            tick: 40_000,
            liquidity_net: -I256::try_from(l).unwrap(),
        },
    ];
    let state = V3State {
        sqrt_price: U256::ONE << 96usize,
        tick: 0,
        liquidity: l,
        ticks: ticks.into(),
        pos: 1,
        lo_cover: MIN_TICK,
        hi_cover: MAX_TICK,
    };
    // Big enough to move the price several words, not just one: 0.5x the
    // liquidity halves sqrtP, i.e. ~13.8k ticks, past five word edges.
    let amount_in = pow10(18) / u(2);
    let walked = sim_v3(&pool, &state, true, amount_in).unwrap();
    let stepped = sim_v3(
        &V3Pool {
            protocol: V3Protocol::UNIV3,
            algebra: None,
            fee_ppm: 3_000,
            ..pool.clone()
        },
        &state,
        true,
        amount_in,
    )
    .unwrap();

    assert_eq!(walked.consumed, amount_in);
    assert_eq!(stepped.consumed, amount_in);
    // Same fee on both (3000 either side), so any gap is the extra steps alone:
    // each word-edge computeSwapStep rounds the output down again.
    assert!(
        stepped.amount_out < walked.amount_out,
        "word-edge stops must lose value: bitmap {} vs linked list {}",
        stepped.amount_out,
        walked.amount_out
    );
}

/// `bps` in the proportional unit Robinhood's Settler build reads.
fn robinhood_proportion(bps: u32) -> U256 {
    sextant::settler::settler_proportion(
        sextant::chain::ROBINHOOD_PROFILE
            .settler
            .expect("Robinhood Settler")
            .encoding,
        bps,
    )
}
