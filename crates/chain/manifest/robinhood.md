# Robinhood (`SOLVER_CHAIN=robinhood`)

## Settler build (re-read 2026-11-06)

The registry's `ownerOf(2)` is now `0xE8852602f84e04e284286d8Db01a41Edd0CCEFb0`
(runtime `0xed954056…d756`). It replaced the bps build the profile was first
reviewed against. All of the following was read-only:

- **Units.** A `BASIC` action selling 10,000 units of a 1,000,000-wei balance
  left 990,000 behind. The build reads ppm, so its encoding is
  `ppmVipPathFromPermit`.
- **Fork table.** Every fork id Sextant routes through dispatches: 0 (Uniswap
  V3), 1 (PancakeSwap V3), 2 (Sushi V3), 40 (Up33 CL), 41 (Sheriff),
  42 (SwapHood V3), 43 (RobinSwap V3) and 45 (GigaDex V3). Fork 7 is unknown.
  The deployers, factories and init hashes in `crates/chain/src/chain.rs`
  equal upstream 0x-settler's `src/chains/RobinHood/Common.sol`.
- **Uniswap V4 and Ekubo.** `UNISWAPV4` names its fork (Uniswap V4 is fork 0;
  `univ4ForkId: 0`), and `EKUBOV3` still dispatches, so the build is listed in
  `ekuboV3Runtimes`.
- **Runtime policy.** The profile pinned this chain's Settler with
  `compatible`, which accepts any runtime on the premise that core actions
  stay stable across rotations. The ppm migration broke that premise: a
  compatible profile would have kept encoding bps for a ppm build. The profile
  now pins the build exactly, as BSC and Ethereum do. The next rotation stops
  the solver at startup instead of letting it build transactions that revert.

Checked live on the same day: 1 WETH → USDG routed over 8 legs, and 0.2 ETH →
USDG was built and simulated at the head (`status: simulated`).
