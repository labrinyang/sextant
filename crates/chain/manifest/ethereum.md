# Ethereum (`SOLVER_CHAIN=ethereum`)

The profile is `crates/chain/manifest/ethereum.json`. Every value in it was
read from the chain or simulated against it on 2026-11-06 (block 26,354,121),
read-only. Nothing was deployed, and no source was verified or published.

## Venues

The venues' own factories name a pair's pools (`discovery.kind: factories`).
Each V3 venue is asked at every fee tier its factory has enabled, read with
`feeAmountTickSpacing`:

| Venue | Factory | Fee tiers (ppm) |
| --- | --- | --- |
| `univ2` | `0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f` | 3000 |
| `sushiv2` | `0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac` | 3000 |
| `univ3` | `0x1F98431c8aD98523631AE4a59f267346ea31F984` | 100, 500, 3000, 10000 |
| `sushiv3` | `0xbACEB8eC6b9355Dfc0269C18bac9d6E2Bdc29C4F` | 100, 500, 3000, 10000 |
| `pancakev3` | `0x0BFbCF9fa4f9C56B0F40a671Ad40E0805A091865` | 100, 500, 2500, 10000 |

Uniswap V4 is left out: a singleton's pools cannot be named by a factory, so
quoting it needs an indexer. Ekubo on Ethereum is not wired either: Sextant
discovers Ekubo pools through Robinhood's API topology only.

Factories answer only for the pairs they are asked about, so routes pass
through the profile's connectors (WETH, USDC, USDT) and nothing else
(`SOLVER_DYNAMIC_CONNECTORS=profile_only`).

## Settler

- **The build.** The registry's `ownerOf(2)` was
  `0xaddc26a3854feabfd20d6bf658254088d83a425a`. Its runtime hash is
  `0xffdce601…3623ff34` (`runtime.exact`). AllowanceHolder's runtime hash
  equals BSC's.
- **Units.** A `BASIC` action selling 10,000 units of a 1,000,000-wei ETH
  balance left exactly 990,000 wei behind. One wei more as the minimum
  reverted with `TooMuchSlippage`. The build therefore reads parts per
  million, so its encoding is `ppmVipPathFromPermit`.
- **Fork table.** 0.1 WETH was sold for USDC through `UNISWAPV3` with fork
  ids 0, 1 and 2, under a balance override:
  - fork 0 (`univ3`) swapped at the 500 and 3000 tiers;
  - fork 1 (`pancakev3`, through deployer `0x41ff9AA7…71c9`) swapped at 500,
    and correctly refused 3000, a tier PancakeSwap does not have;
  - fork 2 (`sushiv3`, with Uniswap's init hash) swapped at 500 and 3000;
  - fork 7 reverted, as an unknown fork should.

  The ids match `src/chains/Mainnet/Common.sol` in 0x-settler.
- **Native RFQ.** The build has no `executeWithNativeAuthorization`, so Native
  is off.

## Checked live

On the same day, against `ethereum-rpc.publicnode.com`:

- `/health` reported the chain and its Settler verified.
- 5 WETH → USDC routed over 6 legs with a certified gap of 0.04 bp across
  33 pools.
- 1 ETH → USDC and 2 ETH → USDT were built and simulated at the head
  (`status: simulated`, about 600k gas).

The Lens reads deep pools here: Uniswap's USDC/WETH 0.05% pool holds about
1,500 initialized ticks in the default window. Lens calls are therefore given
gas planned from each pool's measured depth, from 16M up to a 48M ceiling
(`src/lens.rs`).

A pull from this machine to the public RPC took about 2.5 s, longer than the
2 s a snapshot may age. That run used a local build with a longer limit. In
production, give the solver an RPC close to it (`SOLVER_RPC`).
