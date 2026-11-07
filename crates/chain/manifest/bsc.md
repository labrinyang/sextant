# BSC

## Dynamic connector allowlist

`manifest/bsc.json` `routing.dynamicConnectorAllowlist`.

Tokens a BSC dynamic connector may be — reviewed 2026-08-06.

Rebuild with `scripts/connector_allowlist.py`, which reads the indexer's own
ranking for a sample of live pairs and prices every candidate it offers
against GeckoTerminal. The rule, applied to that table:

  market cap ≥ $50M, or no market cap at all with fully-diluted ≥ $50M and
  ≥ $1M of 24h volume, and present in CoinGecko's Binance Smart Chain
  token registry.

The second clause is for wrappers: BTCB is $4.2B of bridged BTC with no
circulating supply of its own, so it reports no market cap and a market-cap
gate would refuse it outright. It applies only where the strong signal is
missing entirely, because a market cap rests on supply CoinGecko curates
while FDV is price times an arbitrary total supply and volume can be traded
against oneself. The registry clause is weak on its own — it removed 6 of
the 74 candidates sampled — so it stands as a second opinion.

What the rule declined, in the depth range where the ranking would actually
have picked it: CMC20 ($1.34M of measured bottleneck depth against a $6.2M
cap), QYTB ($206k of depth, absent from the registry, $525k FDV, $9.5k of
daily volume), quq, DAO, Moolah, VIN. Two shapes worth naming because a
depth-only gate cannot see either: COSA carries $178M of pool reserve
against a $4.6M cap, and spyb trades $37M a day on a $10.9M cap.

These 27 were drawn from a sample that asked the ranking for 12 candidates
a pair. The solver asks for 32 (`indexer::RANKED_CONNECTOR_CANDIDATES`), and
over that wider set the same rule admits ten more — WLFI, AAVE, ZRO,
PENDLE, 1INCH, UUSD, RIVER and the meme tokens 币安人生, COCO and SPCXB.
Being short costs only reach: a refused candidate no longer takes a
shortlist slot with it (`indexer::permitted_connector`), so the budget fills
from whatever this list does permit.

Ordered by market cap so a diff reads as a ranking rather than as a set.

| Token | Name | Market cap | Address |
| --- | --- | --- | --- |
| USDT | Tether USD | $9.16B | `0x55d398326f99059ff775485246999027b3197955` |
| WBTC | Wrapped BTC | $7.49B | `0x0555e30da8f98308edb960aa94c0db47230d2b9c` |
| LINK | ChainLink Token | $6.12B | `0xf8a0bf9cf54bb92f17374d9e9a321e6a111a51bd` |
| BTCB | BTCB Token | fdv $4.21B | `0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c` |
| USD1 | World Liberty Fin. | $3.99B | `0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d` |
| UNI | Uniswap | $2.51B | `0xbf5140a22578168fd562dccf235e5d43a02ce9b1` |
| ASTER | Aster | $1.62B | `0x000ae314e2a2172a039b26378814c252734f556a` |
| USDC | USD Coin | $1.59B | `0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d` |
| U | United Stables | $1.23B | `0xce24439f2d9c6a2289f741120fe202248b666666` |
| PEPE | Pepe | $1.18B | `0x25d887ce7a35172c62febfd67a1856f20faebb00` |
| WBNB | Wrapped BNB | $1.04B | `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c` |
| ETH | Ethereum Token | $960M | `0x2170ed0880ac9a755fd29b2688956bd959f933f8` |
| STABLE | STABLE | $817M | `0x011ebe7d75e2c9d1e0bd0be0bef5c36f0a90075f` |
| INJ | Injective Protocol | $466M | `0xa2b726b1145a4773f68593cf171187d8ebe4d495` |
| CAKE | PancakeSwap Token | $452M | `0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82` |
| FDUSD | First Digital USD | $351M | `0xc5f0f7b66764f6ec8c8dff7ba683102295e16409` |
| XRP | XRP Token | $342M | `0x1d2f0da169ceb9fc7b3144628db156f3f6c60dbe` |
| BUSD | BUSD Token | $282M | `0xe9e7cea3dedca5984780bafc599bd69add087d56` |
| DOGE | Dogecoin | $179M | `0xba2ae424d960c26247dd6c32edc70b295c744c43` |
| TWT | Trust Wallet | $157M | `0x4b0f1812e5df2a09796481ff14017e6005508003` |
| XAUt | Tether Gold | $115M | `0x21caef8a43163eea865baee23b9c2e327696a3bf` |
| GMT | GoMining Token | $115M | `0x7ddc52c4de30e94be3a6a0a2b259b2850f421989` |
| ZEC | Zcash Token | $108M | `0x1ba42e5193dfa8b03d15dd1b86a3113bbbef8eeb` |
| ADA | Cardano Token | $87M | `0x3ee2200efb3400fabb9aacf31297cbdd1d435d47` |
| FORM | FORM Token | $83M | `0x5b73a93b4e5e4f1fd27d8b3f8c97d69908b5e284` |
| SOL | SOLANA | $81M | `0x570a5d26f7765ecb712c0924e4de545b89fd43df` |
| XAUM | Matrixdock Gold | $69M | `0x23ae4fd8e7844cdbc97775496ebd0e8248656028` |

## Settler build (re-read 2026-11-06)

The registry rotated BSC's Settler (`ownerOf(2)`) away from the build this
profile was first reviewed against (`0x3cd0eb6c…`, bps units). The profile
now pins the current one, `0xd52E8e422A352ac1AfDC2bd6EC533D41B20ACB7b`
(runtime `0x5bea8bbc…a16d`). All of the following was read-only:

- **Units.** A `BASIC` action selling 10,000 units of a 1,000,000-wei
  balance left 990,000 behind. The build reads ppm, so its encoding is
  `ppmVipPathFromPermit`.
- **Fork table.** It is unchanged: fork 0 is Uniswap V3 (100, 500 and 3000
  swapped) and fork 1 is PancakeSwap V3 (100, 500 and 2500 swapped). Fork 7
  is unknown.
- **Uniswap V4.** `UNISWAPV4` now names its fork: selector `0x68f5ee25`,
  with a `uint8 forkId` after `ppm`. The old selector `0xaf72634f` is refused
  with `ActionInvalid`. Uniswap V4 is fork 0, and forks 1 and 9 are unknown
  (`univ4ForkId: 0`).
- **Smoke test.** `examples/bsc_execution_smoke.rs` runs native-BNB swaps
  through Uniswap V2, Pancake V2, Uniswap V3, Pancake V3 and Uniswap V4 with
  the production encoder, and each is executable at the head.
