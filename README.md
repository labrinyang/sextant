# Sextant

[![ci](https://github.com/labrinyang/sextant/actions/workflows/ci.yml/badge.svg)](https://github.com/labrinyang/sextant/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![rust](https://img.shields.io/badge/rust-1.94.1%2B-orange.svg)](#tests)

Sextant quotes and builds exact-input swaps for the 0x Settler, entered through
AllowanceHolder. It searches exact integer models of every venue, splits a
trade across pools, bounds how far the result can be from the best split (the
duality-gap certificate), and simulates each transaction at the chain head
before offering it.

![How a Sextant quote works: WETH is split across six venues over paths of one to three hops through USDT and DAI, converging into USDC, then certified and settled in one transaction](assets/sextant.gif)

*Illustrative: one WETH quote whose six legs take one to three hops through
two connector tokens. The real work is integer arithmetic over one block's
pool state.*

> Early software. The quote path is end to end, but this is not yet the
> production solver, and nothing here is a price or uptime guarantee.

## Why the result can be trusted

- **Exact, not approximate.** Each venue is an integer model of its contract's
  math — ticks, liquidity and fees for concentrated liquidity, reserves for
  constant product — evaluated at one canonical block. The same code prices the
  trade and checks the transaction.
- **Split where it pays.** The search allocates the trade across pools; it is
  a routing problem, not a single best pool.
- **Bounded.** A duality-gap certificate says how far the returned split can be
  from the best allocation over the same pool graph, and is returned with every
  quote.
- **Checked before offered.** The built transaction is simulated at the chain
  head; a revert or a missing balance/allowance is reported instead of a
  transaction that would fail.

## Quick start

```sh
cp .env.example .env          # SOLVER_CHAIN and SOLVER_RPC are required
set -a; . ./.env; set +a      # the binary reads the process environment, not the file
cargo run --release --locked --bin sextant
```

Or run it under Docker Compose, which reads the env file for you:
`docker compose -f deploy/docker-compose.yml --profile ethereum up -d --build`.

It listens on `SOLVER_PORT` (8899) on all interfaces. Ask for a quote with the
addresses of the chain you configured:

```sh
curl -s localhost:8899/quote -H 'content-type: application/json' -d '{
  "chainId": 1,
  "tokenIn":  "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
  "tokenOut": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "amountIn": "100000000000000000",
  "slippageBps": 50
}'
```

Without `recipient` the answer is a quote; with it, the response carries the
transaction (`tx`), the approval to send first (`approval`) and the simulation
result. The routes are unauthenticated: keep the listener on a private network.

One process serves one chain, named by `SOLVER_CHAIN`:

| `SOLVER_CHAIN` | Chain | Pool discovery | Venues |
| --- | --- | --- | --- |
| `ethereum` | Ethereum (1) | the venues' factories, at each enabled fee tier | Uniswap V2/V3, Sushi V2/V3, PancakeSwap V3 |
| `bsc` | BNB Smart Chain (56) | topology indexer (`SOLVER_INDEXER_URL`) | Uniswap V2/V3/V4, PancakeSwap V2/V3 |
| `robinhood` | Robinhood Chain | factories and their events (`SOLVER_LOGS_RPC`) | Uniswap V2/V3/V4, Ekubo V3, Up33 V2/CL, and the V3 forks compiled in `crates/amm/src/venue.rs` |

There is no default chain. A chain is a manifest,
`crates/chain/manifest/<chain>.json`. It holds the contracts, venues,
connectors and the Settler build that chain executes through, each checked
against the chain at startup. `crates/chain/manifest/<chain>.md` records how
every value was read. Adding a chain whose venues use an existing pool family
and discovery kind means adding a manifest, not code.

Native RFQ is a capability a chain has only with a Settler build that carries
`executeWithNativeAuthorization` (see [crates/rfq/README.md](crates/rfq/README.md)).

## Layout

A Cargo workspace. Each crate depends only on those above it:

| Crate | What it holds |
| --- | --- |
| `sextant-budget` | the solver budget: one quote's cooperative deadline and its cancellation |
| `sextant-amm` | venue ids, exact V2/V3/V4 and Ekubo math, the block snapshot, depth ladders, the plan model. No I/O. |
| `sextant-chain` | manifests, chain and Settler profiles, venue catalogs |
| `sextant-route` | route universes, split routing, the duality-gap certificate, counterfactual coverage |
| `sextant-io` | the JSON-RPC client, its dispatch admission, work budgets, ABI |
| `sextant-discovery` | the indexer client, the QuoteLens encoder, Ekubo pool reads |
| `sextant-rfq` | Native RFQ: firm quotes, validation, beneficiary authorization, the quota coordinator |
| `sextant-exec` | plans into Settler transactions, and their simulation |
| `sextant-observe` | the panic hook and the log subscriber |
| `sextant` (root) | state reads, the resident state, the engine, quotes, the server |

The root crate re-exports every module at its old path (`sextant::route`,
`sextant::settler`, …). `sextant::chain` is the chain crate's own `chain`
module, and the process `Config` lives at `sextant::config::Config`.

## How a quote is made

1. **Snapshot.** A pair the resident pool state covers is quoted from memory,
   with no RPC of its own (see below). Any other pair, or one the resident
   state covers but cannot route, takes the per-pair path: the pools of the
   pair and its connectors come from the chain's discovery and are read at one
   canonical block, pinned by hash (EIP-1898), in one Lens `eth_call` with a
   state override. Every pool is proved before it is used: its factory names
   it, and a V3 pool must sit where the Settler's CREATE2 puts it. Which pools
   a pair has is kept for `SOLVER_TOPO_TTL` (600 s); their state is read anew
   for every snapshot. A pair being quoted is refreshed so that its snapshot is
   replaced at about 1.5 s of age; a snapshot older than 2 s is pulled again.
   `meta.source` says which: `resident`, `memory` or `pull`.
2. **Search.** Exact integer models of every venue, with splits across pools.
   A leg may take up to three hops through a connector token (`MAX_ROUTE_HOPS`).
   Nothing is replayed in an EVM while searching. A resident quote may widen
   its graph and search again (see "Which connectors a quote routes").
3. **Build**, when the request names a `recipient`. ERC-20 input goes through
   `AllowanceHolder.exec`, the native coin straight to the Settler. Each
   token's last use spends 100% of what is left, unused intermediate tokens are
   refunded, native output is unwrapped, and the final check enforces the
   minimum.
4. **Check**, at the chain head (never older than the snapshot): one round trip
   for the head, then one for everything else. The taker's balance and
   allowance, `eth_call` and `eth_estimateGas` of the transaction and the gas
   price go out together. When the balance or allowance is short, the response
   says which (`simulation.status: "skipped"`, `reason: "balance"` before
   `"allowance"`), names the exact approval and ignores the call. A transaction
   that reverts is not offered. When it reverts at a later block than it was
   priced on, the quote is priced once more from that block (AMM routes only).

The response carries `tx` (`to`, `value`, `data`), `allowanceHolder`,
`approval`, `simulation` (`block`, `blockHash`, `gasEstimate`), `issues`,
`entrypoint`, `deadline` and `authorizationDeadline` (Native only). Gas and
fees are for display: the wallet sets its own.

## The certificate

It measures; it gates nothing. Its gap is logged and returned with each quote,
and a gap above 0.1 bp re-solves the quote once at 1,024 chunks with a 10 bp
floor. The bound counts any arbitrage among the graph's pools, which no path
plan trades, so on thin tokens a large gap says little about the quote. Ekubo
pools have no certificate model yet.

The bound walks every pool from its price until trading stops paying at the
dual prices, and its search asks that again at many nearby prices on one
block. A walk's ranges and curve amounts do not depend on the prices, so each
state keeps them as a depth ladder, built as deep as a walk has needed and
shared by every clone of the snapshot. Later walks are binary searches over it.
Trial points the search would reject stop as soon as their bound is certain to
reach the best so far. `examples/route_profile.rs` prints warm and cold timings.

## Resident pool state

Off unless `SOLVER_RESIDENT=on`, and only on a chain with a venue table (`bsc`,
`ethereum`). The solver keeps every listed pool's state in memory and brings it
to each new block (`src/resident.rs`).

- **The list.** `SOLVER_RESIDENT_POOL_LIST_URL` serves a JSON array of pools,
  each `{"protocol", "address", "token0", "token1", "feePpm"}` with `protocol`
  a venue id from the chain's table (on BSC `univ2`, `univ3`, `pancakev2`,
  `pancakev3`). It is fetched every 10 minutes and read whole or refused whole.
  A pool new to it is proved exactly as the per-pair path's pools are; one that
  fails is left out with its reason, one no longer listed leaves, and when the
  list cannot be read the last one stays. A new pool has state from the next
  block.
- **Each block.** The head is checked every `SOLVER_RESIDENT_POLL_MS` (1,000).
  A new block's state is pinned to its hash and published only complete and
  only when newer than the published block. A head check that finds the
  published block still the head keeps it fresh.
- **Only what moved is read.** A Uniswap V2 pair moves its reserves only with
  `Sync`; a Uniswap V3 pool (or PancakeSwap's, whose `Swap` differs) moves its
  price, liquidity or ticks only with `Initialize`, `Swap`, `Mint` or `Burn`.
  For each block since the last read, the reader asks `eth_getLogs` by the
  block's hash and those events, all blocks in one JSON-RPC batch, and re-reads
  only the pools that emitted one. Every other pool keeps its state, with its
  cached tick prices and depth ladders. The blocks must link parent to child
  from the last read to the head (their headers come in one more batch), or
  every pool is read, as it is after a gap of more than 32 blocks, a failed log
  read, and at least every `SOLVER_RESIDENT_FULL_READ_MS` (60,000). `0` reads
  every block whole and asks for no logs. A venue not known to run that code is
  read at every block (`src/resident/carry.rs`).
- **The carry is audited.** A whole read that follows linked blocks checks
  every pool that emitted nothing against the state it would have carried.
  `/health` (`resident.carry`) and `/metrics` count the reads of each kind, the
  pools checked and any that drifted, and a drift is logged with the pools'
  addresses. `examples/resident_watch.rs` runs the reader alone against a chain
  and prints these counts.
- **A quote.** A pair is served when both its tokens trade in the published
  state, the state was confirmed at the head within 2 s, and some skeleton has
  a pool on every edge. A quote that must price from a later block waits up to
  3 s for it. A pair the state covers but cannot route is asked again of the
  per-pair path.
- **Connectors.** Every route may pass through the chain's connectors. It may
  also pass through `SOLVER_RESIDENT_CONNECTORS` (comma-separated addresses)
  where those tokens have pools on the list: next to an endpoint they have a
  pool with, then to the other endpoint, a static connector or another resident
  connector, three hops at most. The per-pair path takes these skeletons from
  the list too.
- **Which connectors a quote routes.** A quote starts from the static
  connectors' skeletons. After each solve, every candidate skeleton it does not
  route is probed (`resident::Widening`): its smallest leg is sold down the
  candidate through the best pool on each edge, with the pools the plan traded
  in the state the plan left them. Output is concave in input, so the
  candidate's edge over the best routed skeleton, times the quote, bounds what
  admitting it could add. A candidate whose bound is at least 0.1 bp has its
  connectors admitted and the pair is solved again on the same block's state;
  at most three rounds, and a round that does not improve the quote ends it.
  Nothing is remembered between quotes, so the same request at the same block
  widens the same way. The log line reports `widening_candidates`, `widened`,
  `widening_rounds` and `widening_end`.
- **Thin pools are not crossed.** Every resident pool takes a routing liquidity
  test when it arrives and every 30 minutes (a pool that failed takes it again
  each block): it passes when $500 of its token bought and sold straight back
  loses under 30%, or when a $1,000 buy's unit price is within 20% of a $500
  buy's. The chain's stable token is the dollar; other tokens are priced
  through pools that already passed. A pool that fails is left out of a quote's
  graph unless it is the market of one of the quote's own tokens. When nothing
  routes without them, the thin pools on edges no other pool serves come back.
- **Cost.** Two requests per new block and one head check per poll, whatever
  the quote rate.

## Startup checks

- The Settler is the chain registry's `ownerOf(2)`; its runtime must match the
  reviewed hash (exactly, or with the deployment's immutables masked).
  AllowanceHolder must match its reviewed runtime hash.
- The RPC must report the profile's chain id.
- An indexer-backed chain's manifest may name only the venues and schema
  version its wire carries; a venue id without a compiled core is refused.
- With Native on, the chain's Settler build must have the Native authorization
  entry, and the authorization key's address must equal the Settler's
  `nativeAuthorizationSigner`.

## HTTP

`POST /quote` takes `chainId`, `tokenIn`, `tokenOut` (the native coin is
`0xeeee…eeee`), `amountIn`, `slippageBps`, `recipient` and `deadlineSeconds`.
`SOLVER_MAX_INFLIGHT_QUOTES` (8) quotes run at once; with every slot busy a
quote waits in arrival order for up to `SOLVER_QUOTE_ADMISSION_WAIT_MS` (1,000),
two waiting per slot at most. `x-quote-timeout-ms` shortens
`SOLVER_QUOTE_TIMEOUT` for that quote. It answers 200; 400 for a bad request;
422 for no route or a transaction that reverts; 503 with `Retry-After` when the
RPC or quote capacity is full; 502 when the RPC fails; 504 when the quote runs
out of time.

`GET /health` reports readiness, the verified Settler and AllowanceHolder, the
resident state, RPC dispatch use and per-outcome quote counts and timings.
`GET /metrics` serves the same in Prometheus text. None of these routes is
authenticated: keep the listener on a private network.

## RPC dispatch

Every RPC request takes a dispatch slot (`SOLVER_RPC_MAX_DISPATCHES`, 32) and a
share of the per-second rate (`SOLVER_RPC_DISPATCH_RPS`, 256), waiting up to
`SOLVER_RPC_ADMISSION_WAIT_MS` (2,000) before the quote gets 503. A request
whose outcome is unknown keeps its slot for
`SOLVER_RPC_UNCERTAIN_RELEASE_SECS` (60); `POST /rpc-recovery`, with its own
token (`SOLVER_RPC_RECOVERY_TOKEN`), releases that debt once the provider has
confirmed every unknown request ended.

## Configuration

Start from `.env.example`. Logs go to stdout, one line per event:
`SOLVER_LOG_FORMAT` is `compact` (default) or `json`. A panic anywhere, a
background task included, ends the process. Native settings and the
cross-instance quota coordinator are in [crates/rfq/README.md](crates/rfq/README.md).

## Tests

```sh
cargo test --workspace --locked
cargo test --examples --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The suite builds and runs on Linux and macOS; CI runs these commands plus `cargo
fmt --check` and a feature-free clippy of each crate's library. The routing
golden (`amount_out=994246489566748118282`) is pinned in `examples/route_profile.rs`
and in the release benchmark the workflow runs.

Contract source is never verified or published on an explorer from this
repository; comparing deployed bytecode with a local build uploads nothing.

## License

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE), and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
for code derived from other projects.

## Security

Report a vulnerability privately as described in [SECURITY.md](SECURITY.md).
