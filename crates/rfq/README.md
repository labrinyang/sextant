# Native RFQ

Native is one more source for a quote: at most one Native stage per
transaction, alone or beside one AMM stage (Native only, AMM then Native, or
Native then AMM). The transaction is the same 0x Settler transaction as an AMM
route, entered through AllowanceHolder, with one difference: it calls
`executeWithNativeAuthorization` instead of `execute`.

Native needs two things from the chain's profile (`crates/chain/src/chain.rs`): a
`NativeRfqProfile` (the reviewed Router, pool and stock tokens) and a Settler
build whose `SettlerProfile::native_authorization_typehash` names the
authorization type its `executeWithNativeAuthorization` recovers. The reviewed
upstream 0x Settler builds on BSC and Robinhood have no such entry, so
enabling Native there stops the solver at startup; it opens on a chain only
with a Native-capable Settler build reviewed into its profile. A quote
considers Native only when one end of the request is a reviewed stock token.

## How a Native quote is made

1. The public orderbook prices every feasible Native placement from one cached
   observation. It is indicative and costs no firm quote.
2. Only the best placement asks Native for a firm quote, after the AMM solve,
   so the quote's lifetime is not spent on it. A firm quote is never used as a
   probe: one final quote spends at most one. Native-first routes solve their
   AMM suffix again from the firm output.
3. The firm quote is checked before it is used: Router v6 calldata of the
   reviewed pool, the Settler as recipient and payer, the request's tokens and
   input, a nonzero minimum no larger than the output, no multihop, no widget
   fee, a canonical signature that recovers the declared signer, and a
   deadline inside the requested window.
4. The Settler's `BASIC` action calls the Native Router with Native's calldata
   byte for byte. It writes the Settler's live input balance only at the
   validated `actualSellerAmount` offset. The zero `actualMinOutputAmount`
   stays, so the Router scales Native's own minimum by the input actually
   sold; `AllowedSlippage` remains the whole transaction's minimum.
5. The solver signs the build's authorization type over `(chainId, settler,
   taker, beneficiary, executionHash, deadline)` (the recorded vectors use
   `MorphNativeAuthorizationV1`, the type of the first such build), where `executionHash` is the hash of
   the signature-free `execute(...)` calldata, so the authorization commits the
   complete action list. The Settler recovers it against its
   `nativeAuthorizationSigner()`.

The transaction's deadline is the earlier of the request's (two minutes from
the backend) and Native's. A firm quote must have
`SOLVER_NATIVE_RFQ_MIN_TTL_SECONDS` left, by chain time, both when it is
checked and when the transaction is encoded; otherwise the quote falls back to
AMM. The backend asks the app to quote again 30 s before a deadline, so the
default of 45 s leaves every Native quote it is offered at least 15 s to be
signed.

## Service configuration

```dotenv
SOLVER_NATIVE_RFQ_ENABLED=true
SOLVER_NATIVE_RFQ_URL=https://v2.api.native.org/swap-api-v2/
SOLVER_NATIVE_RFQ_API_KEY=
SOLVER_NATIVE_BENEFICIARY_SIGNING_KEY=
SOLVER_NATIVE_RFQ_TIMEOUT_MS=1500
SOLVER_NATIVE_RFQ_EXPIRY_SECONDS=60
SOLVER_NATIVE_RFQ_MIN_TTL_SECONDS=45
SOLVER_NATIVE_RFQ_QPS=4
SOLVER_NATIVE_RFQ_QUEUE_WAIT_MS=1000
SOLVER_NATIVE_RFQ_MAX_INFLIGHT=8
```

| Setting | Default and effect |
| --- | --- |
| `SOLVER_NATIVE_RFQ_EXPIRY_SECONDS` | `60`, valid `15..=120` (Native's own cap is 120). The lifetime asked of Native, never longer than the request's deadline. |
| `SOLVER_NATIVE_RFQ_MIN_TTL_SECONDS` | `45`; must be above 0 and below the expiry. Keep it above the backend's 30 s re-quote margin. |
| `SOLVER_NATIVE_BENEFICIARY_SIGNING_KEY` | Required when Native is enabled. Its address must be the Settler's `nativeAuthorizationSigner()`. |

Supply the API key and the signing key through the private runtime
environment. At startup the solver reads, at one block, the Native Router,
pool and CreditVault code hashes, their revision and wiring, WETH, the pool's
EIP-712 domain and the Settler's `nativeAuthorizationSigner()`, and refuses to
start on any mismatch. This document supplies no production addresses or keys.

Quote discovery and firm quotes share one Native client per process: the
public book and token metadata caches, the pacing and the in-flight limit.
A missing token's decimals stay missing after a transport failure, so a later
request can retry; a cached negative result stays cached.

## Cross-instance Native quota

Leave `SOLVER_NATIVE_QUOTA_COORDINATOR_URL` unset for the default process mode.
Multi-instance mode uses one authoritative solver server for a Native API
credential scope. Every instance using that credential, including the authority
host itself, must point to that same server:

```dotenv
# All instances, including the authority host. Use an HTTPS origin reachable
# from every instance; HTTP is accepted only on loopback.
SOLVER_NATIVE_QUOTA_COORDINATOR_URL=https://native-quota.example.internal
# Use the same private SOLVER_SERVICE_TOKEN on clients and authority.

# Exactly one authority host; keep false/unset on other workers.
SOLVER_NATIVE_QUOTA_COORDINATOR_ENABLED=true
SOLVER_NATIVE_QUOTA_LEASE_MS=120000
```

The example hostname is a placeholder. Configure TLS/reverse proxy routing for
the existing solver listener; Docker-network HTTP names are not accepted as
coordinator URLs. The URL must contain no user information, query or fragment.
The authority host rejects startup if its own Native client is still in process
mode. The authority's configured Native URL/API key must match the workers'
credential scope. Requests carry a scope digest, not the API key or firm payload.

| Setting | Default and effect |
| --- | --- |
| `SOLVER_NATIVE_QUOTA_COORDINATOR_URL` | Unset: process mode. Set: use the shared authority; an empty value is invalid. |
| `SOLVER_NATIVE_QUOTA_COORDINATOR_ENABLED` | `false`; `true` or `1` mounts authority endpoints on this server. |
| `SOLVER_NATIVE_QUOTA_LEASE_MS` | `120000` on the authority; valid `1000..=120000` and at least its Native queue wait. |
| `SOLVER_SERVICE_TOKEN` | Existing private service token, at least 32 bytes; shared bearer authentication. |
| `SOLVER_NATIVE_RFQ_QPS` | Authority's global outbound admission rate; default `4`, valid `1..=1000`. |
| `SOLVER_NATIVE_RFQ_MAX_INFLIGHT` | Authority's global active/queued firm-attempt ceiling; default `8`, valid `1..=128`. |
| `SOLVER_NATIVE_RFQ_QUEUE_WAIT_MS` | Authority's pacing wait, default `1000`, valid `1..=10000`; clients also apply their request deadline/wait. |

The authority exposes authenticated `POST /internal/native-quota/acquire`,
`POST /internal/native-quota/release` and `GET /internal/native-quota/health`.
It is compiled with this crate's `authority` feature, which the `sextant`
binary enables; a crate that needs only the client (Settler encoding does)
builds without it, and without an HTTP server.
Client requests cannot raise its ceilings. Orderbook and firm HTTP dispatches
share pacing; book discovery does not consume firm capacity. Firm capacity stays
leased through validation, and physical Native calls are bounded by the remaining
lease lifetime and Native HTTP timeout. This does not coordinate chain RPC quota;
`SOLVER_RPC_QUOTA_GROUP` remains process-scoped.

Deploy one authority per credential scope, without active-active replicas or
load balancing across independent authorities. State is in memory. Every startup
waits one configured lease lifetime before granting new work, including first
startup, so old client leases have time to expire after a restart. Health exposes
`restartQuietMs`; the default quiet period is 120 seconds. Clients do not fall
back to independent local quota when the authority is unavailable.

Release handles cancellation and bounded cleanup; crashed clients recover capacity
through expiry. There are at most 256 active/queued leases and 1024 cancellation
tombstones. Normal completed releases do not accumulate tombstones. Cancellation
overflow temporarily stops fresh grants for a lease lifetime instead of forgetting
a possible queued cancellation. Expiry bounds client attempts; it cannot prove
that a timed-out request has stopped executing inside Native. Pacing controls
dispatch admission times, not exact provider arrival times after network jitter.

Work accounting distinguishes actual provider dispatch and observed response
bytes from logical fact consumption and encoded local calldata. Cache hits and
singleflight followers do not create another physical RPC charge. Rejected and
cancelled work remains visible; firm quotes share the request's existing work
limits.

Coordination is charged to the same request: acquire/release HTTP attempts add
to `rpc_calls`, serialized coordination request/response bodies add to `rpc_bytes`,
and encode/decode plus reported authority state sections add to `compute_ns`.
Headers and wire framing are excluded. Queue wait consumes the wall deadline,
not CPU time. A bounded release allowance is withheld from optional work, and
cleanup after cancellation retains the original counters. Handler sections and
admitted-worker occupancy are not a measurement of total platform CPU; include
the authority process and HTTP stack when measuring total resource cost.

## Memory admission and health

Process RSS is sampled every 250 ms on Linux and macOS. Admission stays off
unless `SOLVER_RSS_ADMISSION_BYTES` is a positive byte threshold. When it is on,
a new quote needs room for the sampled RSS, outstanding reservations and its
estimated headroom; a missing sample, or one older than two seconds, rejects
new work without stopping work in flight.

```dotenv
# Optional: a threshold below the container's memory limit. Leave unset to
# disable RSS admission; an empty value is invalid.
# SOLVER_RSS_ADMISSION_BYTES=201326592
SOLVER_REQUEST_MEMORY_RESERVE_BYTES=33554432
```

The reserve defaults to 32 MiB. It is an estimate, not an allocation bound, and
the threshold is not a hard RSS cap; the container limit remains the limit.

`/health` reports `processMemory` (RSS, sample age, threshold, estimated
headroom, outstanding reservations, admitted and rejected counts) and, under
`capabilities.nativeRfq`, whether Native is supported and configured, its
QPS, queue wait, in-flight limit and quota scope. `quotes` counts quote
outcomes and timings; `/metrics` serves the same in Prometheus text.

## Tests

```sh
cargo test --locked --lib rfq
cargo test --locked --lib composed_native
cargo test --locked --lib native
```

The Rust tests cover firm-quote validation, the placement choice with one firm
quote, deadlines and every composed shape the Settler encodes, and check the
signer against vectors a Native-capable Settler build's own tests verify
(`crates/rfq/fixtures/native_authorization.json`). None of them certifies the live
Native API or its liquidity on any chain.
