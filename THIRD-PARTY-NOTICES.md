# Third-party notices

Sextant is licensed MIT OR Apache-2.0 (see `LICENSE-MIT` and `LICENSE-APACHE`).
Parts of it derive from other projects:

- `crates/observe` is forked from CoW Protocol's `observe` crate (through the
  author's `lp-terminal-rootfix`), under MIT OR Apache-2.0.
- `crates/amm/src/v3math.rs` states that it is a verbatim port of Uniswap
  v3-core's `TickMath`, `SqrtPriceMath` and `SwapMath` (exact-input subset),
  and `crates/amm/src/pools.rs` mirrors `UniswapV3Pool.swap`. Uniswap v3-core
  is licensed under BUSL-1.1, which converts to GPL-2.0-or-later. If that code
  is a derivative work, its terms govern it; the owner of this repository has
  to decide how to license it before redistributing it. Until then, treat
  `crates/amm`'s math as subject to the Uniswap v3-core license.
- `crates/amm` depends on `ekubo_sdk` (LGPL-2.1). Distributing a binary that
  links it carries the LGPL's obligations.
- The QuoteLens contract in `lens/` and the Settler ABI in
  `crates/io/src/abi.rs` encode interfaces published by 0x Settler and the
  pools it trades; the interfaces themselves are not this project's work.

Run `cargo deny`-style checks with your own policy; this file names the
derivations this repository's authors know about, and is not legal advice.
