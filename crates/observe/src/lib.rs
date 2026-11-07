//! Forks of CoW Protocol's `observe` crate (cowprotocol/services@dc906ab, MIT
//! OR Apache-2.0), by way of lp-terminal-rootfix's solver: the panic hook and
//! the tracing subscriber. Nothing here knows the solver; callers pass the log
//! format and the crate whose events pass.

pub mod panic_hook;
pub mod tracing;
