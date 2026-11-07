//! Sextant's solver budget: the cooperative deadline and cancellation token
//! that every CPU-heavy phase of one quote checks. It is a leaf crate, so the
//! chain I/O and Native RFQ can use it without depending on the router.

pub mod budget;
