//! Access to Linux resources used by the engine.
//!
//! Handles and descriptors stay with the modules that opened them. A kernel
//! observation helps check identity or state, but authority to act remains with
//! the operation that requested it. See [`fd`](../../src/syrox_engine/platform/linux/fd/mod.rs.html) for descriptor ownership and
//! the ABI contracts beside each call.

pub mod linux;
