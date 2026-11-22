//! Consuming a plan in a Shell session or Services installation.
//!
//! Preparation gathers commands, packages and configuration in [`manifest`].
//! [`shell`] uses a temporary session; [`services`] keeps generations and a journal for
//! applying or recovering an installation. Each path retains its resources until
//! settlement completes.

pub mod manifest;
pub mod services;
pub mod shell;
