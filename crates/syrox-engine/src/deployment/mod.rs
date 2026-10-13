//! Consuming a plan in a Shell session or Os installation.
//!
//! Preparation gathers commands, packages and configuration in [`manifest`].
//! [`shell`] uses a temporary session; [`os`] keeps generations and a journal for
//! applying or recovering an installation. Each path retains its resources until
//! settlement completes.

pub mod manifest;
pub mod os;
pub mod shell;
