//! Protocols and records shared by runtimes, launchers and sessions.
//!
//! [`resources`](../../src/syrox_engine/execution/resources/mod.rs.html) describes transferred resources, [`journal`](../../src/syrox_engine/execution/journal/mod.rs.html) records admission,
//! and [`command_evidence`](../../src/syrox_engine/execution/command_evidence/mod.rs.html) and [`service_evidence`](../../src/syrox_engine/execution/service_evidence/mod.rs.html) record process observations.
//! Operations receiving these data must still check their own authorization before
//! releasing execution gates or retention.
//!
//! Follow [`launcher`](../../src/syrox_engine/execution/launcher/mod.rs.html) for owner and service coordination, or [`native`](../../src/syrox_engine/execution/native/mod.rs.html) for the
//! dedicated Linux processes that prepare namespaces and supervise payloads.

pub(crate) mod command_evidence;
pub(crate) mod configuration;
pub(crate) mod error;
pub(crate) mod journal;
pub(crate) mod resources;
pub(crate) mod service_evidence;
#[expect(
    unsafe_code,
    reason = "packet transport uses socketpair, sendmsg/recvmsg with SCM_RIGHTS, sockopt and poll FFI"
)]
pub(crate) mod transport;

pub(crate) mod launcher;
#[expect(
    unsafe_code,
    reason = "the native runtime forks, clones, waits, masks signals and adopts raw fds"
)]
pub(crate) mod native;
pub mod restart;
pub use restart::{ProcessRestart, RestartLimits, RestartPolicyError};
