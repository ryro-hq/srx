//! Protocolos e registros usados por runtimes, launchers e sessões.
//!
//! Aqui ficam as descrições dos recursos, os journals de admissão e as
//! observações de processos. As operações que recebem esses dados ainda precisam
//! conferir sua própria autorização antes de liberar execução ou retenção.

pub(crate) mod command_evidence;
pub(crate) mod configuration;
pub(crate) mod error;
pub(crate) mod journal;
pub(crate) mod resources;
pub(crate) mod service_evidence;
#[allow(unsafe_code)]
pub(crate) mod transport;

pub(crate) mod launcher;
#[allow(unsafe_code)]
pub(crate) mod native;
pub mod restart;
pub use restart::{ProcessRestart, RestartLimits, RestartPolicyError};
