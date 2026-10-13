//! Build com o toolchain do host escolhido para bootstrap.
//!
//! A identidade do toolchain entra na action e é conferida de novo quando a
//! aquisição pode ter permitido uma mudança nos arquivos. O worker executa com
//! mounts, ambiente e limites preparados antes de receber as instruções.

pub(crate) mod capture;
pub(crate) mod group;
pub(crate) mod linux;
pub(crate) mod sandbox;
pub(crate) mod worker;
pub(crate) use super::{
    BuildError, BuildPart, BuildPath, BuildProfile, BuildProgram, BuildResources, BuildResult,
    BuildSourceFormat, BuildSpecification, BuildStep, BuildText, MAX_LARGE_SOURCE_BYTES,
    MAX_OUTPUT_BYTES, MAX_SOURCE_BYTES, cache, journal, policy, records, shared,
};

pub(crate) use super::{
    BuildInput, MAX_BUILD_PROGRAM_BYTES, check_build_host, profile, publication, relative_path,
};
pub(crate) use crate::cancellation::Cancellation;
