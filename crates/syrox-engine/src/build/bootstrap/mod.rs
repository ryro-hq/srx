//! Building with the host toolchain selected for bootstrap.
//!
//! Toolchain identity contributes to the action and is checked again when
//! acquisition may have allowed files to change. The worker runs with mounts,
//! environment and limits prepared before it receives instructions.

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
