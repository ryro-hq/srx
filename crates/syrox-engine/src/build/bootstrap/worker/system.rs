//! System IR entry after independently authenticated namespace/resource admission.

use super::{
    BuildError, Paths, execute_system_program, normalize_hardlinks_bounded,
    settle_build_descendants, verify_confinement,
};
use crate::{
    build::system::SystemBuildAction,
    cancellation::Cancellation,
    result::{SystemOutputStream, write_system_outputs},
    store::ContentDigest,
    system::workspace::WorkspaceObservation,
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read as _},
    path::Path,
};

/// No Store, helper control, journal or receipt authority enters this process.
///
/// # Safety
/// Dedicated single-threaded payload child only; exit after return, including
/// error. Caller independently authenticates action/budget, role observations,
/// immutable input mounts, manager admission and namespace/custody lifecycle.
/// Process-wide policy can be partly installed on failure and closes all fd>=3.
#[expect(
    unsafe_code,
    reason = "unsafe fn: installs process-wide confinement policy and closes fds >= 3"
)]
pub(crate) unsafe fn run(
    action: &SystemBuildAction,
    observation: &WorkspaceObservation,
    cancellation: &Cancellation,
) -> Result<(), BuildError> {
    cancellation.check()?;
    let layout = action.workspace_layout()?;
    crate::execution::native::build_policy::validate_system_environment(&layout, observation)?;
    same_bytes("/build-action", &action.encode())?;
    same_bytes("/build-program", &action.program().encode())?;
    if hash_file("/proc/self/exe", 128 * 1024 * 1024, cancellation)? != action.worker_digest()
        || hash_file("/syrox-worker", 128 * 1024 * 1024, cancellation)? != action.worker_digest()
        || hash_file("/source", action.source_limit(), cancellation)? != action.source_digest()
    {
        return Err(BuildError::InputChanged);
    }
    let digest = action.digest();
    let paths = Paths {
        work: "/work".into(),
        source: "/source".into(),
        output: format!("/out/syrox/store/{digest}").into(),
        installed: format!("/syrox/store/{digest}").into(),
        inputs: action
            .selected_inputs()
            .iter()
            .map(|input| format!("/syrox/store/{}/{}", input.action, input.output).into())
            .collect(),
    };
    for input in &paths.inputs {
        crate::execution::native::build_policy::validate_system_input(input)?;
    }
    cancellation.check()?;
    // SAFETY: the caller guarantees the dedicated process/exit contract above.
    unsafe {
        crate::execution::native::build_policy::install()?;
    }
    verify_confinement()?;
    crate::platform::linux::fd::become_build_subreaper()?;
    execute_system_program(
        action,
        &paths,
        cancellation,
        settle_build_descendants,
    )?;
    super::verify_system_install_layout(&digest.to_string(), &action.program().outputs)?;
    let maximum = usize::try_from(action.budget().request().files.min(1_000_000))
        .map_err(|_| BuildError::Output)?;
    let mut visited = 0;
    for name in &action.program().outputs {
        normalize_hardlinks_bounded(&paths.output.join(name), maximum, &mut visited)?;
    }
    cancellation.check()?;
    let mut streams = BTreeMap::new();
    for name in &action.program().outputs {
        let source = SystemOutputStream::from_directory(
            File::open(paths.output.join(name))?,
            action.budget(),
            cancellation,
        )
        .map_err(|error| BuildError::Execution(error.to_string()))?;
        streams.insert(name.clone(), source);
    }
    write_system_outputs(
        &mut io::stdout().lock(),
        digest,
        streams,
        action.budget(),
        cancellation,
    )
    .map_err(|error| BuildError::Execution(error.to_string()))
}

#[cfg(test)]
mod tests;
fn same_bytes(path: &str, expected: &[u8]) -> Result<(), BuildError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes != expected {
        return Err(BuildError::InputChanged);
    }
    Ok(())
}
fn hash_file(
    path: &str,
    maximum: u64,
    cancellation: &Cancellation,
) -> Result<ContentDigest, BuildError> {
    let mut file = File::open(Path::new(path))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(BuildError::InputChanged);
    }
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0; 64 * 1024];
    loop {
        cancellation.check()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(BuildError::InputChanged)?;
        if total > maximum {
            return Err(BuildError::InputChanged);
        }
        hash.update(&buffer[..count]);
    }
    if total != metadata.len() {
        return Err(BuildError::InputChanged);
    }
    Ok(ContentDigest::from_sha256_hash(
        hash.finalize().into(),
    ))
}
