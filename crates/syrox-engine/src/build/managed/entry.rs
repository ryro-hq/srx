use super::{
    BuildError, handshake::connect_managed_build_worker,
    namespace::prepare_managed_build_namespace, supervision::validate_endpoint,
    worker::inspect_managed_build_worker,
};
use crate::build::managed::remaining_timeout as remaining;
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
    systemd::SystemdNotifier, systemd::SystemdNotifyEndpoint,
};
use sha2::{Digest as _, Sha256};
use std::{
    ffi::OsString,
    io::Read as _,
    os::fd::AsFd as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const BUDGET: Duration = Duration::from_secs(30);
const MAX_WORKER: u64 = 128 * 1024 * 1024;
struct Arguments {
    operation: PathBuf,
    action: ContentDigest,
    nonce: String,
    endpoint: PathBuf,
}
impl Arguments {
    fn parse(args: &[OsString]) -> Result<Self, BuildError> {
        let [operation, action, nonce, endpoint] = args else {
            return Err(BuildError::InvalidRequest);
        };
        let operation = PathBuf::from(operation);
        let endpoint = PathBuf::from(endpoint);
        let action = action
            .to_str()
            .ok_or(BuildError::InvalidRequest)?;
        let digest: ContentDigest = action
            .parse()
            .map_err(|_| BuildError::InvalidRequest)?;
        let nonce = nonce.to_str().ok_or(BuildError::InvalidRequest)?;
        if !hex_id(nonce)
            || !absolute(&operation)
            || !operation
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("op-"))
                .is_some_and(hex_id)
        {
            return Err(BuildError::InvalidRequest);
        }
        validate_endpoint(&endpoint)?;
        Ok(Self {
            operation,
            action: digest,
            nonce: nonce.into(),
            endpoint,
        })
    }
}
fn absolute(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        text.len() <= 4096
            && text.starts_with('/')
            && !text.contains('\0')
            && text[1..]
                .split('/')
                .all(|part| !matches!(part, "" | "." | ".."))
    })
}
fn hex_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && text.bytes().any(|byte| byte != b'0')
}
fn invocation(text: &str) -> Result<[u8; 16], BuildError> {
    if !hex_id(text) {
        return Err(BuildError::InvalidRequest);
    }
    let mut value = [0; 16];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| BuildError::InvalidRequest)?;
    }
    Ok(value)
}
/// Prepare and publish a parked namespace, accept one authenticated journal
/// COMMIT, and retain resources until the coordinator observes the reaped exit.
/// Exit zero means worker completion, never receipt publication or settlement.
/// Environment notification and invocation values are untrusted claims; peers,
/// the journal and coordinator manager observations authenticate their use.
///
/// # Safety
/// Must run in a dedicated single-threaded process which exits after return.
/// Namespace preparation changes process credentials/namespaces even on errors.
/// The caller installs signal-backed cancellation before entering this function.
#[allow(unsafe_code)]
pub unsafe fn run_managed_build_entry(
    args: &[OsString],
    cancel: &Cancellation,
) -> Result<i32, BuildError> {
    cancel.check()?;
    let args = Arguments::parse(args)?;
    let began = Instant::now();
    let deadline = began + BUDGET;
    let invocation =
        invocation(&std::env::var("INVOCATION_ID").map_err(|_| BuildError::InvalidRequest)?)?;
    let endpoint = SystemdNotifyEndpoint::new(
        &std::env::var("NOTIFY_SOCKET").map_err(|_| BuildError::InvalidRequest)?,
    )
    .map_err(|_| BuildError::InvalidRequest)?;
    let inspection = inspect_managed_build_worker(
        &args.operation,
        args.action,
        &args.nonce,
        cancel,
        deadline,
    )?;
    preparation_phase("inspection", began);
    verify_self(inspection.worker_digest(), cancel, deadline)?;
    preparation_phase("self image", began);
    inspection.revalidate(cancel, deadline)?;
    let hello = connect_managed_build_worker(
        &inspection,
        &args.endpoint,
        invocation,
        cancel,
        deadline,
    )?;
    preparation_phase("hello", began);
    let received = hello.receive_resources(cancel, deadline)?;
    preparation_phase("resources", began);
    let notifier = SystemdNotifier::connect(&endpoint, remaining(cancel, deadline)?, cancel)
        .map_err(|error| notify_error(&error, cancel))?;
    let published = received.publish_retention(&notifier, cancel, deadline)?;
    preparation_phase("retention", began);
    // SAFETY: caller promises this process is single-threaded and exits after return.
    let namespace = unsafe { prepare_managed_build_namespace(&published, cancel, deadline)? };
    preparation_phase("layout", began);
    let namespace = namespace.publish_namespace(&notifier, cancel, deadline)?;
    preparation_phase("namespace published", began);
    namespace.execute(&notifier, cancel, deadline)
}
fn preparation_phase(phase: &str, began: Instant) {
    eprintln!(
        "managed build preparation: {phase} at {} ms",
        began.elapsed().as_millis()
    );
}

fn notify_error(error: &crate::systemd::SystemdError, cancel: &Cancellation) -> BuildError {
    if cancel.is_cancelled() {
        BuildError::Cancelled
    } else {
        BuildError::Cache(error.to_string())
    }
}
fn verify_self(
    expected: ContentDigest,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<(), BuildError> {
    let directory = linux_fd::open_top_directory(&PathBuf::from(format!(
        "/proc/{}",
        std::process::id()
    )))
    .map_err(|_| BuildError::InputChanged)?;
    if linux_fd::filesystem_type(directory.fd())? != 0x9fa0 {
        return Err(BuildError::InputChanged);
    }
    // The procfs magic link is intentional; the numeric process directory is pinned.
    let mut executable = linux_fd::open_proc_executable(directory.fd())?;
    let identity = linux_fd::metadata(executable.as_fd())?;
    let metadata = executable.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_WORKER {
        return Err(BuildError::InputChanged);
    }
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut bytes = [0_u8; 16384];
    loop {
        remaining(cancel, deadline)?;
        let read = executable.read(&mut bytes)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > MAX_WORKER {
            return Err(BuildError::InputChanged);
        }
        hasher.update(&bytes[..read]);
    }
    if linux_fd::metadata(executable.as_fd())? != identity
        || linux_fd::metadata(linux_fd::open_proc_executable(directory.fd())?.as_fd())?.identity()
            != identity.identity()
        || count != metadata.len()
        || ContentDigest::from_sha256_hash(hasher.finalize().into()) != expected
    {
        return Err(BuildError::InputChanged);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn arguments() -> Vec<OsString> {
        [
            "/private/op-11111111111111111111111111111111".into(),
            ContentDigest::sha256(b"action")
                .to_string()
                .into(),
            "22222222222222222222222222222222".into(),
            "/private/worker.sock".into(),
        ]
        .into()
    }
    #[test]
    fn exact_arguments_reject_ambiguous_paths_and_identifiers() {
        assert!(Arguments::parse(&arguments()).is_ok());
        let mut args = arguments();
        args.push("extra".into());
        assert!(Arguments::parse(&args).is_err());
        for (index, bad) in [
            (0, "relative/op-11111111111111111111111111111111"),
            (
                0,
                "/private/../op-11111111111111111111111111111111",
            ),
            (0, "/private/op-00000000000000000000000000000000"),
            (1, "invalid"),
            (2, "00000000000000000000000000000000"),
            (2, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            (3, "/private//socket"),
        ] {
            let mut args = arguments();
            args[index] = bad.into();
            assert!(Arguments::parse(&args).is_err(), "index {index}");
        }
    }
    #[test]
    fn invocation_claim_is_canonical_nonzero() {
        assert_eq!(
            invocation("11111111111111111111111111111111").unwrap(),
            [0x11; 16]
        );
        for bad in [
            "",
            "00000000000000000000000000000000",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(invocation(bad).is_err());
        }
    }
    #[test]
    #[allow(unsafe_code)]
    fn cancellation_precedes_arguments_environment_and_filesystem() {
        let cancel = Cancellation::default();
        cancel.cancel();
        // SAFETY: cancellation returns before any process-global operation.
        assert!(matches!(
            unsafe { run_managed_build_entry(&[], &cancel) },
            Err(BuildError::Cancelled)
        ));
    }
    #[test]
    fn self_image_mismatch_is_rejected_without_namespace_effects() {
        assert!(matches!(
            verify_self(
                ContentDigest::sha256(b"not this executable"),
                &Cancellation::default(),
                Instant::now() + BUDGET
            ),
            Err(BuildError::InputChanged)
        ));
    }
}
