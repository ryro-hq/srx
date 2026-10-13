use super::{
    Cancellation, ContentDigest, Duration, Instant, OsLaunchBinding, OsWorkerError, PathBuf,
    invalid,
};
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd as _;
const MAX_IMAGE: u64 = 128 * 1024 * 1024;
pub(super) struct Arguments {
    pub installation: PathBuf,
    pub store: PathBuf,
    pub binding: ContentDigest,
}
impl Arguments {
    pub(super) fn parse(args: &[OsString]) -> Result<Self, OsWorkerError> {
        let [installation, store, binding] = args else {
            return Err(invalid(
                "expected installation, Store and binding pin",
            ));
        };
        let installation = path(installation)?;
        let store = path(store)?;
        if installation.starts_with(&store) || store.starts_with(&installation) {
            return Err(invalid("installation and Store overlap"));
        }
        let value = binding
            .to_str()
            .ok_or_else(|| invalid("binding pin is not UTF-8"))?;
        let binding = value
            .parse::<ContentDigest>()
            .map_err(|_| invalid("invalid binding pin"))?;
        if binding.to_string() != value {
            return Err(invalid("binding pin is not canonical"));
        }
        Ok(Self {
            installation,
            store,
            binding,
        })
    }
}
fn path(value: &OsString) -> Result<PathBuf, OsWorkerError> {
    let text = value
        .to_str()
        .ok_or_else(|| invalid("worker path is not UTF-8"))?;
    if text.len() > 4096
        || !text.starts_with('/')
        || text == "/"
        || text.chars().any(char::is_control)
        || text[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.len() > 255)
    {
        return Err(invalid(
            "worker path is not canonical absolute text",
        ));
    }
    Ok(PathBuf::from(text))
}
pub(super) fn invocation(text: &str) -> Result<[u8; 16], OsWorkerError> {
    if text.len() != 32
        || text
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid invocation identifier"));
    }
    let mut value = [0; 16];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("invalid invocation identifier"))?;
    }
    if value == [0; 16] {
        return Err(invalid("zero invocation identifier"));
    }
    Ok(value)
}
pub(super) fn hex(invocation: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    for byte in invocation {
        write!(output, "{byte:02x}").expect("String write");
    }
    output
}
pub(super) fn identity(binding: &OsLaunchBinding) -> Result<(), OsWorkerError> {
    // SAFETY: credential queries have no process-global mutations.
    let actual = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    let context = binding.context();
    if actual
        != (
            context.uid(),
            context.uid(),
            context.gid(),
            context.gid(),
        )
    {
        return Err(invalid(
            "worker uid/gid differ from authorized operational identity",
        ));
    }
    Ok(())
}
pub(super) fn verify_image(
    expected: ContentDigest,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<(), OsWorkerError> {
    check(deadline, cancel)?;
    let image = running_image()?;
    if hash_reader(image, MAX_IMAGE, cancel, deadline)? != expected {
        return Err(invalid(
            "running image differs from pinned launcher",
        ));
    }
    Ok(())
}
pub(super) fn running_image() -> Result<File, OsWorkerError> {
    let own_proc = PathBuf::from(format!("/proc/{}", std::process::id()));
    let proc = crate::platform::linux::fd::open_top_directory(&own_proc)
        .map_err(|_| invalid("cannot pin own proc entry"))?;
    if crate::platform::linux::fd::filesystem_type(proc.fd())? != 0x9fa0 {
        return Err(invalid("own image path is not procfs"));
    }
    // This kernel-owned magic link deliberately opens the running executable.
    // Parent is the pinned numeric process directory, never an ambient hint.
    let image = File::open(format!(
        "/proc/self/fd/{}/exe",
        proc.fd().as_raw_fd()
    ))?;
    if !image.metadata()?.is_file() {
        return Err(invalid("running image is not regular"));
    }
    Ok(image)
}
pub(super) fn hash_reader(
    mut source: impl Read,
    maximum: u64,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<ContentDigest, OsWorkerError> {
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        check(deadline, cancel)?;
        let size = source.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        total = total
            .checked_add(size as u64)
            .filter(|n| *n <= maximum)
            .ok_or_else(|| invalid("running image exceeds bound"))?;
        hash.update(&buffer[..size]);
    }
    check(deadline, cancel)?;
    Ok(ContentDigest::from_sha256_hash(
        hash.finalize().into(),
    ))
}
pub(super) fn check(deadline: Instant, cancel: &Cancellation) -> Result<(), OsWorkerError> {
    if cancel.is_cancelled() {
        return Err(io::Error::other("Os startup cancelled").into());
    }
    remaining(deadline)?;
    Ok(())
}
pub(super) fn remaining(deadline: Instant) -> Result<Duration, OsWorkerError> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        Err(io::Error::new(io::ErrorKind::TimedOut, "Os startup deadline").into())
    } else {
        Ok(duration)
    }
}
