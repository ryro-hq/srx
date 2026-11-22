//! Root-activated helper for explicitly delegated private scratch allocation.
//!
//! Accepts one preconnected Unix seqpacket on fd 3 and a root-owned policy.
//! It never elevates itself, accepts a shell, chooses physical disks or changes
//! host boot. Incomplete attempts stay recorded; formatting is never replayed.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::undocumented_unsafe_blocks,
        reason = "tests assert with unwrap and drive raw syscalls; non-test builds keep both lints"
    )
)]
#![expect(
    unsafe_code,
    reason = "the root helper adopts its inherited socket fd and checks credentials and fd flags with libc"
)]

use std::fs::File;
use std::io;
use std::os::fd::FromRawFd as _;
use std::path::Path;

mod journal;
mod policy;
mod recovery;
mod session;
mod wire;
mod workspace;

#[cfg(test)]
mod tests;

fn main() {
    if let Err(error) = run() {
        eprintln!("syrox-system-helper: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    // SAFETY: fixed credential observations, no elevation or identity mutation.
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || args[0] != "--policy" {
        return Err(policy::refused(
            "expected --policy ABSOLUTE_PATH and an accepted seqpacket on fd 3",
        ));
    }
    let (policy, hash) = policy::Policy::load(Path::new(&args[1]))?;
    // SAFETY: verify that fd 3 exists before taking its unique inherited owner;
    // this process does not construct another owner for the activation fd.
    if unsafe { libc::fcntl(3, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd 3 was confirmed open above and this is the only owner created for it.
    let socket = unsafe { File::from_raw_fd(3) };
    session::serve(socket, policy, hash)
}
