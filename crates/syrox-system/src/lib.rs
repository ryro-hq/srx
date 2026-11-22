//! Linux system observation and contracts usable without the evaluator or builder.
//!
//! Observing a device never grants authority to write to it. Installation and
//! reconciliation must independently authorize and revalidate their real targets.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::undocumented_unsafe_blocks,
        reason = "tests assert with unwrap and drive raw syscalls; non-test builds keep both lints"
    )
)]

#[cfg(not(target_os = "linux"))]
compile_error!("syrox-system supports Linux only");

pub mod budget;
#[expect(
    unsafe_code,
    reason = "descriptor transport uses fcntl, socketpair, sendmsg/recvmsg, memfd and raw fd ownership FFI"
)]
pub mod descriptor;
pub mod disk;
#[expect(
    unsafe_code,
    reason = "the pinned ext4 tool sandbox runs pre_exec unshare, chroot, prctl, seccomp, capset and execveat FFI"
)]
#[cfg(target_arch = "x86_64")]
pub mod ext4_tool;
pub mod filesystem;
pub mod helper_activation;
#[expect(
    unsafe_code,
    reason = "the helper client uses socket, connect, poll and getsockopt FFI and adopts the raw socket fd"
)]
pub mod helper_client;
pub mod helper_protocol;
pub mod image;
pub mod inventory;
#[expect(
    unsafe_code,
    reason = "loop device control is ioctl FFI on loop-control and loop block devices"
)]
#[cfg(target_arch = "x86_64")]
pub mod loop_device;
pub mod qcow2;
#[expect(
    unsafe_code,
    reason = "detached scratch mounts use fsopen, fsconfig, fsmount and move_mount syscalls, fchown/fchmod and adopt the mount fd"
)]
#[cfg(target_arch = "x86_64")]
pub mod scratch;
pub mod storage;
pub mod sysctl;
pub mod verity;
#[cfg(target_arch = "x86_64")]
pub mod workspace;
