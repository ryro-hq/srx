pub(crate) mod boot;
#[expect(
    unsafe_code,
    reason = "descriptor primitives wrap openat, fcntl, ioctl, pidfd, waitpid, prctl and raw fd ownership FFI"
)]
pub(crate) mod fd;
pub mod host;
