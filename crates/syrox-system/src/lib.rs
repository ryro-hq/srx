//! Linux system observation and contracts usable without the evaluator or builder.
//!
//! Observing a device never grants authority to write to it. Installation and
//! reconciliation must independently authorize and revalidate their real targets.

#[cfg(not(target_os = "linux"))]
compile_error!("syrox-system supports Linux only");

pub mod budget;
#[allow(unsafe_code)]
pub mod descriptor;
pub mod disk;
#[allow(unsafe_code)]
#[cfg(target_arch = "x86_64")]
pub mod ext4_tool;
pub mod filesystem;
pub mod helper_activation;
#[allow(unsafe_code)]
pub mod helper_client;
pub mod helper_protocol;
pub mod image;
pub mod inventory;
#[allow(unsafe_code)]
#[cfg(target_arch = "x86_64")]
pub mod loop_device;
pub mod qcow2;
#[allow(unsafe_code)]
#[cfg(target_arch = "x86_64")]
pub mod scratch;
pub mod storage;
pub mod sysctl;
pub mod verity;
#[cfg(target_arch = "x86_64")]
pub mod workspace;

/// Lowercase hexadecimal text of digest bytes.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("String write");
    }
    text
}
