//! Bounded observations of explicitly named runtime kernel parameters.
//!
//! Dots separate path components in this initial contract. No write, discovery,
//! sysctl utility, application or restoration contract is implied by a read.

use crate::{descriptor, filesystem::Observation};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::Path;

const MAX_VALUE_BYTES: u64 = 4096;

/// Read a selected dotted name from the caller's current `/proc/sys` view.
/// Missing, inaccessible, oversized and non-text values remain unavailable.
/// Invalid names and cancellation return errors before further observations.
/// Only one final LF is stripped; whitespace and numeric spellings are otherwise
/// preserved because equivalence depends on the individual parameter's contract.
pub fn observe(
    name: &str,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<Observation<String>> {
    check()?;
    validate_name(name)?;
    let mut cancelled = None;
    let result = read(name, &mut || {
        check().map_err(|error| {
            let kind = error.kind();
            cancelled = Some(error);
            io::Error::from(kind)
        })
    });
    if let Some(error) = cancelled {
        return Err(error);
    }
    // Never turn cancellation into an unavailable kernel parameter.
    check()?;
    Ok(match result {
        Ok(value) => Observation::Available {
            value,
        },
        Err(error) => Observation::Unavailable {
            errno: error.raw_os_error(),
            reason: error.to_string(),
        },
    })
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.len() > 255
        || !name.contains('.')
        || !name.split('.').all(|component| {
            !component.is_empty()
                && component.len() <= 64
                && component
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sysctl observation requires a bounded canonical dotted name",
        ));
    }
    Ok(())
}

fn read(name: &str, check: &mut impl FnMut() -> io::Result<()>) -> io::Result<String> {
    let root = descriptor::open_resolved(
        None,
        Path::new("/proc/sys"),
        true,
        libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )?;
    require_procfs(&root)?;
    check()?;
    let file = descriptor::open_resolved(
        Some(root.as_fd()),
        Path::new(&name.replace('.', "/")),
        false,
        libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sysctl is not a regular kernel file",
        ));
    }
    require_procfs(&file)?;
    read_text(file, check)
}

#[allow(unsafe_code)]
fn require_procfs(file: &File) -> io::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fixed read-only query; live file and initialized output on success.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs returned success above, so the kernel initialized `stat`.
    if unsafe { stat.assume_init() }.f_type != 0x9fa0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sysctl observation requires procfs",
        ));
    }
    Ok(())
}

fn read_text(
    file: impl io::Read,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<String> {
    let mut input = file.take(MAX_VALUE_BYTES + 1);
    let mut value = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        check()?;
        match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => value.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    if value.len() as u64 > MAX_VALUE_BYTES || value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sysctl value exceeds text bounds",
        ));
    }
    if value.last() == Some(&b'\n') {
        value.pop();
    }
    String::from_utf8(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "sysctl value is not UTF-8",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_preserves_parameter_specific_spelling_and_rejects_excess_or_binary() {
        assert_eq!(
            read_text(&b"1\t  02  \n"[..], &mut || Ok(())).unwrap(),
            "1\t  02  "
        );
        assert!(read_text(&vec![b'x'; 4096][..], &mut || Ok(())).is_ok());
        assert!(read_text(&vec![b'x'; 4097][..], &mut || Ok(())).is_err());
        assert!(read_text(&b"x\0\n"[..], &mut || Ok(())).is_err());
        assert!(read_text(&b"\xff\n"[..], &mut || Ok(())).is_err());
        assert_eq!(
            read_text(&b"1"[..], &mut || Err(
                io::ErrorKind::Interrupted.into()
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn observes_actual_kernel_read_only_and_refuses_traversal_or_cancellation() {
        for name in [
            "",
            "vm",
            "vm..x",
            "../kernel.hostname",
            "vm./x",
            ".vm.x",
            "vm.x.",
        ] {
            assert_eq!(
                observe(name, || Ok(())).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            observe("kernel.hostname", || Err(
                io::ErrorKind::Interrupted.into()
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        let mut calls = 0;
        assert_eq!(
            observe("kernel.hostname", || {
                calls += 1;
                if calls == 2 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        let before = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
        let Observation::Available {
            value,
        } = observe("kernel.hostname", || Ok(())).unwrap()
        else {
            panic!("kernel.hostname must be readable in the Linux test environment");
        };
        assert_eq!(
            value,
            before.strip_suffix('\n').unwrap_or(&before)
        );
        assert_eq!(
            std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap(),
            before
        );
        assert!(matches!(
            observe("vm.srx_missing_read_only_fixture", || Ok(())).unwrap(),
            Observation::Unavailable {
                errno: Some(libc::ENOENT),
                ..
            }
        ));
    }
}
