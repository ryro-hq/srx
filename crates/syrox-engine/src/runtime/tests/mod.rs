use super::*;

use crate::build::{self, BuildResult};

use std::fs;

use std::process::{Command, Stdio};

mod managed_terminal;

mod closure;

mod foreground;

mod host;

mod materialized;

mod native;

pub(crate) fn elf(
    kind: u16,
    interpreter: Option<&str>,
    needed: &[&str],
    soname: Option<&str>,
    runpath: Option<&str>,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&kind.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(
        &(if interpreter.is_some() {
            3_u16
        } else {
            2_u16
        })
        .to_le_bytes(),
    );
    let ph = 64;
    bytes[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x400_u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x400_u64.to_le_bytes());
    let ph = ph + 56;
    bytes[ph..ph + 4].copy_from_slice(&2_u32.to_le_bytes());
    bytes[ph + 8..ph + 16].copy_from_slice(&0x200_u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(
        &((needed.len() + usize::from(soname.is_some()) + usize::from(runpath.is_some()) + 3)
            as u64
            * 16)
            .to_le_bytes(),
    );
    if let Some(path) = interpreter {
        let ph = ph + 56;
        bytes[ph..ph + 4].copy_from_slice(&3_u32.to_le_bytes());
        bytes[ph + 8..ph + 16].copy_from_slice(&0x180_u64.to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&((path.len() + 1) as u64).to_le_bytes());
        bytes[0x180..0x180 + path.len()].copy_from_slice(path.as_bytes());
    }
    let mut cursor = 0x300;
    let mut tags = Vec::new();
    for name in needed {
        tags.push((1_u64, (cursor - 0x300) as u64));
        bytes[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
        cursor += name.len() + 1;
    }
    if let Some(name) = soname {
        tags.push((14_u64, (cursor - 0x300) as u64));
        bytes[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
        cursor += name.len() + 1;
    }
    if let Some(path) = runpath {
        tags.push((29_u64, (cursor - 0x300) as u64));
        bytes[cursor..cursor + path.len()].copy_from_slice(path.as_bytes());
        cursor += path.len() + 1;
    }
    tags.push((5, 0x0040_0300));
    tags.push((10, (cursor - 0x300) as u64));
    for (n, (tag, value)) in tags.into_iter().enumerate() {
        let at = 0x200 + n * 16;
        bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn retained(
    store: &Store,
    name: &str,
    bytes: &[u8],
    library: Option<(&str, &[u8])>,
) -> BuildResult {
    let lease = store.operation().unwrap();
    let mut action = build::cache::tests::action();
    action.directory = name.to_owned();
    if let Some((soname, content)) = library {
        build::cache::tests::retained_with_library(&lease, &action, bytes, soname, content)
    } else {
        build::cache::tests::retained(&lease, &action, bytes)
    }
}

fn output(result: &BuildResult) -> RuntimeOutput {
    RuntimeOutput {
        root: result.root.clone(),
        receipt: result.receipt,
        output: "out".into(),
    }
}

fn runtime_file(result: &BuildResult) -> RuntimeFile {
    RuntimeFile {
        output: output(result),
        path: "bin/hello".into(),
    }
}

fn compile(source: &str, output: &std::path::Path, options: &[&str]) {
    let mut compiler = Command::new("gcc")
        .args(["-x", "c", "-"])
        .args(options)
        .arg("-o")
        .arg(output)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    assert!(compiler.wait().unwrap().success());
}

fn read_terminal_marker(
    master: &mut fs::File,
    marker: &[u8],
    timeout: Duration,
) -> std::io::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut received = Vec::new();
    loop {
        if received
            .windows(marker.len())
            .any(|bytes| bytes == marker)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "terminal marker deadline",
            ));
        }
        if !crate::execution::native::ready(master.as_fd(), 20)? {
            continue;
        }
        let mut bytes = [0; 1024];
        match master.read(&mut bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "terminal ended before marker",
                ));
            }
            Ok(n) => received.extend_from_slice(&bytes[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
        if received.len() > 16 * 1024 {
            return Err(std::io::Error::other(
                "terminal output limit exceeded",
            ));
        }
    }
}
