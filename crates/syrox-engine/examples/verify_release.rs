use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::Path;
use std::process::{Command, Stdio};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[path = "../../syrox/elf_release.rs"]
mod elf_release;

fn checked(command: &mut Command) -> Result<()> {
    let status = command.stdin(Stdio::null()).status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "release verification command failed: {status}"
        ))
        .into());
    }
    Ok(())
}

fn digest(path: &Path) -> Result<[u8; 32]> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 16384];
    loop {
        let count = input.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hash.update(&bytes[..count]);
    }
    Ok(hash.finalize().into())
}

fn elf(path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 128 * 1024 * 1024 || !elf_release::static_x86_64(&bytes) {
        return Err(io::Error::other(format!(
            "{}: not a bounded static x86_64 ELF",
            path.display()
        ))
        .into());
    }
    println!("{}: no PT_INTERP or DT_NEEDED", path.display());
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [directory] = args.as_slice() else {
        return Err("usage: verify_release <release-directory>".into());
    };
    let directory = fs::canonicalize(directory)?;
    let binary = directory.join("srx");
    let worker = directory.join("syrox-worker");
    elf(&binary)?;
    elf(&worker)?;
    let temporary = tempfile::tempdir()?;
    let prefix = temporary.path();
    for _ in 0..2 {
        checked(
            Command::new(&binary)
                .args(["install-self", "--prefix"])
                .arg(prefix)
                .env_clear()
                .env("PATH", "/nonexistent")
                .env("HOME", prefix),
        )?;
    }
    for args in [
        &["--help"][..],
        &["host", "inspect"][..],
    ] {
        checked(
            Command::new(prefix.join("bin/srx"))
                .args(args)
                .env_clear()
                .env("PATH", "/nonexistent")
                .env("HOME", prefix)
                .stdout(Stdio::null()),
        )?;
    }
    if digest(&prefix.join("current/syrox-worker"))? != digest(&worker)? {
        return Err("installed worker differs from the release worker".into());
    }
    println!("installation is repeatable without distribution utilities; worker bytes match");
    Ok(())
}
