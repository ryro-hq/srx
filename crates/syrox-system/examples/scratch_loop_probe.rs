//! Destructive loop primitive probe for an explicitly marked disposable QEMU VM.
//!
//! This is a qualification executable, not a privileged helper or build executor.
//! It creates only its own regular scratch image, preserves intent/evidence on
//! failure, and never accepts a disk path or formats an existing resource.

#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{DirBuilderExt as _, FileExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use syrox_system::loop_device::{LoopControl, Observation, Phase, ScratchLoop};

const BYTES: u64 = 64 * 1024 * 1024;
const DIRECTORY: &str = "/var/tmp/srx-loop-probe";

#[path = "scratch_loop_probe/ext4.rs"]
mod ext4;

fn main() {
    if let Err(error) = run() {
        eprintln!("SRX_LOOP_PROBE_FAILED: {error}; evidence: {DIRECTORY}");
        std::process::exit(1);
    }
    println!("SRX_LOOP_PROBE_OK");
}

fn run() -> io::Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let isolated = arguments == ["--disposable-vm", "--ext4-isolated"];
    let ext4 = isolated || arguments == ["--disposable-vm", "--ext4"];
    // SAFETY: geteuid only observes the current process's effective identity.
    if unsafe { libc::geteuid() } != 0
        || (!ext4 && arguments != ["--disposable-vm"])
        || std::fs::read("/etc/srx-disposable-vm")? != b"srx-loop-fixture-v1\n"
        || std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim() != "QEMU"
    {
        return Err(io::Error::other(
            "requires root inside the marked disposable QEMU fixture",
        ));
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(DIRECTORY)?;
    let image_path = Path::new(DIRECTORY).join("scratch.img");
    let image = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&image_path)?;
    image.set_len(BYTES)?;
    // SAFETY: private regular file, nonnegative representable offset and length.
    let allocation = unsafe {
        libc::posix_fallocate(
            image.as_raw_fd(),
            0,
            i64::try_from(BYTES).unwrap(),
        )
    };
    if allocation != 0 {
        return Err(io::Error::from_raw_os_error(allocation));
    }
    image.sync_all()?;
    record(0, "image-created", None)?;
    let control = LoopControl::from_file(open_device(Path::new("/dev/loop-control"))?)?;
    record(1, "select-loop-intent", None)?;
    let number = control.select_free()?;
    let device_path = PathBuf::from(format!("/dev/loop{number}"));
    let device = wait_for_node(&device_path)?;
    let mut binding = ScratchLoop::prepare(device, number, image.try_clone()?, BYTES)?;
    record(2, "configure-intent", Some(number))?;
    binding.configure()?;
    assert_eq!(binding.phase(), Phase::Verified);
    assert_eq!(binding.observe()?, Observation::ExpectedBinding);
    assert!(binding.configure().is_err());
    record(3, "binding-verified", Some(number))?;

    let device = File::from(binding.verified_device()?.try_clone_to_owned()?);
    let marker = [0x5a; 4096];
    device.write_all_at(&marker, 0)?;
    device.write_all_at(&marker, BYTES - 4096)?;
    device.sync_all()?;
    let mut actual = [0; 4096];
    image.read_exact_at(&mut actual, BYTES - 4096)?;
    assert_eq!(actual, marker);
    assert!(matches!(
        device.write_at(&marker, BYTES),
        Err(_) | Ok(0)
    ));
    assert_eq!(image.metadata()?.len(), BYTES);
    drop(device);

    std::fs::set_permissions(
        &image_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )?;
    assert!(binding.verified_device().is_err());
    std::fs::set_permissions(
        &image_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;
    let alias = Path::new(DIRECTORY).join("alias");
    std::fs::hard_link(&image_path, &alias)?;
    assert!(binding.observe().is_err());
    std::fs::remove_file(alias)?;
    image.set_len(BYTES - 4096)?;
    assert!(binding.observe().is_err());
    image.set_len(BYTES)?;
    assert_eq!(binding.observe()?, Observation::ExpectedBinding);
    record(4, "bounds-and-identity-checked", Some(number))?;

    // This is a second open description, not dup: it keeps the kernel opener
    // count above one, exercising deferred release rather than only AUTOCLEAR.
    let extra = open_device(&device_path)?;
    record(5, "release-intent", Some(number))?;
    assert_eq!(binding.release()?, Observation::ExpectedBinding);
    assert_eq!(binding.phase(), Phase::ReleaseAttempted);
    assert!(binding.release().is_err());
    assert!(binding.verified_device().is_err());
    drop(binding);
    let mut first = [0; 4096];
    extra.read_exact_at(&mut first, 0)?;
    assert_eq!(first, marker);
    drop(extra);
    wait_for_teardown(number)?;
    record(6, "first-teardown-observed", Some(number))?;

    // A separate, explicitly journaled attempt on the same virtual device proves
    // that the first binding no longer prevents atomic configuration.
    let mut second = ScratchLoop::prepare(
        open_device(&device_path)?,
        number,
        image.try_clone()?,
        BYTES,
    )?;
    record(7, "second-configure-intent", Some(number))?;
    second.configure()?;
    record(8, "second-release-intent", Some(number))?;
    let observation = second.release()?;
    println!("release observation: {observation:?}; final teardown still pending");
    drop(second);
    wait_for_teardown(number)?;
    record(9, "second-teardown-observed", Some(number))?;
    if ext4 {
        ext4::run(isolated)?;
    }
    Ok(())
}

fn open_device(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

fn wait_for_node(path: &Path) -> io::Result<File> {
    for _ in 0..100 {
        match open_device(path) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "loop node did not appear",
    ))
}

fn wait_for_teardown(number: u32) -> io::Result<()> {
    let base = PathBuf::from(format!("/sys/dev/block/7:{number}"));
    for _ in 0..100 {
        if !base.join("loop/backing_file").try_exists()?
            && std::fs::read(base.join("size"))? == b"0\n"
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "loop teardown remains uncertain",
    ))
}

fn record(sequence: u32, state: &str, number: Option<u32>) -> io::Result<()> {
    use std::io::Write as _;
    let path = Path::new(DIRECTORY).join(format!("{sequence:02}.json"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer(
        &mut file,
        &serde_json::json!({
            "version": 1, "state": state, "loop_number": number, "bytes": BYTES,
        }),
    )?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(DIRECTORY)?.sync_all()?;
    println!("SRX_LOOP_PROBE_STEP {sequence} {state} {number:?}");
    Ok(())
}
