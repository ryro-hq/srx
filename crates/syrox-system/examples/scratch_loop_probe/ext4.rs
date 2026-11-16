use super::{BYTES, DIRECTORY, open_device, record, wait_for_node, wait_for_teardown};
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use syrox_system::{
    budget::{BuildBudget, BuilderLimits},
    descriptor::pinned_tool::{PinnedTool, ToolPin},
    ext4_tool::{self, Geometry, Operation},
    loop_device::{LoopControl, Observation, ScratchLoop},
    scratch::DetachedScratch,
};

pub(super) fn run(isolated: bool) -> io::Result<()> {
    let formatter = tool(
        "mke2fs",
        1_735_200,
        "59935ec5c57f7f3b2e5ef1119d7480275264a9f5adecb862b7bd2ae813fd83ec",
    )?;
    let checker = tool(
        "e2fsck",
        2_093_768,
        "da1f6de6ac3a2efd7fc6d2581199ce7109a22dee7843ce923e4111a92666a95a",
    )?;
    let image_path = Path::new(DIRECTORY).join("scratch-ext4.img");
    let image = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&image_path)?;
    image.set_len(BYTES)?;
    record(10, "ext4-format-intent", None)?;
    if isolated {
        isolated_tool(
            &formatter,
            &image,
            Operation::Format(Geometry::new(BYTES, 512)?),
            "format",
        )?;
    } else {
        run_tool(
            &formatter,
            &[
                "-q",
                "-F",
                "-t",
                "ext4",
                "-b",
                "4096",
                "-I",
                "256",
                "-g",
                "32768",
                "-N",
                "512",
                "-m",
                "0",
                "-E",
                "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0",
                image_path.to_str().unwrap(),
                "16384",
            ],
        )?;
    }
    if isolated {
        let probe = tool(
            "isolation-checks",
            1_567_440,
            "96be4e23b124e22112e0cbc963368ded50130419aaa174f5e3c0c55b7ca3bfba",
        )?;
        isolated_tool(
            &probe,
            &image,
            Operation::Check,
            "isolation-checks",
        )?;
        isolated_tool(&checker, &image, Operation::Check, "check-before")?;
    } else {
        run_tool(
            &checker,
            &["-f", "-n", image_path.to_str().unwrap()],
        )?;
    }
    assert_eq!(image.metadata()?.len(), BYTES);
    image.sync_all()?;
    record(11, "ext4-format-and-check-passed", None)?;

    let control = LoopControl::from_file(open_device(Path::new("/dev/loop-control"))?)?;
    record(12, "ext4-loop-selection-intent", None)?;
    let number = control.select_free()?;
    let path = PathBuf::from(format!("/dev/loop{number}"));
    let mut binding = ScratchLoop::prepare(
        wait_for_node(&path)?,
        number,
        image.try_clone()?,
        BYTES,
    )?;
    record(13, "ext4-loop-configure-intent", Some(number))?;
    binding.configure()?;
    let request = BuildBudget {
        memory_bytes: 128 * 1024 * 1024,
        cpu_percent: 100,
        processes: 16,
        descriptors: 128,
        scratch_bytes: BYTES,
        files: 512,
        output_bytes: 1024 * 1024,
        duration_seconds: 120,
    };
    let admitted = BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap();
    let small = BuildBudget {
        scratch_bytes: BYTES - 4096,
        ..request
    };
    let small = BuilderLimits::new(small)
        .unwrap()
        .admit(small)
        .unwrap();
    assert!(DetachedScratch::mount(&binding, &small, || Ok(())).is_err());
    record(14, "ext4-detached-mount-intent", Some(number))?;
    let mount = DetachedScratch::mount(&binding, &admitted, || Ok(()))?;
    assert!(mount.capacity().filesystem_bytes <= BYTES);
    assert_eq!(mount.capacity().inodes, 512);
    mount.assign_owner(1000, 1000)?;
    let root = File::from(mount.root()?.try_clone_to_owned()?);
    let prefix = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));

    let mut files = Vec::new();
    let mut exhausted = false;
    for index in 0..600 {
        let path = prefix.join(format!("inode-{index}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                drop(file);
                files.push(path);
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => {
                exhausted = true;
                break;
            }
            Err(error) => return Err(error),
        }
    }
    assert!(exhausted && !files.is_empty() && files.len() <= 512);
    println!(
        "SRX_EXT4_INODES_ENFORCED {} created, 512 total",
        files.len()
    );
    for path in files {
        std::fs::remove_file(path)?;
    }
    record(15, "ext4-inode-exhaustion-checked", Some(number))?;

    let fill_path = prefix.join("byte-limit");
    let mut fill = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_DSYNC | libc::O_NOFOLLOW)
        .open(&fill_path)?;
    let buffer = vec![0x5a; 1024 * 1024];
    let mut written = 0_u64;
    loop {
        match fill.write(&buffer) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                written += count as u64;
                assert!(written <= BYTES);
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    assert!(written > 0);
    drop(fill);
    assert_eq!(image.metadata()?.len(), BYTES);
    println!("SRX_EXT4_BYTES_ENFORCED {written} written, {BYTES} backing");
    std::fs::remove_file(fill_path)?;
    std::fs::write(
        prefix.join("retained"),
        b"private scratch still live",
    )?;
    record(16, "ext4-byte-exhaustion-checked", Some(number))?;

    // The duplicate root description intentionally retains the detached mount.
    drop(mount);
    record(
        17,
        "ext4-loop-release-with-root-held-intent",
        Some(number),
    )?;
    assert_eq!(binding.release()?, Observation::ExpectedBinding);
    drop(binding);
    let mut text = String::new();
    File::open(prefix.join("retained"))?.read_to_string(&mut text)?;
    assert_eq!(text, "private scratch still live");
    drop(root);
    wait_for_teardown(number)?;
    record(
        18,
        "ext4-final-root-close-and-teardown-observed",
        Some(number),
    )?;
    if isolated {
        isolated_tool(&checker, &image, Operation::Check, "check-after")?;
    } else {
        run_tool(
            &checker,
            &["-f", "-n", image_path.to_str().unwrap()],
        )?;
    }
    record(19, "ext4-final-check-passed", Some(number))?;
    println!("SRX_EXT4_PROBE_OK");
    if isolated {
        println!("SRX_EXT4_ISOLATED_TOOLS_OK");
    }
    Ok(())
}

fn isolated_tool(
    tool: &PinnedTool,
    image: &File,
    operation: Operation,
    stage: &str,
) -> io::Result<()> {
    let path = Path::new(DIRECTORY).join(stage);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)?;
    let directory = File::open(&path)?;
    let intent = serde_json::to_vec(&serde_json::json!({
        "version": 1, "operation": format!("{operation:?}"), "tool_sha256": tool.pin().sha256,
        "tool_bytes": tool.pin().size_bytes, "image_bytes": BYTES,
    }))?;
    let mut journal = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("intent.json"))?;
    journal.write_all(&intent)?;
    journal.sync_all()?;
    directory.sync_all()?;
    File::open(DIRECTORY)?.sync_all()?;
    let result = ext4_tool::run(tool, image, &directory, operation, || Ok(()))?;
    for (name, bytes) in [
        ("stdout", &result.stdout),
        ("stderr", &result.stderr),
    ] {
        let mut log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(name))?;
        log.write_all(bytes)?;
        log.sync_all()?;
        println!(
            "SRX_EXT4_TOOL_OUTPUT {stage} {name}: {}",
            String::from_utf8_lossy(bytes)
        );
    }
    directory.sync_all()?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "isolated {stage}: {}",
            result.status
        )));
    }
    println!("SRX_EXT4_TOOL_COMPLETED {stage}");
    Ok(())
}

fn tool(name: &str, size_bytes: u64, hex: &str) -> io::Result<PinnedTool> {
    let mut sha256 = [0; 32];
    for (index, byte) in sha256.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    PinnedTool::snapshot(
        File::open(format!("/usr/local/libexec/srx-probe/{name}"))?,
        ToolPin {
            sha256,
            size_bytes,
        },
        || Ok(()),
    )
}

fn run_tool(tool: &PinnedTool, arguments: &[&str]) -> io::Result<()> {
    let fd = tool.descriptor()?.as_raw_fd();
    let mut command = Command::new(format!("/proc/self/fd/{fd}"));
    command
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("MKE2FS_CONFIG", "/dev/null")
        .env("E2FSCK_CONFIG", "/dev/null")
        .stdin(Stdio::null());
    // SAFETY: runs only between fork/exec; fcntl is async-signal-safe. The parent
    // retains CLOEXEC, and the pinned descriptor stays owned through child wait.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "pinned tool exited {status}"
        )))
    }
}
