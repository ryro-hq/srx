use super::{ID, ROOT, file_digest, spawn_client, write_policy};
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use syrox_system::helper_activation::{
    HelperActivation, HelperServiceLimits, SERVICE_UNIT, SOCKET_UNIT,
};
use syrox_system::{
    budget::{BuildBudget, BuilderLimits},
    helper_client::HelperClient,
};

const ENDPOINT: &str = "/run/syrox-system-helper-probe.sock";
const MARKER: &str = "/etc/srx-helper-activation-forbidden";

pub(super) fn root() -> io::Result<()> {
    // These are private copies already verified by the guarded root driver.
    // Give installed executables the same explicit guest label as the payload.
    for name in [
        "client",
        "syrox-system-helper",
        "srx",
        "system-scratch-tests",
    ] {
        label(&Path::new(ROOT).join(name))?;
    }
    let state = Path::new(ROOT).join("state-activated");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)?;
    let policy = write_policy("activated-namespace", &state, 1000)?;
    install(&state, policy, true)?;
    run_client("activated-namespace", true)?;
    let image = state.join(format!("op-{ID}/scratch.img"));
    let before = file_digest(&image)?;
    for name in [
        "activated-replay",
        "activated-over-budget",
    ] {
        run_client(name, false)?;
        assert_eq!(file_digest(&image)?, before);
        assert_eq!(std::fs::read_dir(&state)?.count(), 1);
    }
    systemctl(&["stop", SOCKET_UNIT])?;
    let state = Path::new(ROOT).join("state-activated-wrong-peer");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)?;
    let policy = write_policy("activated-wrong-peer", &state, 1001)?;
    install(&state, policy, false)?;
    run_client("activated-wrong-peer", false)?;
    assert_eq!(std::fs::read_dir(state)?.count(), 0);
    systemctl(&["stop", SOCKET_UNIT])?;
    let state = Path::new(ROOT).join("state-activated-recover");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)?;
    let policy = write_policy("typed-disconnect", &state, 1000)?;
    install(&state, policy, false)?;
    run_client("typed-disconnect", false)?;
    super::recover_cli::run(&state, ENDPOINT)?;
    systemctl(&["stop", SOCKET_UNIT])?;
    engine_scratch()?;
    println!("SRX_HELPER_ACTIVATION_PROBE_OK");
    Ok(())
}

fn engine_scratch() -> io::Result<()> {
    use std::os::unix::process::CommandExt as _;
    let state = Path::new(ROOT).join("state-system-component");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)?;
    let policy = write_policy("system-component", &state, 1000)?;
    install(&state, policy, false)?;
    let mut command = Command::new(Path::new(ROOT).join("system-scratch-tests"));
    command.args([
        "--exact",
        "build::system::tests::scratch::disposable_vm_system_scratch_uses_prepared_action_and_private_helper",
        "--ignored", "--nocapture", "--test-threads=1",
    ]);
    command
        .env_clear()
        .env("PATH", "")
        .env("HOME", Path::new(ROOT).join("client-state"));
    // SAFETY: fixed non-root identity drop and CLOEXEC-only fd policy after fork.
    unsafe {
        command.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) < 0
                || libc::setgid(1000) < 0
                || libc::setuid(1000) < 0
                || libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("{stdout}");
    eprintln!("{stderr}");
    assert!(
        output.status.success(),
        "engine scratch test: {}",
        output.status
    );
    assert!(stdout.contains("SRX_SYSTEM_COMPONENT_SCRATCH_OK "));
    let operation = state.join("op-88888888888888888888888888888888");
    let names = std::fs::read_dir(&operation)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    assert!(names.iter().any(|n| {
        n.to_str()
            .is_some_and(|n| n.ends_with("-released.json"))
    }));
    assert!(!names.iter().any(|n| {
        n.to_str()
            .is_some_and(|n| n.ends_with("-uncertain.json"))
    }));
    super::wait_operation_teardown(&operation)?;
    assert!(operation.join("scratch.img").is_file());
    systemctl(&["stop", SOCKET_UNIT])?;
    println!("SRX_HELPER_CASE_OK engine-system-component-scratch");
    Ok(())
}

fn install(state: &Path, policy: PathBuf, first: bool) -> io::Result<()> {
    let units = HelperActivation {
        executable: Path::new(ROOT).join("syrox-system-helper"),
        policy,
        state_directory: state.to_owned(),
        socket: ENDPOINT.into(),
        socket_group: 1000,
        limits: HelperServiceLimits {
            memory_bytes: 536_870_912,
            cpu_percent: 100,
            processes: 8,
            descriptors: 128,
            duration_seconds: 600,
            connections: 4,
        },
    }
    .render()?;
    // Test-only oracle runs under exactly the generated service restrictions.
    // It is a pinned fixture executable, never a project-provided command.
    let service = format!(
        "{}ExecStartPre=:{ROOT}/client --activation-enforcement\n",
        units.service
    );
    for (name, contents) in [
        (SOCKET_UNIT, units.socket),
        (SERVICE_UNIT, service),
    ] {
        let path = Path::new("/run/systemd/system").join(name);
        let mut options = OpenOptions::new();
        options
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        if first {
            options.create_new(true);
        } else {
            options.truncate(true);
        }
        let mut file = options.open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    File::open("/run/systemd/system")?.sync_all()?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["start", SOCKET_UNIT])?;
    let m = std::fs::metadata(ENDPOINT)?;
    assert_eq!(
        (m.uid(), m.gid(), m.mode() & 0o7777),
        (0, 1000, 0o660)
    );
    Ok(())
}

fn systemctl(args: &[&str]) -> io::Result<String> {
    let output = Command::new("/usr/bin/systemctl")
        .args(args)
        .output()?;
    if output.stdout.len() + output.stderr.len() > 65_536 || !output.status.success() {
        return Err(io::Error::other(format!(
            "fixture systemctl failed: {} {}",
            output.status,
            String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(4096)])
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| io::Error::other("invalid fixture systemctl output"))
}

fn run_client(name: &str, observe: bool) -> io::Result<()> {
    let mut child = spawn_client(Path::new(ENDPOINT), name)?;
    if observe {
        wait(&Path::new(ROOT).join("client-state/activation-offered"))?;
        let observed = systemctl(&[
            "show",
            "--no-pager",
            "--property=MainPID,ControlGroup,MemoryMax,TasksMax,LimitNOFILE,NoNewPrivileges,PrivateNetwork,ProtectSystem,DevicePolicy",
            "syrox-system-helper@*.service",
        ])?;
        for expected in [
            "MemoryMax=536870912",
            "TasksMax=8",
            "LimitNOFILE=128",
            "NoNewPrivileges=yes",
            "PrivateNetwork=yes",
            "ProtectSystem=strict",
            "DevicePolicy=closed",
        ] {
            assert!(
                observed.lines().any(|line| line == expected),
                "missing {expected}: {observed}"
            );
        }
        let group = observed
            .lines()
            .find_map(|line| line.strip_prefix("ControlGroup="))
            .unwrap();
        assert!(
            group.starts_with("/system.slice/")
                && !group.contains("..")
                && !group.chars().any(char::is_control)
        );
        let base = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
        assert_eq!(
            std::fs::read(base.join("memory.max"))?,
            b"536870912\n"
        );
        assert_eq!(std::fs::read(base.join("pids.max"))?, b"8\n");
        let cpu = std::fs::read_to_string(base.join("cpu.max"))?;
        let values = cpu.split_whitespace().collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert_ne!(values[0], "max");
        assert_eq!(values[0], values[1]); // exactly one CPU, independently of period.
        let pid: u32 = observed
            .lines()
            .find_map(|line| line.strip_prefix("MainPID="))
            .unwrap()
            .parse()
            .unwrap();
        assert!(pid > 1);
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits"))?;
        let descriptors = limits
            .lines()
            .find(|line| line.starts_with("Max open files"))
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(&descriptors[3..5], &["128", "128"]);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(Path::new(ROOT).join("client-state/activation-observed"))?
            .sync_all()?;
        println!("SRX_HELPER_ACTIVATION_KERNEL_LIMITS_OK");
    }
    assert!(
        child.0.wait()?.success(),
        "activated client {name}"
    );
    println!("SRX_HELPER_CASE_OK {name}");
    Ok(())
}

pub(super) fn offered() -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(Path::new(ROOT).join("client-state/activation-offered"))?
        .sync_all()?;
    wait(&Path::new(ROOT).join("client-state/activation-observed"))
}

pub(super) fn typed_client(endpoint: &Path, case: &str) -> io::Result<()> {
    let request: BuildBudget = serde_json::from_value(super::budget())?;
    let budget = BuilderLimits::new(request)
        .map_err(io::Error::other)?
        .admit(request)
        .map_err(io::Error::other)?;
    let deadline = Instant::now() + Duration::from_secs(180);
    let client = HelperClient::connect(endpoint, || Ok(()), deadline)?;
    let grant = client.prepare(ID, &budget, || Ok(()), deadline)?;
    assert!(grant.capacity().filesystem_bytes <= request.scratch_bytes);
    let (root, lease) = grant.into_parts();
    assert_eq!(*lease.budget(), request);
    if case == "activated-namespace" {
        offered()?;
        super::namespace_worker(&root)?;
        drop(root);
        let receipt = lease.release(|| Ok(()), deadline)?;
        assert_eq!(receipt["state"], "released");
        println!("SRX_HELPER_TYPED_CLIENT_RELEASE_OK");
    } else {
        assert_eq!(case, "typed-disconnect");
        let path = format!("/proc/self/fd/{}/typed-proof", root.as_raw_fd());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(b"typed client retained data")?;
        file.sync_all()?;
        drop(file);
        drop(root);
        drop(lease); // Deliberate disconnect: never an automatic successful release.
        println!("SRX_HELPER_TYPED_CLIENT_DISCONNECTED");
    }
    Ok(())
}

fn wait(path: &Path) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.try_exists()? {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn label(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let context = b"system_u:object_r:bin_t:s0\0";
    // SAFETY: fixed label on a root-owned private fixture copy; bounded bytes.
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            context.as_ptr().cast(),
            context.len(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn enforcement() -> io::Result<()> {
    // This mode can only exercise writes/devices in the marked disposable VM.
    // SAFETY: fixed read-only identity observation.
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(
        std::fs::read("/etc/srx-disposable-vm")?,
        b"srx-loop-fixture-v1\n"
    );
    assert_eq!(
        std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim(),
        "QEMU"
    );
    let denied = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/dev/vda");
    assert_eq!(
        denied.unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
    let denied = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(MARKER);
    assert_eq!(
        denied.unwrap_err().raw_os_error(),
        Some(libc::EROFS)
    );
    println!("SRX_HELPER_ACTIVATION_DEVICE_AND_WRITE_DENIED");
    Ok(())
}
