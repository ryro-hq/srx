//! Root/client qualification of the private-scratch helper in a disposable VM.
//!
//! This fixture creates only its own regular images and Unix sockets. It never
//! selects a physical disk or changes boot; the root mode requires the same
//! explicit QEMU marker as the loop qualification fixture.

#![allow(unsafe_code)]

use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, chown,
};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use syrox_system::descriptor::{self, sealed};

#[path = "helper_probe/activation.rs"]
mod activation;
#[path = "helper_probe/plan_cli.rs"]
mod plan_cli;
#[path = "helper_probe/recover_cli.rs"]
mod recover_cli;
#[path = "helper_probe/workspace.rs"]
mod workspace;
#[path = "helper_probe/workspace_rpc.rs"]
mod workspace_rpc;

const ROOT: &str = "/var/tmp/srx-helper-probe";
const TOOLS: &str = "/usr/local/libexec/srx-probe";
const ID: &str = "0123456789abcdef0123456789abcdef";

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = if args.len() == 3 && args[0] == "--client" {
        if args[2].starts_with("workspace-rpc-") {
            workspace_rpc::client(Path::new(&args[1]), &args[2])
        } else {
            client(Path::new(&args[1]), &args[2])
        }
    } else if args == ["--scratch-namespace"] {
        scratch_namespace()
    } else if args == ["--activation-enforcement"] {
        activation::enforcement()
    } else if args == ["--workspace-namespace"] {
        workspace::worker()
    } else if args == ["--disposable-vm"] {
        root()
    } else {
        Err(io::Error::other("expected --disposable-vm"))
    };
    if let Err(error) = result {
        eprintln!("SRX_HELPER_PROBE_FAILED: {error}");
        std::process::exit(1);
    }
}

fn root() -> io::Result<()> {
    // SAFETY: only observes the effective identity.
    if unsafe { libc::geteuid() } != 0
        || std::fs::read("/etc/srx-disposable-vm")? != b"srx-loop-fixture-v1\n"
        || std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim() != "QEMU"
    {
        return Err(io::Error::other(
            "helper root probe requires the marked disposable QEMU VM",
        ));
    }
    std::fs::DirBuilder::new()
        .mode(0o711)
        .create(ROOT)?;
    let client_state = Path::new(ROOT).join("client-state");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&client_state)?;
    chown(client_state, Some(1000), Some(1000))?;
    copy(
        &std::env::current_exe()?,
        &Path::new(ROOT).join("client"),
        None,
    )?;
    for (name, pin) in [
        (
            "mke2fs",
            "59935ec5c57f7f3b2e5ef1119d7480275264a9f5adecb862b7bd2ae813fd83ec",
        ),
        (
            "e2fsck",
            "da1f6de6ac3a2efd7fc6d2581199ce7109a22dee7843ce923e4111a92666a95a",
        ),
        (
            "syrox-system-helper",
            "4d7def7357daf815339742f78deeb205ce1009a253e3cb026c08aec8815e7eb1",
        ),
        (
            "srx",
            "011543d12c43d65b5a6af61ca3d0b655cc90f0b42560f7b0045d87375524ca88",
        ),
        (
            "system-scratch-tests",
            "a78e7f4bd7cd7fdea825a19b9892ebce1a5b4e1e46da0deb72cb4589faa4c341",
        ),
    ] {
        copy(
            &Path::new(TOOLS).join(name),
            &Path::new(ROOT).join(name),
            Some(pin),
        )?;
    }
    let state = Path::new(ROOT).join("state");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)?;
    case("positive", &state, 1000, true)?;
    let image = state.join(format!("op-{ID}/scratch.img"));
    let before = file_digest(&image)?;
    case("replay", &state, 1000, false)?;
    assert_eq!(before, file_digest(&image)?);
    println!("SRX_HELPER_REPLAY_PRESERVED_IMAGE");
    for (name, uid) in [
        ("wrong-peer", 1001),
        ("unknown-field", 1000),
        ("over-budget", 1000),
    ] {
        let state = Path::new(ROOT).join(format!("state-{name}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)?;
        case(name, &state, uid, false)?;
        assert_eq!(std::fs::read_dir(&state)?.count(), 0);
        println!("SRX_HELPER_NO_EFFECTS {name}");
    }
    let state = Path::new(ROOT).join("state-disconnect");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)?;
    case("disconnect", &state, 1000, false)?;
    wait_teardown(&state)?;
    let image = state.join(format!("op-{ID}/scratch.img"));
    let before = file_digest(&image)?;
    case("after-disconnect", &state, 1000, false)?;
    assert_eq!(before, file_digest(&image)?);
    assert_eq!(std::fs::read_dir(&state)?.count(), 1);
    println!("SRX_HELPER_UNCERTAIN_REFUSED_REFORMAT");
    let count = std::fs::read_dir(state.join(format!("op-{ID}")))?.count();
    case("inspect-quiescent", &state, 1000, true)?;
    assert_eq!(
        std::fs::read_dir(state.join(format!("op-{ID}")))?.count(),
        count
    );
    case("recover-wrong-hash", &state, 1000, false)?;
    // Simulate additional durable evidence arriving after the first inspection.
    let operation = state.join(format!("op-{ID}"));
    let sequence = std::fs::read_dir(&operation)?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|e| e == "json"))
        .count();
    let mut extra = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(operation.join(format!("{sequence:04}-uncertain.json")))?;
    extra.write_all(b"{\"version\":1,\"state\":\"uncertain\",\"details\":{\"error\":\"qualification: additional evidence\"}}\n")?;
    extra.sync_all()?;
    File::open(&operation)?.sync_all()?;
    case("recover-stale", &state, 1000, false)?;
    case("inspect-refreshed", &state, 1000, true)?;
    case("recover-valid", &state, 1000, true)?;
    assert_eq!(before, file_digest(&image)?);
    case("replay-reconciled", &state, 1000, false)?;
    assert_eq!(before, file_digest(&image)?);
    case("after-reconcile", &state, 1000, true)?;
    assert_eq!(before, file_digest(&image)?);
    println!("SRX_HELPER_RECOVERY_RETAINED_IMAGE");

    let state = Path::new(ROOT).join("state-retained");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)?;
    case("retain", &state, 1000, false)?;
    wait_teardown(&state)?;
    case("inspect-after-retained", &state, 1000, true)?;
    case("recover-after-retained", &state, 1000, true)?;
    println!("SRX_HELPER_RETAINED_DESCRIPTOR_RECOVERY_OK");
    let state = Path::new(ROOT).join("state-namespace");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)?;
    case("namespace", &state, 1000, true)?;
    activation::root()?;
    plan_cli::run()?;
    workspace::root()?;
    workspace_rpc::root()?;
    println!("SRX_HELPER_PROBE_OK");
    Ok(())
}

fn copy(source: &Path, target: &Path, pin: Option<&str>) -> io::Result<()> {
    if let Some(pin) = pin {
        assert_eq!(file_digest(source)?, pin);
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o555)
        .open(target)?;
    io::copy(&mut input, &mut output)?;
    output.set_permissions(std::fs::Permissions::from_mode(0o555))?;
    output.sync_all()?;
    Ok(())
}

fn file_digest(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = vec![0; 65_536];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hash.update(&bytes[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn budget() -> serde_json::Value {
    serde_json::json!({ "memory_bytes": 134_217_728, "cpu_percent": 100, "processes": 16,
        "descriptors": 128, "scratch_bytes": 67_108_864, "files": 512, "output_bytes": 1_048_576, "duration_seconds": 180 })
}

fn write_policy(name: &str, state: &Path, uid: u32) -> io::Result<PathBuf> {
    let policy = Path::new(ROOT).join(format!("policy-{name}.json"));
    let body = serde_json::json!({ "version": 1, "client_uid": uid, "client_gid": 1000,
        "maximum": budget(), "maximum_operations": 4, "state_directory": state,
        "formatter": { "path": Path::new(ROOT).join("mke2fs"), "size_bytes": 1_735_200, "sha256": "59935ec5c57f7f3b2e5ef1119d7480275264a9f5adecb862b7bd2ae813fd83ec" },
        "checker": { "path": Path::new(ROOT).join("e2fsck"), "size_bytes": 2_093_768, "sha256": "da1f6de6ac3a2efd7fc6d2581199ce7109a22dee7843ce923e4111a92666a95a" } });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&policy)?;
    file.write_all(&serde_json::to_vec(&body)?)?;
    file.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    Ok(policy)
}

fn case(name: &str, state: &Path, uid: u32, success: bool) -> io::Result<()> {
    let policy = write_policy(name, state, uid)?;
    let path = Path::new(ROOT).join(format!("{name}.sock"));
    let listener = listener(&path)?;
    let mut client = spawn_client(&path, name)?;
    let socket = accept(&listener, &mut client.0)?;
    let raw = socket.as_raw_fd();
    let mut helper = Command::new(Path::new(ROOT).join("syrox-system-helper"));
    helper
        .arg("--policy")
        .arg(policy)
        .stdin(Stdio::null());
    // SAFETY: only the accepted connection is passed to the helper on fd 3.
    unsafe {
        helper.pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 4_u32) < 0
                || (raw != 3 && libc::dup2(raw, 3) < 0)
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut helper = Reap(helper.spawn()?);
    drop(socket);
    if name == "retain" {
        assert!(!helper.0.wait()?.success());
        case("inspect-retained", state, 1000, true)?;
        case("recover-retained", state, 1000, false)?;
        let marker = Path::new(ROOT).join("client-state/release-retained");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(marker)?
            .sync_all()?;
    }
    assert!(client.0.wait()?.success(), "client case {name}");
    assert_eq!(
        helper.0.wait()?.success(),
        success,
        "helper case {name}"
    );
    println!("SRX_HELPER_CASE_OK {name}");
    Ok(())
}

fn spawn_client(path: &Path, name: &str) -> io::Result<Reap> {
    let mut client = Command::new(Path::new(ROOT).join("client"));
    client
        .arg("--client")
        .arg(path)
        .arg(name)
        .stdin(Stdio::null());
    // SAFETY: only fixed identity/FD syscalls execute after fork. The client
    // creates its socket AFTER dropping privileges, so SO_PEERCRED observes 1000.
    unsafe {
        client.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) < 0
                || libc::setgid(1000) < 0
                || libc::setuid(1000) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(Reap(client.spawn()?))
}

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn socket_address(path: &Path) -> io::Result<(libc::sockaddr_un, u32)> {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: zero is a valid sockaddr_un storage; terminated pathname follows.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = u16::try_from(libc::AF_UNIX).unwrap();
    if bytes.len() >= address.sun_path.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = i8::from_ne_bytes([*source]);
    }
    Ok((
        address,
        u32::try_from(std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1).unwrap(),
    ))
}

fn socket() -> io::Result<OwnedFd> {
    // SAFETY: fixed local seqpacket socket with close-on-exec; no network.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: newly created descriptor has no other owner.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn listener(path: &Path) -> io::Result<OwnedFd> {
    let socket = socket()?;
    let (address, bytes) = socket_address(path)?;
    // SAFETY: exact initialized local pathname address and bounded backlog.
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            bytes,
        )
    } < 0
        || unsafe { libc::listen(socket.as_raw_fd(), 4) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(socket)
}

fn accept(listener: &OwnedFd, client: &mut Child) -> io::Result<OwnedFd> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        // SAFETY: no address output is requested; successful result is fresh.
        let raw = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err(error);
        }
        if Instant::now() >= deadline || client.try_wait()?.is_some() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn send(socket: &OwnedFd, body: &serde_json::Value) -> io::Result<()> {
    // SAFETY: fixed anonymous protocol staging file; no path or privilege gain.
    let raw = unsafe { libc::memfd_create(c"srx-helper-client".as_ptr(), libc::MFD_CLOEXEC) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut source = unsafe { File::from_raw_fd(raw) };
    source.write_all(&serde_json::to_vec(body)?)?;
    source.rewind()?;
    let snapshot = sealed::snapshot_secret(source, 65_536, || Ok(()))?;
    descriptor::send_fd(socket.as_fd(), snapshot.as_fd())
}

fn receive(socket: &OwnedFd) -> io::Result<OwnedFd> {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        match descriptor::receive_fd(socket.as_fd()) {
            Ok(fd) => return Ok(fd),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn response(socket: &OwnedFd) -> io::Result<serde_json::Value> {
    let file = File::from(receive(socket)?);
    sealed::validate_secret_owned(file.as_fd(), 0)?;
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::from)
}

fn wait_teardown(state: &Path) -> io::Result<()> {
    let operation = state.join(format!("op-{ID}"));
    wait_operation_teardown(&operation)
}

fn wait_operation_teardown(operation: &Path) -> io::Result<()> {
    let offered = std::fs::read_dir(operation)?
        .find_map(|entry| {
            let entry = entry.ok()?;
            entry
                .file_name()
                .to_str()?
                .ends_with("-offered.json")
                .then(|| entry.path())
        })
        .ok_or_else(|| io::Error::other("missing offered journal"))?;
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(offered)?)?;
    let number = value["details"]["loop_number"].as_u64().unwrap();
    let base = PathBuf::from(format!("/sys/dev/block/7:{number}"));
    for _ in 0..200 {
        if !base.join("loop/backing_file").try_exists()?
            && std::fs::read(base.join("size"))? == b"0\n"
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(io::ErrorKind::TimedOut.into())
}

fn client(path: &Path, case: &str) -> io::Result<()> {
    // SAFETY: verify the separate unprivileged process actually has the intended IDs.
    assert_eq!(unsafe { libc::geteuid() }, 1000);
    assert_eq!(unsafe { libc::getegid() }, 1000);
    assert!(File::open(Path::new(ROOT).join(format!("policy-{case}.json"))).is_err());
    if case == "activated-namespace" || case.starts_with("typed-") {
        return activation::typed_client(path, case);
    }
    let socket = socket()?;
    let (address, bytes) = socket_address(path)?;
    // SAFETY: exact bounded local address; the listener was created before spawn.
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            bytes,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    assert_eq!(
        descriptor::peer_credentials(socket.as_fd())?.uid,
        0
    );
    if case.starts_with("inspect-") || case.starts_with("recover-") {
        return recovery_client(&socket, case);
    }
    let mut request = serde_json::json!({ "operation": "prepare_scratch", "version": 1, "id": ID, "budget": budget() });
    if case == "unknown-field" {
        request["shell"] = serde_json::Value::from("unaccepted");
    }
    if case.ends_with("over-budget") {
        request["budget"]["scratch_bytes"] = serde_json::Value::from(67_112_960_u64);
    }
    let id = if matches!(case, "after-disconnect" | "after-reconcile") {
        request["id"] = serde_json::Value::from("abcdef0123456789abcdef0123456789");
        "abcdef0123456789abcdef0123456789"
    } else {
        ID
    };
    let sent = send(&socket, &request);
    if !matches!(
        case,
        "positive"
            | "disconnect"
            | "after-reconcile"
            | "retain"
            | "namespace"
            | "activated-namespace"
    ) {
        if sent.is_ok() {
            assert!(response(&socket).is_err());
        }
        println!("SRX_HELPER_CLIENT_REJECTED {case}");
        return Ok(());
    }
    sent?;
    let offered = response(&socket)?;
    assert_eq!(offered["state"], "offered");
    assert_eq!(offered["details"]["id"], id);
    let root = File::from(receive(&socket)?);
    assert!(root.metadata()?.is_dir());
    assert_eq!(root.metadata()?.uid(), 1000);
    if matches!(case, "namespace" | "activated-namespace") {
        namespace_worker(&root)?;
    }
    let path = PathBuf::from(format!(
        "/proc/self/fd/{}/client-proof",
        root.as_raw_fd()
    ));
    let mut proof = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    proof.write_all(b"unprivileged helper scratch")?;
    proof.sync_all()?;
    drop(proof);
    assert_eq!(
        std::fs::read(path)?,
        b"unprivileged helper scratch"
    );
    root.sync_all()?;
    if case == "retain" {
        // Keep the actual mounted filesystem alive after losing the session.
        // SAFETY: only stop sending on our connected Unix socket.
        if unsafe { libc::shutdown(socket.as_raw_fd(), libc::SHUT_WR) } < 0 {
            return Err(io::Error::last_os_error());
        }
        assert!(response(&socket).is_err());
        let deadline = Instant::now() + Duration::from_secs(30);
        while !Path::new(ROOT)
            .join("client-state/release-retained")
            .try_exists()?
        {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read(format!(
                "/proc/self/fd/{}/client-proof",
                root.as_raw_fd()
            ))?,
            b"unprivileged helper scratch"
        );
        drop(root);
        println!("SRX_HELPER_CLIENT_RETAINED_DESCRIPTOR_OK");
        return Ok(());
    }
    drop(root);
    if case == "disconnect" {
        println!("SRX_HELPER_CLIENT_DISCONNECTED");
        return Ok(());
    }
    send(
        &socket,
        &serde_json::json!({ "operation": "release_scratch", "version": 1, "id": id,
        "authorization": offered["details"]["authorization"] }),
    )?;
    let released = response(&socket)?;
    assert_eq!(released["state"], "released");
    println!("SRX_HELPER_CLIENT_OK");
    Ok(())
}

fn namespace_worker(root: &File) -> io::Result<()> {
    let raw = root.as_raw_fd();
    let mut child = Command::new(std::env::current_exe()?);
    child
        .arg("--scratch-namespace")
        .stdin(Stdio::null());
    // SAFETY: only the authorized directory crosses exec on fd 3. Helper
    // control and original-user-namespace descriptors remain in the coordinator.
    unsafe {
        child.pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 4_u32) < 0
                || (raw != 3 && libc::dup2(raw, 3) < 0)
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = Reap(child.spawn()?);
    assert!(
        child.0.wait()?.success(),
        "scratch namespace child"
    );
    assert_eq!(
        std::fs::read(format!(
            "/proc/self/fd/{}/namespace-proof",
            root.as_raw_fd()
        ))?,
        b"namespace worker scratch"
    );
    Ok(())
}

fn recovery_client(socket: &OwnedFd, case: &str) -> io::Result<()> {
    let directory = Path::new(ROOT).join("client-state");
    if case.starts_with("inspect-") {
        send(
            socket,
            &serde_json::json!({ "operation": "inspect_scratch", "version": 1, "id": ID }),
        )?;
        let plan = response(socket)?;
        let expected = if case == "inspect-retained" {
            "blocked"
        } else {
            "reconcile-retained-image"
        };
        assert_eq!(plan["plan"]["action"], expected);
        assert_eq!(plan["plan"]["filesystem_health_verified"], false);
        if case == "inspect-retained" {
            assert!(
                plan["plan"]["reasons"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::Value::from(
                        "recorded loop has not completed teardown"
                    ))
            );
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(case))?;
        file.write_all(&serde_json::to_vec(&plan)?)?;
        file.sync_all()?;
    } else {
        let source = match case {
            "recover-valid" => "inspect-refreshed",
            "recover-retained" => "inspect-retained",
            "recover-after-retained" => "inspect-after-retained",
            _ => "inspect-quiescent",
        };
        let plan: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join(source))?)?;
        let hash = if case == "recover-wrong-hash" {
            serde_json::Value::from("00".repeat(32))
        } else {
            plan["plan_sha256"].clone()
        };
        send(
            socket,
            &serde_json::json!({ "operation": "recover_scratch", "version": 1, "id": ID, "plan_sha256": hash }),
        )?;
        if matches!(case, "recover-valid" | "recover-after-retained") {
            let result = response(socket)?;
            assert_eq!(result["state"], "reconciled");
            assert_eq!(result["details"]["image_retained"], true);
            assert_eq!(
                result["details"]["filesystem_health_verified"],
                false
            );
        } else {
            assert!(response(socket).is_err());
        }
    }
    println!("SRX_HELPER_RECOVERY_CLIENT_OK {case}");
    Ok(())
}

fn scratch_namespace() -> io::Result<()> {
    use syrox_system::{
        budget::{BuildBudget, BuilderLimits},
        scratch::ReceivedScratch,
    };
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // The root qualification driver is the only creator of this guest marker.
    // SAFETY: observe credentials only, before any namespace or mount effect.
    assert_eq!(unsafe { libc::geteuid() }, 1000);
    assert_eq!(
        std::fs::metadata("/etc/srx-disposable-vm")?.uid(),
        0
    );
    assert_eq!(
        std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim(),
        "QEMU"
    );
    // SAFETY: child activation transfers the unique directory owner on fd 3.
    let root = unsafe { File::from_raw_fd(3) };
    let identity = root.metadata()?;
    assert!(identity.is_dir());
    assert_eq!(identity.uid(), 1000);
    assert_eq!(identity.mode() & 0o7777, 0o700);
    // This fixture's administrator policy and requested budget are fixed above;
    // the parent authenticated the root helper and sealed offered receipt.
    let request: BuildBudget = serde_json::from_value(budget())?;
    let admitted = BuilderLimits::new(request)
        .map_err(io::Error::other)?
        .admit(request)
        .map_err(io::Error::other)?;
    let received = ReceivedScratch::from_authorized_root(root, &admitted)?;
    let target = Path::new(ROOT).join(format!(
        "client-state/namespace-{}",
        std::process::id()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&target)?;
    // No effects in the parent's mount namespace. The same numeric non-root
    // uid/gid is mapped, matching the managed build worker's identity contract.
    // SAFETY: fresh, dedicated, single-threaded executable with fixed flags.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } < 0 {
        return Err(io::Error::last_os_error());
    }
    std::fs::write("/proc/self/uid_map", "1000 1000 1")?;
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/gid_map", "1000 1000 1")?;
    if unsafe {
        libc::unshare(
            libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this dedicated worker has just created its private user/mount
    // namespaces, made propagation private and opened the fresh target locally.
    // Every error exits the child and discards the namespace.
    let attached = unsafe { received.attach(File::open(&target)?, || Ok(())) }?;
    assert!(attached.capacity().filesystem_bytes <= request.scratch_bytes);
    assert!(attached.capacity().inodes <= request.files);
    assert_eq!(
        File::from(attached.root().try_clone_to_owned()?)
            .metadata()?
            .ino(),
        identity.ino()
    );
    let mounted = File::open(&target)?;
    let actual = mounted.metadata()?;
    assert_eq!(
        (identity.dev(), identity.ino()),
        (actual.dev(), actual.ino())
    );
    // SAFETY: writable fixed ABI output on the observed mount root.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(mounted.as_raw_fd(), &raw mut fs) } < 0 {
        return Err(io::Error::last_os_error());
    }
    assert_eq!(fs.f_type, 0xef53);
    let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(mounted.as_raw_fd(), &raw mut space) } < 0 {
        return Err(io::Error::last_os_error());
    }
    assert_eq!(
        space.f_flag & (libc::ST_NODEV | libc::ST_NOSUID | libc::ST_RDONLY),
        libc::ST_NODEV | libc::ST_NOSUID
    );
    // Fixed capability ABI: remove every permitted/effective/inheritable bit
    // before the worker writes. No initial-user-namespace privilege is gained.
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let caps = [Caps {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
        || unsafe { libc::syscall(libc::SYS_capset, &raw const header, caps.as_ptr()) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    assert!(std::fs::read_to_string("/proc/self/status")?.contains("CapEff:\t0000000000000000"));
    let mut proof = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target.join("namespace-proof"))?;
    proof.write_all(b"namespace worker scratch")?;
    proof.sync_all()?;
    mounted.sync_all()?;
    println!("SRX_HELPER_SCRATCH_NAMESPACE_OK");
    Ok(())
}
