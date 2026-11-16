//! Actual dual-volume workspace limits, only in the guarded disposable guest.
//! The production helper's one-volume RPC is not used as a fake workspace RPC.

use super::{ROOT, Reap};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::{
            fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
            process::CommandExt as _,
        },
    },
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use syrox_system::{
    budget::{AdmittedBudget, BuildBudget, BuilderLimits},
    descriptor::pinned_tool::{PinnedTool, ToolPin},
    ext4_tool::{self, Geometry, Operation},
    loop_device::{LoopControl, ScratchLoop},
    workspace::{DetachedWorkspace, ReceivedWorkspace, WorkspaceLayout, WorkspaceObservation},
};

fn budget() -> BuildBudget {
    BuildBudget {
        memory_bytes: 134_217_728,
        cpu_percent: 100,
        processes: 16,
        descriptors: 128,
        scratch_bytes: 67_108_864,
        files: 1024,
        output_bytes: 134_217_728,
        duration_seconds: 180,
    }
}
fn admission(request: BuildBudget) -> io::Result<AdmittedBudget> {
    BuilderLimits::new(request)
        .and_then(|p| p.admit(request))
        .map_err(io::Error::other)
}
fn layout() -> io::Result<WorkspaceLayout> {
    WorkspaceLayout::from_budget(&admission(budget())?)
}
fn case(name: &str) {
    println!("SRX_HELPER_CASE_OK workspace-{name}");
}

pub(super) fn root() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0
        || std::fs::read("/etc/srx-disposable-vm")? != b"srx-loop-fixture-v1\n"
        || std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim() != "QEMU"
    {
        return Err(io::Error::other(
            "workspace probe requires the marked disposable QEMU guest",
        ));
    }
    let directory = Path::new(ROOT).join("workspace-private");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)?;
    let plan = layout()?;
    assert_eq!(
        (
            plan.scratch_geometry().requested_inodes(),
            plan.output_geometry().requested_inodes()
        ),
        (336, 672)
    );
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
    let scratch_image = image(&directory, "scratch.img", plan.scratch_geometry())?;
    let output_image = image(&directory, "output.img", plan.output_geometry())?;
    for (name, image, geometry) in [
        ("scratch", &scratch_image, plan.scratch_geometry()),
        ("output", &output_image, plan.output_geometry()),
    ] {
        run(
            &formatter,
            image,
            Operation::Format(geometry),
            &directory,
            &format!("{name}-format"),
        )?;
        run(
            &checker,
            image,
            Operation::Check,
            &directory,
            &format!("{name}-before"),
        )?;
    }
    let (mut scratch, scratch_number) = binding(&scratch_image, plan.scratch_geometry())?;
    let (mut output, output_number) = binding(&output_image, plan.output_geometry())?;
    assert!(DetachedWorkspace::mount(&plan, &scratch, &scratch, || Ok(())).is_err());
    // Distinct block devices can still alias the same regular image. Use an
    // equal-size layout so a size mismatch cannot mask the alias check.
    let equal = WorkspaceLayout::from_budget(&admission(BuildBudget {
        output_bytes: budget().scratch_bytes,
        files: 672,
        ..budget()
    })?)?;
    let (mut alias, alias_number) = binding(&scratch_image, plan.scratch_geometry())?;
    assert!(DetachedWorkspace::mount(&equal, &scratch, &alias, || Ok(())).is_err());
    alias.release()?;
    drop(alias);
    teardown(alias_number)?;
    case("alias-image-refused");
    let mut intent = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("mount-intent.json"))?;
    serde_json::to_writer(
        &mut intent,
        &serde_json::json!({"layout":plan.digest(),"scratch_loop":scratch_number,"output_loop":output_number}),
    )?;
    intent.sync_all()?;
    File::open(&directory)?.sync_all()?;
    let workspace = DetachedWorkspace::mount(&plan, &scratch, &output, || Ok(()))?;
    assert!(workspace.assign_owner(0, 1000).is_err());
    workspace.assign_owner(1000, 1000)?;
    let observed = workspace.observation()?;
    assert_eq!(
        observed.scratch.inodes + observed.output.inodes,
        1008
    );
    let mut observation = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(Path::new(ROOT).join("workspace-observation.json"))?;
    serde_json::to_writer(&mut observation, &observed)?;
    observation.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    observation.sync_all()?;
    case("pair-mounted");
    let scratch_root = File::from(workspace.scratch_root()?.try_clone_to_owned()?);
    let output_root = File::from(workspace.output_root()?.try_clone_to_owned()?);
    let left = scratch_root.as_raw_fd();
    let right = output_root.as_raw_fd();
    assert!(left > 4 && right > 4);
    let mut command = Command::new(Path::new(ROOT).join("client"));
    command.arg("--workspace-namespace");
    // SAFETY: fixed FD mapping and identity drop after fork; CLOEXEC on every
    // unrelated inherited descriptor prevents a false retention/teardown proof.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) < 0
                || libc::dup2(left, 3) < 0
                || libc::dup2(right, 4) < 0
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
                || libc::fcntl(4, libc::F_SETFD, 0) < 0
                || libc::setgroups(0, std::ptr::null()) < 0
                || libc::setgid(1000) < 0
                || libc::setuid(1000) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = Reap(command.spawn()?);
    assert!(
        child.0.wait()?.success(),
        "workspace namespace worker"
    );
    workspace.observation()?;
    drop(output_root);
    drop(workspace);
    scratch.release()?;
    output.release()?;
    drop(output);
    teardown(output_number)?;
    // Only scratch is deliberately held; output must already be fully removed.
    assert_eq!(
        std::fs::read(format!(
            "/proc/self/fd/{}/sentinel",
            scratch_root.as_raw_fd()
        ))?,
        b"scratch remains live"
    );
    drop(scratch_root);
    drop(scratch);
    teardown(scratch_number)?;
    case("loop-release-independent");
    run(
        &checker,
        &scratch_image,
        Operation::Check,
        &directory,
        "scratch-after",
    )?;
    run(
        &checker,
        &output_image,
        Operation::Check,
        &directory,
        "output-after",
    )?;
    assert_eq!(
        scratch_image.metadata()?.len(),
        budget().scratch_bytes
    );
    assert_eq!(
        output_image.metadata()?.len(),
        budget().output_bytes
    );
    println!("SRX_WORKSPACE_PROBE_OK");
    Ok(())
}

pub(super) fn worker() -> io::Result<()> {
    assert_eq!(
        (
            unsafe { libc::getuid() },
            unsafe { libc::geteuid() },
            unsafe { libc::getgid() },
            unsafe { libc::getegid() }
        ),
        (1000, 1000, 1000, 1000)
    );
    assert_eq!(
        std::fs::metadata("/etc/srx-disposable-vm")?.uid(),
        0
    );
    assert_eq!(
        std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim(),
        "QEMU"
    );
    // SAFETY: the guarded parent uniquely assigns these two inherited roles.
    let scratch = unsafe { File::from_raw_fd(3) };
    let output = unsafe { File::from_raw_fd(4) };
    let plan = layout()?;
    let observed: WorkspaceObservation = serde_json::from_slice(&std::fs::read(
        Path::new(ROOT).join("workspace-observation.json"),
    )?)?;
    assert!(
        ReceivedWorkspace::from_authorized_roots(
            &plan,
            &observed,
            output.try_clone()?,
            scratch.try_clone()?
        )
        .is_err()
    );
    let mut mixed = observed;
    std::mem::swap(
        &mut mixed.scratch.device,
        &mut mixed.output.device,
    );
    assert!(
        ReceivedWorkspace::from_authorized_roots(
            &plan,
            &mixed,
            scratch.try_clone()?,
            output.try_clone()?
        )
        .is_err()
    );
    case("role-observation-refused");
    let received = ReceivedWorkspace::from_authorized_roots(
        &plan,
        &observed,
        scratch.try_clone()?,
        output.try_clone()?,
    )?;
    let base = Path::new(ROOT).join(format!(
        "client-state/workspace-{}",
        std::process::id()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&base)?;
    for name in ["scratch", "output"] {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(base.join(name))?;
    }
    namespace()?;
    let invalid = ReceivedWorkspace::from_authorized_roots(&plan, &observed, scratch, output)?;
    // SAFETY: this dedicated worker owns its private namespace and discards it
    // after every error. Both aliases must fail before the first move.
    assert!(
        unsafe {
            invalid.attach(
                File::open(base.join("scratch"))?,
                File::open(base.join("scratch"))?,
                || Ok(()),
            )
        }
        .is_err()
    );
    assert_ne!(
        File::open(base.join("scratch"))?
            .metadata()?
            .dev(),
        observed.scratch.device
    );
    case("target-alias-refused");
    // SAFETY: the same private, single-threaded namespace and distinct empty
    // pinned targets; any failure terminates the executable/namespace.
    let attached = unsafe {
        received.attach(
            File::open(base.join("scratch"))?,
            File::open(base.join("output"))?,
            || Ok(()),
        )
    }?;
    for (name, expected) in [
        ("scratch", observed.scratch),
        ("output", observed.output),
    ] {
        let actual = File::open(base.join(name))?.metadata()?;
        assert_eq!(
            (actual.dev(), actual.ino()),
            (expected.device, expected.inode)
        );
    }
    drop_capabilities()?;
    let scratch = base.join("scratch");
    let output = base.join("output");
    assert!(fill_bytes(&scratch, budget().scratch_bytes)? > 0);
    case("bytes-scratch");
    assert!(fill_bytes(&output, budget().output_bytes)? > 0);
    case("bytes-output");
    // Filesystem byte limits are allocated-space limits. Sparse logical sizes
    // need the worker's separate RLIMIT_FSIZE/aggregate result checks.
    let sparse = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output.join("sparse"))?;
    sparse.set_len(budget().output_bytes * 2)?;
    assert!(sparse.metadata()?.len() > budget().output_bytes);
    drop(sparse);
    std::fs::remove_file(output.join("sparse"))?;
    let scratch_count = fill_inodes(&scratch, observed.scratch.inodes)?;
    case("inodes-scratch");
    std::fs::write(
        output.join("independent"),
        b"output remains writable",
    )?;
    let output_count = fill_inodes(&output, observed.output.inodes)?;
    case("inodes-output");
    assert!(scratch_count + output_count <= budget().files);
    // Modify an existing inode after exhaustion; no extra inode is required.
    std::fs::write(scratch.join("sentinel"), b"scratch remains live")?;
    File::open(&scratch)?.sync_all()?;
    File::open(&output)?.sync_all()?;
    attached.revalidate()?;
    case("private-namespace");
    Ok(())
}

fn image(directory: &Path, name: &str, geometry: Geometry) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))?;
    file.set_len(geometry.image_bytes())?;
    file.sync_all()?;
    Ok(file)
}
fn tool(name: &str, bytes: u64, pin: &str) -> io::Result<PinnedTool> {
    let mut sha = [0; 32];
    for (index, byte) in sha.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&pin[index * 2..index * 2 + 2], 16).map_err(io::Error::other)?;
    }
    PinnedTool::snapshot(
        File::open(Path::new(ROOT).join(name))?,
        ToolPin {
            sha256: sha,
            size_bytes: bytes,
        },
        || Ok(()),
    )
}
fn run(
    tool: &PinnedTool,
    image: &File,
    operation: Operation,
    directory: &Path,
    name: &str,
) -> io::Result<()> {
    let path = directory.join(name);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)?;
    let result = ext4_tool::run(tool, image, &File::open(path)?, operation, || {
        Ok(())
    })?;
    assert!(
        result.status.success(),
        "workspace tool {name}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
fn binding(image: &File, geometry: Geometry) -> io::Result<(ScratchLoop, u32)> {
    let control = LoopControl::from_file(open_device(Path::new("/dev/loop-control"))?)?;
    let number = control.select_free()?;
    let path = PathBuf::from(format!("/dev/loop{number}"));
    let deadline = Instant::now() + Duration::from_secs(5);
    let device = loop {
        match open_device(&path) {
            Ok(file) => break file,
            Err(e) if e.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    };
    let mut binding = ScratchLoop::prepare(
        device,
        number,
        image.try_clone()?,
        geometry.image_bytes(),
    )?;
    binding.configure()?;
    Ok((binding, number))
}
fn teardown(number: u32) -> io::Result<()> {
    let base = PathBuf::from(format!("/sys/dev/block/7:{number}"));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !base.join("loop/backing_file").try_exists()?
            && std::fs::read(base.join("size"))? == b"0\n"
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn open_device(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}
fn fill_bytes(root: &Path, maximum: u64) -> io::Result<u64> {
    let path = root.join("fill");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_DSYNC)
        .open(&path)?;
    let buffer = vec![0x5a; 1024 * 1024];
    let mut written = 0;
    loop {
        match file.write(&buffer) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                written += n as u64;
                assert!(written <= maximum);
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    drop(file);
    std::fs::remove_file(path)?;
    Ok(written)
}
fn fill_inodes(root: &Path, maximum: u64) -> io::Result<u64> {
    std::fs::write(root.join("sentinel"), b"existing inode")?;
    let mut count = 1;
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(format!("inode-{count}")))
        {
            Ok(file) => {
                drop(file);
                count += 1;
                assert!(count <= maximum);
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => break,
            Err(e) => return Err(e),
        }
    }
    assert!(count > 1);
    Ok(count)
}
fn namespace() -> io::Result<()> {
    // SAFETY: this is the guarded, dedicated, single-threaded UID/GID-1000 child.
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
        || unsafe {
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
    Ok(())
}
fn drop_capabilities() -> io::Result<()> {
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
    Ok(())
}
