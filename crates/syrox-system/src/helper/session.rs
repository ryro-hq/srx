use super::{
    journal::{self, Journal},
    policy::{self, Policy, refused},
    recovery,
    wire::{self, Request},
};
use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use syrox_system::{
    budget::BuilderLimits,
    descriptor::{self, FlockMode, PeerCredentials},
    ext4_tool::{self, Geometry, Operation},
    filesystem,
    loop_device::{LoopControl, ScratchLoop},
    scratch::DetachedScratch,
};

#[allow(
    clippy::needless_pass_by_value,
    reason = "The session owns its activation connection and selected administrator policy until settlement"
)]
pub(super) fn serve(socket: File, policy: Policy, policy_sha256: [u8; 32]) -> io::Result<()> {
    let peer = wire::authenticate(&socket, &policy)?;
    let request = wire::receive(
        &socket,
        peer,
        Instant::now() + Duration::from_secs(10),
    )?;
    if matches!(
        request,
        Request::PrepareWorkspace { .. }
            | Request::InspectWorkspace { .. }
            | Request::RecoverWorkspace { .. }
    ) {
        return super::workspace::serve(&socket, peer, &request, &policy, policy_sha256);
    }
    match &request {
        Request::Inspect {
            version: 1,
            id,
        }
        | Request::Recover {
            version: 1,
            id,
            ..
        } => {
            validate_id(id)?;
            let state = policy::trusted(&policy.state_directory, true)?;
            if !descriptor::flock(state.as_fd(), FlockMode::ExclusiveNonblocking)? {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let authorization = match &request {
                Request::Recover {
                    plan_sha256,
                    ..
                } => {
                    policy::digest(plan_sha256)?;
                    Some(plan_sha256.as_str())
                }
                _ => None,
            };
            return recovery::serve(&socket, &state, policy_sha256, id, authorization);
        }
        _ => {}
    }
    let Request::Prepare {
        version: 1,
        ref id,
        budget,
    } = request
    else {
        return Err(refused(
            "first helper request must prepare a version-1 private scratch image",
        ));
    };
    validate_id(id)?;
    let budget = BuilderLimits::new(policy.maximum)
        .map_err(io::Error::other)?
        .admit(budget)
        .map_err(io::Error::other)?;
    let geometry = Geometry::new(
        budget.request().scratch_bytes,
        budget.request().files,
    )?;
    let formatter = policy.formatter.snapshot()?;
    let checker = policy.checker.snapshot()?;
    let state = policy::trusted(&policy.state_directory, true)?;
    if !descriptor::flock(state.as_fd(), FlockMode::ExclusiveNonblocking)? {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    check_state(&state, policy.maximum_operations)?;
    let capacity = filesystem::observe(&state)?;
    let required = budget
        .request()
        .storage_bytes()
        .map_err(io::Error::other)?
        .checked_add(64 * 1024 * 1024)
        .ok_or_else(|| refused("scratch reservation overflow"))?;
    if capacity.available_bytes < required || capacity.available_inodes < 64 {
        return Err(io::Error::other(
            "helper state lacks available storage or inodes",
        ));
    }
    let mut authorization = Sha256::new();
    authorization.update(b"syrox-private-scratch-authorization-v1\n");
    authorization.update(policy_sha256);
    authorization.update(peer.uid.to_le_bytes());
    authorization.update(peer.gid.to_le_bytes());
    authorization.update(serde_json::to_vec(&request)?);
    authorization.update(capacity.device.to_le_bytes());
    authorization.update(capacity.inode.to_le_bytes());
    let authorization = crate::hex(&authorization.finalize());
    let runtime = recovery::runtime()?;
    let mut journal = Journal::create(&state, &format!("op-{id}"))?;
    journal.record("authorized", serde_json::json!({ "request": request, "authorization": authorization,
        "policy_sha256": policy_sha256, "peer": { "uid": peer.uid, "gid": peer.gid, "pid": peer.pid },
        "state_filesystem": capacity, "runtime": runtime }))?;
    let result = prepare(
        &socket,
        peer,
        id,
        &authorization,
        &mut journal,
        &budget,
        geometry,
        &formatter,
        &checker,
    );
    if let Err(error) = &result {
        // A failed record is itself uncertain. Never erase the original error,
        // retry formatting, delete evidence or mark teardown complete here.
        let state = if journal.released {
            "response-undelivered"
        } else {
            "uncertain"
        };
        let _ = journal.record(
            state,
            serde_json::json!({ "error": error.to_string() }),
        );
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn prepare(
    socket: &File,
    peer: PeerCredentials,
    id: &str,
    authorization: &str,
    journal: &mut Journal,
    budget: &syrox_system::budget::AdmittedBudget,
    geometry: Geometry,
    formatter: &descriptor::pinned_tool::PinnedTool,
    checker: &descriptor::pinned_tool::PinnedTool,
) -> io::Result<()> {
    let deadline =
        Instant::now() + Duration::from_secs(u64::from(budget.request().duration_seconds));
    let check = || {
        if Instant::now() >= deadline {
            Err(io::Error::from(io::ErrorKind::TimedOut))
        } else {
            Ok(())
        }
    };
    journal.record("allocate-intent", serde_json::json!({ "bytes": geometry.image_bytes(), "inode_ceiling": budget.request().files }))?;
    let image = journal::new_file(&journal.directory, "scratch.img")?;
    journal.directory.sync_all()?;
    // SAFETY: our newly created private regular file; supported bounded positive
    // size. Preallocation is explicit; allocation failure retains the attempt.
    let result = unsafe {
        libc::posix_fallocate(
            image.as_raw_fd(),
            0,
            i64::try_from(geometry.image_bytes()).expect("Geometry caps images at 128 GiB"),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    image.sync_all()?;
    let metadata = image.metadata()?;
    journal.record("image-allocated", serde_json::json!({ "device": metadata.dev(), "inode": metadata.ino(), "bytes": metadata.len() }))?;
    for (stage, tool, operation) in [
        ("format", formatter, Operation::Format(geometry)),
        ("check-before", checker, Operation::Check),
    ] {
        tool_attempt(journal, stage, tool, &image, operation, check)?;
    }
    journal.record("loop-select-intent", serde_json::json!({}))?;
    let control = LoopControl::from_file(device(Path::new("/dev/loop-control"))?)?;
    let number = control.select_free()?;
    let path = PathBuf::from(format!("/dev/loop{number}"));
    let mut block = None;
    for _ in 0..100 {
        check()?;
        match device(&path) {
            Ok(file) => {
                block = Some(file);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    let mut binding = ScratchLoop::prepare(
        block.ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?,
        number,
        image.try_clone()?,
        geometry.image_bytes(),
    )?;
    journal.record(
        "loop-configure-intent",
        serde_json::json!({ "loop_number": number }),
    )?;
    binding.configure()?;
    journal.record(
        "mount-intent",
        serde_json::json!({ "loop_number": number }),
    )?;
    let mount = DetachedScratch::mount(&binding, budget, check)?;
    journal.record(
        "assign-owner-intent",
        serde_json::json!({ "uid": peer.uid, "gid": peer.gid }),
    )?;
    mount.assign_owner(peer.uid, peer.gid)?;
    let offered = journal.record(
        "offered",
        serde_json::json!({ "id": id, "authorization": authorization,
        "filesystem_bytes": mount.capacity().filesystem_bytes, "inodes": mount.capacity().inodes,
        "loop_number": number, "budget": budget.request() }),
    )?;
    wire::reply(socket, offered)?;
    descriptor::send_fd(socket.as_fd(), mount.root()?)?;
    let release = wire::receive(socket, peer, deadline)?;
    match release {
        Request::Release {
            version: 1,
            id: release_id,
            authorization: release_authorization,
        } if release_id == id && release_authorization == authorization => {}
        _ => {
            return Err(refused(
                "release does not match the authorized scratch operation",
            ));
        }
    }
    drop(mount);
    journal.record(
        "loop-release-intent",
        serde_json::json!({ "loop_number": number }),
    )?;
    let observation = binding.release()?;
    journal.record(
        "loop-release-observed",
        serde_json::json!({ "observation": format!("{observation:?}"), "loop_number": number }),
    )?;
    drop(binding);
    // ENXIO alone also covers rundown. Require the independent final evidence
    // after closing our descriptions; retained client mount FDs prevent success.
    let base = PathBuf::from(format!("/sys/dev/block/7:{number}"));
    loop {
        check()?;
        if !base.join("loop/backing_file").try_exists()?
            && std::fs::read(base.join("size"))? == b"0\n"
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    tool_attempt(
        journal,
        "check-after",
        checker,
        &image,
        Operation::Check,
        check,
    )?;
    let released = journal.record(
        "released",
        serde_json::json!({ "id": id, "authorization": authorization,
        "loop_number": number, "image_retained": true }),
    )?;
    wire::reply(socket, released)
}

pub(super) fn tool_attempt(
    journal: &mut Journal,
    stage: &str,
    tool: &descriptor::pinned_tool::PinnedTool,
    image: &File,
    operation: Operation,
    check: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    journal.record(
        "tool-intent",
        serde_json::json!({ "stage": stage, "tool_sha256": tool.pin().sha256,
        "tool_bytes": tool.pin().size_bytes, "operation": format!("{operation:?}") }),
    )?;
    let directory = journal::new_directory(&journal.directory, stage)?;
    let result = ext4_tool::run(tool, image, &directory, operation, check)?;
    for (name, bytes) in [
        ("stdout", &result.stdout),
        ("stderr", &result.stderr),
    ] {
        let mut file = journal::new_file(&directory, name)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    directory.sync_all()?;
    journal.record("tool-result", serde_json::json!({ "stage": stage, "status": result.status.to_string(),
        "stdout_sha256": crate::hex(&Sha256::digest(&result.stdout)), "stderr_sha256": crate::hex(&Sha256::digest(&result.stderr)) }))?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "helper {stage} failed: {}",
            result.status
        )));
    }
    Ok(())
}

pub(super) fn device(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

pub(super) fn check_state(state: &File, maximum: u32) -> io::Result<()> {
    let mut count = 0;
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", state.as_raw_fd()))? {
        let entry = entry?;
        count += 1;
        if count > maximum {
            return Err(refused(
                "helper operation retention ceiling reached",
            ));
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(refused("unexpected helper state entry"));
        };
        if !name.starts_with("op-") {
            return Err(refused("unexpected helper state entry"));
        }
        if !recovery::settled(state, name)? {
            return Err(refused(
                "unreconciled helper operation requires explicit recovery",
            ));
        }
    }
    if count >= maximum {
        return Err(refused(
            "helper operation retention ceiling reached",
        ));
    }
    Ok(())
}

pub(super) fn validate_id(id: &str) -> io::Result<()> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refused(
            "scratch operation id requires 32 lowercase hex digits",
        ));
    }
    Ok(())
}
