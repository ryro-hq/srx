//! One authorized operation owns both writable roles and their release evidence.

use super::{
    journal::{self, Journal},
    policy::{self, Policy, refused},
    recovery, session,
    wire::{self, Request},
};
use sha2::{Digest as _, Sha256};
use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd as _, AsRawFd as _},
        unix::fs::MetadataExt as _,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use syrox_system::{
    budget::BuilderLimits,
    descriptor::{self, FlockMode, PeerCredentials},
    ext4_tool::{Geometry, Operation},
    filesystem,
    loop_device::{LoopControl, ScratchLoop},
    workspace::{DetachedWorkspace, WorkspaceLayout},
};

pub(super) fn serve(
    socket: &File,
    peer: PeerCredentials,
    request: &Request,
    policy: &Policy,
    policy_sha256: [u8; 32],
) -> io::Result<()> {
    if peer.uid == 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let (Request::PrepareWorkspace {
        version: 1,
        id,
        ..
    }
    | Request::InspectWorkspace {
        version: 1,
        id,
    }
    | Request::RecoverWorkspace {
        version: 1,
        id,
        ..
    }) = request
    else {
        return Err(refused("unsupported workspace request version"));
    };
    session::validate_id(id)?;
    // Admission and geometry fail before the state lock, journal or allocation.
    let layout = match request {
        Request::PrepareWorkspace {
            budget,
            layout_sha256,
            ..
        } => {
            policy::digest(layout_sha256)?;
            let admitted = BuilderLimits::new(policy.maximum)
                .map_err(io::Error::other)?
                .admit(*budget)
                .map_err(io::Error::other)?;
            Some(WorkspaceLayout::from_budget(&admitted)?)
        }
        _ => None,
    };
    let state = policy::trusted(&policy.state_directory, true)?;
    if !descriptor::flock(state.as_fd(), FlockMode::ExclusiveNonblocking)? {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    match request {
        Request::InspectWorkspace {
            ..
        } => return recovery::serve_workspace(socket, &state, policy_sha256, id, None),
        Request::RecoverWorkspace {
            plan_sha256,
            ..
        } => {
            policy::digest(plan_sha256)?;
            return recovery::serve_workspace(
                socket,
                &state,
                policy_sha256,
                id,
                Some(plan_sha256),
            );
        }
        _ => {}
    }
    let layout = layout.ok_or_else(|| refused("missing admitted workspace layout"))?;
    session::check_state(&state, policy.maximum_operations)?;
    let capacity = filesystem::observe(&state)?;
    let required = layout
        .storage_bytes()
        .checked_add(64 * 1024 * 1024)
        .ok_or_else(|| refused("workspace reservation overflow"))?;
    if capacity.available_bytes < required || capacity.available_inodes < 64 {
        return Err(refused("helper state lacks workspace capacity"));
    }
    let formatter = policy.formatter.snapshot()?;
    let checker = policy.checker.snapshot()?;
    let mut authorization = Sha256::new();
    authorization.update(b"syrox-private-workspace-authorization-v1\n");
    authorization.update(policy_sha256);
    authorization.update(peer.uid.to_le_bytes());
    authorization.update(peer.gid.to_le_bytes());
    authorization.update(serde_json::to_vec(request)?);
    authorization.update(layout.digest());
    authorization.update(capacity.device.to_le_bytes());
    authorization.update(capacity.inode.to_le_bytes());
    let authorization = crate::hex(&authorization.finalize());
    let mut journal = Journal::create(&state, &format!("op-{id}"))?;
    journal.record("authorized", serde_json::json!({"request":request,"authorization":authorization,"policy_sha256":policy_sha256,"helper_layout_sha256":layout.digest(),"peer":{"uid":peer.uid,"gid":peer.gid,"pid":peer.pid},"state_filesystem":capacity,"runtime":recovery::runtime()?}))?;
    let result = prepare(
        socket,
        peer,
        request,
        &authorization,
        &layout,
        &mut journal,
        &formatter,
        &checker,
    );
    if let Err(error) = &result {
        let _ = journal.record(
            if journal.released {
                "response-undelivered"
            } else {
                "uncertain"
            },
            serde_json::json!({"error":error.to_string()}),
        );
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn prepare(
    socket: &File,
    peer: PeerCredentials,
    request: &Request,
    authorization: &str,
    layout: &WorkspaceLayout,
    journal: &mut Journal,
    formatter: &descriptor::pinned_tool::PinnedTool,
    checker: &descriptor::pinned_tool::PinnedTool,
) -> io::Result<()> {
    let Request::PrepareWorkspace {
        id,
        layout_sha256,
        ..
    } = request
    else {
        return Err(refused("expected workspace preparation"));
    };
    let deadline = Instant::now()
        + Duration::from_secs(u64::from(
            layout.budget().request().duration_seconds,
        ));
    let check = || {
        if Instant::now() >= deadline {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(())
        }
    };
    let scratch = allocate(
        journal,
        "scratch",
        layout.scratch_geometry(),
        check,
    )?;
    let output = allocate(journal, "output", layout.output_geometry(), check)?;
    for (role, image, geometry) in [
        ("scratch", &scratch, layout.scratch_geometry()),
        ("output", &output, layout.output_geometry()),
    ] {
        for (stage, tool, operation) in [
            (
                format!("{role}-format"),
                formatter,
                Operation::Format(geometry),
            ),
            (
                format!("{role}-check-before"),
                checker,
                Operation::Check,
            ),
        ] {
            session::tool_attempt(journal, &stage, tool, image, operation, check)?;
        }
    }
    let (mut scratch_loop, scratch_number) = bind(
        journal,
        "scratch",
        &scratch,
        layout.scratch_geometry(),
        check,
    )?;
    let (mut output_loop, output_number) = bind(
        journal,
        "output",
        &output,
        layout.output_geometry(),
        check,
    )?;
    journal.record(
        "mount-intent",
        serde_json::json!({"scratch_loop":scratch_number,"output_loop":output_number}),
    )?;
    let workspace = DetachedWorkspace::mount(layout, &scratch_loop, &output_loop, check)?;
    journal.record(
        "assign-owner-intent",
        serde_json::json!({"uid":peer.uid,"gid":peer.gid}),
    )?;
    workspace.assign_owner(peer.uid, peer.gid)?;
    let mut observation = workspace.observation()?;
    // The caller's layout binds its independently selected builder policy. Root
    // admission/geometry instead use this helper's own policy, also journaled.
    // Echoing a caller binding grants no extra authority over either image.
    observation.layout_sha256 = policy::digest(layout_sha256)?;
    let offered = journal.record("offered", serde_json::json!({"id":id,"authorization":authorization,"budget":layout.budget().request(),"observation":observation,"helper_layout_sha256":layout.digest()}))?;
    wire::reply(socket, offered)?;
    descriptor::send_fd(socket.as_fd(), workspace.scratch_root()?)?;
    descriptor::send_fd(socket.as_fd(), workspace.output_root()?)?;
    match wire::receive(socket, peer, deadline)? {
        Request::ReleaseWorkspace {
            version: 1,
            id: released_id,
            authorization: released_authorization,
        } if released_id == *id && released_authorization == authorization => {}
        _ => {
            return Err(refused(
                "workspace release differs from its authorization",
            ));
        }
    }
    drop(workspace);
    for (role, binding, number) in [
        ("scratch", &mut scratch_loop, scratch_number),
        ("output", &mut output_loop, output_number),
    ] {
        check()?;
        journal.record(
            "loop-release-intent",
            serde_json::json!({"role":role,"loop_number":number}),
        )?;
        let observed = binding.release()?;
        journal.record("loop-release-observed", serde_json::json!({"role":role,"loop_number":number,"observation":format!("{observed:?}")}))?;
    }
    drop(scratch_loop);
    drop(output_loop);
    for number in [scratch_number, output_number] {
        teardown(number, check)?;
    }
    for (role, image) in [
        ("scratch", &scratch),
        ("output", &output),
    ] {
        session::tool_attempt(
            journal,
            &format!("{role}-check-after"),
            checker,
            image,
            Operation::Check,
            check,
        )?;
    }
    let released = journal.record("released", serde_json::json!({"id":id,"authorization":authorization,"layout_sha256":layout_sha256,"image_retained":true,"images":2,"scratch_loop":scratch_number,"output_loop":output_number}))?;
    wire::reply(socket, released)
}

fn allocate(
    journal: &mut Journal,
    role: &str,
    geometry: Geometry,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<File> {
    check()?;
    journal.record("allocate-intent", serde_json::json!({"role":role,"bytes":geometry.image_bytes(),"inode_ceiling":geometry.requested_inodes()}))?;
    let image = journal::new_file(&journal.directory, &format!("{role}.img"))?;
    journal.directory.sync_all()?;
    // SAFETY: new root-owned private regular image and bounded admitted geometry.
    let error = unsafe {
        libc::posix_fallocate(
            image.as_raw_fd(),
            0,
            i64::try_from(geometry.image_bytes()).expect("Geometry caps images at 128 GiB"),
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    image.sync_all()?;
    let metadata = image.metadata()?;
    journal.record("image-allocated", serde_json::json!({"role":role,"device":metadata.dev(),"inode":metadata.ino(),"bytes":metadata.len()}))?;
    check()?;
    Ok(image)
}

fn bind(
    journal: &mut Journal,
    role: &str,
    image: &File,
    geometry: Geometry,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<(ScratchLoop, u32)> {
    check()?;
    journal.record(
        "loop-select-intent",
        serde_json::json!({"role":role}),
    )?;
    let control = LoopControl::from_file(session::device(Path::new("/dev/loop-control"))?)?;
    let number = control.select_free()?;
    let mut block = None;
    for _ in 0..100 {
        check()?;
        match session::device(&PathBuf::from(format!("/dev/loop{number}"))) {
            Ok(file) => {
                block = Some(file);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
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
        serde_json::json!({"role":role,"loop_number":number}),
    )?;
    binding.configure()?;
    check()?;
    Ok((binding, number))
}

fn teardown(number: u32, mut check: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    let base = PathBuf::from(format!("/sys/dev/block/7:{number}"));
    loop {
        check()?;
        if !base.join("loop/backing_file").try_exists()?
            && std::fs::read(base.join("size"))? == b"0\n"
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
