//! Production two-root protocol, release and reconciliation in the guarded guest.

use super::{ID, ROOT, Reap};
use std::{
    fs::OpenOptions,
    io::{self, Write as _},
    os::{
        fd::AsRawFd as _,
        unix::{
            fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
            process::CommandExt as _,
        },
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use syrox_system::{
    budget::{BuildBudget, BuilderLimits},
    helper_client::HelperClient,
    workspace::{ReceivedWorkspace, WorkspaceLayout},
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
fn layout(request: BuildBudget) -> io::Result<WorkspaceLayout> {
    let admitted = BuilderLimits::new(request)
        .and_then(|p| p.admit(request))
        .map_err(io::Error::other)?;
    WorkspaceLayout::from_budget(&admitted)
}
pub(super) fn root() -> io::Result<()> {
    // The root main has already authenticated marker contents and QEMU DMI.
    for (group, cases) in [
        (
            "normal",
            vec![
                ("grant", true),
                ("grant-second", true),
                ("engine-inputs", true),
                ("terminal-second", true),
            ],
        ),
        ("denied", vec![("budget-refused", false)]),
        (
            "abandoned",
            vec![
                ("disconnect", false),
                ("legacy-inspect", false),
                ("inspect", true),
                ("wrong-hash", false),
                ("recover", true),
                ("terminal", true),
            ],
        ),
        (
            "retained",
            vec![
                ("retain", false),
                ("inspect-after-retained", true),
                ("recover-after-retained", true),
            ],
        ),
        (
            "cli",
            vec![
                ("cli-abandon", false),
                ("cli-inspect", true),
                ("cli-wrong-hash", false),
                ("cli-recover", true),
                ("cli-terminal", true),
            ],
        ),
    ] {
        let state = Path::new(ROOT).join(format!("workspace-rpc-{group}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)?;
        let mut image_pins = None;
        for (case, success) in cases {
            if matches!(
                case,
                "wrong-hash" | "recover" | "cli-wrong-hash" | "cli-recover"
            ) {
                image_pins = Some(pins(&state)?);
            }
            let before = std::fs::read_dir(&state)?.count();
            run(&format!("workspace-rpc-{case}"), &state, success)?;
            if case == "budget-refused" {
                assert_eq!(before, 0);
                assert_eq!(std::fs::read_dir(&state)?.count(), 0);
            }
            if let Some(expected) = &image_pins {
                assert_eq!(&pins(&state)?, expected);
            }
        }
    }
    println!("SRX_WORKSPACE_RPC_PROBE_OK");
    Ok(())
}
fn pins(state: &Path) -> io::Result<(String, String)> {
    let operation = state.join(format!("op-{ID}"));
    Ok((
        super::file_digest(&operation.join("scratch.img"))?,
        super::file_digest(&operation.join("output.img"))?,
    ))
}
fn run(name: &str, state: &Path, success: bool) -> io::Result<()> {
    let policy = Path::new(ROOT).join(format!("policy-{name}.json"));
    let maximum = BuildBudget {
        memory_bytes: 268_435_456,
        files: 2048,
        output_bytes: 268_435_456,
        ..budget()
    };
    let body = serde_json::json!({"version":1,"client_uid":1000,"client_gid":1000,"maximum":maximum,"maximum_operations":4,"state_directory":state,
        "formatter":{"path":Path::new(ROOT).join("mke2fs"),"size_bytes":1_735_200,"sha256":"59935ec5c57f7f3b2e5ef1119d7480275264a9f5adecb862b7bd2ae813fd83ec"},
        "checker":{"path":Path::new(ROOT).join("e2fsck"),"size_bytes":2_093_768,"sha256":"da1f6de6ac3a2efd7fc6d2581199ce7109a22dee7843ce923e4111a92666a95a"}});
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&policy)?;
    file.write_all(&serde_json::to_vec(&body)?)?;
    file.sync_all()?;
    let path = Path::new("/run").join(format!("srx-{name}.sock"));
    let listener = super::listener(&path)?;
    // Production client requires a protected root-owned endpoint.
    std::os::unix::fs::chown(&path, Some(0), Some(1000))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
    let mut client = super::spawn_client(&path, name)?;
    let socket = super::accept(&listener, &mut client.0)?;
    let raw = socket.as_raw_fd();
    let mut command = Command::new(Path::new(ROOT).join("syrox-system-helper"));
    command
        .arg("--policy")
        .arg(policy)
        .stdin(Stdio::null());
    // SAFETY: fixed CLOEXEC mapping of only this accepted connection.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 4_u32) < 0
                || (raw != 3 && libc::dup2(raw, 3) < 0)
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut helper = Reap(command.spawn()?);
    drop(socket);
    if name == "workspace-rpc-retain" {
        assert!(!helper.0.wait()?.success());
        run("workspace-rpc-inspect-retained", state, true)?;
        run("workspace-rpc-recover-blocked", state, false)?;
        let marker = Path::new(ROOT).join("client-state/workspace-rpc-release");
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(marker)?
            .sync_all()?;
    }
    assert!(
        client.0.wait()?.success(),
        "workspace client {name}"
    );
    assert_eq!(
        helper.0.wait()?.success(),
        success,
        "workspace helper {name}"
    );
    println!("SRX_HELPER_CASE_OK {name}");
    Ok(())
}

pub(super) fn client(path: &Path, name: &str) -> io::Result<()> {
    assert_eq!(unsafe { libc::geteuid() }, 1000);
    if name.starts_with("workspace-rpc-cli-") && name != "workspace-rpc-cli-abandon" {
        return cli(path, name);
    }
    if name == "workspace-rpc-engine-inputs" {
        let status = Command::new(Path::new(ROOT).join("system-scratch-tests"))
            .args(["--exact", "build::system::tests::scratch::disposable_vm_system_workspace_retains_prepared_inputs_through_gc_and_release", "--ignored", "--nocapture", "--test-threads=1"])
            .env_clear()
            .env("SRX_SYSTEM_WORKSPACE_VM_HELPER", path)
            .stdin(Stdio::null())
            .status()?;
        assert!(
            status.success(),
            "prepared component workspace/GC integration"
        );
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let connect = || HelperClient::connect(path, || Ok(()), deadline);
    let id = if name.ends_with("second") {
        "11111111111111111111111111111111"
    } else {
        ID
    };
    if name == "workspace-rpc-budget-refused" {
        let plan = layout(BuildBudget {
            scratch_bytes: 134_217_728,
            ..budget()
        })?;
        assert!(
            connect()?
                .prepare_workspace(id, &plan, || Ok(()), deadline)
                .is_err()
        );
        return Ok(());
    }
    if name == "workspace-rpc-legacy-inspect" {
        assert!(
            connect()?
                .inspect(id, || Ok(()), deadline)
                .is_err()
        );
        return Ok(());
    }
    let retained = name.contains("retained") || name.ends_with("blocked");
    let pin_path = Path::new(ROOT).join(if retained {
        "client-state/workspace-retained-plan.json"
    } else {
        "client-state/workspace-abandoned-plan.json"
    });
    if name.contains("inspect") || name.contains("terminal") {
        let inspection = connect()?.inspect_workspace(id, || Ok(()), deadline)?;
        let expected = if name.contains("terminal") || name == "workspace-rpc-inspect-retained" {
            "blocked"
        } else {
            "reconcile-retained-workspace"
        };
        assert_eq!(inspection.plan["action"], expected);
        assert_eq!(
            inspection.plan["images"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
        std::fs::write(
            pin_path,
            serde_json::to_vec(
                &serde_json::json!({"plan":inspection.plan,"pin":inspection.plan_sha256}),
            )?,
        )?;
        return Ok(());
    }
    if name.contains("recover") || name == "workspace-rpc-wrong-hash" {
        let evidence: serde_json::Value = serde_json::from_slice(&std::fs::read(&pin_path)?)?;
        let pin = if name == "workspace-rpc-wrong-hash" {
            "00".repeat(32)
        } else {
            evidence["pin"].as_str().unwrap().into()
        };
        let result = connect()?.recover_workspace(id, &pin, || Ok(()), deadline);
        if name == "workspace-rpc-wrong-hash" || name == "workspace-rpc-recover-blocked" {
            assert!(result.is_err());
        } else {
            result?;
        }
        return Ok(());
    }
    let plan = layout(budget())?;
    let grant = connect()?.prepare_workspace(id, &plan, || Ok(()), deadline)?;
    let observation = *grant.observation();
    assert_eq!(
        (
            observation.scratch.inodes,
            observation.output.inodes
        ),
        (336, 672)
    );
    let (scratch, output, lease) = grant.into_parts();
    assert_eq!(lease.layout(), &plan);
    let received = ReceivedWorkspace::from_authorized_roots(
        &plan,
        &observation,
        scratch.try_clone()?,
        output.try_clone()?,
    )?;
    received.revalidate()?;
    for (role, root) in [
        ("scratch", &scratch),
        ("output", &output),
    ] {
        let root_path = format!("/proc/self/fd/{}", root.as_raw_fd());
        std::fs::write(
            Path::new(&root_path).join("sentinel"),
            role.as_bytes(),
        )?;
        root.sync_all()?;
    }
    drop(received);
    if name == "workspace-rpc-retain" {
        drop(output);
        drop(lease);
        let marker = Path::new(ROOT).join("client-state/workspace-rpc-release");
        while !marker.try_exists()? {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read(format!(
                "/proc/self/fd/{}/sentinel",
                scratch.as_raw_fd()
            ))?,
            b"scratch"
        );
        drop(scratch);
    } else {
        drop(scratch);
        drop(output);
        if name == "workspace-rpc-disconnect" || name == "workspace-rpc-cli-abandon" {
            drop(lease);
        } else {
            lease.release(|| Ok(()), deadline)?;
        }
    }
    Ok(())
}

fn cli(path: &Path, name: &str) -> io::Result<()> {
    let plan_path = Path::new(ROOT).join("client-state/workspace-cli-plan.json");
    let mut command = Command::new(Path::new(ROOT).join("srx"));
    command
        .args([
            "--std",
            "none",
            "system",
            "recover",
            "--workspace-operation",
            ID,
            "--helper-socket",
        ])
        .arg(path)
        .arg("--json")
        .env_clear()
        .stdin(Stdio::null());
    let authorization = if name == "workspace-rpc-cli-wrong-hash" {
        Some("00".repeat(32))
    } else if name == "workspace-rpc-cli-recover" {
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&plan_path)?)?;
        Some(value["plan_sha256"].as_str().unwrap().into())
    } else {
        None
    };
    if let Some(pin) = &authorization {
        command.args(["--apply-plan", pin]);
    }
    let output = command.output()?;
    if name == "workspace-rpc-cli-wrong-hash" {
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        return Ok(());
    }
    assert!(
        output.status.success(),
        "workspace CLI {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= 65_536);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    if name == "workspace-rpc-cli-recover" {
        assert_eq!(value["state"], "reconciled");
        assert_eq!(value["details"]["image_retained"], true);
        assert_eq!(
            value["details"]["filesystem_health_verified"],
            false
        );
    } else {
        assert_eq!(
            value["plan"]["action"],
            if name == "workspace-rpc-cli-terminal" {
                "blocked"
            } else {
                "reconcile-retained-workspace"
            }
        );
        assert_eq!(
            value["plan"]["images"].as_object().unwrap().len(),
            2
        );
        if name == "workspace-rpc-cli-inspect" {
            std::fs::write(plan_path, &output.stdout)?;
        }
    }
    Ok(())
}
