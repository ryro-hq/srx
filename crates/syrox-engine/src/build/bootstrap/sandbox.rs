use crate::build::cancellation::BuildControl;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::{
    BuildError, BuildResources,
    capture::Capture,
    group,
    journal::{self, Operation},
};

pub(in crate::build) struct CapturedOutput {
    pub file: std::fs::File,
}

const LOG_BYTES: usize = 16 * 1024;

pub(in crate::build) use super::policy::seccomp_filter;

fn manager(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C");
    for name in [
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

/// Cheap, bounded checks before a download or /usr inventory. The real build
/// must still establish its own cgroup and sandbox; a probe is not that evidence.
pub(in crate::build) fn preflight() -> Result<(), BuildError> {
    for (capability, args) in [
        (
            "systemd user manager",
            &[
                "/usr/bin/systemctl",
                "--user",
                "show-environment",
            ][..],
        ),
        (
            "Bubblewrap namespaces and setpriv Landlock",
            &[
                "/usr/bin/bwrap",
                "--unshare-all",
                "--unshare-user",
                "--unshare-cgroup",
                "--disable-userns",
                "--assert-userns-disabled",
                "--cap-drop",
                "ALL",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/bin",
                "/bin",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--",
                "/usr/bin/setpriv",
                "--no-new-privs",
                "--landlock-access",
                "fs",
                "--landlock-rule",
                "path-beneath:read-file,read-dir,execute:/",
                "--",
                "/usr/bin/true",
            ][..],
        ),
    ] {
        let status = manager("/usr/bin/timeout")
            .args(["--kill-after=1", "5"])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| BuildError::Capability(capability))?;
        if !status.success() {
            return Err(BuildError::Capability(capability));
        }
    }
    Ok(())
}

pub(in crate::build) fn execute(
    operation: &Operation,
    description: &super::records::Action,
    timeout_seconds: u32,
    blocked: &[std::path::PathBuf],
    cancellation: &dyn BuildControl,
) -> Result<CapturedOutput, BuildError> {
    // This backend mounts the host toolchain and launches host supervisors.
    // Keep its boundary explicit even for callers below realization.
    if description.program.profile != super::BuildProfile::HostBootstrap {
        return Err(BuildError::UnsupportedProfile);
    }
    operation.write_stage("seccomp", &seccomp_filter(), false)?;
    supervise(
        sandbox_command(operation, description, timeout_seconds, blocked),
        operation,
        timeout_seconds,
        description.program.resources == BuildResources::Large,
        cancellation,
    )
}

// The fixed argv is deliberately spelled out for auditing the sandbox boundary.
fn sandbox_command(
    operation: &Operation,
    description: &super::records::Action,
    timeout_seconds: u32,
    blocked: &[std::path::PathBuf],
) -> Command {
    // The trusted launcher remains time-bounded even if its coordinator dies
    // while the service-manager request is pending.
    let mut command = manager("/usr/bin/timeout");
    command.args([
        "--kill-after=1",
        &(timeout_seconds + 15).to_string(),
        "/usr/bin/systemd-run",
    ]);
    command
        .args([
            "--user",
            "--quiet",
            "--wait",
            "--pipe",
            "--service-type=exec",
        ])
        .arg(format!("--unit={}", operation.unit()));
    let limits = description.program.resources.envelope();
    for property in [
        "ExitType=cgroup",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "TimeoutStopSec=2s",
        "MemorySwapMax=0",
        "LimitCORE=0",
        "UMask=0077",
    ] {
        command.arg(format!("--property={property}"));
    }
    for property in [
        format!("MemoryMax={}", limits.memory),
        format!("TasksMax={}", limits.tasks),
        format!("CPUQuota={}%", limits.cpu_percent),
        format!("LimitNOFILE={}", limits.nofile),
    ] {
        command.arg(format!("--property={property}"));
    }
    command.arg(format!(
        "--property=LimitFSIZE={}",
        limits.output_bytes
    ));
    command.arg(format!(
        "--property=RuntimeMaxSec={timeout_seconds}s"
    ));
    command
        .arg("--")
        .arg(operation.stage_path().join("worker"))
        .arg("__build-gate")
        .arg(&operation.path)
        .arg(&description.directory);
    for path in blocked {
        command.arg("--blocked").arg(path);
    }
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

pub(crate) fn run_gate(
    operation: &Path,
    source_directory: &str,
    blocked: &[std::path::PathBuf],
) -> Result<(), BuildError> {
    if !super::relative_path(source_directory)
        || source_directory.contains('/')
        || blocked.len() > 1024
        || blocked.iter().any(|path| {
            !path.starts_with("/usr")
                || path.as_os_str().len() > 4096
                || path
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir))
        })
    {
        return Err(BuildError::InvalidRequest);
    }
    let gate = journal::enter_gate(operation)?;
    if gate.description().directory != source_directory {
        return Err(BuildError::InvalidRequest);
    }
    if gate.description().program.profile != super::BuildProfile::HostBootstrap {
        return Err(BuildError::UnsupportedProfile);
    }
    let status = payload_command(
        &operation.join("stage"),
        source_directory,
        gate.description(),
        blocked,
    )
    .status()?;
    if !status.success() {
        return Err(BuildError::Execution(format!(
            "sandbox: {status}"
        )));
    }
    Ok(())
}

// Fixed namespace argv remains independent of recipe-controlled commands.
fn payload_command(
    stage: &Path,
    source_directory: &str,
    description: &super::records::Action,
    blocked: &[std::path::PathBuf],
) -> Command {
    let limits = description.program.resources.envelope();
    let mut command = manager("/usr/bin/bwrap");
    command.args([
        "--unshare-all",
        "--unshare-user",
        "--unshare-cgroup",
        "--disable-userns",
        "--assert-userns-disabled",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
    ]);
    for path in blocked {
        command.args(["--ro-bind", "/dev/null"]).arg(path);
    }
    for (file, dest) in [
        ("worker", "/syrox-worker"),
        ("source", "/source"),
        ("build-program", "/build-program"),
        ("build-action", "/build-action"),
        ("seccomp", "/seccomp"),
    ] {
        command
            .arg("--ro-bind")
            .arg(stage.join(file))
            .arg(dest);
    }
    if !description.inputs.is_empty() {
        let views = stage
            .parent()
            .expect("operation")
            .parent()
            .expect("builds")
            .parent()
            .expect(".syrox-store")
            .join("views");
        let mut mounted = std::collections::BTreeSet::new();
        for input in &description.inputs {
            if !mounted.insert((input.action, input.output.as_str())) {
                continue;
            }
            command
                .arg("--ro-bind")
                .arg(views.join(format!("tree_{}", input.artifact)))
                .arg(format!(
                    "/syrox/store/{}/{}",
                    input.action, input.output
                ));
        }
    }
    command.args([
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        &limits.work_tmpfs.to_string(),
        "--tmpfs",
        "/work",
    ]);
    command.args([
        "--size",
        &limits.output_tmpfs.to_string(),
        "--tmpfs",
        "/out",
    ]);
    command.args([
        "--size",
        "67108864",
        "--tmpfs",
        "/tmp",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LC_ALL",
        "C",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "SOURCE_DATE_EPOCH",
        "0",
    ]);
    command.args([
        "--chdir",
        "/work",
        "--die-with-parent",
        "--new-session",
        "--",
        "/usr/bin/setpriv",
        "--no-new-privs",
        "--landlock-access",
        "fs",
        "--landlock-rule",
        "path-beneath:read-file,read-dir,execute:/",
    ]);
    for path in ["/work", "/out", "/tmp", "/dev"] {
        command.args(["--landlock-rule", &format!("path-beneath:write-file,remove-dir,remove-file,make-dir,make-reg,make-sock,make-fifo,make-sym,refer,truncate,ioctl-dev:{path}")]);
    }
    command.args([
        "--seccomp-filter",
        "/seccomp",
        "--",
        "/syrox-worker",
        "__build-worker",
        source_directory,
    ]);
    command.arg(description.digest().to_string());
    command.stdin(Stdio::null());
    command
}

fn supervise(
    mut command: Command,
    operation: &Operation,
    timeout_seconds: u32,
    large: bool,
    cancellation: &dyn BuildControl,
) -> Result<CapturedOutput, BuildError> {
    let stage = operation.stage_path();
    let unit = operation.unit();
    cancellation.check()?;
    let mut child = command.spawn()?;
    // Even a pipe setup error must pass through launcher reaping and settlement.
    let mut pipes = Pipes::new(&mut child, large);
    let mut outcome = match &mut pipes {
        Ok(pipes) => pipes.wait(
            &mut child,
            timeout_seconds,
            cancellation,
            operation,
        ),
        Err(error) => Err(BuildError::Execution(format!(
            "cannot capture build channels: {error}"
        ))),
    };
    if let Ok(pipes) = &pipes
        && let Err(journal) = operation.log(&pipes.log.tail_bytes(16 * 1024))
    {
        outcome = Err(match outcome {
            Ok(()) => journal,
            Err(primary) => BuildError::FailureAndJournal {
                primary: Box::new(primary),
                journal: journal.to_string(),
            },
        });
    }
    // Reap the trusted launcher before any stop/query, so it cannot submit a
    // delayed activation after settlement. Never block forever in Child::wait.
    let launcher_completed = if outcome.is_err() {
        let Some(status) = terminate_launcher(&mut child) else {
            return Err(unsettled(
                &stage,
                "launcher could not be reaped",
                outcome.err(),
            ));
        };
        // A cancellation can race with an already completed --wait launcher.
        // Preserve its actual wait status as finalization evidence, while the
        // requested operation still returns cancellation rather than success.
        status.success()
    } else {
        true
    };
    let unit_result = match settle(&unit, launcher_completed) {
        Ok(result) => result,
        Err(reason) => return Err(unsettled(&stage, reason, outcome.err())),
    };
    if let Ok(pipes) = &mut pipes
        && let Err(reason) = pipes.finish()
    {
        return Err(unsettled(&stage, reason, outcome.err()));
    }
    if let Ok(pipes) = &pipes
        && let Err(journal) = operation.log(&pipes.log.tail_bytes(16 * 1024))
    {
        outcome = Err(match outcome {
            Ok(()) => journal,
            Err(primary) => BuildError::FailureAndJournal {
                primary: Box::new(primary),
                journal: journal.to_string(),
            },
        });
    }
    // Cancellation wins over the consequential launcher SIGKILL. A service
    // timeout wins over its otherwise generic nonzero launcher exit.
    if matches!(outcome, Err(BuildError::Cancelled)) {
        return Err(BuildError::Cancelled);
    }
    if unit_result == "timeout"
        && !matches!(
            outcome,
            Err(BuildError::Journal(_) | BuildError::FailureAndJournal { .. })
        )
    {
        return Err(BuildError::Timeout);
    }
    let Ok(pipes) = pipes else {
        return Err(outcome.expect_err("pipe setup error must fail the operation"));
    };
    if let Err(error) = outcome {
        return Err(match error {
            BuildError::Execution(message) => {
                BuildError::Execution(format!("{message}\n{}", pipes.log.diagnostic()))
            }
            error => error,
        });
    }
    if unit_result != "success" {
        return Err(BuildError::Execution(pipes.log.diagnostic()));
    }
    if pipes.output.overflow {
        return Err(BuildError::Output);
    }
    cancellation.check()?;
    let (file, _) = pipes.output.into_disk()?;
    Ok(CapturedOutput {
        file,
    })
}

fn unsettled(stage: &Path, reason: &'static str, primary: Option<BuildError>) -> BuildError {
    BuildError::Settlement {
        stage: stage.to_path_buf(),
        reason,
        primary: primary.map(Box::new),
    }
}

fn terminate_launcher(child: &mut Child) -> Option<ExitStatus> {
    if let Some(status) = child.try_wait().ok()? {
        return Some(status);
    }
    let _ = crate::platform::linux::fd::kill_launcher_group(child.id());
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            _ => return None,
        }
    }
}

struct Pipes {
    output: Capture<ChildStdout>,
    log: Capture<ChildStderr>,
}

impl Pipes {
    fn new(child: &mut Child, large: bool) -> std::io::Result<Self> {
        Ok(Self {
            output: Capture::new_disk(
                child.stdout.take().unwrap(),
                usize::try_from(group::MAX_GROUP_BYTES).expect("bounded output fits usize"),
            )?,
            log: Capture::new(
                child.stderr.take().unwrap(),
                if large {
                    512 * 1024
                } else {
                    LOG_BYTES
                },
                true,
            )?,
        })
    }

    fn drain(&mut self) -> std::io::Result<bool> {
        let output = self.output.drain()?;
        let log = self.log.drain()?;
        Ok(output || log)
    }

    fn wait(
        &mut self,
        child: &mut Child,
        timeout_seconds: u32,
        cancellation: &dyn BuildControl,
        operation: &Operation,
    ) -> Result<(), BuildError> {
        let deadline = Instant::now() + Duration::from_secs(u64::from(timeout_seconds) + 5);
        let mut logged = Instant::now();
        loop {
            cancellation.check()?;
            if Instant::now() >= deadline {
                return Err(BuildError::Timeout);
            }
            let activity = self.drain()?;
            if logged.elapsed() >= Duration::from_secs(1) {
                operation.log(&self.log.tail_bytes(16 * 1024))?;
                logged = Instant::now();
            }
            if self.output.overflow {
                return Err(BuildError::Output);
            }
            if let Some(status) = child.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(BuildError::Execution(format!(
                        "build launcher: {status}"
                    )))
                };
            }
            if !activity {
                thread::sleep(Duration::from_millis(25));
            }
        }
    }

    fn finish(&mut self) -> Result<(), &'static str> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !self.output.eof || !self.log.eof {
            if Instant::now() >= deadline {
                return Err("build channels did not reach EOF after unit stop");
            }
            let activity = self
                .drain()
                .map_err(|_| "build channel read failed after unit stop")?;
            if !activity {
                thread::sleep(Duration::from_millis(25));
            }
        }
        Ok(())
    }
}

pub(in crate::build) fn stop_unit(unit: &str) -> bool {
    let stop = manager("/usr/bin/timeout")
        .args([
            "--kill-after=1",
            "10",
            "/usr/bin/systemctl",
            "--user",
            "stop",
            unit,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    stop.is_ok_and(|status| status.success())
}

/// Caller owns the revoked gate. Kernel cgroup evidence is checked separately
/// before deletion; absence here cannot authorize any future payload launch.
pub(in crate::build) fn recover_unit(unit: &str) -> Result<(), &'static str> {
    settle(unit, true).map(|_| ())
}

fn settle(unit: &str, launcher_completed: bool) -> Result<String, &'static str> {
    let stopped = stop_unit(unit);
    let result = manager("/usr/bin/timeout")
        .args([
            "--kill-after=1",
            "10",
            "/usr/bin/systemctl",
            "--user",
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=ControlGroup",
            "--property=Result",
        ])
        .stdin(Stdio::null())
        .output();
    let output = result.map_err(|_| "service manager state query failed")?;
    if !output.status.success() {
        return Err("service manager state query failed");
    }
    let observation = parse_settlement(&output.stdout)
        .ok_or("service manager did not confirm an inactive empty unit")?;
    let result = admit_settlement(observation, stopped, launcher_completed)?;
    let _ = manager("/usr/bin/timeout")
        .args([
            "--kill-after=1",
            "5",
            "/usr/bin/systemctl",
            "--user",
            "reset-failed",
            unit,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(result.to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnitObservation<'a> {
    Inactive(&'a str),
    Collected,
}

fn admit_settlement(
    observation: UnitObservation<'_>,
    stopped: bool,
    launcher_completed: bool,
) -> Result<&str, &'static str> {
    match observation {
        UnitObservation::Inactive(result) if stopped => Ok(result),
        // Transient metadata can disappear before stop or between stop and
        // show. Absence is sufficient only after StopUnit completion OR the
        // successful --wait launcher (ExitType=cgroup) completed this exact unit.
        // A killed/failed launcher alone cannot authorize this path.
        UnitObservation::Collected if stopped || launcher_completed => Ok("success"),
        _ => Err("service manager did not confirm stop or completed unit collection"),
    }
}

fn parse_settlement(bytes: &[u8]) -> Option<UnitObservation<'_>> {
    if bytes.len() >= 4096 {
        return None;
    }
    let mut loaded = None;
    let mut active = None;
    let mut group = None;
    let mut result = None;
    for line in std::str::from_utf8(bytes).ok()?.lines() {
        let (key, value) = line.split_once('=')?;
        let field = match key {
            "LoadState" => &mut loaded,
            "ActiveState" => &mut active,
            "ControlGroup" => &mut group,
            "Result" => &mut result,
            _ => return None,
        };
        if field.replace(value).is_some() {
            return None;
        }
    }
    if group != Some("") {
        return None;
    }
    match (loaded, active) {
        (Some("not-found"), Some("inactive")) => Some(UnitObservation::Collected),
        (Some("loaded"), Some("inactive" | "failed")) => result
            .filter(|value| !value.is_empty() && value.len() < 128)
            .map(UnitObservation::Inactive),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_profile_cannot_enter_the_host_sandbox_or_write_its_stage() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(root.path()).unwrap();
        let lease = store.operation().unwrap();
        let operation = Operation::create(&lease).unwrap();
        let mut action = crate::build::cache::tests::action();
        action.program.profile = super::super::BuildProfile::Managed;
        action.toolchain = None;
        assert!(matches!(
            execute(
                &operation,
                &action,
                1,
                &[],
                &crate::cancellation::Cancellation::default()
            ),
            Err(BuildError::UnsupportedProfile)
        ));
        assert!(!operation.stage_path().join("seccomp").exists());
    }

    #[test]
    fn settlement_requires_complete_unambiguous_service_manager_evidence() {
        let valid = "LoadState=loaded\nActiveState=inactive\nControlGroup=\nResult=success\n";
        assert_eq!(
            parse_settlement(valid.as_bytes()),
            Some(UnitObservation::Inactive("success"))
        );
        for invalid in [
            valid.replace("inactive", "active"),
            valid.replace("ControlGroup=", "ControlGroup=/live"),
            valid.replace("LoadState=loaded", "LoadState=error"),
            valid.replace("Result=success\n", ""),
            format!("{valid}ActiveState=active\n"),
        ] {
            assert_eq!(parse_settlement(invalid.as_bytes()), None);
        }
        let collected = valid.replace("LoadState=loaded", "LoadState=not-found");
        assert_eq!(
            parse_settlement(collected.as_bytes()),
            Some(UnitObservation::Collected)
        );
        assert!(admit_settlement(UnitObservation::Collected, false, false).is_err());
        assert_eq!(
            admit_settlement(UnitObservation::Collected, true, false),
            Ok("success")
        );
        assert_eq!(
            admit_settlement(UnitObservation::Collected, false, true),
            Ok("success")
        );
    }

    #[test]
    fn uncertain_settlement_preserves_cancellation_as_the_primary_failure() {
        let error = unsettled(
            Path::new("/private/stage"),
            "service manager state query failed",
            Some(BuildError::Cancelled),
        );
        assert!(
            matches!(error, BuildError::Settlement { primary: Some(ref error), .. } if matches!(error.as_ref(), BuildError::Cancelled))
        );
        assert!(
            error
                .to_string()
                .contains("original failure: build cancelled")
        );
    }
}
