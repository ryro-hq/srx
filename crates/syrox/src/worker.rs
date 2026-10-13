//! Entrada do worker usado para builds, runtimes e serviços.
//!
//! Este binário fica separado da CLI e da std empacotada: mudar um comando
//! público não deve mudar o hash do worker. Cada modo entra no protocolo da
//! engine que confere seus descritores e a autorização antes de liberar o payload.

use std::path::PathBuf;
use std::process::ExitCode;
mod signals;

fn execute() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or("missing worker mode")?;
    #[cfg(target_os = "linux")]
    if mode == "__runtime" {
        let code = runtime(&args.collect::<Vec<_>>()).map_err(|error| error.to_string())?;
        std::process::exit(code);
    }
    if mode == "__runtime-managed" {
        let code = managed_runtime(&args.collect::<Vec<_>>()).map_err(|error| error.to_string())?;
        std::process::exit(code);
    }
    if mode == "__runtime-managed-commands" {
        let code =
            managed_commands(&args.collect::<Vec<_>>()).map_err(|error| error.to_string())?;
        std::process::exit(code);
    }
    if mode == "__shell-command" {
        let code = shell_command(&args.collect::<Vec<_>>()).map_err(|error| error.to_string())?;
        std::process::exit(code);
    }
    if mode == "__managed-build" {
        let code = managed_build(&args.collect::<Vec<_>>()).map_err(|error| error.to_string())?;
        std::process::exit(code);
    }
    if mode == "__service" {
        let code = match service(&args.collect::<Vec<_>>()) {
            Ok(code) => code,
            Err(error @ syrox_engine::worker::ServiceWorkerError::Denied(_)) => {
                eprintln!("error: {error}");
                78
            }
            Err(error) => return Err(error.to_string()),
        };
        std::process::exit(code);
    }
    if mode == "__os-service" {
        let code = match os_service(&args.collect::<Vec<_>>()) {
            Ok(code) => code,
            Err(error @ syrox_engine::worker::OsWorkerError::Denied(_)) => {
                eprintln!("error: {error}");
                78
            }
            Err(error) => return Err(error.to_string()),
        };
        std::process::exit(code);
    }
    if mode == "__session-owner" {
        return syrox_engine::worker::run_session_owner(
            &args.collect::<Vec<_>>(),
            &syrox_engine::cancellation::Cancellation::default(),
        )
        .map_err(|error| error.to_string());
    }
    let first = args.next().ok_or("missing worker argument")?;
    let second = args.next().ok_or("missing worker argument")?;
    if mode == "__build-worker" || mode == "__build-managed-worker" {
        if args.next().is_some() {
            return Err("unexpected worker argument".into());
        }
        let directory = first.to_str().ok_or("invalid source directory")?;
        let action = second.to_str().ok_or("invalid action")?;
        if mode == "__build-managed-worker" {
            managed_build_ir(directory, action).map_err(|error| error.to_string())
        } else {
            syrox_engine::worker::run_build_worker(directory, action)
                .map_err(|error| error.to_string())
        }
    } else if mode == "__build-gate" {
        let mut blocked = Vec::new();
        while let Some(flag) = args.next() {
            if flag != "--blocked" || blocked.len() >= 1024 {
                return Err("invalid gate argument".into());
            }
            blocked.push(PathBuf::from(
                args.next().ok_or("missing blocked path")?,
            ));
        }
        syrox_engine::worker::run_build_gate(
            &PathBuf::from(first),
            second
                .to_str()
                .ok_or("invalid source directory")?,
            &blocked,
        )
        .map_err(|error| error.to_string())
    } else {
        Err("invalid worker mode".into())
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn runtime(args: &[std::ffi::OsString]) -> std::io::Result<i32> {
    // SAFETY: this dedicated executable has not started threads or retained
    // borrowed global locks. Channels inherited from the coordinator have no
    // Rust owners yet; the helper takes ownership and validates distinctness.
    unsafe { syrox_engine::worker::runtime_helper(args) }
}

#[allow(unsafe_code)]
fn managed_runtime(args: &[std::ffi::OsString]) -> std::io::Result<i32> {
    // SAFETY: dedicated executable, no threads or borrowed global locks; the
    // helper validates and takes ownership of the inherited channel descriptors.
    unsafe { syrox_engine::worker::managed_runtime_helper(args) }
}

#[allow(unsafe_code)]
fn managed_commands(args: &[std::ffi::OsString]) -> std::io::Result<i32> {
    // SAFETY: dedicated single-threaded executable; the native guardian owns
    // its signal handling, inherited descriptors and descendant cleanup.
    unsafe { syrox_engine::worker::managed_command_runtime_helper(args) }
}

#[allow(unsafe_code)]
fn shell_command(args: &[std::ffi::OsString]) -> std::io::Result<i32> {
    let signals = signals::OperationSignals::install()?;
    // SAFETY: dedicated executable before threads; helper completes guardian,
    // namespace and terminal cleanup before returning a payload outcome.
    let outcome = unsafe { syrox_engine::worker::run_shell_command(args, &signals.cancellation) };
    // Unregister frontend handlers before restoring a payload signal's default
    // disposition. Cleanup failures remain errors even if cancellation occurred.
    drop(signals);
    match outcome? {
        syrox_engine::worker::ShellCommandExit::Exited(code) => Ok(i32::from(code)),
        syrox_engine::worker::ShellCommandExit::Signaled(signal) => {
            // SAFETY: helper has completed all owned cleanup; this worker has
            // no remaining work and must reproduce signal termination exactly.
            unsafe { syrox_engine::worker::reraise_shell_command_signal(signal)? };
            Err(std::io::Error::other(
                "command termination signal returned",
            ))
        }
    }
}

#[allow(unsafe_code)]
fn managed_build(args: &[std::ffi::OsString]) -> Result<i32, syrox_engine::build::BuildError> {
    let signals =
        signals::OperationSignals::install().map_err(syrox_engine::build::BuildError::Io)?;
    // SAFETY: this dedicated executable has not started threads and terminates
    // after the helper, including failures after changing its user namespace.
    let result =
        unsafe { syrox_engine::worker::run_managed_build_entry(args, &signals.cancellation) };
    if signals.cancellation.is_cancelled() {
        Ok(i32::from(signals.cancelled_exit_code()))
    } else {
        result
    }
}

#[allow(unsafe_code)]
fn managed_build_ir(directory: &str, action: &str) -> Result<(), syrox_engine::build::BuildError> {
    // SAFETY: dedicated subprocess, no threads or borrowed global locks. The
    // helper validates its private namespace before installing process policy.
    unsafe { syrox_engine::worker::run_managed_build_worker(directory, action) }
}

#[allow(unsafe_code)]
fn service(args: &[std::ffi::OsString]) -> Result<i32, syrox_engine::worker::ServiceWorkerError> {
    // SAFETY: dedicated executable has started no threads and exits after return.
    unsafe {
        syrox_engine::worker::run_session_service(
            args,
            &syrox_engine::cancellation::Cancellation::default(),
        )
    }
}

#[allow(unsafe_code)]
fn os_service(args: &[std::ffi::OsString]) -> Result<i32, syrox_engine::worker::OsWorkerError> {
    // SAFETY: this dedicated executable starts no threads and exits after return.
    unsafe {
        syrox_engine::worker::run_os_service(
            args,
            &syrox_engine::cancellation::Cancellation::default(),
        )
    }
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
