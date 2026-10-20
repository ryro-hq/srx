use std::process::ExitCode;
use syrox_engine::{
    project::CheckFailure, project::ProjectOperationError, realize::CommandError,
    realize::RealizeError,
};

/// Keep source diagnostics when operational handlers convert typed errors to text.
pub(crate) fn project_error(error: &ProjectOperationError) -> String {
    let ProjectOperationError::Check(failure) = error else {
        return error.to_string();
    };
    let mut message = error.to_string();
    match failure {
        CheckFailure::Diagnostics {
            input,
            errors,
        } => {
            message.push('\n');
            message.push_str(&diagnostics_text(input, errors));
        }
        CheckFailure::Evaluation {
            input,
            errors,
            failed_roots,
        } => {
            message.push('\n');
            message.push_str(&diagnostics_text(input, errors));
            if !failed_roots.is_empty() {
                message.push_str("failed evaluation root(s): ");
                message.push_str(&failed_roots.join(", "));
            }
        }
        _ => {}
    }
    message
}

pub(crate) fn realize_error(error: &RealizeError) -> String {
    match error {
        RealizeError::Project(error) => project_error(error),
        error => error.to_string(),
    }
}

pub(crate) fn command_error(error: &CommandError) -> String {
    match error {
        CommandError::Resolve(error) => realize_error(error),
        CommandError::Project(error) => project_error(error),
        error => error.to_string(),
    }
}

pub(crate) fn usage_error(error: &str) -> ExitCode {
    eprintln!("error: {error}");
    ExitCode::from(2)
}

pub(crate) fn render_operation_error(error: ProjectOperationError) -> ExitCode {
    match error {
        ProjectOperationError::Check(error) => render_check_error(error),
        error => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

pub(crate) fn render_check_error(error: CheckFailure) -> ExitCode {
    match error {
        CheckFailure::Diagnostics {
            input,
            errors,
        } => {
            render_diagnostics(&input, &errors);
            ExitCode::from(1)
        }
        CheckFailure::Evaluation {
            input,
            errors,
            failed_roots,
        } => {
            render_diagnostics(&input, &errors);
            if failed_roots.is_empty() {
                eprintln!("error: evaluation failed");
            } else {
                eprintln!(
                    "error: failed evaluation root(s): {}",
                    failed_roots.join(", ")
                );
            }
            ExitCode::from(1)
        }
        error => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

/// Render only after the operation has completed cleanup. A received signal
/// takes precedence over its result while preserving any cleanup diagnostic.
pub(crate) fn render_cancellable_result(
    signals: &crate::signals::OperationSignals,
    result: Result<ExitCode, String>,
) -> ExitCode {
    if signals.cancellation.is_cancelled() {
        if let Err(error) = result {
            eprintln!("error: {error}");
        }
        return ExitCode::from(signals.cancelled_exit_code());
    }
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn render_message(result: Result<String, String>) -> ExitCode {
    match result {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn render_diagnostics(
    input: &syrox_lang::source::SourceSet,
    errors: &[syrox_lang::diagnostic::Diagnostic],
) {
    eprint!("{}", diagnostics_text(input, errors));
}

fn diagnostics_text(
    input: &syrox_lang::source::SourceSet,
    errors: &[syrox_lang::diagnostic::Diagnostic],
) -> String {
    let mut text = String::new();
    for error in errors {
        if let Some(rendered) = error.render_from(input) {
            text.push_str(&rendered);
        } else {
            text.push_str("error: ");
            text.push_str(&error.to_string());
            text.push('\n');
        }
    }
    text
}

/// Preserve each command's policy for a status with neither code nor signal.
pub(crate) fn exit_status(status: std::process::ExitStatus, missing: u8) -> ExitCode {
    use std::os::unix::process::ExitStatusExt as _;
    let code = status.code().unwrap_or_else(|| {
        status
            .signal()
            .map_or(i32::from(missing), |signal| 128 + signal)
    });
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::OperationSignals;

    #[test]
    fn nested_operational_errors_preserve_type_and_evaluation_diagnostics() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("main.srx");
        for (text, expected, root) in [
            (
                "value Number(int); let broken: Number = \"wrong\";",
                "srx.type-check",
                None,
            ),
            (
                "resource Port(int); outputs { duplicate: [Port] = [Port(80), Port(80)]; }",
                "resource claim conflicts",
                Some("failed evaluation root(s): duplicate"),
            ),
        ] {
            std::fs::write(&source, text).unwrap();
            let failure = syrox_engine::project::check_path_with(
                directory.path(),
                &crate::cli::configuration(true),
            )
            .unwrap_err();
            let error = CommandError::Resolve(RealizeError::Project(
                ProjectOperationError::Check(failure),
            ));
            let rendered = command_error(&error);
            assert!(rendered.contains(expected), "{rendered}");
            assert!(rendered.contains("main.srx:1:"), "{rendered}");
            assert!(rendered.contains(text), "{rendered}");
            if let Some(root) = root {
                assert!(rendered.contains(root), "{rendered}");
            }
        }
    }

    #[test]
    fn completed_operation_preserves_reconciliation_status_unless_cancelled() {
        let signals = OperationSignals::install().unwrap();
        assert_eq!(
            render_cancellable_result(&signals, Ok(ExitCode::from(2))),
            ExitCode::from(2),
        );
        assert_eq!(
            render_cancellable_result(&signals, Err("cleanup unconfirmed".into())),
            ExitCode::FAILURE,
        );
        // Cancel cooperatively without sending a signal to the test runner.
        signals.cancellation.cancel();
        assert_eq!(
            render_cancellable_result(&signals, Ok(ExitCode::from(2))),
            ExitCode::from(130),
        );
        assert_eq!(
            render_cancellable_result(&signals, Err("cleanup unconfirmed".into())),
            ExitCode::from(130),
        );
    }
}
