use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::process::ExitCode;

use syrox_lang::{
    MAX_SOURCE_BYTES, formatter::FormatError, formatter::format_source, source::Source,
};

#[derive(Debug, clap::Args)]
pub(crate) struct Arguments {
    /// Source file, or - to read standard input. Files are never overwritten.
    path: PathBuf,
    /// Emit no text and fail if the input is not already formatted.
    #[arg(long)]
    check: bool,
}

pub(crate) fn run(arguments: &Arguments) -> ExitCode {
    match execute(arguments) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("srx fmt: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(arguments: &Arguments) -> Result<bool, String> {
    let text = read_source(arguments)?;
    let source = Source::new(
        arguments.path.to_string_lossy().as_ref(),
        text.as_str(),
    )
    .map_err(|error| error.to_string())?;
    let formatted = format_source(&source).map_err(|error| match error {
        FormatError::Syntax(diagnostics) => diagnostics
            .iter()
            .map(|diagnostic| diagnostic.render(&source))
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.to_string(),
    })?;
    if arguments.check {
        if text != formatted {
            eprintln!("{}: formatting differs", arguments.path.display());
            return Ok(false);
        }
    } else {
        std::io::stdout()
            .lock()
            .write_all(formatted.as_bytes())
            .map_err(|error| format!("cannot write formatted source: {error}"))?;
    }
    Ok(true)
}

fn read_source(arguments: &Arguments) -> Result<String, String> {
    let reader: Box<dyn std::io::Read> = if arguments.path == std::path::Path::new("-") {
        Box::new(std::io::stdin().lock())
    } else {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&arguments.path)
            .map_err(|error| format!("{}: {error}", arguments.path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.len() > MAX_SOURCE_BYTES as u64 {
            return Err(format!(
                "{}: expected a regular source file of at most {MAX_SOURCE_BYTES} bytes",
                arguments.path.display()
            ));
        }
        Box::new(file)
    };
    let mut bytes = Vec::new();
    reader
        .take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(format!("source exceeds {MAX_SOURCE_BYTES} bytes"));
    }
    String::from_utf8(bytes).map_err(|error| format!("source is not UTF-8: {error}"))
}
