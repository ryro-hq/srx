use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::process::ExitCode;

use syrox_engine::{
    bundle::export_bundle, bundle::import_bundle, result::AdmittedResult, result::ResultCommand,
    result::ResultManifest, result::admit_result, runtime::RuntimeFile, runtime::RuntimeOutput,
    runtime::RuntimeRequest, runtime::run_runtime_with_cancellation,
    runtime::verify_runtime_with_cancellation, store::ContentDigest, store::RootName, store::Store,
};

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    /// Export a verified built application and its explicitly selected providers.
    Export(Export),
    /// Admit an offline bundle authorized by an independently supplied manifest pin.
    Import(Import),
    /// Inspect an admitted manifest without evaluating a project or starting a build.
    Inspect(Selection),
    /// Run a named command from an admitted bundle, offline.
    Run(Run),
}

#[derive(Debug, clap::Args)]
pub(crate) struct Selection {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    root: String,
    /// Exact manifest digest authorized by local policy.
    #[arg(long)]
    manifest_sha256: String,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Export {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    root: String,
    #[arg(long)]
    receipt: String,
    /// Named build output containing the command.
    #[arg(long, default_value = "out")]
    artifact_output: String,
    /// Executable path relative to the selected output.
    #[arg(long)]
    entry: String,
    /// Destination must not exist.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value = "main")]
    name: String,
    #[arg(long, requires_all = ["loader_receipt", "loader_entry"])]
    loader_root: Option<String>,
    #[arg(long, requires = "loader_root")]
    loader_receipt: Option<String>,
    #[arg(long, default_value = "out")]
    loader_output: String,
    #[arg(long, requires = "loader_root")]
    loader_entry: Option<String>,
    /// Repeat ROOT@RECEIPT@OUTPUT for each runtime library output.
    #[arg(long)]
    library: Vec<String>,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Import {
    #[command(flatten)]
    selection: Selection,
    #[arg(long)]
    file: PathBuf,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Run {
    #[command(flatten)]
    selection: Selection,
    #[arg(long, default_value = "main")]
    command: String,
    #[arg(last = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

pub(crate) fn run(command: &Command) -> ExitCode {
    let signals = match crate::signals::OperationSignals::install() {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    match execute(command, &signals.cancellation) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            if signals.cancellation.is_cancelled() {
                ExitCode::from(signals.cancelled_exit_code())
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn runtime_output(root: &str, receipt: &str, output: &str) -> Result<RuntimeOutput, String> {
    Ok(RuntimeOutput {
        output: output.to_owned(),
        root: RootName::new(root).map_err(|error| error.to_string())?,
        receipt: receipt
            .parse()
            .map_err(|error: syrox_engine::store::DigestParseError| error.to_string())?,
    })
}

fn open(
    selection: &Selection,
    cancellation: &syrox_engine::cancellation::Cancellation,
) -> Result<(Store, AdmittedResult), String> {
    let root = RootName::new(&selection.root).map_err(|error| error.to_string())?;
    let digest = selection
        .manifest_sha256
        .parse::<ContentDigest>()
        .map_err(|error| error.to_string())?;
    let store = Store::open(&selection.store).map_err(|error| error.to_string())?;
    let admitted = AdmittedResult::open(&store, &root, digest, cancellation)
        .map_err(|error| error.to_string())?;
    Ok((store, admitted))
}

fn execute(
    command: &Command,
    cancellation: &syrox_engine::cancellation::Cancellation,
) -> Result<ExitCode, String> {
    match command {
        Command::Export(args) => export(args, cancellation)?,
        Command::Import(args) => {
            let root = RootName::new(&args.selection.root).map_err(|error| error.to_string())?;
            let expected = args
                .selection
                .manifest_sha256
                .parse::<ContentDigest>()
                .map_err(|error| error.to_string())?;
            // Opening a FIFO must not wait for a writer before cancellation can
            // be observed. Validate the opened inode before initializing Store.
            let mut input = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&args.file)
                .map_err(|error| error.to_string())?;
            let metadata = input
                .metadata()
                .map_err(|error| error.to_string())?;
            if !metadata.is_file() || metadata.len() > syrox_engine::bundle::MAX_BUNDLE_BYTES {
                return Err(
                    "bundle input must be a regular file within the bundle byte limit".into(),
                );
            }
            let store =
                Store::initialize(&args.selection.store).map_err(|error| error.to_string())?;
            import_bundle(&store, &root, expected, &mut input, cancellation)
                .map_err(|error| error.to_string())?;
            println!(
                "manifest {expected}\nroot {}",
                args.selection.root
            );
        }
        Command::Inspect(selection) => {
            let (_, admitted) = open(selection, cancellation)?;
            println!(
                "manifest {}\nroot {}\norigin imported",
                selection.manifest_sha256, selection.root
            );
            for (key, output) in admitted.manifest().outputs() {
                println!(
                    "output {key} {} {} {}",
                    output.action, output.output, output.artifact
                );
            }
            for name in admitted.manifest().commands().keys() {
                println!("command {name}");
            }
        }
        Command::Run(args) => {
            let (store, admitted) = open(&args.selection, cancellation)?;
            let selected = admitted
                .command(&args.command)
                .ok_or_else(|| format!("bundle has no command `{}`", args.command))?;
            let closure = selected
                .open(&store, cancellation)
                .map_err(|error| error.to_string())?;
            // The verified closure owns granular interests now. Release the
            // admission transaction before the potentially long-running payload.
            drop(admitted);
            let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
            let status = run_runtime_with_cancellation(&closure, &args.argv, &cwd, cancellation)
                .map_err(|error| error.to_string())?;
            return Ok(crate::cli::presentation::exit_status(status, 129));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn export(
    args: &Export,
    cancellation: &syrox_engine::cancellation::Cancellation,
) -> Result<(), String> {
    let store = Store::open(&args.store).map_err(|error| error.to_string())?;
    let loader = args
        .loader_root
        .as_deref()
        .zip(args.loader_receipt.as_deref())
        .map(|(root, receipt)| {
            Ok::<_, String>(RuntimeFile {
                output: runtime_output(root, receipt, &args.loader_output)?,
                path: args
                    .loader_entry
                    .clone()
                    .ok_or("loader requires --loader-entry")?,
            })
        })
        .transpose()?;
    let libraries = args
        .library
        .iter()
        .map(|text| {
            let parts: Vec<_> = text.split('@').collect();
            let [root, receipt, output] = parts.as_slice() else {
                return Err("library must be ROOT@RECEIPT@OUTPUT".to_owned());
            };
            runtime_output(root, receipt, output)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let request = RuntimeRequest {
        application: RuntimeFile {
            output: runtime_output(&args.root, &args.receipt, &args.artifact_output)?,
            path: args.entry.clone(),
        },
        loader,
        libraries,
    };
    let closure = verify_runtime_with_cancellation(&store, &request, cancellation)
        .map_err(|error| error.to_string())?;
    let mut outputs = BTreeMap::from([(
        "application".to_owned(),
        &closure.application().output,
    )]);
    let loader = closure.loader().map(|view| {
        outputs.insert("loader".to_owned(), &view.output);
        "loader".to_owned()
    });
    let libraries = closure
        .libraries()
        .iter()
        .enumerate()
        .map(|(index, view)| {
            let key = format!("library_{index}");
            outputs.insert(key.clone(), view);
            key
        })
        .collect();
    let commands = BTreeMap::from([(
        args.name.clone(),
        ResultCommand {
            application: "application".to_owned(),
            application_path: closure.application().path.as_str().to_owned(),
            loader_path: closure
                .loader()
                .map(|file| file.path.as_str())
                .map(str::to_owned),
            loader,
            libraries,
        },
    )]);
    let manifest =
        ResultManifest::from_views(outputs, commands).map_err(|error| error.to_string())?;
    let digest = manifest
        .digest()
        .map_err(|error| error.to_string())?;
    let root = RootName::new(format!("result_{digest}")).map_err(|error| error.to_string())?;
    admit_result(&store, &root, &manifest, digest, cancellation)
        .map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .map_err(|error| error.to_string())?;
    let result = export_bundle(&store, &root, digest, &mut file, cancellation)
        .map_err(|error| error.to_string())
        .and_then(|()| file.sync_all().map_err(|error| error.to_string()));
    drop(file);
    if let Err(error) = result {
        if let Err(cleanup) = std::fs::remove_file(&args.output) {
            return Err(format!(
                "{error}; output cleanup failed: {cleanup}"
            ));
        }
        return Err(error);
    }
    println!("manifest {digest}");
    Ok(())
}
