//! Explicit editor checkouts, candidate pins, bounded logs and optional real hosts.
use super::{
    Result, common,
    process::{self, Control},
    snapshot,
};
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Inputs {
    pub core: PathBuf,
    pub binary: PathBuf,
    pub vscode: PathBuf,
    pub neovim: PathBuf,
    pub opencode: PathBuf,
    pub hosts: bool,
}

#[derive(Debug)]
pub struct Tools {
    pub npm: PathBuf,
    pub neovim: PathBuf,
}
impl Default for Tools {
    fn default() -> Self {
        Self {
            npm: "npm".into(),
            neovim: "nvim".into(),
        }
    }
}

pub fn main(args: &[String]) -> Result<()> {
    let core = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root unavailable")?
        .to_owned();
    let mut options = std::collections::BTreeMap::new();
    let mut hosts = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--hosts" {
            hosts = true;
            continue;
        }
        if !matches!(
            arg.as_str(),
            "--binary" | "--vscode" | "--neovim" | "--opencode"
        ) {
            return Err(format!("unknown editor option: {arg}").into());
        }
        let value = args
            .next()
            .ok_or("editor option requires a path")?;
        if options
            .insert(arg.as_str(), PathBuf::from(value))
            .is_some()
        {
            return Err("duplicate editor option".into());
        }
    }
    let mut take = |name| {
        options
            .remove(name)
            .ok_or_else(|| format!("required editor option: {name}"))
    };
    let input = Inputs {
        core,
        binary: take("--binary")?,
        vscode: take("--vscode")?,
        neovim: take("--neovim")?,
        opencode: take("--opencode")?,
        hosts,
    };
    let evidence = input
        .core
        .join("target/test-evidence")
        .join(format!(
            "editors-{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_nanos(),
            std::process::id()
        ));
    fs::create_dir_all(
        evidence
            .parent()
            .ok_or("evidence parent missing")?,
    )?;
    println!("editor evidence: {}", evidence.display());
    run(&input, &Tools::default(), &evidence)
}

pub fn run(input: &Inputs, tools: &Tools, evidence: &Path) -> Result<()> {
    // Refuse a reused destination; previous results are never overwritten.
    fs::create_dir(evidence)?;
    fs::set_permissions(evidence, fs::Permissions::from_mode(0o700))?;
    let control = Control::new(None)?;
    let mut report = json!({"status":"preparing","hosts":input.hosts,
        "pending":if input.hosts {vec![]} else {vec!["VS Code Extension Host", "packaged OpenCode host"]}});
    common::save(&evidence.join("report.json"), &report)?;
    let outcome: Result<()> = (|| {
        let binary = fs::canonicalize(&input.binary)?;
        if fs::metadata(&binary)?.permissions().mode() & 0o111 == 0 {
            return Err("editor candidate must be executable".into());
        }
        let fixture = fs::read(
            input
                .core
                .join("tests/fixtures/lsp-contract.json"),
        )?;
        for checkout in [
            &input.vscode,
            &input.neovim,
            &input.opencode,
        ] {
            if !checkout.is_absolute()
                || fs::read(checkout.join("tests/fixtures/lsp-contract.json"))? != fixture
            {
                return Err(format!(
                    "editor checkout path or contract differs: {}",
                    checkout.display()
                )
                .into());
            }
        }
        let candidates = evidence.join("candidates");
        common::private(&candidates)?;
        let candidate = candidates.join("srx");
        let pin = snapshot::copy_candidate(&binary, &candidate, 128 * 1024 * 1024)?;
        report["candidate"] = json!({"path":binary,"sha256":pin});
        let worker = binary.with_file_name("syrox-worker");
        if worker.exists() {
            report["worker_sha256"] = json!(snapshot::copy_candidate(
                &worker,
                &candidates.join("syrox-worker"),
                128 * 1024 * 1024
            )?);
        }
        common::save(&evidence.join("report.json"), &report)?;
        let mut commands: Vec<(&Path, Command, String)> = Vec::new();
        for (name, checkout) in [
            ("vscode", &input.vscode),
            ("opencode", &input.opencode),
        ] {
            let mut cmd = Command::new(&tools.npm);
            cmd.args(["run", "check"]);
            commands.push((checkout, cmd, format!("{name}-check")));
        }
        for script in ["check", "smoke", "std"] {
            let mut cmd = Command::new(&tools.neovim);
            cmd.args(["--headless", "-u", "NONE", "-l"])
                .arg(format!("tests/{script}.lua"));
            commands.push((&input.neovim, cmd, format!("neovim-{script}")));
        }
        if input.hosts {
            for (name, checkout, script) in [
                ("vscode", &input.vscode, "test:host"),
                ("opencode", &input.opencode, "test:package"),
                ("opencode", &input.opencode, "test:host"),
            ] {
                let mut cmd = Command::new(&tools.npm);
                cmd.args(["run", script]);
                commands.push((
                    checkout,
                    cmd,
                    format!("{name}-{}", script.replace(':', "-")),
                ));
            }
        }
        for (checkout, mut cmd, label) in commands {
            process::command(
                cmd.current_dir(checkout)
                    .env("SRX_BIN", &candidate)
                    .env("SRX_STD_DIR", input.core.join("std"))
                    .env("XDG_STATE_HOME", evidence.join("editor-state")),
                &evidence.join(format!("{label}.log")),
                Duration::from_mins(10),
                &control,
            )?;
            if snapshot::digest(&candidate)? != pin {
                return Err("editor candidate bytes changed".into());
            }
        }
        Ok(())
    })();
    report["status"] = json!(if outcome.is_ok() {
        "passed"
    } else {
        "failed"
    });
    if let Err(error) = &outcome {
        report["error"] = json!(error.to_string());
    }
    common::save(&evidence.join("report.json"), &report)?;
    outcome
}
