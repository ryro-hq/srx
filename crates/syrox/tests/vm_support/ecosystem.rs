use super::{
    Result,
    common::{self},
    process::Control,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Repository {
    path: PathBuf,
    revision: String,
}

pub fn capture(core: &Path, evidence: &Path) -> Result<()> {
    let config = std::env::var_os("SYROX_ECOSYSTEM_CONFIG").map_or_else(
        || core.join("target/ecosystem-config.json"),
        PathBuf::from,
    );
    let repositories: BTreeMap<String, Repository> =
        serde_json::from_slice(&fs::read(&config).map_err(|error| {
            format!(
                "explicit five-repository configuration {}: {error}",
                config.display()
            )
        })?)?;
    let expected: BTreeSet<_> = [
        "syrox",
        "syrox-pkgs",
        "syrox-vscode",
        "syrox-opencode",
        "syrox.nvim",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if repositories
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(
            "ecosystem requires explicit paths and revisions for all five repositories".into(),
        );
    }
    let mut plan = BTreeMap::new();
    for (name, repository) in repositories {
        if !repository.path.is_absolute()
            || repository.revision.len() != 40
            || !repository
                .revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(
                "repository paths must be absolute and revisions must be full Git commit IDs"
                    .into(),
            );
        }
        let path = repository.path.canonicalize()?;
        let head = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&path)
            .output()?;
        if !head.status.success()
            || String::from_utf8_lossy(&head.stdout).trim() != repository.revision
        {
            return Err(format!("ecosystem revision differs: {name}").into());
        }
        if name == "syrox" {
            if path != core.canonicalize()? {
                return Err("ecosystem core must be the harness checkout".into());
            }
            plan.insert(
                name,
                json!({"revision":repository.revision,"sources":"source-manifest.json"}),
            );
        } else {
            let sources =
                super::snapshot::snapshot(&path, &evidence.join("ecosystem").join(&name))?;
            plan.insert(
                name,
                json!({"revision":repository.revision,"original_path":path,"snapshot":sources}),
            );
        }
    }
    common::save(&evidence.join("ecosystem-plan.json"), &plan)
}

pub fn guest(evidence: &Path, control: &Control) -> Result<Value> {
    let root = Path::new("/work/ecosystem");
    let binary = Path::new(common::GUEST_CANDIDATES).join("srx");
    let mut results = Vec::new();
    let fixture = fs::read("tests/fixtures/lsp-contract.json")?;
    for repository in [
        "syrox-vscode",
        "syrox-opencode",
        "syrox.nvim",
    ] {
        if fs::read(
            root.join(repository)
                .join("tests/fixtures/lsp-contract.json"),
        )? != fixture
        {
            return Err(format!("LSP contract differs: {repository}").into());
        }
    }
    let catalogue = root.join("syrox-pkgs");
    super::catalogue::run(
        Path::new("/work/src"),
        &catalogue,
        Path::new(common::GUEST_CANDIDATES),
        evidence,
        control,
    )?;
    results.push(json!({"repository":"syrox-pkgs","status":"passed","scope":"local catalogue tests; ignored artifact/host proofs remain pending"}));
    for repository in ["syrox-vscode", "syrox-opencode"] {
        super::process::command(
            Command::new("npm")
                .args(["run", "check"])
                .current_dir(root.join(repository))
                .env("SRX_BIN", &binary)
                .env("SRX_STD_DIR", "/work/src/std"),
            &evidence.join(format!("ecosystem-{repository}.log")),
            Duration::from_mins(2),
            control,
        )?;
        results.push(json!({"repository":repository,"status":"passed","scope":"local checks; real editor hosts pending"}));
    }
    for script in ["check", "smoke", "std"] {
        super::process::command(
            Command::new("nvim")
                .args(["--headless", "-u", "NONE", "-l"])
                .arg(format!("tests/{script}.lua"))
                .current_dir(root.join("syrox.nvim"))
                .env("SRX_BIN", &binary)
                .env("SRX_STD_DIR", "/work/src/std")
                .env("XDG_STATE_HOME", evidence.join("editor-state")),
            &evidence.join(format!("ecosystem-neovim-{script}.log")),
            Duration::from_mins(2),
            control,
        )?;
    }
    results.push(
        json!({"repository":"syrox.nvim","status":"passed","scope":"headless check/smoke/std"}),
    );
    let plan: BTreeMap<String, Value> =
        serde_json::from_slice(&fs::read(evidence.join("ecosystem-plan.json"))?)?;
    for (name, record) in plan {
        if name != "syrox" {
            let files = serde_json::from_value(record["snapshot"]["files"].clone())?;
            super::snapshot::verify_files(&root.join(name), &files)?;
        }
    }
    Ok(
        json!({"status":"passed","repositories":results,"pending":["seed/Hello/glibc artifacts", "VS Code and packaged OpenCode hosts"]}),
    )
}
