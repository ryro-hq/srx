//! Reproducible developer checks and security gates used locally and in CI.
use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};
mod policy;
mod release;
mod structure;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
fn run(program: &str, args: &[&str]) -> Result {
    if !Command::new(program)
        .args(args)
        .status()?
        .success()
    {
        return Err(format!("{program} {args:?} failed").into());
    }
    Ok(())
}
fn files(path: &Path, suffix: &str, found: &mut Vec<PathBuf>) -> Result {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            files(&entry.path(), suffix, found)?;
        } else if entry.file_type()?.is_file()
            && entry
                .file_name()
                .to_string_lossy()
                .ends_with(suffix)
        {
            found.push(entry.path());
        }
    }
    Ok(())
}
fn language_format(write: bool) -> Result {
    let cli = if let Some(cli) = env::var_os("SRX") {
        PathBuf::from(cli)
    } else {
        run(
            "cargo",
            &[
                "build", "--locked", "-p", "syrox", "--bin", "srx",
            ],
        )?;
        env::var_os("CARGO_TARGET_DIR")
            .map_or_else(|| PathBuf::from("target"), PathBuf::from)
            .join("debug/srx")
    };
    let mut paths = Vec::new();
    for root in ["std", "examples"] {
        files(Path::new(root), ".srx", &mut paths)?;
    }
    for path in paths {
        let mut command = Command::new(&cli);
        command.arg("fmt").arg(&path);
        if write {
            let output = command.output()?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr)
                    .into_owned()
                    .into());
            }
            fs::write(path, output.stdout)?;
        } else if !command.arg("--check").status()?.success() {
            return Err("srx formatting differs".into());
        }
    }
    Ok(())
}
fn check() -> Result {
    run("cargo", &["fmt", "--all", "--", "--check"])?;
    run(
        "rustfmt",
        &[
            "--edition",
            "2024",
            "--check",
            "tests/fixtures/stalled-test.rs",
        ],
    )?;
    structure::run(Path::new("."))?;
    language_format(false)?;
    run(
        "cargo",
        &[
            "check",
            "--workspace",
            "--all-targets",
            "--locked",
            "--no-default-features",
        ],
    )
}
fn suite(name: &str) -> Result {
    match name {
        "portable" => {
            run("cargo", &["test", "--locked", "-p", "syrox-lang"])?;
            run(
                "cargo",
                &[
                    "test", "--locked", "-p", "srx-fuzz", "--lib",
                ],
            )?;
            run(
                "cargo",
                &[
                    "test",
                    "--locked",
                    "-p",
                    "syrox",
                    "--no-default-features",
                    "--bins",
                    "--test",
                    "cli",
                    "--test",
                    "diagnostics",
                    "--test",
                    "public_bindings",
                    "--test",
                    "language_reference",
                    "--test",
                    "os_profiles",
                    "--test",
                    "usability",
                    "--test",
                    "format",
                    "--test",
                    "lsp",
                    "--test",
                    "vm_harness",
                ],
            )?;
            run("cargo", &["test", "--locked", "-p", "xtask"])
        }
        "native" | "acceptance" => {
            if name == "native" {
                run(
                    "cargo",
                    &[
                        "test", "--locked", "-p", "syrox", "--test", "vm", "--", "--suite",
                        "native",
                    ],
                )
            } else {
                run(
                    "cargo",
                    &[
                        "test", "--locked", "-p", "syrox", "--test", "vm",
                    ],
                )
            }
        }
        _ => Err(
            "suite must be portable, native or acceptance; VM suites require explicit preparation"
                .into(),
        ),
    }
}
fn main() -> ExitCode {
    let result = execute();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}
fn execute() -> Result {
    env::set_current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?;
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["check"] => check(),
        ["structure"] => { structure::run(Path::new("."))?; Ok(()) },
        ["fmt"] => { run("cargo", &["fmt", "--all"])?; language_format(true) }
        ["test", "--suite", name] => suite(name),
        ["security", "exceptions"] => policy::exceptions(),
        ["security", "workflows"] => policy::workflows(),
        ["security", "tools", "--output", directory] => policy::tools(Path::new(directory), "all"),
        ["security", "tools", "--output", directory, "--tool", name] => policy::tools(Path::new(directory), name),
        ["ci", "classify", base, head] => policy::classify(base, head),
        ["ci", "commits", base, head] => policy::commits(base, head),
        ["release", "core", directory, target] => release::core(Path::new(directory), target),
        ["release", "catalog", directory] => release::catalog(Path::new(directory)),
        ["release", "checksums", directory] => release::checksums(Path::new(directory)),
        ["security", "audit"] => run("cargo", &["deny", "--locked", "check"]),
        _ => Err("use cargo xtask check | fmt | test --suite portable|native|acceptance | security audit".into()),
    }
}
