//! Auditable exception expiry, workflow policy and verified maintenance binaries.
use super::Result;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn today() -> Result<String> {
    // Gregorian date conversion from the UTC Unix day; no locale or clock shell.
    let days = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            / 86400,
    )? + 719_468;
    let era = days / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp
        + if mp < 10 {
            3
        } else {
            -9
        };
    if month <= 2 {
        year += 1;
    }
    Ok(format!("{year:04}-{month:02}-{day:02}"))
}

pub(super) fn exceptions() -> Result {
    let document: Value = serde_json::from_slice(&fs::read("security/exceptions.json")?)?;
    let configuration: toml::Value = toml::from_str(&fs::read_to_string("deny.toml")?)?;
    let records = document["exceptions"]
        .as_array()
        .ok_or("missing exception inventory")?;
    let today = today()?;
    for record in records {
        let expires = record["expires"]
            .as_str()
            .ok_or("exception lacks expiry")?;
        let reason = record["reason"]
            .as_str()
            .ok_or("exception lacks reason")?;
        if expires.len() != 10
            || expires <= today.as_str()
            || reason.len() < 30
            || record["owner"].as_str().is_none()
        {
            return Err("expired or unexplained security exception".into());
        }
        match record["kind"].as_str() {
            Some("advisory") => {
                let id = record["id"]
                    .as_str()
                    .ok_or("exception lacks advisory id")?;
                if !configuration["advisories"]["ignore"]
                    .as_array()
                    .is_some_and(|items| {
                        items
                            .iter()
                            .any(|item| item.get("id").and_then(toml::Value::as_str) == Some(id))
                    })
                {
                    return Err("advisory exception has no corresponding cargo-deny entry".into());
                }
            }
            Some("license") => {
                let name = record["package"]
                    .as_str()
                    .ok_or("exception lacks package")?;
                let version = record["version"]
                    .as_str()
                    .ok_or("exception lacks exact version")?;
                if !version.starts_with('=')
                    || !configuration["licenses"]["exceptions"]
                        .as_array()
                        .is_some_and(|items| {
                            items.iter().any(|item| {
                                item.get("name").and_then(toml::Value::as_str) == Some(name)
                                    && item.get("version").and_then(toml::Value::as_str)
                                        == Some(version)
                            })
                        })
                {
                    return Err("license exception lacks exact cargo-deny scope".into());
                }
            }
            _ => return Err("unsupported exception kind".into()),
        }
    }
    if let Some(items) = configuration
        .get("advisories")
        .and_then(|v| v.get("ignore"))
        .and_then(toml::Value::as_array)
    {
        for item in items {
            let id = item
                .get("id")
                .and_then(toml::Value::as_str)
                .ok_or("bare advisory ignores are not allowed")?;
            if !records
                .iter()
                .any(|record| record["kind"] == "advisory" && record["id"] == id)
            {
                return Err(format!("advisory {id} lacks a tracked expiry").into());
            }
        }
    }
    if let Some(items) = configuration
        .get("licenses")
        .and_then(|v| v.get("exceptions"))
        .and_then(toml::Value::as_array)
    {
        for item in items {
            if !records.iter().any(|record| {
                record["kind"] == "license"
                    && record["package"].as_str() == item.get("name").and_then(toml::Value::as_str)
                    && record["version"].as_str()
                        == item.get("version").and_then(toml::Value::as_str)
            }) {
                return Err("license exception lacks a tracked expiry".into());
            }
        }
    }
    println!(
        "{} scoped policy exceptions are unexpired",
        records.len()
    );
    Ok(())
}

pub(super) fn tools(destination: &Path, selection: &str) -> Result {
    if !destination.is_absolute() {
        return Err("tools destination must be absolute".into());
    }
    let document: Value = serde_json::from_slice(&fs::read("security/tools.json")?)?;
    fs::create_dir_all(destination)?;
    let mut selected = 0;
    for tool in document["tools"]
        .as_array()
        .ok_or("missing tool pins")?
    {
        let name = tool["name"].as_str().ok_or("missing tool name")?;
        if selection != "all"
            && selection != name
            && !(selection == "workflows" && ["actionlint", "shellcheck"].contains(&name))
        {
            continue;
        }
        selected += 1;
        if ![
            "actionlint",
            "shellcheck",
            "syft",
            "grype",
        ]
        .contains(&name)
        {
            return Err("unknown maintenance tool".into());
        }
        let pin = tool["sha256"]
            .as_str()
            .filter(|pin| hex(pin, 64))
            .ok_or("invalid tool digest")?;
        let url = tool["url"]
            .as_str()
            .filter(|url| {
                url.starts_with("https://github.com/") && !url.contains(['\n', '\r', '\0'])
            })
            .ok_or("invalid official tool URL")?;
        let temporary = tempfile::tempdir()?;
        let archive = temporary.path().join("tool.tar.gz");
        let status = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--max-time",
                "180",
                "--max-filesize",
                "134217728",
                "--url",
                url,
                "--output",
            ])
            .arg(&archive)
            .status()?;
        if !status.success() {
            return Err(format!("download failed: {name}").into());
        }
        let bytes = fs::read(&archive)?;
        if bytes.len() > 128 * 1024 * 1024 || format!("{:x}", Sha256::digest(&bytes)) != pin {
            return Err(format!("tool checksum mismatch: {name}").into());
        }
        let entry = if name == "shellcheck" {
            let version = tool["version"]
                .as_str()
                .filter(|version| {
                    version
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
                })
                .ok_or("invalid tool version")?;
            format!("shellcheck-v{version}/shellcheck")
        } else {
            name.to_owned()
        };
        if !Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("--directory")
            .arg(temporary.path())
            .args([
                "--no-same-owner",
                "--no-same-permissions",
                "--",
                &entry,
            ])
            .status()?
            .success()
        {
            return Err("tool extraction failed".into());
        }
        let binary = temporary.path().join(&entry);
        let meta = fs::symlink_metadata(&binary)?;
        if !meta.is_file() || meta.len() > 256 * 1024 * 1024 || meta.len() == 0 {
            return Err("expected bounded regular tool executable".into());
        }
        let mut source = fs::File::open(binary)?;
        let mut target = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(name))?;
        std::io::copy(&mut source, &mut target)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            target.set_permissions(fs::Permissions::from_mode(0o755))?;
        }
        target.sync_all()?;
        println!("verified {name}: archive sha256:{pin}");
    }
    if selected == 0 {
        return Err("no matching tool pin".into());
    }
    Ok(())
}

pub(super) fn classify(base: &str, head: &str) -> Result {
    if !hex(base, 40) || !hex(head, 40) {
        return Err("classification requires exact commit SHAs".into());
    }
    let output = Command::new("git")
        .args([
            "diff",
            "--name-only",
            "-z",
            base,
            head,
            "--",
        ])
        .output()?;
    if !output.status.success() {
        return Err("cannot classify changed files".into());
    }
    let mut paths = output
        .stdout
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .peekable();
    let heavy = paths.peek().is_none()
        || paths.any(|path| std::str::from_utf8(path).map_or(true, |path| !documentation(path)));
    println!("heavy={heavy}");
    Ok(())
}
fn documentation(path: &str) -> bool {
    matches!(
        path,
        "README.md" | "CONTRIBUTING.md" | "SECURITY.md" | "CODE_OF_CONDUCT.md" | "LICENSE"
    ) || (path.starts_with("docs/")
        && Path::new(path)
            .extension()
            .is_some_and(|extension| extension == "md"))
}

pub(super) fn commits(base: &str, head: &str) -> Result {
    if !hex(base, 40) || !hex(head, 40) {
        return Err("commit policy requires exact SHAs".into());
    }
    let output = Command::new("git")
        .args([
            "log",
            "--format=%s",
            &format!("{base}..{head}"),
        ])
        .output()?;
    if !output.status.success() {
        return Err("cannot inspect commits".into());
    }
    for subject in String::from_utf8(output.stdout)?.lines() {
        if !conventional(subject) {
            return Err(format!("expected type(lowercase-scope): description: {subject}").into());
        }
    }
    Ok(())
}
fn conventional(subject: &str) -> bool {
    let Some((prefix, description)) = subject.split_once(": ") else {
        return false;
    };
    let prefix = prefix.strip_suffix('!').unwrap_or(prefix);
    let Some((kind, scope)) = prefix.split_once('(') else {
        return false;
    };
    let Some(scope) = scope.strip_suffix(')') else {
        return false;
    };
    [
        "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore",
        "revert",
    ]
    .contains(&kind)
        && !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_/".contains(&b))
        && !description.trim().is_empty()
}

pub(super) fn workflows() -> Result {
    let mut paths = Vec::new();
    super::files(Path::new(".github"), ".yml", &mut paths)?;
    super::files(Path::new(".github"), ".yaml", &mut paths)?;
    for path in paths {
        let text = fs::read_to_string(&path)?;
        for line in text.lines() {
            let Some((_, uses)) = line.split_once("uses:") else {
                continue;
            };
            let uses = uses
                .split_whitespace()
                .next()
                .ok_or("empty action reference")?;
            if uses.starts_with("./") {
                continue;
            }
            if uses.starts_with("docker://")
                && uses
                    .rsplit_once("@sha256:")
                    .is_some_and(|(_, pin)| hex(pin, 64))
            {
                continue;
            }
            if !uses
                .rsplit_once('@')
                .is_some_and(|(_, pin)| hex(pin, 40))
            {
                return Err(format!(
                    "{}: action must be commit-pinned: {uses}",
                    path.display()
                )
                .into());
            }
        }
        if text.contains("pull_request_target:") {
            return Err("untrusted contribution builds cannot use pull_request_target".into());
        }
    }
    super::run("shellcheck", &["--version"])?;
    super::run("actionlint", &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scopes_and_documentation_classification_are_conservative() {
        for subject in [
            "feat(catalog): add K3s",
            "refactor(build)!: require exact versions",
            "ci(deps): update Actions",
        ] {
            assert!(conventional(subject));
        }
        for subject in [
            "feat: no scope",
            "fix(Core): uppercase",
            "catalog: old type",
            "fix(core): ",
        ] {
            assert!(!conventional(subject));
        }
        for path in [
            ".github/workflows/ci.yml",
            "Cargo.lock",
            "recipes/hello.srx",
            "docs/payload.sh",
            "new-format.unknown",
        ] {
            assert!(!documentation(path));
        }
        assert!(documentation("docs/authoring.md"));
        assert_eq!(today().unwrap().len(), 10);
    }
}
