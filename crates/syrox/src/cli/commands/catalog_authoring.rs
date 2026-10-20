//! Transactional package authoring. Validation finishes before any project edit.
use std::{
    collections::BTreeMap,
    fs,
    io::Read as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};
use syrox_engine::project::{CheckConfiguration, check_path_with};
use syrox_lang::{formatter::format_source, source::Source};

type Error = Box<dyn std::error::Error>;
type Snapshot = BTreeMap<PathBuf, Option<Vec<u8>>>;

#[derive(Debug, clap::Args)]
pub(crate) struct Arguments {
    pub(crate) name: String,
    #[arg(long, default_value = ".")]
    pub(crate) path: PathBuf,
    #[arg(long, default_value = "autotools", value_parser = ["autotools"])]
    scaffold: String,
    #[arg(long)]
    version: String,
    #[arg(long)]
    url: String,
    #[arg(long)]
    sha256: String,
    #[arg(long)]
    maximum_bytes: u64,
    #[arg(long, conflicts_with = "source_directory")]
    source_name: Option<String>,
    #[arg(long)]
    source_directory: Option<String>,
    #[arg(long)]
    dry_run: bool,
}

fn component(text: &str) -> bool {
    text.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

fn literal(text: &str) -> Result<String, Error> {
    Ok(serde_json::to_string(text)?.replace('$', "\\$"))
}

impl Arguments {
    fn values(&self) -> Result<BTreeMap<&str, String>, Error> {
        let url = url::Url::parse(&self.url)?;
        if !self
            .name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || !self
                .version
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_digit)
            || !component(&self.version)
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !(1..=134_217_728).contains(&self.maximum_bytes)
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !url.path().ends_with(".tar.gz")
            || self.url.bytes().any(|b| b <= 32 || b == 127)
        {
            return Err("expected a lowercase package identifier, exact version, HTTPS .tar.gz URL and bounded SHA256 pin".into());
        }
        let source_name = self.source_name.as_deref().unwrap_or(&self.name);
        if !component(source_name)
            || self
                .source_directory
                .as_deref()
                .is_some_and(|name| !component(name))
        {
            return Err("source directory must be one archive directory name".into());
        }
        let directory = match &self.source_directory {
            Some(directory) => literal(directory)?,
            None => format!("\"{source_name}-${{source.version}}\""),
        };
        Ok(BTreeMap::from([
            ("name", self.name.clone()),
            ("version", literal(&self.version)?),
            ("url", literal(&self.url)?),
            ("sha256", literal(&self.sha256)?),
            ("maximum_bytes", self.maximum_bytes.to_string()),
            ("directory", directory),
        ]))
    }
}

fn bounded(path: &Path) -> Result<Vec<u8>, Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
        return Err(format!(
            "expected bounded regular project file: {}",
            path.display()
        )
        .into());
    }
    let mut result = Vec::new();
    fs::File::open(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut result)?;
    if result.len() as u64 != metadata.len() {
        return Err("project file changed while reading".into());
    }
    Ok(result)
}

fn snapshot(root: &Path) -> Result<Snapshot, Error> {
    fn visit(
        root: &Path,
        relative: &Path,
        result: &mut Snapshot,
        total: &mut usize,
    ) -> Result<(), Error> {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        if result.len() >= 4096 || metadata.is_symlink() {
            return Err("project contains too many files or a symbolic link".into());
        }
        if metadata.is_dir() {
            result.insert(relative.into(), None);
            for entry in fs::read_dir(path)? {
                visit(
                    root,
                    &relative.join(entry?.file_name()),
                    result,
                    total,
                )?;
            }
        } else {
            let bytes = bounded(&path)?;
            *total += bytes.len();
            if *total > 64 * 1024 * 1024 {
                return Err("authoring snapshot exceeds 64 MiB".into());
            }
            result.insert(relative.into(), Some(bytes));
        }
        Ok(())
    }
    let mut result = Snapshot::new();
    let mut total = 0;
    for name in [
        "main.srx",
        "recipes",
        "assets",
        "scaffolds",
    ] {
        if root.join(name).try_exists()? {
            visit(root, Path::new(name), &mut result, &mut total)?;
        }
    }
    Ok(result)
}

fn formatted(name: &str, text: &str) -> Result<String, Error> {
    Ok(format_source(&Source::new(name, text)?)?)
}

pub(crate) fn generate(args: &Arguments, checks: &CheckConfiguration) -> Result<String, Error> {
    generate_with(args, checks, || {})
}

fn generate_with(
    args: &Arguments,
    checks: &CheckConfiguration,
    after_validation: impl FnOnce(),
) -> Result<String, Error> {
    let values = args.values()?;
    let root = args.path.canonicalize()?;
    let lock = fs::File::open(&root)?;
    lock.lock()?;
    let destination = root.join("recipes/packages").join(&args.name);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err("package already exists".into());
    }
    let original = snapshot(&root)?;
    let main = original
        .get(Path::new("main.srx"))
        .and_then(Option::as_ref)
        .ok_or("missing main.srx")?;
    let mut files = BTreeMap::new();
    for name in ["package", "build", "releases"] {
        let scaffold = root
            .join("scaffolds")
            .join(&args.scaffold)
            .join(format!("{name}.srx.in"));
        let text = String::from_utf8(bounded(&scaffold)?)?;
        // Substitute only @{name}; shell variables and srx interpolation stay literal.
        let mut rendered = String::new();
        let mut remaining = text.as_str();
        while let Some((before, after)) = remaining.split_once("@{") {
            rendered.push_str(before);
            let (key, rest) = after
                .split_once('}')
                .ok_or("unterminated scaffold placeholder")?;
            rendered.push_str(
                values
                    .get(key)
                    .ok_or("unknown scaffold placeholder")?,
            );
            remaining = rest;
        }
        rendered.push_str(remaining);
        files.insert(format!("{name}.srx"), formatted(name, &rendered)?);
    }
    let alias: String = args
        .name
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            chars
                .next()
                .unwrap()
                .to_uppercase()
                .collect::<String>()
                + chars.as_str()
        })
        .collect();
    let name = &args.name;
    let main_text = formatted(
        "main.srx",
        &format!(
            "{}\npub use catalog::packages::{name}::{name}_version;\npub type {alias}Selection = catalog::packages::{name}::Selection;\npub let {name} = recipe_ref(catalog::packages::{name}::recipe);\n",
            std::str::from_utf8(main)?.trim_end()
        ),
    )?;
    let stage = tempfile::Builder::new()
        .prefix(".srx-authoring-")
        .tempdir_in(
            root.parent()
                .ok_or("catalog requires a parent directory")?,
        )?;
    for (relative, contents) in &original {
        let path = stage.path().join(relative);
        match contents {
            None => fs::create_dir_all(path)?,
            Some(bytes) => {
                fs::create_dir_all(path.parent().ok_or("invalid snapshot path")?)?;
                fs::write(path, bytes)?;
            }
        }
    }
    let staged_package = stage.path().join("recipes/packages").join(name);
    fs::create_dir(&staged_package)?;
    for (name, text) in &files {
        fs::write(staged_package.join(name), text)?;
    }
    let staged_main = stage.path().join("main.srx");
    fs::write(&staged_main, &main_text)?;
    fs::set_permissions(
        &staged_main,
        fs::Permissions::from_mode(
            fs::metadata(root.join("main.srx"))?
                .permissions()
                .mode()
                & 0o777,
        ),
    )?;
    check_path_with(stage.path(), checks)?;
    after_validation();
    if snapshot(&root)? != original || fs::symlink_metadata(&destination).is_ok() {
        return Err("project changed while preparing the package; retry".into());
    }
    if args.dry_run {
        return Ok(serde_json::to_string_pretty(
            &serde_json::json!({"destination": destination, "files": files, "main.srx": main_text}),
        )?);
    }
    commit_package(
        &staged_package,
        &destination,
        &staged_main,
        &root.join("main.srx"),
    )?;
    Ok(serde_json::to_string_pretty(
        &serde_json::json!({"package": name, "status": "experimental", "path": destination,
        "next": ["srx project lock .", "srx project check .", "review outputs and qualify before catalog registration"]}),
    )?)
}

fn commit_package(
    staged_package: &Path,
    destination: &Path,
    staged_main: &Path,
    main: &Path,
) -> Result<(), Error> {
    fs::rename(staged_package, destination)?;
    if let Err(error) = fs::rename(staged_main, main) {
        fs::rename(destination, staged_package)?;
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn invalid_authoring_arguments_fail_before_project_access() {
        for (field, value) in [
            ("name", "bad-name"),
            ("version", "latest"),
            ("url", "https://user@example.com/file.tar.gz"),
            ("sha256", "bad"),
            ("maximum-bytes", "0"),
        ] {
            let mut args = vec![
                "srx",
                "catalog",
                "new",
                "good",
                "--version",
                "1.2.3",
                "--url",
                "https://example.com/a.tar.gz",
                "--sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--maximum-bytes",
                "1024",
            ];
            let index = if field == "name" {
                3
            } else {
                args.iter()
                    .position(|arg| *arg == format!("--{field}"))
                    .unwrap()
                    + 1
            };
            args[index] = value;
            let cli = crate::cli::arguments::Cli::try_parse_from(args).unwrap();
            let crate::cli::arguments::Command::Catalog {
                command: super::super::catalog::Command::New(arguments),
            } = cli.command
            else {
                panic!("catalog new");
            };
            assert!(arguments.values().is_err(), "{field}");
        }
        assert_eq!(literal("a${b}").unwrap(), "\"a\\${b}\"");
    }
    #[test]
    fn failed_main_commit_rolls_back_the_package() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path();
        let staged = path.join("staged");
        let destination = path.join("package");
        fs::create_dir(&staged).unwrap();
        fs::write(staged.join("package.srx"), "original").unwrap();
        let main = path.join("main.srx");
        fs::create_dir(&main).unwrap();
        fs::write(main.join("kept"), "unchanged").unwrap();
        let staged_main = path.join("staged.srx");
        fs::write(&staged_main, "new main").unwrap();
        assert!(commit_package(&staged, &destination, &staged_main, &main).is_err());
        assert!(!destination.exists());
        assert_eq!(
            fs::read_to_string(staged.join("package.srx")).unwrap(),
            "original"
        );
        assert_eq!(
            fs::read_to_string(main.join("kept")).unwrap(),
            "unchanged"
        );
    }

    #[test]
    fn editor_changes_during_validation_are_preserved() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path();
        fs::create_dir_all(path.join("recipes/packages")).unwrap();
        fs::create_dir_all(path.join("scaffolds/autotools")).unwrap();
        fs::write(
            path.join("main.srx"),
            "inputs { catalog = \"modules:recipes\"; }\n",
        )
        .unwrap();
        fs::write(
            path.join("scaffolds/autotools/package.srx.in"),
            r#"pub struct Selection { version: PackagePinText; }
pub fn @{name}_version() -> RecipeRef<Recipe> { recipe_ref(recipe) }
pub fn recipe() -> Recipe { Recipe { package = Package { id = "sample"; dependencies = []; }; } }
"#,
        )
        .unwrap();
        for name in ["build", "releases"] {
            fs::write(
                path.join(format!("scaffolds/autotools/{name}.srx.in")),
                "pub value Text(str);\n",
            )
            .unwrap();
        }
        let args = Arguments {
            name: "sample".into(),
            path: path.into(),
            scaffold: "autotools".into(),
            version: "1.2.3".into(),
            url: "https://example.org/sample.tar.gz".into(),
            sha256: "a".repeat(64),
            maximum_bytes: 1024,
            source_name: None,
            source_directory: None,
            dry_run: false,
        };
        let edited = "inputs { catalog = \"modules:recipes\"; }\n// Kept from another editor.\n";
        let result = generate_with(
            &args,
            &CheckConfiguration {
                standard_library: Some(
                    syrox_engine::project::AuthenticatedStandardLibrary::bundled(),
                ),
                ..CheckConfiguration::default()
            },
            || {
                fs::write(path.join("main.srx"), edited).unwrap();
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("project changed")
        );
        assert_eq!(
            fs::read_to_string(path.join("main.srx")).unwrap(),
            edited
        );
        assert!(!path.join("recipes/packages/sample").exists());
    }
}
