//! Public reference, configuration and realization boundaries. These cases never
//! need a build host or external service; the sandbox flow has its own host test.
#![cfg(target_os = "linux")]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use syrox_engine::{
    acquire::local::AuthorizedLocalDirectory, acquire::local::LocalSourceRequest,
    acquire::local::acquire_local, store::ContentDigest, store::RootName, store::Store,
};

struct Fixture {
    directory: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
    config: PathBuf,
    store: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("home with spaces");
        let project = directory.path().join("project");
        let config = home.join(".config/syrox/config.toml");
        let store = home.join(".local/share/syrox/store");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::create_dir(&project).unwrap();
        let fixture = Self {
            directory,
            home,
            project,
            config,
            store,
        };
        fixture.write_recipe();
        fixture
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_srx"));
        command
            .args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .output()
            .unwrap()
    }

    fn write_recipe(&self) {
        let digest = ContentDigest::sha256(b"source");
        fs::write(self.project.join("main.srx"), format!(r#"fn recipe() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "internal-id"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [
                std::SourceRequest {{ url = "https://nonexistent.invalid/source"; sha256 = "{digest}"; maximum_bytes = 100; }}
            ]; }});
            build = std::Option::Some(std::autotools(std::BuildOptions {{ source_directory = "fixture";
                timeout_seconds = 30;
            }}));
            commands = [];
        }} }}
        mod factories::friendly {{ pub fn recipe() -> std::Recipe {{ project::recipe() }} }}
        pub publish(factories, recipe): std::Recipe;
        "#)).unwrap();
        success(self.run(&["project", "lock", "."]));
    }

    fn configure(&self, catalog: bool) {
        let mut text = "[build]\nhost-toolchain = '/usr'\n".to_owned();
        if catalog {
            let info = success(self.run(&["info", ".#friendly"]));
            let digest = info
                .lines()
                .find_map(|line| line.strip_prefix("lock sha256 "))
                .unwrap();
            write!(
                &mut text,
                "[catalog]\npath = '{}'\nlock-sha256 = '{digest}'\n",
                self.project.display()
            )
            .unwrap();
        }
        fs::write(&self.config, text).unwrap();
    }
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn failure(output: Output, expected: &str) {
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains(expected), "{error}");
}

#[test]
fn run_requires_a_declared_command_and_uses_the_locked_file_selection() {
    let fixture = Fixture::new();
    let file = fixture.project.join("main.srx");
    let file = file.to_str().unwrap();
    failure(
        fixture.run(&["run", "-f", file]),
        "select a public member",
    );
    failure(
        fixture.run(&["run", ".#friendly", "-f", file]),
        "--command",
    );
    failure(
        fixture.run(&[
            "run",
            ".#friendly",
            "--command",
            "main",
            "-f",
            file,
        ]),
        "no declared command",
    );
    let source = fs::read_to_string(file).unwrap().replace(
        "commands = [];",
        r#"commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/app"; }];"#,
    );
    fs::write(file, source).unwrap();
    success(fixture.run(&["project", "lock", "."]));
    fixture.configure(false);
    failure(
        fixture.run(&[
            "run",
            ".#friendly",
            "--command",
            "main",
            "-f",
            file,
            "-o",
            "--",
            "argument",
        ]),
        "absent in offline mode",
    );
    fixture.configure(true);
    failure(
        fixture.run(&[
            "run",
            "friendly",
            "--command",
            "main",
            "-o",
        ]),
        "absent in offline mode",
    );
}

#[test]
fn pinned_project_file_acquisition_needs_no_network_or_build_host() {
    let fixture = Fixture::new();
    let bytes = b"pinned local source bytes";
    let digest = ContentDigest::sha256(bytes);
    fs::create_dir(fixture.project.join("assets")).unwrap();
    fs::write(
        fixture.project.join("assets/source.tar.gz"),
        bytes,
    )
    .unwrap();
    let recipe = fixture.project.join("main.srx");
    let original = fs::read_to_string(&recipe).unwrap();
    let updated = original
        .replace(
            "https://nonexistent.invalid/source",
            "project:assets/source.tar.gz",
        )
        .replace(
            &ContentDigest::sha256(b"source").to_string(),
            &digest.to_string(),
        );
    fs::write(recipe, updated).unwrap();
    success(fixture.run(&["project", "lock", "."]));
    success(fixture.run(&["project", "lock", "--check", "."]));
    fixture.configure(false);
    let store = Store::initialize(&fixture.store).unwrap();
    let authority = AuthorizedLocalDirectory::open(&fixture.project).unwrap();
    let request = LocalSourceRequest::new(
        &format!(
            "file://{}/assets/source.tar.gz",
            fixture.project.display()
        ),
        digest,
        100,
    )
    .unwrap();
    let root = RootName::new(format!("source_{digest}")).unwrap();
    assert!(
        !acquire_local(&store, &authority, &request, &root)
            .unwrap()
            .cache_hit()
    );
    assert!(
        acquire_local(&store, &authority, &request, &root)
            .unwrap()
            .cache_hit()
    );
    assert!(
        store
            .operation()
            .unwrap()
            .verify(digest)
            .unwrap()
            .is_some()
    );
}

#[test]
#[ignore = "inventories the host /usr before rejecting the intentionally invalid local archive"]
fn offline_build_imports_project_source_from_a_path_with_url_metacharacters() {
    let mut fixture = Fixture::new();
    let relocated = fixture.directory.path().join("project % # ü");
    fs::rename(&fixture.project, &relocated).unwrap();
    fixture.project = relocated;
    let bytes = b"not a gzip archive";
    let digest = ContentDigest::sha256(bytes);
    fs::create_dir(fixture.project.join("assets")).unwrap();
    fs::write(
        fixture.project.join("assets/source.tar.gz"),
        bytes,
    )
    .unwrap();
    let recipe = fixture.project.join("main.srx");
    let updated = fs::read_to_string(&recipe)
        .unwrap()
        .replace(
            "https://nonexistent.invalid/source",
            "project:assets/source.tar.gz",
        )
        .replace(
            &ContentDigest::sha256(b"source").to_string(),
            &digest.to_string(),
        );
    fs::write(recipe, updated).unwrap();
    success(fixture.run(&["project", "lock", "."]));
    fixture.configure(false);
    failure(
        fixture.run(&["build", ".#friendly", "-o"]),
        "archive",
    );
    let store = Store::open(&fixture.store).unwrap();
    assert!(
        store
            .operation()
            .unwrap()
            .verify(digest)
            .unwrap()
            .is_some()
    );
}

#[test]
fn explicit_store_and_config_do_not_require_a_home_or_xdg_data_directory() {
    let fixture = Fixture::new();
    fixture.configure(false);
    let output = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["build", "-n", ".#friendly", "--config"])
        .arg(&fixture.config)
        .arg("--store")
        .arg(&fixture.store)
        .current_dir(&fixture.project)
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap();
    assert!(success(output).contains("would build internal-id"));
}

#[test]
fn compact_cli_selects_project_file_searches_pinned_catalog_and_checks_dry_run() {
    let fixture = Fixture::new();
    let file = fixture.project.join("main.srx");
    let file = file.to_str().unwrap();
    let direct = success(fixture.run(&["info", ".#friendly"]));
    assert_eq!(
        success(fixture.run(&["info", "-f", file, "--search", "friend"])).trim(),
        "friendly"
    );
    assert_eq!(
        success(fixture.run(&["info", ".", "--search", "friend"])).trim(),
        "friendly"
    );
    failure(
        fixture.run(&[
            "info",
            ".#friendly",
            "--search",
            "friend",
        ]),
        "requires a project path",
    );
    let selected = success(fixture.run(&["info", "-f", file, ".#friendly"]));
    assert_eq!(direct, selected);
    failure(
        fixture.run(&["info", "-f", file]),
        "select a public member",
    );
    failure(fixture.run(&["info"]), "select a public member");
    failure(
        fixture.run(&["info", "friendly", "-f", file]),
        "-f/--file selects a project",
    );
    failure(
        fixture.run(&["info", "-f", "other.srx"]),
        "main.srx",
    );
    assert!(success(fixture.run(&["project", "check", "-f", file])).contains("checked"));
    assert!(success(fixture.run(&["project", "lock", "--check", "-f", file])).contains("current"));
    assert!(success(fixture.run(&["project", "plan", "-f", file])).contains("internal-id"));
    failure(
        fixture.run(&["project", "plan", ".", "-f", file]),
        "either a project path",
    );
    let preview = success(fixture.run(&["build", ".#friendly", "-n", "-f", file]));
    assert!(preview.starts_with("would build internal-id"));
    let all = success(fixture.run(&["build", "-n", "-A", "-f", file]));
    assert!(all.contains("friendly"));
    assert!(!fixture.store.exists());
    failure(
        fixture.run(&["build", "-j", "2", "-f", file]),
        "--all",
    );
    fixture.configure(true);
    assert_eq!(
        success(fixture.run(&["info", "--search", "friend"])).trim(),
        "friendly"
    );
    assert_eq!(
        success(fixture.run(&["info", "--search", "absent"])).trim(),
        "no matching packages"
    );
    failure(
        fixture.run(&["info", "hello", "--search", "friend"]),
        "requires a project path",
    );
    assert!(!fixture.store.exists());
}

#[test]
fn search_lists_locked_functional_package_set_without_evaluating_recipes() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.project.join("recipes/group")).unwrap();
    fs::write(
        fixture.project.join("recipes/group/hello.srx"),
        "pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = \"hello\"; dependencies = []; }; } }",
    )
    .unwrap();
    fs::write(
        fixture.project.join("recipes/unused.srx"),
        "pub fn recipe() -> std::Recipe { recipe() }",
    )
    .unwrap();
    fs::write(
        fixture.project.join("main.srx"),
        r#"
        inputs { recipes = "modules:recipes"; }
        pub publish(recipes, recipe): std::Recipe;

        "#,
    )
    .unwrap();
    success(fixture.run(&["project", "lock", "."]));
    let file = fixture.project.join("main.srx");
    assert_eq!(
        success(fixture.run(&[
            "info",
            "-f",
            file.to_str().unwrap(),
            "--search",
            "group"
        ]))
        .trim(),
        "group::hello"
    );
    assert_eq!(
        success(fixture.run(&["info", ".", "--search", "unused"])).trim(),
        "unused"
    );
    assert_eq!(
        success(fixture.run(&[
            "info",
            fixture.project.to_str().unwrap(),
            "--search",
            "group",
        ]))
        .trim(),
        "group::hello"
    );
    let digest = ContentDigest::sha256(&fs::read(fixture.project.join("Syrox.lock")).unwrap());
    fs::write(
        &fixture.config,
        format!(
            "[catalog]\npath = '{}'\nlock-sha256 = '{digest}'\n",
            fixture.project.display()
        ),
    )
    .unwrap();
    assert_eq!(
        success(fixture.run(&["info", "--search", "group"])).trim(),
        "group::hello"
    );
    assert_eq!(
        success(fixture.run(&["info", "--search", "unused"])).trim(),
        "unused"
    );
    assert!(!fixture.store.exists());
    fs::write(
        fixture.project.join("recipes/new.srx"),
        "pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = \"new\"; dependencies = []; }; } }",
    )
    .unwrap();
    failure(fixture.run(&["info", "--search", "new"]), "drift");
    failure(
        fixture.run(&[
            "info",
            "-f",
            file.to_str().unwrap(),
            "--search",
            "new",
        ]),
        "lock",
    );
}

#[test]
fn explicit_recipe_export_selected_from_imported_package_set_works_in_cli() {
    let fixture = Fixture::new();
    let catalog = fixture.directory.path().join("catalog");
    fs::create_dir_all(catalog.join("recipes")).unwrap();
    fs::write(
        catalog.join("main.srx"),
        r#"
        inputs { recipes = "modules:recipes"; }
        pub type Entry = std::Recipe;
        pub publish(recipes, recipe): Entry;

    "#,
    )
    .unwrap();
    fs::write(catalog.join("recipes/hello.srx"), r#"
        pub fn recipe() -> std::Recipe {
            std::Recipe {
                package = std::Package { id = "internal-hello"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                    "https://nonexistent.invalid/source", "0000000000000000000000000000000000000000000000000000000000000000", 100
                )]; });
                build = std::Option::Some(std::autotools(std::BuildOptions { source_directory = "hello-1";
                    timeout_seconds = 30; }));
                build_inputs = std::Option::None;
                commands = [];
            }
        }
    "#).unwrap();
    fs::write(
        catalog.join("recipes/unused.srx"),
        "pub fn recipe() -> std::Recipe { recipe() }",
    )
    .unwrap();
    fs::create_dir_all(catalog.join("recipes/group")).unwrap();
    fs::copy(
        catalog.join("recipes/hello.srx"),
        catalog.join("recipes/group/hello.srx"),
    )
    .unwrap();
    success(fixture.run(&[
        "project",
        "lock",
        catalog.to_str().unwrap(),
    ]));
    let selected = format!("{}#hello", catalog.display());
    let direct = success(fixture.run(&["info", &selected]));
    assert!(direct.contains("internal-hello"), "{direct}");
    assert!(
        success(fixture.run(&["build", "-n", &selected])).contains("would build internal-hello")
    );
    let catalog_lock = ContentDigest::sha256(&fs::read(catalog.join("Syrox.lock")).unwrap());
    fs::write(
        &fixture.config,
        format!(
            "[catalog]\npath = '{}'\nlock-sha256 = '{catalog_lock}'\n",
            catalog.display()
        ),
    )
    .unwrap();
    assert_eq!(success(fixture.run(&["info", "hello"])), direct);
    assert!(
        success(fixture.run(&["build", "-n", "group::hello"]))
            .contains("would build internal-hello")
    );
    failure(
        fixture.run(&[
            "run",
            "group::hello",
            "--command",
            "main",
        ]),
        "no declared command",
    );
    failure(
        fixture.run(&["info", "unused"]),
        "evaluation failed",
    );
    failure(
        fixture.run(&["info", "missing"]),
        "no public buildable package export",
    );
    fs::write(
        fixture.project.join("main.srx"),
        r#"
        inputs { pkgs = "path:../catalog"; }
        pub use pkgs::hello;

    "#,
    )
    .unwrap();
    success(fixture.run(&["project", "lock", "."]));
    let info = success(fixture.run(&["info", ".#hello"]));
    assert!(info.contains("internal-hello"));
    assert!(
        success(fixture.run(&["build", "-n", ".#hello"])).contains("would build internal-hello")
    );
    let all = success(fixture.run(&["build", "-n", "-A"]));
    assert!(all.contains("hello"));
    assert!(!all.contains("unused"));
    failure(
        fixture.run(&["info", "."]),
        "select a public member",
    );
    assert!(!fixture.store.exists());
}

#[test]
fn store_gc_previews_and_collects_only_unretained_objects() {
    let fixture = Fixture::new();
    let store = Store::initialize(&fixture.store).unwrap();
    let orphan = ContentDigest::sha256(b"orphan");
    store
        .operation()
        .unwrap()
        .ingest(&b"orphan"[..], orphan, 6)
        .unwrap();
    let retained = ContentDigest::sha256(b"retained");
    let lease = store.operation().unwrap();
    lease
        .ingest(&b"retained"[..], retained, 8)
        .unwrap();
    lease
        .publish_root(&RootName::new("keep").unwrap(), &[retained])
        .unwrap();
    drop(lease);
    let first = success(fixture.run(&["store", "gc"]));
    assert!(
        first.contains("1 unretained object(s), 6 bytes collectable"),
        "{first}"
    );
    assert!(
        store
            .operation()
            .unwrap()
            .verify(orphan)
            .unwrap()
            .is_some()
    );
    let applied = success(fixture.run(&["store", "gc", "--apply"]));
    assert!(
        applied.contains("1 unretained object(s), 6 bytes collected"),
        "{applied}"
    );
    assert!(
        store
            .operation()
            .unwrap()
            .verify(orphan)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .operation()
            .unwrap()
            .verify(retained)
            .unwrap()
            .is_some()
    );
    failure(
        fixture.run(&["store", "doctor"]),
        "not configured",
    );
}

#[test]
fn all_build_exports_are_selected_from_one_file_and_offline_misses_do_not_publish() {
    let fixture = Fixture::new();
    let file = fixture.project.join("main.srx");
    let text = fs::read_to_string(&file).unwrap();
    let text = text.replace("pub publish(factories, recipe)",
        "mod factories::another { pub fn recipe() -> std::Recipe { project::recipe() } } pub publish(factories, recipe)");
    fs::write(&file, text).unwrap();
    success(fixture.run(&["project", "lock"]));
    fixture.configure(false);
    let file = file.to_str().unwrap();
    let preview = success(fixture.run(&[
        "build", "-A", "-j", "2", "-n", "-f", file,
    ]));
    assert!(preview.contains("another, friendly"), "{preview}");
    assert!(!fixture.store.exists());
    failure(
        fixture.run(&[
            "build", "-A", "-j", "2", "-o", "-f", file,
        ]),
        "offline mode",
    );
    assert_eq!(
        fs::read_dir(fixture.store.join("roots/retained"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn references_require_explicit_members_without_local_catalog_fallback() {
    let fixture = Fixture::new();
    let local = success(fixture.run(&["info", ".#friendly"]));
    assert!(local.contains("package internal-id"));
    assert!(local.contains("backend syrox-host-program-x86_64-v3"));
    failure(fixture.run(&["info"]), "select a public member");
    assert!(!fixture.store.exists());
    fs::create_dir(fixture.project.join("friendly")).unwrap();
    failure(
        fixture.run(&["info", "friendly"]),
        "no default catalog",
    );
    failure(
        fixture.run(&["info", ".#internal-id"]),
        "invalid build reference",
    );
    failure(
        fixture.run(&["info", ".#source"]),
        "no public buildable package export",
    );
    fixture.configure(true);
    assert_eq!(
        success(fixture.run(&["info", "friendly"]))
            .lines()
            .take(7)
            .collect::<Vec<_>>(),
        local.lines().take(7).collect::<Vec<_>>()
    );
    // Re-locking a changed checkout is insufficient to change its registered pin.
    let path = fixture.project.join("main.srx");
    let text = fs::read_to_string(&path)
        .unwrap()
        .replace("timeout_seconds = 30", "timeout_seconds = 31");
    fs::write(path, text).unwrap();
    failure(fixture.run(&["info", ".#friendly"]), "drift");
    success(fixture.run(&["project", "lock", "."]));
    failure(
        fixture.run(&["info", "friendly"]),
        "catalog lock has changed",
    );
    success(fixture.run(&["info", ".#friendly"]));
    assert!(!fixture.store.exists());
}

#[test]
fn automatic_store_initialization_offline_miss_and_network_policy_are_distinct() {
    let fixture = Fixture::new();
    // A project config cannot grant host or network authority.
    fs::write(
        fixture.project.join("syrox.toml"),
        "[build]\nhost-toolchain='/usr'",
    )
    .unwrap();
    failure(
        fixture.run(&["build", ".#friendly"]),
        "host bootstrap is not configured",
    );
    assert!(!fixture.store.exists());
    fixture.configure(false);
    failure(
        fixture.run(&["build", ".#friendly", "--offline"]),
        "absent in offline mode",
    );
    assert!(fixture.store.join("roots/retained").is_dir());
    failure(
        fixture.run(&["build", ".#friendly"]),
        "no exact grant",
    );
    assert_eq!(
        fs::read_dir(fixture.store.join("roots/retained"))
            .unwrap()
            .count(),
        0
    );
    // Corruption is reported before any network retry or backend probe.
    let store = Store::open(&fixture.store).unwrap();
    let digest = ContentDigest::sha256(b"source");
    store
        .operation()
        .unwrap()
        .ingest(&b"source"[..], digest, 100)
        .unwrap();
    let text = digest.to_string();
    fs::write(
        fixture
            .store
            .join("objects/sha256")
            .join(&text[..2])
            .join(&text),
        b"broken",
    )
    .unwrap();
    failure(
        fixture.run(&["build", ".#friendly", "--offline"]),
        "corrupt",
    );
}

#[test]
fn xdg_and_cli_paths_are_operational_and_initialization_refuses_collisions() {
    let fixture = Fixture::new();
    fixture.configure(false);
    let data = fixture.directory.path().join("xdg data");
    let config = fixture.home.join(".config");
    let output = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["build", ".#friendly", "--offline"])
        .current_dir(&fixture.project)
        .env_remove("HOME")
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_DATA_HOME", &data)
        .output()
        .unwrap();
    failure(output, "absent in offline mode");
    assert!(data.join("syrox/store/roots/retained").exists());
    assert!(!fixture.store.exists());
    let collision = fixture.directory.path().join("collision");
    fs::write(&collision, b"keep me").unwrap();
    failure(
        fixture.run(&[
            "build",
            ".#friendly",
            "--offline",
            "--store",
            collision.to_str().unwrap(),
        ]),
        "directory",
    );
    assert_eq!(fs::read(collision).unwrap(), b"keep me");
    let symlink = fixture.directory.path().join("linked");
    std::os::unix::fs::symlink(&data, &symlink).unwrap();
    failure(
        fixture.run(&[
            "build",
            ".#friendly",
            "--offline",
            "--store",
            symlink.join("new").to_str().unwrap(),
        ]),
        "symbolic link",
    );
    assert!(!data.join("new").exists());
}
