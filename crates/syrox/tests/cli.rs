#[cfg(target_os = "linux")]
use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use syrox_engine::{store::ContentDigest, store::Store};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempProject(PathBuf);

impl TempProject {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "syrox-cli-test-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join("main.srx"),
            "value Number(int); outputs { answer: Number = 42; }",
        )
        .unwrap();
        Self(path)
    }

    fn write(&self, text: &str) {
        std::fs::write(self.0.join("main.srx"), text).unwrap();
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(arguments)
        .output()
        .expect("srx should start")
}

#[test]
fn host_manager_diagnostic_survives_an_invalid_cgroup_selection() {
    let project = TempProject::new();
    let bus = project.0.join("missing-user-bus");
    let output = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["host", "inspect", "--cgroup-parent"])
        .arg(&project.0)
        .arg("--systemd-user-bus")
        .arg(&bus)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "invalid:must-not-be-used",
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!(
        "systemd scope user; bus {}",
        bus.display()
    )));
    assert!(stdout.contains("systemd API: unavailable"));
    assert!(stdout.contains("logout and boot: not verified"));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("cgroup parent")
    );
}

fn project_command(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_srx"))
        .arg("project")
        .args(arguments)
        .output()
        .expect("srx should start")
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[cfg(target_os = "linux")]
#[test]
fn host_inspect_needs_no_external_command_and_rejects_outside_cgroupfs() {
    let result = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["host", "inspect"])
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8_lossy(&result.stdout);
    assert!(output.contains("openat2:"));
    assert!(output.contains("cgroup-delegation: requires active probe"));
    assert!(output.contains("cgroup-child-control: requires active probe"));
    assert!(output.contains("cgroup-probe-migration: requires active probe"));
    let probe = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["host", "inspect", "--probe-cgroup"])
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert!(
        probe.status.success(),
        "{}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let probed = String::from_utf8_lossy(&probe.stdout);
    assert!(
        probed.contains("cgroup-child-control: available (")
            || probed.contains("cgroup-child-control: unavailable (")
    );
    assert!(
        probed.contains("cgroup-probe-migration: available (")
            || probed.contains("cgroup-probe-migration: unavailable (")
    );
    assert!(probed.contains("cgroup-delegation: requires active probe"));
    let invalid = run(&[
        "host",
        "inspect",
        "--cgroup-parent",
        "/tmp",
    ]);
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("beneath /sys/fs/cgroup"));
}

#[cfg(target_os = "linux")]
#[test]
fn gated_probe_child_waits_for_parent_before_exit() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["host", "probe-child"])
        .env("PATH", "/nonexistent")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = [0];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .unwrap();
    assert_eq!(&ready, b"R");
    assert!(child.try_wait().unwrap().is_none());
    drop(child.stdin.take());
    assert!(!child.wait().unwrap().success());
}

#[test]
fn check_reports_success_and_language_errors_with_distinct_exit_codes() {
    let valid = project_command(&[
        "check",
        fixture("valid.srx").to_str().unwrap(),
    ]);
    assert!(valid.status.success());
    assert!(String::from_utf8_lossy(&valid.stdout).contains("13 top-level declaration(s)"));

    let without_std = run(&[
        "--std",
        "none",
        "project",
        "check",
        fixture("valid.srx").to_str().unwrap(),
    ]);
    assert!(without_std.status.success());
    assert!(String::from_utf8_lossy(&without_std.stdout).contains("3 top-level declaration(s)"));

    let invalid = project_command(&[
        "check",
        fixture("invalid.srx").to_str().unwrap(),
    ]);
    assert_eq!(invalid.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("expected `]` after list type"));

    let evaluation_invalid = project_command(&[
        "check",
        fixture("evaluation-invalid.srx")
            .to_str()
            .unwrap(),
    ]);
    assert_eq!(evaluation_invalid.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&evaluation_invalid.stderr).contains("resource claim conflicts")
    );
    assert!(
        String::from_utf8_lossy(&evaluation_invalid.stderr)
            .contains("failed evaluation root(s): duplicate")
    );

    let usage = run(&[]);
    assert_eq!(usage.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&usage.stderr).contains("Usage:"));
    for removed in [
        "recover-builds",
        "reindex-builds",
        "lock",
        "plan",
        "check",
        "fetch",
    ] {
        let output = run(&[removed]);
        assert_eq!(output.status.code(), Some(2), "{removed}");
    }
}

#[test]
fn check_accepts_project_directories_and_reports_loader_errors() {
    let valid = project_command(&[
        "check",
        fixture("project").to_str().unwrap(),
    ]);
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert!(String::from_utf8_lossy(&valid.stdout).contains("13 top-level declaration(s)"));

    let invalid = project_command(&[
        "check",
        fixture("project-invalid").to_str().unwrap(),
    ]);
    assert_eq!(invalid.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("unsupported locator"));
}

#[test]
fn built_in_std_mode_is_locked_and_plans_package_dependencies() {
    let project = TempProject::new();
    project.write(
        r#"fn library() -> std::Recipe { std::Recipe {
            package = std::Package { id = "lib"; dependencies = []; };
            acquisition = None; build = None; build_inputs = None; commands = [];
        } }
        fn application() -> std::Recipe { std::Recipe {
            package = std::Package { id = "app"; dependencies = [std::Dependency { recipe = lib; }]; };
            acquisition = None; build = None; build_inputs = None; commands = [];
        } }
        mod factories::app { pub fn recipe() -> std::Recipe { project::application() } }
        mod factories::lib { pub fn recipe() -> std::Recipe { project::library() } }
        pub publish(factories, recipe): std::Recipe;"#,
    );
    let path = project.0.to_str().unwrap();

    assert!(project_command(&["lock", path]).status.success());

    let plan = project_command(&["plan", path]);
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let output = String::from_utf8_lossy(&plan.stdout);
    assert!(output.contains("std sha256 "));
    assert!(output.contains("packages 2 edges 1"));
    assert!(output.find("package \"lib\"").unwrap() < output.find("package \"app\"").unwrap());

    let no_std_project = TempProject::new();
    let no_std_path = no_std_project.0.to_str().unwrap();
    assert!(
        run(&[
            "--std",
            "none",
            "project",
            "lock",
            no_std_path
        ])
        .status
        .success()
    );
    let drift = project_command(&["lock", "--check", no_std_path]);
    assert_eq!(drift.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&drift.stderr).contains("standard library has drifted"));
}

#[test]
fn selected_consumer_plan_is_lazy_and_does_not_materialize_configuration() {
    let project = TempProject::new();
    project.write(
        r#"fn package() -> std::Recipe { std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });
            package = std::Package { id = "only-in-service"; dependencies = []; };
            acquisition = std::Option::Some(std::Acquisition { sources = [
                std::source_request("https://nonexistent.invalid/config.tar",
                    "0000000000000000000000000000000000000000000000000000000000000000", 1024)
            ]; });
        } }
        fn broken() -> std::Os { broken() }
        mod factories::broken_catalog { pub fn recipe() -> std::Recipe { recipe() } }
        pub publish(factories, recipe): std::Recipe;
        outputs {
            os: std::Os = broken();
            shell: std::Shell = std::Shell {
                pkgs = [];
                services = [std::Service {
                    id = "cli-config";
                    pkgs = [std::select_package(std::recipe_ref(package))];
                    files = [std::ConfigFile {
                        path = "config/example.conf";
                        text = "managed=true";
                    }];
                }];
            };
        }"#,
    );
    let path = project.0.to_str().unwrap();
    let locked = project_command(&["lock", path]);
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    let source = std::fs::read(project.0.join("main.srx")).unwrap();
    let lock = std::fs::read(project.0.join("Syrox.lock")).unwrap();

    let selected = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["project", "plan", "--output", "shell"])
        .current_dir(&project.0)
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    let display = String::from_utf8_lossy(&selected.stdout);
    for expected in [
        "consumer",
        "shell",
        "cli-config",
        "config/example.conf",
        "package \"only-in-service\"",
    ] {
        assert!(
            display.contains(expected),
            "missing {expected}: {display}"
        );
    }
    assert!(!project.0.join("config").exists());
    assert_eq!(std::fs::read_dir(&project.0).unwrap().count(), 2);
    assert_eq!(
        std::fs::read(project.0.join("main.srx")).unwrap(),
        source
    );
    assert_eq!(
        std::fs::read(project.0.join("Syrox.lock")).unwrap(),
        lock
    );

    let broken = project_command(&["plan", path, "--output", "os"]);
    assert_eq!(broken.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&broken.stderr).contains("function call depth limit reached"),
        "{}",
        String::from_utf8_lossy(&broken.stderr)
    );
    assert!(broken.stdout.is_empty());
}

#[test]
fn selected_consumer_plan_rejects_missing_and_nonstandard_outputs() {
    let project = TempProject::new();
    project.write(
        r"value Number(int);
        struct Shell { pkgs: [std::RecipeRef<std::Recipe>]; services: [std::Service]; }
        fn imitation_value() -> Shell { imitation_value() }
        outputs {
            answer: Number = 42;
            imitation: Shell = imitation_value();
            valid: std::Shell = std::Shell { pkgs = []; services = []; };
        }",
    );
    let path = project.0.to_str().unwrap();
    let locked = project_command(&["lock", path]);
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    let lock = std::fs::read(project.0.join("Syrox.lock")).unwrap();
    let missing = project_command(&["plan", path, "--output", "missing"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing"));
    assert!(missing.stdout.is_empty());
    for name in ["answer", "imitation"] {
        let invalid = project_command(&["plan", path, "--output", name]);
        assert_eq!(invalid.status.code(), Some(1));
        let diagnostic = String::from_utf8_lossy(&invalid.stderr);
        assert!(
            diagnostic.contains("Os") || diagnostic.contains("Shell"),
            "{diagnostic}"
        );
        assert!(!diagnostic.contains("function call depth limit reached"));
        assert!(invalid.stdout.is_empty());
    }
    assert_eq!(
        std::fs::read(project.0.join("Syrox.lock")).unwrap(),
        lock
    );
}

#[test]
fn plan_displays_pinned_sources_without_acquiring_them() {
    let project = TempProject::new();
    let digest = "0".repeat(64);
    project.write(&format!(
        r#"mod factories::app {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{
            sources = [std::SourceRequest {{
                url = "https://nonexistent.invalid/pinned.tar";
                sha256 = "{digest}";
                maximum_bytes = 1024;
            }}];
        }}); }} }} }} pub publish(factories, recipe): std::Recipe;"#
    ));
    let path = project.0.to_str().unwrap();
    assert!(project_command(&["lock", path]).status.success());
    assert!(
        project_command(&["lock", "--check", path])
            .status
            .success()
    );
    let output = project_command(&["plan", path]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let display = String::from_utf8_lossy(&output.stdout);
    assert!(display.contains("syrox plan\n"));
    assert!(display.contains("acquisition \"app\" sources 1"));
    assert!(display.contains("https://nonexistent.invalid/pinned.tar"));
}

#[test]
fn fetch_requires_exact_grant_and_reuses_verified_bytes_offline() {
    let project = TempProject::new();
    let store_path = TempProject::new();
    let bytes = b"pinned source bytes";
    let digest = ContentDigest::sha256(bytes);
    let url = "https://nonexistent.invalid/hello.tar";
    project.write(&format!(
        r#"mod factories::app {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{ package = std::Package {{ id = "app"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "{url}"; sha256 = "{digest}"; maximum_bytes = 100; }}
        ]; }}); }} }} }} pub publish(factories, recipe): std::Recipe;"#
    ));
    let path = project.0.to_str().unwrap();
    let store = store_path.0.to_str().unwrap();
    assert!(project_command(&["lock", path]).status.success());
    let missing = project_command(&[
        "inspect-source",
        path,
        "app",
        "0",
        "--store",
        store,
    ]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("absent"));
    let denied = project_command(&[
        "fetch",
        path,
        "app",
        "0",
        "--store",
        store,
        "--root",
        "catalog_hello",
        "--allow-https",
        "https://other.invalid/hello.tar",
    ]);
    assert_eq!(denied.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("exact planned source URL"));

    let store_handle = Store::open(&store_path.0).unwrap();
    store_handle
        .operation()
        .unwrap()
        .ingest(&bytes[..], digest, 100)
        .unwrap();
    let fetched = project_command(&[
        "fetch",
        path,
        "app",
        "0",
        "--store",
        store,
        "--root",
        "catalog_hello",
        "--allow-https",
        url,
    ]);
    assert!(
        fetched.status.success(),
        "{}",
        String::from_utf8_lossy(&fetched.stderr)
    );
    assert!(String::from_utf8_lossy(&fetched.stdout).contains("cache_hit=true"));
    assert!(
        store_path
            .0
            .join("roots/retained/catalog_hello")
            .exists()
    );

    project.write("value Changed(int); outputs { changed: Changed = 2; }");
    let drift = project_command(&[
        "fetch",
        path,
        "app",
        "0",
        "--store",
        store,
        "--root",
        "other_root",
        "--allow-https",
        url,
    ]);
    assert_eq!(drift.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&drift.stderr).contains("drift"));
    assert!(
        !store_path
            .0
            .join("roots/retained/other_root")
            .exists()
    );
}

#[test]
fn source_commands_resolve_public_export_to_its_package_node() {
    let project = TempProject::new();
    let store = TempProject::new();
    let digest = ContentDigest::sha256(b"pinned bytes");
    project.write(&format!(r#"
        fn make() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "internal-id"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [
                std::SourceRequest {{ url = "https://example.invalid/source.tar"; sha256 = "{digest}"; maximum_bytes = 100; }}
            ]; }});
            build = None; build_inputs = None; commands = [];
        }} }}
        mod factories::public_alias {{ pub fn recipe() -> std::Recipe {{ project::make() }} }}
        pub publish(factories, recipe): std::Recipe;

    "#));
    let path = project.0.to_str().unwrap();
    let storage = store.0.to_str().unwrap();
    let lock = project_command(&["lock", path]);
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let unopened_store = store.0.join("uninitialized-store");
    let unopened = unopened_store.to_str().unwrap();
    for command in ["fetch", "inspect-source"] {
        let mut arguments = vec![
            command,
            path,
            "public_alias",
            "1",
            "--store",
            unopened,
        ];
        if command == "fetch" {
            arguments.extend([
                "--root",
                "invalid_source",
                "--allow-https",
                "https://example.invalid/source.tar",
            ]);
        }
        let invalid = project_command(&arguments);
        assert_eq!(invalid.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&invalid.stderr)
                .contains("no acquisition source at that index"),
            "{}",
            String::from_utf8_lossy(&invalid.stderr),
        );
        assert!(
            !unopened_store.exists(),
            "source selection must precede Store I/O"
        );
    }
    let inspected = project_command(&[
        "inspect-source",
        path,
        "public_alias",
        "0",
        "--store",
        storage,
    ]);
    assert_eq!(inspected.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&inspected.stderr).contains("absent"),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let denied = project_command(&[
        "fetch",
        path,
        "public_alias",
        "0",
        "--store",
        storage,
        "--root",
        "aliased_source",
        "--allow-https",
        "https://other.invalid/source.tar",
    ]);
    assert_eq!(denied.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("exact planned source URL"));
}

#[test]
fn package_graph_failures_are_stable_cli_errors() {
    let project = TempProject::new();
    let path = project.0.to_str().unwrap();
    project.write(
        r#"fn missing() -> std::Recipe { missing() }
        fn make_app() -> std::Recipe { std::Recipe {
            package = std::Package { id = "app"; dependencies = [std::Dependency { recipe = std::recipe_ref(missing); }]; };
            acquisition = None; build = None; build_inputs = None; commands = [];
        } }
        mod factories::app { pub fn recipe() -> std::Recipe { project::make_app() } }
        pub publish(factories, recipe): std::Recipe;"#,
    );
    assert!(project_command(&["lock", path]).status.success());
    let missing = project_command(&["plan", path]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("function call depth limit reached"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );

    project.write(
        r#"fn make_a() -> std::Recipe { std::Recipe {
            package = std::Package { id = "a"; dependencies = [std::Dependency { recipe = b; }]; };
            acquisition = None; build = None; build_inputs = None; commands = [];
        } }
        fn make_b() -> std::Recipe { std::Recipe {
            package = std::Package { id = "b"; dependencies = [std::Dependency { recipe = a; }]; };
            acquisition = None; build = None; build_inputs = None; commands = [];
        } }
        mod factories::a { pub fn recipe() -> std::Recipe { project::make_a() } }
        mod factories::b { pub fn recipe() -> std::Recipe { project::make_b() } }
        pub publish(factories, recipe): std::Recipe;"#,
    );
    assert!(project_command(&["lock", path]).status.success());
    let cycle = project_command(&["plan", path]);
    assert_eq!(cycle.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&cycle.stderr).contains("package dependency cycle: a -> b"));
}

#[test]
fn lock_check_drift_and_plan_are_end_to_end() {
    let project = TempProject::new();
    project.write("outputs { shell: std::Shell = std::Shell { pkgs = []; services = []; }; }");
    let path = project.0.to_str().unwrap();

    let missing = project_command(&["plan", path]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("no Syrox.lock"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );

    let created = project_command(&["lock", path]);
    assert!(created.status.success());
    assert!(String::from_utf8_lossy(&created.stdout).contains("lock created"));
    let locked = std::fs::read(project.0.join("Syrox.lock")).unwrap();

    let checked = project_command(&["lock", "--check", path]);
    assert!(checked.status.success());
    assert!(String::from_utf8_lossy(&checked.stdout).contains("lock current"));
    assert_eq!(
        std::fs::read(project.0.join("Syrox.lock")).unwrap(),
        locked
    );

    let planned = project_command(&["plan", path]);
    assert!(planned.status.success());
    assert!(String::from_utf8_lossy(&planned.stdout).contains("shell"));
    assert_eq!(
        std::fs::read(project.0.join("Syrox.lock")).unwrap(),
        locked
    );

    std::fs::write(
        project.0.join("main.srx"),
        "outputs { renamed: std::Shell = std::Shell { pkgs = []; services = []; }; }",
    )
    .unwrap();
    let drift = project_command(&["lock", "--check", path]);
    assert_eq!(drift.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&drift.stderr).contains("drifted"));
    assert_eq!(
        std::fs::read(project.0.join("Syrox.lock")).unwrap(),
        locked
    );
}
