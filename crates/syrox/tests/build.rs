//! Explicit host integration: requires systemd user services, Bubblewrap,
//! setpriv and Landlock ABI >= 6. Execute with `cargo test --release --locked
//! -p syrox --test build -- --ignored` on the intended build host.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use flate2::{Compression, write::GzEncoder};
use syrox_engine::{
    result::materialize_artifact, result::materialize_named_artifact, runtime::RuntimeFile,
    runtime::RuntimeOutput, runtime::RuntimeRequest, runtime::run_runtime, runtime::verify_runtime,
    store::ContentDigest, store::RootName, store::Store,
};

fn build_probe_script(body: &[u8]) -> Vec<u8> {
    let mut script = b"cat > probe.c <<'SYROX_BUILD_PROBE'\n".to_vec();
    script.extend_from_slice(include_bytes!(
        "../../../tests/fixtures/build-probe.c"
    ));
    script.extend_from_slice(b"\nSYROX_BUILD_PROBE\n");
    script.extend_from_slice(body);
    script
}

#[test]
#[ignore = "executes an external .srx builder, cache, runtime, failure and cancellation on a configured Linux host"]
fn host_external_srx_builder_runs_without_binary_changes_and_preserves_settlement() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path();
    let store_path = tempfile::tempdir().unwrap();
    fs::create_dir(project.join("builders")).unwrap();
    let source = b"int main(void) { return 37; }\n";
    fs::write(project.join("source.c"), source).unwrap();
    fs::write(
        project.join("config.toml"),
        "[build]\nhost-toolchain = '/usr'\n",
    )
    .unwrap();
    fs::write(project.join("main.srx"), format!(r#"
        inputs {{ builders = "modules:builders"; }}
        fn recipe() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "external"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request("project:source.c", "{}", 1024)]; }});
            build = std::Option::Some(builders::direct::build());
        }} }}
        mod factories::package {{ pub fn recipe() -> std::Recipe {{ project::recipe() }} }}
        mod factories::consumer {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{
                package = std::Package {{ id = "consumer"; dependencies = []; }};
                acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request("project:source.c", "{}", 1024)]; }});
                build = std::Option::Some(std::Build {{ profile = std::BuildProfile::HostBootstrap; source_directory = "consumer"; timeout_seconds = 30; source_format = std::BuildSourceFormat::Raw;
                    steps = [std::BuildStep::Copy(std::BuildPath::Input(0, "readme"), std::BuildPath::Output("out", "copied"))]; }});
                build_inputs = std::Option::Some(std::BuildInputs {{ selected = [std::recipe_output(std::recipe_ref(project::recipe), "doc")]; }});
            }} }} }}
        pub publish(factories, recipe): std::Recipe;
    "#, ContentDigest::sha256(source), ContentDigest::sha256(source))).unwrap();
    let save = |executable: &str, arguments: &str, text: &str| {
        fs::write(project.join("builders/direct.srx"), format!(r#"
            pub fn build() -> std::Build {{ std::Build {{ profile = std::BuildProfile::HostBootstrap;
                source_directory = "external"; timeout_seconds = 60;
                source_format = std::BuildSourceFormat::Raw; produces = ["doc", "out"];
                steps = [
                    std::BuildStep::Directory(std::BuildPath::Output("out", "bin")),
                    std::BuildStep::Run(std::BuildProcess {{ executable = std::BuildPath::Host("{executable}"); directory = std::BuildPath::Work(""); arguments = [{arguments}]; }}),
                    std::BuildStep::Write(std::BuildFile {{ path = std::BuildPath::Output("doc", "readme"); text = std::build_text("{text}"); }}),
                ];
            }} }}
        "#)).unwrap();
    };
    let relock = || {
        let result = run(&[
            "project",
            "lock",
            project.to_str().unwrap(),
        ]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    let arguments = r#"std::build_text("-static"), std::build_text("-x"), std::build_text("c"), std::build_path(std::BuildPath::Source), std::build_text("-o"), std::build_path(std::BuildPath::Output("out", "bin/demo"))"#;
    save("/usr/bin/gcc", arguments, "first");
    relock();
    let first = build(project, store_path.path());
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let text = String::from_utf8(first.stdout).unwrap();
    assert!(text.contains("built external"));
    let field = |prefix: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap()
    };
    let root = RootName::new(field("root ")).unwrap();
    let receipt = field("receipt ").parse().unwrap();
    let store = Store::open(store_path.path()).unwrap();
    let docs = materialize_named_artifact(&store, &root, receipt, "doc").unwrap();
    assert_eq!(
        fs::read(docs.directory().unwrap().join("readme")).unwrap(),
        b"first"
    );
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: RuntimeFile {
                output: RuntimeOutput {
                    root,
                    receipt,
                    output: "out".into(),
                },
                path: "bin/demo".into(),
            },
            loader: None,
            libraries: vec![],
        },
    )
    .unwrap();
    assert_eq!(
        run_runtime(&closure, &[], project)
            .unwrap()
            .code(),
        Some(37)
    );
    let second = build(project, store_path.path());
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(String::from_utf8_lossy(&second.stdout).contains("reused external"));
    let consumer = run(&[
        "build",
        &format!("{}#consumer", project.display()),
        "--config",
        project.join("config.toml").to_str().unwrap(),
        "--store",
        store_path.path().to_str().unwrap(),
        "--offline",
    ]);
    assert!(
        consumer.status.success(),
        "{}",
        String::from_utf8_lossy(&consumer.stderr)
    );
    let consumer = String::from_utf8(consumer.stdout).unwrap();
    let consumer_field = |prefix: &str| {
        consumer
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap()
    };
    let view = materialize_artifact(
        &store,
        &RootName::new(consumer_field("root ")).unwrap(),
        consumer_field("receipt ").parse().unwrap(),
    )
    .unwrap();
    assert_eq!(
        fs::read(view.directory().unwrap().join("copied")).unwrap(),
        b"first"
    );
    save("/usr/bin/gcc", arguments, "second");
    assert!(!build(project, store_path.path()).status.success());
    relock();
    let changed = build(project, store_path.path());
    assert!(
        changed.status.success(),
        "{}\nfailed fixture retained at {}; Store at {}",
        String::from_utf8_lossy(&changed.stderr),
        temporary.keep().display(),
        store_path.keep().display()
    );
    assert!(String::from_utf8_lossy(&changed.stdout).contains("built external"));
    assert!(!String::from_utf8_lossy(&changed.stdout).contains(field("action ")));
    let roots = managed_roots(store_path.path());
    assert_eq!(roots, 3);
    save("/usr/bin/false", "", "failed");
    relock();
    assert!(!build(project, store_path.path()).status.success());
    assert_eq!(managed_roots(store_path.path()), roots);
    save(
        "/usr/bin/sleep",
        r#"std::build_text("30")"#,
        "cancelled",
    );
    relock();
    let mut running = RunningBuild::start(project, store_path.path());
    let group = running.wait_for_payload();
    let result = running.signal_and_wait("TERM");
    assert_eq!(
        result.status.code(),
        Some(143),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    wait_for_empty_cgroup(&group);
    assert_eq!(managed_roots(store_path.path()), roots);
    assert!(
        !running
            .operation
            .as_ref()
            .unwrap()
            .join("stage")
            .exists()
    );
    running.unit = None;
}

#[test]
#[ignore = "requires Linux build preflight (user systemd, Bubblewrap, setpriv and Landlock); uses a local stalled TLS connection"]
fn build_cli_signals_cancel_pending_https_before_the_deadline() {
    for (signal, code) in [("-INT", 130), ("-TERM", 143)] {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://localhost:{}/stall",
            listener.local_addr().unwrap().port()
        );
        fs::write(
            project.join("main.srx"),
            format!(
                r#"fn recipe() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "app"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [
                std::SourceRequest {{ url = "{url}"; sha256 = "{}"; maximum_bytes = 100; }}
            ]; }});
            build = std::Option::Some(std::autotools(std::BuildOptions {{
                source_directory = "app-1"; timeout_seconds = 30;
            }}));
        }} }} mod factories::app {{ pub fn recipe() -> std::Recipe {{ project::recipe() }} }}
        pub publish(factories, recipe): std::Recipe;
    "#,
                "0".repeat(64)
            ),
        )
        .unwrap();
        let config = project.join("config.toml");
        fs::write(
            &config,
            format!("[build]\nhost-toolchain = '/usr'\n[network]\nallow-https = ['{url}']\n"),
        )
        .unwrap();
        let lock = Command::new(env!("CARGO_BIN_EXE_srx"))
            .args(["project", "lock"])
            .arg(project)
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let store = project.join("store");
        let mut child = Command::new(env!("CARGO_BIN_EXE_srx"))
            .arg("build")
            .arg(format!("{}#app", project.display()))
            .arg("--config")
            .arg(&config)
            .arg("--store")
            .arg(&store)
            .arg("-v")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let observed = (|| {
            let (mut connection, _) = loop {
                match listener.accept() {
                    Ok(value) => break value,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && start.elapsed() < Duration::from_secs(5) =>
                    {
                        if child.try_wait().unwrap().is_some() {
                            return None;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return None,
                    Err(error) => panic!("TLS fixture failed to accept: {error}"),
                }
            };
            connection
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buffer = [0_u8; 4096];
            if connection.read(&mut buffer).unwrap_or(0) == 0 {
                return Some(false);
            }
            let sent = Command::new("/usr/bin/kill")
                .arg(signal)
                .arg(child.id().to_string())
                .status()
                .unwrap();
            if !sent.success() {
                return Some(false);
            }
            let closed = match connection.read(&mut buffer) {
                Ok(0) => true,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => true,
                _ => false,
            };
            Some(closed)
        })();
        while child.try_wait().unwrap().is_none() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            observed == Some(true),
            "build never reached TLS: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "{signal} took too long"
        );
        assert!(
            !store
                .join("roots/retained")
                .read_dir()
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("source_"))
        );
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(args)
        .output()
        .unwrap()
}

fn archive(configure: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 512];
    header[..17].copy_from_slice(b"fixture/configure");
    header[100..108].copy_from_slice(b"0000644\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", configure.len()).as_bytes());
    header[156] = b'0';
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|b| u64::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut tar = header.to_vec();
    tar.extend_from_slice(configure);
    tar.resize(tar.len().div_ceil(512) * 512 + 1024, 0);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

fn project(path: &Path, store: &Store, configure: &[u8], timeout: u32) {
    let bytes = archive(configure);
    let digest = ContentDigest::sha256(&bytes);
    store
        .operation()
        .unwrap()
        .ingest(bytes.as_slice(), digest, bytes.len() as u64)
        .unwrap();
    fs::write(path.join("main.srx"), format!(r#"fn recipe() -> std::Recipe {{ std::Recipe {{
        package = std::Package {{ id = "fixture"; dependencies = []; }};
        acquisition = std::Option::Some(std::Acquisition {{ sources = [
            std::SourceRequest {{ url = "https://nonexistent.invalid/source"; sha256 = "{digest}"; maximum_bytes = 1048576; }}
        ]; }});
        build = std::Option::Some(std::autotools(std::BuildOptions {{
            source_directory = "fixture";
            timeout_seconds = {timeout};
        }}));
        commands = [];
    }} }} mod factories::package {{ pub fn recipe() -> std::Recipe {{ project::recipe() }} }}
        pub publish(factories, recipe): std::Recipe;
    "#)).unwrap();
    fs::write(
        path.join("config.toml"),
        "[build]\nhost-toolchain = '/usr'\n",
    )
    .unwrap();
    let result = run(&[
        "project",
        "lock",
        path.to_str().unwrap(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn build(project: &Path, store: &Path) -> Output {
    run(&[
        "build",
        &format!("{}#package", project.display()),
        "--config",
        project.join("config.toml").to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
        "--offline",
    ])
}

fn managed_roots(store: &Path) -> usize {
    fs::read_dir(store.join("roots/retained"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("build_")
        })
        .count()
}

#[test]
#[ignore = "builds a static application on a configured Linux host and runs its retained output rootless"]
fn host_build_prefix_materializes_and_runs_at_its_action_path() {
    let mut project_path = tempfile::tempdir().unwrap();
    let mut store_path = tempfile::tempdir().unwrap();
    if std::env::var_os("SYROX_MANAGED_WORKER").is_some() {
        project_path.disable_cleanup(true);
        store_path.disable_cleanup(true);
        eprintln!(
            "CLI gate project: {}; store: {}",
            project_path.path().display(),
            store_path.path().display()
        );
    }
    let store = Store::open(store_path.path()).unwrap();
    let configure = br#"set -eu
cat > hello.c <<'END'
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "hold") == 0) {
        int child = fork();
        if (child < 0) return 11;
        if (child == 0) {
            sleep(1);
            int late = open("late", O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (late >= 0) close(late);
            return 0;
        }
        int ready = open("ready", O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (ready < 0) return 12;
        close(ready);
        sleep(5);
        return 0;
    }
    return 37;
}
END
cat > Makefile <<'END'
all:
	/usr/bin/gcc -static -o hello hello.c
install:
	mkdir -p $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin
	install -m 755 hello $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
END
"#;
    project(project_path.path(), &store, configure, 60);
    let main = project_path.path().join("main.srx");
    let source = fs::read_to_string(&main).unwrap().replace(
        "commands = [];",
        r#"commands = [std::Command { name = "main"; output = "out"; path = "usr/bin/hello"; }];"#,
    );
    fs::write(&main, source).unwrap();
    assert!(
        run(&[
            "project",
            "lock",
            project_path.path().to_str().unwrap()
        ])
        .status
        .success()
    );
    let output = build(project_path.path(), store_path.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let field = |label: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(label))
            .unwrap()
    };
    let root = RootName::new(field("root ")).unwrap();
    let receipt = field("receipt ").parse().unwrap();
    let action = field("action ");
    let closure = verify_runtime(
        &store,
        &RuntimeRequest {
            application: RuntimeFile {
                output: RuntimeOutput {
                    root,
                    receipt,
                    output: "out".into(),
                },
                path: "usr/bin/hello".into(),
            },
            loader: None,
            libraries: vec![],
        },
    )
    .unwrap();
    assert_eq!(
        closure.entry(),
        format!("/syrox/store/{action}/out/usr/bin/hello")
    );
    let status = run_runtime(&closure, &[], project_path.path()).unwrap();
    assert_eq!(status.code(), Some(37));
    let public = run(&[
        "run",
        ".#package",
        "--command",
        "main",
        "-f",
        main.to_str().unwrap(),
        "--config",
        project_path
            .path()
            .join("config.toml")
            .to_str()
            .unwrap(),
        "--store",
        store_path.path().to_str().unwrap(),
        "-o",
        "--",
        "hello",
    ]);
    assert_eq!(
        public.status.code(),
        Some(37),
        "{}",
        String::from_utf8_lossy(&public.stderr)
    );
    assert_runtime_signals(&main, project_path.path(), store_path.path());
}

fn assert_runtime_signals(main: &Path, project: &Path, store: &Path) {
    for (signal, code) in [("INT", 130), ("TERM", 143)] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_srx"))
            .args([
                "run",
                ".#package",
                "--command",
                "main",
                "-f",
                main.to_str().unwrap(),
                "--config",
                project.join("config.toml").to_str().unwrap(),
                "--store",
                store.to_str().unwrap(),
                "-o",
                "--",
                "hold",
            ])
            .current_dir(project)
            .spawn()
            .unwrap();
        let ready = project.join("ready");
        let start = Instant::now();
        while !ready.exists() && start.elapsed() < Duration::from_secs(240) {
            assert!(
                child.try_wait().unwrap().is_none(),
                "runtime exited before signal"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "runtime did not start");
        assert!(
            Command::new("/usr/bin/kill")
                .args([
                    format!("-{signal}"),
                    child.id().to_string()
                ])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(child.wait().unwrap().code(), Some(code));
        std::thread::sleep(Duration::from_millis(1200));
        assert!(!project.join("late").exists());
        fs::remove_file(ready).unwrap();
    }
}

#[test]
#[ignore = "executes the bounded sandbox on a configured Linux host; inventories /usr"]
fn host_build_publishes_only_after_success_and_rejects_timeout_and_symlink_output() {
    let project_path = tempfile::tempdir().unwrap();
    let store_path = tempfile::tempdir().unwrap();
    let store = Store::open(store_path.path()).unwrap();
    let script = br"set -eu
test ! -e /home
test ! -e /run/user
if touch /usr/syrox-should-be-denied 2>/dev/null; then exit 71; fi
/usr/bin/gcc -std=c11 -O2 -Wall -Wextra -Werror probe.c -o probe
./probe network
cat > Makefile <<'END'
all:
	/usr/bin/true
install:
	mkdir -p $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin
	printf 'fixture executable' > $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
	chmod 755 $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
END
";
    let script = build_probe_script(script);
    project(project_path.path(), &store, &script, 30);
    let output = build(project_path.path(), store_path.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let artifact: ContentDigest = stdout
        .lines()
        .find_map(|l| l.strip_prefix("artifact "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        store
            .operation()
            .unwrap()
            .read_verified(artifact, 1024 * 1024)
            .unwrap()
            .is_some()
    );
    let root = stdout
        .lines()
        .find_map(|line| line.strip_prefix("root "))
        .unwrap();
    assert!(root.starts_with("build_"));
    assert!(
        store_path
            .path()
            .join("roots/retained")
            .join(root)
            .exists()
    );
    let retained = fs::read_dir(store_path.path().join("roots/retained"))
        .unwrap()
        .count();

    assert_reuse_and_reindex(project_path.path(), store_path.path(), &stdout);

    // A lingering descendant must be terminated by the enclosing cgroup. No
    // root is created even though the initial script can spawn successfully.
    project(
        project_path.path(),
        &store,
        b"sleep 30 &\nwait\n",
        1,
    );
    let timeout = build(project_path.path(), store_path.path());
    assert!(!timeout.status.success());
    assert!(
        String::from_utf8_lossy(&timeout.stderr).contains("deadline"),
        "{}",
        String::from_utf8_lossy(&timeout.stderr)
    );
    assert_eq!(
        fs::read_dir(store_path.path().join("roots/retained"))
            .unwrap()
            .count(),
        retained
    );

    let unsafe_script = br"cat > Makefile <<'END'
all:
	true
install:
	mkdir -p $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin
	ln -s /etc/passwd $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
END
";
    project(project_path.path(), &store, unsafe_script, 30);
    let rejected = build(project_path.path(), store_path.path());
    assert!(!rejected.status.success());
    assert_eq!(
        fs::read_dir(store_path.path().join("roots/retained"))
            .unwrap()
            .count(),
        retained
    );

    assert_outside_output_rejected(
        project_path.path(),
        store_path.path(),
        &store,
        retained,
    );
}

fn assert_outside_output_rejected(
    project_path: &Path,
    store_path: &Path,
    store: &Store,
    retained: usize,
) {
    let outside_output = br"cat > Makefile <<'END'
all:
	true
install:
	mkdir -p $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin
	printf 'valid' > $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
	chmod 755 $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
	printf 'undeclared' > $(DESTDIR)/unexpected
END
";
    project(project_path, store, outside_output, 30);
    let rejected = build(project_path, store_path);
    assert!(!rejected.status.success());
    assert_eq!(
        fs::read_dir(store_path.join("roots/retained"))
            .unwrap()
            .count(),
        retained
    );
}

fn assert_reuse_and_reindex(project: &Path, store: &Path, stdout: &str) {
    let operations = fs::read_dir(store.join(".syrox-store/builds"))
        .unwrap()
        .count();
    // A verified local hit neither starts a sandbox nor needs a service manager.
    let reused = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args([
            "build",
            &format!("{}#package", project.display()),
            "--config",
            project.join("config.toml").to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--offline",
        ])
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent/syrox-cache-test",
        )
        .output()
        .unwrap();
    assert!(
        reused.status.success(),
        "{}",
        String::from_utf8_lossy(&reused.stderr)
    );
    let reused = String::from_utf8(reused.stdout).unwrap();
    assert!(reused.starts_with("reused fixture\n"));
    let selected = run(&[
        "build",
        "-A",
        "-j",
        "2",
        "-f",
        project.join("main.srx").to_str().unwrap(),
        "--config",
        project.join("config.toml").to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
        "-o",
    ]);
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert!(String::from_utf8_lossy(&selected.stdout).starts_with("reused fixture\n"));
    for prefix in [
        "action ",
        "artifact ",
        "receipt ",
        "root ",
    ] {
        assert_eq!(
            stdout
                .lines()
                .find(|line| line.starts_with(prefix)),
            reused
                .lines()
                .find(|line| line.starts_with(prefix))
        );
    }
    assert_eq!(
        fs::read_dir(store.join(".syrox-store/builds"))
            .unwrap()
            .count(),
        operations
    );
    fs::remove_dir_all(store.join(".syrox-store/actions")).unwrap();
    let reindexed = run(&[
        "store",
        "reindex",
        "--config",
        project.join("config.toml").to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
    ]);
    assert!(
        reindexed.status.success(),
        "{}",
        String::from_utf8_lossy(&reindexed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&reindexed.stdout).contains("indexed 1 retained build actions")
    );
}

#[test]
fn malformed_build_request_cannot_launch_or_publish() {
    let path = tempfile::tempdir().unwrap();
    let store_path = tempfile::tempdir().unwrap();
    let store = Store::open(store_path.path()).unwrap();
    project(path.path(), &store, b"exit 0\n", 30);
    let main = path.path().join("main.srx");
    let text = fs::read_to_string(&main).unwrap().replace(
        "source_directory = \"fixture\"",
        "source_directory = \"../escape\"",
    );
    fs::write(&main, text).unwrap();
    assert!(
        run(&[
            "project",
            "lock",
            path.path().to_str().unwrap()
        ])
        .status
        .success()
    );
    let invalid = build(path.path(), store_path.path());
    assert!(!invalid.status.success());
    let error = String::from_utf8_lossy(&invalid.stderr);
    assert!(error.contains("invalid build request"), "{error}");
    assert_eq!(
        fs::read_dir(store_path.path().join("roots/retained"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
#[ignore = "executes adopted descendants and output collection on a configured Linux host"]
fn host_collection_waits_for_double_fork_and_rejects_late_failure_or_unsafe_output() {
    let project_path = tempfile::tempdir().unwrap();
    let store_path = tempfile::tempdir().unwrap();
    let store = Store::open(store_path.path()).unwrap();
    let configure = r"/usr/bin/gcc -std=c11 -O2 -Wall -Wextra -Werror probe.c -o probe
cat > Makefile <<'END'
all:
	true
install:
	mkdir -p $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin
	printf 'unstable before orphan' > $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
	chmod 755 $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
	./probe stable
END
";
    let configure = String::from_utf8(build_probe_script(configure.as_bytes())).unwrap();
    project(
        project_path.path(),
        &store,
        configure.as_bytes(),
        30,
    );
    let result = build(project_path.path(), store_path.path());
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    let artifact: ContentDigest = stdout
        .lines()
        .find_map(|line| line.strip_prefix("artifact "))
        .unwrap()
        .parse()
        .unwrap();
    let bytes = store
        .operation()
        .unwrap()
        .read_verified(artifact, 1024 * 1024)
        .unwrap()
        .unwrap();
    assert!(
        bytes
            .as_bytes()
            .windows(b"stable after orphan".len())
            .any(|part| part == b"stable after orphan")
    );
    assert!(
        !bytes
            .as_bytes()
            .windows(b"unstable before orphan".len())
            .any(|part| part == b"unstable before orphan")
    );
    let roots = fs::read_dir(store_path.path().join("roots/retained"))
        .unwrap()
        .count();
    for (replacement, diagnostic) in [
        ("failure", "background build descendant"),
        ("symlink", "build output"),
    ] {
        let script = configure.replace(
            "./probe stable",
            &format!("./probe {replacement}"),
        );
        project(project_path.path(), &store, script.as_bytes(), 30);
        let result = build(project_path.path(), store_path.path());
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(diagnostic),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            fs::read_dir(store_path.path().join("roots/retained"))
                .unwrap()
                .count(),
            roots
        );
    }
    let failure = build_probe_script(
        b"/usr/bin/gcc -std=c11 -O2 -Wall -Wextra -Werror probe.c -o probe\n./probe log\n",
    );
    project(project_path.path(), &store, &failure, 30);
    let failed = build(project_path.path(), store_path.path());
    assert!(!failed.status.success());
    let diagnostic = String::from_utf8_lossy(&failed.stderr);
    assert!(
        diagnostic.contains("earlier diagnostics truncated")
            && diagnostic.contains("FINAL_FAILURE_MARKER"),
        "{diagnostic}"
    );
    assert!(failed.stderr.len() < 20 * 1024);
    assert_eq!(
        fs::read_dir(store_path.path().join("roots/retained"))
            .unwrap()
            .count(),
        roots
    );
}

/// Owns exactly one test CLI. Failure paths stop only its uniquely named unit.
struct RunningBuild {
    child: Option<Child>,
    namespace: PathBuf,
    operation: Option<PathBuf>,
    unit: Option<String>,
}

impl RunningBuild {
    fn start(project: &Path, store: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_srx"))
            .arg("build")
            .arg(format!("{}#package", project.display()))
            .arg("--config")
            .arg(project.join("config.toml"))
            .arg("--store")
            .arg(store)
            .arg("--offline")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self {
            child: Some(child),
            namespace: store.join(".syrox-store/builds"),
            operation: None,
            unit: None,
        }
    }

    fn wait_for_payload(&mut self) -> PathBuf {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if self.unit.is_none() {
                self.operation = fs::read_dir(&self.namespace)
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with("op-")
                            && path.join("stage").exists()
                    });
                self.unit = self.operation.as_ref().map(|path| {
                    format!(
                        "syrox-build-{}.service",
                        &path.file_name().unwrap().to_str().unwrap()[3..]
                    )
                });
            }
            if let Some(unit) = &self.unit {
                let result = systemctl(&[
                    "show",
                    unit,
                    "--property=ControlGroup",
                    "--value",
                ]);
                let group = String::from_utf8_lossy(&result.stdout);
                let group = group.trim();
                if result.status.success() && group.starts_with('/') && !group.contains("..") {
                    let path = Path::new("/sys/fs/cgroup").join(&group[1..]);
                    if fs::read_to_string(path.join("cgroup.procs")).is_ok_and(|pids| {
                        pids.lines().any(|pid| {
                            pid.parse::<u32>().is_ok()
                                && fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|argv| {
                                    argv.windows(6).any(|part| part == b"sleep\0")
                                })
                        })
                    }) {
                        return path;
                    }
                }
            }
            if self
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some()
            {
                let output = self
                    .child
                    .take()
                    .unwrap()
                    .wait_with_output()
                    .unwrap();
                panic!(
                    "build ended before payload readiness: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("build payload did not become ready");
    }

    fn signal_and_wait(&mut self, signal: &str) -> Output {
        let child = self.child.as_mut().unwrap();
        assert!(
            Command::new("/usr/bin/kill")
                .args([
                    "--signal",
                    signal,
                    &child.id().to_string()
                ])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while child.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "coordinator did not terminate after {signal}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        self.child
            .take()
            .unwrap()
            .wait_with_output()
            .unwrap()
    }

    fn wait_for_interest(&mut self, operation: &Path) {
        use std::os::unix::fs::MetadataExt as _;
        let inode = fs::metadata(operation.join("consumers"))
            .unwrap()
            .ino()
            .to_string();
        let pid = self.child.as_ref().unwrap().id().to_string();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let locks = fs::read_to_string("/proc/locks").unwrap();
            if locks.lines().any(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.get(1) == Some(&"FLOCK")
                    && fields.get(3) == Some(&"READ")
                    && fields.get(4) == Some(&pid.as_str())
                    && fields
                        .get(5)
                        .is_some_and(|value| value.rsplit(':').next() == Some(inode.as_str()))
            }) {
                return;
            }
            if self
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some()
            {
                let output = self
                    .child
                    .take()
                    .unwrap()
                    .wait_with_output()
                    .unwrap();
                panic!(
                    "consumer ended before joining: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert!(
                Instant::now() < deadline,
                "consumer did not join the producer"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn finish(&mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(60);
        while self
            .child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
        {
            assert!(
                Instant::now() < deadline,
                "test build did not finish"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        self.child
            .take()
            .unwrap()
            .wait_with_output()
            .unwrap()
    }
}

#[test]
#[ignore = "two real CLI consumers share a producer and cancel independently on a configured Linux host"]
fn host_concurrent_consumers_share_one_payload_and_cancel_independently() {
    for cancel_coordinator_consumer in [true, false] {
        let project_path = tempfile::tempdir().unwrap();
        let store_path = tempfile::tempdir().unwrap();
        let store = Store::open(store_path.path()).unwrap();
        project(
            project_path.path(),
            &store,
            br"sleep 20
cat > Makefile <<'END'
all:
	true
install:
	mkdir -p $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin
	printf 'shared executable' > $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
	chmod 755 $(DESTDIR)$(SYROX_OUTPUT_PREFIX)/bin/hello
END
",
            60,
        );
        let mut first = RunningBuild::start(project_path.path(), store_path.path());
        let group = first.wait_for_payload();
        let journal = first.operation.clone().unwrap();
        let mut second = RunningBuild::start(project_path.path(), store_path.path());
        second.wait_for_interest(&journal);
        let (cancelled, success) = if cancel_coordinator_consumer {
            (first.signal_and_wait("INT"), second.finish())
        } else {
            (second.signal_and_wait("TERM"), first.finish())
        };
        assert_eq!(
            cancelled.status.code(),
            Some(if cancel_coordinator_consumer {
                130
            } else {
                143
            }),
            "{}",
            String::from_utf8_lossy(&cancelled.stderr)
        );
        assert!(
            success.status.success(),
            "{}",
            String::from_utf8_lossy(&success.stderr)
        );
        assert!(
            String::from_utf8_lossy(&success.stdout).starts_with(if cancel_coordinator_consumer {
                "shared fixture\n"
            } else {
                "built fixture\n"
            })
        );
        assert_eq!(
            fs::read_dir(store_path.path().join(".syrox-store/builds"))
                .unwrap()
                .count(),
            1
        );
        assert_eq!(
            fs::read_dir(store_path.path().join("roots/retained"))
                .unwrap()
                .count(),
            1
        );
        wait_for_empty_cgroup(&group);
        first.unit = None;
        assert!(
            recover(project_path.path(), store_path.path())
                .status
                .success()
        );
        let hit = build(project_path.path(), store_path.path());
        assert!(
            hit.status.success(),
            "{}",
            String::from_utf8_lossy(&hit.stderr)
        );
        assert!(String::from_utf8_lossy(&hit.stdout).starts_with("reused fixture\n"));
        assert_eq!(
            fs::read_dir(store_path.path().join(".syrox-store/builds"))
                .unwrap()
                .count(),
            0
        );
    }
}

impl Drop for RunningBuild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(unit) = &self.unit {
            let stopped = systemctl(&["stop", unit]);
            if !stopped.status.success() {
                eprintln!(
                    "test unit stop unconfirmed: {unit}, journal {}",
                    self.namespace.display()
                );
            }
        }
    }
}

fn systemctl(arguments: &[&str]) -> Output {
    Command::new("/usr/bin/timeout")
        .args([
            "--kill-after=1",
            "5",
            "/usr/bin/systemctl",
            "--user",
        ])
        .args(arguments)
        .output()
        .unwrap()
}

fn wait_for_empty_cgroup(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match fs::read_to_string(path.join("cgroup.events")) {
            Ok(events) if events.lines().any(|line| line == "populated 0") => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "test payload cgroup did not settle: {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
#[ignore = "sends signals to its own coordinator and inspects its owned cgroup on a configured Linux host"]
fn host_cancellation_cleans_up_and_coordinator_death_cannot_publish() {
    let project_path = tempfile::tempdir().unwrap();
    let store_path = tempfile::tempdir().unwrap();
    let store = Store::open(store_path.path()).unwrap();
    for (signal, expected) in [
        ("INT", Some(130)),
        ("TERM", Some(143)),
        ("KILL", None),
    ] {
        project(
            project_path.path(),
            &store,
            b"sleep 30 &\nwait\n",
            if signal == "KILL" {
                5
            } else {
                30
            },
        );
        let mut operation = RunningBuild::start(project_path.path(), store_path.path());
        let group = operation.wait_for_payload();
        let active = recover(project_path.path(), store_path.path());
        assert!(
            active.status.success(),
            "{}",
            String::from_utf8_lossy(&active.stderr)
        );
        assert!(String::from_utf8_lossy(&active.stdout).contains("active op-"));
        let journal = operation.operation.clone().unwrap();
        let result = operation.signal_and_wait(signal);
        assert_eq!(
            result.status.code(),
            expected,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        wait_for_empty_cgroup(&group);
        if signal == "KILL" {
            assert!(
                journal.join("stage/source").exists(),
                "abrupt death should retain the private staging evidence"
            );
        } else {
            assert!(String::from_utf8_lossy(&result.stderr).contains("build cancelled"));
            assert!(!journal.join("stage").exists());
            assert!(
                fs::read_to_string(journal.join("outcome"))
                    .unwrap()
                    .contains("build cancelled")
            );
        }
        assert_eq!(
            fs::read_dir(store_path.path().join("roots/retained"))
                .unwrap()
                .count(),
            0
        );
        // The cgroup has now independently proved empty. Cleanup is safe even
        // if systemd already garbage-collected the transient unit's metadata.
        operation.unit = None;
        let recovered = recover(project_path.path(), store_path.path());
        assert!(
            recovered.status.success(),
            "{}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        assert!(String::from_utf8_lossy(&recovered.stdout).contains("recovered op-"));
        assert!(!journal.exists());
        assert!(
            recover(project_path.path(), store_path.path())
                .status
                .success()
        );
    }
}

fn recover(project: &Path, store: &Path) -> Output {
    run(&[
        "store",
        "recover",
        "--config",
        project.join("config.toml").to_str().unwrap(),
        "--store",
        store.to_str().unwrap(),
    ])
}

#[test]
#[ignore = "recovers its own live orphaned cgroup and simulates an unavailable manager connection"]
fn host_orphan_recovery_retains_on_manager_loss_then_stops_and_revokes_launch() {
    let project_path = tempfile::tempdir().unwrap();
    let store_path = tempfile::tempdir().unwrap();
    let store = Store::open(store_path.path()).unwrap();
    project(
        project_path.path(),
        &store,
        b"sleep 30 &\nwait\n",
        30,
    );
    let mut operation = RunningBuild::start(project_path.path(), store_path.path());
    let group = operation.wait_for_payload();
    let journal = operation.operation.clone().unwrap();
    let mut child = operation.child.take().unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    // Keep the inherited channels alive but do not wait for their EOF: the
    // orphan is deliberately still running when recovery starts.
    let unavailable = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["store", "recover"])
        .arg("--config")
        .arg(project_path.path().join("config.toml"))
        .arg("--store")
        .arg(store_path.path())
        .env(
            "XDG_RUNTIME_DIR",
            project_path.path().join("absent-runtime"),
        )
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent-syrox-test-bus",
        )
        .output()
        .unwrap();
    assert!(!unavailable.status.success());
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("retained op-"));
    assert!(journal.join("stage/source").exists());
    let recovered = recover(project_path.path(), store_path.path());
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    wait_for_empty_cgroup(&group);
    assert!(!journal.exists());
    let delayed = Command::new(env!("CARGO_BIN_EXE_syrox-worker"))
        .args([
            "__build-gate",
            journal.to_str().unwrap(),
            "fixture",
        ])
        .output()
        .unwrap();
    assert!(!delayed.status.success());
    assert_eq!(
        fs::read_dir(store_path.path().join("roots/retained"))
            .unwrap()
            .count(),
        0
    );
    operation.unit = None;
}

#[test]
fn managed_profile_never_falls_back_to_host_or_initializes_a_store() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path();
    let source = b"managed source";
    fs::write(project.join("source"), source).unwrap();
    fs::write(project.join("main.srx"), format!(r#"
        fn recipe() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "managed"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request("project:source", "{}", 1024)]; }});
            build = std::Option::Some(std::Build {{
                profile = std::BuildProfile::Managed;
                source_directory = "managed"; timeout_seconds = 30; source_format = std::BuildSourceFormat::Raw;
                steps = [std::BuildStep::Write(std::BuildFile {{ path = std::BuildPath::Output("out", "data"); text = std::build_text("data"); }})];
            }});
        }} }}
        mod factories::selected {{ pub fn recipe() -> std::Recipe {{ project::recipe() }} }}
        pub publish(factories, recipe): std::Recipe;
    "#, ContentDigest::sha256(source))).unwrap();
    let locked = run(&[
        "project",
        "lock",
        project.to_str().unwrap(),
    ]);
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    fs::remove_file(project.join("source")).unwrap();
    let store = project.join("uncreated-store");
    // A Managed request must reach its explicit configuration even when the
    // optional HostBootstrap worker is absent beside this CLI installation.
    let binary = Path::new(env!("CARGO_BIN_EXE_srx"));
    let installation = tempfile::tempdir_in(binary.parent().unwrap()).unwrap();
    let isolated_cli = installation.path().join("srx");
    fs::hard_link(binary, &isolated_cli).unwrap();
    assert!(!installation.path().join("syrox-worker").exists());
    for configuration in ["", "[build]\nhost-toolchain = '/usr'\n"] {
        fs::write(project.join("config.toml"), configuration).unwrap();
        let result = Command::new(&isolated_cli)
            .arg("build")
            .arg(format!("{}#selected", project.display()))
            .arg("--config")
            .arg(project.join("config.toml"))
            .arg("--store")
            .arg(&store)
            .arg("--offline")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(
            error.contains("managed build is not configured"),
            "{error}"
        );
        assert!(!store.exists());
    }
}

#[test]
fn managed_worker_dispatch_rejects_unprepared_entries_without_output_or_files() {
    let scratch = tempfile::tempdir().unwrap();
    let pin = ContentDigest::sha256(b"unprepared action").to_string();
    let endpoint = scratch.path().join("coordinator.sock");
    let operation = scratch
        .path()
        .join("op-11111111111111111111111111111111");
    let invalid = [
        vec!["__managed-build".to_owned()],
        vec![
            "__managed-build".into(),
            "relative-operation".into(),
            pin.clone(),
            "11111111111111111111111111111111".into(),
            endpoint.to_str().unwrap().into(),
        ],
        vec![
            "__managed-build".into(),
            operation.to_str().unwrap().into(),
            pin.clone(),
            "invalid-nonce".into(),
            endpoint.to_str().unwrap().into(),
        ],
        vec![
            "__managed-build".into(),
            operation.to_str().unwrap().into(),
            pin.clone(),
            "11111111111111111111111111111111".into(),
            endpoint.to_str().unwrap().into(),
            "extra".into(),
        ],
        vec![
            "__build-managed-worker".into(),
            "../source".into(),
            pin.clone(),
        ],
        vec![
            "__build-managed-worker".into(),
            "source-1".into(),
            pin,
        ],
    ];
    for args in invalid {
        let result = Command::new(env!("CARGO_BIN_EXE_syrox-worker"))
            .args(&args)
            .env_clear()
            .current_dir(scratch.path())
            .output()
            .unwrap();
        assert!(
            !result.status.success(),
            "unprepared entry succeeded: {args:?}"
        );
        assert!(
            result.stdout.is_empty(),
            "unprepared entry emitted artifact bytes"
        );
        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
    }
}
