//! Real CLI planning with locked declarations and read-only Linux observations.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn command(directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_srx"));
    command
        .current_dir(directory)
        .env("PATH", "/nonexistent")
        .env("HOME", directory.join("home"))
        .env("XDG_CONFIG_HOME", directory.join("config"))
        .env("XDG_DATA_HOME", directory.join("data"))
        .env("XDG_STATE_HOME", directory.join("state"));
    command
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn lock(directory: &Path, source: &str) -> Vec<u8> {
    fs::write(directory.join("main.srx"), source).unwrap();
    success(
        &command(directory)
            .args(["project", "lock", "."])
            .output()
            .unwrap(),
    );
    fs::read(directory.join("Syrox.lock")).unwrap()
}

fn preserved(directory: &Path, source: &str, lock: &[u8]) {
    assert_eq!(
        fs::read_to_string(directory.join("main.srx")).unwrap(),
        source
    );
    assert_eq!(
        fs::read(directory.join("Syrox.lock")).unwrap(),
        lock
    );
    assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
}

#[test]
fn host_plan_compares_actual_parameters_without_project_or_host_writes() {
    let directory = tempfile::tempdir().unwrap();
    let before = fs::read_to_string("/proc/sys/vm/swappiness").unwrap();
    let current = before.strip_suffix('\n').unwrap_or(&before);
    let source = r#"outputs {
        host: HostConfiguration = HostConfiguration {
            sysctls = [
                std::system::SysctlSetting { name = "vm.swappiness"; value = "CURRENT"; },
                std::system::SysctlSetting { name = "vm.srx_missing_read_only_fixture"; value = "1"; }
            ];
            services = Services { pkgs = []; services = []; };
        };
        different: HostConfiguration = HostConfiguration {
            sysctls = [std::system::SysctlSetting { name = "vm.swappiness"; value = "DIFFERENT"; }];
            services = Services { pkgs = []; services = []; };
        };
    }"#.replace("CURRENT", current).replace("DIFFERENT", if current == "0" { "1" } else { "0" });
    let locked = lock(directory.path(), &source);
    for (selected, comparison) in [
        (".#host", "equal"),
        (".#different", "different"),
    ] {
        let output = command(directory.path())
            .args(["system", "plan", selected, "--json"])
            .output()
            .unwrap();
        success(&output);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let plan = &report["plan"];
        assert_eq!(plan["version"], 1);
        assert!(plan.get("builder_admission").is_none());
        assert_eq!(plan["declaration_kind"], "HostConfiguration");
        assert_eq!(plan["target"], "current_process_namespaces");
        assert_eq!(
            plan["namespace_ids"].as_object().unwrap().len(),
            7
        );
        for name in [
            "user", "mnt", "net", "ipc", "uts", "pid", "cgroup",
        ] {
            use std::os::unix::fs::MetadataExt as _;
            let actual = fs::metadata(format!("/proc/self/ns/{name}")).unwrap();
            assert_eq!(
                plan["namespace_ids"][name]["device"],
                actual.dev()
            );
            assert_eq!(plan["namespace_ids"][name]["inode"], actual.ino());
        }
        let setting = plan["sysctls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "vm.swappiness")
            .unwrap();
        assert_eq!(setting["observed"]["value"], current);
        assert_eq!(setting["comparison"], comparison);
        assert_eq!(setting["restoration_verified"], false);
        if selected == ".#host" {
            let missing = plan["sysctls"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == "vm.srx_missing_read_only_fixture")
                .unwrap();
            assert_eq!(missing["comparison"], "unavailable");
        }
        assert_eq!(plan["can_apply"], false);
        assert_eq!(plan["ownership_established"], false);
        assert_eq!(plan["observation_is_atomic"], false);
        assert!(plan["storage"].is_null());
        assert_eq!(
            report["observation_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            plan["declaration_sha256"].as_str().unwrap().len(),
            64
        );
        preserved(directory.path(), &source, &locked);
    }
    let text = command(directory.path())
        .args(["system", "plan", ".#host"])
        .output()
        .unwrap();
    success(&text);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("system observation sha256 "));
    assert!(text.contains("current process namespaces"));
    assert_eq!(
        fs::read_to_string("/proc/sys/vm/swappiness").unwrap(),
        before
    );
    preserved(directory.path(), &source, &locked);
}

fn builder_configuration(directory: &Path) -> String {
    format!(
        "[store]\npath='{}'\n[build.system]\nworker='{}'\nworker-sha256='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'\nscope='user'\nuser-bus='{}'\nsocket-parent='{}'\nhelper-socket='{}'\n[build.system.maximum]\nmemory-bytes=8589934592\ncpu-percent=400\nprocesses=1024\ndescriptors=8192\nscratch-bytes=68719476736\nfiles=1000000\noutput-bytes=17179869184\nduration-seconds=14400\n",
        directory.join("absent-store").display(),
        directory.join("absent-worker").display(),
        directory.join("absent-bus").display(),
        directory.join("absent-sockets").display(),
        directory.join("helper.sock").display()
    )
}

#[test]
fn system_budget_admission_is_explicit_read_only_and_uses_a_separate_report_version() {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let directory = tempfile::tempdir().unwrap();
    let source = include_str!("plan-system.srx");
    let locked = lock(directory.path(), source);
    let policy_directory = tempfile::tempdir().unwrap();
    let config = policy_directory.path().join("builder.toml");
    let policy = builder_configuration(policy_directory.path());
    fs::write(&config, &policy).unwrap();
    // A regular file at the endpoint is deliberately unsuitable for a helper.
    // Policy admission must not connect to it or claim it has been authenticated.
    fs::write(
        policy_directory.path().join("helper.sock"),
        b"preserve endpoint",
    )
    .unwrap();
    let output = command(directory.path())
        .args([
            "system",
            "plan",
            ".#system",
            "--json",
            "--builder-config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    success(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let plan = &report["plan"];
    assert_eq!(plan["version"], 2);
    assert_eq!(plan["can_apply"], false);
    let admitted = &plan["builder_admission"];
    assert_eq!(admitted["policy_admitted"], true);
    assert_eq!(
        admitted["policy_scope"],
        "explicit_local_builder_configuration"
    );
    assert_eq!(admitted["request"]["memory_bytes"], 1_073_741_824);
    assert_eq!(admitted["request"]["duration_seconds"], 7200);
    assert_eq!(
        admitted["maximum"]["memory_bytes"],
        8_589_934_592_u64
    );
    assert_eq!(admitted["scope"]["kind"], "user");
    for field in [
        "worker_verified",
        "manager_verified",
        "helper_authority_verified",
        "capacity_verified",
        "runtime_enforcement_verified",
    ] {
        assert_eq!(admitted[field], false);
    }
    let mut hash = Sha256::new();
    hash.update(b"srx-system-observation-plan-v2\n");
    hash.update(serde_json::to_vec(plan).unwrap());
    assert_eq!(
        report["observation_sha256"],
        syrox_encoding::hex(&hash.finalize())
    );
    let user = syrox_engine::config::UserConfiguration::load(Some(&config)).unwrap();
    let mut expected = String::with_capacity(64);
    for byte in user
        .system_build()
        .unwrap()
        .limits()
        .fingerprint()
    {
        write!(expected, "{byte:02x}").unwrap();
    }
    assert_eq!(admitted["policy_sha256"], expected);
    assert_eq!(fs::read_to_string(&config).unwrap(), policy);
    assert_eq!(
        fs::read(policy_directory.path().join("helper.sock")).unwrap(),
        b"preserve endpoint"
    );
    assert_eq!(
        fs::read_dir(policy_directory.path())
            .unwrap()
            .count(),
        2
    );
    preserved(directory.path(), source, &locked);
}

#[test]
fn builder_admission_rejects_each_excess_before_machine_inspection_or_store_effects() {
    let directory = tempfile::tempdir().unwrap();
    let source = include_str!("plan-system.srx");
    let locked = lock(directory.path(), source);
    let policy_directory = tempfile::tempdir().unwrap();
    let config = policy_directory.path().join("builder.toml");
    let policy = builder_configuration(policy_directory.path());
    for (maximum, denied) in [
        (
            "memory-bytes=8589934592",
            "memory-bytes=1073741823",
        ),
        ("cpu-percent=400", "cpu-percent=99"),
        ("processes=1024", "processes=255"),
        ("descriptors=8192", "descriptors=1023"),
        (
            "scratch-bytes=68719476736",
            "scratch-bytes=1073741823",
        ),
        ("files=1000000", "files=99999"),
        (
            "output-bytes=17179869184",
            "output-bytes=268435455",
        ),
        ("duration-seconds=14400", "duration-seconds=7199"),
    ] {
        fs::write(&config, policy.replace(maximum, denied)).unwrap();
        let output = command(directory.path())
            .args([
                "system",
                "plan",
                ".#system",
                "--json",
                "--builder-config",
            ])
            .arg(&config)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("above administrator limit"));
        preserved(directory.path(), source, &locked);
        assert_eq!(
            fs::read_dir(policy_directory.path())
                .unwrap()
                .count(),
            1
        );
    }
    fs::write(&config, "[build]\nhost-toolchain='/usr'\n").unwrap();
    let output = command(directory.path())
        .args([
            "system",
            "plan",
            ".#system",
            "--builder-config",
        ])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("explicitly set build.system"));
    preserved(directory.path(), source, &locked);
}

#[test]
fn builder_policy_is_not_inferred_or_applied_to_host_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let source = "outputs { host: HostConfiguration = HostConfiguration { services = Services { pkgs = []; services = []; }; }; }";
    let locked = lock(directory.path(), source);
    let output = command(directory.path())
        .args([
            "system",
            "plan",
            ".#host",
            "--builder-config",
            "/absent-policy-must-not-be-opened",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires a System output"));
    assert!(output.stdout.is_empty());
    preserved(directory.path(), source, &locked);
}

#[test]
fn planning_requires_explicit_system_contract_and_current_lock() {
    let directory = tempfile::tempdir().unwrap();
    let source = "outputs { services: Services = Services { pkgs = []; services = []; }; }";
    let locked = lock(directory.path(), source);
    for selected in [
        ".",
        "catalog",
        ".#services",
        ".#missing",
    ] {
        let output = command(directory.path())
            .args(["system", "plan", selected])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        preserved(directory.path(), source, &locked);
    }
    let changed = "outputs { host: HostConfiguration = HostConfiguration { services = Services { pkgs = []; services = []; }; }; }";
    fs::write(directory.path().join("main.srx"), changed).unwrap();
    let output = command(directory.path())
        .args(["system", "plan", ".#host", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    preserved(directory.path(), changed, &locked);
    for flags in [
        ["--apply", "yes"],
        ["--device", "/dev/sda"],
        ["--store", "/tmp/srx-not-created"],
    ] {
        let output = command(directory.path())
            .args(["system", "plan", ".#host"])
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
    preserved(directory.path(), changed, &locked);
}

#[test]
fn system_plan_exposes_unresolved_disk_binding_and_separate_boot_requirements() {
    let directory = tempfile::tempdir().unwrap();
    let source = include_str!("plan-system.srx");
    let locked = lock(directory.path(), source);
    let before = fs::read_to_string("/proc/sys/vm/swappiness").unwrap();
    let output = command(directory.path())
        .args(["system", "plan", ".#system", "--json"])
        .output()
        .unwrap();
    success(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let plan = &report["plan"];
    assert_eq!(plan["declaration_kind"], "System");
    assert_eq!(plan["storage"]["status"], "unresolved");
    assert!(
        plan["storage"]["reason"]
            .as_str()
            .unwrap()
            .contains("no observed disk matches")
    );
    assert_eq!(
        plan["storage"]["effect_if_provisioned"],
        "destructive"
    );
    assert_eq!(
        plan["kernel"]["desired_release"],
        "6.18.57-srx-plan-fixture"
    );
    assert_eq!(
        plan["kernel"]["generation_change_requires_boot"],
        true
    );
    assert_eq!(
        plan["kernel"]["artifact_compatibility_verified"],
        false
    );
    assert_eq!(plan["sysctls"][0]["name"], "vm.swappiness");
    assert_eq!(plan["can_apply"], false);
    assert!(
        plan["declaration"]
            .as_str()
            .unwrap()
            .contains("uki-signing")
    );
    assert_eq!(
        fs::read_to_string("/proc/sys/vm/swappiness").unwrap(),
        before
    );
    preserved(directory.path(), source, &locked);
}
