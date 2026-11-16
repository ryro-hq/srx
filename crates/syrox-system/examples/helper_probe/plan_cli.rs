//! Read-only real CLI plans against explicitly attached disposable VM disks.

use super::{ROOT, recover_cli::unprivileged_command};
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, chown};
use std::path::Path;

pub(super) fn run() -> io::Result<()> {
    let before = std::fs::read_to_string("/proc/sys/vm/swappiness")?;
    let project = Path::new(ROOT).join("client-state/plan-project");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&project)?;
    chown(&project, Some(1000), Some(1000))?;
    let source = r#"outputs {
        host: HostConfiguration = HostConfiguration {
            sysctls = [std::system::SysctlSetting { name = "vm.swappiness"; value = "10"; }];
            services = Services { pkgs = []; services = []; };
        };
    }"#;
    write(&project, source, true)?;
    invoke(&project, &["project", "lock", "."])?;
    let locked = std::fs::read(project.join("Syrox.lock"))?;
    let plan = invoke(&project, &["system", "plan", ".#host", "--json"])?;
    let report: serde_json::Value = serde_json::from_slice(&plan)?;
    assert_eq!(
        report["plan"]["declaration_kind"],
        "HostConfiguration"
    );
    assert_eq!(
        report["plan"]["target"],
        "current_process_namespaces"
    );
    assert_eq!(
        report["plan"]["namespace_ids"]
            .as_object()
            .unwrap()
            .len(),
        7
    );
    assert_eq!(
        report["plan"]["sysctls"][0]["observed"]["value"],
        before.trim_end_matches('\n')
    );
    assert_eq!(report["plan"]["can_apply"], false);
    unchanged(&project, source, &locked)?;
    println!("SRX_HELPER_CASE_OK cli-plan-host");

    let fixture = include_str!("../../../syrox/tests/system/plan-system.srx");
    for (serial, case, status) in [
        (
            "srx-plan-disk",
            "cli-plan-system-bound",
            "bound_to_inventory",
        ),
        (
            "srx-probe-tools",
            "cli-plan-system-readonly",
            "unresolved",
        ),
    ] {
        let source = fixture.replace("srx-absent-plan-fixture-disk-934bf021", serial);
        write(&project, &source, false)?;
        invoke(&project, &["project", "lock", "."])?;
        let locked = std::fs::read(project.join("Syrox.lock"))?;
        let plan = invoke(
            &project,
            &["system", "plan", ".#system", "--json"],
        )?;
        let report: serde_json::Value = serde_json::from_slice(&plan)?;
        let plan = &report["plan"];
        assert_eq!(plan["declaration_kind"], "System");
        assert_eq!(
            plan["storage"]["status"], status,
            "storage: {}",
            plan["storage"]
        );
        assert_eq!(
            plan["storage"]["effect_if_provisioned"],
            "destructive"
        );
        assert_eq!(
            plan["kernel"]["generation_change_requires_boot"],
            true
        );
        assert_eq!(plan["can_apply"], false);
        if status == "bound_to_inventory" {
            let disk = &plan["storage"]["binding"]["disks"][0]["observed"];
            assert_eq!(disk["identity"]["serial"], serial);
            assert_eq!(disk["capacity_bytes"], 4_u64 * 1024 * 1024 * 1024);
            assert_eq!(
                plan["storage"]["binding"]["nodes"]
                    .as_array()
                    .unwrap()
                    .len(),
                7
            );
            assert_eq!(plan["storage"]["metadata_verified"], false);
            assert_eq!(plan["storage"]["exclusive_use_verified"], false);
        } else {
            assert!(
                plan["storage"]["reason"]
                    .as_str()
                    .unwrap()
                    .contains("read-only")
            );
        }
        unchanged(&project, &source, &locked)?;
        println!("SRX_HELPER_CASE_OK {case}");
    }
    assert_eq!(
        std::fs::read_to_string("/proc/sys/vm/swappiness")?,
        before
    );
    println!("SRX_HELPER_PLAN_CLI_READ_ONLY_OK");
    Ok(())
}

fn invoke(project: &Path, args: &[&str]) -> io::Result<Vec<u8>> {
    let output = unprivileged_command()
        .current_dir(project)
        .env("PATH", "/nonexistent")
        .args(args)
        .output()?;
    assert!(output.stdout.len() + output.stderr.len() <= 262_144);
    assert!(
        output.status.success(),
        "plan CLI {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn write(project: &Path, source: &str, first: bool) -> io::Result<()> {
    let path = project.join("main.srx");
    let mut options = OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    if first {
        options.create_new(true);
    } else {
        options.truncate(true);
    }
    let mut file = options.open(&path)?;
    file.write_all(source.as_bytes())?;
    file.sync_all()?;
    chown(path, Some(1000), Some(1000))?;
    File::open(project)?.sync_all()
}

fn unchanged(project: &Path, source: &str, locked: &[u8]) -> io::Result<()> {
    assert_eq!(
        std::fs::read_to_string(project.join("main.srx"))?,
        source
    );
    assert_eq!(std::fs::read(project.join("Syrox.lock"))?, locked);
    assert_eq!(std::fs::read_dir(project)?.count(), 2);
    Ok(())
}
