use super::*;
use crate::{config::UserConfiguration, systemd::SystemdScope};

fn configuration() -> String {
    "[build.system]\nworker='/explicit/system-worker'\nworker-sha256='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'\nscope='user'\nuser-bus='/explicit/bus'\nsocket-parent='/explicit/sockets'\nhelper-socket='/run/syrox/system-helper.sock'\n[build.system.maximum]\nmemory-bytes=8589934592\ncpu-percent=400\nprocesses=1024\ndescriptors=8192\nscratch-bytes=68719476736\nfiles=1000000\noutput-bytes=17179869184\nduration-seconds=14400\n".into()
}
fn parse(text: &str) -> Result<UserConfiguration, ConfigurationError> {
    UserConfiguration::parse(text, "/explicit/store".into())
}

#[test]
fn system_policy_is_explicit_pure_and_does_not_select_other_backends() {
    let directory = tempfile::tempdir().unwrap();
    let absent = directory.path().join("absent");
    let text = configuration().replace("/explicit", absent.to_str().unwrap());
    let user = parse(&text).unwrap();
    let system = user.system_build().unwrap();
    assert_eq!(
        system.worker().worker(),
        absent.join("system-worker")
    );
    assert_eq!(
        system.worker().scope(),
        &SystemdScope::User {
            bus_socket: absent.join("bus")
        }
    );
    assert_eq!(
        system.helper_socket(),
        Path::new("/run/syrox/system-helper.sock")
    );
    assert_eq!(
        system.limits().maximum().scratch_bytes,
        68_719_476_736
    );
    assert!(user.managed_build().is_none());
    assert!(user.host_toolchain().is_none());
    assert!(!absent.exists());
    assert!(parse("").unwrap().system_build().is_none());
    assert!(
        parse("[build]\nhost-toolchain='/usr'")
            .unwrap()
            .system_build()
            .is_none()
    );
}

#[test]
fn all_resource_dimensions_must_be_positive_integral_explicit_and_known() {
    for name in [
        "memory-bytes",
        "cpu-percent",
        "processes",
        "descriptors",
        "scratch-bytes",
        "files",
        "output-bytes",
        "duration-seconds",
    ] {
        let missing = configuration()
            .lines()
            .filter(|line| !line.starts_with(&format!("{name}=")))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse(&missing).is_err(), "missing {name}");
        for invalid in [
            toml::Value::Integer(0),
            toml::Value::Integer(-1),
            toml::Value::String("1024".into()),
            toml::Value::Float(1.5),
            toml::Value::Boolean(true),
        ] {
            let mut table: toml::Table = configuration().parse().unwrap();
            table["build"]["system"]["maximum"][name] = invalid;
            assert!(
                parse(&table.to_string()).is_err(),
                "invalid {name}"
            );
        }
    }
    for name in [
        "cpu-percent",
        "processes",
        "descriptors",
        "duration-seconds",
    ] {
        let mut table: toml::Table = configuration().parse().unwrap();
        table["build"]["system"]["maximum"][name] = toml::Value::Integer(i64::from(u32::MAX) + 1);
        assert!(
            parse(&table.to_string()).is_err(),
            "overflow {name}"
        );
    }
    assert!(parse(&format!("{}unknown=1", configuration())).is_err());
    assert!(
        parse(&configuration().replace(
            "[build.system.maximum]",
            "unknown=true\n[build.system.maximum]"
        ))
        .is_err()
    );
}

#[test]
fn endpoint_and_worker_policy_require_complete_canonical_operational_inputs() {
    for name in [
        "worker",
        "worker-sha256",
        "scope",
        "user-bus",
        "socket-parent",
        "helper-socket",
    ] {
        let missing = configuration()
            .lines()
            .filter(|line| !line.starts_with(&format!("{name}=")))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse(&missing).is_err(), "missing {name}");
    }
    for endpoint in [
        "relative",
        "",
        "/",
        "/a/../b",
        "/a/./b",
        "/a//b",
        "/a/",
        "/a b",
        "/%n",
        "@abstract",
    ] {
        assert!(
            parse(&configuration().replace("/run/syrox/system-helper.sock", endpoint)).is_err(),
            "{endpoint}"
        );
    }
    assert!(
        parse(&configuration().replace(
            "/run/syrox/system-helper.sock",
            &format!("/{}", "a".repeat(107))
        ))
        .is_err()
    );
}

#[test]
fn policy_admission_denies_each_dimension_without_expanding_common_managed_limits() {
    let user = parse(&configuration()).unwrap();
    let system = user.system_build().unwrap();
    let maximum = *system.limits().maximum();
    let admitted = system.admit(maximum).unwrap();
    assert_eq!(admitted.request(), &maximum);
    assert_eq!(
        admitted.policy_fingerprint(),
        &system.limits().fingerprint()
    );
    for index in 0..8 {
        let mut request = maximum;
        match index {
            0 => request.memory_bytes += 1,
            1 => request.cpu_percent += 1,
            2 => request.processes += 1,
            3 => request.descriptors += 1,
            4 => request.scratch_bytes += 1,
            5 => request.files += 1,
            6 => request.output_bytes += 1,
            7 => request.duration_seconds += 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            system.admit(request),
            Err(BudgetError::Denied { .. })
        ));
    }
    assert_eq!(
        crate::build::BuildResources::Large.output_limit(),
        128 * 1024 * 1024
    );
    assert!(user.managed_build().is_none());
}
