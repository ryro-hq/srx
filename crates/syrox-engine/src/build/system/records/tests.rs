use super::*;
use crate::{
    build::{BuildPath, BuildResources, BuildSourceFormat, BuildStep},
    system::budget::BuilderLimits,
};

fn request() -> BuildBudget {
    BuildBudget {
        memory_bytes: 256 * 1024 * 1024,
        cpu_percent: 100,
        processes: 32,
        descriptors: 128,
        scratch_bytes: 64 * 1024 * 1024,
        files: 4096,
        output_bytes: 16 * 1024 * 1024,
        duration_seconds: 7200,
    }
}
fn limits() -> BuilderLimits {
    let b = request();
    BuilderLimits::new(BuildBudget {
        memory_bytes: b.memory_bytes * 2,
        cpu_percent: b.cpu_percent * 2,
        processes: b.processes * 2,
        descriptors: b.descriptors * 2,
        scratch_bytes: b.scratch_bytes * 2,
        files: b.files * 2,
        output_bytes: b.output_bytes * 2,
        duration_seconds: b.duration_seconds * 2,
    })
    .unwrap()
}
fn template() -> Action {
    Action {
        program: BuildProgram {
            profile: BuildProfile::Managed,
            resources: BuildResources::Standard,
            source_format: BuildSourceFormat::Raw,
            outputs: vec!["out".into()],
            steps: vec![BuildStep::Directory(BuildPath::Work(
                "build".into(),
            ))],
        },
        source: ContentDigest::sha256(b"source"),
        toolchain: None,
        worker: ContentDigest::sha256(b"worker"),
        directory: "source-1".into(),
        inputs: vec![],
    }
}
fn action() -> SystemBuildAction {
    SystemBuildAction::new(
        template(),
        1024,
        limits().admit(request()).unwrap(),
    )
    .unwrap()
}

#[test]
fn canonical_record_round_trips_and_never_enters_the_ordinary_action_parser() {
    let action = action();
    assert_eq!(
        SystemBuildAction::parse(&action.encode(), action.budget()).unwrap(),
        action
    );
    assert!(Action::parse(&action.encode()).is_err());
    let ordinary = template();
    assert_eq!(
        Action::parse(&ordinary.encode()).unwrap(),
        ordinary
    );
    assert_ne!(action.digest(), ordinary.digest());
    assert!(SystemBuildAction::parse(&ordinary.encode(), action.budget()).is_err());
}

#[test]
fn canonical_system_record_has_an_independently_assembled_wire_identity() {
    let action = action();
    assert_eq!(action.encode().len(), 692);
    assert_eq!(
        action.digest().to_string(),
        "e6e6850162239d2e4c4b16f735a2bc5e929514939e39436e243afe7ed0fc750c"
    );
}

#[test]
fn each_requested_dimension_is_bound_independently_of_unchanged_administrator_maxima() {
    let action = action();
    let limits = limits();
    for index in 0..8 {
        let mut changed = request();
        match index {
            0 => changed.memory_bytes += 1,
            1 => changed.cpu_percent += 1,
            2 => changed.processes += 1,
            3 => changed.descriptors += 1,
            4 => changed.scratch_bytes += 1,
            5 => changed.files += 1,
            6 => changed.output_bytes += 1,
            7 => changed.duration_seconds += 1,
            _ => unreachable!(),
        }
        let admitted = limits.admit(changed).unwrap();
        assert_eq!(
            admitted.policy_fingerprint(),
            action.budget().policy_fingerprint()
        );
        let other = SystemBuildAction::new(template(), 1024, admitted).unwrap();
        assert_ne!(action.digest(), other.digest());
        assert!(SystemBuildAction::parse(&action.encode(), &admitted).is_err());
    }
}

#[test]
fn authority_policy_changes_are_distinct_even_for_the_same_effective_request() {
    let action = action();
    let other = BuilderLimits::new(request())
        .unwrap()
        .admit(request())
        .unwrap();
    assert_eq!(other.request(), action.budget().request());
    assert_ne!(
        other.policy_fingerprint(),
        action.budget().policy_fingerprint()
    );
    assert_ne!(
        SystemBuildAction::new(template(), 1024, other)
            .unwrap()
            .digest(),
        action.digest()
    );
    assert!(SystemBuildAction::parse(&action.encode(), &other).is_err());
}

#[test]
fn source_worker_program_input_and_source_limit_participate_in_identity() {
    let original = action();
    for index in 0..4 {
        let mut changed = template();
        match index {
            0 => changed.source = ContentDigest::sha256(b"other source"),
            1 => changed.worker = ContentDigest::sha256(b"other worker"),
            2 => {
                changed.program.steps = vec![BuildStep::Directory(BuildPath::Work(
                    "other".into(),
                ))];
            }
            3 => changed.inputs.push(InputIdentity {
                origin: OutputOrigin::Imported {
                    manifest: ContentDigest::sha256(b"manifest"),
                },
                action: ContentDigest::sha256(b"input action"),
                artifact: ContentDigest::sha256(b"input artifact"),
                output: "out".into(),
            }),
            _ => unreachable!(),
        }
        let action = SystemBuildAction::new(changed, 1024, *original.budget()).unwrap();
        assert_ne!(action.digest(), original.digest());
        assert_eq!(
            SystemBuildAction::parse(&action.encode(), original.budget()).unwrap(),
            action
        );
    }
    assert_ne!(
        SystemBuildAction::new(template(), 1023, *original.budget())
            .unwrap()
            .digest(),
        original.digest()
    );
}

#[test]
fn malformed_noncanonical_and_unsupported_records_are_refused() {
    let action = action();
    let text = String::from_utf8(action.encode()).unwrap();
    for malformed in [
        text.replace(
            "syrox-system-build-action",
            "syrox-system-build-action-v2",
        ),
        text.replace(PROFILE, "syrox-managed-program-x86_64"),
        text.replace("\"source_limit\":1024", "\"source_limit\":0"),
        text.replace(
            "\"source_limit\":1024",
            "\"source_limit\":1073741825",
        ),
        text.replace(
            "\"duration_seconds\":7200",
            "\"duration_seconds\":7201",
        ),
        text.replace("subreaper-echild", "none"),
        text.replace(
            "syrox-system-worker-outputs",
            "syrox-build-output-v1",
        ),
        text.replace(
            &action.source_digest().to_string(),
            &action.source_digest().to_string().to_uppercase(),
        ),
        text.replacen('{', "{\"extra\":true,", 1),
        text.replacen('{', "{ ", 1),
        text.clone() + "\n",
    ] {
        assert!(SystemBuildAction::parse(malformed.as_bytes(), action.budget()).is_err());
    }
    assert!(SystemBuildAction::parse(&vec![0; MAX_BYTES + 1], action.budget()).is_err());
}

#[test]
fn host_authority_invalid_paths_input_indices_and_caps_are_refused() {
    let budget = *action().budget();
    let mut host = template();
    host.program.profile = BuildProfile::HostBootstrap;
    assert!(SystemBuildAction::new(host, 1024, budget).is_err());
    let mut host = template();
    host.toolchain = Some(ContentDigest::sha256(b"ambient"));
    assert!(SystemBuildAction::new(host, 1024, budget).is_err());
    let mut host = template();
    host.program.steps = vec![BuildStep::Copy {
        source: BuildPath::Host("/usr/bin/cc".into()),
        destination: BuildPath::Work("cc".into()),
    }];
    assert!(SystemBuildAction::new(host, 1024, budget).is_err());
    let mut inputs = template();
    inputs.program.steps = vec![BuildStep::Copy {
        source: BuildPath::Input {
            index: 0,
            path: "data".into(),
        },
        destination: BuildPath::Work("data".into()),
    }];
    assert!(SystemBuildAction::new(inputs, 1024, budget).is_err());
    let mut directory = template();
    directory.directory = "../outside".into();
    assert!(SystemBuildAction::new(directory, 1024, budget).is_err());
    assert!(SystemBuildAction::new(template(), 0, budget).is_err());
    assert!(
        SystemBuildAction::new(
            template(),
            budget.request().scratch_bytes + 1,
            budget
        )
        .is_err()
    );
}
