use super::super::encoding::{Origin, Process, ShellSessionManifest, command_key};
use super::super::*;
use crate::deployment::os::diff::{
    ChangeKind, Effect, GenerationChange, GenerationDiff, ResourceKind, diff_generations,
};
use std::fs;
use std::path::Path;

fn launcher() -> LauncherIdentity {
    LauncherIdentity::new(ContentDigest::sha256(b"launcher bytes"), 1).unwrap()
}

#[test]
fn restart_policy_changes_generation_pin_and_requires_restart_only_for_its_process() {
    let previous = fixture();
    let mut candidate = previous.clone();
    candidate
        .processes
        .get_mut("a/server")
        .unwrap()
        .restart = crate::execution::restart::ProcessRestart::OnFailure(
        crate::execution::restart::RestartLimits::new(2, 30, 5).unwrap(),
    );
    let bytes = candidate.canonical_bytes().unwrap();
    let digest = ContentDigest::sha256(&bytes);
    assert_ne!(
        digest,
        ContentDigest::sha256(&previous.canonical_bytes().unwrap())
    );
    assert_eq!(
        GenerationManifest::decode_bounded(&bytes, digest).unwrap(),
        candidate
    );
    let diff = diff_generations(&previous, &candidate);
    let altered = change(&diff, ResourceKind::Process, "a/server");
    assert_eq!(altered.effect, Effect::RestartRequired);
    assert!(altered.reasons.contains(&"restart policy"));
    assert_eq!(
        change(&diff, ResourceKind::Process, "b/server").effect,
        Effect::None
    );
    let text = String::from_utf8(bytes).unwrap();
    for invalid in [
        text.replace("\"delay_seconds\":2", "\"delay_seconds\":0"),
        text.replace("\"window_seconds\":30", "\"window_seconds\":1"),
        text.replace("\"burst\":5", "\"burst\":101"),
    ] {
        assert!(
            GenerationManifest::decode_bounded(
                invalid.as_bytes(),
                ContentDigest::sha256(invalid.as_bytes())
            )
            .is_err()
        );
    }
}
fn fixture() -> GenerationManifest {
    let mut manifest = GenerationManifest::empty(launcher());
    let output = Output {
        action: ContentDigest::sha256(b"action").to_string(),
        origin: Origin::Imported {
            manifest: ContentDigest::sha256(b"admitted result").to_string(),
        },
        artifact: ContentDigest::sha256(b"artifact").to_string(),
        name: "out".into(),
    };
    let key = output.key().unwrap();
    manifest.outputs.insert(key.clone(), output);
    manifest.provenance.insert(
        key.clone(),
        BTreeSet::from([Provenance {
            label: "same-name".into(),
            path: vec!["pkg".into()],
        }]),
    );
    manifest.selections.insert(Selection {
        service: None,
        output: key.clone(),
    });
    for service in ["a", "b"] {
        manifest.services.insert(service.into());
        manifest.configs.insert(
            format!("{service}/config"),
            Config {
                service: service.into(),
                path: "config".into(),
                text: "old".into(),
                digest: ContentDigest::sha256(b"old").to_string(),
                mode: 0o400,
            },
        );
        let command = command_key(Some(service), "run");
        manifest.commands.insert(
            command.clone(),
            Invocation {
                service: Some(service.into()),
                name: "run".into(),
                application: Role {
                    output: key.clone(),
                    path: "bin/run".into(),
                },
                loader: None,
                libraries: BTreeSet::new(),
                arguments: vec![Argument::File("config".into())],
                environment: BTreeMap::new(),
            },
        );
        manifest.processes.insert(
            format!("{service}/server"),
            Process {
                command,
                restart: crate::execution::restart::ProcessRestart::Never,
            },
        );
    }
    manifest.canonical_bytes().unwrap();
    manifest
}
fn change<'a>(diff: &'a GenerationDiff, kind: ResourceKind, key: &str) -> &'a GenerationChange {
    diff.changes()
        .iter()
        .find(|change| change.resource == kind && change.key == key)
        .unwrap()
}
#[test]
fn canonical_roundtrip_pins_bytes_and_rejects_noncanonical_unknown_or_malformed_data() {
    let original = fixture();
    let bytes = original.canonical_bytes().unwrap();
    assert_eq!(
        GenerationManifest::decode_bounded(&bytes, ContentDigest::sha256(&bytes)).unwrap(),
        original
    );
    assert!(GenerationManifest::decode_bounded(&bytes, ContentDigest::sha256(b"wrong")).is_err());
    let text = String::from_utf8(bytes).unwrap();
    for changed in [
        format!("{text}\n"),
        text.replace("syrox-generation-v2", "syrox-generation-v1"),
        text.replace("\"protocol\":1", "\"protocol\":1,\"protocol\":1"),
        text.replace(
            "\"protocol\":1",
            "\"protocol\":1,\"unknown\":true",
        ),
    ] {
        assert!(
            GenerationManifest::decode_bounded(
                changed.as_bytes(),
                ContentDigest::sha256(changed.as_bytes())
            )
            .is_err()
        );
    }
    let mut invalid = original;
    invalid
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .application
        .output = "absent".into();
    assert!(invalid.canonical_bytes().is_err());
}
#[test]
fn presentation_changes_and_reordering_do_not_restart_or_publish_resources() {
    let previous = fixture();
    let mut candidate = previous.clone();
    let origins = candidate.provenance.values_mut().next().unwrap();
    origins.clear();
    origins.insert(Provenance {
        label: "renamed presentation".into(),
        path: vec!["different".into()],
    });
    assert_ne!(
        previous.canonical_bytes().unwrap(),
        candidate.canonical_bytes().unwrap()
    );
    let diff = diff_generations(&previous, &candidate);
    assert!(!diff.has_operational_changes());
    assert!(diff.render().contains("No operational changes."));
    let serialized = candidate.canonical_bytes().unwrap();
    candidate.commands = candidate.commands.into_iter().rev().collect();
    assert_eq!(serialized, candidate.canonical_bytes().unwrap());
}
#[test]
fn configuration_change_restarts_only_its_service_and_never_leaks_content_in_preview() {
    let previous = fixture();
    let mut candidate = previous.clone();
    let file = candidate.configs.get_mut("a/config").unwrap();
    file.text = "new private preview contents".into();
    file.digest = ContentDigest::sha256(file.text.as_bytes()).to_string();
    let diff = diff_generations(&previous, &candidate);
    assert_eq!(
        change(&diff, ResourceKind::Configuration, "a/config").kind,
        ChangeKind::Changed
    );
    assert_eq!(
        change(&diff, ResourceKind::Process, "a/server").effect,
        Effect::RestartRequired
    );
    assert_eq!(
        change(&diff, ResourceKind::Process, "b/server").effect,
        Effect::None
    );
    assert!(
        !diff
            .render()
            .contains("new private preview contents")
    );
    // Every file in a mounted service tree may be consumed, even without an argv File reference.
    candidate
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .arguments
        .clear();
    let mut previous = previous;
    previous
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .arguments
        .clear();
    assert_eq!(
        change(
            &diff_generations(&previous, &candidate),
            ResourceKind::Process,
            "a/server"
        )
        .effect,
        Effect::RestartRequired
    );
}
#[test]
fn command_runtime_change_and_launcher_change_have_explicit_restart_reasons() {
    let previous = fixture();
    let mut candidate = previous.clone();
    candidate
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .arguments
        .push(Argument::Literal("--flag".into()));
    let diff = diff_generations(&previous, &candidate);
    assert_eq!(
        change(&diff, ResourceKind::Process, "a/server").reasons,
        ["arguments"]
    );
    assert_eq!(
        change(&diff, ResourceKind::Process, "b/server").effect,
        Effect::None
    );
    candidate = previous.clone();
    candidate.launcher = LauncherIdentity::new(ContentDigest::sha256(b"new launcher"), 1).unwrap();
    for change in diff_generations(&previous, &candidate)
        .changes()
        .iter()
        .filter(|change| change.resource == ResourceKind::Process)
    {
        assert_eq!(change.effect, Effect::RestartRequired);
        assert_eq!(change.reasons, ["launcher"]);
    }
}
#[test]
fn removing_root_selection_keeps_output_needed_by_service_and_configuration_only_needs_no_process()
{
    let previous = fixture();
    let mut candidate = previous.clone();
    candidate.selections.clear();
    candidate.canonical_bytes().unwrap();
    let diff = diff_generations(&previous, &candidate);
    assert!(diff.changes().iter().any(
        |change| change.resource == ResourceKind::PackageSelection
            && change.kind == ChangeKind::Removed
    ));
    assert!(
        diff.changes()
            .iter()
            .filter(|change| matches!(
                change.resource,
                ResourceKind::Output | ResourceKind::Process
            ))
            .all(|change| change.kind == ChangeKind::Unchanged)
    );
    let mut previous = previous;
    previous.processes.clear();
    candidate = previous.clone();
    candidate
        .configs
        .get_mut("a/config")
        .unwrap()
        .text = "new".into();
    candidate
        .configs
        .get_mut("a/config")
        .unwrap()
        .digest = ContentDigest::sha256(b"new").to_string();
    assert!(
        !diff_generations(&previous, &candidate)
            .changes()
            .iter()
            .any(|change| change.resource == ResourceKind::Process)
    );
}
#[test]
fn package_output_change_affects_only_commands_using_that_identity() {
    let previous = fixture();
    let mut candidate = previous.clone();
    let old_key = candidate.outputs.keys().next().unwrap().clone();
    let mut output = candidate.outputs[&old_key].clone();
    output.artifact = ContentDigest::sha256(b"changed artifact").to_string();
    let key = output.key().unwrap();
    candidate.outputs.insert(key.clone(), output);
    candidate.provenance.insert(
        key.clone(),
        candidate.provenance[&old_key].clone(),
    );
    candidate
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .application
        .output = key;
    candidate.canonical_bytes().unwrap();
    let diff = diff_generations(&previous, &candidate);
    assert!(
        diff.changes()
            .iter()
            .any(|change| change.resource == ResourceKind::Output
                && change.kind == ChangeKind::Added)
    );
    assert_eq!(
        change(&diff, ResourceKind::Process, "a/server").reasons,
        ["executable"]
    );
    assert_eq!(
        change(&diff, ResourceKind::Process, "b/server").effect,
        Effect::None
    );
}
#[test]
fn validation_rejects_invalid_graph_paths_environment_content_and_bounds() {
    let original = fixture();
    let mut invalid = original.clone();
    invalid.configs.get_mut("a/config").unwrap().text = "tampered".into();
    assert!(invalid.canonical_bytes().is_err());
    invalid = original.clone();
    invalid
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .environment
        .insert(
            "LD_PRELOAD".into(),
            Argument::Literal("bad".into()),
        );
    assert!(invalid.canonical_bytes().is_err());
    invalid = original.clone();
    invalid
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .arguments = vec![Argument::Literal("x".repeat(4097))];
    assert!(invalid.canonical_bytes().is_err());
    invalid = original.clone();
    invalid.processes.insert(
        "a/server".into(),
        Process {
            command: "service/b/run".into(),
            restart: crate::execution::restart::ProcessRestart::Never,
        },
    );
    assert!(invalid.canonical_bytes().is_err());
    invalid = original.clone();
    invalid
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .application
        .path = "../outside".into();
    assert!(invalid.canonical_bytes().is_err());
    invalid = original.clone();
    invalid
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .arguments = vec![Argument::File("undeclared".into())];
    assert!(invalid.canonical_bytes().is_err());
    invalid = original.clone();
    invalid
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .arguments = vec![Argument::Literal("x".into()); 257];
    assert!(invalid.canonical_bytes().is_err());
    assert!(LauncherIdentity::new(ContentDigest::sha256(b"launcher"), 2).is_err());
    let bytes = vec![0; encoding::MAX_BYTES + 1];
    assert!(GenerationManifest::decode_bounded(&bytes, ContentDigest::sha256(b"unused")).is_err());
}

fn prepared(kind: &str) -> (tempfile::TempDir, PreparedConsumer) {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("main.srx"),format!(r#"outputs {{ target: std::{kind} = std::{kind} {{ pkgs=[]; services=[std::Service{{id="git";files=[std::ConfigFile{{path="gitconfig";text="[user]";}}];}}]; }}; }}"#)).unwrap();
    let checks = crate::project::CheckConfiguration {
        standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
        ..crate::project::CheckConfiguration::default()
    };
    crate::project::lock_project_with(temp.path(), &checks).unwrap();
    let prepared =
        crate::project::prepare_project_consumer_with(temp.path(), &checks, "target").unwrap();
    let user = UserConfiguration::parse("", temp.path().join("store")).unwrap();
    let consumer = prepare_consumer(
        prepared,
        "target",
        &user,
        Path::new("missing-worker"),
        true,
        &Cancellation::default(),
        |_, _| panic!("configuration-only must not build"),
    )
    .unwrap();
    assert!(!user.store().exists());
    (temp, consumer)
}
#[test]
fn freeze_keeps_prepared_configuration_without_source_store_or_worker_and_rejects_shell() {
    let (temp, consumer) = prepared("Os");
    fs::remove_file(temp.path().join("main.srx")).unwrap();
    let generation = PreparedGeneration::freeze(consumer, launcher()).unwrap();
    assert_eq!(
        generation.manifest().configs["git/gitconfig"].text,
        "[user]"
    );
    assert_eq!(
        ContentDigest::sha256(generation.canonical_bytes()),
        generation.digest()
    );
    assert_eq!(
        GenerationManifest::decode_bounded(generation.canonical_bytes(), generation.digest())
            .unwrap(),
        *generation.manifest()
    );
    assert!(generation.consumer().outputs().is_empty());
    let (_temp, consumer) = prepared("Shell");
    assert!(matches!(
        PreparedGeneration::freeze(consumer, launcher()),
        Err(GenerationError::NotOs)
    ));
}

#[test]
fn many_processes_share_configuration_change_without_affecting_an_independent_service() {
    let mut previous = fixture();
    for number in 0..1000 {
        previous.processes.insert(
            format!("a/p{number}"),
            Process {
                command: "service/a/run".into(),
                restart: crate::execution::restart::ProcessRestart::Never,
            },
        );
    }
    for number in 0..200 {
        previous.configs.insert(
            format!("a/f{number}"),
            Config {
                service: "a".into(),
                path: format!("f{number}"),
                text: "data".into(),
                digest: ContentDigest::sha256(b"data").to_string(),
                mode: 0o400,
            },
        );
    }
    previous.canonical_bytes().unwrap();
    let mut candidate = previous.clone();
    let file = candidate.configs.get_mut("a/f199").unwrap();
    file.text = "changed".into();
    file.digest = ContentDigest::sha256(b"changed").to_string();
    let diff = diff_generations(&previous, &candidate);
    assert_eq!(
        diff.changes()
            .iter()
            .filter(|change| change.resource == ResourceKind::Process
                && change.effect == Effect::RestartRequired)
            .count(),
        1001
    );
    assert_eq!(
        change(&diff, ResourceKind::Process, "b/server").effect,
        Effect::None
    );
}

#[test]
fn decode_checks_structure_before_allocation_and_configuration_entry_count_is_bounded() {
    let bytes = format!(
        "syrox-generation-v2\n{}0{}",
        "[".repeat(17),
        "]".repeat(17)
    );
    assert!(matches!(
        GenerationManifest::decode_bounded(
            bytes.as_bytes(),
            ContentDigest::sha256(bytes.as_bytes())
        ),
        Err(GenerationError::Invalid(
            "generation structural allocation bound exceeded"
        ))
    ));
    let mut invalid = fixture();
    for number in 0..crate::execution::configuration::MAX_CONFIGURATION_ENTRIES {
        invalid.configs.insert(
            format!("a/f{number}"),
            Config {
                service: "a".into(),
                path: format!("f{number}"),
                text: String::new(),
                digest: ContentDigest::sha256(b"").to_string(),
                mode: 0o400,
            },
        );
    }
    assert!(matches!(
        invalid.canonical_bytes(),
        Err(GenerationError::Invalid(
            "service configuration entry bound exceeded"
        ))
    ));
}

#[test]
fn shell_snapshot_borrows_preparation_and_is_distinct_from_os_generation() {
    let (temp, shell) = prepared("Shell");
    fs::remove_file(temp.path().join("main.srx")).unwrap();
    let (bytes, pin) = shell_snapshot(&shell, launcher()).unwrap();
    assert!(bytes.starts_with(b"syrox-shell-session-v2\n"));
    assert_eq!(ContentDigest::sha256(&bytes), pin);
    let decoded = ShellSessionManifest::decode_bounded(&bytes, pin).unwrap();
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    assert_eq!(
        shell.consumer().services()[0].files()[0].text(),
        "[user]"
    );
    assert_eq!(
        shell_snapshot(&shell, launcher()).unwrap(),
        (bytes.clone(), pin)
    );
    assert!(GenerationManifest::decode_bounded(&bytes, pin).is_err());
    let (_temp, os) = prepared("Os");
    assert!(matches!(
        shell_snapshot(&os, launcher()),
        Err(GenerationError::NotShell)
    ));
    let generation = PreparedGeneration::freeze(os, launcher()).unwrap();
    assert!(
        ShellSessionManifest::decode_bounded(generation.canonical_bytes(), generation.digest())
            .is_err()
    );
    // Operational data, including config content pins, uses exactly the same
    // representation; only the explicit destination wire domain differs.
    assert_eq!(
        bytes
            .strip_prefix(b"syrox-shell-session-v2\n")
            .unwrap(),
        generation
            .canonical_bytes()
            .strip_prefix(b"syrox-generation-v2\n")
            .unwrap()
    );
}

#[test]
fn shell_snapshot_preserves_output_origins_commands_and_process_identity() {
    let manifest = fixture();
    let os = manifest.canonical_bytes().unwrap();
    let shell = ShellSessionManifest::new(manifest.clone());
    let bytes = shell.canonical_bytes().unwrap();
    assert_eq!(
        ShellSessionManifest::decode_bounded(&bytes, ContentDigest::sha256(&bytes)).unwrap(),
        shell
    );
    assert_eq!(
        bytes
            .strip_prefix(b"syrox-shell-session-v2\n")
            .unwrap(),
        os.strip_prefix(b"syrox-generation-v2\n").unwrap()
    );
    let mut changed = manifest;
    changed
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .arguments
        .push(Argument::Literal("new".into()));
    assert_ne!(
        ContentDigest::sha256(&bytes),
        ContentDigest::sha256(
            &ShellSessionManifest::new(changed)
                .canonical_bytes()
                .unwrap()
        )
    );
}

#[test]
fn shell_decode_enforces_pin_canonical_shape_graph_and_bounds() {
    let bytes = ShellSessionManifest::new(fixture())
        .canonical_bytes()
        .unwrap();
    assert!(ShellSessionManifest::decode_bounded(&bytes, ContentDigest::sha256(b"wrong")).is_err());
    let text = String::from_utf8(bytes).unwrap();
    for changed in [
        format!("{text}\n"),
        text.replace("syrox-shell-session-v2", "syrox-shell-session-v1"),
        text.replace("\"protocol\":1", "\"protocol\":1,\"protocol\":1"),
        text.replace(
            "\"protocol\":1",
            "\"protocol\":1,\"unexpected\":1",
        ),
        text.replace("bin/run", "../outside"),
        text.replace("\"mode\":256", "\"mode\":384"),
    ] {
        assert!(
            ShellSessionManifest::decode_bounded(
                changed.as_bytes(),
                ContentDigest::sha256(changed.as_bytes())
            )
            .is_err()
        );
    }
    let excessive = vec![0; encoding::MAX_BYTES + 1];
    assert!(
        ShellSessionManifest::decode_bounded(&excessive, ContentDigest::sha256(b"unused")).is_err()
    );
    let deep = format!(
        "syrox-shell-session-v2\n{}0{}",
        "[".repeat(17),
        "]".repeat(17)
    );
    assert!(matches!(
        ShellSessionManifest::decode_bounded(
            deep.as_bytes(),
            ContentDigest::sha256(deep.as_bytes())
        ),
        Err(GenerationError::Invalid(
            "generation structural allocation bound exceeded"
        ))
    ));
}

#[test]
fn session_state_snapshot_roundtrips_declarations_only_and_os_rejects_them() {
    let mut manifest = fixture();
    manifest.session_states.insert("a".into());
    manifest
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .arguments
        .push(Argument::StateDirectory);
    assert!(manifest.canonical_bytes().is_err());
    let snapshot = ShellSessionManifest::new(manifest.clone());
    let bytes = snapshot.canonical_bytes().unwrap();
    assert_eq!(
        ShellSessionManifest::decode_bounded(&bytes, ContentDigest::sha256(&bytes)).unwrap(),
        snapshot
    );
    manifest.session_states.clear();
    assert!(
        ShellSessionManifest::new(manifest)
            .canonical_bytes()
            .is_err()
    );
}

#[test]
fn shell_secret_snapshot_contains_declarations_only_and_rejects_undeclared_references() {
    let mut manifest = fixture();
    manifest
        .secrets
        .insert("a".into(), BTreeSet::from(["token".into()]));
    manifest
        .commands
        .get_mut("service/a/run")
        .unwrap()
        .arguments
        .push(Argument::SecretFile("token".into()));
    assert!(manifest.canonical_bytes().is_err());
    let snapshot = ShellSessionManifest::new(manifest.clone());
    let bytes = snapshot.canonical_bytes().unwrap();
    assert_eq!(
        ShellSessionManifest::decode_bounded(&bytes, ContentDigest::sha256(&bytes)).unwrap(),
        snapshot
    );
    manifest.secrets.clear();
    assert!(
        ShellSessionManifest::new(manifest)
            .canonical_bytes()
            .is_err()
    );
}
