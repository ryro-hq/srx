use super::*;
use crate::store::Store;
use std::fs;

pub(super) fn prepared(source: &str) -> (tempfile::TempDir, PreparedPlan) {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("main.srx"), source).unwrap();
    let checks = crate::project::CheckConfiguration {
        standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
        ..crate::project::CheckConfiguration::default()
    };
    crate::project::lock_project_with(temp.path(), &checks).unwrap();
    let plan =
        crate::project::prepare_project_consumer_with(temp.path(), &checks, "shell").unwrap();
    (temp, plan)
}

fn source(selections: &str) -> String {
    format!(
        r#"
        fn recipe() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "same-name"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request("https://example.invalid/source", "{}", 1024)]; }});
            build = std::Option::Some(std::Build {{ profile = std::BuildProfile::HostBootstrap;
                source_directory = "source"; timeout_seconds = 30;
                source_format = std::BuildSourceFormat::Raw; produces = ["out", "data"];
                steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "bin/run")),
                    std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("data", "message"))];
            }});
            commands = [std::Command {{ name = "run"; output = "out"; path = "bin/run"; }}];
        }} }}
        outputs {{
            first: std::RecipeRef<std::Recipe> = std::recipe_ref(recipe);
            second: std::RecipeRef<std::Recipe> = std::recipe_ref(recipe);
            shell: std::Shell = std::Shell {{ pkgs = [{selections}]; services = []; }};
        }}
    "#,
        ContentDigest::sha256(b"source")
    )
}

#[test]
fn homonymous_commands_conflict_before_store_creation() {
    let (temp, plan) = prepared(&source(
        "std::select_command(first, \"out\", \"run\"), std::select_command(second, \"out\", \"run\")",
    ));
    let user = UserConfiguration::parse("", temp.path().join("store")).unwrap();
    assert!(matches!(
        prepare_consumer(
            plan,
            "shell",
            &user,
            Path::new("missing-worker"),
            true,
            &Cancellation::default(),
            |_, _| panic!("no effects")
        ),
        Err(DeploymentError::CommandConflict {
            service: None,
            ..
        })
    ));
    assert!(!user.store().exists());
}

#[test]
fn repeated_commands_share_selection_but_homonymous_data_outputs_stay_distinct() {
    let (_temp, plan) = prepared(&source(
        "std::select_command(first, \"out\", \"run\"), std::select_command(first, \"out\", \"run\"), std::select_output(first, \"data\"), std::select_output(second, \"data\")",
    ));
    let selected = select_consumer(&plan, "shell").unwrap();
    assert_eq!(selected.outputs().count(), 3);
    assert_eq!(selected.commands().count(), 1);
}

#[test]
fn configuration_only_consumer_keeps_contents_private_without_store() {
    let (temp, plan) = prepared(
        r#"outputs { shell: std::Shell = std::Shell {
        pkgs = []; services = [std::Service { id = "git"; files = [std::ConfigFile { path = "git/config"; text = "[core]\neditor = managed"; }]; }];
    }; }"#,
    );
    let user = UserConfiguration::parse("", temp.path().join("store")).unwrap();
    let consumer = prepare_consumer(
        plan,
        "shell",
        &user,
        Path::new("missing-worker"),
        true,
        &Cancellation::default(),
        |_, _| panic!("no effects"),
    )
    .unwrap();
    assert!(consumer.outputs().is_empty());
    assert!(consumer.invocations().is_empty());
    assert_eq!(
        consumer.consumer().services()[0].files()[0].path(),
        "git/config"
    );
    assert!(!user.store().exists());
    assert!(!temp.path().join("git").exists());
}

#[test]
fn verified_fixture_output_prepares_command_and_holds_lease() {
    let (temp, plan) = prepared(&source(
        "std::select_command(first, \"out\", \"run\")",
    ));
    let selected = select_consumer(&plan, "shell").unwrap();
    let reference = selected.outputs().next().unwrap().clone();
    let store = Store::initialize(&temp.path().join("store")).unwrap();
    let cancellation = Cancellation::default();
    let result = crate::build::cache::tests::retained_at(
        &store.operation().unwrap(),
        &crate::build::cache::tests::action(),
        "bin/run",
        &crate::runtime::tests::elf(2, None, &[], None, None),
    );
    let view = crate::result::materialize::materialize_named_with_cancellation(
        &store,
        &result.root,
        result.receipt,
        "out",
        &cancellation,
    )
    .unwrap();
    let root = result.root.clone();
    let receipt = result.receipt;
    // Only the prepared views should retain the objects during this proof.
    drop(result);
    let prepared = finish(
        plan,
        selected,
        BTreeMap::from([(reference, view)]),
        &cancellation,
    )
    .unwrap();
    assert!(
        prepared
            .invocations()
            .values()
            .next()
            .unwrap()
            .closure()
            .entry()
            .ends_with("/bin/run")
    );
    let view = prepared.outputs().values().next().unwrap();
    let physical = view.directory().unwrap();
    let artifact = view.artifact();
    let junk = ContentDigest::sha256(b"unrelated garbage");
    store
        .operation()
        .unwrap()
        .ingest(&b"unrelated garbage"[..], junk, 17)
        .unwrap();
    let mut maintenance = store.maintenance().unwrap();
    let report = maintenance
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            remove_roots: vec![root],
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert_eq!(report.removed_objects, [junk]);
    assert_eq!(
        crate::result::materialize::clear_materializations(&mut maintenance).unwrap(),
        0
    );
    drop(maintenance);
    assert_eq!(
        view.read_file("bin/run", 4096, &cancellation)
            .unwrap(),
        crate::runtime::tests::elf(2, None, &[], None, None)
    );
    assert!(physical.exists());
    drop(prepared);
    let mut maintenance = store.maintenance().unwrap();
    assert_eq!(
        crate::result::materialize::clear_materializations(&mut maintenance).unwrap(),
        1
    );
    assert!(!physical.exists());
    let report = maintenance
        .garbage_collect(&crate::store::GcRequest {
            collect: true,
            ..crate::store::GcRequest::default()
        })
        .unwrap();
    assert!(report.removed_objects.contains(&artifact));
    assert!(report.removed_objects.contains(&receipt));
}

#[test]
fn service_command_namespaces_remain_private() {
    let source = source("std::select_command(first, \"out\", \"run\")").replace(
        "services = [];",
        r#"services = [std::Service { id = "private"; pkgs = [std::select_command(second, "out", "run")]; }];"#,
    );
    let (_temp, plan) = prepared(&source);
    let selected = select_consumer(&plan, "shell").unwrap();
    assert_eq!(selected.outputs().count(), 2);
    assert_eq!(selected.commands().count(), 2);
    assert!(
        selected
            .commands()
            .any(|(key, _)| key.0.is_none())
    );
    assert!(
        selected
            .commands()
            .any(|(key, _)| key.0.as_deref() == Some("private"))
    );
}

pub(super) fn configured_source(
    arguments: &str,
    environment: &str,
    expose: &str,
    processes: &str,
) -> String {
    source("").replace("services = [];", &format!(r#"services = [std::Service {{
        id = "git";
        files = [std::ConfigFile {{ path = "git/config"; text = "[core]\neditor = managed"; }}];
        commands = [std::ServiceCommand {{ name = "configured"; command = std::recipe_command(first, "run");
            arguments = [{arguments}]; environment = [{environment}]; expose = {expose}; }}];
        processes = [{processes}];
    }}];"#))
}

#[test]
fn configured_command_selects_recipe_without_duplicate_package_and_keeps_file_binding() {
    let (temp, plan) = prepared(&configured_source(
        "std::CommandArgument::Literal(\"--config\"), std::CommandArgument::File(\"git/config\")",
        "std::CommandEnvironment { name = \"GIT_CONFIG_GLOBAL\"; argument = std::CommandArgument::File(\"git/config\"); }",
        "std::Option::Some(\"git\")",
        "",
    ));
    let selected = select_consumer(&plan, "shell").unwrap();
    assert_eq!(selected.outputs().count(), 1);
    assert!(selected.consumer().pkgs().is_empty());
    assert!(
        selected.consumer().services()[0]
            .pkgs()
            .is_empty()
    );
    let reference = selected.outputs().next().unwrap().clone();
    assert_eq!(
        selected.exposures()["git"],
        (Some("git".into()), "configured".into())
    );
    let store = Store::initialize(&temp.path().join("store")).unwrap();
    let cancellation = Cancellation::default();
    let result = crate::build::cache::tests::retained_at(
        &store.operation().unwrap(),
        &crate::build::cache::tests::action(),
        "bin/run",
        &crate::runtime::tests::elf(2, None, &[], None, None),
    );
    let view = crate::result::materialize::materialize_named_with_cancellation(
        &store,
        &result.root,
        result.receipt,
        "out",
        &cancellation,
    )
    .unwrap();
    let consumer = finish(
        plan,
        selected,
        BTreeMap::from([(reference, view)]),
        &cancellation,
    )
    .unwrap();
    let invocation = &consumer.invocations()[&consumer.exposures()["git"]];
    assert_eq!(
        invocation.arguments(),
        [
            PlanCommandArgument::Literal("--config".into()),
            PlanCommandArgument::File("git/config".into())
        ]
    );
    assert_eq!(
        invocation.environment()[0].name,
        "GIT_CONFIG_GLOBAL"
    );
    assert_eq!(
        invocation.environment()[0].value,
        PlanCommandArgument::File("git/config".into())
    );
    assert!(!temp.path().join("git").exists());
}

#[test]
fn configured_commands_reject_invalid_bindings_before_store_effects() {
    for source in [
        configured_source(
            "std::CommandArgument::File(\"absent\")",
            "",
            "std::Option::None",
            "",
        ),
        configured_source(
            "",
            "std::CommandEnvironment { name = \"PATH\"; argument = std::CommandArgument::Literal(\"/host\"); }",
            "std::Option::None",
            "",
        ),
        configured_source(
            "",
            "std::CommandEnvironment { name = \"LC_ALL\"; argument = std::CommandArgument::Literal(\"C\"); }",
            "std::Option::None",
            "",
        ),
        configured_source("", "", "std::Option::Some(\"../git\")", ""),
        configured_source(
            "",
            "",
            "std::Option::None",
            "std::ServiceProcess {id = \"worker\"; command = \"absent\";}",
        ),
        configured_source("", "", "std::Option::None", "").replace(
            "recipe_command(first, \"run\")",
            "recipe_command(first, \"absent\")",
        ),
        configured_source(
            "",
            "",
            "std::Option::None",
            "std::ServiceProcess {id = \"worker\"; command = \"configured\";}, std::ServiceProcess {id = \"worker\"; command = \"configured\";}",
        ),
        configured_source(
            "",
            "std::CommandEnvironment { name = \"GIT_CONFIG_GLOBAL\"; argument = std::CommandArgument::Literal(\"one\"); }, std::CommandEnvironment { name = \"GIT_CONFIG_GLOBAL\"; argument = std::CommandArgument::Literal(\"two\"); }",
            "std::Option::None",
            "",
        ),
        configured_source("", "", "std::Option::Some(\"run\")", "").replace(
            "pkgs = []; services",
            "pkgs = [std::select_command(first, \"out\", \"run\")]; services",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.srx"), source).unwrap();
        let checks = crate::project::CheckConfiguration {
            standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
            ..crate::project::CheckConfiguration::default()
        };
        crate::project::lock_project_with(temp.path(), &checks).unwrap();
        assert!(matches!(
            crate::project::prepare_project_consumer_with(temp.path(), &checks, "shell"),
            Err(crate::project::ProjectOperationError::Plan(_))
        ));
        assert!(!temp.path().join("store").exists());
    }
}

#[test]
fn foreground_process_is_descriptive_and_binds_private_configured_command() {
    let (_temp, plan) = prepared(&configured_source(
        "std::CommandArgument::Literal(\"-c\"), std::CommandArgument::File(\"git/config\"), std::CommandArgument::Literal(\"-g\"), std::CommandArgument::Literal(\"daemon off;\")",
        "",
        "std::Option::None",
        "std::ServiceProcess {id = \"server\"; command = \"configured\";}",
    ));
    let selected = select_consumer(&plan, "shell").unwrap();
    assert!(selected.exposures().is_empty());
    let process = &selected.consumer().services()[0].processes()[0];
    assert_eq!(process.id, "server");
    assert_eq!(process.command, "configured");
    assert!(plan.plan().to_string().contains("daemon off;"));
}

#[test]
fn expanded_file_environment_path_is_bounded_before_realization() {
    let base = vec!["a".repeat(255); 15].join("/");
    let length = 4096 - "/syrox/config/git/".len();
    let path = format!("{base}/{}", "a".repeat(length - base.len() - 1));
    let source = configured_source(
        "",
        "std::CommandEnvironment {name = \"GIT_CONFIG_GLOBAL\"; argument = std::CommandArgument::File(\"git/config\");}",
        "std::Option::None",
        "",
    );
    let (_temp, plan) = prepared(&source.replace("git/config", &path));
    assert!(select_consumer(&plan, "shell").is_ok());
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("main.srx"),
        source.replace("git/config", &(path + "a")),
    )
    .unwrap();
    let checks = crate::project::CheckConfiguration {
        standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
        ..crate::project::CheckConfiguration::default()
    };
    crate::project::lock_project_with(temp.path(), &checks).unwrap();
    assert!(matches!(
        crate::project::prepare_project_consumer_with(temp.path(), &checks, "shell"),
        Err(crate::project::ProjectOperationError::Plan(_))
    ));
}

/// Verified ELF fixture for descriptor preparation tests; never executes a build.
pub(crate) fn prepared_static_service_fixture() -> (tempfile::TempDir, PreparedConsumer) {
    prepared_service_payload_fixture(
        &crate::runtime::tests::elf(2, None, &[], None, None),
        r#"std::CommandArgument::Literal("literal;$HOME"), std::CommandArgument::File("nested/config")"#,
    )
}

pub(crate) fn prepared_service_payload_fixture(
    payload: &[u8],
    arguments: &str,
) -> (tempfile::TempDir, PreparedConsumer) {
    prepared_service_payload_fixture_kind(payload, arguments, "Shell")
}

pub(crate) fn prepared_service_payload_fixture_kind(
    payload: &[u8],
    arguments: &str,
    kind: &str,
) -> (tempfile::TempDir, PreparedConsumer) {
    prepared_service_payload_fixture_with_source(payload, arguments, kind, None, |source| source)
}

pub(crate) fn prepared_service_payload_fixture_with_source(
    payload: &[u8],
    arguments: &str,
    kind: &str,
    store_path: Option<&Path>,
    transform: impl FnOnce(String) -> String,
) -> (tempfile::TempDir, PreparedConsumer) {
    let text = source("").replace("services = [];", r#"services = [std::Service {
        id = "probe";
        files = [std::ConfigFile { path = "nested/config"; text = "controlled"; }];
        commands = [std::ServiceCommand {
            name = "serve"; command = std::recipe_command(first, "run");
            arguments = [std::CommandArgument::Literal("literal;$HOME"), std::CommandArgument::File("nested/config")];
            environment = [std::CommandEnvironment { name = "APP_CONFIG"; argument = std::CommandArgument::File("nested/config"); }];
        }];
        processes = [std::ServiceProcess { id = "worker"; command = "serve"; }];
    }];"#);
    let text = text.replace(r#"std::CommandArgument::Literal("literal;$HOME"), std::CommandArgument::File("nested/config")"#, arguments);
    let text = text.replace("std::Shell", &format!("std::{kind}"));
    let text = transform(text);
    let (temp, plan) = prepared(&text);
    let selected = select_consumer(&plan, "shell").unwrap();
    let reference = selected.outputs().next().unwrap().clone();
    let default_store = temp.path().join("store");
    let store = Store::initialize(store_path.unwrap_or(&default_store)).unwrap();
    let cancellation = Cancellation::default();
    let result = crate::build::cache::tests::retained_at(
        &store.operation().unwrap(),
        &crate::build::cache::tests::action(),
        "bin/run",
        payload,
    );
    let view = crate::result::materialize::materialize_named_with_cancellation(
        &store,
        &result.root,
        result.receipt,
        "out",
        &cancellation,
    )
    .unwrap();
    let result = finish(
        plan,
        selected,
        BTreeMap::from([(reference, view)]),
        &cancellation,
    )
    .unwrap();
    (temp, result)
}

mod snapshots;
