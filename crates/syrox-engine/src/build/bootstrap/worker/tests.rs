use super::*;
use crate::{
    project::AuthenticatedStandardLibrary, project::CheckConfiguration, project::lock_project_with,
    project::plan_project_package_with, store::ContentDigest,
};

const BUILDER: &str = r#"
pub fn build(message: std::BuildLiteral) -> std::Build {
    std::Build { profile = std::BuildProfile::HostBootstrap;
        source_directory = "external"; timeout_seconds = 10;
        source_format = std::BuildSourceFormat::Raw; produces = ["out", "doc"];
        steps = [
            std::BuildStep::Directory(std::BuildPath::Work("job")),
            std::BuildStep::Write(std::BuildFile { path = std::BuildPath::Work("job/input"); text = std::build_text(message); }),
            std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("doc", "source")),
            std::BuildStep::Run(std::BuildProcess {
                executable = std::BuildPath::Host("/bin/sh"); directory = std::BuildPath::Work("job");
                arguments = [std::build_text("-eu"), std::build_text("-c"), std::build_text("test \"$(cat input)\" = \"$TEXT\"; printf %s \"$2\" > \"$1\""), std::build_text("external"), std::build_path(std::BuildPath::Work("result")), std::build_text(message)];
                environment = [std::BuildEnv { name = "TEXT"; text = std::build_text(message); }];
            }),
            std::BuildStep::Move(std::BuildPath::Work("result"), std::BuildPath::Output("out", "message")),
            std::BuildStep::Write(std::BuildFile { path = std::BuildPath::Output("doc", "prefix"); text = std::build_path(std::BuildPath::Installed("out", "message")); }),
        ];
    }
}
"#;

fn project(directory: &Path) -> CheckConfiguration {
    std::fs::create_dir(directory.join("builders")).unwrap();
    std::fs::write(directory.join("builders/external.srx"), BUILDER).unwrap();
    std::fs::write(directory.join("source"), b"source content").unwrap();
    std::fs::write(directory.join("main.srx"), format!(r#"
        inputs {{ builders = "modules:builders"; }}
        fn make() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "external"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request("project:source", "{}", 1024)]; }});
            build = std::Option::Some(builders::external::build("spaces ; $(false) ' literal"));
        }} }} mod factories::demo {{ pub fn recipe() -> std::Recipe {{ project::make() }} }}
        pub publish(factories, recipe): std::Recipe;
    "#, ContentDigest::sha256(b"source content"))).unwrap();
    CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    }
}

#[test]
fn external_srx_builder_lowers_serializes_executes_and_relocks_without_registration() {
    let project_dir = tempfile::tempdir().unwrap();
    let config = project(project_dir.path());
    lock_project_with(project_dir.path(), &config).unwrap();
    let plan = plan_project_package_with(project_dir.path(), &config, "demo").unwrap();
    let build = plan.builds().next().unwrap();
    let program = build.program();
    let encoded = program.encode();
    assert_eq!(program.encoded_size(), encoded.len());
    assert_eq!(BuildProgram::decode(&encoded).unwrap(), *program);
    let work = tempfile::tempdir().unwrap();
    let paths = Paths {
        work: work.path().into(),
        source: project_dir.path().join("source"),
        output: work.path().join("staged"),
        installed: "/syrox/store/test-action".into(),
        inputs: Vec::new(),
    };
    execute(program, &paths, || Ok(())).unwrap();
    assert_eq!(
        std::fs::read_to_string(paths.output.join("out/message")).unwrap(),
        "spaces ; $(false) ' literal"
    );
    assert_eq!(
        std::fs::read(paths.output.join("doc/source")).unwrap(),
        b"source content"
    );
    assert_eq!(
        std::fs::read_to_string(paths.output.join("doc/prefix")).unwrap(),
        "/syrox/store/test-action/out/message"
    );
    let mut framed = Vec::new();
    group::pack(
        &[
            ("out", &paths.output.join("out")),
            ("doc", &paths.output.join("doc")),
        ],
        &mut framed,
    )
    .unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = crate::store::Store::initialize(&store_dir.path().join("store")).unwrap();
    let artifacts = group::unpack(
        framed.as_slice(),
        &std::collections::BTreeMap::from([
            ("doc".into(), String::new()),
            ("out".into(), String::new()),
        ]),
        &store.operation().unwrap(),
        &crate::cancellation::Cancellation::default(),
    )
    .unwrap();
    assert_eq!(artifacts.len(), 2);
    std::fs::write(
        project_dir.path().join("builders/external.srx"),
        BUILDER.replace("\"result\"", "\"changed\""),
    )
    .unwrap();
    assert!(matches!(
        plan_project_package_with(project_dir.path(), &config, "demo"),
        Err(crate::project::ProjectOperationError::ProjectDrift)
    ));
    lock_project_with(project_dir.path(), &config).unwrap();
    let changed = plan_project_package_with(project_dir.path(), &config, "demo").unwrap();
    assert_ne!(
        encoded,
        changed
            .builds()
            .next()
            .unwrap()
            .program()
            .encode()
    );
    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(BuildProgram::decode(&truncated).is_err());
    truncated = encoded.clone();
    truncated.push(0);
    assert!(BuildProgram::decode(&truncated).is_err());
}

#[test]
fn failed_external_process_stops_before_output_publication_and_input_paths_are_explicit() {
    let project_dir = tempfile::tempdir().unwrap();
    let config = project(project_dir.path());
    lock_project_with(project_dir.path(), &config).unwrap();
    let plan = plan_project_package_with(project_dir.path(), &config, "demo").unwrap();
    let mut program = plan.builds().next().unwrap().program().clone();
    let BuildStep::Run(process) = &mut program.steps[3] else {
        panic!("process");
    };
    process.executable = BuildPath::Host("/usr/bin/false".into());
    let work = tempfile::tempdir().unwrap();
    let paths = Paths {
        work: work.path().into(),
        source: project_dir.path().join("source"),
        output: work.path().join("out"),
        installed: "/syrox/store/test-action".into(),
        inputs: Vec::new(),
    };
    assert!(matches!(
        execute(&program, &paths, || Ok(())),
        Err(BuildError::Execution(_))
    ));
    assert!(!paths.output.join("out/message").exists());
    program.steps = vec![BuildStep::Copy {
        source: BuildPath::Input {
            index: 0,
            path: "source".into(),
        },
        destination: BuildPath::Output {
            name: "out".into(),
            path: "copied".into(),
        },
    }];
    assert!(matches!(
        execute(&program, &paths, || Ok(())),
        Err(BuildError::UnsupportedInputs)
    ));
    let paths = Paths {
        inputs: vec![project_dir.path().into()],
        ..paths
    };
    execute(&program, &paths, || Ok(())).unwrap();
    assert_eq!(
        std::fs::read(paths.output.join("out/copied")).unwrap(),
        b"source content"
    );
    program.steps = vec![BuildStep::Directory(BuildPath::Work(
        "../escape".into(),
    ))];
    assert!(program.validate().is_err());
    program.steps = vec![BuildStep::Move {
        source: BuildPath::Input {
            index: 0,
            path: "source".into(),
        },
        destination: BuildPath::Work("moved".into()),
    }];
    assert!(program.validate().is_err());
}

#[test]
fn malformed_extraction_stops_before_following_steps() {
    let project_dir = tempfile::tempdir().unwrap();
    let config = project(project_dir.path());
    lock_project_with(project_dir.path(), &config).unwrap();
    let plan = plan_project_package_with(project_dir.path(), &config, "demo").unwrap();
    let mut program = plan.builds().next().unwrap().program().clone();
    program.source_format = BuildSourceFormat::Gzip;
    program.steps = vec![
        BuildStep::Extract(BuildPath::Work("unpacked".into())),
        BuildStep::Directory(BuildPath::Output {
            name: "out".into(),
            path: "should-not-exist".into(),
        }),
    ];
    let work = tempfile::tempdir().unwrap();
    let paths = Paths {
        work: work.path().into(),
        source: project_dir.path().join("source"),
        output: work.path().join("staged"),
        installed: "/syrox/store/test-action".into(),
        inputs: Vec::new(),
    };
    assert!(execute(&program, &paths, || Ok(())).is_err());
    assert!(!paths.output.join("out/should-not-exist").exists());
}

#[test]
fn process_environment_is_closed_and_profile_selects_only_the_default_path() {
    for (profile, path) in [
        (BuildProfile::HostBootstrap, "/usr/bin:/bin"),
        (BuildProfile::Managed, ""),
    ] {
        // An absolute test helper observes the actual child environment, including
        // any accidental inheritance. This is not a managed executor host gate.
        let output = command(profile, "/usr/bin/env").output().unwrap();
        assert!(output.status.success());
        let mut environment = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        environment.sort();
        assert_eq!(
            environment,
            [
                "HOME=/tmp".to_owned(),
                "LC_ALL=C".to_owned(),
                format!("PATH={path}"),
                "SOURCE_DATE_EPOCH=0".to_owned(),
            ]
        );
    }
}

#[test]
fn managed_run_uses_declared_input_path_environment_and_literal_arguments() {
    let project_dir = tempfile::tempdir().unwrap();
    let config = project(project_dir.path());
    lock_project_with(project_dir.path(), &config).unwrap();
    let plan = plan_project_package_with(project_dir.path(), &config, "demo").unwrap();
    let mut program = plan.builds().next().unwrap().program().clone();
    program.profile = BuildProfile::Managed;
    let work = tempfile::tempdir().unwrap();
    let input = work.path().join("declared-tools");
    std::fs::create_dir(&input).unwrap();
    // Host helpers exercise environment/argv only, outside namespaces and
    // artifact admission. Symlinks avoid freshly writable executable inodes
    // inherited by concurrent test children (ETXTBSY). This is not a seed or
    // managed isolation proof; the public managed worker remains unavailable.
    std::os::unix::fs::symlink("/bin/sh", input.join("sh")).unwrap();
    std::os::unix::fs::symlink("/usr/bin/printf", input.join("printf")).unwrap();
    let literal = |text: &str| BuildText(vec![BuildPart::Literal(text.into())]);
    program.steps = vec![BuildStep::Run(
        crate::build::BuildProcess {
            executable: BuildPath::Input {
                index: 0,
                path: "sh".into(),
            },
            directory: BuildPath::Work(String::new()),
            arguments: vec![
                literal("-eu"),
                literal("-c"),
                literal(
                    "test \"$PATH\" = \"$TOOLS\"; test \"$LC_ALL\" = C; test \"$CUSTOM\" = explicit; exec printf '%s' \"$2\" > \"$1\"",
                ),
                literal("test-helper"),
                BuildText(vec![BuildPart::Path(BuildPath::Output {
                    name: "out".into(),
                    path: "result".into(),
                })]),
                literal("literal $(must-not-execute); with spaces"),
            ],
            environment: vec![
                ("CUSTOM".into(), literal("explicit")),
                (
                    "PATH".into(),
                    BuildText(vec![BuildPart::Path(BuildPath::Input {
                        index: 0,
                        path: String::new(),
                    })]),
                ),
                (
                    "TOOLS".into(),
                    BuildText(vec![BuildPart::Path(BuildPath::Input {
                        index: 0,
                        path: String::new(),
                    })]),
                ),
            ],
        },
    )];
    let paths = Paths {
        work: work.path().into(),
        source: project_dir.path().join("source"),
        output: work.path().join("out"),
        installed: "/syrox/store/test-action".into(),
        inputs: vec![input],
    };
    execute(&program, &paths, || Ok(())).unwrap();
    assert_eq!(
        std::fs::read_to_string(paths.output.join("out/result")).unwrap(),
        "literal $(must-not-execute); with spaces"
    );
}

#[test]
fn worker_profile_never_adopts_the_other_execution_environment() {
    let project_dir = tempfile::tempdir().unwrap();
    let config = project(project_dir.path());
    lock_project_with(project_dir.path(), &config).unwrap();
    let plan = plan_project_package_with(project_dir.path(), &config, "demo").unwrap();
    let mut program = plan.builds().next().unwrap().program().clone();
    let pin = ContentDigest::sha256(b"host-inventory");
    assert!(verify_profile(&program, Some(pin), BuildProfile::HostBootstrap).is_ok());
    assert!(verify_profile(&program, None, BuildProfile::Managed).is_err());
    assert!(verify_profile(&program, None, BuildProfile::HostBootstrap).is_err());
    program.profile = BuildProfile::Managed;
    program.steps = vec![BuildStep::Directory(
        BuildPath::Output {
            name: "out".into(),
            path: "empty".into(),
        },
    )];
    assert!(verify_profile(&program, None, BuildProfile::Managed).is_ok());
    assert!(verify_profile(&program, Some(pin), BuildProfile::Managed).is_err());
    assert!(verify_profile(&program, Some(pin), BuildProfile::HostBootstrap).is_err());
    let work = tempfile::tempdir().unwrap();
    let paths = Paths {
        work: work.path().into(),
        source: work.path().join("source"),
        output: work.path().join("out"),
        installed: "/syrox/store/test".into(),
        inputs: vec![],
    };
    // IR semantics only: installation of the process policy requires a host gate.
    execute(&program, &paths, || Ok(())).unwrap();
    assert!(paths.output.join("out/empty").is_dir());
}
