//! Public `RecipeRef` globals use the same pure CLI selection as publications.

use std::process::{Command, Output};

fn cli(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(arguments)
        .output()
        .unwrap()
}

fn success(arguments: &[&str]) -> String {
    let output = cli(arguments);
    assert!(
        output.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn public_binding_exports_support_info_search_build_and_command_selection() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("main.srx"), r#"
        pub let package = recipe_ref(make);
        pub let alias = package;
        let private_alias = package;
        fn make() -> Recipe { Recipe {
            package = Package { id = "internal-id"; dependencies = []; };
            acquisition = Option::Some(Acquisition { sources = [source_request(
                "https://example.invalid/source", "0000000000000000000000000000000000000000000000000000000000000000", 1024
            )]; });
            build = Option::Some(Build {
                profile = BuildProfile::Managed; source_directory = "source";
                timeout_seconds = 30; source_format = BuildSourceFormat::Raw;
                steps = [BuildStep::Directory(BuildPath::Output("out", "bin"))];
            });
            commands = [Command { name = "test"; output = "out"; path = "bin/test"; }];
        } }
    "#).unwrap();
    let config = project.path().join("config.toml");
    std::fs::write(&config, "").unwrap();
    let store = project.path().join("unopened-store");
    let directory = project.path().to_str().unwrap();
    let config = config.to_str().unwrap();
    let store_path = store.to_str().unwrap();
    success(&["project", "lock", directory]);
    for name in ["package", "alias"] {
        let reference = format!("{directory}#{name}");
        assert!(success(&["info", &reference, "--config", config]).contains("internal-id"));
        assert!(
            success(&[
                "build",
                &reference,
                "--dry-run",
                "--offline",
                "--config",
                config,
                "--store",
                store_path
            ])
            .contains("would build internal-id")
        );
        let output = cli(&[
            "run",
            &reference,
            "--command",
            "missing",
            "--offline",
            "--config",
            config,
            "--store",
            store_path,
        ]);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("no declared command `missing`"));

        let user = syrox_engine::config::UserConfiguration::load_with_store(
            Some(config.as_ref()),
            Some(store.as_path()),
        )
        .unwrap();
        let checks = syrox_engine::project::CheckConfiguration {
            standard_library: Some(syrox_engine::project::AuthenticatedStandardLibrary::bundled()),
            ..Default::default()
        };
        let command =
            syrox_engine::realize::resolve_command(&reference, Some("test"), &user, &checks)
                .unwrap();
        assert_eq!(command.description().name(), "test");
        assert_eq!(command.export(), name);
    }
    let main = project.path().join("main.srx");
    let search = success(&[
        "info",
        "--search",
        "package",
        "-f",
        main.to_str().unwrap(),
        "--config",
        config,
    ]);
    assert!(search.contains("package"));
    assert!(!search.contains("no matching packages"));
    let private = success(&[
        "info",
        "--search",
        "private_alias",
        "-f",
        main.to_str().unwrap(),
        "--config",
        config,
    ]);
    assert!(private.contains("no matching packages"));
    assert!(
        !store.exists(),
        "pure selection must not initialize the Store"
    );
}

#[test]
fn public_binding_initializer_diagnostics_reach_cli_without_store_effects() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.srx"),
        r#"
        value Positive(int) where in [1];
        pub let package = initialize();
        fn initialize() -> RecipeRef<Recipe> {
            let invalid = Positive(0);
            recipe_ref(make)
        }
        fn make() -> Recipe { Recipe { package = Package { id = "valid"; dependencies = []; }; } }
    "#,
    )
    .unwrap();
    let config = project.path().join("config.toml");
    std::fs::write(&config, "").unwrap();
    let store = project.path().join("unopened-store");
    let directory = project.path().to_str().unwrap();
    let reference = format!("{directory}#package");
    success(&["project", "lock", directory]);
    for arguments in [
        vec!["info", reference.as_str()],
        vec![
            "build",
            reference.as_str(),
            "--dry-run",
            "--store",
            store.to_str().unwrap(),
        ],
        vec![
            "run",
            reference.as_str(),
            "--command",
            "test",
            "--store",
            store.to_str().unwrap(),
        ],
        vec!["info", directory, "--search", "package"],
    ] {
        let mut arguments = arguments;
        arguments.extend(["--config", config.to_str().unwrap()]);
        let output = cli(&arguments);
        assert_eq!(output.status.code(), Some(1), "{arguments:?}");
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostics.contains("[srx.evaluation]"),
            "{diagnostics}"
        );
        assert!(diagnostics.contains("main.srx"), "{diagnostics}");
        assert!(
            diagnostics.contains("Positive(0)"),
            "{diagnostics}"
        );
    }
    assert!(!store.exists());
}
