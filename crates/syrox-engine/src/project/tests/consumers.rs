use super::*;

fn consumer_source(services: &str) -> String {
    format!("outputs {{ os: std::Os = std::Os {{ pkgs = []; services = [{services}]; }}; }}")
}

fn srx_string(text: &str) -> String {
    format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    )
}

fn service_with_files(id: &str, paths: &[&str]) -> String {
    let files = paths
        .iter()
        .map(|path| {
            format!(
                "std::ConfigFile {{ path = {}; text = \"public text\"; }}",
                srx_string(path)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "std::Service {{ id = {}; files = [{files}]; }}",
        srx_string(id)
    )
}

#[test]
fn empty_os_and_shell_are_distinct_pure_consumers() {
    let plan = package_plan(
        r"
        use std::{Os, Shell};
        outputs {
            os: Os = Os { pkgs = []; services = []; };
            shell: Shell = Shell { pkgs = []; services = []; };
        }
        ",
    )
    .unwrap();
    let consumers: Vec<_> = plan.consumers().collect();
    assert_eq!(consumers.len(), 2);
    assert_eq!(consumers[0].name(), "os");
    assert_eq!(
        consumers[0].kind(),
        crate::plan::PlanConsumerKind::Os
    );
    assert_eq!(consumers[0].path(), ["os"]);
    assert_eq!(
        consumers[0].domain(),
        SourceDomainId::project().as_u32()
    );
    assert_eq!(consumers[1].name(), "shell");
    assert_eq!(
        consumers[1].kind(),
        crate::plan::PlanConsumerKind::Shell
    );
    assert!(
        consumers
            .iter()
            .all(|consumer| consumer.pkgs().is_empty())
    );
    assert!(
        consumers
            .iter()
            .all(|consumer| consumer.services().is_empty())
    );
    assert_eq!(plan.packages().len(), 0);
    assert_eq!(plan.builds().len(), 0);
    assert_eq!(plan.commands().len(), 0);
}

#[test]
fn both_root_fields_are_required_while_service_dependencies_and_files_default_empty() {
    for name in ["Os", "Shell"] {
        for fields in ["pkgs = [];", "services = [];"] {
            let source =
                format!("outputs {{ selected: std::{name} = std::{name} {{ {fields} }}; }}");
            assert!(matches!(
                package_plan(&source),
                Err(ProjectOperationError::Check(_))
            ));
        }
    }
    let plan = package_plan(&consumer_source(
        "std::Service { id = \"empty\"; }",
    ))
    .unwrap();
    let consumer = plan.consumers().next().unwrap();
    assert_eq!(consumer.services().len(), 1);
    assert_eq!(consumer.services()[0].id(), "empty");
    assert!(consumer.services()[0].pkgs().is_empty());
    assert!(consumer.services()[0].files().is_empty());
}

#[test]
fn configuration_only_service_preserves_public_text_without_creating_files() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        use std::{Os, Service, ServiceId, ConfigFile, ConfigPath, ConfigText};
        fn file(path: ConfigPath, text: ConfigText) -> ConfigFile {
            ConfigFile { path = path; text = text; }
        }
        fn configure(id: ServiceId) -> Service {
            Service { id = id; files = [file("config/message", "Olá\nsegunda linha")]; }
        }
        outputs { os: Os = Os { pkgs = []; services = [configure("message")]; }; }
        "#,
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let before = fs::read_dir(&project.0).unwrap().count();
    let plan = plan_project_with(&project.0, &config).unwrap();
    let consumer = plan.consumers().next().unwrap();
    let service = &consumer.services()[0];
    assert!(service.pkgs().is_empty());
    assert_eq!(service.files()[0].path(), "config/message");
    assert_eq!(service.files()[0].text(), "Olá\nsegunda linha");
    assert_eq!(plan.packages().len(), 0);
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), before);
    assert!(!project.0.join("config").exists());
}

#[test]
fn service_dependencies_expand_without_direct_exposure_or_an_application() {
    let plan = package_plan(
        r#"
        fn dependency() -> std::Recipe {
            std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://fixture.invalid/data", "0000000000000000000000000000000000000000000000000000000000000000", 4096)]; }); package = std::Package { id = "data"; dependencies = []; }; }
        }
        fn provider() -> std::Recipe {
            std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://fixture.invalid/data", "0000000000000000000000000000000000000000000000000000000000000000", 4096)]; });
                package = std::Package {
                    id = "provider";
                    dependencies = [std::Dependency { recipe = data; }];
                };
            }
        }
        mod factories { mod data { pub fn recipe() -> std::Recipe { project::dependency() } } mod package { pub fn recipe() -> std::Recipe { project::provider() } } }
        pub publish(factories, recipe): std::Recipe;
        mod aliases { pub use project::package; }
outputs {
os: std::Os = std::Os {
                pkgs = [];
                services = [std::Service { id = "configured"; pkgs = [std::select_package(package)]; }];
            };
        }
        "#,
    )
    .unwrap();
    let consumer = plan.consumers().next().unwrap();
    assert!(consumer.pkgs().is_empty());
    let services = consumer.services();
    assert_eq!(services[0].pkgs().len(), 1);
    assert_eq!(
        services[0].pkgs()[0].package().as_str(),
        "provider"
    );
    let packages: Vec<_> = plan.packages().collect();
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].id().as_str(), "data");
    assert_eq!(packages[1].id(), services[0].pkgs()[0].package());
    assert_eq!(
        packages[1].dependencies().collect::<Vec<_>>(),
        [packages[0].id()]
    );
    assert_eq!(plan.commands().len(), 0);
    assert_eq!(plan.builds().len(), 2);
}

#[test]
fn repeated_references_and_aliases_share_identity_but_homonymous_instances_do_not() {
    let plan = package_plan(
        r#"
        fn recipe() -> std::Recipe {
            std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://fixture.invalid/data", "0000000000000000000000000000000000000000000000000000000000000000", 4096)]; }); package = std::Package { id = "same"; dependencies = []; }; }
        }
        mod factories { mod first { pub fn recipe() -> std::Recipe { project::recipe() } } mod second { pub fn recipe() -> std::Recipe { project::recipe() } } }
        pub publish(factories, recipe): std::Recipe;
        mod aliases { pub use project::first; }
outputs {
os: std::Os = std::Os {
                pkgs = [std::select_package(first), std::select_package(aliases::first), std::select_package(first), std::select_package(second)];
                services = [std::Service {
                    id = "configuration";
                    pkgs = [std::select_package(aliases::first), std::select_package(second), std::select_package(first), std::select_package(second)];
                }];
            };
        }
        "#,
    )
    .unwrap();
    let consumer = plan.consumers().next().unwrap();
    assert_eq!(plan.packages().len(), 2);
    assert_eq!(consumer.pkgs().len(), 2);
    assert_eq!(consumer.services()[0].pkgs().len(), 2);
    assert_ne!(consumer.pkgs()[0], consumer.pkgs()[1]);
    assert!(
        consumer
            .pkgs()
            .iter()
            .all(|package| package.package().as_str() == "same")
    );
    for package in consumer.pkgs() {
        assert!(consumer.services()[0].pkgs().contains(package));
    }
}

#[test]
fn imported_homonymous_packages_keep_origin_and_service_aliases_keep_the_provider() {
    let workspace = TempProject::new();
    let config = package_configuration();
    for input in ["left", "right"] {
        workspace.write(
            &format!("{input}/main.srx"),
            r#"
            fn recipe() -> std::Recipe {
                std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://fixture.invalid/data", "0000000000000000000000000000000000000000000000000000000000000000", 4096)]; }); package = std::Package { id = "same"; dependencies = []; }; }
            }
            mod factories { mod package { pub fn recipe() -> std::Recipe { project::recipe() } } }
        pub publish(factories, recipe): std::Recipe;
        pub fn alias() -> std::RecipeRef<std::Recipe> { project::package }

            "#,
        );
        lock_project_with(&workspace.0.join(input), &config).unwrap();
    }
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { left = "path:../left"; right = "path:../right"; }
        outputs {
            os: std::Os = std::Os {
                pkgs = [std::select_package(left::package), std::select_package(right::package)];
                services = [
                    std::Service { id = "left"; pkgs = [std::select_package(left::alias()), std::select_package(left::package)]; },
                    std::Service { id = "right"; pkgs = [std::select_package(right::alias()), std::select_package(right::package)]; },
                ];
            };
        }
        "#,
    );
    let project = workspace.0.join("consumer");
    lock_project_with(&project, &config).unwrap();
    let plan = plan_project_consumer_with(&project, &config, "os").unwrap();
    let consumer = plan.consumers().next().unwrap();
    assert_eq!(plan.packages().len(), 2);
    assert_eq!(consumer.pkgs().len(), 2);
    let left = consumer.services()[0].pkgs();
    let right = consumer.services()[1].pkgs();
    assert_eq!(left.len(), 1);
    assert_eq!(right.len(), 1);
    assert_eq!(left[0].package().as_str(), "same");
    assert_eq!(right[0].package().as_str(), "same");
    assert_ne!(left[0], right[0]);
    assert!(consumer.pkgs().contains(&left[0]));
    assert!(consumer.pkgs().contains(&right[0]));
}

#[test]
fn separate_roots_keep_their_own_exposure_and_service_names() {
    let plan = package_plan(
        r#"
        fn first() -> std::Recipe {
            std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://fixture.invalid/data", "0000000000000000000000000000000000000000000000000000000000000000", 4096)]; }); package = std::Package { id = "first"; dependencies = []; }; }
        }
        fn second() -> std::Recipe {
            std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://fixture.invalid/data", "0000000000000000000000000000000000000000000000000000000000000000", 4096)]; }); package = std::Package { id = "second"; dependencies = []; }; }
        }
        mod factories { mod a { pub fn recipe() -> std::Recipe { project::first() } } mod b { pub fn recipe() -> std::Recipe { project::second() } } }
        pub publish(factories, recipe): std::Recipe;
        outputs {
os: std::Os = std::Os {
                pkgs = [std::select_package(a)]; services = [std::Service { id = "web"; pkgs = [std::select_package(b)]; }];
            };
            shell: std::Shell = std::Shell {
                pkgs = [std::select_package(b)]; services = [std::Service { id = "web"; pkgs = [std::select_package(a)]; }];
            };
        }
        "#,
    )
    .unwrap();
    let consumers: Vec<_> = plan.consumers().collect();
    assert_eq!(consumers.len(), 2);
    assert_eq!(plan.packages().len(), 2);
    assert_eq!(consumers[0].pkgs()[0].package().as_str(), "first");
    assert_eq!(
        consumers[1].pkgs()[0].package().as_str(),
        "second"
    );
    assert_eq!(
        consumers[0].pkgs(),
        consumers[1].services()[0].pkgs()
    );
    assert_eq!(
        consumers[1].pkgs(),
        consumers[0].services()[0].pkgs()
    );
}

#[test]
fn selecting_one_consumer_does_not_force_an_unselected_recipe_or_consumer() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        fn recipe() -> std::Recipe {
            std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://fixture.invalid/data", "0000000000000000000000000000000000000000000000000000000000000000", 4096)]; }); package = std::Package { id = "selected"; dependencies = []; }; }
        }
        fn broken() -> std::Recipe { broken() }
        mod factories { mod good { pub fn recipe() -> std::Recipe { project::recipe() } } mod bad { pub fn recipe() -> std::Recipe { project::broken() } } }
        pub publish(factories, recipe): std::Recipe;
        outputs {
os: std::Os = std::Os { pkgs = [std::select_package(good)]; services = []; };
            shell: std::Shell = std::Shell { pkgs = [std::select_package(bad)]; services = []; };
        }
        "#,
    );
    let config = package_configuration();
    let locked = lock_project_with(&project.0, &config).unwrap();
    assert_eq!(locked.check.realized_roots, 0);
    let plan = plan_project_outputs_with(&project.0, &config, &["os"]).unwrap();
    assert_eq!(plan.consumers().len(), 1);
    assert_eq!(plan.consumers().next().unwrap().name(), "os");
    assert_eq!(plan.packages().len(), 1);
    assert_eq!(
        plan.packages().next().unwrap().id().as_str(),
        "selected"
    );
    assert!(matches!(
        plan_project_outputs_with(&project.0, &config, &["shell"]),
        Err(ProjectOperationError::Check(
            CheckFailure::Evaluation { .. }
        ))
    ));
}

#[test]
fn consumer_selection_keeps_only_the_requested_root_when_values_reference_another_root() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        fn recipe() -> std::Recipe {
            std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request("https://fixture.invalid/data", "0000000000000000000000000000000000000000000000000000000000000000", 4096)]; }); package = std::Package { id = "shared"; dependencies = []; }; }
        }
        mod factories { mod package { pub fn recipe() -> std::Recipe { project::recipe() } } }
        pub publish(factories, recipe): std::Recipe;
        mod aliases { pub use project::package; }
outputs {
os: std::Os = std::Os { pkgs = [std::select_package(package)]; services = []; };
            shell: std::Shell = std::Shell { pkgs = os.pkgs; services = []; };
        }
        "#,
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let plan = plan_project_consumer_with(&project.0, &config, "shell").unwrap();
    assert_eq!(plan.consumers().len(), 1);
    assert_eq!(plan.consumers().next().unwrap().name(), "shell");
    assert_eq!(
        plan.consumers().next().unwrap().kind(),
        crate::plan::PlanConsumerKind::Shell
    );
    assert_eq!(plan.packages().len(), 1);
    assert!(plan.roots().all(|root| root.name() != "os"));
}

#[test]
fn local_nominal_lookalikes_are_not_projected_or_accepted_as_consumers() {
    let error = package_plan(
        r"
        struct Os { pkgs: [std::RecipeRef<std::Recipe>]; services: [std::Service]; }
        struct Shell { pkgs: [std::RecipeRef<std::Recipe>]; services: [std::Service]; }
        outputs {
            os: Os = Os { pkgs = []; services = []; };
            shell: Shell = Shell { pkgs = []; services = []; };
        }
        ",
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ProjectOperationError::InvalidConsumerOutput { .. }
    ));

    let project = TempProject::new();
    project.write(
        "main.srx",
        "struct Os {} fn broken() -> Os { broken() } outputs { fake: Os = broken(); }",
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    assert!(matches!(
        plan_project_consumer_with(&project.0, &config, "fake"),
        Err(ProjectOperationError::InvalidConsumerOutput { name }) if name == "fake"
    ));
}

#[test]
fn os_forced_through_a_generic_recipe_reference_is_not_a_consumer_output() {
    let error = package_plan(
        r"
        struct Wrapper { reference: std::RecipeRef<std::Os>; }
        fn configuration() -> std::Os {
            std::Os { pkgs = []; services = []; }
        }
        outputs {
            wrapper: Wrapper = Wrapper { reference = std::recipe_ref(configuration); };
        }
        ",
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ProjectOperationError::InvalidConsumerOutput { .. }
    ));
}

#[test]
fn service_ids_are_validated_and_unique_within_each_consumer() {
    for id in [
        "", "Upper", "-first", ".first", "_first", "a/b", "a b", "á",
    ] {
        let source = consumer_source(&service_with_files(id, &[]));
        let error = package_plan(&source).unwrap_err();
        assert!(
            matches!(error, ProjectOperationError::Plan(crate::plan::PlanError::InvalidService { ref root, ref service, .. }) if root == "os" && service == id),
            "{id:?}: {error}"
        );
    }
    let too_long = "a".repeat(129);
    assert!(matches!(
        package_plan(&consumer_source(&service_with_files(
            &too_long,
            &[]
        ))),
        Err(ProjectOperationError::Plan(
            crate::plan::PlanError::InvalidService { .. }
        ))
    ));
    let duplicate = "std::Service { id = \"web\"; }, std::Service { id = \"web\"; }";
    assert!(matches!(
        package_plan(&consumer_source(duplicate)),
        Err(ProjectOperationError::Plan(crate::plan::PlanError::InvalidService { root, service, .. }))
            if root == "os" && service == "web"
    ));
    for id in ["0", "a.b_c-2", &"a".repeat(128)] {
        package_plan(&consumer_source(&service_with_files(id, &[]))).unwrap();
    }
}

#[test]
fn config_paths_are_relative_canonical_and_bounded() {
    for path in [
        "",
        "/absolute",
        ".",
        "..",
        "a/./b",
        "a/../b",
        "a//b",
        "a/",
        "a\\b",
        "a\tb",
    ] {
        let error = package_plan(&consumer_source(&service_with_files(
            "config",
            &[path],
        )))
        .unwrap_err();
        assert!(
            matches!(error, ProjectOperationError::Plan(crate::plan::PlanError::InvalidConfigFile { ref root, ref service, path: ref actual, .. }) if root == "os" && service == "config" && actual == path),
            "{path:?}: {error}"
        );
    }
    for path in [
        "a".repeat(256),
        format!("{}a", "a/".repeat(2048)),
        vec!["a"; 33].join("/"),
    ] {
        assert!(matches!(
            package_plan(&consumer_source(&service_with_files(
                "config",
                &[&path]
            ))),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidConfigFile { .. }
            ))
        ));
    }
    for path in [
        "a".repeat(255),
        vec!["a".repeat(255); 16].join("/"),
    ] {
        package_plan(&consumer_source(&service_with_files(
            "config",
            &[&path],
        )))
        .unwrap();
    }
}

#[test]
fn file_duplicates_and_ancestor_conflicts_are_rejected_only_within_the_service() {
    for paths in [
        ["config", "config"],
        ["config", "config/git"],
        ["config/git", "config"],
    ] {
        assert!(matches!(
            package_plan(&consumer_source(&service_with_files("one", &paths))),
            Err(ProjectOperationError::Plan(crate::plan::PlanError::InvalidConfigFile { root, service, .. }))
                if root == "os" && service == "one"
        ));
    }
    let services = format!(
        "{}, {}",
        service_with_files("one", &["config", "configuration/git"]),
        service_with_files("two", &["config"])
    );
    let plan = package_plan(&consumer_source(&services)).unwrap();
    let consumer = plan.consumers().next().unwrap();
    assert_eq!(consumer.services().len(), 2);
    assert_eq!(consumer.services()[0].files().len(), 2);
    assert_eq!(consumer.services()[1].files().len(), 1);
}

#[test]
fn projecting_consumer_acquisitions_does_not_fetch_or_create_a_store() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"
        fn recipe() -> std::Recipe {
            std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });
                package = std::Package { id = "remote-data"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                    "https://acquisition-must-not-run.invalid/source",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    4096
                )]; });
            }
        }
        mod factories { mod reference { pub fn recipe() -> std::Recipe { project::recipe() } } }
        pub publish(factories, recipe): std::Recipe;
        outputs {
os: std::Os = std::Os {
                pkgs = [];
                services = [std::Service { id = "data"; pkgs = [std::select_package(reference)]; }];
            };
        }
        "#,
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let before = fs::read_dir(&project.0).unwrap().count();
    let plan = plan_project_consumer_with(&project.0, &config, "os").unwrap();
    assert_eq!(plan.consumers().len(), 1);
    assert_eq!(plan.acquisitions().len(), 1);
    assert_eq!(plan.builds().len(), 1);
    assert_eq!(plan.commands().len(), 0);
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), before);
    assert!(!project.0.join(".syrox-store").exists());
}

#[test]
fn prepared_consumer_keeps_asset_owner_and_does_not_force_other_factories() {
    let workspace = TempProject::new();
    let config = package_configuration();
    workspace.write("provider/assets/data", "owned by provider");
    workspace.write("consumer/assets/data", "wrong owner");
    workspace.write(
        "provider/main.srx",
        r#"
        fn make() -> std::Recipe {
            std::Recipe {build = std::Option::Some(std::Build { profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1; source_format = std::BuildSourceFormat::Raw; steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "share/data"))]; });
                package = std::Package { id = "data"; dependencies = []; };
                acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                    "project:assets/data",
                    "5600e1d3da3250a2d33873d183ac6a68e1d234845f9b79c07dfb21dd71bc22fa", 4096
                )]; });
            }
        }
        mod factories { mod data { pub fn recipe() -> std::Recipe { project::make() } } }
        pub publish(factories, recipe): std::Recipe;
        
    "#,
    );
    workspace.write(
        "consumer/main.srx",
        r#"
        inputs { provider = "path:../provider"; }
        fn broken() -> std::Recipe { broken() }
        mod factories { mod bad { pub fn recipe() -> std::Recipe { project::broken() } } }
        pub publish(factories, recipe): std::Recipe;
        outputs {
os: std::Os = std::Os { pkgs = [std::select_package(bad)]; services = []; };
            shell: std::Shell = std::Shell {
                pkgs = [std::select_package(provider::data)];
                services = [std::Service { id = "data"; pkgs = [std::select_package(provider::data)]; }];
            };
        }
    "#,
    );
    let provider = workspace.0.join("provider");
    let consumer = workspace.0.join("consumer");
    lock_project_with(&provider, &config).unwrap();
    lock_project_with(&consumer, &config).unwrap();
    let prepared = prepare_project_consumer_with(&consumer, &config, "shell").unwrap();
    assert_eq!(prepared.plan().consumers().len(), 1);
    assert_eq!(prepared.plan().packages().len(), 1);
    assert_eq!(
        prepared.plan().consumers().next().unwrap().name(),
        "shell"
    );
    let request = prepared
        .plan()
        .acquisitions()
        .next()
        .unwrap()
        .sources()
        .next()
        .unwrap();
    let owner = request.owner().unwrap();
    let held = prepared.clone();
    drop(prepared);
    assert_eq!(
        fs::canonicalize(held.project_root(owner).unwrap()).unwrap(),
        fs::canonicalize(provider).unwrap()
    );
    assert_eq!(
        fs::read(
            held.project_root(owner)
                .unwrap()
                .join("assets/data")
        )
        .unwrap(),
        b"owned by provider"
    );
    // A caller may retain and use this preparation after the project changes.
    workspace.write(
        "consumer/main.srx",
        "this is no longer a valid project",
    );
    assert_eq!(
        held.plan().consumers().next().unwrap().name(),
        "shell"
    );
    assert!(prepare_project_consumer_with(&consumer, &config, "shell").is_err());
}

fn selection_source(selection: &str) -> String {
    format!(
        r#"
        fn recipe() -> std::Recipe {{
            std::Recipe {{
                package = std::Package {{ id = "tools"; dependencies = []; }};
                acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request(
                    "https://fixture.invalid/data", "0000000000000000000000000000000000000000000000000000000000000000", 4096
                )]; }});
                build = std::Option::Some(std::Build {{ profile = std::BuildProfile::HostBootstrap; source_directory = "fixture"; timeout_seconds = 1;
                    source_format = std::BuildSourceFormat::Raw; produces = ["out", "data"];
                    steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("data", "share/data"))];
                }});
                commands = [
                    std::Command {{ name = "first"; output = "out"; path = "bin/first"; }},
                    std::Command {{ name = "second"; output = "out"; path = "bin/second"; }},
                ];
            }}
        }}
        mod factories {{ mod tools {{ pub fn recipe() -> std::Recipe {{ project::recipe() }} }} }}
        pub publish(factories, recipe): std::Recipe;
        outputs {{
shell: std::Shell = std::Shell {{ pkgs = [{selection}]; services = []; }};
        }}
    "#
    )
}

#[test]
fn explicit_output_and_commands_merge_without_exposing_data_as_executable() {
    let plan = package_plan(&selection_source(
        r#"
        std::select_package(tools),
        std::select_command(tools, "out", "second"),
        std::select_command(tools, "out", "first"),
        std::select_command(tools, "out", "first"),
        std::select_output(tools, "data")
    "#,
    ))
    .unwrap();
    let selected = plan.consumers().next().unwrap().pkgs();
    assert_eq!(selected.len(), 2);
    let data = selected
        .iter()
        .find(|selection| selection.output().output == "data")
        .unwrap();
    assert!(data.commands().is_empty());
    let executable = selected
        .iter()
        .find(|selection| selection.output().output == "out")
        .unwrap();
    assert_eq!(executable.commands(), ["first", "second"]);
    assert_eq!(executable.package(), data.package());
    assert!(
        plan.to_string()
            .contains("output \"data\" commands []")
    );
}

#[test]
fn missing_outputs_commands_and_wrong_output_commands_fail_before_effects() {
    for selection in [
        "std::select_output(tools, \"missing\")",
        "std::select_command(tools, \"out\", \"missing\")",
        "std::select_command(tools, \"data\", \"first\")",
    ] {
        let project = TempProject::new();
        project.write("main.srx", &selection_source(selection));
        let configuration = package_configuration();
        lock_project_with(&project.0, &configuration).unwrap();
        let before = fs::read_dir(&project.0).unwrap().count();
        assert!(matches!(
            prepare_project_consumer_with(&project.0, &configuration, "shell"),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidConsumer { .. }
            ))
        ));
        assert_eq!(fs::read_dir(&project.0).unwrap().count(), before);
        assert!(!project.0.join(".syrox-store").exists());
    }
    assert!(
        matches!(
            package_plan(&selection_source("tools")),
            Err(ProjectOperationError::Check(_))
        ),
        "raw RecipeRef must not retain an implicit legacy selection path"
    );
}

#[test]
fn session_state_requires_declaration_and_managed_shell_destination() {
    let service = r#"std::Service { id = "cache"; state = std::ServiceState::Session;
        commands = [std::ServiceCommand { name = "run"; command = std::recipe_command(tools, "first");
            arguments = [std::CommandArgument::StateDirectory];
            environment = [std::CommandEnvironment { name = "APP_HOME"; argument = std::CommandArgument::StateDirectory; }];
            expose = std::Option::Some("run"); }]; }"#;
    let source = selection_source("").replace(
        "services = [];",
        &format!("services = [{service}];"),
    );
    let plan = package_plan(&source).unwrap();
    let consumer = plan.consumers().next().unwrap();
    assert_eq!(
        consumer.services()[0].state(),
        crate::plan::PlanServiceState::Session
    );
    assert_eq!(
        consumer.services()[0].commands()[0].arguments(),
        &[crate::plan::PlanCommandArgument::StateDirectory]
    );
    for rejected in [
        source.replace("state = std::ServiceState::Session;", ""),
        source.replace("std::Shell", "std::Os"),
    ] {
        assert!(package_plan(&rejected).is_err());
    }
}

fn restart_source(policy: &str, consumer: &str) -> String {
    let service = format!(
        r#"std::Service {{ id = "daemon";
        commands = [std::ServiceCommand {{ name = "run"; command = std::recipe_command(tools, "first"); }}];
        processes = [std::ServiceProcess {{ id = "worker"; command = "run"; {policy} }}]; }}"#
    );
    selection_source("")
        .replace(
            "services = [];",
            &format!("services = [{service}];"),
        )
        .replace("std::Shell", &format!("std::{consumer}"))
}

#[test]
fn process_restart_is_explicit_bounded_and_os_only() {
    for consumer in ["Os", "Shell"] {
        let plan = package_plan(&restart_source("", consumer)).unwrap();
        let process = &plan.consumers().next().unwrap().services()[0].processes()[0];
        assert_eq!(
            process.restart(),
            crate::execution::restart::ProcessRestart::Never
        );
    }
    for (delay, window, burst) in [(1, 1, 1), (300, 3600, 100)] {
        let policy = format!(
            "restart = std::ProcessRestart::OnFailure(std::RestartLimits {{ delay_seconds = {delay}; window_seconds = {window}; burst = {burst}; }});"
        );
        let plan = package_plan(&restart_source(&policy, "Os")).unwrap();
        assert_eq!(
            plan.consumers().next().unwrap().services()[0].processes()[0].restart(),
            crate::execution::restart::ProcessRestart::OnFailure(
                crate::execution::restart::RestartLimits::new(delay, window, burst).unwrap()
            )
        );
        assert!(plan.to_string().contains("restart on-failure"));
        assert!(matches!(
            package_plan(&restart_source(&policy, "Shell")),
            Err(ProjectOperationError::Plan(_))
        ));
    }
    for (delay, window, burst) in [
        (0, 1, 1),
        (301, 3600, 1),
        (1, 0, 1),
        (1, 3601, 1),
        (2, 1, 1),
        (1, 1, 0),
        (1, 1, 101),
    ] {
        let policy = format!(
            "restart = std::ProcessRestart::OnFailure(std::RestartLimits {{ delay_seconds = {delay}; window_seconds = {window}; burst = {burst}; }});"
        );
        assert!(matches!(
            package_plan(&restart_source(&policy, "Os")),
            Err(ProjectOperationError::Plan(_))
        ));
    }
    // A standalone '-' is not a language token: negative text is rejected
    // during source checking, before restart policy projection.
    let negative = "restart = std::ProcessRestart::OnFailure(std::RestartLimits { delay_seconds = -1; window_seconds = 1; burst = 1; });";
    let error = package_plan(&restart_source(negative, "Os")).unwrap_err();
    assert!(
        matches!(error, ProjectOperationError::Check(_)),
        "{error}"
    );
    for missing in [
        "delay_seconds = 1; window_seconds = 10;",
        "delay_seconds = 1; burst = 2;",
        "window_seconds = 10; burst = 2;",
    ] {
        let policy = format!(
            "restart = std::ProcessRestart::OnFailure(std::RestartLimits {{ {missing} }});"
        );
        assert!(matches!(
            package_plan(&restart_source(&policy, "Os")),
            Err(ProjectOperationError::Check(_))
        ));
    }
}

#[test]
fn unsupported_shell_restart_fails_before_realization_or_state() {
    let project = TempProject::new();
    project.write("main.srx", &restart_source("restart = std::ProcessRestart::OnFailure(std::RestartLimits { delay_seconds = 1; window_seconds = 10; burst = 3; });", "Shell"));
    let configuration = package_configuration();
    lock_project_with(&project.0, &configuration).unwrap();
    let before = fs::read_dir(&project.0).unwrap().count();
    assert!(matches!(
        prepare_project_consumer_with(&project.0, &configuration, "shell"),
        Err(ProjectOperationError::Plan(_))
    ));
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), before);
    assert!(!project.0.join(".syrox-store").exists());
}

#[test]
fn secret_files_require_declared_names_and_managed_shell_destination() {
    let service = r#"std::Service { id = "credentials"; secrets = ["token"];
        commands = [std::ServiceCommand { name = "run"; command = std::recipe_command(tools, "first");
            arguments = [std::CommandArgument::SecretFile("token")];
            environment = [std::CommandEnvironment { name = "TOKEN_FILE"; argument = std::CommandArgument::SecretFile("token"); }];
            expose = std::Option::Some("run"); }]; }"#;
    let source = selection_source("").replace(
        "services = [];",
        &format!("services = [{service}];"),
    );
    let plan = package_plan(&source).unwrap();
    let consumer = plan.consumers().next().unwrap();
    assert_eq!(consumer.services()[0].secrets(), ["token"]);
    assert_eq!(
        consumer.services()[0].commands()[0].arguments(),
        &[crate::plan::PlanCommandArgument::SecretFile("token".into())]
    );
    let sources = crate::config::ShellSecretSources::new([
        (
            "credentials".into(),
            "token".into(),
            "/private/sentinel-secret-source".into(),
        ),
        (
            "other-project".into(),
            "unused".into(),
            "/not-opened/unused".into(),
        ),
    ])
    .unwrap();
    let selected = sources.for_consumer(consumer).unwrap();
    assert_eq!(selected.len(), 1);
    assert!(!format!("{sources:?}").contains("sentinel"));
    assert!(!plan.to_string().contains("sentinel"));
    assert!(
        crate::config::ShellSecretSources::default()
            .for_consumer(consumer)
            .is_err()
    );
    for rejected in [
        source.replace("secrets = [\"token\"];", ""),
        source.replace(
            "secrets = [\"token\"];",
            "secrets = [\"token\", \"token\"];",
        ),
        source.replace("\"token\"", "\"../secret\""),
        source.replace("std::Shell", "std::Os"),
        source.replace(
            "secrets = [\"token\"];",
            &format!(
                "secrets = [{}];",
                (0..33)
                    .map(|n| format!("\"s{n}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
    ] {
        assert!(package_plan(&rejected).is_err());
    }
}

#[test]
fn declared_secret_limits_cover_per_service_and_consumer_boundaries() {
    fn source(counts: &[usize]) -> String {
        let services = counts
            .iter()
            .enumerate()
            .map(|(service, count)| {
                let names = (0..*count)
                    .map(|n| format!("\"key{n}\""))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("std::Service {{ id = \"service{service}\"; secrets = [{names}]; }}")
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "outputs {{ shell: std::Shell = std::Shell {{ pkgs = []; services = [{services}]; }}; }}"
        )
    }
    assert_eq!(
        package_plan(&source(&[32]))
            .unwrap()
            .consumers()
            .next()
            .unwrap()
            .services()[0]
            .secrets()
            .len(),
        32
    );
    assert_eq!(
        package_plan(&source(&[32; 8]))
            .unwrap()
            .consumers()
            .next()
            .unwrap()
            .services()
            .iter()
            .map(|service| service.secrets().len())
            .sum::<usize>(),
        256
    );
    for counts in [
        vec![33],
        vec![32, 32, 32, 32, 32, 32, 32, 32, 1],
    ] {
        let error = package_plan(&source(&counts)).unwrap_err();
        assert!(error.to_string().contains("too many"), "{error}");
    }
}
