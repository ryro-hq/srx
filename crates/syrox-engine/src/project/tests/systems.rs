use super::*;

fn system_source() -> String {
    r#"
    fn component() -> std::Recipe { std::Recipe {
        package = std::Package { id = "system-component"; dependencies = []; };
        imported = std::Option::Some(std::ImportedResult {
            root = "fixture_component";
            manifest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            entries = [std::ImportedOutput { output = "out"; key = "data"; }];
        });
    } }
    let selected = std::recipe_ref(component);
    let selected_output = std::recipe_output(selected, "out");
    outputs {
        system: std::System = std::System {
            platform = $SystemPlatform::LinuxX86_64;
            kernel = $Kernel {
                image = $SystemFileSource { output = selected_output; path = "boot/vmlinuz"; };
                modules = selected_output;
                headers = selected_output;
                configuration = $SystemFileSource { output = selected_output; path = "boot/config"; };
                release = "6.18.57-srx-fixture";
                kconfig = [$KernelOption { symbol = "CONFIG_EXT4_FS"; value = $KconfigValue::Boolean(std::Bool::True); }];
                command_line = ["console=ttyS0"];
            };
            userspace = [selected_output];
            identity = $SystemIdentity { hostname = "vm.example"; users = [
                $SystemUser { name = "root"; uid = 0; gid = 0; home = "/root"; shell = "/bin/sh"; }
            ]; };
            directories = [$SystemDirectory { path = "/"; uid = 0; gid = 0; mode = 493; }];
            exposures = [];
            links = [];
            boot = $SystemBoot { signing_credential = "uki-signing"; attempts = 3; };
            storage = $SystemStorage {
                nodes = [
                    $StorageNode { id = "disk"; device = $StorageResource::Disk($DiskResource { selector = $DiskSelector { serial = std::Option::Some("virtual-fixture"); }; }); },
                    $StorageNode { id = "esp-part"; device = $StorageResource::Partition($PartitionResource { disk = "disk"; start_bytes = 1048576; size_bytes = 536870912; partition_kind = $PartitionKind::Esp; }); },
                    $StorageNode { id = "a-part"; device = $StorageResource::Partition($PartitionResource { disk = "disk"; start_bytes = 537919488; size_bytes = 1073741824; partition_kind = $PartitionKind::LinuxData; }); },
                    $StorageNode { id = "b-part"; device = $StorageResource::Partition($PartitionResource { disk = "disk"; start_bytes = 1611661312; size_bytes = 1073741824; partition_kind = $PartitionKind::LinuxData; }); },
                    $StorageNode { id = "esp"; device = $StorageResource::Filesystem($FilesystemResource { source = "esp-part"; filesystem = $FilesystemKind::Fat32; }); },
                    $StorageNode { id = "a"; device = $StorageResource::Filesystem($FilesystemResource { source = "a-part"; filesystem = $FilesystemKind::Ext4; }); },
                    $StorageNode { id = "b"; device = $StorageResource::Filesystem($FilesystemResource { source = "b-part"; filesystem = $FilesystemKind::Ext4; }); },
                ];
                esp = ["esp"]; root_a = "a"; root_b = "b"; persistent = [];
            };
            services = std::Services { pkgs = []; services = []; };
            health = $SystemHealth { timeout_seconds = 120; essential_services = []; require_network = std::Bool::True; };
            budget = $SystemBuildBudget { memory_bytes = 1073741824; cpu_percent = 100; processes = 256; descriptors = 1024; scratch_bytes = 1073741824; files = 100000; output_bytes = 268435456; duration_seconds = 7200; };
        };
    }
    "#.replace('$', "std::system::")
}

#[test]
fn system_declarations_resolve_recipe_references_and_remain_separate_from_services() {
    let project = TempProject::new();
    project.write("main.srx", &system_source());
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let before = fs::read_dir(&project.0).unwrap().count();
    let plan = plan_project_consumer_with(&project.0, &config, "system").unwrap();
    assert_eq!(plan.consumers().len(), 0);
    assert_eq!(plan.systems().len(), 1);
    assert_eq!(plan.host_configurations().len(), 0);
    assert_eq!(plan.imports().len(), 1);
    let system = plan.systems().next().unwrap();
    assert_eq!(system.name, "system");
    assert_eq!(system.kernel.image.path, "boot/vmlinuz");
    assert_eq!(system.kernel.release, "6.18.57-srx-fixture");
    assert_eq!(
        system.kernel.kconfig,
        [crate::plan::PlanKernelOption {
            symbol: "CONFIG_EXT4_FS".into(),
            value: crate::plan::PlanKconfigValue::Boolean(true)
        }]
    );
    assert_eq!(system.identity.hostname, "vm.example");
    assert_eq!(system.identity.users.len(), 1);
    let user = &system.identity.users[0];
    assert_eq!(
        (user.name.as_str(), user.uid, user.gid),
        ("root", 0, 0)
    );
    assert_eq!(
        (user.home.as_str(), user.shell.as_str()),
        ("/root", "/bin/sh")
    );
    assert!(user.authorized_keys.is_empty());
    assert!(user.password_credential.is_none());
    assert_eq!(system.boot.signing_credential, "uki-signing");
    assert_eq!(system.boot.attempts, 3);
    assert_eq!(system.health.timeout_seconds, 120);
    assert!(system.health.essential_services.is_empty());
    assert!(system.health.require_network);
    assert!(system.persistent.is_empty());
    assert_eq!(system.budget.duration_seconds, 7200);
    assert_eq!(system.root_a, "a");
    assert_eq!(system.root_b, "b");
    assert_eq!(system.esp, ["esp"]);
    assert_eq!(
        system.userspace.as_slice(),
        std::slice::from_ref(&system.kernel.modules)
    );
    assert_eq!(system.storage.nodes.len(), 7);
    assert!(matches!(
        system
            .storage
            .plan(&crate::system::inventory::SystemInventory {
                version: 1,
                inspector_architecture: "x86_64".into(),
                kernel_release: "fixture".into(),
                boot_id: "fixture".into(),
                uefi_present: false,
                kvm_device_present: false,
                devices: vec![],
                mounts: vec![],
            }),
        Err(crate::system::storage::StorageError::MissingDisk(
            _
        ))
    ));
    assert_eq!(fs::read_dir(&project.0).unwrap().count(), before);
}

#[test]
fn system_semantics_reject_bad_roots_graphs_budgets_references_and_boot_tokens() {
    let source = system_source();
    for (old, new) in [
        ("root_b = \"b\"", "root_b = \"a\""),
        ("esp = [\"esp\"]", "esp = [\"a\"]"),
        (
            "disk = \"disk\"; start_bytes = 1048576",
            "disk = \"missing\"; start_bytes = 1048576",
        ),
        ("cpu_percent = 100", "cpu_percent = 0"),
        ("path = \"boot/vmlinuz\"", "path = \"../host\""),
        ("\"console=ttyS0\"", "\"root=/dev/sda\""),
        ("\"console=ttyS0\"", "\"rd.luks=0\""),
        ("\"console=ttyS0\"", "\"--\""),
        (
            "uid = 0; gid = 0; home",
            "uid = 10; gid = 0; home",
        ),
        (
            "essential_services = []",
            "essential_services = [\"missing\"]",
        ),
        (
            "signing_credential = \"uki-signing\"",
            "signing_credential = \"../private.key\"",
        ),
        ("symbol = \"CONFIG_EXT4_FS\"", "symbol = \"ext4\""),
        ("mode = 493", "mode = 65535"),
    ] {
        assert!(source.contains(old));
        let result = package_plan(&source.replace(old, new));
        assert!(
            matches!(
                result,
                Err(ProjectOperationError::Plan(
                    crate::plan::PlanError::InvalidSystem { .. }
                ))
            ),
            "{old} => {result:?}"
        );
    }
}

#[test]
fn persistent_data_cannot_replace_generation_binaries_configuration_or_store_paths() {
    let additional = r#"
        std::system::StorageNode { id = "persistent-part"; device = std::system::StorageResource::Partition(std::system::PartitionResource { disk = "disk"; start_bytes = 4294967296; size_bytes = 1073741824; partition_kind = std::system::PartitionKind::LinuxData; }); },
        std::system::StorageNode { id = "persistent-fs"; device = std::system::StorageResource::Filesystem(std::system::FilesystemResource { source = "persistent-part"; filesystem = std::system::FilesystemKind::Ext4; }); },
    "#;
    let source = system_source().replace("nodes = [", &format!("nodes = [{additional}"));
    for target in [
        "/usr/lib",
        "/etc/pki",
        "/boot/efi",
        "/lib/modules",
        "/syrox/store/component",
        "/syrox/generations",
        "/bin",
    ] {
        let value = format!(
            "persistent = [std::system::PersistentVolume {{ filesystem = \"persistent-fs\"; target = \"{target}\"; compatibility = std::system::DataCompatibility::Shared; }}]"
        );
        assert!(
            matches!(
                package_plan(&source.replace("persistent = []", &value)),
                Err(ProjectOperationError::Plan(
                    crate::plan::PlanError::InvalidSystem { .. }
                ))
            ),
            "{target}"
        );
    }
    for target in ["/var/lib/app", "/home", "/usr-local"] {
        let value = format!(
            "persistent = [std::system::PersistentVolume {{ filesystem = \"persistent-fs\"; target = \"{target}\"; compatibility = std::system::DataCompatibility::Shared; }}]"
        );
        let plan = package_plan(&source.replace("persistent = []", &value)).unwrap();
        let system = plan.systems().next().unwrap();
        assert_eq!(
            system.persistent,
            [crate::plan::PlanPersistentVolume {
                filesystem: "persistent-fs".into(),
                target: target.into(),
                compatibility: crate::plan::PlanDataCompatibility::Shared
            }]
        );
        let versioned = package_plan(&source.replace(
            "persistent = []",
            &value.replace(
                "DataCompatibility::Shared",
                "DataCompatibility::Versioned(\"schema-v2\")",
            ),
        ))
        .unwrap();
        assert_eq!(
            versioned.systems().next().unwrap().persistent[0].compatibility,
            crate::plan::PlanDataCompatibility::Versioned("schema-v2".into())
        );
    }
}

#[test]
fn typed_system_projection_keeps_kconfig_values_credentials_and_health_selections() {
    use crate::plan::{PlanKconfigValue as Value, PlanKernelTristate as Tristate};
    let source = system_source().replace(
        "kconfig = [std::system::KernelOption { symbol = \"CONFIG_EXT4_FS\"; value = std::system::KconfigValue::Boolean(std::Bool::True); }];",
        r#"kconfig = [
            std::system::KernelOption { symbol = "CONFIG_A"; value = std::system::KconfigValue::Boolean(std::Bool::False); },
            std::system::KernelOption { symbol = "CONFIG_B"; value = std::system::KconfigValue::Tristate(std::system::KernelTristate::Module); },
            std::system::KernelOption { symbol = "CONFIG_C"; value = std::system::KconfigValue::Integer(-17); },
            std::system::KernelOption { symbol = "CONFIG_D"; value = std::system::KconfigValue::Hexadecimal("0xAbCd"); },
            std::system::KernelOption { symbol = "CONFIG_E"; value = std::system::KconfigValue::Text("requested text"); }
        ];"#,
    ).replace("shell = \"/bin/sh\";", "shell = \"/bin/sh\"; password = std::Option::Some(\"root-password\"); authorized_keys = [\"ssh-ed25519 projection-fixture\"];" )
        .replace("services = std::Services { pkgs = []; services = []; };", "services = std::Services { pkgs = []; services = [std::Service { id = \"console\"; }]; };")
        .replace("essential_services = []", "essential_services = [\"console\"]");
    let plan = package_plan(&source).unwrap();
    let system = plan.systems().next().unwrap();
    assert_eq!(
        system
            .kernel
            .kconfig
            .iter()
            .map(|option| option.value.clone())
            .collect::<Vec<_>>(),
        [
            Value::Boolean(false),
            Value::Tristate(Tristate::Module),
            Value::Integer(-17),
            Value::Hexadecimal("0xAbCd".into()),
            Value::Text("requested text".into())
        ]
    );
    assert_eq!(
        system.identity.users[0]
            .password_credential
            .as_deref(),
        Some("root-password")
    );
    assert_eq!(
        system.identity.users[0].authorized_keys,
        ["ssh-ed25519 projection-fixture"]
    );
    assert_eq!(system.health.essential_services, ["console"]);
}

#[test]
fn normalized_module_parameters_and_filesystem_uuid_shapes_are_checked() {
    let source = r#"outputs { host: std::HostConfiguration = std::HostConfiguration {
        modules = [std::system::KernelModule { name = "fixture"; parameters = [
            std::system::ModuleParameter { name = "log-level"; value = "1"; },
            std::system::ModuleParameter { name = "log_level"; value = "2"; }
        ]; }];
        services = std::Services { pkgs = []; services = []; };
    }; }"#;
    assert!(matches!(
        package_plan(source),
        Err(ProjectOperationError::Plan(
            crate::plan::PlanError::InvalidSystem { .. }
        ))
    ));
    for (kind, good, bad) in [
        (
            "Ext4",
            "12345678-abcd-1234-abcd-1234567890ab",
            "-",
        ),
        ("Fat32", "1234-ABCD", "1234abcd"),
    ] {
        let source = format!(
            r#"outputs {{ host: std::HostConfiguration = std::HostConfiguration {{
            mounts = [std::system::HostMount {{ filesystem_uuid = "{good}"; target = "/srv/data"; filesystem = std::system::FilesystemKind::{kind}; read_only = std::Bool::False; }}];
            services = std::Services {{ pkgs = []; services = []; }};
        }}; }}"#
        );
        package_plan(&source).unwrap();
        assert!(matches!(
            package_plan(&source.replace(good, bad)),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidSystem { .. }
            ))
        ));
    }
}

#[test]
fn tree_layout_is_typed_and_symlink_traversal_is_checked_before_component_builds() {
    let source = system_source().replace("exposures = []", r#"exposures = [std::system::SystemExposure {
        source = std::system::SystemFileSource { output = selected_output; path = "boot/vmlinuz"; };
        destination = "/init"; uid = 42; gid = 43; mode = 488;
    }]"#).replace("links = []", r#"links = [std::system::SystemLink { path = "/alias"; target = "init"; uid = 42; gid = 43; }]"#);
    let plan = package_plan(&source).unwrap();
    let layout = &plan.systems().next().unwrap().layout;
    assert_eq!(layout.directories[0].path, "/");
    assert_eq!(layout.exposures[0].source.path, "boot/vmlinuz");
    assert_eq!(layout.exposures[0].destination, "/init");
    assert_eq!(
        layout.exposures[0].metadata,
        crate::system::image::FileMetadata {
            uid: 42,
            gid: 43,
            mode: 0o750
        }
    );
    assert_eq!(layout.links[0].target, "init");
    for target in ["../host", "alias", "init/../alias"] {
        assert!(
            matches!(
                package_plan(&source.replace(
                    "target = \"init\"",
                    &format!("target = \"{target}\"")
                )),
                Err(ProjectOperationError::Plan(
                    crate::plan::PlanError::InvalidSystem { .. }
                ))
            ),
            "{target}"
        );
    }
}

#[test]
fn host_ownership_selections_are_typed_validated_and_not_service_profiles() {
    let source = r#"
        outputs { host: std::HostConfiguration = std::HostConfiguration {
            sysctls = [std::system::SysctlSetting { name = "vm.swappiness"; value = "10"; }];
            modules = [std::system::KernelModule { name = "virtio_net"; parameters = []; }];
            mounts = [std::system::HostMount { filesystem_uuid = "12345678-abcd-1234-abcd-1234567890ab"; target = "/srv/data"; filesystem = std::system::FilesystemKind::Ext4; read_only = std::Bool::False; }];
            services = std::Services { pkgs = []; services = []; };
        }; }
    "#;
    let plan = package_plan(source).unwrap();
    assert_eq!(plan.consumers().len(), 0);
    assert_eq!(plan.systems().len(), 0);
    let host = plan.host_configurations().next().unwrap();
    assert_eq!(host.sysctls[0].name, "vm.swappiness");
    assert_eq!(host.modules[0].name, "virtio_net");
    assert_eq!(host.mounts[0].target, "/srv/data");
    assert!(!host.mounts[0].read_only);
    assert!(host.kernel.is_none());
    for (old, new) in [
        ("vm.swappiness", "../sys/kernel"),
        ("virtio_net", "../../module"),
        ("/srv/data", "/"),
        ("12345678-abcd-1234-abcd-1234567890ab", "/dev/sda"),
    ] {
        assert!(matches!(
            package_plan(&source.replace(old, new)),
            Err(ProjectOperationError::Plan(
                crate::plan::PlanError::InvalidSystem { .. }
            ))
        ));
    }
}

#[test]
fn missing_required_system_fields_and_unrelated_structs_are_rejected() {
    assert!(matches!(
        package_plan("outputs { system: std::System = std::System {}; }"),
        Err(ProjectOperationError::Check(_))
    ));
    assert!(matches!(
        package_plan("outputs { host: std::HostConfiguration = std::HostConfiguration {}; }"),
        Err(ProjectOperationError::Check(_))
    ));
    let project = TempProject::new();
    project.write(
        "main.srx",
        "struct System {} outputs { fake: System = System {}; }",
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    assert!(matches!(
        plan_project_consumer_with(&project.0, &config, "fake"),
        Err(ProjectOperationError::InvalidConsumerOutput { .. })
    ));
}
