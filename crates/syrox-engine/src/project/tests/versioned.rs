use super::*;

const CATALOG: &str = r#"
    value Port(int) where 1..=65535;
    value ProxyUrl(str);
    pub struct Old { listen: Port = 8080; }
    struct New { listen: Port = 8080; proxyPass: ProxyUrl = "http://127.0.0.1:3000"; }
    pub fn nginx() -> std::PackageRef<New> package("nginx", "2", "minimal", "linux-x86_64-gnu") {
        std::with_package_service(std::package_ref(std::recipe_ref(recipe), "2", "minimal", "linux-x86_64-gnu", "new", render_new), integrate)
    }
    pub fn old() -> std::PackageRef<Old> package("nginx", "1", "minimal", "linux-x86_64-gnu") {
        std::with_package_service(std::package_ref(std::recipe_ref(recipe), "1", "minimal", "linux-x86_64-gnu", "old", render_old), integrate)
    }
    mod other_abi {
        pub fn musl() -> std::PackageRef<Old> package("nginx", "2", "minimal", "linux-x86_64-musl") {
            std::package_ref(std::recipe_ref(recipe), "2", "minimal", "linux-x86_64-musl", "old", render_old)
        }
    }
    fn recipe() -> std::Recipe {
        std::Recipe { package = std::Package { id = "nginx"; dependencies = []; }; }
    }
    fn render_old(settings: Old) -> std::ConfigText { "old" }
    fn render_new(settings: New) -> std::ConfigText { "new" }
    fn integrate(tool: std::RecipeRef<std::Recipe>, text: std::ConfigText) -> std::Service {
        std::Service { id = "nginx"; files = [std::ConfigFile { path = "nginx.conf"; text = text; }]; }
    }
    pub fn service<C>(package: std::PackageRef<C>, settings: C) -> std::Service {
        std::Service { id = "nginx"; files = [std::ConfigFile { path = "nginx.conf"; text = std::package_config(package, settings); }]; }
    }
"#;

fn fixture(body: &str) -> TempProject {
    let project = TempProject::new();
    project.write(
        "main.srx",
        &format!(
            r#"
        inputs {{ pkgs = "modules:pkgs"; }}
        outputs {{ dev: std::Shell = {body}; }}
    "#
        ),
    );
    project.write("pkgs/package.srx", CATALOG);
    project
}

#[test]
fn selected_version_controls_contextual_settings() {
    for (version, settings, valid) in [
        (
            "2",
            "{ listen = 8080; proxyPass = \"http://localhost\"; }",
            true,
        ),
        ("1", "{ listen = 8080; }", true),
        (
            "1",
            "{ proxyPass = \"http://localhost\"; }",
            false,
        ),
        ("2", "{ listen = \"wrong\"; }", false),
        ("3", "{}", false),
    ] {
        let project = fixture(&format!(
            r#"std::Shell {{ pkgs = []; services = [pkgs::package::service(pkgs::package.nginx {{version = "{version}";}}, {settings})]; }}"#
        ));
        let result = check_path_with(&project.0, &package_configuration());
        assert_eq!(
            result.is_ok(),
            valid,
            "version {version}, settings {settings}: {result:?}"
        );
    }
}

#[test]
fn constants_booleans_and_multiline_configuration_are_pure() {
    let project = fixture(
        r#"let version = "1"; enabled: bool = true; in std::Shell {
        pkgs = []; services = [pkgs::package::service(pkgs::package::nginx({version = version;}), {})];
    }"#,
    );
    let config = package_configuration();
    check_path_with(&project.0, &config).unwrap();
    lock_project_with(&project.0, &config).unwrap();
    let plan = plan_project_with(&project.0, &config).unwrap();
    assert!(plan.to_string().contains("old"));
}

#[test]
fn platform_and_variant_selection_cannot_mix_contracts() {
    for (request, settings, valid) in [
        (
            "pkgs::package.forSystem(\"linux-x86_64-musl\").nginx {version = \"2\";}",
            "{}",
            true,
        ),
        (
            "pkgs::package.forSystem(\"linux-x86_64-musl\").nginx {version = \"2\";}",
            "{proxyPass = \"http://localhost\";}",
            false,
        ),
        (
            "pkgs::package.nginx {variant = \"tls\";}",
            "{}",
            false,
        ),
        (
            "pkgs::package.nginx {system = \"linux-aarch64-musl\";}",
            "{}",
            false,
        ),
        (
            "pkgs::package.nginx {version = \"2\";}",
            "pkgs::package::Old {}",
            false,
        ),
        (
            "pkgs::package.nginx {version = \"2\"; version = \"1\";}",
            "{}",
            false,
        ),
    ] {
        let project = fixture(&format!(
            "std::Shell {{ pkgs = []; services = [pkgs::package::service({request}, {settings})]; }}"
        ));
        assert_eq!(
            check_path_with(&project.0, &package_configuration()).is_ok(),
            valid,
            "{request}: {settings}"
        );
    }
}

#[test]
fn range_failure_is_reported_at_the_configuration_value_before_effects() {
    let project = fixture(
        r#"std::Shell { pkgs = []; services = [pkgs::package::service(pkgs::package.nginx {version = "2";}, {listen = 0;})]; }"#,
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let error = plan_project_with(&project.0, &config).unwrap_err();
    assert!(format!("{error:?}").contains("refinement"));
    assert!(!project.0.join(".syrox").exists());
}

#[test]
fn multiline_text_preserves_ordinary_quotes_interpolation_and_lines() {
    let project = TempProject::new();
    project.write(
        "main.srx",
        r#"outputs { dev: std::Shell = let port = 8080; in std::Shell {
        pkgs = []; services = [std::Service { id = "web"; files = [std::ConfigFile {
            path = "config"; text = """listen ${port};
label "quoted";
""";
        }]; }];
    }; }"#,
    );
    let config = package_configuration();
    lock_project_with(&project.0, &config).unwrap();
    let plan = plan_project_with(&project.0, &config).unwrap();
    assert_eq!(
        plan.consumers().next().unwrap().services()[0].files()[0].text(),
        "listen 8080;\nlabel \"quoted\";\n"
    );
}

#[test]
fn service_attribute_syntax_uses_the_selected_contract_and_honors_disable() {
    for (enabled, version, settings, valid) in [
        (
            true,
            "2",
            "{listen = 8080; proxyPass = \"http://localhost\";}",
            true,
        ),
        (
            true,
            "1",
            "{proxyPass = \"http://localhost\";}",
            false,
        ),
        (false, "1", "{listen = 8080;}", true),
    ] {
        let project = TempProject::new();
        project.write("pkgs/package.srx", CATALOG);
        project.write("main.srx", &format!(r#"inputs {{ pkgs = "modules:pkgs"; }}
            services.nginx = {{ enable = {enabled}; package = pkgs::package.nginx {{version = "{version}";}}; settings = {settings}; }};
        "#));
        let config = package_configuration();
        assert_eq!(
            check_path_with(&project.0, &config).is_ok(),
            valid
        );
        if valid {
            lock_project_with(&project.0, &config).unwrap();
            let plan = plan_project_with(&project.0, &config).unwrap();
            let output = plan.consumers().next().unwrap();
            assert_eq!(output.name(), "os");
            assert_eq!(output.services()[0].id(), "nginx");
            assert_eq!(output.services()[0].files().is_empty(), !enabled);
        }
    }
}
