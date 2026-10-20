use super::*;

#[test]
fn version_changes_refresh_configuration_completion_and_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let declaration = r#"pub struct Selection { version: std::PackagePinText = "2"; variant: std::PackagePinText = "minimal"; system: std::PackagePinText = "linux-x86_64-gnu"; }
    pub fn nginx(const selection: Selection) -> _ { match selection.variant { "minimal" => match selection.system { "linux-x86_64-gnu" => match selection.version { "1" => old(), "2" => newer() } } } }
value S(str); pub struct Old { listen: S = "old"; } pub struct New { listen: S = "new"; proxyPass: S = "http://localhost"; } pub fn newer() -> std::PackageRef<New> { std::package_ref(std::recipe_ref(recipe), "2", "minimal", "linux-x86_64-gnu", "new", render_new) } pub fn old() -> std::PackageRef<Old> { std::package_ref(std::recipe_ref(recipe), "1", "minimal", "linux-x86_64-gnu", "old", render_old) } fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "nginx"; dependencies = []; }; } } fn render_new(settings: New) -> std::ConfigText { "" } fn render_old(settings: Old) -> std::ConfigText { "" } fn configure<C>(package: std::PackageRef<C>, settings: C) -> std::ConfigText { std::package_config(package, settings) } "#.replace('\n', " ");
    let path = temp.path().join("main.srx");
    let text = format!(
        r#"{declaration} fn selected() {{ configure(nginx({{version = "2";}}), {{ }}); }}"#
    );
    std::fs::write(&path, &text).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    client.open(&document, &text);
    for (version, selected, labels) in [
        (2, "2", vec!["listen", "proxyPass"]),
        (3, "1", vec!["listen"]),
    ] {
        let text = format!(
            r#"{declaration} fn selected() {{ configure(nginx({{version = "{selected}";}}), {{ }}); }}"#
        );
        client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":version},"contentChanges":[{"text":text}]}));
        let diagnostics = client.diagnostics(&document, version);
        assert!(
            diagnostics["params"]["diagnostics"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{diagnostics}"
        );
        let offset = text.rfind("{ }").unwrap() + 2;
        let response = client.request("textDocument/completion", json!({"textDocument":{"uri":document},"position":{"line":0,"character":text[..offset].encode_utf16().count()}}));
        let actual: Vec<_> = response["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["label"].as_str().unwrap())
            .collect();
        assert_eq!(actual, labels, "{response}");
    }
    let text = format!(
        r#"{declaration} fn selected() {{ configure(nginx({{version = "1";}}), {{ proxyPass = "http://localhost"; }}); }}"#
    );
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":4},"contentChanges":[{"text":text}]}),
    );
    let diagnostic = client.wait(|message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["version"] == 4
            && message["params"]["diagnostics"]
                .to_string()
                .contains("proxyPass")
    });
    assert!(
        diagnostic.to_string().contains("proxyPass"),
        "{diagnostic}"
    );
    client.stop();
}

#[test]
fn global_platform_and_version_edits_refresh_settings_and_prelude_queries() {
    let temp = tempfile::tempdir().unwrap();
    let declaration = r#"
        struct PlatformSelection { system: PackagePinText; libc: PackagePinText = "gnu"; }
        struct Platform { system: PackagePinText; libc: PackagePinText; }
        struct PackageSet { platform: Platform; }
        fn forPlatform(const selection: PlatformSelection) -> PackageSet { PackageSet { platform = Platform { system = selection.system; libc = selection.libc; }; } }
        struct Selection { version: PackagePinText; }
        impl PackageSet { fn nginx(const packages: Self, const selection: Selection) -> _ { match packages.platform.libc { "gnu" => match selection.version { "1" => old(), "2" => newer() }, "musl" => old() } } }
        value S(str); struct Old { listen: S = "old"; } struct New { listen: S = "new"; proxyPass: S = "http://localhost"; }
        fn newer() -> PackageRef<New> { package_ref(recipe_ref(recipe), "2", "minimal", "linux-x86_64-gnu", "new", render_new) }
        fn old() -> PackageRef<Old> { package_ref(recipe_ref(recipe), "1", "minimal", "linux-x86_64-musl", "old", render_old) }
        fn recipe() -> Recipe { Recipe { package = Package { id = "nginx"; dependencies = []; }; } }
        fn render_new(settings: New) -> ConfigText { "" } fn render_old(settings: Old) -> ConfigText { "" }
        fn configure<C>(package: PackageRef<C>, settings: C) -> ConfigText { package_config(package, settings) }
    "#.split_whitespace().collect::<Vec<_>>().join(" ");
    let text = |libc: &str, version: &str, settings: &str| {
        format!(
            r#"{declaration} let packages = forPlatform({{ system = "linux-x86_64"; libc = "{libc}"; }}); let selected = packages.nginx {{ version = "{version}"; }}; outputs {{ config: ConfigText = configure(selected, {{ {settings} }}); }}"#
        )
    };
    let path = temp.path().join("main.srx");
    let initial = text("gnu", "2", "");
    std::fs::write(&path, &initial).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "bundled");
    client.open(&document, &initial);
    for (revision, libc, version, labels) in [
        (2, "gnu", "2", vec!["listen", "proxyPass"]),
        (3, "musl", "2", vec!["listen"]),
        (4, "gnu", "1", vec!["listen"]),
        (5, "gnu", "2", vec!["listen", "proxyPass"]),
    ] {
        let text = text(libc, version, "");
        client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":revision},"contentChanges":[{"text":text}]}));
        let diagnostics = client.diagnostics(&document, revision);
        assert!(
            diagnostics["params"]["diagnostics"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{diagnostics}"
        );
        let offset = text.rfind("{  }").unwrap() + 2;
        let response = client.request(
            "textDocument/completion",
            json!({"textDocument":{"uri":document},"position":{"line":0,"character":offset}}),
        );
        let actual: Vec<_> = response["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["label"].as_str().unwrap())
            .collect();
        assert_eq!(actual, labels, "{response}");
    }
    let invalid = text("musl", "2", "proxyPass = \"http://localhost\";");
    client.notify(
        "textDocument/didChange",
        json!({"textDocument":{"uri":document,"version":6},"contentChanges":[{"text":invalid}]}),
    );
    let diagnostics = client.wait(|message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["version"] == 6
            && message["params"]["diagnostics"]
                .to_string()
                .contains("proxyPass")
    });
    assert!(
        diagnostics.to_string().contains("proxyPass"),
        "{diagnostics}"
    );
    let offset = invalid.find("-> Recipe").unwrap() + 6;
    let completion = client.request(
        "textDocument/completion",
        json!({"textDocument":{"uri":document},"position":{"line":0,"character":offset}}),
    );
    assert!(
        completion["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["label"] == "Recipe"),
        "{completion}"
    );
    let offset = invalid.find("package_ref(recipe_ref").unwrap() + "package_ref(".len();
    let signature = client.request(
        "textDocument/signatureHelp",
        json!({"textDocument":{"uri":document},"position":{"line":0,"character":offset}}),
    );
    assert!(
        !signature["result"]["signatures"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{signature}"
    );
    client.stop();
}

#[test]
fn invalid_global_interpolation_is_diagnosed_before_evaluation() {
    let temp = tempfile::tempdir().unwrap();
    let initial = r#"value S(str); fn example() -> S { "ok" } let text: S = "${example}";"#;
    let path = temp.path().join("main.srx");
    std::fs::write(&path, initial).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "none");
    client.open(&document, initial);
    let diagnostics = client.wait(|message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["uri"] == document
            && message["params"]["version"] == 1
            && message["params"]["diagnostics"]
                .to_string()
                .contains("interpolation requires a primitive")
    });
    assert!(
        diagnostics
            .to_string()
            .contains("interpolation requires a primitive"),
        "{diagnostics}"
    );
    for (version, source, expected) in [
        (
            2,
            r#"value S(str); let text: S = "${S}";"#,
            Some("a declaration is not a value"),
        ),
        (
            3,
            r#"resource R(int); value S(str); outputs { held: R = R(1); text: S = "${held}"; }"#,
            Some("imported value output cannot carry an affine resource"),
        ),
        (
            4,
            r#"value S(str); let example: S = "ok"; let text: S = "${example}";"#,
            None,
        ),
    ] {
        client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":version},"contentChanges":[{"text":source}]}));
        let diagnostics = client.wait(|message| {
            message["method"] == "textDocument/publishDiagnostics"
                && message["params"]["uri"] == document
                && message["params"]["version"] == version
                && expected.is_none_or(|expected| {
                    message["params"]["diagnostics"]
                        .to_string()
                        .contains(expected)
                })
        });
        if let Some(expected) = expected {
            assert!(
                diagnostics.to_string().contains(expected),
                "{diagnostics}"
            );
        } else {
            assert!(
                diagnostics["params"]["diagnostics"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "{diagnostics}"
            );
        }
    }
    client.stop();
}

#[test]
fn enum_selection_edits_refresh_inferred_settings_fields() {
    let temp = tempfile::tempdir().unwrap();
    let text = |variant: &str| {
        format!(r#"
        value I(int); value S(str); enum Target {{ Gnu, Musl }}
        struct Gnu {{ port: I = 80; tls: S = ""; }} struct Musl {{ socket: S = "sock"; }}
        fn select(const target: Target) -> _ {{ match target {{ Gnu => Gnu {{}}, Musl => Musl {{}} }} }}
        fn configure<T>(package: T, settings: T) -> I {{ 1 }}
        let target: Target = Target::{variant}; let selected = select(target);
        outputs {{ result: I = configure(selected, {{  }}); }}
    "#).split_whitespace().collect::<Vec<_>>().join(" ")
    };
    let path = temp.path().join("main.srx");
    let initial = text("Gnu");
    std::fs::write(&path, &initial).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "none");
    client.open(&document, &initial);
    client.diagnostics(&document, 1);
    for (version, variant, expected) in [
        (2, "Musl", vec!["socket"]),
        (3, "Gnu", vec!["port", "tls"]),
    ] {
        let source = text(variant);
        client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":version},"contentChanges":[{"text":source}]}));
        let diagnostics = client.diagnostics(&document, version);
        assert!(
            diagnostics["params"]["diagnostics"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{diagnostics}"
        );
        let offset = source.rfind("{ }").unwrap() + 2;
        let response = client.request(
            "textDocument/completion",
            json!({"textDocument":{"uri":document},"position":{"line":0,"character":offset}}),
        );
        let actual: Vec<_> = response["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["label"].as_str().unwrap())
            .collect();
        assert_eq!(actual, expected, "{response}");
    }
    client.stop();
}

#[test]
fn global_callback_effect_diagnostics_refresh_after_body_edits() {
    let temp = tempfile::tempdir().unwrap();
    let initial = "resource R(int); value I(int); let callback = fn() -> I { let consumed = I(7); I(1) }; let answer = callback();";
    let path = temp.path().join("main.srx");
    std::fs::write(&path, initial).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(temp.path(), "utf-16", false, "none");
    client.open(&document, initial);
    for (version, text, invalid) in [
        (2, initial.replace("I(7)", "R(7)"), true),
        (3, initial.to_owned(), false),
    ] {
        client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":version},"contentChanges":[{"text":text}]}));
        let message = client.wait(|message| {
            message["method"] == "textDocument/publishDiagnostics"
                && message["params"]["uri"] == document
                && message["params"]["version"] == version
                && (!invalid
                    || message["params"]["diagnostics"]
                        .to_string()
                        .contains("affine resource through a callback"))
        });
        let diagnostics = message["params"]["diagnostics"]
            .as_array()
            .unwrap();
        if invalid {
            let diagnostic = diagnostics
                .iter()
                .find(|diagnostic| {
                    diagnostic["message"]
                        .as_str()
                        .unwrap()
                        .contains("affine resource through a callback")
                })
                .unwrap_or_else(|| panic!("{message}"));
            assert_eq!(
                diagnostic["range"]["start"]["character"],
                initial.rfind("callback()").unwrap(),
                "{diagnostic}"
            );
        } else {
            assert!(diagnostics.is_empty(), "{message}");
        }
    }
    client.stop();
}
