use super::*;

#[test]
fn package_set_methods_complete_navigate_and_show_signatures_across_platform_edits() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("pkgs");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&catalog).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let library = r#"
        pub struct PlatformSelection { system: PackagePinText; libc: PackagePinText = "gnu"; }
        pub struct Platform { system: PackagePinText; libc: PackagePinText; }
        pub struct PackageSet { platform: Platform; }
        pub struct Selection { version: PackagePinText; }
        pub fn forPlatform(const selection: PlatformSelection) -> PackageSet {
            PackageSet { platform = { system = selection.system; libc = selection.libc; }; }
        }
        impl PackageSet {
            fn nginx(const packages: Self, const selection: Selection) -> _ {
                match packages.platform.libc {
                    "gnu" => match selection.version { "1" => old(), "2" => newer() },
                    "musl" => old()
                }
            }
        }
        pub struct Old { listen: PackagePinText = "old"; }
        pub struct New { listen: PackagePinText = "new"; proxyPass: PackagePinText = "http://localhost"; }
        fn newer() -> PackageRef<New> { package_ref(recipe_ref(recipe), "2", "minimal", "linux-x86_64-gnu", "new", render_new) }
        fn old() -> PackageRef<Old> { package_ref(recipe_ref(recipe), "1", "minimal", "linux-x86_64-musl", "old", render_old) }
        fn recipe() -> Recipe { Recipe { package = Package { id = "nginx"; dependencies = []; }; } }
        fn render_new(settings: New) -> ConfigText { "" }
        fn render_old(settings: Old) -> ConfigText { "" }
    "#.split_whitespace().collect::<Vec<_>>().join(" ");
    std::fs::write(catalog.join("main.srx"), &library).unwrap();
    let locked = Command::new(env!("CARGO_BIN_EXE_srx"))
        .args(["project", "lock"])
        .arg(&catalog)
        .output()
        .unwrap();
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    let declaration = |libc: &str| {
        format!(
            r#"inputs {{ pkgs = "path:../pkgs"; }} let packages = pkgs.forPlatform {{ system = "linux-x86_64"; libc = "{libc}"; }}; "#
        )
    };
    let source = |libc: &str, version: &str, parens: bool| {
        let selection = format!(r#"{{ version = "{version}"; }}"#);
        let arguments = if parens {
            format!("({selection})")
        } else {
            format!(" {selection}")
        };
        format!(
            "{}let selected = packages.nginx{arguments}; outputs {{ config: ConfigText = package_config(selected, {{  }}); }}",
            declaration(libc)
        )
    };
    let initial = source("gnu", "2", false);
    let path = project.join("main.srx");
    std::fs::write(&path, &initial).unwrap();
    let document = uri(&path);
    let mut client = Client::with_options(&project, "utf-16", false, "bundled");
    client.open(&document, &initial);
    let at = |offset: usize| json!({"textDocument":{"uri":document},"position":{"line":0,"character":offset}});
    for (revision, libc, version, parens, expected) in [
        (2, "gnu", "2", false, "New"),
        (3, "musl", "2", false, "Old"),
        (4, "gnu", "1", false, "Old"),
        (5, "gnu", "2", true, "New"),
    ] {
        let text = source(libc, version, parens);
        client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":revision},"contentChanges":[{"text":text}]}));
        let factory = text.find("pkgs.forPlatform").unwrap() + "pkgs.".len();
        let completion = client.request("textDocument/completion", at(factory + 3));
        assert!(
            completion["result"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["label"] == "forPlatform"),
            "{completion}"
        );
        let signature = client.request(
            "textDocument/signatureHelp",
            at(factory + "forPlatform {".len()),
        );
        assert_eq!(
            signature["result"]["activeParameter"], 0,
            "{signature}"
        );
        assert!(
            signature["result"]["signatures"][0]["label"]
                .as_str()
                .unwrap()
                .starts_with("pkgs.forPlatform(selection:"),
            "{signature}"
        );
        let member = text.find("packages.nginx").unwrap() + "packages.".len();
        let completion = client.request("textDocument/completion", at(member + 2));
        assert!(
            completion["result"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["label"] == "nginx" && item["kind"] == 2),
            "{completion}"
        );
        let definition = client.request("textDocument/definition", at(member + 1));
        assert_ne!(
            definition["result"]["uri"], document,
            "{definition}"
        );
        assert_eq!(
            definition["result"]["range"]["start"]["character"],
            library.find("fn nginx").unwrap() + 3,
            "{definition}"
        );
        let signature = client.request(
            "textDocument/signatureHelp",
            at(member + "nginx".len() + 2),
        );
        let signature = &signature["result"];
        assert_eq!(signature["activeParameter"], 0, "{signature}");
        assert_eq!(
            signature["signatures"][0]["parameters"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "{signature}"
        );
        let label = signature["signatures"][0]["label"]
            .as_str()
            .unwrap();
        assert!(
            label.starts_with("packages.nginx(selection:"),
            "{signature}"
        );
        assert!(label.contains(expected), "{signature}");
        let completion = client.request(
            "textDocument/completion",
            at(text.rfind("{  }").unwrap() + 2),
        );
        let labels: Vec<_> = completion["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["label"].as_str().unwrap())
            .collect();
        assert_eq!(
            labels,
            if expected == "New" {
                vec!["listen", "proxyPass"]
            } else {
                vec!["listen"]
            },
            "{completion}"
        );
    }
    for (revision, suffix, method) in [
        (
            6,
            "let selected = packages.ng",
            "textDocument/completion",
        ),
        (
            7,
            "let selected = packages.nginx {",
            "textDocument/signatureHelp",
        ),
    ] {
        let text = format!("{}{suffix}", declaration("musl"));
        client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":revision},"contentChanges":[{"text":text}]}));
        let response = client.request(method, at(text.len()));
        if method.ends_with("completion") {
            assert!(
                response["result"]["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item["label"] == "nginx"),
                "{response}"
            );
        } else {
            assert_eq!(
                response["result"]["activeParameter"], 0,
                "{response}"
            );
        }
    }
    client.stop();
}

#[test]
fn record_call_forms_complete_fields_show_signatures_and_navigate() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("main.srx");
    let prefix = "value I(int); struct Options { port: I = 80; } fn make(options: Options) -> I { options.port } mod api { pub fn make(options: Options) -> I { options.port } } let callback = fn(options: Options) -> I { options.port }; ";
    let initial = format!("{prefix}let answer = make {{  }};");
    std::fs::write(&path, &initial).unwrap();
    let document = uri(&path);
    let mut client = Client::new(temp.path(), "utf-16");
    client.open(&document, &initial);
    for (revision, callee) in [
        "make",
        "api::make",
        "api.make",
        "callback",
    ]
    .into_iter()
    .enumerate()
    {
        let text = format!("{prefix}let answer = {callee} {{  }};");
        client.notify("textDocument/didChange", json!({"textDocument":{"uri":document,"version":revision + 2},"contentChanges":[{"text":text}]}));
        let at = |offset: usize| json!({"textDocument":{"uri":document},"position":{"line":0,"character":offset}});
        let offset = text.rfind("{  }").unwrap() + 2;
        let completion = client.request("textDocument/completion", at(offset));
        assert!(
            completion["result"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["label"] == "port"),
            "{callee}: {completion}"
        );
        let signature = client.request("textDocument/signatureHelp", at(offset));
        assert_eq!(
            signature["result"]["activeParameter"], 0,
            "{callee}: {signature}"
        );
        assert!(
            signature["result"]["signatures"][0]["label"]
                .as_str()
                .unwrap()
                .contains("Options"),
            "{callee}: {signature}"
        );
        let position = text.rfind(callee).unwrap() + callee.len() - 1;
        let definition = client.request("textDocument/definition", at(position));
        assert!(
            !definition["result"].is_null(),
            "{callee}: {definition}"
        );
        assert!(
            definition["result"]["range"]["start"]["character"]
                .as_u64()
                .unwrap()
                < prefix.len() as u64,
            "{callee}: {definition}"
        );
    }
    client.stop();
}
