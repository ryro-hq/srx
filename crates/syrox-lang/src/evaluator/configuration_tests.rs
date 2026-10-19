use super::*;
use crate::{
    checker::{CheckPolicy, check},
    resolver::resolve,
    source::SourceSet,
    syntax::parse_sources,
};

fn program(text: &str) -> Result<CheckedProgram, Vec<crate::diagnostic::Diagnostic>> {
    let mut sources = SourceSet::new();
    sources.add("main.srx", text).unwrap();
    for (name, text) in [
        (
            "std/main.srx",
            "mod std { pub enum Bool { False, True } pub use option::Option; pub use result::Result; pub use list::map; pub use maps::{OrderedMap, MapKey, MapEntry, map_from_entries, map_empty}; pub value ConfigText(str); }",
        ),
        (
            "std/option.srx",
            include_str!("../../../../std/option.srx"),
        ),
        (
            "std/yaml.srx",
            include_str!("../../../../std/yaml.srx"),
        ),
        (
            "std/toml.srx",
            include_str!("../../../../std/toml.srx"),
        ),
        (
            "std/list.srx",
            include_str!("../../../../std/collections/list.srx"),
        ),
        (
            "std/result.srx",
            include_str!("../../../../std/result.srx"),
        ),
        (
            "std/maps.srx",
            include_str!("../../../../std/collections/map.srx"),
        ),
        (
            "std/files.srx",
            include_str!("../../../../std/files.srx"),
        ),
    ] {
        sources.add_standard_library(name, text).unwrap();
    }
    check(
        resolve(parse_sources(&sources)?)?,
        &CheckPolicy::default(),
    )
}
fn run(text: &str) -> RealizedProgram {
    let policy = CheckPolicy::default();
    let checked = program(text).unwrap();
    evaluate(
        &checked,
        &policy,
        &EvaluationEnvironment::new(&policy),
    )
    .unwrap()
}
fn output(result: &RealizedProgram, name: &str) -> String {
    let root = result
        .roots()
        .find(|root| root.name() == name)
        .unwrap();
    let Some(Value::Nominal {
        value: PrimitiveValue::Str(text),
        ..
    }) = root.value()
    else {
        panic!("{:?}", root.diagnostics());
    };
    text.clone()
}

#[test]
fn typed_configuration_roundtrip_defaults_options_and_keys() {
    for format in ["yaml", "toml"] {
        let result = run(&format!(
            r#"
            value Name(str); value Port(int) where 1..=65535;
            struct Nested {{ port: Port = 6443; }}
            struct Config {{ #[key("node-name")] nodeName: Name; nested: Nested;
                labels: [Name]; enabled: std::Bool = true; optional: std::Option<Name> = std::Option::None<Name>(); }}
            outputs {{ text: std::ConfigText = std::{format}::encode(std::{format}::decode<Config>(std::{format}::encode(Config {{
                nodeName = "node\\path\n\"quoted\""; nested = {{}}; labels = ["yes", "a:b", "é"]; }}))); }}
        "#
        ));
        let text = output(&result, "text");
        assert!(text.contains("node-name"), "{text}");
        assert!(text.contains("6443"), "{text}");
        assert!(text.contains("true"), "{text}");
    }
}

#[test]
fn immutable_documents_preserve_bytes_comments_unknown_fields_and_partial_defaults() {
    for (format, original, changed) in [
        (
            "yaml",
            "# header\nnode-name: old # keep\nport: 1234\nunknown: preserve\n",
            "node-name: \"new\" # keep",
        ),
        (
            "toml",
            "# header\nnode-name = 'old' # keep\nport = 1234\nunknown = 'preserve'\n",
            "node-name = \"new\" # keep",
        ),
    ] {
        let literal = serde_json::to_string(original).unwrap();
        let result = run(&format!(
            r#"
            value Port(int); struct Config {{ #[key("node-name")] nodeName: std::ConfigText; port: Port = 6443; }}
            fn texts() -> [std::ConfigText] {{
                let original = std::{format}::document<Config>({literal});
                let updated = std::{format}::patch(original, {{ nodeName = "new"; }});
                [std::{format}::render(original), std::{format}::render(updated)]
            }}
            outputs {{ result: [std::ConfigText] = texts(); }}
        "#
        ));
        let root = result.roots().next().unwrap();
        let Some(Value::List {
            items,
            ..
        }) = root.value()
        else {
            panic!("{:?}", root.diagnostics());
        };
        assert!(
            matches!(&items[0], Value::Nominal { value: PrimitiveValue::Str(text), .. } if text == original)
        );
        let Value::Nominal {
            value: PrimitiveValue::Str(updated),
            ..
        } = &items[1]
        else {
            panic!();
        };
        assert!(updated.contains(changed), "{updated}");
        assert!(updated.contains("1234"), "{updated}");
        assert!(updated.contains("preserve"), "{updated}");
    }
}

#[test]
fn strict_decode_and_invalid_patch_diagnostics() {
    for (format, text) in [
        ("yaml", "name: a\nextra: 1\n"),
        ("toml", "name = 'a'\nextra = 1\n"),
    ] {
        let result = run(&format!(
            "struct C {{ name: std::ConfigText; }} outputs {{ bad: C = std::{format}::decode<C>({}); }}",
            serde_json::to_string(text).unwrap()
        ));
        assert!(!result.is_success());
        assert!(
            result
                .diagnostics()
                .any(|d| d.message.contains("$.extra"))
        );
        for changes in ["{ typo = 1; }", "{ name = 1; }"] {
            assert!(program(&format!("struct C {{ name: std::ConfigText; }} outputs {{ bad: std::{format}::Document<C> = std::{format}::patch(std::{format}::document<C>({}), {changes}); }}", serde_json::to_string(text).unwrap())).is_err());
        }
    }
}

#[test]
fn maps_aliases_and_option_values_roundtrip() {
    for format in ["yaml", "toml"] {
        let result = run(&format!(
            r#"
            value Name(str); type Label = Name;
            struct C {{ nested: std::OrderedMap<Label>; selected: std::Option<Name>; }}
            outputs {{ text: std::ConfigText = std::{format}::encode(std::{format}::decode<C>(
                std::{format}::encode(C {{
                    nested = match std::map_from_entries([std::MapEntry::Entry(std::MapKey("a.b"), Name("yes"))]) {{
                        Ok(map) => map, Err(_) => std::map_empty<Name>(),
                    }};
                    selected = std::Option::Some(Name("quoted\nvalue"));
                }})
            )); }}
        "#
        ));
        assert!(output(&result, "text").contains("a.b"));
    }
}

#[test]
fn empty_patch_preserves_bytes_and_none_removes_optional_values() {
    for (format, original) in [
        ("yaml", "name: old # keep\nother: 9\n"),
        ("toml", "name = 'old' # keep\nother = 9\n"),
    ] {
        let result = run(&format!(
            r#"
            value Name(str); struct C {{ name: std::Option<Name> = std::Option::None; }}
            fn unchanged() -> std::ConfigText {{
                std::{format}::render(std::{format}::patch(std::{format}::document<C>({literal}), {{}}))
            }}
            fn clear_config() -> C {{
                std::{format}::value(std::{format}::patch(std::{format}::document<C>({literal}), {{name = std::Option::None;}}))
            }}
            outputs {{ text: std::ConfigText = unchanged(); cleared: C = clear_config(); }}
        "#,
            literal = serde_json::to_string(original).unwrap()
        ));
        assert_eq!(output(&result, "text"), original);
        let Some(Value::Struct {
            fields,
            ..
        }) = result
            .roots()
            .find(|r| r.name() == "cleared")
            .unwrap()
            .value()
        else {
            panic!("{:?}", result.diagnostics().collect::<Vec<_>>());
        };
        assert!(matches!(
            &fields[0].1,
            Value::Variant {
                index: 0,
                ..
            }
        ));
    }
}

#[test]
fn malformed_documents_type_errors_and_resources_fail_with_field_context() {
    for (format, text) in [
        ("yaml", "name: [unterminated"),
        ("toml", "name = [unterminated"),
        ("yaml", "name: 12\n"),
        ("toml", "name = 12\n"),
    ] {
        let result = run(&format!(
            "value Name(str); struct C {{ name: Name; }} outputs {{ bad: C = std::{format}::decode<C>({}); }}",
            serde_json::to_string(text).unwrap()
        ));
        assert!(!result.is_success(), "{format}: {text}");
    }
    let result = run(
        r#"resource Secret(str); outputs { bad: std::ConfigText = std::yaml::encode(Secret("private")); }"#,
    );
    assert!(!result.is_success());
    let result = run(
        r#"value Name(str); fn f() -> Name { "a" } outputs { bad: std::ConfigText = std::yaml::encode(f); }"#,
    );
    assert!(!result.is_success());
}

#[test]
fn documents_preserve_unknown_aliases_tags_and_datetimes() {
    for (format, text) in [
        ("yaml", "name: ok\nunknown: !custom something\n"),
        (
            "toml",
            "name = 'ok'\nunknown = 2026-10-19T12:00:00Z\n",
        ),
    ] {
        let result = run(&format!(
            "value Name(str); struct C {{ name: Name; }} outputs {{ text: std::ConfigText = std::{format}::render(std::{format}::document<C>({})); }}",
            serde_json::to_string(text).unwrap()
        ));
        assert_eq!(output(&result, "text"), text);
    }
}

#[test]
fn unsupported_schemas_are_rejected_even_for_empty_lists_and_defaults() {
    let result = run(r#"resource R(str); struct C { empty: [R] = []; }
        outputs { bad: C = std::yaml::decode<C>("{}"); }"#);
    assert!(!result.is_success());
    let result = run(r#"resource R(str); struct C { empty: [R] = []; }
        outputs { bad: std::ConfigText = std::yaml::encode(C {}); }"#);
    assert!(!result.is_success());
}

#[test]
fn explicit_patch_arguments_and_grouped_partial_records_are_checked() {
    let result = run(
        r#"value Name(str); value Port(int); struct C { name: Name; port: Port; }
        outputs { text: std::ConfigText = std::toml::render(std::toml::patch<C>(
            std::toml::document<C>("name = 'old'\nport = 1234\n"), ({ name = "new"; })
        )); }"#,
    );
    assert!(output(&result, "text").contains("1234"));
}
