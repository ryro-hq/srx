#![no_main]
use libfuzzer_sys::fuzz_target;
use syrox_lang::{
    checker::{CheckPolicy, check},
    evaluator::{EvaluationEnvironment, EvaluationLimits, evaluate_with_limits},
    resolver::resolve,
    source::SourceSet,
    syntax::parse_sources,
};
fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let format = if selector % 2 == 0 {
        "yaml"
    } else {
        "toml"
    };
    let literal = serde_json::to_string(text)
        .unwrap()
        .replace('$', "\\$");
    let main = format!(
        "value Name(str); struct Config {{ name: Name = \"default\"; }} outputs {{ parsed: Config = std::{format}::decode<Config>({literal}); edited: std::ConfigText = std::{format}::render(std::{format}::patch(std::{format}::document<Config>({literal}), {{name = \"patched\";}})); }}"
    );
    let mut sources = SourceSet::new();
    if sources.add("main.srx", main.as_str()).is_err() {
        return;
    }
    for (name, text) in [
        (
            "std/main.srx",
            "mod std { pub enum Bool { False, True } pub use option::Option; pub use result::Result; pub use list::map; pub use maps::{OrderedMap, MapKey, MapEntry, map_from_entries, map_empty}; pub value ConfigText(str); }",
        ),
        (
            "std/option.srx",
            include_str!("../../std/option.srx"),
        ),
        (
            "std/result.srx",
            include_str!("../../std/result.srx"),
        ),
        ("std/yaml.srx", include_str!("../../std/yaml.srx")),
        ("std/toml.srx", include_str!("../../std/toml.srx")),
        (
            "std/list.srx",
            include_str!("../../std/collections/list.srx"),
        ),
        (
            "std/maps.srx",
            include_str!("../../std/collections/map.srx"),
        ),
    ] {
        sources.add_standard_library(name, text).unwrap();
    }
    let policy = CheckPolicy::default();
    let parsed = parse_sources(&sources).expect("literal configuration wrapper must parse");
    let resolved = resolve(parsed).expect("configuration prelude must resolve");
    let checked = check(resolved, &policy).expect("literal configuration wrapper must check");
    let limits = EvaluationLimits {
        max_total_steps: 100_000,
        max_steps_per_root: 50_000,
        max_expansion_bytes: 1024 * 1024,
        max_retained_expansion_bytes: 2 * 1024 * 1024,
        ..EvaluationLimits::default()
    };
    let _ = evaluate_with_limits(
        &checked,
        &policy,
        &EvaluationEnvironment::new(&policy),
        limits,
    );
});
