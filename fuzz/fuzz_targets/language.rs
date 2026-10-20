#![no_main]
use libfuzzer_sys::fuzz_target;
use syrox_lang::{
    checker, formatter, resolver,
    source::{Source, SourceSet},
    syntax,
};
fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(source) = Source::new("fuzz.srx", text) else {
        return;
    };
    let _ = formatter::format_source(&source);
    let mut sources = SourceSet::new();
    if sources.add("main.srx", text).is_err() {
        return;
    }
    if let Ok(parsed) = syntax::parse_sources(&sources)
        && let Ok(resolved) = resolver::resolve(parsed)
    {
        let _ = checker::check(resolved, &checker::CheckPolicy::default());
    }
});
