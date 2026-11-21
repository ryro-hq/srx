use super::*;

use crate::{resolver::resolve, source::SourceSet, syntax::parse_sources};

mod constants;

mod effects;

mod exports;

mod functions;

mod generics;

mod limits;

mod opaque;

mod ownership;

mod policy;

mod traits;

mod typing;

fn resolved(text: &str) -> ResolvedProgram {
    let mut sources = SourceSet::new();
    let prelude = "mod std { pub enum Bool { False, True } }";
    let text = if text.contains(prelude) {
        sources
            .add_standard_library("std.srx", prelude)
            .unwrap();
        text.replace(prelude, "")
    } else {
        text.to_owned()
    };
    sources.add("main.srx", text).unwrap();
    resolve(parse_sources(&sources).unwrap()).unwrap()
}

fn checked(text: &str) -> CheckedProgram {
    check(resolved(text), &CheckPolicy::default()).unwrap()
}

fn messages(text: &str) -> Vec<String> {
    check(resolved(text), &CheckPolicy::default())
        .unwrap_err()
        .into_iter()
        .map(|diagnostic| diagnostic.message)
        .collect()
}
