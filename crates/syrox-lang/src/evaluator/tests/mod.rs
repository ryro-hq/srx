use std::sync::Arc;

use super::*;

use crate::{
    checker::CanonicalItemIdentity, checker::PrimitiveType, checker::ScopeRule, checker::check,
    resolver::resolve, source::SourceDomainId, source::SourceSet, syntax::parse_sources,
};

mod closures;

mod constants;

mod enums;

mod functions;

mod imports;

mod limits;

mod roots;

mod values;

fn checked(source: &str, policy: &CheckPolicy) -> CheckedProgram {
    let mut sources = SourceSet::new();
    let prelude = "mod std { pub enum Bool { False, True } }";
    let source = if source.contains(prelude) {
        sources
            .add_standard_library("std.srx", prelude)
            .unwrap();
        source.replace(prelude, "")
    } else {
        source.to_owned()
    };
    sources.add("main.srx", source).unwrap();
    check(
        resolve(parse_sources(&sources).unwrap()).unwrap(),
        policy,
    )
    .unwrap()
}

fn run(source: &str, policy: &CheckPolicy) -> RealizedProgram {
    let checked = checked(source, policy);
    evaluate(
        &checked,
        policy,
        &EvaluationEnvironment::new(policy),
    )
    .unwrap()
}
