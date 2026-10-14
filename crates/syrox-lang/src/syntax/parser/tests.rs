use super::*;

#[test]
fn representative_v1_source_builds_a_complete_ast() {
    let source = Source::new(
        "main.srx",
        r#"
                use std::pkg::{Package, Arch,};
                inputs { channel = "stable"; }
                type Name = std::Name;
                opaque struct Request<owner O, T> in [machine, user,] {
                    name: Name = "pkg-${channel.name}";
                    packages: [Package] = [];
                }
                enum Mode { Fast, Safe, }
                value Port(int) where 1..=65535, validate(self);
                resource User(str) in machine where in ["root", "build",];
                fn make(name: Name, packages: [Package],) -> Request<Name> {
                    let all = packages ++ [std::base()];
                    Request<Name> { name = name; packages = all; }
                }
                outputs {
                    request: Request<Name> = erase<Request<Name>>(make("app", []));
                    type PublicRequest = Request<Name>;
                    build: fn(Name, [Package],) -> Request<Name> = tools::build;
                }
            "#,
    )
    .unwrap();
    let program = analyze(&source).unwrap();
    assert_eq!(program.declaration_count(), 9);
    assert!(matches!(
        program.items[3].kind,
        ItemKind::Struct(_)
    ));
    assert!(matches!(
        program.items[8].kind,
        ItemKind::Outputs(_)
    ));
}

#[test]
fn qualified_module_path_is_preserved() {
    let source = Source::new("main.srx", "mod a::b::c { type T = root::T; }").unwrap();
    let program = analyze(&source).unwrap();
    let ItemKind::Module(module) = &program.items[0].kind else {
        panic!("expected module");
    };
    let names: Vec<_> = module
        .path
        .segments
        .iter()
        .map(|name| name.text.as_str())
        .collect();
    assert_eq!(names, ["a", "b", "c"]);
    assert_eq!(module.items.len(), 1);
}

#[test]
fn sources_keep_repeated_qualified_modules_and_delimiters_independent() {
    let mut sources = SourceSet::new();
    let first = sources
        .add(
            "first.srx",
            "mod shared::qualified { type First = Root; }",
        )
        .unwrap();
    let second = sources
        .add(
            "second.srx",
            "mod shared::qualified { type Second = Root; }",
        )
        .unwrap();
    let parsed = parse_sources(&sources).unwrap();

    for source_id in [first, second] {
        let program = parsed.get(source_id).unwrap();
        let ItemKind::Module(module) = &program.items[0].kind else {
            panic!("expected module");
        };
        assert_eq!(program.items[0].span.source_id(), source_id);
        assert_eq!(module.path.span.source_id(), source_id);
        assert_eq!(
            module
                .path
                .segments
                .iter()
                .map(|segment| segment.text.as_str())
                .collect::<Vec<_>>(),
            ["shared", "qualified"]
        );
    }

    let mut split = SourceSet::new();
    let unclosed = split
        .add(
            "unclosed.srx",
            "mod shared::qualified { type First = Root;",
        )
        .unwrap();
    let stray_close = split
        .add(
            "stray-close.srx",
            "} mod shared::qualified { type Second = Root; }",
        )
        .unwrap();
    let errors = parse_sources(&split).unwrap_err();

    assert!(errors.iter().any(|error| {
        error.span.source_id() == unclosed && error.message.contains("expected `}`")
    }));
    assert!(errors.iter().any(|error| {
        error.span.source_id() == stray_close && error.message.contains("expected a declaration")
    }));
    assert!(
        errors
            .windows(2)
            .all(|pair| pair[0].span.source_id() <= pair[1].span.source_id())
    );
}

#[test]
fn parse_sources_caps_diagnostics_across_files_in_source_order() {
    let mut sources = SourceSet::new();
    let first = sources
        .add("first.srx", "? ".repeat(200))
        .unwrap();
    let second = sources
        .add("second.srx", "? ".repeat(200))
        .unwrap();
    sources
        .add("third.srx", "? ".repeat(200))
        .unwrap();

    let errors = parse_sources(&sources).unwrap_err();
    assert_eq!(errors.len(), MAX_DIAGNOSTICS);
    assert_eq!(
        errors
            .iter()
            .filter(|error| error.span.source_id() == first)
            .count(),
        200
    );
    assert_eq!(
        errors
            .iter()
            .filter(|error| error.span.source_id() == second)
            .count(),
        56
    );
    assert!(errors.windows(2).all(|pair| {
        (pair[0].span.source_id(), pair[0].span.start())
            <= (pair[1].span.source_id(), pair[1].span.start())
    }));
}

#[test]
fn invalid_field_syntax_is_rejected_without_a_partial_program() {
    let source = Source::new("broken.srx", "struct Broken { field [int]; }").unwrap();
    let errors = analyze(&source).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("`:`"))
    );
    assert!(
        errors[0]
            .render(&source)
            .contains("broken.srx:1:")
    );
}

#[test]
fn invalid_function_internal_syntax_is_rejected() {
    let source = Source::new("broken.srx", "fn bad() { let x = 1 x }").unwrap();
    let errors = analyze(&source).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("`;`"))
    );
}

#[test]
fn nesting_beyond_limit_is_rejected() {
    let mut text = "fn deep() { ".to_owned();
    text.push_str(&"(".repeat(MAX_DEPTH));
    text.push('1');
    text.push_str(&")".repeat(MAX_DEPTH));
    text.push_str(" }");
    let source = Source::new("deep.srx", text).unwrap();
    let errors = analyze(&source).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("nesting"))
    );
}

#[test]
fn nested_matches_are_covered_by_the_nesting_limit() {
    let mut expression = "x".to_owned();
    for _ in 0..MAX_DEPTH {
        expression = format!("match {expression} {{ _ => x }}");
    }
    let source = Source::new(
        "deep-match.srx",
        format!("fn deep() {{ {expression} }}"),
    )
    .unwrap();
    let errors = analyze(&source).unwrap_err();

    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("nesting"))
    );
}

#[test]
fn long_concat_and_field_chains_are_flat() {
    const CHAIN_LENGTH: usize = 10_000;

    let mut text = "fn chains() { ".to_owned();
    text.push_str(&"x ++ ".repeat(CHAIN_LENGTH));
    text.push_str("x; x");
    text.push_str(&".field".repeat(CHAIN_LENGTH));
    text.push_str(" }");
    let source = Source::new("chains.srx", text).unwrap();
    let program = analyze(&source).unwrap();
    let ItemKind::Function(function) = &program.items[0].kind else {
        panic!("expected function");
    };
    let StatementKind::Expression(concat) = &function.body.statements[0].kind else {
        panic!("expected expression statement");
    };
    let ExpressionKind::Concat(expressions) = &concat.kind else {
        panic!("expected concat expression");
    };
    let ExpressionKind::Field {
        fields,
        ..
    } = &function.body.tail.as_ref().unwrap().kind
    else {
        panic!("expected field expression");
    };

    assert_eq!(expressions.len(), CHAIN_LENGTH + 1);
    assert_eq!(fields.len(), CHAIN_LENGTH);
}

#[test]
fn postfix_calls_and_fields_have_a_bounded_expression_depth() {
    let text = format!(
        "fn nested() {{ f{} }}",
        "().field".repeat(MAX_DEPTH)
    );
    let source = Source::new("nested.srx", text).unwrap();
    assert!(
        analyze(&source)
            .unwrap_err()
            .iter()
            .any(|diagnostic| {
                diagnostic
                    .message
                    .contains("chain exceeds syntax nesting limit")
            })
    );
}

#[test]
fn invalid_empty_and_string_forms_are_rejected() {
    let cases = [
        ("empty generic", "type T = Generic<>;"),
        ("empty struct generic", "fn f() { Generic<> {} }"),
        ("empty refinement", "value V(int) where in [];"),
        (
            "raw carriage return",
            "inputs { value = \"a\rb\"; }",
        ),
        (
            "keyword interpolation",
            "inputs { value = \"${match}\"; }",
        ),
    ];

    for (name, text) in cases {
        let source = Source::new(format!("{name}.srx"), text).unwrap();
        assert!(analyze(&source).is_err(), "{name} was accepted");
    }
}

#[test]
fn failed_item_restores_depth_and_recovery_preserves_consumed_syntax() {
    let source = Source::new("recovery.srx", "inputs { broken } type Good = T;").unwrap();
    let tokens: Vec<_> = lex(SourceId::SINGLE, &source)
        .tokens
        .into_iter()
        .filter(|token| !token.kind.is_trivia())
        .collect();
    let mut parser = Parser::new(SourceId::SINGLE, &source, &tokens);

    assert!(parser.parse_item().is_none());
    assert_eq!(parser.depth, 0);
    assert!(parser.at > 0);

    parser.recover_item(0, false);
    let item = parser
        .parse_item()
        .expect("recovery should reach the type alias");
    assert!(matches!(item.kind, ItemKind::TypeAlias(_)));
    assert_eq!(parser.depth, 0);
}
