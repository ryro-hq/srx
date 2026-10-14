use super::{Diagnostic, Item, ParsedProgram, Parser, Source, SourceId, SyntaxTree, lex};

/// Complete syntactic header, retained even if the body is malformed. Types are
/// unresolved; visibility and module membership still require semantic checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionSignature {
    /// Lexical namespace relative to this file's project-assigned module.
    pub module: std::sync::Arc<[String]>,
    pub public: bool,
    pub name: crate::syntax::Ident,
    pub type_parameters: Vec<crate::syntax::TypeParameter>,
    pub parameters: Vec<crate::syntax::Parameter>,
    pub result: Option<crate::syntax::Type>,
    pub span: crate::source::Span,
}

pub use crate::syntax::lexer::{Keyword, Token as SyntaxToken, TokenKind as SyntaxTokenKind};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MAX_DIAGNOSTICS, MAX_TOKENS, syntax::ItemKind, syntax::SyntaxElement, syntax::SyntaxKind,
        syntax::analyze,
    };

    fn round_trip(parsed: &ParsedFile) -> String {
        let mut text = String::new();
        let mut end = 0;
        for token in parsed.tokens() {
            assert_eq!(token.span.start(), end);
            assert!(token.span.end() > token.span.start());
            text.push_str(&parsed.source().text()[token.span.range()]);
            end = token.span.end();
        }
        assert_eq!(end as usize, parsed.source().text().len());
        let mut from_tree = String::new();
        let mut stack = vec![SyntaxElement::Node(
            parsed.syntax().root(),
        )];
        let mut tree_end = 0;
        while let Some(element) = stack.pop() {
            match element {
                SyntaxElement::Node(node) => {
                    if let Some(parent) = node.parent() {
                        assert!(parent.span().start() <= node.span().start());
                        assert!(node.span().end() <= parent.span().end());
                    }
                    let mut previous = node.span().start();
                    for child in node.children() {
                        let span = match child {
                            SyntaxElement::Node(child) => child.span(),
                            SyntaxElement::Token(token) => token.span,
                        };
                        assert!(
                            span.start() >= previous,
                            "overlapping children in {node:?}"
                        );
                        assert!(span.end() <= node.span().end());
                        previous = span.end();
                    }
                    stack.extend(node.children().rev());
                }
                SyntaxElement::Token(token) => {
                    assert_eq!(token.span.start(), tree_end);
                    tree_end = token.span.end();
                    from_tree.push_str(&parsed.source().text()[token.span.range()]);
                }
            }
        }
        assert_eq!(text, from_tree);
        text
    }

    #[test]
    fn statement_recovery_is_lossless_and_preserves_siblings_after_bad_delimiters() {
        for broken in [
            "let bad = ;",
            "let bad = call(;",
            "let bad: [I = ;",
            "unknown.;",
            "let bad = I(1)",
        ] {
            let text =
                format!("fn first() {{ {broken} let later = I(2); later }} fn sibling() {{}}");
            let parsed = parse_file(&Source::new("buffer.srx", text.clone()).unwrap());
            assert_eq!(round_trip(&parsed), text);
            let ItemKind::Function(function) = &parsed.recovered_program().items[0].kind else {
                panic!("function");
            };
            assert!(function.body.incomplete);
            assert!(function.body.statements.iter().any(|statement|matches!(&statement.kind,crate::syntax::StatementKind::Let {name,..} if name.text == "later")),"{text}");
            assert_eq!(parsed.function_signatures().count(), 2, "{text}");
            assert!(parsed.into_program().is_err());
        }
        let text = "fn first() { let bad = ; let later = I(2); fn sibling() {}";
        let parsed = parse_file(&Source::new("buffer.srx", text).unwrap());
        assert_eq!(round_trip(&parsed), text);
        assert_eq!(parsed.function_signatures().count(), 2);
        assert!(parsed.into_program().is_err());
    }

    #[test]
    fn incomplete_expressions_retain_their_field_argument_and_path_contexts() {
        for (text, expected) in [
            (
                "outputs { pkg: P = P { name = ",
                vec![
                    SyntaxKind::MissingExpression,
                    SyntaxKind::PrimaryExpression,
                    SyntaxKind::PostfixExpression,
                    SyntaxKind::Expression,
                    SyntaxKind::FieldValue,
                    SyntaxKind::StructLiteral,
                ],
            ),
            (
                "outputs { pkg: P = make(I(1), ",
                vec![
                    SyntaxKind::MissingExpression,
                    SyntaxKind::PrimaryExpression,
                    SyntaxKind::PostfixExpression,
                    SyntaxKind::Expression,
                    SyntaxKind::Argument,
                    SyntaxKind::Arguments,
                ],
            ),
            (
                "fn f() { pkg.",
                vec![
                    SyntaxKind::MissingToken(SyntaxTokenKind::Ident),
                    SyntaxKind::FieldAccess,
                    SyntaxKind::PostfixExpression,
                ],
            ),
            (
                "fn f() { catalog::",
                vec![
                    SyntaxKind::MissingToken(SyntaxTokenKind::Ident),
                    SyntaxKind::Path,
                    SyntaxKind::PrimaryExpression,
                ],
            ),
        ] {
            let parsed = parse_file(&Source::new("buffer.srx", text).unwrap());
            let mut node = parsed
                .syntax()
                .nodes()
                .find(|node| node.kind() == expected[0])
                .unwrap();
            assert_eq!(
                parsed
                    .syntax()
                    .context_at(u32::try_from(text.len()).unwrap())
                    .unwrap()
                    .kind(),
                expected[0]
            );
            assert!(
                parsed
                    .syntax()
                    .context_at(u32::try_from(text.len()).unwrap() + 1)
                    .is_none()
            );
            assert_eq!(node.span().start() as usize, text.len());
            assert_eq!(node.span().start(), node.span().end());
            for kind in expected {
                assert_eq!(node.kind(), kind, "{text}");
                assert!(node.has_errors());
                node = node.parent().unwrap();
            }
            assert_eq!(round_trip(&parsed), text);
            assert!(parsed.into_program().is_err());
        }
    }

    #[test]
    fn malformed_arguments_fields_and_outputs_preserve_following_siblings() {
        let text = "outputs { pkg: P = P { bad = make(, I(1), nested(I(2))); good = I(3); }; other: I = I(4); } value Good(int);";
        let parsed = parse_file(&Source::new("buffer.srx", text).unwrap());
        for (kind, prefix) in [
            (SyntaxKind::Argument, "I(1)"),
            (SyntaxKind::Argument, "nested(I(2))"),
            (SyntaxKind::FieldValue, "good = I(3);"),
            (SyntaxKind::Output, "other: I = I(4);"),
        ] {
            assert!(
                parsed
                    .syntax()
                    .nodes()
                    .any(|node| node.kind() == kind
                        && !node.has_errors()
                        && &text[node.span().range()] == prefix),
                "missing recovered {prefix}"
            );
        }
        assert!(
            parsed.recovered_items().any(
                |item| matches!(&item.kind, ItemKind::Value(value) if value.name.text == "Good")
            )
        );
        assert_eq!(round_trip(&parsed), text);
        assert!(parsed.into_program().is_err());
    }

    #[test]
    fn cursor_queries_select_missing_syntax_before_the_following_delimiter() {
        let text = "outputs { pkg: P = P { bad = ; good = I(3); }; }";
        let parsed = parse_file(&Source::new("buffer.srx", text).unwrap());
        let offset = u32::try_from(text.find(';').unwrap()).unwrap();
        assert_eq!(
            parsed.syntax().context_at(offset).unwrap().kind(),
            SyntaxKind::MissingExpression
        );
        let offset = u32::try_from(text.find("good").unwrap()).unwrap();
        assert_eq!(
            parsed.syntax().context_at(offset).unwrap().kind(),
            SyntaxKind::FieldValue
        );
        assert_eq!(
            parsed.syntax().context_at(0).unwrap().kind(),
            SyntaxKind::Declaration
        );
    }

    #[test]
    fn missing_field_separators_do_not_consume_the_next_field() {
        for (text, kind, next) in [
            (
                "struct S { bad: ; good: I; }",
                SyntaxKind::Field,
                "good: I;",
            ),
            (
                "struct S { bad: I good: I; }",
                SyntaxKind::Field,
                "good: I;",
            ),
            (
                "outputs { bad: I = I(1) good: I = I(2); }",
                SyntaxKind::Output,
                "good: I = I(2);",
            ),
            (
                "fn f() { S { bad = I(1) good = I(2); } }",
                SyntaxKind::FieldValue,
                "good = I(2);",
            ),
        ] {
            let parsed = parse_file(&Source::new("buffer.srx", text).unwrap());
            assert!(
                parsed
                    .syntax()
                    .nodes()
                    .any(|node| node.kind() == kind
                        && !node.has_errors()
                        && &text[node.span().range()] == next),
                "{text}"
            );
            assert_eq!(round_trip(&parsed), text);
            assert!(parsed.into_program().is_err());
        }
    }

    #[test]
    fn editing_prefixes_and_delimiters_always_produces_a_lossless_bounded_tree() {
        let text = "// é 😀\nmod recipes { pub struct P { name: S; } pub fn make(x: I) -> P { let f = fn(n: I) -> I { n }; P { name = S(\"hi\"); } } outputs { selected: P = make(f(I(1)), [I(2), I(3)]); } }";
        let mut edits: Vec<String> = text
            .char_indices()
            .map(|(offset, _)| text[..offset].to_owned())
            .collect();
        for (offset, character) in text.char_indices() {
            if "{}()[];,:=".contains(character) {
                edits.push(format!(
                    "{}{}",
                    &text[..offset],
                    &text[offset + 1..]
                ));
                edits.push(format!(
                    "{}@{}",
                    &text[..offset],
                    &text[offset + 1..]
                ));
            }
        }
        for text in edits {
            let parsed = parse_file(&Source::new("buffer.srx", text.as_str()).unwrap());
            assert_eq!(round_trip(&parsed), text);
            assert!(parsed.syntax().nodes().len() <= 16 * (parsed.tokens().len() + 1));
            assert!(parsed.diagnostics().len() <= MAX_DIAGNOSTICS);
            assert_eq!(
                parsed.syntax().root().has_errors(),
                !parsed.diagnostics().is_empty(),
                "{text}"
            );
        }
    }

    #[test]
    fn function_return_type_recursion_obeys_the_syntax_budget() {
        let text = format!("type Deep = {}I;", "fn() -> ".repeat(2000));
        let parsed = parse_file(&Source::new("buffer.srx", text.as_str()).unwrap());
        assert!(
            parsed
                .diagnostics()
                .iter()
                .any(|error| error.message.contains("syntax nesting"))
        );
        assert_eq!(round_trip(&parsed), text);
        assert!(parsed.into_program().is_err());
    }

    #[test]
    fn editor_tokens_are_lossless_for_trivia_unicode_and_invalid_text() {
        for text in [
            "// comentário 😀\r\nvalue I(int);\n",
            "value S(str); outputs { text: S = \"é 😀\"; } // fim",
            "@ 🦀 value I(int);",
            "value S(str); outputs { text: S = \"unterminated\n",
            "\t  \r\n",
            "",
        ] {
            let source = Source::new("buffer.srx", text).unwrap();
            let parsed = parse_file(&source);
            assert_eq!(round_trip(&parsed), text);
            assert_eq!(parsed.clone().into_program(), analyze(&source));
        }
    }

    #[test]
    fn complete_declarations_survive_a_broken_neighbor_but_strict_admission_fails() {
        let source = Source::new(
            "buffer.srx",
            "value I(int); inputs { broken } @ fn identity(item: I) -> I { item }",
        )
        .unwrap();
        let parsed = parse_file(&source);
        assert!(parsed.diagnostics().len() >= 2);
        assert!(
            parsed
                .recovered_items()
                .any(|item| matches!(&item.kind, ItemKind::Value(value) if value.name.text == "I"))
        );
        assert!(parsed.recovered_items().any(|item| matches!(&item.kind, ItemKind::Function(function) if function.name.text == "identity")));
        assert_eq!(round_trip(&parsed), source.text());
        assert!(parsed.into_program().is_err());
    }

    #[test]
    fn truncated_declarations_are_never_silently_accepted() {
        for text in [
            "pub",
            "fn",
            "fn f(",
            "fn f(x:",
            "fn f() ->",
            "fn f() { let x =",
            "outputs { result:",
            "outputs { result: I =",
            "opaque",
            "value",
            "type",
            "mod",
            "enum E {",
            "struct S { field:",
        ] {
            let source = Source::new("buffer.srx", text).unwrap();
            let parsed = parse_file(&source);
            assert!(!parsed.diagnostics().is_empty(), "{text}");
            assert_eq!(round_trip(&parsed), text);
            assert!(parsed.into_program().is_err(), "{text}");
        }
    }

    #[test]
    fn exhausted_lexing_retains_the_unparsed_suffix_and_cannot_admit_a_prefix() {
        for text in [
            "@".repeat(MAX_DIAGNOSTICS + 10),
            ";".repeat(MAX_TOKENS + 10),
        ] {
            let source = Source::new("buffer.srx", text).unwrap();
            let parsed = parse_file(&source);
            assert!(parsed.tokens().len() <= MAX_TOKENS + 1);
            assert!(parsed.diagnostics().len() <= MAX_DIAGNOSTICS);
            assert!(
                parsed
                    .tokens()
                    .any(|token| token.kind == SyntaxTokenKind::Unparsed)
            );
            assert_eq!(round_trip(&parsed), source.text());
            assert!(parsed.into_program().is_err());
        }
    }
}

/// One file's lossless token stream and recovered declarations.
/// Recovered items are editor data; only `into_program` admits a valid program.
/// Incomplete grammar contexts and missing syntax are retained in `syntax`.
#[derive(Clone, Debug)]
pub struct ParsedFile {
    source: Source,
    syntax: SyntaxTree,
    program: ParsedProgram,
    diagnostics: Vec<Diagnostic>,
    signatures: Vec<FunctionSignature>,
    pub(crate) incomplete_bodies: Vec<crate::source::Span>,
}

impl ParsedFile {
    pub(crate) fn recovered_program(&self) -> &ParsedProgram {
        &self.program
    }
    pub const fn source(&self) -> &Source {
        &self.source
    }

    pub fn tokens(&self) -> impl ExactSizeIterator<Item = &SyntaxToken> {
        self.syntax.tokens()
    }

    pub const fn syntax(&self) -> &SyntaxTree {
        &self.syntax
    }

    pub fn recovered_items(&self) -> impl ExactSizeIterator<Item = &Item> {
        self.program.items.iter()
    }

    /// Name spans of functions whose recovered AST has a placeholder empty
    /// body. Such bodies are unavailable, not successfully parsed empty blocks.
    pub fn incomplete_function_bodies(
        &self,
    ) -> impl ExactSizeIterator<Item = crate::source::Span> + '_ {
        self.incomplete_bodies.iter().copied()
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn function_signatures(&self) -> impl ExactSizeIterator<Item = &FunctionSignature> {
        self.signatures.iter()
    }

    pub fn into_program(self) -> Result<ParsedProgram, Vec<Diagnostic>> {
        if self.diagnostics.is_empty() {
            Ok(self.program)
        } else {
            Err(self.diagnostics)
        }
    }
}

/// Parse an editor buffer without losing valid declarations or original tokens
/// when another declaration is malformed. Uses the same grammar as `analyze`.
pub fn parse_file(source: &Source) -> ParsedFile {
    parse_file_in(SourceId::SINGLE, source)
}

pub(crate) fn parse_file_in(source_id: SourceId, source: &Source) -> ParsedFile {
    parse_file_cancellable(source_id, source, None).expect("uncancelled parse")
}

pub(crate) fn parse_file_cancellable(
    source_id: SourceId,
    source: &Source,
    cancellation: Option<&crate::analysis::AnalysisCancellation>,
) -> Result<ParsedFile, crate::analysis::AnalysisCancelled> {
    if let Some(cancel) = cancellation {
        cancel.check()?;
    }
    let lexed = match cancellation {
        Some(cancel) => crate::syntax::lexer::lex_cancellable(source_id, source, Some(cancel))?,
        None => lex(source_id, source),
    };
    let significant: Vec<_> = lexed
        .tokens
        .iter()
        .copied()
        .filter(|token| !token.kind.is_trivia())
        .collect();
    if let Some(cancel) = cancellation {
        cancel.check()?;
    }
    let mut parser = Parser::new(source_id, source, &significant);
    parser.cancellation = cancellation;
    let parsed = parser.parse();
    if let Some(cancel) = cancellation {
        cancel.check()?;
    }
    let mut diagnostics = lexed.diagnostics;
    diagnostics.extend(
        parsed
            .diagnostics
            .into_iter()
            .take(crate::MAX_DIAGNOSTICS.saturating_sub(diagnostics.len())),
    );
    Ok(ParsedFile {
        source: source.clone(),
        syntax: SyntaxTree::build(
            source_id,
            u32::try_from(source.text().len()).expect("source size is bounded"),
            lexed.tokens,
            parsed.events,
            cancellation,
        )?,
        program: parsed.program,
        diagnostics,
        signatures: parsed.signatures,
        incomplete_bodies: parsed.incomplete_bodies,
    })
}
