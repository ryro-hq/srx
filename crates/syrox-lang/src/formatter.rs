//! Formata `.srx` preservando os tokens, comentários e strings.
//!
//! A sintaxe precisa estar completa antes de emitir texto. Depois da formatação,
//! os tokens são conferidos outra vez. Resolver imports, avaliar receitas e
//! atualizar locks ficam fora desta operação.

use crate::syntax::lexer::{Token, TokenKind};
use crate::{
    analysis::AnalysisCancellation, analysis::AnalysisCancelled, diagnostic::Diagnostic,
    source::Source, source::SourceId,
};

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("cannot format a source with syntax errors")]
    Syntax(Vec<Diagnostic>),
    #[error("formatted source exceeds the source or token budget")]
    OutputLimit,
    #[error("formatting would change source tokens")]
    TokenMismatch,
    #[error(transparent)]
    Cancelled(#[from] AnalysisCancelled),
}

/// Format one syntactically complete source using four-space indentation.
/// Comments and strings retain their exact bytes. Invalid/incomplete sources
/// produce diagnostics, never a partial edit. No project evaluation is needed.
pub fn format_source(source: &Source) -> Result<String, FormatError> {
    format(source, None)
}

/// The same formatter with cooperative cancellation for editor requests.
pub fn format_source_cancellable(
    source: &Source,
    cancellation: &AnalysisCancellation,
) -> Result<String, FormatError> {
    format(source, Some(cancellation))
}

fn format(
    source: &Source,
    cancellation: Option<&AnalysisCancellation>,
) -> Result<String, FormatError> {
    let parsed =
        crate::syntax::parser::parse_file_cancellable(SourceId::SINGLE, source, cancellation)?;
    if !parsed.diagnostics().is_empty() {
        return Err(FormatError::Syntax(parsed.diagnostics().to_vec()));
    }
    let tokens: Vec<_> = parsed
        .tokens()
        .filter(|token| token.kind != TokenKind::Whitespace)
        .copied()
        .collect();
    let mut writer = Writer::default();
    let mut stack = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if index % 64 == 0
            && let Some(cancel) = cancellation
        {
            cancel.check()?;
        }
        let previous = index.checked_sub(1).map(|index| &tokens[index]);
        let next = tokens.get(index + 1);
        if closes(token.kind) {
            stack.pop(); // Parsing already validated matching delimiters.
        }
        if token.kind == TokenKind::Comment {
            // Preserve whether this comment belongs to the preceding line.
            let inline = previous.is_some_and(|previous| {
                !source.text()[previous.span.end() as usize..token.span.start() as usize]
                    .contains('\n')
            });
            writer.newline = !inline;
            writer.token(text(source, token), stack.len(), inline)?;
            writer.newline = true;
            continue;
        }
        if token.kind == TokenKind::RightBrace {
            writer.newline = previous.is_some_and(|p| p.kind != TokenKind::LeftBrace);
        }
        writer.token(
            text(source, token),
            stack.len(),
            previous.is_some_and(|p| space(p.kind, token.kind)),
        )?;
        match token.kind {
            TokenKind::LeftBrace | TokenKind::Semicolon => writer.newline = true,
            TokenKind::Comma => writer.newline = stack.last() == Some(&TokenKind::LeftBrace),
            TokenKind::RightBrace => {
                writer.newline = next.is_some_and(|next| {
                    !matches!(
                        next.kind,
                        TokenKind::Semicolon
                            | TokenKind::Comma
                            | TokenKind::RightParen
                            | TokenKind::RightBracket
                            | TokenKind::Dot
                            | TokenKind::PlusPlus
                    )
                });
            }
            _ => {}
        }
        if opens(token.kind) {
            stack.push(token.kind);
        }
    }
    if !writer.output.is_empty() {
        writer.append("\n")?;
    }
    // Whitespace is the only permitted change. This also catches accidentally
    // merged punctuation and comments swallowing a following token.
    let formatted =
        Source::new(source.name(), writer.output.as_str()).map_err(|_| FormatError::OutputLimit)?;
    let checked =
        crate::syntax::lexer::lex_cancellable(SourceId::SINGLE, &formatted, cancellation)?;
    if !checked.diagnostics.is_empty() {
        return Err(FormatError::OutputLimit);
    }
    let mut after = checked
        .tokens
        .iter()
        .filter(|t| t.kind != TokenKind::Whitespace);
    for (index, before) in tokens.iter().enumerate() {
        if index % 64 == 0
            && let Some(cancel) = cancellation
        {
            cancel.check()?;
        }
        let Some(after) = after.next() else {
            return Err(FormatError::TokenMismatch);
        };
        if before.kind != after.kind || text(source, before) != text(&formatted, after) {
            return Err(FormatError::TokenMismatch);
        }
    }
    if after.next().is_some() {
        return Err(FormatError::TokenMismatch);
    }
    if let Some(cancel) = cancellation {
        cancel.check()?;
    }
    Ok(writer.output)
}

fn text<'a>(source: &'a Source, token: &Token) -> &'a str {
    &source.text()[token.span.range()]
}

fn opens(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::LeftBrace | TokenKind::LeftBracket | TokenKind::LeftParen | TokenKind::LeftAngle
    )
}
fn closes(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::RightBrace
            | TokenKind::RightBracket
            | TokenKind::RightParen
            | TokenKind::RightAngle
    )
}
fn space(previous: TokenKind, current: TokenKind) -> bool {
    use TokenKind::{
        Arrow, Colon, ColonColon, Comma, Dot, Equal, FatArrow, Keyword, LeftAngle, LeftBracket,
        LeftParen, PlusPlus, RightAngle, RightBrace, RightBracket, RightParen, Semicolon,
    };
    if matches!(
        current,
        RightBrace
            | RightBracket
            | RightParen
            | RightAngle
            | Colon
            | ColonColon
            | Dot
            | Comma
            | Semicolon
            | LeftAngle
            | LeftParen
    ) || matches!(
        previous,
        LeftParen | LeftBracket | LeftAngle | ColonColon | Dot
    ) {
        return false;
    }
    if current == LeftBracket {
        return matches!(
            previous,
            Equal | Colon | Comma | Arrow | FatArrow | PlusPlus | Keyword(_)
        );
    }
    true
}

#[derive(Default)]
struct Writer {
    output: String,
    newline: bool,
}
impl Writer {
    fn append(&mut self, value: &str) -> Result<(), FormatError> {
        if self.output.len().saturating_add(value.len()) > crate::MAX_SOURCE_BYTES {
            return Err(FormatError::OutputLimit);
        }
        self.output.push_str(value);
        Ok(())
    }
    fn token(&mut self, value: &str, depth: usize, space: bool) -> Result<(), FormatError> {
        if self.newline && !self.output.is_empty() {
            self.append("\n")?;
        }
        self.newline = false;
        if self.output.is_empty() || self.output.ends_with('\n') {
            for _ in 0..depth {
                self.append("    ")?;
            }
        } else if space {
            self.append(" ")?;
        }
        self.append(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn formatted(input: &str) -> String {
        format_source(&Source::new("test.srx", input).unwrap()).unwrap()
    }

    #[test]
    fn formats_nested_declarations_and_is_idempotent() {
        let input = "mod demo{struct Pair{left:Number;right:[Text];}fn id<T>(x:T)->T{x} outputs{answer:Number=id(7);}}";
        let result = formatted(input);
        assert!(
            result.contains(
                "    struct Pair {\n        left: Number;\n        right: [Text];\n    }"
            )
        );
        assert!(result.contains("    fn id<T>(x: T) -> T {\n        x\n    }"));
        assert_eq!(formatted(&result), result);
        assert!(crate::syntax::analyze(&Source::new("formatted.srx", result).unwrap()).is_ok());
    }

    #[test]
    fn preserves_comment_and_string_bytes_including_unicode_and_escapes() {
        let input = "// início\r\nfn text()->Text{ // keep  two spaces  \nlet x=\"a\\n\\\"é\\$\";// trailing\n// own line\nx++\" suffix\"}\n";
        let result = formatted(input);
        assert!(result.starts_with("// início\r\n"));
        assert!(result.contains("{ // keep  two spaces  \n"));
        assert!(result.contains("; // trailing\n"));
        assert!(result.contains("    // own line\n"));
        assert!(result.contains("\"a\\n\\\"é\\$\""));
        assert_eq!(formatted(&result), result);
    }

    #[test]
    fn formats_without_resolving_names_or_running_recursive_functions() {
        let input = "fn cycle()->missing::Type{cycle()}";
        assert_eq!(
            formatted(input),
            "fn cycle() -> missing::Type {\n    cycle()\n}\n"
        );
    }

    #[test]
    fn refuses_incomplete_syntax_and_honors_cancellation() {
        let source = Source::new("broken.srx", "fn broken(").unwrap();
        assert!(
            matches!(format_source(&source), Err(FormatError::Syntax(errors)) if !errors.is_empty())
        );
        let cancel = AnalysisCancellation::default();
        cancel.cancel();
        assert!(matches!(
            format_source_cancellable(&source, &cancel),
            Err(FormatError::Cancelled(_))
        ));
        assert_eq!(formatted(" \n\t"), "");
    }

    #[test]
    fn output_growth_is_bounded_before_returning_an_edit() {
        let input = "mod nested{".repeat(64) + &"// comment\n".repeat(5000) + &"}".repeat(64);
        let source = Source::new("indentation-growth.srx", input).unwrap();
        assert!(crate::syntax::analyze(&source).is_ok());
        assert!(matches!(
            format_source(&source),
            Err(FormatError::OutputLimit)
        ));
    }

    #[test]
    fn comments_between_generic_closers_and_collection_items_remain_stable() {
        for input in [
            "fn id<T>(x:A<B<T // inner\n>>)->T{x}",
            "fn f()->T{[T{field=x;}, // tail\nT{field=y;}]}",
            "// comment at EOF",
            "// first\r\n// final\r",
        ] {
            let result = formatted(input);
            assert_eq!(formatted(&result), result, "{input}");
            assert!(crate::syntax::analyze(&Source::new("formatted.srx", result).unwrap()).is_ok());
        }
    }

    #[test]
    fn bundled_standard_library_is_idempotent_and_remains_syntactically_valid() {
        fn visit(directory: &std::path::Path, count: &mut usize) {
            for entry in std::fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    visit(&path, count);
                } else if path.extension().is_some_and(|ext| ext == "srx") {
                    let original = std::fs::read_to_string(&path).unwrap();
                    let source = Source::new(path.to_string_lossy().as_ref(), original).unwrap();
                    let result = format_source(&source)
                        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                    let source = Source::new(source.name(), result.as_str()).unwrap();
                    assert!(
                        crate::syntax::analyze(&source).is_ok(),
                        "{}",
                        path.display()
                    );
                    assert_eq!(
                        format_source(&source).unwrap(),
                        result,
                        "{}",
                        path.display()
                    );
                    *count += 1;
                }
            }
        }
        let mut count = 0;
        visit(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../std"),
            &mut count,
        );
        assert!(count > 0);
    }

    #[test]
    fn independent_publication_declaration_is_canonical_and_idempotent() {
        let result = formatted("pub publish(factories,recipe):std::Recipe;");
        assert_eq!(
            result,
            "pub publish(factories, recipe): std::Recipe;\n"
        );
        assert_eq!(formatted(&result), result);
    }
}
