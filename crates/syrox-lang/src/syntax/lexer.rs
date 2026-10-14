use crate::{
    MAX_DIAGNOSTICS, MAX_TOKENS, diagnostic::Diagnostic, source::Source, source::SourceId,
    source::Span,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Whitespace,
    Comment,
    Invalid,
    /// Unscanned suffix after a lexer budget was exhausted.
    Unparsed,
    Ident,
    String,
    Integer,
    Keyword(Keyword),
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    LeftParen,
    RightParen,
    LeftAngle,
    RightAngle,
    Colon,
    ColonColon,
    Comma,
    Dot,
    DotDot,
    DotDotEqual,
    Equal,
    FatArrow,
    Arrow,
    PlusPlus,
    Semicolon,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyword {
    Compare,
    Enum,
    Erase,
    Fn,
    Fold,
    SortByKeys,
    In,
    Inputs,
    Int,
    Let,
    Match,
    Mod,
    ModuleExports,
    Memoize,
    Opaque,
    Once,
    Outputs,
    Publish,
    Owner,
    Pub,
    Resource,
    SelfValue,
    Str,
    Struct,
    Type,
    Use,
    Value,
    Where,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl TokenKind {
    pub const fn is_trivia(self) -> bool {
        matches!(self, Self::Whitespace | Self::Comment)
    }
}

pub(crate) struct Lexed {
    pub tokens: Vec<Token>,
    pub diagnostics: Vec<Diagnostic>,
}

pub(crate) fn lex(source_id: SourceId, source: &Source) -> Lexed {
    lex_cancellable(source_id, source, None).expect("uncancelled lexer")
}

pub(crate) fn lex_cancellable(
    source_id: SourceId,
    source: &Source,
    cancellation: Option<&crate::analysis::AnalysisCancellation>,
) -> Result<Lexed, crate::analysis::AnalysisCancelled> {
    let mut next_check = 0;
    let result = lex_with_checkpoint(source_id, source, |at| {
        if at >= next_check {
            if let Some(cancel) = cancellation {
                cancel.check()?;
            }
            next_check = at + 1024;
        }
        Ok::<_, crate::analysis::AnalysisCancelled>(())
    })?;
    if let Some(cancel) = cancellation {
        cancel.check()?;
    }
    Ok(result)
}

// One scanner preserves ordered token recognition, recovery and byte offsets.
fn lex_with_checkpoint(
    source_id: SourceId,
    source: &Source,
    mut checkpoint: impl FnMut(usize) -> Result<(), crate::analysis::AnalysisCancelled>,
) -> Result<Lexed, crate::analysis::AnalysisCancelled> {
    let bytes = source.text().as_bytes();
    let mut tokens = Vec::new();
    let mut errors = Vec::new();
    let mut at = 0;

    while at < bytes.len() {
        checkpoint(at)?;
        let start = at;
        if tokens.len() == MAX_TOKENS {
            push_error(
                &mut errors,
                Diagnostic::error(
                    format!("source exceeds the {MAX_TOKENS}-token limit"),
                    make_span(source_id, start, start, bytes.len()),
                ),
            );
            break;
        }
        let kind = match bytes[at] {
            b' ' | b'\t' | b'\r' | b'\n' => {
                while bytes
                    .get(at)
                    .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                {
                    checkpoint(at)?;
                    at += 1;
                }
                TokenKind::Whitespace
            }
            b'/' if bytes.get(at + 1) == Some(&b'/') => {
                at += 2;
                while at < bytes.len() && bytes[at] != b'\n' {
                    checkpoint(at)?;
                    at += 1;
                }
                TokenKind::Comment
            }
            b'"' => {
                let multiline = bytes[at..].starts_with(b"\"\"\"");
                let delimiter = if multiline {
                    3
                } else {
                    1
                };
                at += delimiter;
                let mut closed = false;
                while at < bytes.len() {
                    checkpoint(at)?;
                    match bytes[at] {
                        b'"' => {
                            if !multiline || bytes[at..].starts_with(b"\"\"\"") {
                                at += delimiter;
                                closed = true;
                                break;
                            }
                            at += 1;
                        }
                        b'\\' => {
                            at += 1;
                            if !bytes.get(at).is_some_and(|byte| {
                                matches!(byte, b'"' | b'\\' | b'n' | b'r' | b't' | b'$')
                            }) {
                                push_error(
                                    &mut errors,
                                    Diagnostic::error(
                                        "unsupported string escape",
                                        make_span(
                                            source_id,
                                            start,
                                            at.saturating_add(1),
                                            bytes.len(),
                                        ),
                                    ),
                                );
                                while at < bytes.len() && !matches!(bytes[at], b'"' | b'\r' | b'\n')
                                {
                                    checkpoint(at)?;
                                    at += 1;
                                }
                                continue;
                            }
                            at += 1;
                        }
                        b'\r' | b'\n' if !multiline => {
                            push_error(
                                &mut errors,
                                Diagnostic::error(
                                    "string literal cannot cross a line",
                                    make_span(source_id, start, at, bytes.len()),
                                ),
                            );
                            break;
                        }
                        _ => at += 1,
                    }
                }
                if !closed {
                    push_error(
                        &mut errors,
                        Diagnostic::error(
                            "unterminated string literal",
                            make_span(source_id, start, at, bytes.len()),
                        ),
                    );
                }
                TokenKind::String
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                at += 1;
                while bytes
                    .get(at)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    checkpoint(at)?;
                    at += 1;
                }
                keyword(&source.text()[start..at]).map_or(TokenKind::Ident, TokenKind::Keyword)
            }
            byte if byte.is_ascii_digit() => {
                at += 1;
                while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                    checkpoint(at)?;
                    at += 1;
                }
                TokenKind::Integer
            }
            b'{' => single(&mut at, TokenKind::LeftBrace),
            b'}' => single(&mut at, TokenKind::RightBrace),
            b'[' => single(&mut at, TokenKind::LeftBracket),
            b']' => single(&mut at, TokenKind::RightBracket),
            b'(' => single(&mut at, TokenKind::LeftParen),
            b')' => single(&mut at, TokenKind::RightParen),
            b'<' => single(&mut at, TokenKind::LeftAngle),
            b'>' => single(&mut at, TokenKind::RightAngle),
            b':' if bytes.get(at + 1) == Some(&b':') => double(&mut at, TokenKind::ColonColon),
            b':' => single(&mut at, TokenKind::Colon),
            b',' => single(&mut at, TokenKind::Comma),
            b'.' if bytes.get(at + 1) == Some(&b'.') => {
                at += 2;
                if bytes.get(at) == Some(&b'=') {
                    at += 1;
                    TokenKind::DotDotEqual
                } else {
                    TokenKind::DotDot
                }
            }
            b'.' => single(&mut at, TokenKind::Dot),
            b'=' if bytes.get(at + 1) == Some(&b'>') => double(&mut at, TokenKind::FatArrow),
            b'=' => single(&mut at, TokenKind::Equal),
            b'-' if bytes.get(at + 1) == Some(&b'>') => double(&mut at, TokenKind::Arrow),
            b'+' if bytes.get(at + 1) == Some(&b'+') => double(&mut at, TokenKind::PlusPlus),
            b';' => single(&mut at, TokenKind::Semicolon),
            _ => {
                at += source.text()[at..]
                    .chars()
                    .next()
                    .map_or(1, char::len_utf8);
                push_error(
                    &mut errors,
                    Diagnostic::error(
                        "unexpected character",
                        make_span(source_id, start, at, bytes.len()),
                    ),
                );
                TokenKind::Invalid
            }
        };
        tokens.push(Token {
            kind,
            span: make_span(source_id, start, at, bytes.len()),
        });
        if errors.len() == MAX_DIAGNOSTICS {
            break;
        }
    }

    if at < bytes.len() {
        tokens.push(Token {
            kind: TokenKind::Unparsed,
            span: make_span(source_id, at, bytes.len(), bytes.len()),
        });
    }
    Ok(Lexed {
        tokens,
        diagnostics: errors,
    })
}

fn single(at: &mut usize, kind: TokenKind) -> TokenKind {
    *at += 1;
    kind
}

fn double(at: &mut usize, kind: TokenKind) -> TokenKind {
    *at += 2;
    kind
}

fn push_error(errors: &mut Vec<Diagnostic>, error: Diagnostic) {
    if errors.len() < MAX_DIAGNOSTICS {
        errors.push(error.in_phase(crate::diagnostic::DiagnosticCode::Lexical));
    }
}

fn keyword(word: &str) -> Option<Keyword> {
    Some(match word {
        "enum" => Keyword::Enum,
        "erase" => Keyword::Erase,
        "fn" => Keyword::Fn,
        "fold" => Keyword::Fold,
        "sort_by_keys" => Keyword::SortByKeys,
        "compare" => Keyword::Compare,
        "module_exports" => Keyword::ModuleExports,
        "memoize" => Keyword::Memoize,
        "in" => Keyword::In,
        "inputs" => Keyword::Inputs,
        "int" => Keyword::Int,
        "let" => Keyword::Let,
        "match" => Keyword::Match,
        "mod" => Keyword::Mod,
        "opaque" => Keyword::Opaque,
        "once" => Keyword::Once,
        "outputs" => Keyword::Outputs,
        "publish" => Keyword::Publish,
        "owner" => Keyword::Owner,
        "pub" => Keyword::Pub,
        "resource" => Keyword::Resource,
        "self" => Keyword::SelfValue,
        "str" => Keyword::Str,
        "struct" => Keyword::Struct,
        "type" => Keyword::Type,
        "use" => Keyword::Use,
        "value" => Keyword::Value,
        "where" => Keyword::Where,
        _ => return None,
    })
}

pub(crate) fn is_keyword(word: &str) -> bool {
    keyword(word).is_some()
}

fn make_span(source_id: SourceId, start: usize, end: usize, limit: usize) -> Span {
    Span::new(
        source_id,
        u32::try_from(start.min(limit)).unwrap_or(u32::MAX),
        u32::try_from(end.min(limit)).unwrap_or(u32::MAX),
    )
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn cancellation_interrupts_inside_long_tokens_without_publishing_partial_lexing() {
        for text in [
            " ".repeat(8192),
            format!("//{}", "c".repeat(8192)),
            format!("\"{}\"", "s".repeat(8192)),
            "name".repeat(2048),
            "9".repeat(8192),
            format!("\"\\q{}\"", "x".repeat(8192)),
        ] {
            let source = Source::new("buffer.srx", text).unwrap();
            let mut observed = 0;
            let cancelled = lex_with_checkpoint(SourceId::SINGLE, &source, |offset| {
                observed = offset;
                if offset >= 2048 {
                    Err(crate::analysis::AnalysisCancelled)
                } else {
                    Ok(())
                }
            });
            assert!(cancelled.is_err());
            assert_eq!(observed, 2048);
            let fresh = lex_cancellable(
                SourceId::SINGLE,
                &source,
                Some(&crate::analysis::AnalysisCancellation::default()),
            )
            .unwrap();
            let strict = lex(SourceId::SINGLE, &source);
            assert_eq!(fresh.tokens, strict.tokens);
            assert_eq!(fresh.diagnostics, strict.diagnostics);
        }
    }
}
