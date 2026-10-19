//! Complete parsing for the language and recovery parsing for the editor.
//!
//! The parser bounds depth, token count and diagnostics. On an error, it retains
//! the incomplete region and finds a point where parsing can resume without
//! losing the spans of declarations it can still read.

use crate::syntax::lexer::{Keyword, Token, TokenKind, is_keyword, lex};
use crate::syntax::{
    Block, Enum, Expression, ExpressionKind, Field, Function, Ident, Input, Inputs, IntegerLiteral,
    Item, ItemKind, Literal, MatchArm, Module, Output, OutputKind, Outputs, Parameter,
    ParsedProgram, ParsedSource, ParsedSources, Path, Pattern, Primitive, PrimitiveDeclaration,
    Refinement, RefinementKind, Statement, StatementKind, StringLiteral, StringPart, Struct,
    StructField, Type, TypeAlias, TypeKind, TypeParameter, Use,
};
use crate::{
    MAX_DEPTH, MAX_DIAGNOSTICS, diagnostic::Diagnostic, diagnostic::DiagnosticCode,
    diagnostic::SyntaxExpectation, source::Source, source::SourceId, source::SourceSet,
    source::Span,
};

mod expressions;
mod items;
mod parsed_file;
mod syntax;
pub(crate) use parsed_file::parse_file_cancellable;
pub(crate) use parsed_file::parse_file_in;

use syntax::Event;
pub use syntax::{SyntaxElement, SyntaxKind, SyntaxNode, SyntaxTree};

pub use parsed_file::{
    FunctionSignature, Keyword as SyntaxKeyword, ParsedFile, SyntaxToken, SyntaxTokenKind,
    parse_file,
};

#[cfg(test)]
mod tests;

pub fn analyze(source: &Source) -> Result<ParsedProgram, Vec<Diagnostic>> {
    parse_source(SourceId::SINGLE, source)
}

pub fn parse_sources(sources: &SourceSet) -> Result<ParsedSources, Vec<Diagnostic>> {
    let mut parsed = Vec::with_capacity(sources.len());
    let mut errors = Vec::new();
    for (source_id, source) in sources.iter() {
        match parse_source(source_id, source) {
            Ok(program) => parsed.push(ParsedSource {
                source_id,
                domain: sources
                    .domain(source_id)
                    .expect("source iteration only yields registered sources"),
                module: sources
                    .module(source_id)
                    .expect("registered module")
                    .to_vec(),
                program,
            }),
            Err(source_errors) => {
                errors.extend(
                    source_errors
                        .into_iter()
                        .take(MAX_DIAGNOSTICS.saturating_sub(errors.len())),
                );
                if errors.len() == MAX_DIAGNOSTICS {
                    break;
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(ParsedSources {
            sources: parsed,
            input_domains: sources
                .input_domains()
                .cloned()
                .unwrap_or_default(),
            project_roots: sources.project_roots().clone(),
        })
    } else {
        errors.sort_by_key(|error| {
            (
                error.span.source_id(),
                error.span.start(),
                error.span.end(),
            )
        });
        Err(errors)
    }
}

fn parse_source(source_id: SourceId, source: &Source) -> Result<ParsedProgram, Vec<Diagnostic>> {
    parse_file_in(source_id, source).into_program()
}

struct Parser<'a> {
    cancellation: Option<&'a crate::analysis::AnalysisCancellation>,
    source_id: SourceId,
    source: &'a Source,
    tokens: &'a [Token],
    at: usize,
    depth: usize,
    errors: Vec<Diagnostic>,
    events: Vec<Event>,
    error_count: usize,
    module: std::sync::Arc<[String]>,
    signatures: Vec<FunctionSignature>,
    incomplete_bodies: Vec<Span>,
}

struct ParseResult {
    program: ParsedProgram,
    diagnostics: Vec<Diagnostic>,
    events: Vec<Event>,
    signatures: Vec<FunctionSignature>,
    incomplete_bodies: Vec<Span>,
}

impl<'a> Parser<'a> {
    fn new(source_id: SourceId, source: &'a Source, tokens: &'a [Token]) -> Self {
        Self {
            cancellation: None,
            source_id,
            source,
            tokens,
            at: 0,
            depth: 0,
            errors: Vec::new(),
            events: Vec::new(),
            error_count: 0,
            module: std::sync::Arc::from([]),
            signatures: Vec::new(),
            incomplete_bodies: Vec::new(),
        }
    }

    fn parse(mut self) -> ParseResult {
        let items = self.parse_items(false);
        ParseResult {
            program: ParsedProgram {
                items,
            },
            diagnostics: self.errors,
            events: self.events,
            signatures: self.signatures,
            incomplete_bodies: self.incomplete_bodies,
        }
    }

    fn syntax<T>(
        &mut self,
        kind: SyntaxKind,
        parse: impl FnOnce(&mut Self) -> Option<T>,
    ) -> Option<T> {
        self.events.push(Event::Start(kind));
        let depth = self.depth;
        let errors = self.error_count;
        let result = parse(self);
        self.depth = depth;
        if result.is_none() && self.error_count == errors {
            self.error(Diagnostic::error(
                "incomplete syntax",
                self.peek()
                    .map_or_else(|| self.eof_span(), |token| token.span),
            ));
        }
        self.events.push(Event::Finish {
            failed: result.is_none() || self.error_count != errors,
        });
        result
    }

    fn missing(&mut self, kind: SyntaxKind) {
        self.events.push(Event::Start(kind));
        self.events.push(Event::Finish {
            failed: true,
        });
    }

    fn parse_path(&mut self, message: &str) -> Option<Path> {
        self.syntax(SyntaxKind::Path, |parser| {
            parser.parse_path_inner(message)
        })
    }

    fn parse_path_inner(&mut self, message: &str) -> Option<Path> {
        let first = self.ident(message)?;
        let start = first.span;
        let mut end = first.span;
        let mut segments = vec![first];
        while self.at(TokenKind::ColonColon)
            && self
                .peek_n(1)
                .is_none_or(|token| token.kind != TokenKind::LeftBrace)
        {
            self.advance();
            let segment = self.ident("expected path segment after `::`")?;
            end = segment.span;
            segments.push(segment);
        }
        Some(Path {
            segments,
            span: start.join(end),
        })
    }

    fn comma_idents(&mut self, close: TokenKind, allow_empty: bool) -> Option<Vec<Ident>> {
        let mut values = Vec::new();
        if self.at(close) {
            if allow_empty {
                return Some(values);
            }
            self.error(Diagnostic::error(
                "expected at least one name",
                self.peek()?.span,
            ));
            return None;
        }
        loop {
            values.push(self.ident("expected name")?);
            if self.consume(TokenKind::Comma).is_none() || self.at(close) {
                break;
            }
        }
        Some(values)
    }

    fn comma_types(&mut self, close: TokenKind, allow_empty: bool) -> Option<Vec<Type>> {
        let mut values = Vec::new();
        if self.at(close) {
            if allow_empty {
                return Some(values);
            }
            self.error(Diagnostic::error(
                "expected at least one type",
                self.peek()?.span,
            ));
            return None;
        }
        loop {
            values.push(self.parse_type()?);
            if self.consume(TokenKind::Comma).is_none() || self.at(close) {
                break;
            }
        }
        Some(values)
    }

    fn comma_expressions(&mut self, close: TokenKind) -> Option<Vec<Expression>> {
        self.syntax(SyntaxKind::Arguments, |parser| {
            parser.comma_expressions_inner(close)
        })
    }

    fn comma_expressions_inner(&mut self, close: TokenKind) -> Option<Vec<Expression>> {
        let mut values = Vec::new();
        let mut valid = true;
        if self.at(close) {
            return Some(values);
        }
        loop {
            if let Some(value) = self.syntax(SyntaxKind::Argument, Self::parse_expression) {
                values.push(value);
            } else {
                valid = false;
                self.recover_entry(TokenKind::Comma, close);
            }
            if self.errors.len() == MAX_DIAGNOSTICS {
                return None;
            }
            if self.consume(TokenKind::Comma).is_none() || self.at(close) {
                break;
            }
        }
        valid.then_some(values)
    }

    fn semicolon_entries<T>(
        &mut self,
        kind: SyntaxKind,
        parse: impl FnMut(&mut Self) -> Option<T>,
    ) -> (Vec<T>, bool) {
        let (values, recovery) = self.recoverable_entries(kind, parse);
        (values, recovery.is_empty())
    }

    fn recoverable_entries<T>(
        &mut self,
        kind: SyntaxKind,
        mut parse: impl FnMut(&mut Self) -> Option<T>,
    ) -> (Vec<T>, Vec<Span>) {
        let mut values = Vec::new();
        let mut recovery = Vec::new();
        while self.peek().is_some() && !self.at(TokenKind::RightBrace) {
            let start = self.at;
            let value = self.syntax(kind, |parser| parse(parser));
            if let Some(value) = value {
                values.push(value);
            } else {
                // A missing semicolon should not consume the following field.
                let next_entry = self.at > start
                    && self.at(TokenKind::Ident)
                    && self.peek_n(1).is_some_and(|token| {
                        matches!(token.kind, TokenKind::Equal | TokenKind::Colon)
                    });
                if !next_entry {
                    self.recover_entry(TokenKind::Semicolon, TokenKind::RightBrace);
                    self.consume(TokenKind::Semicolon);
                }
                let first = self.tokens[start].span;
                let last = self.tokens[self.at.saturating_sub(1).max(start)].span;
                recovery.push(first.join(last));
            }
            if self.at == start || self.errors.len() == MAX_DIAGNOSTICS {
                break;
            }
        }
        (values, recovery)
    }

    fn ident(&mut self, message: &str) -> Option<Ident> {
        let token = if self.at(TokenKind::Keyword(Keyword::Value)) {
            self.advance()?
        } else {
            self.expect(TokenKind::Ident, message)?
        };
        Some(Ident {
            text: self.text(token.span).to_owned(),
            span: token.span,
        })
    }

    fn enter(&mut self, span: Span) -> bool {
        if self.depth == MAX_DEPTH {
            self.error(Diagnostic::error(
                format!("syntax nesting exceeds the limit of {MAX_DEPTH}"),
                span,
            ));
            false
        } else {
            self.depth += 1;
            true
        }
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn recover_item(&mut self, start: usize, nested: bool) {
        let mut depth = 0usize;
        let mut cursor = start;
        while let Some(token) = self.tokens.get(cursor) {
            if self.cancelled() {
                return;
            }
            let reached_failure = cursor >= self.at;
            match token.kind {
                TokenKind::Keyword(
                    Keyword::Pub
                    | Keyword::Mod
                    | Keyword::Use
                    | Keyword::Inputs
                    | Keyword::Outputs
                    | Keyword::Type
                    | Keyword::Struct
                    | Keyword::Opaque
                    | Keyword::Enum
                    | Keyword::Resource
                    | Keyword::Value
                    | Keyword::Fn,
                ) if depth == 0 && cursor > start && reached_failure => break,
                TokenKind::LeftBrace | TokenKind::LeftBracket | TokenKind::LeftParen => depth += 1,
                TokenKind::RightBrace if depth == 0 => {
                    if reached_failure {
                        if !nested {
                            cursor += 1;
                        }
                        break;
                    }
                }
                TokenKind::RightBrace | TokenKind::RightBracket | TokenKind::RightParen => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 && reached_failure {
                        cursor += 1;
                        break;
                    }
                }
                TokenKind::Semicolon if depth == 0 && reached_failure => {
                    cursor += 1;
                    break;
                }
                _ => {}
            }
            cursor += 1;
        }
        if cursor > self.at {
            self.events.push(Event::Start(SyntaxKind::Error));
            while self.at < cursor {
                if self.advance().is_none() {
                    break;
                }
            }
            self.events.push(Event::Finish {
                failed: true,
            });
        }
    }

    /// Skip only the malformed portion of an entry. Enclosing delimiters are
    /// left for their owner, and balanced nested constructs are skipped whole.
    fn recover_entry(&mut self, separator: TokenKind, close: TokenKind) {
        self.events.push(Event::Start(SyntaxKind::Error));
        let mut closing = Vec::new();
        while let Some(token) = self.peek() {
            if closing.is_empty()
                && (token.kind == separator
                    || token.kind == close
                    || matches!(
                        token.kind,
                        TokenKind::RightBrace
                            | TokenKind::RightParen
                            | TokenKind::RightBracket
                            | TokenKind::Semicolon
                    ))
            {
                break;
            }
            match token.kind {
                TokenKind::LeftBrace => closing.push(TokenKind::RightBrace),
                TokenKind::LeftParen => closing.push(TokenKind::RightParen),
                TokenKind::LeftBracket => closing.push(TokenKind::RightBracket),
                TokenKind::RightBrace | TokenKind::RightParen | TokenKind::RightBracket
                    if closing.pop() != Some(token.kind) =>
                {
                    break;
                }
                _ => {}
            }
            self.advance();
        }
        self.events.push(Event::Finish {
            failed: true,
        });
    }

    fn error(&mut self, diagnostic: Diagnostic) {
        self.error_count += 1;
        if self.errors.len() < MAX_DIAGNOSTICS {
            self.errors
                .push(diagnostic.in_phase(DiagnosticCode::Syntax));
        }
    }

    fn expect(&mut self, kind: TokenKind, message: &str) -> Option<Token> {
        let Some(token) = self.peek() else {
            self.error(
                Diagnostic::error(message, self.eof_span())
                    .with_expected(SyntaxExpectation::Token(kind)),
            );
            self.missing(SyntaxKind::MissingToken(kind));
            return None;
        };
        if token.kind == kind {
            self.advance()
        } else {
            self.error(
                Diagnostic::error(message, token.span)
                    .with_expected(SyntaxExpectation::Token(kind)),
            );
            self.missing(SyntaxKind::MissingToken(kind));
            None
        }
    }

    fn expect_keyword(&mut self, keyword: Keyword, message: &str) -> Option<Token> {
        self.expect(TokenKind::Keyword(keyword), message)
    }

    fn consume(&mut self, kind: TokenKind) -> Option<Token> {
        if self.at(kind) {
            self.advance()
        } else {
            None
        }
    }

    fn consume_keyword(&mut self, keyword: Keyword) -> Option<Token> {
        self.consume(TokenKind::Keyword(keyword))
    }

    fn at(&self, kind: TokenKind) -> bool {
        self.peek()
            .is_some_and(|token| token.kind == kind)
    }

    fn at_keyword(&self, keyword: Keyword) -> bool {
        self.at(TokenKind::Keyword(keyword))
    }

    fn peek(&self) -> Option<Token> {
        self.peek_n(0)
    }

    fn peek_n(&self, offset: usize) -> Option<Token> {
        if self.cancelled() {
            return None;
        }
        self.tokens.get(self.at + offset).copied()
    }

    fn cancelled(&self) -> bool {
        self.cancellation
            .is_some_and(|cancel| cancel.check().is_err())
    }

    fn advance(&mut self) -> Option<Token> {
        let token = self.peek()?;
        self.at += 1;
        self.events.push(Event::Token);
        Some(token)
    }

    fn text(&self, span: Span) -> &str {
        &self.source.text()[span.range()]
    }

    fn subspan(outer: Span, start: usize, end: usize) -> Span {
        Span::new(
            outer.source_id(),
            outer
                .start()
                .saturating_add(u32::try_from(start).unwrap_or(u32::MAX)),
            outer
                .start()
                .saturating_add(u32::try_from(end).unwrap_or(u32::MAX)),
        )
    }

    fn eof_span(&self) -> Span {
        let end = u32::try_from(self.source.text().len()).unwrap_or(u32::MAX);
        Span::new(self.source_id, end, end)
    }
}
