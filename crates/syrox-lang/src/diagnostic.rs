use ariadne::{Config, Label, Report, ReportKind};
use thiserror::Error;

use crate::{
    source::Source, source::SourceId, source::SourceSet, source::Span, syntax::SyntaxTokenKind,
};

/// Stable diagnostic categories. Specific rules can acquire narrower codes
/// without requiring clients to parse human-readable messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    General,
    Lexical,
    Syntax,
    ExpectedToken,
    ExpectedExpression,
    Resolution,
    TypeCheck,
    MovedValue,
    Evaluation,
}

impl DiagnosticCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::General => "srx.language",
            Self::Lexical => "srx.lexical",
            Self::Syntax => "srx.syntax",
            Self::ExpectedToken => "srx.syntax.expected-token",
            Self::ExpectedExpression => "srx.syntax.expected-expression",
            Self::Resolution => "srx.resolution",
            Self::TypeCheck => "srx.type-check",
            Self::MovedValue => "srx.ownership.moved-value",
            Self::Evaluation => "srx.evaluation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntaxExpectation {
    Token(SyntaxTokenKind),
    Expression,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelatedDiagnostic {
    pub span: Span,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub severity: Severity,
    pub message: String,
    pub span: Span,
    pub note: Option<String>,
    pub expected: Option<SyntaxExpectation>,
    pub related: Vec<RelatedDiagnostic>,
}

impl Diagnostic {
    pub fn error(message: impl Into<String>, span: Span) -> Self {
        Self {
            code: DiagnosticCode::General,
            severity: Severity::Error,
            message: message.into(),
            span,
            note: None,
            expected: None,
            related: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_code(mut self, code: DiagnosticCode) -> Self {
        self.code = code;
        self
    }

    #[must_use]
    pub fn with_expected(mut self, expected: SyntaxExpectation) -> Self {
        self.code = match expected {
            SyntaxExpectation::Token(_) => DiagnosticCode::ExpectedToken,
            SyntaxExpectation::Expression => DiagnosticCode::ExpectedExpression,
        };
        self.expected = Some(expected);
        self
    }

    #[must_use]
    pub fn with_related(mut self, span: Span, message: impl Into<String>) -> Self {
        self.related.push(RelatedDiagnostic {
            span,
            message: message.into(),
        });
        self
    }

    pub(crate) fn in_phase(mut self, code: DiagnosticCode) -> Self {
        if self.code == DiagnosticCode::General {
            self.code = code;
        }
        self
    }

    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    pub fn render(&self, source: &Source) -> String {
        self.render_resolved(source, |id| {
            (id == self.span.source_id()).then_some(source)
        })
    }

    pub fn render_from(&self, sources: &SourceSet) -> Option<String> {
        sources
            .get(self.span.source_id())
            .map(|source| self.render_resolved(source, |id| sources.get(id)))
    }

    fn render_resolved<'a>(
        &self,
        source: &'a Source,
        lookup: impl Fn(SourceId) -> Option<&'a Source>,
    ) -> String {
        let kind = match self.severity {
            Severity::Error => ReportKind::Error,
            Severity::Warning => ReportKind::Warning,
        };
        let primary = location(source, self.span);
        let mut cache_sources = vec![(primary.0.clone(), source.text())];
        let mut report = Report::build(kind, primary.clone())
            .with_config(Config::default().with_color(false))
            .with_code(self.code.as_str())
            .with_message(&self.message)
            .with_label(Label::new(primary).with_message(&self.message));
        for related in &self.related {
            if let Some(source) = lookup(related.span.source_id()) {
                let location = location(source, related.span);
                cache_sources.push((location.0.clone(), source.text()));
                report = report.with_label(Label::new(location).with_message(&related.message));
            }
        }
        if let Some(note) = &self.note {
            report = report.with_note(note);
        }

        let mut output = Vec::new();
        report
            .finish()
            .write(ariadne::sources(cache_sources), &mut output)
            .expect("writing diagnostics to a byte buffer cannot fail");
        String::from_utf8(output).expect("ariadne diagnostics are valid UTF-8")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DiagnosticSource {
    id: SourceId,
    name: String,
}

impl std::fmt::Display for DiagnosticSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.name)
    }
}

fn location(source: &Source, span: Span) -> (DiagnosticSource, std::ops::Range<usize>) {
    let text = source.text();
    let bytes = span.range();
    (
        DiagnosticSource {
            id: span.source_id(),
            name: source.name().to_owned(),
        },
        byte_to_char_offset(text, bytes.start)..byte_to_char_offset(text, bytes.end),
    )
}

fn byte_to_char_offset(text: &str, byte_offset: usize) -> usize {
    text.char_indices()
        .take_while(|(offset, _)| *offset < byte_offset)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_translates_byte_spans_after_multibyte_text() {
        let source = Source::new("unicode.srx", "é @").unwrap();
        let errors = crate::syntax::analyze(&source).unwrap_err();
        let rendered = errors[1].render(&source);

        assert!(rendered.contains("unicode.srx:1:3"));
        assert!(rendered.contains("é @"));
    }

    #[test]
    fn source_set_rendering_selects_the_span_source() {
        let mut sources = SourceSet::new();
        sources
            .add("valid.srx", "type Good = T;")
            .unwrap();
        let invalid = sources.add("invalid.srx", "type Bad T;").unwrap();
        let errors = crate::syntax::parse_sources(&sources).unwrap_err();
        let error = errors
            .iter()
            .find(|error| error.span.source_id() == invalid)
            .unwrap();
        let rendered = error.render_from(&sources).unwrap();

        assert!(rendered.contains("invalid.srx:1:"));
        assert!(rendered.contains("type Bad T;"));
        assert!(!rendered.contains("type Good = T;"));
    }

    #[test]
    fn syntax_diagnostics_expose_codes_and_expectations_without_message_parsing() {
        let source = Source::new("buffer.srx", "outputs { item: I = ; } type T I;").unwrap();
        let parsed = crate::syntax::parse_file(&source);
        let expression = parsed
            .diagnostics()
            .iter()
            .find(|error| error.code == DiagnosticCode::ExpectedExpression)
            .unwrap();
        assert_eq!(
            expression.expected,
            Some(SyntaxExpectation::Expression)
        );
        assert_eq!(&source.text()[expression.span.range()], ";");
        let token = parsed
            .diagnostics()
            .iter()
            .find(|error| error.expected == Some(SyntaxExpectation::Token(SyntaxTokenKind::Equal)))
            .unwrap();
        assert_eq!(token.code.as_str(), "srx.syntax.expected-token");
        assert!(
            token
                .render(&source)
                .contains("srx.syntax.expected-token")
        );
    }

    #[test]
    fn related_labels_render_across_sources_even_when_names_match() {
        let mut sources = SourceSet::new();
        let first = sources.add("shared.srx", "é first").unwrap();
        let second = sources.add("shared.srx", "😀 second").unwrap();
        let diagnostic = Diagnostic::error("conflict", Span::new(first, 3, 8))
            .with_related(Span::new(second, 5, 11), "related declaration");
        let rendered = diagnostic.render_from(&sources).unwrap();
        assert!(rendered.contains("é first"), "{rendered}");
        assert!(rendered.contains("😀 second"), "{rendered}");
        assert!(
            rendered.contains("related declaration"),
            "{rendered}"
        );
        assert_eq!(diagnostic.related[0].span.source_id(), second);
    }

    #[test]
    fn moved_value_diagnostic_points_to_move_and_declaration() {
        let text = "resource R(int); fn f(x: R) { x; x; }";
        let mut sources = SourceSet::new();
        sources.add("ownership.srx", text).unwrap();
        let resolved =
            crate::resolver::resolve(crate::syntax::parse_sources(&sources).unwrap()).unwrap();
        let diagnostics =
            crate::checker::check(resolved, &crate::checker::CheckPolicy::default()).unwrap_err();
        let diagnostic = diagnostics
            .iter()
            .find(|error| error.code == DiagnosticCode::MovedValue)
            .unwrap();
        assert_eq!(diagnostic.related.len(), 2);
        assert_eq!(
            diagnostic.related[0].span.start() as usize,
            text.find("x;").unwrap()
        );
        assert_eq!(
            diagnostic.related[1].span.start() as usize,
            text.find("x:").unwrap()
        );
        assert_eq!(
            diagnostic.span.start() as usize,
            text.rfind("x;").unwrap()
        );
        let rendered = diagnostic.render_from(&sources).unwrap();
        assert!(rendered.contains("first moved here"));
        assert!(rendered.contains("declared here"));
    }
}
