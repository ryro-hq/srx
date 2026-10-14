use super::{AnalysisCancellation, AnalysisCancelled, DocumentSnapshot};
#[cfg(test)]
use crate::syntax::parse_file;
use crate::{
    diagnostic::SyntaxExpectation, source::Source, source::Span, syntax::SyntaxTokenKind as Token,
};

/// An insertion proven to remove a syntax error by reparsing this document's
/// text. Its span is local; consumers must retain the document's revision/version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxFix {
    pub span: Span,
    pub text: &'static str,
}

impl DocumentSnapshot {
    /// Bounded, cached punctuation repairs. Never guesses identifiers, types or
    /// expressions. Cancellation does not publish an incomplete fix cache.
    pub fn syntax_fixes(
        &self,
        cancellation: &AnalysisCancellation,
    ) -> Result<&[SyntaxFix], AnalysisCancelled> {
        cancellation.check()?;
        if let Some(fixes) = self.document.analysis.fixes.get() {
            return Ok(fixes);
        }
        let parsed = self.parsed(cancellation)?;
        let mut fixes = Vec::new();
        for diagnostic in parsed.diagnostics().iter().take(32) {
            cancellation.check()?;
            let Some(SyntaxExpectation::Token(token)) = diagnostic.expected else {
                continue;
            };
            let text = match token {
                Token::Semicolon => ";",
                Token::RightParen => ")",
                Token::RightBracket => "]",
                Token::RightBrace => "}",
                _ => continue,
            };
            let offset = diagnostic.span.start();
            if fixes
                .iter()
                .any(|fix: &SyntaxFix| fix.span.start() == offset && fix.text == text)
            {
                continue;
            }
            let mut repaired = self.source().text().to_owned();
            if !repaired.is_char_boundary(offset as usize) {
                continue;
            }
            repaired.insert_str(offset as usize, text);
            let Ok(source) = Source::new(self.source().name(), repaired) else {
                continue;
            };
            let after = crate::syntax::parser::parse_file_cancellable(
                crate::source::SourceId::SINGLE,
                &source,
                Some(cancellation),
            )?;
            cancellation.check()?;
            if after.diagnostics().len() < parsed.diagnostics().len()
                && !after.diagnostics().iter().any(|error| {
                    error.expected == diagnostic.expected && error.span.start() == offset
                })
            {
                fixes.push(SyntaxFix {
                    span: Span::new(diagnostic.span.source_id(), offset, offset),
                    text,
                });
            }
            if fixes.len() == 8 {
                break;
            }
        }
        cancellation.check()?;
        let _ = self.document.analysis.fixes.set(fixes);
        Ok(self
            .document
            .analysis
            .fixes
            .get()
            .expect("fix cache initialized"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::AnalysisHost;

    #[test]
    fn repairs_are_syntax_proven_and_cached_by_effective_text() {
        let mut host = AnalysisHost::default();
        let text = "value S(str); outputs { name: S = S(\"😀\") }";
        host.set_overlay("main", 1, text).unwrap();
        let first = host.snapshot().document("main").unwrap();
        let cancel = AnalysisCancellation::default();
        let fixes = first.syntax_fixes(&cancel).unwrap();
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].text, ";");
        let mut repaired = text.to_owned();
        repaired.insert_str(fixes[0].span.start() as usize, fixes[0].text);
        assert!(
            parse_file(&Source::new("main", repaired).unwrap())
                .diagnostics()
                .is_empty()
        );
        host.set_overlay("main", 2, text).unwrap();
        let next = host.snapshot().document("main").unwrap();
        assert_ne!(first.revision(), next.revision());
        assert!(std::ptr::eq(
            fixes,
            next.syntax_fixes(&cancel).unwrap()
        ));
        cancel.cancel();
        assert!(next.syntax_fixes(&cancel).is_err());
    }

    #[test]
    fn missing_expressions_do_not_get_invented_values() {
        let mut host = AnalysisHost::default();
        host.set_disk("main", "value I(int); outputs { x: I = ; }")
            .unwrap();
        assert!(
            host.snapshot()
                .document("main")
                .unwrap()
                .syntax_fixes(&AnalysisCancellation::default())
                .unwrap()
                .is_empty()
        );
    }
}
