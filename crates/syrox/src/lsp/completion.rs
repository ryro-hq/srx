use serde_json::{Value, json};
use syrox_lang::{
    analysis::SemanticAnalysis, checker::Ty, line_index::LineIndex, resolver::ResolvedItemKind,
    resolver::ResolvedTarget, source::SourceId, syntax::ParsedFile, syntax::SyntaxKind,
    syntax::SyntaxTokenKind as Token,
};

use super::{
    Server,
    features::{display_type, edit_range, path_label, text_edit},
};

impl Server {
    pub(super) fn complete(
        &self,
        parsed: &ParsedFile,
        offset: u32,
        semantic: Option<(&SemanticAnalysis, SourceId)>,
    ) -> Value {
        if let Some((analysis, id)) = semantic
            && let Some(value) = self.complete_construction(parsed, offset, analysis, id)
        {
            return value;
        }
        if let Some((analysis, id)) = semantic
            && let Some(value) = self.complete_interpolation(parsed, offset, analysis, id)
        {
            return value;
        }
        if let Some((analysis, id)) = semantic
            && let Some(value) = self.complete_fields(parsed, offset, analysis, id)
        {
            return value;
        }
        let Some((parts, span)) = completion_path(parsed, offset) else {
            return json!({"isIncomplete":false,"items":[]});
        };
        let Some((analysis, id)) = semantic else {
            return json!({"isIncomplete":true,"items":[]});
        };
        let (prefix, qualifier) = parts.split_last().expect("completion prefix");
        let candidates = if type_context(parsed, span.0) {
            analysis.complete_type_path(id, offset, qualifier, prefix)
        } else {
            analysis.complete_path(id, offset, qualifier, prefix)
        };
        let incomplete = candidates.len() >= 256;
        let lines = LineIndex::new(parsed.source());
        let range = edit_range(&lines, span.0, span.1, self.encoding).expect("token boundary");
        let items: Vec<_> = candidates
            .into_iter()
            .take(256)
            .map(|(name, target)| {
                let (kind, detail) = match target {
                    ResolvedTarget::Item(id) => {
                        let item = analysis
                            .items()
                            .find(|item| item.id() == id)
                            .expect("resolved item");
                        let kind = match item.kind() {
                            ResolvedItemKind::Function => 3,
                            ResolvedItemKind::Struct => 22,
                            ResolvedItemKind::Enum => 13,
                            ResolvedItemKind::OutputValue => 6,
                            _ => 7,
                        };
                        let ty = analysis
                            .function_type(id)
                            .or_else(|| analysis.output_type(id));
                        let detail = ty.map_or_else(
                            || format!("{:?}", item.kind()),
                            |ty| display_type(analysis, ty, &mut 128, 0),
                        );
                        (kind, detail)
                    }
                    ResolvedTarget::Local(id) => {
                        let local = analysis.locals().find(|local| local.id() == id);
                        let parameter = local.is_some_and(|local| {
                            local.kind() == syrox_lang::resolver::LocalKind::TypeParameter
                        });
                        let kind = if parameter {
                            25
                        } else {
                            6
                        };
                        let detail = analysis
                            .local_type(id)
                            .map_or_else(|| "local".into(), |ty| analysis.display_type(ty));
                        (kind, detail)
                    }
                    ResolvedTarget::EnumVariant {
                        ..
                    } => (20, "enum variant".into()),
                    _ => (9, "module".into()),
                };
                let edit = text_edit(range.clone(), name.clone());
                json!({
                    "label": name,
                    "kind": kind,
                    "detail": detail,
                    "textEdit": edit,
                })
            })
            .collect();
        json!({ "isIncomplete": incomplete, "items": items })
    }

    pub(super) fn signature_help(
        parsed: &ParsedFile,
        offset: u32,
        semantic: Option<(&SemanticAnalysis, SourceId)>,
    ) -> Value {
        let Some((analysis, id)) = semantic else {
            return Value::Null;
        };
        let Some((parts, active)) = call_at(parsed, offset) else {
            return Value::Null;
        };
        let Some(target) = analysis.lookup_path(id, offset, &parts) else {
            return Value::Null;
        };
        let signature = match target {
            ResolvedTarget::Item(item) => analysis
                .function_type(item)
                .or_else(|| analysis.output_type(item)),
            ResolvedTarget::Local(local) => analysis.local_type(local),
            _ => None,
        };
        let Some(Ty::Function {
            parameters,
            result,
            ..
        }) = signature
        else {
            return Value::Null;
        };
        let names = match target {
            ResolvedTarget::Item(item) => analysis.function_parameters(item),
            _ => None,
        };
        let mut budget = 128;
        let labels: Vec<_> = parameters
            .iter()
            .take(128)
            .enumerate()
            .map(|(index, ty)| {
                let name = names
                    .and_then(|parameters| parameters.get(index))
                    .map_or_else(String::new, |parameter| {
                        parameter.name.text.clone()
                    });
                if name.is_empty() {
                    display_type(analysis, ty, &mut budget, 0)
                } else {
                    format!(
                        "{name}: {}",
                        display_type(analysis, ty, &mut budget, 0)
                    )
                }
            })
            .collect();
        let label = format!(
            "{}({}) -> {}",
            path_label(&parts),
            labels.join(", "),
            display_type(analysis, result, &mut budget, 0)
        );
        let parameters: Vec<_> = labels
            .into_iter()
            .map(|label| json!({"label":label}))
            .collect();
        let active = if parameters.is_empty() {
            Value::Null
        } else {
            json!(active.min(parameters.len() - 1))
        };
        json!({
            "signatures": [{
                "label": label,"parameters": parameters,"activeParameter": active
            }],
            "activeSignature": 0,
            "activeParameter": active
        })
    }
}

fn type_context(parsed: &ParsedFile, offset: u32) -> bool {
    let mut context = parsed.syntax().context_at(offset);
    while let Some(node) = context {
        if node.kind() == SyntaxKind::Type {
            return true;
        }
        context = node.parent();
    }
    parsed
        .tokens()
        .filter(|token| !token.kind.is_trivia() && token.span.end() <= offset)
        .last()
        .is_some_and(|token| matches!(token.kind, Token::Colon | Token::Arrow))
}

fn completion_path(parsed: &ParsedFile, offset: u32) -> Option<(Vec<String>, (u32, u32))> {
    let text = parsed.source().text();
    if !text.is_char_boundary(offset as usize) {
        return None;
    }
    let tokens: Vec<_> = parsed
        .tokens()
        .filter(|token| !token.kind.is_trivia())
        .collect();
    if parsed.tokens().any(|token| {
        token.span.start() <= offset
            && (offset < token.span.end()
                || token.kind == Token::Comment && offset == token.span.end())
            && matches!(
                token.kind,
                Token::String | Token::Comment | Token::Invalid | Token::Unparsed
            )
    }) {
        return None;
    }
    let mut index = tokens.partition_point(|token| token.span.end() <= offset);
    let mut start = offset;
    let mut end = offset;
    let mut prefix = String::new();
    if let Some(token) = tokens
        .get(index)
        .filter(|token| token.kind == Token::Ident && token.span.start() <= offset)
    {
        start = token.span.start();
        end = token.span.end();
        prefix = text[start as usize..offset as usize].into();
    } else if index > 0
        && tokens[index - 1].kind == Token::Ident
        && tokens[index - 1].span.end() == offset
    {
        index -= 1;
        start = tokens[index].span.start();
        end = offset;
        prefix = text[start as usize..offset as usize].into();
    }
    let mut parts = vec![prefix];
    while index >= 2
        && tokens[index - 1].kind == Token::ColonColon
        && tokens[index - 2].kind == Token::Ident
    {
        parts.push(
            text[tokens[index - 2].span.start() as usize..tokens[index - 2].span.end() as usize]
                .into(),
        );
        index -= 2;
    }
    if index > 0
        && matches!(
            tokens[index - 1].kind,
            Token::Dot | Token::ColonColon
        )
    {
        return None;
    }
    parts.reverse();
    Some((parts, (start, end)))
}

fn call_at(parsed: &ParsedFile, offset: u32) -> Option<(Vec<String>, usize)> {
    let tokens: Vec<_> = parsed
        .tokens()
        .filter(|token| !token.kind.is_trivia())
        .collect();
    let calls: std::collections::BTreeSet<_> = parsed
        .syntax()
        .nodes()
        .filter(|node| node.kind() == SyntaxKind::Arguments)
        .filter_map(|node| {
            let index = tokens.partition_point(|token| token.span.end() <= node.span().start());
            index
                .checked_sub(1)
                .filter(|index| tokens[*index].kind == Token::LeftParen)
        })
        .collect();
    let mut stack = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.span.start() >= offset {
            break;
        }
        match token.kind {
            Token::LeftParen | Token::LeftBrace | Token::LeftBracket | Token::LeftAngle => {
                stack.push(index);
            }
            Token::RightParen | Token::RightBrace | Token::RightBracket | Token::RightAngle => {
                stack.pop();
            }
            _ => {}
        }
    }
    let open = stack
        .into_iter()
        .rev()
        .find(|index| calls.contains(index))?;
    let mut index = open;
    let text = parsed.source().text();
    let mut parts = Vec::new();
    while index > 0 && tokens[index - 1].kind == Token::Ident {
        let span = tokens[index - 1].span;
        parts.push(text[span.start() as usize..span.end() as usize].into());
        index -= 1;
        if index == 0 || tokens[index - 1].kind != Token::ColonColon {
            break;
        }
        index -= 1;
    }
    if parts.is_empty() {
        return None;
    }
    if index > 0
        && matches!(
            tokens[index - 1].kind,
            Token::Dot | Token::ColonColon
        )
    {
        return None;
    }
    parts.reverse();
    let mut depth = 0usize;
    let mut active = 0;
    for token in &tokens[open + 1..] {
        if token.span.start() >= offset {
            break;
        }
        match token.kind {
            Token::LeftParen | Token::LeftBrace | Token::LeftBracket | Token::LeftAngle => {
                depth += 1;
            }
            Token::RightParen | Token::RightBrace | Token::RightBracket | Token::RightAngle => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
            }
            Token::Comma if depth == 0 => active += 1,
            _ => {}
        }
    }
    Some((parts, active))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syrox_lang::{source::Source, syntax::parse_file};

    #[test]
    fn completion_replaces_the_whole_identifier_and_ignores_comments_and_fields() {
        let text = "fn run() { lib::maker(); value.field; } // lib::ma";
        let parsed = parse_file(&Source::new("test.srx", text).unwrap());
        let start = u32::try_from(text.find("maker").unwrap()).unwrap();
        let (parts, span) = completion_path(&parsed, start + 2).unwrap();
        assert_eq!(parts, ["lib", "ma"]);
        assert_eq!(span, (start, start + 5));
        assert!(completion_path(&parsed, u32::try_from(text.len()).unwrap()).is_none());
        assert!(
            completion_path(
                &parsed,
                u32::try_from(text.find("field").unwrap()).unwrap() + 2
            )
            .is_none()
        );
    }

    #[test]
    fn calls_ignore_nested_commas_strings_and_non_call_parentheses() {
        let text = "fn run() { choose([I(1), I(2)], S(\"a,b\"), I(3)); empty(); }";
        let parsed = parse_file(&Source::new("test.srx", text).unwrap());
        let offset = u32::try_from(text.find("I(3)").unwrap()).unwrap();
        assert_eq!(
            call_at(&parsed, offset),
            Some((vec!["choose".into()], 2))
        );
        let empty = u32::try_from(text.find("empty(").unwrap() + 6).unwrap();
        assert_eq!(
            call_at(&parsed, empty),
            Some((vec!["empty".into()], 0))
        );
        assert!(call_at(&parsed, 7).is_none());
    }
}
