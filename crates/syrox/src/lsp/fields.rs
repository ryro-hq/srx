use super::{
    Server,
    features::{edit_range, text_edit},
};
use serde_json::{Value, json};
use syrox_lang::{
    analysis::SemanticAnalysis, checker::Ty, line_index::LineIndex, resolver::ResolvedTarget,
    source::SourceId, syntax::ParsedFile, syntax::SyntaxKind, syntax::SyntaxToken,
    syntax::SyntaxTokenKind as Token,
};

impl Server {
    pub(super) fn complete_fields(
        &self,
        parsed: &ParsedFile,
        offset: u32,
        analysis: &SemanticAnalysis,
        id: SourceId,
    ) -> Option<Value> {
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
                && offset < token.span.end()
                && matches!(token.kind, Token::String | Token::Comment)
        }) {
            return None;
        }
        let mut index = tokens.partition_point(|token| token.span.end() <= offset);
        let (start, end, prefix) = if let Some(token) = tokens
            .get(index)
            .filter(|token| token.kind == Token::Ident && token.span.start() <= offset)
        {
            (
                token.span.start(),
                token.span.end(),
                &text[token.span.start() as usize..offset as usize],
            )
        } else if index > 0
            && tokens[index - 1].kind == Token::Ident
            && tokens[index - 1].span.end() == offset
        {
            index -= 1;
            (
                tokens[index].span.start(),
                offset,
                &text[tokens[index].span.start() as usize..offset as usize],
            )
        } else {
            (offset, offset, "")
        };
        if index == 0 || tokens[index - 1].kind != Token::Dot {
            return None;
        }
        let dot = index - 1;
        let ty = receiver_type(text, &tokens[..dot], analysis, id, offset)?;
        self.field_candidates(
            parsed, offset, analysis, id, &ty, start, end, prefix,
        )
    }

    #[allow(clippy::too_many_arguments)] // Keep source/lookup identity and replacement boundaries explicit.
    fn field_candidates(
        &self,
        parsed: &ParsedFile,
        offset: u32,
        analysis: &SemanticAnalysis,
        id: SourceId,
        ty: &Ty,
        start: u32,
        end: u32,
        prefix: &str,
    ) -> Option<Value> {
        let lines = LineIndex::new(parsed.source());
        let range = edit_range(&lines, start, end, self.encoding)?;
        let methods = analysis.methods_for_type(ty);
        let mut items: Vec<_> = analysis
            .fields_at(id, offset, ty)
            .into_iter()
            .filter(|field| field.name.starts_with(prefix))
            .filter(|field| {
                !methods
                    .iter()
                    .any(|method| method.path().segments().last() == Some(&field.name))
            })
            .map(|field| {
                let detail = analysis.display_type(&field.ty);
                let edit = text_edit(range.clone(), field.name.clone());
                json!({ "label": field.name, "kind": 5, "detail": detail, "textEdit": edit })
            })
            .collect();
        items.extend(methods.into_iter().filter_map(|method| {
            let name = method.path().segments().last()?;
            if !name.starts_with(prefix) {
                return None;
            }
            let detail = analysis.function_type(method.id()).map(|ty| analysis.display_type(ty));
            Some(json!({"label": name, "kind": 2, "detail": detail, "textEdit": text_edit(range.clone(), name.clone())}))
        }));
        let incomplete = items.len() >= 256 || analysis.editor_facts_truncated();
        items.truncate(256);
        Some(json!({"isIncomplete":incomplete,"items":items}))
    }
}

pub(super) fn receiver_type(
    text: &str,
    tokens: &[&SyntaxToken],
    analysis: &SemanticAnalysis,
    source: SourceId,
    offset: u32,
) -> Option<Ty> {
    let previous = tokens.last()?;
    if matches!(
        previous.kind,
        Token::RightParen | Token::RightBracket | Token::RightBrace
    ) {
        return analysis
            .expression_at(source, previous.span.start())
            .map(syrox_lang::checker::CheckedExpression::ty)
            .filter(|ty| ty.is_known())
            .cloned()
            .or_else(|| receiver_result(text, tokens, analysis, source, offset));
    }
    let mut beginning = tokens.len();
    while beginning > 0
        && matches!(
            tokens[beginning - 1].kind,
            Token::Ident | Token::Dot | Token::ColonColon
        )
    {
        beginning -= 1;
    }
    let receiver = tokens[beginning..]
        .iter()
        .map(|token| &text[token.span.start() as usize..token.span.end() as usize])
        .collect::<String>();
    let mut segments = receiver.split('.');
    let root = segments.next()?;
    let mut ty = if root.is_empty() && beginning > 0 && tokens[beginning].kind == Token::Dot {
        // A temporary receiver can have further fields, as in
        // `forPlatform({...}).platform.system` or `Outer {...}.inner.field`.
        receiver_type(
            text,
            &tokens[..beginning],
            analysis,
            source,
            offset,
        )?
    } else {
        let parts = root
            .split("::")
            .map(str::to_owned)
            .collect::<Vec<_>>();
        match analysis.lookup_path(source, offset, &parts)? {
            ResolvedTarget::Local(local) => analysis.local_type(local)?.clone(),
            ResolvedTarget::Item(item) => analysis.output_type(item)?.clone(),
            _ => return None,
        }
    };
    for field in segments {
        ty = analysis
            .fields_at(source, offset, &ty)
            .into_iter()
            .find(|candidate| candidate.name == field)?
            .ty;
    }
    Some(ty)
}

fn receiver_result(
    text: &str,
    tokens: &[&SyntaxToken],
    analysis: &SemanticAnalysis,
    source: SourceId,
    offset: u32,
) -> Option<Ty> {
    if tokens.last()?.kind != Token::RightParen {
        return None;
    }
    let mut depth = 0usize;
    let open = (0..tokens.len()).rev().find(|index| {
        match tokens[*index].kind {
            Token::RightParen => depth += 1,
            Token::LeftParen => depth -= 1,
            _ => {}
        }
        depth == 0
    })?;
    let mut start = open;
    while start > 0
        && matches!(
            tokens[start - 1].kind,
            Token::Ident | Token::ColonColon
        )
    {
        start -= 1;
    }
    let (path, call) = if start < open {
        (&tokens[start..open], true)
    } else {
        (&tokens[open + 1..tokens.len() - 1], false)
    };
    if path.is_empty()
        || path.len().is_multiple_of(2)
        || path.iter().enumerate().any(|(index, token)| {
            token.kind
                != if index.is_multiple_of(2) {
                    Token::Ident
                } else {
                    Token::ColonColon
                }
        })
    {
        return None;
    }
    let parts = path
        .iter()
        .filter(|token| token.kind == Token::Ident)
        .map(|token| text[token.span.start() as usize..token.span.end() as usize].to_owned())
        .collect::<Vec<_>>();
    let target = analysis.lookup_path(source, offset, &parts)?;
    let ty = match target {
        ResolvedTarget::Local(local) => analysis.local_type(local)?,
        ResolvedTarget::Item(item) => analysis
            .function_type(item)
            .or_else(|| analysis.output_type(item))?,
        _ => return None,
    };
    if call {
        if let Ty::Function {
            result,
            ..
        } = ty
        {
            Some((**result).clone())
        } else {
            None
        }
    } else {
        Some(ty.clone())
    }
}

impl Server {
    pub(super) fn complete_construction(
        &self,
        parsed: &ParsedFile,
        offset: u32,
        analysis: &SemanticAnalysis,
        source: SourceId,
    ) -> Option<Value> {
        let text = parsed.source().text();
        if !text.is_char_boundary(offset as usize) {
            return None;
        }
        let node = parsed
            .syntax()
            .nodes()
            .filter(|node| {
                node.kind() == SyntaxKind::StructLiteral
                    && node.span().start() < offset
                    && (offset < node.span().end()
                        || offset == node.span().end() && offset as usize == text.len())
            })
            .min_by_key(|node| node.span().end() - node.span().start())?;
        if parsed.tokens().any(|token| {
            matches!(token.kind, Token::String | Token::Comment)
                && token.span.start() <= offset
                && offset < token.span.end()
        }) {
            return None;
        }
        let tokens: Vec<_> = parsed
            .tokens()
            .filter(|token| {
                !token.kind.is_trivia()
                    && token.span.start() >= node.span().start()
                    && token.span.end() <= node.span().end()
            })
            .collect();
        let open = tokens.first()?;
        if open.kind != Token::LeftBrace {
            return None;
        }
        let segments = field_segments(&tokens, node.span().end().max(offset));
        let (index, (_, _, current)) = segments
            .iter()
            .enumerate()
            .find(|(_, (start, end, _))| *start <= offset && offset <= *end)?;
        let name = current
            .first()
            .filter(|token| token.kind == Token::Ident);
        let editing_name = name.is_some_and(|name| name.span.start() <= offset);
        let (start, end, prefix) = if let Some(name) = name {
            if offset > name.span.end() {
                return None;
            }
            if offset < name.span.start() {
                (offset, offset, "")
            } else {
                (
                    name.span.start(),
                    name.span.end(),
                    &text[name.span.start() as usize..offset as usize],
                )
            }
        } else if current.is_empty() {
            (offset, offset, "")
        } else {
            return None;
        };
        let existing: Vec<_> = segments
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index || !editing_name)
            .filter_map(|(_, (_, _, segment))| {
                let first = segment.first()?;
                (first.kind == Token::Ident && segment.get(1)?.kind == Token::Equal)
                    .then(|| &text[first.span.start() as usize..first.span.end() as usize])
            })
            .collect();
        let ty = analysis
            .expression_at(source, open.span.start())?
            .ty();
        let lines = LineIndex::new(parsed.source());
        let range = edit_range(&lines, start, end, self.encoding)?;
        let fields = analysis.construction_fields_at(source, offset, ty);
        let incomplete = fields.len() >= 256 || analysis.editor_facts_truncated();
        let items: Vec<_> = fields.into_iter().filter(|field| field.name.starts_with(prefix) && !existing.contains(&field.name.as_str()))
            .map(|field| {
                let status = if field.has_default { "default" } else { "required" };
                json!({"label":field.name,"kind":5,"detail":format!("{} ({status})", analysis.display_type(&field.ty)),
                    "sortText":format!("{}:{}",u8::from(field.has_default),field.name),
                    "textEdit":text_edit(range.clone(), field.name)})
            }).collect();
        Some(json!({"isIncomplete":incomplete,"items":items}))
    }
}

/// Only top-level semicolons divide fields. Nested literals and closure bodies
/// retain their own fields and statement separators.
fn field_segments<'a>(
    tokens: &[&'a SyntaxToken],
    end: u32,
) -> Vec<(u32, u32, Vec<&'a SyntaxToken>)> {
    let mut segments = Vec::new();
    let mut start = tokens[0].span.end();
    let mut current = Vec::new();
    let mut depth = 0usize;
    for token in tokens.iter().skip(1) {
        if depth == 0 && matches!(token.kind, Token::Semicolon | Token::RightBrace) {
            segments.push((
                start,
                token.span.start(),
                std::mem::take(&mut current),
            ));
            start = token.span.end();
            if token.kind == Token::RightBrace {
                return segments;
            }
            continue;
        }
        match token.kind {
            Token::LeftBrace | Token::LeftParen | Token::LeftBracket => depth += 1,
            Token::RightBrace | Token::RightParen | Token::RightBracket => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        current.push(*token);
    }
    segments.push((start, end, current));
    segments
}
