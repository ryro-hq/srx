use serde_json::{Value, json};
use syrox_lang::{
    analysis::SemanticAnalysis, line_index::LineIndex, resolver::LocalKind,
    resolver::ResolvedTarget, source::SourceId, syntax::ParsedFile, syntax::SyntaxTokenKind,
};

use super::{
    Server,
    features::{edit_range, text_edit},
};

impl Server {
    pub(super) fn complete_interpolation(
        &self,
        parsed: &ParsedFile,
        offset: u32,
        analysis: &SemanticAnalysis,
        source: SourceId,
    ) -> Option<Value> {
        let token = parsed.tokens().find(|token| {
            token.kind == SyntaxTokenKind::String
                && token.span.start() < offset
                && offset <= token.span.end()
        })?;
        let empty = || json!({"isIncomplete":false,"items":[]});
        let text = parsed.source().text();
        let Some(start) = interpolation_start(text, token.span.start() as usize, offset as usize)
        else {
            return Some(empty());
        };
        let path = &text[start..offset as usize];
        if !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
        {
            return Some(empty());
        }
        let mut parts = path.split('.').collect::<Vec<_>>();
        let prefix = parts.pop()?;
        let replace_start = offset as usize - prefix.len();
        let replace_end = offset as usize
            + text.as_bytes()[offset as usize..token.span.end() as usize]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
                .count();
        let lines = LineIndex::new(parsed.source());
        let range = edit_range(
            &lines,
            u32::try_from(replace_start).ok()?,
            u32::try_from(replace_end).ok()?,
            self.encoding,
        )?;
        let mut items = Vec::new();
        if parts.is_empty() {
            for (name, target) in analysis.complete_path(source, offset, &[], prefix) {
                let ResolvedTarget::Local(local) = target else {
                    continue;
                };
                if analysis
                    .locals()
                    .nth(local.index())
                    .is_none_or(|local| local.kind() == LocalKind::TypeParameter)
                {
                    continue;
                }
                items.push(json!({
                    "label": name,
                    "kind": 6,
                    "detail": analysis.local_type(local).map(|ty|analysis.display_type(ty)),
                    "textEdit": text_edit(range.clone(), name)
                }));
            }
        } else {
            let Some(ResolvedTarget::Local(local)) =
                analysis.lookup_path(source, offset, &[parts[0].into()])
            else {
                return Some(empty());
            };
            let Some(mut ty) = analysis.local_type(local).cloned() else {
                return Some(empty());
            };
            for field in parts.iter().skip(1) {
                let Some(found) = analysis
                    .fields_at(source, offset, &ty)
                    .into_iter()
                    .find(|candidate| candidate.name == *field)
                else {
                    return Some(empty());
                };
                ty = found.ty;
            }
            for field in analysis
                .fields_at(source, offset, &ty)
                .into_iter()
                .filter(|field| field.name.starts_with(prefix))
            {
                items.push(json!({
                    "label": field.name,
                    "kind": 5,
                    "detail": analysis.display_type(&field.ty),
                    "textEdit": text_edit(range.clone(), field.name)
                }));
            }
        }
        Some(json!({"isIncomplete":false,"items":items}))
    }
}

/// Track only an unescaped interpolation open at the cursor. String text and
/// escaped `${` never become expression completion contexts.
fn interpolation_start(text: &str, start: usize, cursor: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if !text.is_char_boundary(cursor) {
        return None;
    }
    let mut at = start + 1;
    let mut active = None;
    while at < cursor {
        match bytes[at] {
            b'\\' => {
                at += 2;
                continue;
            }
            b'$' if bytes.get(at + 1) == Some(&b'{') && at + 1 < cursor => {
                active = Some(at + 2);
                at += 2;
                continue;
            }
            b'}' => active = None,
            b'"' => return None,
            _ => {}
        }
        at += 1;
    }
    active
}
