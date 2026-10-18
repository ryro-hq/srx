//! Decode known string spellings without evaluating package recipes.

use super::{Checker, Expression, ExpressionKind, ResolvedTarget, StringPart};

impl Checker<'_> {
    pub(super) fn string_constant(&self, expression: &Expression) -> Option<std::sync::Arc<str>> {
        match &expression.kind {
            ExpressionKind::String(value) => {
                let mut result = String::new();
                for part in &value.parts {
                    let StringPart::Text {
                        source,
                        ..
                    } = part
                    else {
                        return None;
                    };
                    let mut chars = source.chars();
                    while let Some(ch) = chars.next() {
                        result.push(if ch == '\\' {
                            match chars.next()? {
                                'n' => '\n',
                                'r' => '\r',
                                't' => '\t',
                                ch @ ('"' | '\\' | '$') => ch,
                                _ => return None,
                            }
                        } else {
                            ch
                        });
                    }
                }
                Some(result.into())
            }
            ExpressionKind::Group(value) => self.string_constant(value),
            ExpressionKind::Path(path) => match self.target(path.span) {
                Some(ResolvedTarget::Item(item)) => match self.global_constants.get(item)? {
                    super::Constant::String(value) => Some(value.clone()),
                    _ => None,
                },
                Some(ResolvedTarget::Local(local)) => {
                    match self.body.bindings.get(local)?.constant.as_ref()? {
                        super::Constant::String(value) => Some(value.clone()),
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }
}
