use serde_json::{Value, json};
use std::fmt::Write as _;
use syrox_lang::{
    analysis::AnalysisCancellation, analysis::SemanticAnalysis,
    analysis::SemanticSymbolKind as Kind, checker::OwnershipUseKind, checker::Ty,
    line_index::LineIndex, source::SourceDomainId, source::SourceId,
};

use super::{
    Server,
    features::{location, range},
    position,
    worker::ResultSet,
};

pub(super) const TOKEN_TYPES: [&str; 10] = [
    "namespace",
    "type",
    "struct",
    "enum",
    "enumMember",
    "function",
    "variable",
    "parameter",
    "typeParameter",
    "property",
];

#[derive(Clone, Debug)]
pub(super) struct HintSettings {
    pub types: bool,
    pub parameters: bool,
    pub ownership: bool,
}
impl Default for HintSettings {
    fn default() -> Self {
        Self {
            types: true,
            parameters: true,
            ownership: false,
        }
    }
}
impl HintSettings {
    pub fn update(&mut self, value: &Value) {
        if let Some(value) = value["types"].as_bool() {
            self.types = value;
        }
        if let Some(value) = value["parameters"].as_bool() {
            self.parameters = value;
        }
        if let Some(value) = value["ownership"].as_bool() {
            self.ownership = value;
        }
    }
}

impl Server {
    pub(super) fn inlay_hints(
        &self,
        params: &Value,
        result: &ResultSet,
        analysis: &SemanticAnalysis,
        source: SourceId,
        lines: &LineIndex,
        resolved: bool,
    ) -> Result<Value, String> {
        let start = lines
            .offset_clamped(
                position(&params["range"]["start"])?,
                self.encoding,
            )
            .ok_or("invalid hint range")?;
        let end = lines
            .offset_clamped(position(&params["range"]["end"])?, self.encoding)
            .ok_or("invalid hint range")?;
        if start > end {
            return Err("reversed hint range".into());
        }
        let inside = |span: syrox_lang::source::Span, offset| {
            span.source_id() == source && start <= offset && offset <= end
        };
        let mut hints = Vec::new();
        if self.hints.types {
            for local in analysis
                .checked_locals()
                .filter(|local| {
                    !local.annotated
                        && inside(local.declaration, local.declaration.end())
                        && local.status == syrox_lang::checker::TypeStatus::Known
                })
                .take(1024)
            {
                let Some(position) = lines.position(local.declaration.end(), self.encoding) else {
                    continue;
                };
                let label = format!(": {}", analysis.display_type(&local.ty));
                hints.push(json!({"position":{"line":position.line,"character":position.character},"label":label,"kind":1,"paddingRight":true,
                    "tooltip":format!("{} value. {}", if local.affine {"Affine"} else {"Reusable"}, if local.affine {"May be consumed at most once; unused values are allowed."} else {"May be used more than once."})}));
            }
        }
        if self.hints.parameters {
            for argument in analysis
                .parameter_hints()
                .iter()
                .filter(|argument| inside(argument.argument, argument.argument.start()))
            {
                if hints.len() >= 1024 {
                    break;
                }
                let text = &analysis
                    .sources()
                    .get(source)
                    .expect("hint source")
                    .text()
                    [argument.argument.start() as usize..argument.argument.end() as usize];
                if text == argument.name || argument.name.starts_with('_') {
                    continue;
                }
                let Some(position) = lines.position(argument.argument.start(), self.encoding)
                else {
                    continue;
                };
                let parameter_source = analysis
                    .sources()
                    .get(argument.parameter.source_id())
                    .expect("parameter source");
                let location = location(
                    result.uri(argument.parameter.source_id()),
                    range(
                        &LineIndex::new(parameter_source),
                        argument.parameter,
                        self.encoding,
                    )
                    .unwrap_or(Value::Null),
                );
                hints.push(json!({
                    "position": {
                        "line": position.line,
                        "character": position.character
                    },
                    "label": [{
                        "value": format!("{}:", argument.name),"location": location
                    }],
                    "kind": 2,
                    "paddingRight": true
                }));
            }
        }
        if self.hints.ownership {
            for usage in analysis.ownership_uses().iter().filter(|usage| {
                usage.affine && usage.is_valid() && usage.kind != OwnershipUseKind::Reuse
            }) {
                if hints.len() >= 1024 {
                    break;
                }
                let span = usage.closure.unwrap_or(usage.span);
                if !inside(span, span.start()) {
                    continue;
                }
                let Some(position) = lines.position(span.start(), self.encoding) else {
                    continue;
                };
                let name = analysis
                    .locals()
                    .find(|local| local.id() == usage.local)
                    .map_or("value", |local| local.name());
                let label = if usage.kind == OwnershipUseKind::Capture {
                    format!("captures {name}")
                } else {
                    "consumes".into()
                };
                hints.push(json!({
                    "position": {
                        "line": position.line,
                        "character": position.character
                    },
                    "label": label,
                    "paddingRight": true,
                    "tooltip": "Affine ownership: this operation transfers the value. Field projection and interpolation consume the complete carrier."
                }));
            }
        }
        hints.sort_by_key(|hint| {
            (
                hint["position"]["line"].as_u64(),
                hint["position"]["character"].as_u64(),
            )
        });
        self.stamp_hints(params, result, &mut hints, resolved);
        Ok(json!(hints))
    }

    pub(super) fn semantic_tokens(
        &self,
        analysis: &SemanticAnalysis,
        source: SourceId,
        lines: &LineIndex,
        generation: u64,
    ) -> Result<Value, String> {
        let mut data = Vec::<u32>::new();
        let mut previous = (0, 0);
        let mut previous_end = 0;
        for token in analysis
            .occurrences_in(source, &AnalysisCancellation::default())
            .map_err(|error| error.to_string())?
            .iter()
            .filter(|entry| entry.span.source_id() == source)
        {
            if token.span.start() < previous_end {
                continue;
            }
            let Some(start) = lines.position(token.span.start(), self.encoding) else {
                continue;
            };
            let Some(end) = lines.position(token.span.end(), self.encoding) else {
                continue;
            };
            if start.line != end.line || end.character <= start.character {
                continue;
            }
            let mut modifiers = u32::from(token.is_declaration);
            if matches!(
                token.kind,
                Kind::Variable | Kind::Parameter | Kind::Field
            ) {
                modifiers |= 2;
            }
            if analysis
                .sources()
                .domain(token.declaration.source_id())
                == Some(SourceDomainId::standard_library())
            {
                modifiers |= 4;
            }
            data.extend([
                start.line - previous.0,
                if start.line == previous.0 {
                    start.character - previous.1
                } else {
                    start.character
                },
                end.character - start.character,
                token_kind(token.kind),
                modifiers,
            ]);
            previous = (start.line, start.character);
            previous_end = token.span.end();
        }
        Ok(json!({"data":data,"resultId":format!("{generation}:{}",source.index())}))
    }

    pub(super) fn semantic_hover(
        analysis: &SemanticAnalysis,
        source: SourceId,
        offset: u32,
    ) -> Option<Value> {
        let cancel = AnalysisCancellation::default();
        let symbol = analysis
            .symbol_at(source, offset, &cancel)
            .ok()
            .flatten();
        let local = analysis.local_at(source, offset);
        let referenced_function = analysis
            .references()
            .find(|reference| {
                reference.span().source_id() == source
                    && reference.span().start() <= offset
                    && offset < reference.span().end()
            })
            .and_then(|reference| match reference.target() {
                syrox_lang::resolver::ResolvedTarget::Item(item) => analysis.function_type(*item),
                _ => None,
            });
        let ty = referenced_function
            .or_else(|| analysis.type_at(source, offset))
            .or_else(|| symbol.and_then(|symbol| symbol.ty.as_ref()));
        let mut text = match (symbol, ty) {
            (Some(symbol), Some(ty)) => format!("{}: {}", symbol.name, analysis.display_type(ty)),
            (Some(symbol), None) => format!("{:?} {}", symbol.kind, symbol.name),
            (None, Some(ty)) => analysis.display_type(ty),
            _ => return None,
        };
        if let Some(local) = local {
            if local.status != syrox_lang::checker::TypeStatus::Known {
                text.push_str(if local.annotated {
                    "\n\nDeclared type; the initializer is invalid or unavailable."
                } else {
                    "\n\nType information is incomplete or comes from an invalid initializer."
                });
                return Some(json!({"contents":{"kind":"plaintext","value":text}}));
            }
            text.push_str(if local.affine {
                "\n\nAffine value: can be consumed at most once."
            } else {
                "\n\nReusable value."
            });
            if let Some(usage) = analysis
                .ownership_uses()
                .iter()
                .rev()
                .find(|usage| {
                    usage.local == local.id
                        && usage.span.source_id() == source
                        && usage.span.start() <= offset
                        && offset < usage.span.end()
                })
            {
                if usage.is_uncertain() {
                    text.push_str(" Ownership is unknown across an incomplete statement.");
                } else if usage.previous_move.is_some() {
                    text.push_str(if usage.conditional {
                        " This value may already have been consumed in a branch."
                    } else {
                        " This value has already been consumed."
                    });
                } else if usage.affine
                    && usage.is_valid()
                    && usage.kind == OwnershipUseKind::Consume
                {
                    text.push_str(" This use consumes the value.");
                }
            }
            if let Ty::Function {
                once: true,
                ..
            } = local.ty
            {
                text.push_str(" Calling this closure consumes it.");
            }
        }
        if let Some(symbol) = symbol
            && !symbol.documentation.is_empty()
        {
            text.push_str("\n\n");
            text.push_str(&symbol.documentation);
        }
        let captures: Vec<_> = analysis
            .ownership_uses()
            .iter()
            .filter(|usage| {
                usage.closure.is_some_and(|span| {
                    span.source_id() == source && span.start() <= offset && offset < span.end()
                })
            })
            .take(16)
            .collect();
        if !captures.is_empty() {
            text.push_str("\n\nCaptures:");
            for capture in captures {
                if let Some(local) = analysis
                    .locals()
                    .find(|local| local.id() == capture.local)
                {
                    let _ = write!(
                        text,
                        "\n- {} ({})",
                        local.name(),
                        if capture.is_uncertain() {
                            "ownership unknown after syntax recovery"
                        } else if !capture.is_valid() {
                            "invalid capture"
                        } else if capture.affine {
                            "moved at closure creation"
                        } else {
                            "reusable"
                        }
                    );
                }
            }
        }
        Some(json!({"contents":{"kind":"plaintext","value":text}}))
    }
}

pub(super) fn symbol_kind(kind: Kind) -> u32 {
    match kind {
        Kind::Namespace => 3,
        Kind::Type => 5,
        Kind::Struct => 23,
        Kind::Enum => 10,
        Kind::Variant => 22,
        Kind::Function => 12,
        Kind::Field => 8,
        Kind::TypeParameter => 26,
        Kind::Variable | Kind::Parameter => 13,
    }
}
fn token_kind(kind: Kind) -> u32 {
    match kind {
        Kind::Namespace => 0,
        Kind::Type => 1,
        Kind::Struct => 2,
        Kind::Enum => 3,
        Kind::Variant => 4,
        Kind::Function => 5,
        Kind::Variable => 6,
        Kind::Parameter => 7,
        Kind::TypeParameter => 8,
        Kind::Field => 9,
    }
}
