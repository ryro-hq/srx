//! Pure configuration conversion. Documents retain text, never mutable CST handles.
use super::{
    BTreeMap, BTreeSet, Eval, Evaluator, Halt, ItemId, LocalId, PrimitiveValue, Span, Ty, Value,
};
use crate::source::SourceDomainId;
mod formats;
mod schema;
use formats::{encode_data, parse_data, patch_data, prune_absent_options};

impl Evaluator<'_> {
    pub(super) fn configuration_call(
        &mut self,
        item: ItemId,
        values: &mut Vec<Value>,
        supplied: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Option<Eval<Value>> {
        let identity = self.index.identity(item)?;
        let path = identity.path();
        if identity.domain() != SourceDomainId::standard_library()
            || path.len() != 3
            || path[0] != "std"
        {
            return None;
        }
        if path[1] == "files" && path[2] == "read_text" {
            return Some((|| {
                let [
                    Value::Nominal {
                        value: PrimitiveValue::Str(path),
                        ..
                    },
                ] = values.as_slice()
                else {
                    return self.fail(span, "read_text expects an asset path");
                };
                let Some(bytes) = self
                    .environment
                    .assets
                    .get(&(self.project_context, path.clone()))
                    .cloned()
                else {
                    return self.fail(
                        span,
                        format!("asset `{path}` is not authenticated for this project"),
                    );
                };
                self.expand(bytes.len(), span)?;
                self.charge_steps(bytes.len(), span)?;
                match std::str::from_utf8(&bytes) {
                    Ok(text) => self.config_text(text.to_owned(), span),
                    Err(error) => self.fail(
                        span,
                        format!(
                            "{path}: invalid UTF-8 at byte {}",
                            error.valid_up_to()
                        ),
                    ),
                }
            })());
        }
        if !matches!(path[1].as_str(), "yaml" | "toml")
            || !matches!(
                path[2].as_str(),
                "encode" | "decode" | "document" | "patch"
            )
        {
            return None;
        }
        let format = path[1].clone();
        let operation = path[2].clone();
        Some((|| {
            let function = self.index.functions[&item];
            let parameter = self
                .index
                .local(function.type_parameters[0].name.span)
                .ok_or(Halt)?;
            let schema = supplied.get(&parameter).ok_or(Halt)?.clone();
            self.validate_config_schema(&schema, span, 0, &mut BTreeSet::new())?;
            match operation.as_str() {
                "encode" => {
                    let value = values.pop().ok_or(Halt)?;
                    let mut data = self.config_data(&value, span, 0)?;
                    prune_absent_options(&mut data);
                    let text = encode_data(&format, &data).map_err(|message| {
                        self.error(span, message);
                        Halt
                    })?;
                    self.expand(text.len(), span)?;
                    self.config_text(text, span)
                }
                "decode" | "document" => {
                    let Some(Value::Nominal {
                        value: PrimitiveValue::Str(text),
                        ..
                    }) = values.pop()
                    else {
                        return self.fail(span, "configuration expects text");
                    };
                    self.charge_steps(text.len(), span)?;
                    self.expand(text.len().saturating_mul(32), span)?;
                    let data =
                        parse_data(&format, &text, self.limits.max_depth).map_err(|message| {
                            self.config_error(&text, span, message);
                            Halt
                        })?;
                    let diagnostic_start = self.diagnostics.len();
                    let value = self.config_value(
                        &schema,
                        &data,
                        operation == "document",
                        "$",
                        span,
                        0,
                    );
                    self.config_context(&text, diagnostic_start);
                    let value = value?;
                    if operation == "decode" {
                        Ok(value)
                    } else {
                        self.config_document(item, &schema, text, value, span)
                    }
                }
                "patch" => {
                    let changes = values.pop().ok_or(Halt)?;
                    let Some(Value::Struct {
                        fields,
                        ..
                    }) = values.pop()
                    else {
                        return self.fail(span, "patch requires a document");
                    };
                    let text = fields.into_iter().find_map(|(name, value)| {
                        if name == "text" {
                            Some(value)
                        } else {
                            None
                        }
                    });
                    let Some(Value::Nominal {
                        value: PrimitiveValue::Str(text),
                        ..
                    }) = text
                    else {
                        return self.fail(span, "document text is unavailable");
                    };
                    let changes = self.config_data(&changes, span, 0)?;
                    let Some(changes) = changes.as_object() else {
                        return self.fail(span, "patch requires a record");
                    };
                    self.expand(text.len().saturating_mul(32), span)?;
                    self.charge_steps(text.len(), span)?;
                    let updated = patch_data(&format, &text, changes).map_err(|message| {
                        self.error(span, message);
                        Halt
                    })?;
                    self.expand(updated.len(), span)?;
                    let data = parse_data(&format, &updated, self.limits.max_depth).map_err(
                        |message| {
                            self.error(span, message);
                            Halt
                        },
                    )?;
                    let value = self.config_value(&schema, &data, true, "$", span, 0)?;
                    self.config_document(item, &schema, updated, value, span)
                }
                _ => unreachable!(),
            }
        })())
    }

    fn config_error(&mut self, text: &str, span: Span, message: String) {
        let start = self.diagnostics.len();
        self.error(span, message);
        self.config_context(text, start);
    }

    fn config_context(&mut self, text: &str, start: usize) {
        let origin = self
            .environment
            .assets
            .iter()
            .find(|(_, bytes)| bytes.as_ref() == text.as_bytes())
            .map_or("<configuration>", |((_, path), _)| path.as_str());
        for diagnostic in &mut self.diagnostics[start..] {
            // Typed errors carry an external field path. Keep the .srx call span
            // and add the asset position so both CLI and editor can show context.
            let key = diagnostic
                .message
                .strip_prefix("$.")
                .and_then(|message| message.split(':').next())
                .and_then(|path| path.rsplit('.').next());
            let position = key.and_then(|key| {
                text.lines().enumerate().find_map(|(line, text)| {
                    let text_start = text.trim_start();
                    let key_text = text_start
                        .split([':', '='])
                        .next()?
                        .trim()
                        .trim_matches(['\"', '\'']);
                    (key_text == key).then_some((line + 1, text.len() - text_start.len() + 1))
                })
            });
            let location = position.map_or_else(
                || origin.to_owned(),
                |(line, column)| format!("{origin}:{line}:{column}"),
            );
            diagnostic.message = format!("{location}: {}", diagnostic.message);
        }
    }

    fn config_text(&mut self, text: String, span: Span) -> Eval<Value> {
        self.charge_steps(self.index.primitives.len(), span)?;
        let item = self
            .index
            .primitives
            .keys()
            .copied()
            .find(|item| {
                self.index.identity(*item).is_some_and(|id| {
                    id.domain() == SourceDomainId::standard_library()
                        && id
                            .path()
                            .last()
                            .is_some_and(|p| p == "ConfigText")
                })
            })
            .ok_or(Halt)?;
        self.construct_primitive(item, PrimitiveValue::Str(text), span, true)
    }

    fn config_document(
        &mut self,
        operation: ItemId,
        schema: &Ty,
        text: String,
        data: Value,
        span: Span,
    ) -> Eval<Value> {
        let identity = self.index.identity(operation).ok_or(Halt)?;
        self.charge_steps(self.index.structures.len(), span)?;
        let document = self
            .index
            .structures
            .keys()
            .copied()
            .find(|item| {
                self.index.identity(*item).is_some_and(|id| {
                    id.domain() == identity.domain()
                        && id.path().len() == 3
                        && id.path()[..2] == identity.path()[..2]
                        && id.path()[2] == "Document"
                })
            })
            .ok_or(Halt)?;
        let text = self.config_text(text, span)?;
        Ok(Value::Struct {
            ty: self.canonical_ty(
                &Ty::Specialization {
                    template: document,
                    arguments: vec![schema.clone()],
                },
                &BTreeMap::new(),
                span,
            )?,
            fields: vec![
                ("text".into(), text),
                ("data".into(), data),
            ],
            owner: None,
        })
    }
}
