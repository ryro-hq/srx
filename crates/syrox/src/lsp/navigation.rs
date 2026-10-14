use serde_json::{Value, json};
use syrox_lang::{
    analysis::AnalysisCancellation, analysis::SemanticAnalysis, checker::Ty, line_index::LineIndex,
    source::SourceId,
};

use super::{
    Server,
    features::{location, range},
    worker::ResultSet,
};

impl Server {
    pub(super) fn navigate(
        &self,
        method: &str,
        params: &Value,
        result: &ResultSet,
        analysis: &SemanticAnalysis,
        source: SourceId,
        offset: u32,
    ) -> Result<Value, String> {
        let cancel = AnalysisCancellation::default();
        if method == "textDocument/definition" {
            return Ok(analysis
                .definition_at(source, offset)
                .and_then(|span| {
                    let text = analysis.sources().get(span.source_id())?;
                    Some(location(
                        result.uri(span.source_id()),
                        range(&LineIndex::new(text), span, self.encoding)?,
                    ))
                })
                .unwrap_or(Value::Null));
        }
        let symbol = analysis
            .symbol_at(source, offset, &cancel)
            .map_err(|error| error.to_string())?;
        if method == "textDocument/typeDefinition" {
            return Ok((|| {
                let mut ty = analysis
                    .type_at(source, offset)
                    .or_else(|| symbol.and_then(|symbol| symbol.ty.as_ref()))?;
                while let Ty::List(inner) = ty {
                    ty = inner;
                }
                let item = match ty {
                    Ty::Nominal(id)
                    | Ty::Specialization {
                        template: id,
                        ..
                    } => analysis.items().nth(id.index())?,
                    _ => return None,
                };
                let text = analysis.sources().get(item.span().source_id())?;
                Some(location(
                    result.uri(item.span().source_id()),
                    range(&LineIndex::new(text), item.span(), self.encoding)?,
                ))
            })()
            .unwrap_or(Value::Null));
        }
        let Some(symbol) = symbol else {
            return Ok(json!([]));
        };
        let highlights = method == "textDocument/documentHighlight";
        let include_declaration =
            highlights || params["context"]["includeDeclaration"].as_bool() == Some(true);
        let mut locations = Vec::new();
        let mut indexes = std::collections::BTreeMap::new();
        for entry in analysis
            .occurrences(&cancel)
            .map_err(|error| error.to_string())?
            .iter()
            .filter(|entry| {
                entry.declaration == symbol.declaration
                    && (include_declaration || !entry.is_declaration)
                    && (!highlights || entry.span.source_id() == source)
            })
            .take(4096)
        {
            let lines = indexes
                .entry(entry.span.source_id())
                .or_insert_with(|| {
                    LineIndex::new(
                        analysis
                            .sources()
                            .get(entry.span.source_id())
                            .expect("reference source"),
                    )
                });
            let range = range(lines, entry.span, self.encoding);
            locations.push(if highlights {
                json!({"range":range,"kind":1})
            } else {
                location(
                    result.uri(entry.span.source_id()),
                    range.unwrap_or(Value::Null),
                )
            });
        }
        Ok(json!(locations))
    }
}
