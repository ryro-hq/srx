use std::collections::BTreeMap;

use super::SemanticAnalysis;
use crate::{
    analysis::AnalysisCancellation, analysis::AnalysisCancelled, checker::Elaboration,
    checker::FieldInfo, checker::Ty, resolver::LocalKind, resolver::ResolvedItemKind,
    resolver::ResolvedTarget, source::SourceId, source::Span, syntax::ItemKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticSymbolKind {
    Namespace,
    Type,
    Struct,
    Enum,
    Variant,
    Function,
    Variable,
    Parameter,
    TypeParameter,
    Field,
}

#[derive(Clone, Debug)]
pub struct SemanticSymbol {
    pub name: String,
    pub declaration: Span,
    pub kind: SemanticSymbolKind,
    pub ty: Option<Ty>,
    pub documentation: String,
}

#[derive(Clone, Copy, Debug)]
pub struct SemanticOccurrence {
    pub span: Span,
    pub declaration: Span,
    pub kind: SemanticSymbolKind,
    pub is_declaration: bool,
}

#[derive(Debug, Default)]
pub(super) struct SymbolIndex {
    pub symbols: BTreeMap<Span, SemanticSymbol>,
    pub occurrences: Vec<SemanticOccurrence>,
    members: BTreeMap<crate::resolver::ItemId, SemanticSymbol>,
    member_occurrences: BTreeMap<Span, crate::resolver::ItemId>,
    retained_text: usize,
    truncated: bool,
}

const MAX_SYMBOLS: usize = 65_536;
const MAX_OCCURRENCES: usize = 262_144;
const MAX_SYMBOL_TEXT: usize = 8 * 1024 * 1024;

impl SemanticAnalysis {
    pub fn symbols_truncated(
        &self,
        cancel: &AnalysisCancellation,
    ) -> Result<bool, AnalysisCancelled> {
        Ok(self.editor_facts_truncated() || self.symbol_index(cancel)?.truncated)
    }

    pub fn occurrences_in(
        &self,
        source: SourceId,
        cancel: &AnalysisCancellation,
    ) -> Result<&[SemanticOccurrence], AnalysisCancelled> {
        let entries = &self.symbol_index(cancel)?.occurrences;
        let start = entries.partition_point(|entry| entry.span.source_id() < source);
        let end = entries.partition_point(|entry| entry.span.source_id() <= source);
        Ok(&entries[start..end])
    }
    pub fn symbols(
        &self,
        cancel: &AnalysisCancellation,
    ) -> Result<impl Iterator<Item = &SemanticSymbol>, AnalysisCancelled> {
        let index = self.symbol_index(cancel)?;
        Ok(index
            .symbols
            .values()
            .chain(index.members.values()))
    }

    pub fn occurrences(
        &self,
        cancel: &AnalysisCancellation,
    ) -> Result<&[SemanticOccurrence], AnalysisCancelled> {
        Ok(&self.symbol_index(cancel)?.occurrences)
    }

    pub fn symbol_at(
        &self,
        source: SourceId,
        offset: u32,
        cancel: &AnalysisCancellation,
    ) -> Result<Option<&SemanticSymbol>, AnalysisCancelled> {
        let index = self.symbol_index(cancel)?;
        let found = self
            .occurrences_in(source, cancel)?
            .iter()
            .filter(|entry| {
                entry.span.source_id() == source
                    && entry.span.start() <= offset
                    && offset < entry.span.end()
            })
            .min_by_key(|entry| entry.span.end() - entry.span.start());
        Ok(found.and_then(|entry| {
            index
                .member_occurrences
                .get(&entry.span)
                .and_then(|item| index.members.get(item))
                .or_else(|| index.symbols.get(&entry.declaration))
        }))
    }

    pub fn fields_at(&self, source: SourceId, offset: u32, ty: &Ty) -> Vec<FieldInfo> {
        let Some(shape) = Ty::nominal_head(ty).and_then(|id| self.editor.shapes.get(&id)) else {
            return Vec::new();
        };
        let Some(module) = self.resolved.editor_module_at(source, offset) else {
            return Vec::new();
        };
        if !shape
            .authority
            .permits(&self.resolved, ty, module)
        {
            return Vec::new();
        }
        let arguments = match ty {
            Ty::Specialization {
                arguments,
                ..
            } => arguments.as_slice(),
            _ => &[],
        };
        let substitutions = shape
            .parameters
            .iter()
            .copied()
            .zip(arguments.iter().cloned())
            .collect();
        let mut budget = 4096;
        shape
            .fields
            .iter()
            .take(256)
            .filter_map(|field| {
                Some(FieldInfo {
                    ty: crate::checker::substitute_type(&field.ty, &substitutions, &mut budget)?,
                    ..field.clone()
                })
            })
            .collect()
    }

    /// Fields permitted in a literal constructor, including policy restrictions
    /// that do not apply to projection. Types come from checked specializations.
    pub fn construction_fields_at(&self, source: SourceId, offset: u32, ty: &Ty) -> Vec<FieldInfo> {
        if Ty::nominal_head(ty)
            .and_then(|id| self.editor.shapes.get(&id))
            .is_none_or(|shape| !shape.literal_constructor)
        {
            return Vec::new();
        }
        self.fields_at(source, offset, ty)
    }

    pub fn variants(
        &self,
        enumeration: crate::resolver::ItemId,
    ) -> impl Iterator<Item = (&str, Span)> {
        self.editor
            .shapes
            .get(&enumeration)
            .into_iter()
            .flat_map(|shape| {
                shape
                    .variants
                    .iter()
                    .map(|(name, span, _)| (name.as_str(), *span))
            })
    }

    pub fn output_type(&self, id: crate::resolver::ItemId) -> Option<&Ty> {
        self.editor.outputs.get(&id)
    }

    fn symbol_index(
        &self,
        cancel: &AnalysisCancellation,
    ) -> Result<&SymbolIndex, AnalysisCancelled> {
        cancel.check()?;
        if let Some(index) = self.symbols.get() {
            return Ok(index);
        }
        let mut index = SymbolIndex::default();
        self.index_declarations(&mut index, cancel)?;
        self.index_references(&mut index, cancel)?;
        index.occurrences.sort_by_key(|entry| {
            (
                entry.span.source_id(),
                entry.span.start(),
                entry.span.end(),
            )
        });
        index
            .occurrences
            .dedup_by_key(|entry| (entry.span, entry.declaration));
        cancel.check()?;
        let _ = self.symbols.set(index);
        Ok(self
            .symbols
            .get()
            .expect("symbol index initialized"))
    }

    fn index_declarations(
        &self,
        index: &mut SymbolIndex,
        cancel: &AnalysisCancellation,
    ) -> Result<(), AnalysisCancelled> {
        for item in self.items() {
            cancel.check()?;
            if let Some(member) = self.resolved.published_member(item.id()) {
                if let Some(origin) = self.items().nth(member.factory().index()) {
                    index.add_member(
                        item.id(),
                        item.path()
                            .segments()
                            .last()
                            .cloned()
                            .unwrap_or_default(),
                        origin.span(),
                        self.output_type(item.id()).cloned(),
                        self.documentation_before(origin.span()),
                    );
                }
                continue;
            }
            let kind = match item.kind() {
                ResolvedItemKind::Function => SemanticSymbolKind::Function,
                ResolvedItemKind::Struct => SemanticSymbolKind::Struct,
                ResolvedItemKind::Enum => SemanticSymbolKind::Enum,
                ResolvedItemKind::OutputValue => SemanticSymbolKind::Variable,
                _ => SemanticSymbolKind::Type,
            };
            index.add(
                item.path()
                    .segments()
                    .last()
                    .cloned()
                    .unwrap_or_default(),
                item.span(),
                kind,
                self.function_type(item.id())
                    .or_else(|| self.output_type(item.id()))
                    .cloned(),
                self.documentation_before(item.span()),
            );
        }
        for local in self.locals() {
            cancel.check()?;
            let kind = match local.kind() {
                LocalKind::Parameter => SemanticSymbolKind::Parameter,
                LocalKind::TypeParameter => SemanticSymbolKind::TypeParameter,
                _ => SemanticSymbolKind::Variable,
            };
            let ty = self.local_type(local.id()).cloned().or_else(|| {
                (local.kind() == LocalKind::TypeParameter).then_some(Ty::Parameter(local.id()))
            });
            index.add(
                local.name().into(),
                local.span(),
                kind,
                ty,
                String::new(),
            );
        }
        for (id, shape) in &self.editor.shapes {
            cancel.check()?;
            for field in &shape.fields {
                cancel.check()?;
                index.add(
                    field.name.clone(),
                    field.declaration,
                    SemanticSymbolKind::Field,
                    Some(field.ty.clone()),
                    self.documentation_before(field.declaration),
                );
            }
            for (name, span, payload) in &shape.variants {
                cancel.check()?;
                let result = if shape.parameters.is_empty() {
                    Ty::Nominal(*id)
                } else {
                    Ty::Specialization {
                        template: *id,
                        arguments: shape
                            .parameters
                            .iter()
                            .map(|id| Ty::Parameter(*id))
                            .collect(),
                    }
                };
                let ty = if payload.is_empty() {
                    result
                } else {
                    Ty::Function {
                        parameters: payload.clone(),
                        result: Box::new(result),
                        once: false,
                    }
                };
                index.add(
                    name.clone(),
                    *span,
                    SemanticSymbolKind::Variant,
                    Some(ty),
                    self.documentation_before(*span),
                );
            }
        }
        Ok(())
    }

    fn index_references(
        &self,
        index: &mut SymbolIndex,
        cancel: &AnalysisCancellation,
    ) -> Result<(), AnalysisCancelled> {
        // Module declarations can be repeated; each remains a navigable symbol.
        for file in self.resolved.parsed().iter() {
            let mut pending: Vec<_> = file.program().items.iter().collect();
            while let Some(item) = pending.pop() {
                cancel.check()?;
                if let ItemKind::Module(module) = &item.kind {
                    for part in &module.path.segments {
                        index.add(
                            part.text.clone(),
                            part.span,
                            SemanticSymbolKind::Namespace,
                            None,
                            String::new(),
                        );
                    }
                    pending.extend(&module.items);
                }
            }
        }
        for reference in self.references() {
            cancel.check()?;
            let target = match reference.target() {
                ResolvedTarget::Item(id) => {
                    let origin = self
                        .resolved
                        .published_member(*id)
                        .map_or(*id, crate::resolver::PublishedMember::factory);
                    self.items()
                        .nth(origin.index())
                        .map(crate::resolver::ResolvedItem::span)
                }
                ResolvedTarget::Local(id) => self
                    .locals()
                    .nth(id.index())
                    .map(crate::resolver::ResolvedLocal::span),
                ResolvedTarget::EnumVariant {
                    enumeration,
                    index: variant,
                } => self
                    .editor
                    .shapes
                    .get(enumeration)
                    .and_then(|shape| shape.variants.get(*variant as usize))
                    .map(|(_, span, _)| *span),
                _ => None,
            };
            if let Some(target) = target {
                let span = if reference.kind() == crate::resolver::ReferenceKind::Interpolation {
                    self.first_name(reference.span())
                } else {
                    self.last_name(reference.span())
                };
                if let ResolvedTarget::Item(item) = reference.target()
                    && self.resolved.published_member(*item).is_some()
                {
                    index.member_reference(span, *item);
                } else {
                    index.reference(span, target);
                }
            }
        }
        for pattern in &self.editor.patterns {
            cancel.check()?;
            if let Some((_, declaration, _)) = self
                .editor
                .shapes
                .get(&pattern.enumeration())
                .and_then(|shape| shape.variants.get(pattern.index() as usize))
            {
                index.reference(self.last_name(pattern.span()), *declaration);
            }
        }
        for expression in self.expressions.iter() {
            cancel.check()?;
            if let Some(Elaboration::ContextualVariant {
                enumeration,
                index: variant,
            }) = expression.elaboration()
                && let Some((_, declaration, _)) = self
                    .editor
                    .shapes
                    .get(enumeration)
                    .and_then(|shape| shape.variants.get(*variant as usize))
            {
                // Constructor calls have an expression span including arguments.
                index.reference(self.first_name(expression.span()), *declaration);
            }
        }
        for (span, declaration, _) in &self.editor.fields {
            cancel.check()?;
            index.reference(*span, *declaration);
        }
        Ok(())
    }

    fn first_name(&self, span: Span) -> Span {
        let text = &self
            .sources
            .get(span.source_id())
            .expect("registered source")
            .text()[span.range()];
        let length = text
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        Span::new(
            span.source_id(),
            span.start(),
            span.start() + u32::try_from(length).expect("bounded source"),
        )
    }
    fn last_name(&self, span: Span) -> Span {
        let text = &self
            .sources
            .get(span.source_id())
            .expect("registered source")
            .text()[span.range()];
        let length = text
            .bytes()
            .rev()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        Span::new(
            span.source_id(),
            span.end() - u32::try_from(length).expect("bounded source"),
            span.end(),
        )
    }

    fn documentation_before(&self, span: Span) -> String {
        let Some(source) = self.sources.get(span.source_id()) else {
            return String::new();
        };
        let before = &source.text()[..span.start() as usize];
        let Some(line) = before.rfind('\n') else {
            return String::new();
        };
        let mut lines = Vec::new();
        for line in before[..line].lines().rev().take(32) {
            let Some(comment) = line.trim().strip_prefix("//") else {
                break;
            };
            lines.push(
                comment
                    .strip_prefix('/')
                    .unwrap_or(comment)
                    .trim()
                    .chars()
                    .take(256)
                    .collect::<String>(),
            );
        }
        lines.reverse();
        lines.join("\n")
    }
}

impl SymbolIndex {
    fn add_member(
        &mut self,
        item: crate::resolver::ItemId,
        name: String,
        declaration: Span,
        ty: Option<Ty>,
        documentation: String,
    ) {
        let bytes = name.len().saturating_add(documentation.len());
        if self
            .symbols
            .len()
            .saturating_add(self.members.len())
            >= MAX_SYMBOLS
            || bytes > MAX_SYMBOL_TEXT.saturating_sub(self.retained_text)
        {
            self.truncated = true;
            return;
        }
        self.retained_text += bytes;
        self.members.insert(
            item,
            SemanticSymbol {
                name,
                declaration,
                kind: SemanticSymbolKind::Variable,
                ty,
                documentation,
            },
        );
    }

    fn member_reference(&mut self, span: Span, item: crate::resolver::ItemId) {
        if self.occurrences.len() >= MAX_OCCURRENCES {
            self.truncated = true;
            return;
        }
        if span.start() == span.end() {
            return;
        }
        if let Some(symbol) = self.members.get(&item) {
            self.occurrences.push(SemanticOccurrence {
                span,
                declaration: symbol.declaration,
                kind: symbol.kind,
                is_declaration: false,
            });
            self.member_occurrences.insert(span, item);
        }
    }

    fn add(
        &mut self,
        name: String,
        declaration: Span,
        kind: SemanticSymbolKind,
        ty: Option<Ty>,
        documentation: String,
    ) {
        let bytes = name.len().saturating_add(documentation.len());
        if self.symbols.len() >= MAX_SYMBOLS
            || self.occurrences.len() >= MAX_OCCURRENCES
            || bytes > MAX_SYMBOL_TEXT.saturating_sub(self.retained_text)
        {
            self.truncated = true;
            return;
        }
        self.retained_text += bytes;
        self.symbols.insert(
            declaration,
            SemanticSymbol {
                name,
                declaration,
                kind,
                ty,
                documentation,
            },
        );
        self.occurrences.push(SemanticOccurrence {
            span: declaration,
            declaration,
            kind,
            is_declaration: true,
        });
    }
    fn reference(&mut self, span: Span, declaration: Span) {
        if self.occurrences.len() >= MAX_OCCURRENCES {
            self.truncated = true;
            return;
        }
        if span.start() == span.end() {
            return;
        }
        if let Some(symbol) = self.symbols.get(&declaration) {
            self.occurrences.push(SemanticOccurrence {
                span,
                declaration,
                kind: symbol.kind,
                is_declaration: false,
            });
        }
    }
}
