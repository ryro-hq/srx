//! Conservative, inspection-only relocation. Successful coordinate conversion
//! does not replay work/metadata costs or shared generic-instance deduplication.
use super::SemanticAnalysis;
use crate::checker::FactMapper;
use crate::{
    analysis::AnalysisCancellation, analysis::AnalysisCancelled, checker::CanonicalItemIdentity,
    checker::OwnerCheckedFacts, resolver::ItemId, resolver::LocalId, resolver::OwnerSourceMap,
    resolver::ResolutionOwnerKey, source::Span,
};
use std::collections::{BTreeMap, BTreeSet};

struct Coordinates<'a> {
    old: &'a SemanticAnalysis,
    new: &'a SemanticAnalysis,
    cancel: &'a AnalysisCancellation,
    owners: Vec<(&'a ResolutionOwnerKey, Span, Option<usize>)>,
    items: BTreeMap<CanonicalItemIdentity, Option<ItemId>>,
    maps: BTreeMap<ResolutionOwnerKey, (OwnerSourceMap, OwnerSourceMap)>,
    locals: BTreeMap<LocalId, LocalId>,
    units: usize,
    bytes: usize,
}

impl SemanticAnalysis {
    /// Relocate the ordered effect journal independently of inspection facts.
    /// Replay requires the receiver's prefix state and remains simulation-only.
    pub fn remap_body_effects_from(
        &self,
        previous: &Self,
        key: &ResolutionOwnerKey,
        cancel: &AnalysisCancellation,
    ) -> Result<Option<crate::checker::BodyEffects>, AnalysisCancelled> {
        if !self.body_dependencies_match(previous, key, cancel)? {
            return Ok(None);
        }
        let result = (|| {
            let mut map = Coordinates::new(
                previous,
                self,
                key,
                cancel,
                262_144,
                8 * 1024 * 1024,
            )?;
            map.publication(key)?
                .effects
                .as_ref()?
                .remap(&mut map)
        })();
        cancel.check()?;
        Ok(result)
    }

    fn body_dependencies_match(
        &self,
        previous: &Self,
        key: &ResolutionOwnerKey,
        cancel: &AnalysisCancellation,
    ) -> Result<bool, AnalysisCancelled> {
        cancel.check()?;
        if previous.bodies.truncated || self.bodies.truncated || previous.policy != self.policy {
            return Ok(false);
        }
        let Some(before) = previous.owner_type_dependencies(key, cancel)? else {
            return Ok(false);
        };
        let Some(after) = self.owner_type_dependencies(key, cancel)? else {
            return Ok(false);
        };
        Ok(before == after)
    }

    /// Relocate a previous body's inspection facts into this snapshot. Guards are
    /// intentionally conservative (including exact text of external span owners).
    /// This never installs facts or bypasses checking. `None` means unavailable,
    /// changed dependencies, ambiguous identity, truncation or budget exhaustion.
    pub fn remap_checked_body_from(
        &self,
        previous: &Self,
        key: &ResolutionOwnerKey,
        cancel: &AnalysisCancellation,
    ) -> Result<Option<OwnerCheckedFacts>, AnalysisCancelled> {
        self.remap_checked_body_bounded(previous, key, cancel, 262_144, 8 * 1024 * 1024)
    }

    fn remap_checked_body_bounded(
        &self,
        previous: &Self,
        key: &ResolutionOwnerKey,
        cancel: &AnalysisCancellation,
        units: usize,
        bytes: usize,
    ) -> Result<Option<OwnerCheckedFacts>, AnalysisCancelled> {
        if !self.body_dependencies_match(previous, key, cancel)? {
            return Ok(None);
        }
        let result = (|| {
            let mut map = Coordinates::new(previous, self, key, cancel, units, bytes)?;
            let body = map.publication(key)?;
            Some(OwnerCheckedFacts {
                diagnostics: previous
                    .body_diagnostics
                    .get(body.diagnostics.clone())?
                    .iter()
                    .map(|value| map.diagnostic(value))
                    .collect::<Option<_>>()?,
                expressions: previous
                    .expressions
                    .get(body.expressions.clone())?
                    .iter()
                    .map(|value| map.expression(value))
                    .collect::<Option<_>>()?,
                patterns: previous
                    .editor
                    .patterns
                    .get(body.patterns.clone())?
                    .iter()
                    .map(|value| map.pattern(value))
                    .collect::<Option<_>>()?,
                locals: body
                    .locals
                    .iter()
                    .map(|id| {
                        let value = map.binding(previous.editor.locals.get(id)?)?;
                        Some((value.id, value))
                    })
                    .collect::<Option<_>>()?,
                ownership: previous
                    .editor
                    .uses
                    .get(body.uses.clone())?
                    .iter()
                    .map(|value| map.ownership(value))
                    .collect::<Option<_>>()?,
                fields: previous
                    .editor
                    .fields
                    .get(body.fields.clone())?
                    .iter()
                    .map(|(span, declaration, ty)| {
                        Some((
                            map.span(*span)?,
                            map.span(*declaration)?,
                            map.ty(ty)?,
                        ))
                    })
                    .collect::<Option<_>>()?,
                arguments: previous
                    .editor
                    .arguments
                    .get(body.arguments.clone())?
                    .iter()
                    .map(|value| map.argument(value))
                    .collect::<Option<_>>()?,
                outputs: body
                    .outputs
                    .iter()
                    .map(|id| {
                        Some((
                            map.item(*id)?,
                            map.ty(previous.editor.outputs.get(id)?)?,
                        ))
                    })
                    .collect::<Option<_>>()?,
            })
        })();
        cancel.check()?;
        Ok(result)
    }
}

impl<'a> Coordinates<'a> {
    fn new(
        old: &'a SemanticAnalysis,
        new: &'a SemanticAnalysis,
        key: &ResolutionOwnerKey,
        cancel: &'a AnalysisCancellation,
        units: usize,
        bytes: usize,
    ) -> Option<Self> {
        let mut map = Self {
            old,
            new,
            cancel,
            owners: Vec::new(),
            items: BTreeMap::new(),
            maps: BTreeMap::new(),
            locals: BTreeMap::new(),
            units,
            bytes,
        };
        map.initialize()?;
        map.ensure_owner(key)?;
        Some(map)
    }
    fn publication(
        &mut self,
        key: &ResolutionOwnerKey,
    ) -> Option<&'a crate::checker::BodyPublication> {
        let current_span = self.maps.get(key)?.1.span();
        let mut current = None;
        for body in &self.new.bodies.entries {
            self.reserve(0)?;
            if body.anchor.source_id() == current_span.source_id()
                && current_span.start() <= body.anchor.start()
                && body.anchor.end() <= current_span.end()
            {
                if current.is_some() || !body.complete {
                    return None;
                }
                current = Some(body);
            }
        }
        current?;
        let mut publication = None;
        for candidate in &self.old.bodies.entries {
            self.reserve(0)?;
            if self.span_owner(candidate.anchor) == Some(key) {
                if publication.is_some() || !candidate.complete {
                    return None;
                }
                publication = Some(candidate);
            }
        }
        publication
    }

    fn initialize(&mut self) -> Option<()> {
        if self.old.sources.input_domains() != self.new.sources.input_domains()
            || self.old.sources.project_roots() != self.new.sources.project_roots()
        {
            return None;
        }
        let mut topologies = Vec::new();
        for analysis in [self.old, self.new] {
            let mut topology = BTreeSet::new();
            for (id, source) in analysis.sources.iter() {
                self.reserve(0)?;
                let identity = (
                    analysis.sources.domain(id)?,
                    analysis.sources.module(id)?,
                    source.name(),
                );
                if !topology.insert(identity) {
                    return None;
                }
            }
            topologies.push(topology);
        }
        if topologies[0] != topologies[1] {
            return None;
        }
        for (key, span) in self.old.resolution_owners() {
            self.reserve(0)?;
            self.owners.push((key, span, None));
        }
        self.owners.sort_by_key(|(_, span, _)| {
            (
                span.source_id(),
                span.start(),
                std::cmp::Reverse(span.end()),
            )
        });
        let mut stack: Vec<usize> = Vec::new();
        for index in 0..self.owners.len() {
            self.reserve(0)?;
            let span = self.owners[index].1;
            while let Some(&parent) = stack.last() {
                let outer = self.owners[parent].1;
                if outer.source_id() == span.source_id()
                    && outer.start() <= span.start()
                    && span.end() <= outer.end()
                {
                    if outer == span {
                        return None;
                    }
                    break;
                }
                stack.pop();
            }
            self.owners[index].2 = stack.last().copied();
            stack.push(index);
        }
        for item in self.new.items() {
            for segment in item.path().segments() {
                self.reserve(segment.len())?;
            }
            self.reserve(0)?;
            let identity = CanonicalItemIdentity::from_resolved(item);
            self.items
                .entry(identity)
                .and_modify(|entry| *entry = None)
                .or_insert(Some(item.id()));
        }
        Some(())
    }

    fn span_owner(&mut self, span: Span) -> Option<&'a ResolutionOwnerKey> {
        let mut index = self
            .owners
            .partition_point(|(_, owner, _)| {
                (owner.source_id(), owner.start()) <= (span.source_id(), span.start())
            })
            .checked_sub(1)?;
        loop {
            self.reserve(0)?;
            let (key, owner, parent) = self.owners[index];
            if owner.source_id() == span.source_id()
                && owner.start() <= span.start()
                && span.end() <= owner.end()
            {
                return Some(key);
            }
            index = parent?;
        }
    }

    fn ensure_owner(&mut self, key: &ResolutionOwnerKey) -> Option<()> {
        self.reserve(0)?;
        if self.maps.contains_key(key) {
            return Some(());
        }
        let old = self
            .old
            .owner_resolution(key, self.cancel)
            .ok()??;
        let new = self
            .new
            .owner_resolution(key, self.cancel)
            .ok()??;
        let old_span = old.source_map.span();
        let new_span = new.source_map.span();
        let old_text = self
            .old
            .sources
            .get(old_span.source_id())?
            .text()
            .get(old_span.range())?;
        let new_text = self
            .new
            .sources
            .get(new_span.source_id())?
            .text()
            .get(new_span.range())?;
        if old_text != new_text
            || !old.namespace_dependencies_complete
            || !new.namespace_dependencies_complete
            || old.locals != new.locals
            || old.references != new.references
            || old.diagnostics != new.diagnostics
            || old.namespace_dependencies != new.namespace_dependencies
        {
            return None;
        }
        for ordinal in 0..old.locals.len() {
            self.reserve(0)?;
            let ordinal = u32::try_from(ordinal).ok()?;
            self.locals.insert(
                old.source_map.local(ordinal)?,
                new.source_map.local(ordinal)?,
            );
        }
        for part in &key.path {
            self.reserve(part.len())?;
        }
        self.maps
            .insert(key.clone(), (old.source_map, new.source_map));
        Some(())
    }
}

impl FactMapper for Coordinates<'_> {
    fn reference_scan(&mut self, references: &[Span]) -> Option<std::sync::Arc<[Span]>> {
        if references.len() != self.new.references().len() {
            return None;
        }
        let mut mapped = Vec::new();
        for (span, current) in references.iter().zip(self.new.references()) {
            let span = self.span(*span)?;
            if span != current.span() {
                return None;
            }
            mapped.push(span);
        }
        Some(mapped.into())
    }
    fn reserve(&mut self, bytes: usize) -> Option<()> {
        self.cancel.check().ok()?;
        self.units = self.units.checked_sub(1)?;
        self.bytes = self.bytes.checked_sub(bytes)?;
        Some(())
    }

    fn span(&mut self, span: Span) -> Option<Span> {
        self.reserve(0)?;
        let key = self.span_owner(span)?;
        self.ensure_owner(key)?;
        let (old, new) = self.maps.get(key)?;
        new.absolute_span(old.relative_span(span)?)
    }

    fn item(&mut self, id: ItemId) -> Option<ItemId> {
        self.reserve(0)?;
        let old = self.old.items().nth(id.index())?;
        for segment in old.path().segments() {
            self.reserve(segment.len())?;
        }
        let identity = CanonicalItemIdentity::from_resolved(old);
        let new = (*self.items.get(&identity)?)?;
        (self.new.items().nth(new.index())?.kind() == old.kind()).then_some(new)
    }

    fn local(&mut self, id: LocalId) -> Option<LocalId> {
        self.reserve(0)?;
        if let Some(mapped) = self.locals.get(&id) {
            return Some(*mapped);
        }
        let span = self.old.locals().nth(id.index())?.span();
        let key = self.span_owner(span)?;
        self.ensure_owner(key)?;
        self.locals.get(&id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::AnalysisHost, checker::CheckPolicy, resolver::ResolutionOwnerPart,
        source::SourceDomainId, source::SourceSet,
    };

    fn analyze(files: &[(&str, &str)]) -> SemanticAnalysis {
        analyze_with(files, &CheckPolicy::default())
    }

    fn analyze_with(files: &[(&str, &str)], policy: &CheckPolicy) -> SemanticAnalysis {
        let mut sources = SourceSet::new();
        for (name, text) in files {
            sources.add(*name, *text).unwrap();
        }
        AnalysisHost::default()
            .snapshot()
            .analyze_project(
                &sources,
                &BTreeMap::new(),
                policy,
                &AnalysisCancellation::default(),
            )
            .unwrap()
    }

    fn key(name: &str) -> ResolutionOwnerKey {
        ResolutionOwnerKey {
            domain: SourceDomainId::project(),
            path: vec![name.into()],
            part: ResolutionOwnerPart::Declaration,
        }
    }

    fn cold(analysis: &SemanticAnalysis, key: &ResolutionOwnerKey) -> OwnerCheckedFacts {
        let owner = analysis
            .owner_resolution(key, &AnalysisCancellation::default())
            .unwrap()
            .unwrap();
        let span = owner.source_map.span();
        let body = analysis
            .bodies
            .entries
            .iter()
            .find(|body| {
                body.anchor.source_id() == span.source_id()
                    && body.anchor.start() >= span.start()
                    && body.anchor.end() <= span.end()
            })
            .unwrap();
        OwnerCheckedFacts {
            diagnostics: analysis.body_diagnostics[body.diagnostics.clone()].to_vec(),
            expressions: analysis.expressions[body.expressions.clone()].to_vec(),
            patterns: analysis.editor.patterns[body.patterns.clone()].to_vec(),
            locals: body
                .locals
                .iter()
                .map(|id| (*id, analysis.editor.locals[id].clone()))
                .collect(),
            ownership: analysis.editor.uses[body.uses.clone()].to_vec(),
            fields: analysis.editor.fields[body.fields.clone()].to_vec(),
            arguments: analysis.editor.arguments[body.arguments.clone()].to_vec(),
            outputs: body
                .outputs
                .iter()
                .map(|id| (*id, analysis.editor.outputs[id].clone()))
                .collect(),
        }
    }

    #[test]
    fn relocated_bodies_match_every_cold_fact_after_ids_and_offsets_move() {
        let text = r"
        value I(int); resource R(int);
        enum Choice<T> { Left(T), Right(T) }
        struct Box<T> { payload: T; }
        struct Defaults<T> { make: fn(T) -> T = fn(x: T) -> T { x }; }
        fn identity<T>(x: T) -> T { x }
        fn inspect(x: Choice<R>) -> R { match x { Left(y) => y, Right(y) => y } }
        fn capture(r: R) -> R { let f = once fn() -> R { r }; f() }
        fn bad(r: R) { r; r; }
        fn fields(x: Box<I>) -> I { identity(x.payload) }
        outputs { result: I = fields(Box<I> { payload = I(1); }); }
    ";
        let before = analyze(&[("main.srx", text)]);
        let changed = format!(
            "// déplacement é 🦀\nvalue Before(int); fn earlier<T>(x: T) -> T {{ let y=x; y }}\n{text}"
        );
        let after = analyze(&[("main.srx", &changed)]);
        let mut keys = vec![
            key("inspect"),
            key("capture"),
            key("bad"),
            key("fields"),
            key("result"),
        ];
        keys.push(ResolutionOwnerKey {
            part: ResolutionOwnerPart::FieldDefault("make".into()),
            ..key("Defaults")
        });
        for key in &keys {
            let mapped = after
                .remap_checked_body_from(&before, key, &AnalysisCancellation::default())
                .unwrap()
                .unwrap();
            assert_eq!(mapped, cold(&after, key), "{key:?}");
            assert_ne!(mapped, cold(&before, key), "{key:?}");
        }
        assert!(!cold(&after, &key("inspect")).patterns.is_empty());
        assert!(!cold(&after, &key("bad")).diagnostics.is_empty());
        assert!(
            cold(&after, &key("capture"))
                .ownership
                .iter()
                .any(|usage| usage.closure.is_some())
        );
        assert!(!cold(&after, &key("fields")).fields.is_empty());
        assert!(!cold(&after, &key("fields")).arguments.is_empty());
        assert!(!cold(&after, &key("result")).outputs.is_empty());
    }

    #[test]
    fn reordered_sources_relocate_external_field_and_parameter_spans() {
        let main = "fn inspect(x: lib::Box) -> lib::I { lib::identity(x.payload) }";
        let lib = "mod lib { pub value I(int); pub struct Box { payload: I; } pub fn identity<T>(x: T) -> T { x } }";
        let before = analyze(&[("main.srx", main), ("lib.srx", lib)]);
        assert!(
            before.diagnostics().is_empty(),
            "{:?}",
            before.diagnostics()
        );
        let changed = format!("// é\n{lib}");
        let after = analyze(&[
            ("lib.srx", &changed),
            ("main.srx", main),
        ]);
        let key = key("inspect");
        let mapped = after
            .remap_checked_body_from(&before, &key, &AnalysisCancellation::default())
            .unwrap()
            .unwrap();
        assert_eq!(mapped, cold(&after, &key));
        assert!(!mapped.fields.is_empty() && !mapped.arguments.is_empty());
        assert_ne!(mapped, cold(&before, &key));
    }

    #[test]
    fn recovered_bodies_keep_unknown_status_and_movement_diagnostics() {
        let text = "value I(int); resource R(int); fn inspect(r: R) { let missing: I = ; let later=I(2); r; r; }";
        let before = analyze(&[("main.srx", text)]);
        let changed = format!("fn earlier() {{}} {text}");
        let after = analyze(&[("main.srx", &changed)]);
        let key = key("inspect");
        let mapped = after
            .remap_checked_body_from(&before, &key, &AnalysisCancellation::default())
            .unwrap()
            .unwrap();
        assert_eq!(mapped, cold(&after, &key));
        assert!(!mapped.locals.is_empty());
        assert!(
            mapped
                .locals
                .values()
                .any(|local| local.status != crate::checker::TypeStatus::Known)
        );
    }

    #[test]
    fn elaborations_discovery_and_erasure_relocate_all_embedded_identities() {
        let text = r"
        value I(int); value Key(str); enum Mode { Fast, Slow }
        enum Choice<T> { Left(T), Right(T) }
        struct Box<T> { n: I; hidden: T; } struct Public { n: I; }
        mod collection { pub fn make() -> I { I(1) } }
        fn identity<T>(x: T) -> T { x }
        outputs {
            keys: [Key] = module_exports(collection, make, fn(key: Key, make: fn() -> I) -> Key { key });
            p: Public = erase<Public>(Box<I> { n = 1; hidden = 2; });
            mode: Mode = Fast;
            choice: Choice<I> = Choice::Left<I>(I(1));
            result: I = identity(I(2));
        }
    ";
        let identity =
            |name| CanonicalItemIdentity::new(SourceDomainId::project(), [name]).unwrap();
        let policy = CheckPolicy::default()
            .with_erasure(identity("Box"), identity("Public"))
            .unwrap();
        let before = analyze_with(&[("main.srx", text)], &policy);
        assert!(
            before.diagnostics().is_empty(),
            "{:?}",
            before.diagnostics()
        );
        let changed = format!("value Earlier(int); fn prior(x: Earlier) {{}} {text}");
        let after = analyze_with(&[("main.srx", &changed)], &policy);
        let mut kinds = BTreeSet::new();
        for name in ["keys", "p", "mode", "choice", "result"] {
            let mapped = after
                .remap_checked_body_from(
                    &before,
                    &key(name),
                    &AnalysisCancellation::default(),
                )
                .unwrap()
                .unwrap();
            assert_eq!(mapped, cold(&after, &key(name)));
            for expression in mapped.expressions {
                if let Some(elaboration) = expression.elaboration() {
                    kinds.insert(match elaboration {
                        crate::checker::Elaboration::ModuleExports {
                            ..
                        } => 0,
                        crate::checker::Elaboration::VariantConstructor {
                            ..
                        } => 1,
                        crate::checker::Elaboration::FunctionSpecialization {
                            ..
                        } => 2,
                        crate::checker::Elaboration::ContextualVariant {
                            ..
                        } => 3,
                        crate::checker::Elaboration::ValueLiteral(_) => 4,
                        crate::checker::Elaboration::PackageSelection {
                            ..
                        } => 6,
                        crate::checker::Elaboration::Erasure {
                            ..
                        } => 5,
                    });
                }
            }
        }
        assert_eq!(kinds.len(), 6, "{kinds:?}");
        let changed_policy = policy.with_scope("new_scope").unwrap();
        let different = analyze_with(&[("main.srx", text)], &changed_policy);
        assert!(
            different
                .remap_checked_body_from(
                    &before,
                    &key("result"),
                    &AnalysisCancellation::default()
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn remapped_effects_replay_in_the_receiving_type_coordinates() {
        let text = "value I(int); struct Box<T> { payload: T; } fn inspect() { let x=Box<I> { payload=I(1); }; }";
        let before = analyze(&[("main.srx", text)]);
        let changed = format!("value Earlier(int); fn earlier(x: Earlier) {{}} {text}");
        let after = analyze(&[("main.srx", &changed)]);
        let cancel = AnalysisCancellation::default();
        let old = after
            .remap_body_effects_from(&before, &key("inspect"), &cancel)
            .unwrap()
            .unwrap();
        let cold = after
            .remap_body_effects_from(&after, &key("inspect"), &cancel)
            .unwrap()
            .unwrap();
        assert_ne!(old.entry(), cold.entry());
        assert_eq!(cold.entry().generic_instances, 0);
        let input = crate::checker::BodyReplayState {
            budget: cold.entry(),
            instances: BTreeSet::new(),
        };
        let mapped = old
            .replay(
                &input,
                crate::checker::CheckLimits::default(),
                &cancel,
            )
            .unwrap()
            .unwrap();
        let expected = cold
            .replay(
                &input,
                crate::checker::CheckLimits::default(),
                &cancel,
            )
            .unwrap()
            .unwrap();
        assert_eq!(mapped, expected);
        assert_eq!(mapped.budget, cold.exit());
        assert_eq!(mapped.instances.len(), 1);
        cancel.cancel();
        assert!(
            after
                .remap_body_effects_from(&before, &key("inspect"), &cancel)
                .is_err()
        );
    }

    #[test]
    fn remapping_limits_and_incomplete_publications_return_no_partial_facts() {
        let text = "value I(int); fn inspect(x: I) -> I { x }";
        let before = analyze(&[("main.srx", text)]);
        let key = key("inspect");
        let cancel = AnalysisCancellation::default();
        for (units, bytes) in [(0, usize::MAX), (usize::MAX, 0)] {
            assert!(
                before
                    .remap_checked_body_bounded(&before, &key, &cancel, units, bytes)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            before
                .remap_checked_body_from(&before, &key, &cancel)
                .unwrap()
                .unwrap(),
            cold(&before, &key)
        );
        let mut after = analyze(&[("main.srx", text)]);
        std::sync::Arc::get_mut(&mut after.bodies)
            .unwrap()
            .entries[0]
            .complete = false;
        assert!(
            after
                .remap_checked_body_from(&before, &key, &cancel)
                .unwrap()
                .is_none()
        );
        assert!(
            before
                .remap_checked_body_from(&after, &key, &cancel)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn changed_text_interfaces_topology_and_missing_owners_refuse_relocation() {
        let text = "value I(int); fn inspect(x: I) -> I { x }";
        let before = analyze(&[("main.srx", text)]);
        for changed in [
            text.replace("value I", "resource I"),
            text.replace("{ x }", "{ let y=x; y }"),
            text.replace("fn inspect", "fn other"),
            format!("{text} fn inspect() {{}} "),
        ] {
            let after = analyze(&[("main.srx", &changed)]);
            assert!(
                after
                    .remap_checked_body_from(
                        &before,
                        &key("inspect"),
                        &AnalysisCancellation::default()
                    )
                    .unwrap()
                    .is_none()
            );
        }
        let after = analyze(&[
            ("main.srx", text),
            ("added.srx", "fn extra() {}"),
        ]);
        assert!(
            after
                .remap_checked_body_from(
                    &before,
                    &key("inspect"),
                    &AnalysisCancellation::default()
                )
                .unwrap()
                .is_none()
        );
        let cancel = AnalysisCancellation::default();
        cancel.cancel();
        assert!(
            before
                .remap_checked_body_from(&before, &key("inspect"), &cancel)
                .is_err()
        );
    }
}
