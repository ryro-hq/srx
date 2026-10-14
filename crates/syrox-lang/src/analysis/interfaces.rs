//! Conservative declared interfaces, independent of snapshot-local IDs/offsets.
//! This is dependency evidence, not an executable or reusable checked body.
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use super::SemanticAnalysis;
use crate::{
    analysis::AnalysisCancellation, analysis::AnalysisCancelled, checker::CanonicalItemIdentity,
    checker::CheckPolicy, resolver::NamespaceDependency, resolver::NamespaceOutcome,
    resolver::OwnerReferenceTarget, resolver::OwnerResolution, resolver::ResolutionOwnerKey,
    resolver::ResolutionOwnerPart, resolver::ResolvedItemKind, source::Span, syntax::ItemKind,
    syntax::OutputKind,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceNamespaceDependency {
    pub part: ResolutionOwnerPart,
    pub observation: NamespaceDependency,
}

/// Exact declared contract plus resolved bindings. Function bodies and output
/// initializers are excluded; struct defaults are included conservatively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeInterface {
    pub identity: CanonicalItemIdentity,
    pub kind: ResolvedItemKind,
    pub declaration: Arc<str>,
    pub dependencies: BTreeSet<CanonicalItemIdentity>,
    pub namespace_dependencies: Vec<InterfaceNamespaceDependency>,
}

/// A transitive interface closure under the exact checking policy. Equality
/// still requires independent owner-text/topology/namespace and budget guards
/// before any reuse of checking results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerTypeDependencies {
    pub owner: ResolutionOwnerKey,
    pub policy: Arc<CheckPolicy>,
    pub interfaces: BTreeMap<CanonicalItemIdentity, Arc<TypeInterface>>,
}

#[derive(Debug, Default)]
pub(super) struct InterfaceIndex {
    entries: BTreeMap<CanonicalItemIdentity, Arc<TypeInterface>>,
    truncated: bool,
}

#[derive(Clone, Copy)]
struct Limits {
    units: usize,
    bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            units: 262_144,
            bytes: 8 * 1024 * 1024,
        }
    }
}

struct Budget {
    left: Limits,
    exhausted: bool,
}
impl Budget {
    fn new(left: Limits) -> Self {
        Self {
            left,
            exhausted: false,
        }
    }
    fn reserve(&mut self, units: usize, bytes: usize) -> bool {
        if units > self.left.units || bytes > self.left.bytes {
            self.exhausted = true;
            return false;
        }
        self.left.units -= units;
        self.left.bytes -= bytes;
        true
    }
    fn identity(&mut self, id: &CanonicalItemIdentity) -> bool {
        self.reserve(
            1 + id.path().len(),
            id.path().iter().map(String::len).sum(),
        )
    }
}

struct Descriptor {
    identity: CanonicalItemIdentity,
    kind: ResolvedItemKind,
    span: Span,
    header: Span,
    defaults: Vec<String>,
    package_family: Option<String>,
}

impl SemanticAnalysis {
    pub fn type_interfaces_truncated(
        &self,
        cancel: &AnalysisCancellation,
    ) -> Result<bool, AnalysisCancelled> {
        Ok(self.interface_index(cancel)?.truncated)
    }

    /// Returns no manifest when metadata or a required declaration is unavailable.
    /// This query never runs factories or changes strict checking diagnostics.
    pub fn owner_type_dependencies(
        &self,
        key: &ResolutionOwnerKey,
        cancel: &AnalysisCancellation,
    ) -> Result<Option<OwnerTypeDependencies>, AnalysisCancelled> {
        let index = self.interface_index(cancel)?;
        if index.truncated {
            return Ok(None);
        }
        let Some(owner) = self.owner_resolution(key, cancel)? else {
            return Ok(None);
        };
        if !owner.namespace_dependencies_complete {
            return Ok(None);
        }
        let mut budget = Budget::new(Limits::default());
        let mut roots = BTreeSet::new();
        if !collect_targets(&owner, None, &mut roots, &mut budget, cancel)? {
            return Ok(None);
        }
        let Ok(identity) = CanonicalItemIdentity::new(key.domain, key.path.clone()) else {
            return Ok(None);
        };
        if !budget.identity(&identity) {
            return Ok(None);
        }
        roots.insert(identity);
        // Erasure introduces nominal types without a source-level reference.
        // Conservatively include both endpoints of every rule, including rules
        // whose source is reached only through an inferred specialization.
        for rule in self.policy.erasures() {
            cancel.check()?;
            for identity in [&rule.source, &rule.target] {
                if !budget.identity(identity) {
                    return Ok(None);
                }
                roots.insert(identity.clone());
            }
        }
        let mut interfaces = BTreeMap::new();
        while let Some(identity) = roots.pop_first() {
            cancel.check()?;
            if interfaces.contains_key(&identity) {
                continue;
            }
            if !budget.identity(&identity) {
                return Ok(None);
            }
            let Some(interface) = index.entries.get(&identity) else {
                return Ok(None);
            };
            for dependency in &interface.dependencies {
                cancel.check()?;
                if !budget.identity(dependency) {
                    return Ok(None);
                }
                if !interfaces.contains_key(dependency) {
                    roots.insert(dependency.clone());
                }
            }
            interfaces.insert(identity, interface.clone());
        }
        cancel.check()?;
        Ok(Some(OwnerTypeDependencies {
            owner: key.clone(),
            policy: self.policy.clone(),
            interfaces,
        }))
    }

    fn interface_index(
        &self,
        cancel: &AnalysisCancellation,
    ) -> Result<&InterfaceIndex, AnalysisCancelled> {
        cancel.check()?;
        if let Some(index) = self.interfaces.get() {
            return Ok(index);
        }
        let index = self.build_interfaces(Limits::default(), cancel)?;
        cancel.check()?;
        let _ = self.interfaces.set(index);
        Ok(self
            .interfaces
            .get()
            .expect("interface index initialized"))
    }

    fn build_interfaces(
        &self,
        limits: Limits,
        cancel: &AnalysisCancellation,
    ) -> Result<InterfaceIndex, AnalysisCancelled> {
        let mut budget = Budget::new(limits);
        if self.resolution_owners_truncated() {
            return Ok(InterfaceIndex {
                truncated: true,
                ..InterfaceIndex::default()
            });
        }
        let descriptors = self.interface_descriptors(&mut budget, cancel)?;
        let mut index = InterfaceIndex::default();
        for descriptor in &descriptors {
            cancel.check()?;
            if budget.exhausted {
                break;
            }
            if let Some(mut interface) = self.declared_interface(descriptor, &mut budget, cancel)? {
                if let Some(family) = &descriptor.package_family {
                    // Selection depends on the entire family, including the
                    // absence of duplicate or newly registered combinations.
                    for candidate in &descriptors {
                        cancel.check()?;
                        if candidate.identity.domain() == descriptor.identity.domain()
                            && candidate.package_family.as_ref() == Some(family)
                            && candidate.identity != descriptor.identity
                        {
                            if !budget.identity(&candidate.identity) {
                                break;
                            }
                            interface
                                .dependencies
                                .insert(candidate.identity.clone());
                        }
                    }
                }
                index
                    .entries
                    .insert(descriptor.identity.clone(), Arc::new(interface));
            }
        }
        if budget.exhausted {
            return Ok(InterfaceIndex {
                truncated: true,
                ..InterfaceIndex::default()
            });
        }
        Ok(index)
    }

    fn interface_descriptors(
        &self,
        budget: &mut Budget,
        cancel: &AnalysisCancellation,
    ) -> Result<Vec<Descriptor>, AnalysisCancelled> {
        let mut locations = BTreeMap::new();
        for item in self.items() {
            cancel.check()?;
            if !budget.reserve(1, 0) {
                return Ok(Vec::new());
            }
            locations.insert(item.span(), item);
        }
        let mut descriptors = Vec::new();
        for source in self.resolved.parsed().iter() {
            let mut pending: Vec<_> = source.program().items.iter().collect();
            while let Some(item) = pending.pop() {
                cancel.check()?;
                if !budget.reserve(1, 0) {
                    return Ok(Vec::new());
                }
                let (name, end, defaults) = match &item.kind {
                    ItemKind::Module(module) => {
                        pending.extend(&module.items);
                        continue;
                    }
                    ItemKind::Function(function) => (
                        function.name.span,
                        function.body.span.start(),
                        Vec::new(),
                    ),
                    ItemKind::Struct(structure) => {
                        let mut defaults = Vec::new();
                        for field in &structure.fields {
                            cancel.check()?;
                            if field.default.is_some() {
                                if !budget.reserve(1, field.name.text.len()) {
                                    return Ok(Vec::new());
                                }
                                defaults.push(field.name.text.clone());
                            }
                        }
                        (structure.name.span, item.span.end(), defaults)
                    }
                    ItemKind::Enum(enumeration) => {
                        (enumeration.name.span, item.span.end(), Vec::new())
                    }
                    ItemKind::TypeAlias(alias) => (alias.name.span, item.span.end(), Vec::new()),
                    ItemKind::Resource(primitive) | ItemKind::Value(primitive) => {
                        (primitive.name.span, item.span.end(), Vec::new())
                    }
                    ItemKind::Outputs(outputs) => {
                        for output in &outputs.entries {
                            cancel.check()?;
                            if !budget.reserve(1, 0) {
                                return Ok(Vec::new());
                            }
                            if let OutputKind::Value {
                                value,
                                ..
                            } = &output.kind
                                && let Some(resolved) = locations.get(&output.span)
                            {
                                if !budget.reserve(
                                    1 + resolved.path().segments().len(),
                                    resolved
                                        .path()
                                        .segments()
                                        .iter()
                                        .map(String::len)
                                        .sum(),
                                ) {
                                    return Ok(Vec::new());
                                }
                                descriptors.push(Descriptor {
                                    identity: CanonicalItemIdentity::from_resolved(resolved),
                                    kind: resolved.kind(),
                                    span: output.span,
                                    header: Span::new(
                                        output.span.source_id(),
                                        output.span.start(),
                                        value.span.start(),
                                    ),
                                    defaults: Vec::new(),
                                    package_family: None,
                                });
                            }
                        }
                        continue;
                    }
                    _ => continue,
                };
                if let Some(resolved) = locations.get(&name) {
                    if !budget.reserve(
                        1 + resolved.path().segments().len(),
                        resolved
                            .path()
                            .segments()
                            .iter()
                            .map(String::len)
                            .sum(),
                    ) {
                        return Ok(Vec::new());
                    }
                    descriptors.push(Descriptor {
                        identity: CanonicalItemIdentity::from_resolved(resolved),
                        kind: resolved.kind(),
                        span: item.span,
                        header: Span::new(item.span.source_id(), item.span.start(), end),
                        defaults,
                        package_family: match &item.kind {
                            ItemKind::Function(function) => function
                                .package
                                .as_ref()
                                .map(|identity| identity[0].source.clone()),
                            _ => None,
                        },
                    });
                }
            }
        }
        Ok(descriptors)
    }

    fn declared_interface(
        &self,
        descriptor: &Descriptor,
        budget: &mut Budget,
        cancel: &AnalysisCancellation,
    ) -> Result<Option<TypeInterface>, AnalysisCancelled> {
        let key = ResolutionOwnerKey {
            domain: descriptor.identity.domain(),
            path: descriptor.identity.path().to_vec(),
            part: ResolutionOwnerPart::Declaration,
        };
        let Some(owner) = self.owner_resolution(&key, cancel)? else {
            return Ok(None);
        };
        if !owner.namespace_dependencies_complete || owner.source_map.span() != descriptor.span {
            return Ok(None);
        }
        let Some(header) = owner.source_map.relative_span(descriptor.header) else {
            return Ok(None);
        };
        let Some(text) = self
            .sources
            .get(descriptor.header.source_id())
            .and_then(|source| source.text().get(descriptor.header.range()))
        else {
            return Ok(None);
        };
        if !budget.identity(&descriptor.identity) || !budget.reserve(1, text.len()) {
            return Ok(None);
        }
        let mut interface = TypeInterface {
            identity: descriptor.identity.clone(),
            kind: descriptor.kind,
            declaration: Arc::from(text),
            dependencies: BTreeSet::new(),
            namespace_dependencies: Vec::new(),
        };
        if !extend_interface(
            &mut interface,
            &owner,
            Some(header.end),
            budget,
            cancel,
        )? {
            return Ok(None);
        }
        for field in &descriptor.defaults {
            cancel.check()?;
            let key = ResolutionOwnerKey {
                part: ResolutionOwnerPart::FieldDefault(field.clone()),
                ..key.clone()
            };
            let Some(default) = self.owner_resolution(&key, cancel)? else {
                return Ok(None);
            };
            if !default.namespace_dependencies_complete
                || !extend_interface(&mut interface, &default, None, budget, cancel)?
            {
                return Ok(None);
            }
        }
        Ok(Some(interface))
    }
}

fn extend_interface(
    interface: &mut TypeInterface,
    owner: &OwnerResolution,
    end: Option<u32>,
    budget: &mut Budget,
    cancel: &AnalysisCancellation,
) -> Result<bool, AnalysisCancelled> {
    if !collect_targets(
        owner,
        end,
        &mut interface.dependencies,
        budget,
        cancel,
    )? {
        return Ok(false);
    }
    for observation in owner
        .namespace_dependencies
        .iter()
        .filter(|observation| end.is_none_or(|end| observation.span.end <= end))
    {
        cancel.check()?;
        let (units, bytes) = observation_cost(observation);
        let part_bytes = match &owner.key.part {
            ResolutionOwnerPart::Declaration => 0,
            ResolutionOwnerPart::FieldDefault(name) | ResolutionOwnerPart::Publication(name) => {
                name.len()
            }
        };
        if !budget.reserve(units, bytes.saturating_add(part_bytes)) {
            return Ok(false);
        }
        interface
            .namespace_dependencies
            .push(InterfaceNamespaceDependency {
                part: owner.key.part.clone(),
                observation: observation.clone(),
            });
    }
    Ok(true)
}

fn collect_targets(
    owner: &OwnerResolution,
    end: Option<u32>,
    targets: &mut BTreeSet<CanonicalItemIdentity>,
    budget: &mut Budget,
    cancel: &AnalysisCancellation,
) -> Result<bool, AnalysisCancelled> {
    let mut insert = |target: &OwnerReferenceTarget| {
        let (domain, path) = match target {
            OwnerReferenceTarget::Item {
                domain,
                path,
            }
            | OwnerReferenceTarget::EnumVariant {
                domain,
                path,
                ..
            } => (*domain, path),
            OwnerReferenceTarget::Local {
                owner,
                ..
            } => (owner.domain, &owner.path),
            _ => return true,
        };
        if !budget.reserve(1 + path.len(), path.iter().map(String::len).sum()) {
            return false;
        }
        let Ok(identity) = CanonicalItemIdentity::new(domain, path.clone()) else {
            return false;
        };
        targets.insert(identity);
        true
    };
    for reference in owner
        .references
        .iter()
        .filter(|reference| end.is_none_or(|end| reference.span.end <= end))
    {
        cancel.check()?;
        if !insert(&reference.target) {
            return Ok(false);
        }
    }
    for dependency in owner
        .namespace_dependencies
        .iter()
        .filter(|dependency| end.is_none_or(|end| dependency.span.end <= end))
    {
        cancel.check()?;
        match &dependency.outcome {
            NamespaceOutcome::Target(Some(target)) => {
                if !insert(&target.identity) {
                    return Ok(false);
                }
            }
            NamespaceOutcome::Exports {
                entries: Some(entries),
                ..
            } => {
                for entry in entries {
                    cancel.check()?;
                    if !insert(&entry.target.identity) {
                        return Ok(false);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(true)
}

fn observation_cost(observation: &NamespaceDependency) -> (usize, usize) {
    fn target_cost(target: &OwnerReferenceTarget) -> (usize, usize) {
        let path = match target {
            OwnerReferenceTarget::Item {
                path,
                ..
            }
            | OwnerReferenceTarget::Module {
                path,
                ..
            }
            | OwnerReferenceTarget::EnumVariant {
                path,
                ..
            } => path,
            OwnerReferenceTarget::Local {
                owner,
                ..
            } => &owner.path,
            OwnerReferenceTarget::ContextualEnumVariant => return (1, 0),
        };
        (1 + path.len(), path.iter().map(String::len).sum())
    }
    let (mut units, mut bytes) = target_cost(&observation.requester);
    units += 1 + observation.path.len() + observation.diagnostics.len();
    bytes += observation
        .path
        .iter()
        .map(String::len)
        .sum::<usize>()
        + observation
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.len())
            .sum::<usize>();
    if let crate::resolver::NamespaceQuery::ModuleExports {
        export,
    } = &observation.query
    {
        bytes += export.len();
    }
    let mut add = |target: &OwnerReferenceTarget| {
        let (u, b) = target_cost(target);
        units += u;
        bytes += b;
    };
    match &observation.outcome {
        NamespaceOutcome::Target(Some(target)) => add(&target.identity),
        NamespaceOutcome::Exports {
            root,
            entries,
        } => {
            if let Some(root) = root {
                add(&root.identity);
            }
            for entry in entries.iter().flat_map(|entries| entries.iter()) {
                add(&entry.target.identity);
            }
            bytes += entries
                .iter()
                .flat_map(|entries| entries.iter())
                .map(|entry| entry.key.len())
                .sum::<usize>();
        }
        NamespaceOutcome::Target(None) => {}
    }
    (units, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analysis::AnalysisHost, source::SourceDomainId, source::SourceSet};

    fn analyze(files: &[(&str, &str)], policy: &CheckPolicy) -> SemanticAnalysis {
        let mut sources = SourceSet::new();
        for (path, text) in files {
            sources.add(*path, *text).unwrap();
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

    fn manifest(analysis: &SemanticAnalysis, name: &str) -> OwnerTypeDependencies {
        analysis
            .owner_type_dependencies(
                &ResolutionOwnerKey {
                    domain: SourceDomainId::project(),
                    path: vec![name.into()],
                    part: ResolutionOwnerPart::Declaration,
                },
                &AnalysisCancellation::default(),
            )
            .unwrap()
            .unwrap()
    }

    #[test]
    fn signatures_change_dependencies_but_other_bodies_and_offsets_do_not() {
        let text =
            "value I(int); value S(str); fn target() -> I { I(1) } fn inspect() -> I { target() }";
        let before = analyze(&[("main.srx", text)], &CheckPolicy::default());
        assert!(
            before.diagnostics().is_empty(),
            "{:?}",
            before.diagnostics()
        );
        let baseline = manifest(&before, "inspect");
        for changed in [
            text.replace("I(1)", "I(234)"),
            format!("// é\nfn earlier() {{}} {text}"),
        ] {
            let after = analyze(&[("main.srx", &changed)], &CheckPolicy::default());
            assert_eq!(baseline, manifest(&after, "inspect"));
        }
        let changed = text.replace(
            "fn target() -> I { I(1) }",
            "fn target() -> S { S(\"changed\") }",
        );
        let after = analyze(&[("main.srx", &changed)], &CheckPolicy::default());
        assert!(!after.diagnostics().is_empty());
        assert_ne!(baseline, manifest(&after, "inspect"));
    }

    #[test]
    fn transitive_payload_changes_detect_affinity_through_aliases_and_generics() {
        let text = "value I(int); enum E<T> { Wrap(T) } type Alias = E<I>; struct Box { payload: Alias; } fn inspect(x: Box) { let a = x; let b = x; }";
        let before = analyze(&[("main.srx", text)], &CheckPolicy::default());
        assert!(
            before.diagnostics().is_empty(),
            "{:?}",
            before.diagnostics()
        );
        let baseline = manifest(&before, "inspect");
        assert!(
            baseline
                .interfaces
                .keys()
                .any(|id| id.path() == ["I"])
        );
        let changed = text.replace("value I", "resource I");
        let after = analyze(&[("main.srx", &changed)], &CheckPolicy::default());
        assert!(
            after
                .diagnostics()
                .iter()
                .any(|d| d.code == crate::diagnostic::DiagnosticCode::MovedValue)
        );
        assert_ne!(baseline, manifest(&after, "inspect"));
    }

    #[test]
    fn defaults_are_subowners_and_part_of_the_declared_interface() {
        let text = "value I(int); fn seed() -> I { I(1) } struct Box { payload: I = seed(); } fn inspect() -> Box { Box {} }";
        let before = analyze(&[("main.srx", text)], &CheckPolicy::default());
        assert!(
            before.diagnostics().is_empty(),
            "{:?}",
            before.diagnostics()
        );
        let baseline = manifest(&before, "inspect");
        assert!(
            baseline
                .interfaces
                .keys()
                .any(|id| id.path() == ["seed"])
        );
        let changed = text.replace("= seed()", "= I(2)");
        assert_ne!(
            baseline,
            manifest(
                &analyze(&[("main.srx", &changed)], &CheckPolicy::default()),
                "inspect"
            )
        );
        let key = ResolutionOwnerKey {
            domain: SourceDomainId::project(),
            path: vec!["Box".into()],
            part: ResolutionOwnerPart::FieldDefault("payload".into()),
        };
        assert!(
            before
                .owner_type_dependencies(&key, &AnalysisCancellation::default())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn output_initializers_are_excluded_and_recursive_interfaces_terminate() {
        let text = "value I(int); struct Node { next: Node; } fn inspect(x: Node) -> Node { x } outputs { number: I = I(1); }";
        let before = analyze(&[("main.srx", text)], &CheckPolicy::default());
        assert_eq!(manifest(&before, "inspect").interfaces.len(), 2);
        let changed = text.replace("I(1)", "I(987)");
        assert_eq!(
            manifest(&before, "number"),
            manifest(
                &analyze(&[("main.srx", &changed)], &CheckPolicy::default()),
                "number"
            )
        );
    }

    #[test]
    fn policy_rules_participate_even_when_policy_names_are_identical() {
        let text = "value I(int); fn inspect(x: I) -> I { x }";
        let first = CheckPolicy::new("same").unwrap();
        let second = first.clone().with_scope("scope").unwrap();
        assert_ne!(
            manifest(&analyze(&[("main.srx", text)], &first), "inspect"),
            manifest(
                &analyze(&[("main.srx", text)], &second),
                "inspect"
            )
        );
    }

    #[test]
    fn reexports_change_interface_bindings_even_with_identical_spelling() {
        let text = "mod a { pub value I(int); } mod b { pub value I(int); } mod api { pub use a::I; pub fn target(x: I) -> I { x } } fn inspect() { let f = api::target; }";
        let before = analyze(&[("main.srx", text)], &CheckPolicy::default());
        assert!(
            before.diagnostics().is_empty(),
            "{:?}",
            before.diagnostics()
        );
        let changed = text.replace("use a::I", "use b::I");
        let after = analyze(&[("main.srx", &changed)], &CheckPolicy::default());
        assert!(
            after.diagnostics().is_empty(),
            "{:?}",
            after.diagnostics()
        );
        assert_ne!(
            manifest(&before, "inspect"),
            manifest(&after, "inspect")
        );
    }

    #[test]
    fn opaque_owner_refinement_and_scope_are_interface_inputs() {
        let cases = [
            (
                "value I(int); mod vault { pub struct Secret { payload: I; } } fn inspect(x: vault::Secret) -> I { x.payload }",
                "pub struct Secret",
                "pub opaque struct Secret",
            ),
            (
                "value I(int); struct Agent {} mod vault { pub opaque struct Secret<owner O> { payload: I; } } fn inspect(x: vault::Secret<Agent>) -> I { x.payload }",
                "<owner O>",
                "<O>",
            ),
            (
                "value I(int) where 1..3; fn inspect(x: I) -> I { x }",
                "1..3",
                "1..4",
            ),
            (
                "resource R(int) in net; fn inspect(x: R) -> R { x }",
                "in net",
                "in local",
            ),
        ];
        let policy = CheckPolicy::default()
            .with_scope("net")
            .unwrap()
            .with_scope("local")
            .unwrap();
        for (text, old, new) in cases {
            let before = analyze(&[("main.srx", text)], &policy);
            assert!(
                before.diagnostics().is_empty(),
                "{:?}",
                before.diagnostics()
            );
            let changed = text.replace(old, new);
            let after = analyze(&[("main.srx", &changed)], &policy);
            assert_ne!(
                manifest(&before, "inspect"),
                manifest(&after, "inspect"),
                "{old}"
            );
            if old.starts_with("pub") || old.starts_with('<') {
                assert!(!after.diagnostics().is_empty());
            }
        }
    }

    #[test]
    fn policy_erasure_targets_and_discovered_functions_enter_the_closure() {
        let text = "value I(int); struct Raw<T> { payload: T; } struct Erased { payload: I; } fn inspect() {}";
        let identity =
            |name| CanonicalItemIdentity::new(SourceDomainId::project(), [name]).unwrap();
        let policy = CheckPolicy::default()
            .with_erasure(identity("Raw"), identity("Erased"))
            .unwrap();
        let before = analyze(&[("main.srx", text)], &policy);
        let changed = text.replace(
            "struct Erased { payload: I; }",
            "struct Erased { payload: I; extra: I; }",
        );
        assert_ne!(
            manifest(&before, "inspect"),
            manifest(
                &analyze(&[("main.srx", &changed)], &policy),
                "inspect"
            )
        );

        let text = "value I(int); mod recipes { mod a { pub fn recipe() -> I { I(1) } } } fn mapper() {} fn inspect() { module_exports(recipes, recipe, mapper); }";
        let before = analyze(&[("main.srx", text)], &CheckPolicy::default());
        let closure = manifest(&before, "inspect");
        assert!(
            closure
                .interfaces
                .keys()
                .any(|id| id.path() == ["recipes", "a", "recipe"])
        );
        let changed = text.replace("-> I { I(1) }", "{ }");
        assert_ne!(
            closure,
            manifest(
                &analyze(&[("main.srx", &changed)], &CheckPolicy::default()),
                "inspect"
            )
        );
    }

    #[test]
    fn source_reordering_and_same_text_revalidation_preserve_manifests() {
        let main = "fn inspect(x: model::I) -> model::I { x }";
        let model = "mod model { pub value I(int); }";
        let before = analyze(
            &[("main.srx", main), ("model.srx", model)],
            &CheckPolicy::default(),
        );
        let after = analyze(
            &[("model.srx", model), ("main.srx", main)],
            &CheckPolicy::default(),
        );
        assert_eq!(
            manifest(&before, "inspect"),
            manifest(&after, "inspect")
        );
        assert!(before.diagnostics().is_empty() && after.diagnostics().is_empty());
        assert!(
            manifest(&before, "inspect")
                .interfaces
                .keys()
                .any(|id| id.path() == ["model", "I"])
        );
        let cancel = AnalysisCancellation::default();
        let revalidated = AnalysisHost::default()
            .snapshot()
            .revalidate_project_analysis(&before, &cancel)
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(
            &before.interfaces,
            &revalidated.interfaces
        ));
        assert!(Arc::ptr_eq(&before.policy, &revalidated.policy));
        assert_eq!(
            manifest(&before, "inspect"),
            manifest(&revalidated, "inspect")
        );
    }

    #[test]
    fn duplicates_limits_and_cancellation_never_publish_partial_manifests() {
        let analysis = analyze(
            &[(
                "main.srx",
                "value I(int); value I(int); fn inspect(x: I) {}",
            )],
            &CheckPolicy::default(),
        );
        let key = ResolutionOwnerKey {
            domain: SourceDomainId::project(),
            path: vec!["inspect".into()],
            part: ResolutionOwnerPart::Declaration,
        };
        assert!(
            analysis
                .owner_type_dependencies(&key, &AnalysisCancellation::default())
                .unwrap()
                .is_none()
        );
        let analysis = analyze(
            &[("main.srx", "value I(int); fn inspect(x: I) {}")],
            &CheckPolicy::default(),
        );
        for limits in [
            Limits {
                units: 0,
                bytes: usize::MAX,
            },
            Limits {
                units: usize::MAX,
                bytes: 0,
            },
        ] {
            let index = analysis
                .build_interfaces(limits, &AnalysisCancellation::default())
                .unwrap();
            assert!(index.truncated && index.entries.is_empty());
        }
        let cancelled = AnalysisCancellation::default();
        cancelled.cancel();
        assert!(
            analysis
                .owner_type_dependencies(&key, &cancelled)
                .is_err()
        );
        assert!(analysis.interfaces.get().is_none());
        assert!(
            analysis
                .owner_type_dependencies(&key, &AnalysisCancellation::default())
                .unwrap()
                .is_some()
        );
        assert!(
            analysis
                .owner_type_dependencies(&key, &cancelled)
                .is_err()
        );
    }
}
