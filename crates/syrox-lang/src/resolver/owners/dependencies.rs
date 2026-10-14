use super::{OwnerDiagnostic, OwnerReferenceTarget, OwnerRelativeSpan, OwnerSourceMap};
use crate::resolver::{
    ModuleId, Path, ResolvedItemKind, ResolvedModuleExport, ResolvedTarget, Resolver,
};
use crate::source::Span;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamespaceQuery {
    Lookup {
        expected: &'static str,
    },
    Variant,
    ModuleExports {
        export: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceTarget {
    pub identity: OwnerReferenceTarget,
    pub item_kind: Option<ResolvedItemKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceExport {
    pub key: String,
    pub target: NamespaceTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamespaceOutcome {
    /// `None` records a negative lookup, not an absent dependency.
    Target(Option<NamespaceTarget>),
    Exports {
        root: Option<NamespaceTarget>,
        entries: Option<Vec<NamespaceExport>>,
    },
}

/// Observed namespace behavior. Equality is not proof that item interfaces,
/// policy, topology or owner text are unchanged, nor permission to reuse checking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceDependency {
    pub requester: OwnerReferenceTarget,
    pub path: Vec<String>,
    pub span: OwnerRelativeSpan,
    pub query: NamespaceQuery,
    pub outcome: NamespaceOutcome,
    pub diagnostics: Vec<OwnerDiagnostic>,
    pub complete: bool,
}

#[derive(Clone, Copy)]
pub(crate) enum ObservedNamespace<'a> {
    Target(Option<&'a ResolvedTarget>),
    Exports {
        root: Option<&'a ResolvedTarget>,
        entries: Option<&'a [ResolvedModuleExport]>,
    },
}

impl Resolver<'_> {
    // Called after the existing lookup, without changing its work counter or
    // diagnostics. Reserve all retained text/records before copying query data.
    pub(in crate::resolver) fn observe_namespace(
        &mut self,
        module: ModuleId,
        path: &Path,
        span: Span,
        query: NamespaceQuery,
        result: ObservedNamespace<'_>,
        diagnostics_start: usize,
    ) {
        let Some(owner) = self.owners.active else {
            return;
        };
        if self.owners.truncated {
            return;
        }
        let map = OwnerSourceMap {
            span: self.owners.owners[owner].span,
            locals: Vec::new(),
        };
        let Some(relative) = map.relative_span(span) else {
            self.owners.owners[owner].dependencies_complete = false;
            return;
        };
        let bytes = |parts: &[String]| parts.iter().map(String::len).sum::<usize>();
        let target_bytes = |target: &ResolvedTarget| match target {
            ResolvedTarget::Item(id)
            | ResolvedTarget::EnumVariant {
                enumeration: id,
                ..
            } => bytes(self.items[id.index()].path.segments()),
            ResolvedTarget::Module(id) => bytes(self.modules[id.index()].path.segments()),
            _ => 0,
        };
        let mut text = bytes(self.modules[module.index()].path.segments())
            + path
                .segments
                .iter()
                .map(|part| part.text.len())
                .sum::<usize>()
            + self.diagnostics[diagnostics_start..]
                .iter()
                .map(|diagnostic| diagnostic.message.len())
                .sum::<usize>();
        if let NamespaceQuery::ModuleExports {
            export,
        } = &query
        {
            text = text.saturating_add(export.len());
        }
        let mut units = path.segments.len() + self.diagnostics.len() - diagnostics_start + 1;
        match &result {
            ObservedNamespace::Target(target) => {
                if let Some(target) = target {
                    text = text.saturating_add(target_bytes(target));
                }
            }
            ObservedNamespace::Exports {
                root,
                entries,
            } => {
                if let Some(root) = root {
                    text = text.saturating_add(target_bytes(root));
                }
                for entry in entries.iter().flat_map(|entries| entries.iter()) {
                    if self
                        .cancellation
                        .is_some_and(|cancel| cancel.check().is_err())
                    {
                        self.owners.owners[owner].dependencies_complete = false;
                        return;
                    }
                    units = units.saturating_add(1);
                    text = text
                        .saturating_add(entry.key.len())
                        .saturating_add(target_bytes(&ResolvedTarget::Item(entry.item)));
                }
            }
        }
        if !self.owners.reserve(units, text) {
            return;
        }
        let diagnostics = self.diagnostics[diagnostics_start..]
            .iter()
            .filter_map(|diagnostic| map.diagnostic(diagnostic))
            .collect::<Vec<_>>();
        let complete = !self.exhausted
            && self.diagnostics.len() < crate::MAX_DIAGNOSTICS
            && diagnostics.len() == self.diagnostics.len() - diagnostics_start
            && self
                .cancellation
                .is_none_or(|cancel| cancel.check().is_ok());
        let dependency = NamespaceDependency {
            requester: self
                .namespace_target(&ResolvedTarget::Module(module))
                .identity,
            path: path
                .segments
                .iter()
                .map(|part| part.text.clone())
                .collect(),
            span: relative,
            query,
            outcome: self.namespace_outcome(result),
            diagnostics,
            complete,
        };
        self.owners.owners[owner].dependencies_complete &= complete;
        std::sync::Arc::make_mut(&mut self.owners.owners[owner].dependencies).push(dependency);
    }

    fn namespace_outcome(&self, result: ObservedNamespace<'_>) -> NamespaceOutcome {
        match result {
            ObservedNamespace::Target(target) => {
                NamespaceOutcome::Target(target.map(|target| self.namespace_target(target)))
            }
            ObservedNamespace::Exports {
                root,
                entries,
            } => NamespaceOutcome::Exports {
                root: root.map(|root| self.namespace_target(root)),
                entries: entries.map(|entries| {
                    entries
                        .iter()
                        .map(|entry| NamespaceExport {
                            key: entry.key.clone(),
                            target: self.namespace_target(&ResolvedTarget::Item(entry.item)),
                        })
                        .collect()
                }),
            },
        }
    }

    fn namespace_target(&self, target: &ResolvedTarget) -> NamespaceTarget {
        let (identity, item_kind) = match target {
            ResolvedTarget::Item(id) => {
                let item = &self.items[id.index()];
                (
                    OwnerReferenceTarget::Item {
                        domain: item.domain,
                        path: item.path.segments.clone(),
                    },
                    Some(item.kind),
                )
            }
            ResolvedTarget::Module(id) => {
                let module = &self.modules[id.index()];
                (
                    OwnerReferenceTarget::Module {
                        domain: module.domain,
                        path: module.path.segments.clone(),
                    },
                    None,
                )
            }
            ResolvedTarget::EnumVariant {
                enumeration,
                index,
            } => {
                let item = &self.items[enumeration.index()];
                (
                    OwnerReferenceTarget::EnumVariant {
                        domain: item.domain,
                        path: item.path.segments.clone(),
                        index: *index,
                    },
                    Some(item.kind),
                )
            }
            ResolvedTarget::Local(_) | ResolvedTarget::ContextualEnumVariant => {
                unreachable!("namespace lookup cannot return a lexical/contextual target")
            }
        };
        NamespaceTarget {
            identity,
            item_kind,
        }
    }
}
