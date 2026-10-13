/// Operation-local identity of a top-level publication declaration, never an output.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicationId(pub(super) u32);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleId(pub(super) u32);

impl ModuleId {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ItemId(pub(super) u32);

impl ItemId {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalId(pub(super) u32);

impl LocalId {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A local identity and the declaration that introduced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedLocal {
    pub(super) id: LocalId,
    pub(super) span: Span,
    pub(super) name: String,
    pub(super) kind: LocalKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalKind {
    Binding,
    Parameter,
    Pattern,
    TypeParameter,
}

impl ResolvedLocal {
    pub const fn id(&self) -> LocalId {
        self.id
    }

    pub const fn span(&self) -> Span {
        self.span
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub const fn kind(&self) -> LocalKind {
        self.kind
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalPath {
    pub(super) segments: Vec<String>,
}

impl CanonicalPath {
    pub fn segments(&self) -> &[String] {
        &self.segments
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedItemKind {
    TypeAlias,
    Struct,
    Enum,
    Resource,
    Value,
    Function,
    OutputValue,
    PublishedMember,
    OutputType,
}

impl ResolvedItemKind {
    pub(super) const fn is_type(self) -> bool {
        matches!(
            self,
            Self::TypeAlias
                | Self::Struct
                | Self::Enum
                | Self::Resource
                | Self::Value
                | Self::OutputType
        )
    }

    pub(super) const fn description(self) -> &'static str {
        match self {
            Self::TypeAlias => "type alias",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Resource => "resource",
            Self::Value => "value",
            Self::Function => "function",
            Self::PublishedMember => "published member",
            Self::OutputValue => "output value",
            Self::OutputType => "exported type",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedModule {
    pub(super) id: ModuleId,
    pub(super) domain: SourceDomainId,
    pub(super) path: CanonicalPath,
}

impl ResolvedModule {
    pub const fn id(&self) -> ModuleId {
        self.id
    }

    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    pub const fn domain(&self) -> SourceDomainId {
        self.domain
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedItem {
    pub(super) id: ItemId,
    pub(super) domain: SourceDomainId,
    pub(super) module: ModuleId,
    pub(super) path: CanonicalPath,
    pub(super) kind: ResolvedItemKind,
    pub(super) span: Span,
}

impl ResolvedItem {
    pub const fn id(&self) -> ItemId {
        self.id
    }

    pub const fn module(&self) -> ModuleId {
        self.module
    }

    pub const fn domain(&self) -> SourceDomainId {
        self.domain
    }

    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    pub const fn kind(&self) -> ResolvedItemKind {
        self.kind
    }

    pub const fn span(&self) -> Span {
        self.span
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedTarget {
    Module(ModuleId),
    Item(ItemId),
    Local(LocalId),
    EnumVariant {
        enumeration: ItemId,
        index: u32,
    },
    /// A bare pattern/value that the checker must resolve against an expected
    /// enum type, or reject if no matching variant exists.
    ContextualEnumVariant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceKind {
    Import,
    Type,
    Function,
    Value,
    StructConstructor,
    Refinement,
    Pattern,
    Interpolation,
}

#[derive(Clone, Debug)]
pub struct ResolvedReference {
    pub(super) span: Span,
    pub(super) kind: ReferenceKind,
    pub(super) target: ResolvedTarget,
}

impl ResolvedReference {
    pub const fn span(&self) -> Span {
        self.span
    }

    pub const fn kind(&self) -> ReferenceKind {
        self.kind
    }

    pub const fn target(&self) -> &ResolvedTarget {
        &self.target
    }
}

/// A parsed program together with successful structural name resolution.
///
/// Its fields are private so callers cannot claim resolution for an arbitrary
/// syntax tree. Bare enum variants remain explicit contextual obligations that
/// a type checker must discharge. Construct it with [`super::resolve`].
#[derive(Clone, Debug)]
pub struct ResolvedProgram {
    pub(super) parsed: ParsedSources,
    pub(super) modules: Vec<ResolvedModule>,
    pub(super) items: Vec<ResolvedItem>,
    pub(super) references: Vec<ResolvedReference>,
    pub(super) locals: Vec<ResolvedLocal>,
    pub(super) module_exports:
        std::collections::BTreeMap<(usize, u32, u32), std::sync::Arc<[ResolvedModuleExport]>>,
    pub(super) publications:
        std::collections::BTreeMap<PublicationId, std::sync::Arc<[ResolvedModuleExport]>>,
    pub(super) visible_members:
        std::collections::BTreeMap<SourceDomainId, std::collections::BTreeMap<String, ItemId>>,
    pub(super) catalog_members: std::collections::BTreeMap<ItemId, PublishedMember>,
    pub(super) editor: Option<std::sync::Arc<super::editor::Namespace>>,
    pub(super) ambiguous_names: std::sync::OnceLock<std::collections::BTreeSet<ItemId>>,
}

/// A lazy member of a publication. Symbol identity belongs to the member;
/// navigation and evaluation preserve the canonical factory origin.
#[derive(Clone, Debug)]
pub struct PublishedMember {
    pub publication: PublicationId,
    pub(super) inventory: std::sync::Arc<[ResolvedModuleExport]>,
    pub(super) index: usize,
}

impl PublishedMember {
    pub fn factory(&self) -> ItemId {
        self.inventory[self.index].item()
    }
    pub fn key(&self) -> &str {
        self.inventory[self.index].key()
    }
}

/// A public function selected from an authenticated module namespace.
/// Reexports retain the canonical item identity; keys describe the exporting module.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedModuleExport {
    pub(super) key: String,
    pub(super) item: ItemId,
}

impl ResolvedModuleExport {
    pub fn key(&self) -> &str {
        &self.key
    }
    pub const fn item(&self) -> ItemId {
        self.item
    }
}

impl ResolvedProgram {
    pub fn item(&self, id: ItemId) -> Option<&ResolvedItem> {
        self.items.get(id.index())
    }
    /// Public publication members visible at this domain root; excludes merely imported dependencies.
    pub fn visible_published_members(
        &self,
        domain: SourceDomainId,
    ) -> impl Iterator<Item = (&str, ItemId)> {
        self.visible_members
            .get(&domain)
            .into_iter()
            .flat_map(|entries| {
                entries
                    .iter()
                    .map(|(name, id)| (name.as_str(), *id))
            })
    }
    pub fn published_member(&self, item: ItemId) -> Option<&PublishedMember> {
        self.catalog_members.get(&item)
    }

    pub fn publication(&self, item: PublicationId) -> Option<&[ResolvedModuleExport]> {
        self.publications.get(&item).map(AsRef::as_ref)
    }
    pub(crate) fn ambiguous_type_name(&self, id: ItemId) -> bool {
        self.ambiguous_names
            .get_or_init(|| {
                let mut first = std::collections::BTreeMap::new();
                let mut ambiguous = std::collections::BTreeSet::new();
                for item in &self.items {
                    let (domain, original) = first
                        .entry(item.path())
                        .or_insert((item.domain(), item.id()));
                    if *domain != item.domain() {
                        ambiguous.insert(*original);
                        ambiguous.insert(item.id());
                    }
                }
                ambiguous
            })
            .contains(&id)
    }
    pub fn module_exports(&self, span: Span) -> Option<&[ResolvedModuleExport]> {
        self.module_exports
            .get(&(span.source_id().index(), span.start(), span.end()))
            .map(AsRef::as_ref)
    }

    pub const fn parsed(&self) -> &ParsedSources {
        &self.parsed
    }

    pub fn modules(&self) -> impl ExactSizeIterator<Item = &ResolvedModule> {
        self.modules.iter()
    }

    pub fn items(&self) -> impl ExactSizeIterator<Item = &ResolvedItem> {
        self.items.iter()
    }

    pub fn references(&self) -> impl ExactSizeIterator<Item = &ResolvedReference> {
        self.references.iter()
    }

    pub fn locals(&self) -> impl ExactSizeIterator<Item = &ResolvedLocal> + '_ {
        self.locals.iter()
    }

    /// References whose final enum variant identity requires an expected type.
    pub fn contextual_obligations(&self) -> impl Iterator<Item = &ResolvedReference> {
        self.references
            .iter()
            .filter(|reference| reference.target == ResolvedTarget::ContextualEnumVariant)
    }
}
use crate::{source::SourceDomainId, source::Span, syntax::ParsedSources};
