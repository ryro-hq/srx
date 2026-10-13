//! Texto e coordenadas usados pelas etapas da linguagem.
//!
//! Um `SourceId` só identifica uma fonte dentro do seu `SourceSet`. Guarde o
//! conjunto junto dos spans que pretende consultar. Domínios separam o projeto,
//! a std e os inputs, inclusive quando eles têm nomes de módulos iguais.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use thiserror::Error;

use crate::{MAX_SOURCE_BYTES, MAX_SOURCES};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceDomainId(u32);

impl SourceDomainId {
    pub(crate) const PROJECT: Self = Self(0);
    pub(crate) const STANDARD_LIBRARY: Self = Self(1);

    /// The domain shared by ordinary project sources.
    pub const fn project() -> Self {
        Self::PROJECT
    }

    /// The reserved domain assigned only by a caller asserting authenticated std text.
    pub const fn standard_library() -> Self {
        Self::STANDARD_LIBRARY
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceId(u32);

impl SourceId {
    pub(crate) const SINGLE: Self = Self(0);

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    pub(crate) source: SourceId,
    pub(crate) start: u32,
    pub(crate) end: u32,
}

impl Span {
    pub(crate) const fn new(source: SourceId, start: u32, end: u32) -> Self {
        Self {
            source,
            start,
            end,
        }
    }

    #[must_use]
    pub(crate) const fn join(self, other: Self) -> Self {
        assert!(
            self.source.0 == other.source.0,
            "cannot join spans from different sources"
        );
        Self::new(self.source, self.start, other.end)
    }

    pub const fn source_id(self) -> SourceId {
        self.source
    }

    pub const fn start(self) -> u32 {
        self.start
    }

    pub const fn end(self) -> u32 {
        self.end
    }

    pub(crate) fn range(self) -> std::ops::Range<usize> {
        self.start as usize..self.end as usize
    }
}

#[derive(Clone, Debug)]
pub struct Source {
    name: Arc<str>,
    text: Arc<str>,
}

impl Source {
    pub fn new(name: impl Into<Arc<str>>, text: impl Into<Arc<str>>) -> Result<Self, SourceError> {
        let name = name.into();
        let text = text.into();
        if text.len() > MAX_SOURCE_BYTES || text.len() > u32::MAX as usize {
            return Err(SourceError::TooLarge);
        }
        Ok(Self {
            name,
            text,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

#[derive(Clone, Debug)]
pub struct SourceSet {
    sources: Vec<Source>,
    metadata: Box<SourceMetadata>,
    input_domains: Option<Arc<BTreeMap<SourceDomainId, BTreeMap<String, SourceDomainId>>>>,
    total_bytes: usize,
    next_domain: u32,
}

#[derive(Clone, Debug, Default)]
struct SourceMetadata {
    domains: Vec<SourceDomainId>,
    modules: Vec<Vec<String>>,
    project_roots: BTreeSet<SourceDomainId>,
}

impl Default for SourceSet {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceSet {
    pub(crate) fn replace_text(&mut self, id: SourceId, text: &str) -> Result<(), SourceError> {
        let old = &self.sources[id.index()];
        let source = Source::new(old.name(), text)?;
        self.total_bytes = self
            .total_bytes
            .checked_sub(old.text().len())
            .and_then(|bytes| bytes.checked_add(text.len()))
            .ok_or(SourceError::SourceSetTooLarge)?;
        self.sources[id.index()] = source;
        Ok(())
    }
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            metadata: Box::default(),
            input_domains: None,
            total_bytes: 0,
            next_domain: 2,
        }
    }

    pub fn add(
        &mut self,
        name: impl Into<Arc<str>>,
        text: impl Into<Arc<str>>,
    ) -> Result<SourceId, SourceError> {
        self.insert(Source::new(name, text)?)
    }

    pub fn insert(&mut self, source: Source) -> Result<SourceId, SourceError> {
        self.insert_in_domain(SourceDomainId::PROJECT, source)
    }

    /// Creates a distinct sealed input source domain bound to a trusted project alias.
    pub fn create_input_domain(
        &mut self,
        alias: impl Into<String>,
    ) -> Result<SourceDomainId, SourceError> {
        self.create_domain(SourceDomainId::PROJECT, alias.into(), false)
    }

    /// Bind an authenticated child project's root as one input of its parent.
    /// A child project owns its own input alias namespace.
    pub fn create_project_domain(
        &mut self,
        parent: SourceDomainId,
        alias: impl Into<String>,
    ) -> Result<SourceDomainId, SourceError> {
        self.create_domain(parent, alias.into(), true)
    }

    /// Bind another authenticated edge to an already admitted project snapshot.
    pub fn bind_project_domain(
        &mut self,
        parent: SourceDomainId,
        alias: impl Into<String>,
        domain: SourceDomainId,
    ) -> Result<(), SourceError> {
        if (parent != SourceDomainId::PROJECT && !self.metadata.project_roots.contains(&parent))
            || !self.metadata.project_roots.contains(&domain)
        {
            return Err(SourceError::InvalidProjectDomain);
        }
        let alias = alias.into();
        if alias == "std" {
            return Err(SourceError::ReservedInputAlias);
        }
        let aliases = Arc::make_mut(
            self.input_domains
                .get_or_insert_with(|| Arc::new(BTreeMap::new())),
        )
        .entry(parent)
        .or_default();
        if aliases.contains_key(&alias) {
            return Err(SourceError::DuplicateInputAlias);
        }
        aliases.insert(alias, domain);
        Ok(())
    }

    pub fn create_child_input_domain(
        &mut self,
        parent: SourceDomainId,
        alias: impl Into<String>,
    ) -> Result<SourceDomainId, SourceError> {
        self.create_domain(parent, alias.into(), false)
    }

    fn create_domain(
        &mut self,
        parent: SourceDomainId,
        alias: String,
        project: bool,
    ) -> Result<SourceDomainId, SourceError> {
        if parent != SourceDomainId::PROJECT && !self.metadata.project_roots.contains(&parent) {
            return Err(SourceError::InvalidProjectDomain);
        }
        if alias == "std" {
            return Err(SourceError::ReservedInputAlias);
        }
        if self
            .input_domains
            .as_ref()
            .and_then(|domains| domains.get(&parent))
            .is_some_and(|domains| domains.contains_key(&alias))
        {
            return Err(SourceError::DuplicateInputAlias);
        }
        if self.next_domain as usize >= MAX_SOURCES + 2 {
            return Err(SourceError::TooManyDomains);
        }
        let domain = SourceDomainId(self.next_domain);
        self.next_domain = self
            .next_domain
            .checked_add(1)
            .ok_or(SourceError::TooManyDomains)?;
        Arc::make_mut(
            self.input_domains
                .get_or_insert_with(|| Arc::new(BTreeMap::new())),
        )
        .entry(parent)
        .or_default()
        .insert(alias, domain);
        if project {
            self.metadata.project_roots.insert(domain);
        }
        Ok(domain)
    }

    pub fn add_to_project_domain(
        &mut self,
        domain: SourceDomainId,
        name: impl Into<Arc<str>>,
        text: impl Into<Arc<str>>,
    ) -> Result<SourceId, SourceError> {
        if !self.metadata.project_roots.contains(&domain) {
            return Err(SourceError::InvalidProjectDomain);
        }
        self.add_to_input_domain(domain, name, text)
    }

    pub fn add_to_input_domain(
        &mut self,
        domain: SourceDomainId,
        name: impl Into<Arc<str>>,
        text: impl Into<Arc<str>>,
    ) -> Result<SourceId, SourceError> {
        if domain.0 < 2 || domain.0 >= self.next_domain {
            return Err(SourceError::InvalidInputDomain);
        }
        let source = Source::new(name, text)?;
        self.insert_in_domain(domain, source)
    }

    /// Give one authenticated input file its own logical module. The loader,
    /// not source text, assigns this path from the pinned input inventory.
    pub fn add_to_input_module(
        &mut self,
        domain: SourceDomainId,
        name: impl Into<Arc<str>>,
        text: impl Into<Arc<str>>,
        module: Vec<String>,
    ) -> Result<SourceId, SourceError> {
        if module.is_empty()
            || module.len() > crate::MAX_DEPTH
            || module.iter().any(|part| {
                part.is_empty()
                    || part.len() > 255
                    || !part.bytes().enumerate().all(|(index, byte)| {
                        byte == b'_'
                            || byte.is_ascii_alphabetic()
                            || (index > 0 && byte.is_ascii_digit())
                    })
            })
        {
            return Err(SourceError::InvalidInputModule);
        }
        let id = self.add_to_input_domain(domain, name, text)?;
        self.metadata.modules[id.index()] = module;
        Ok(id)
    }

    /// Adds a source which the caller asserts is authenticated standard-library text.
    ///
    /// This public call is a trusted boundary: the caller must authenticate and
    /// pin the source before assigning the reserved origin. The domain records
    /// that assertion but does not authenticate bytes itself. Source spelling
    /// alone must never select this domain.
    pub fn add_standard_library(
        &mut self,
        name: impl Into<Arc<str>>,
        text: impl Into<Arc<str>>,
    ) -> Result<SourceId, SourceError> {
        let source = Source::new(name, text)?;
        self.insert_in_domain(SourceDomainId::STANDARD_LIBRARY, source)
    }

    fn insert_in_domain(
        &mut self,
        domain: SourceDomainId,
        source: Source,
    ) -> Result<SourceId, SourceError> {
        if self.sources.len() >= MAX_SOURCES {
            return Err(SourceError::TooManySources);
        }
        let total_bytes = self
            .total_bytes
            .checked_add(source.text.len())
            .ok_or(SourceError::SourceSetTooLarge)?;
        let id =
            SourceId(u32::try_from(self.sources.len()).map_err(|_| SourceError::TooManySources)?);
        self.sources.push(source);
        self.metadata.domains.push(domain);
        self.metadata.modules.push(Vec::new());
        self.total_bytes = total_bytes;
        Ok(id)
    }

    pub fn get(&self, id: SourceId) -> Option<&Source> {
        self.sources.get(id.index())
    }

    pub fn domain(&self, id: SourceId) -> Option<SourceDomainId> {
        self.metadata.domains.get(id.index()).copied()
    }

    pub fn child_project_domain(
        &self,
        parent: SourceDomainId,
        alias: &str,
    ) -> Option<SourceDomainId> {
        let domain = *self
            .input_domains
            .as_ref()?
            .get(&parent)?
            .get(alias)?;
        self.metadata
            .project_roots
            .contains(&domain)
            .then_some(domain)
    }

    /// Domain bound to an input alias, including file/module inputs.
    pub fn input_domain(&self, parent: SourceDomainId, alias: &str) -> Option<SourceDomainId> {
        self.input_domains
            .as_ref()?
            .get(&parent)?
            .get(alias)
            .copied()
    }

    pub(crate) fn module(&self, id: SourceId) -> Option<&[String]> {
        self.metadata
            .modules
            .get(id.index())
            .map(Vec::as_slice)
    }

    pub(crate) fn input_domains(
        &self,
    ) -> Option<&BTreeMap<SourceDomainId, BTreeMap<String, SourceDomainId>>> {
        self.input_domains.as_deref()
    }

    pub(crate) fn project_roots(&self) -> &BTreeSet<SourceDomainId> {
        &self.metadata.project_roots
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (SourceId, &Source)> {
        self.sources
            .iter()
            .enumerate()
            .map(|(index, source)| {
                let index = u32::try_from(index).expect("source count is bounded by u32");
                (SourceId(index), source)
            })
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SourceError {
    #[error("source exceeds the {MAX_SOURCE_BYTES}-byte limit")]
    TooLarge,
    #[error("source set exceeds the {MAX_SOURCES}-source limit")]
    TooManySources,
    #[error("source set byte count cannot be represented")]
    SourceSetTooLarge,
    #[error("source domain count cannot be represented")]
    TooManyDomains,
    #[error("input source domain was not created by this source set")]
    InvalidInputDomain,
    #[error("parent is not an authenticated project domain")]
    InvalidProjectDomain,
    #[error("input module path must be a bounded sequence of identifiers")]
    InvalidInputModule,
    #[error("input alias is already bound in this source set")]
    DuplicateInputAlias,
    #[error("`std` is reserved and cannot be used as an input alias")]
    ReservedInputAlias,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ids_are_stable_and_source_count_is_bounded() {
        let mut sources = SourceSet::new();
        let first = sources.add("first.srx", "").unwrap();
        let second = sources.add("second.srx", "").unwrap();

        assert_eq!(sources.get(first).unwrap().name(), "first.srx");
        assert_eq!(sources.get(second).unwrap().name(), "second.srx");

        for index in sources.len()..MAX_SOURCES {
            sources.add(index.to_string(), "").unwrap();
        }
        assert_eq!(
            sources.add("too-many.srx", "").unwrap_err(),
            SourceError::TooManySources
        );
    }

    #[test]
    fn source_domains_are_explicit_and_project_is_the_default() {
        let mut sources = SourceSet::new();
        let project = sources.add("project.srx", "").unwrap();
        let input_domain = sources.create_input_domain("input").unwrap();
        let input = sources
            .add_to_input_domain(input_domain, "input.srx", "")
            .unwrap();
        let standard = sources
            .add_standard_library("std.srx", "")
            .unwrap();

        assert_eq!(
            sources.domain(project),
            Some(SourceDomainId::PROJECT)
        );
        assert_eq!(sources.domain(input), Some(input_domain));
        assert_eq!(
            sources.domain(standard),
            Some(SourceDomainId::STANDARD_LIBRARY)
        );
    }

    #[test]
    fn input_aliases_are_bound_when_their_domains_are_created() {
        let mut sources = SourceSet::new();
        let domain = sources.create_input_domain("catalog").unwrap();

        assert_eq!(
            sources
                .input_domains()
                .unwrap()
                .get(&SourceDomainId::PROJECT)
                .and_then(|aliases| aliases.get("catalog")),
            Some(&domain)
        );
        assert_eq!(
            sources
                .create_input_domain("catalog")
                .unwrap_err(),
            SourceError::DuplicateInputAlias
        );
        assert_eq!(
            sources.create_input_domain("std").unwrap_err(),
            SourceError::ReservedInputAlias
        );
    }

    #[test]
    fn project_domains_own_isolated_bounded_alias_namespaces() {
        let mut sources = SourceSet::new();
        let first = sources
            .create_project_domain(SourceDomainId::project(), "first")
            .unwrap();
        let second = sources
            .create_project_domain(SourceDomainId::project(), "second")
            .unwrap();
        let first_dep = sources
            .create_child_input_domain(first, "dep")
            .unwrap();
        let second_dep = sources
            .create_child_input_domain(second, "dep")
            .unwrap();
        assert_ne!(first_dep, second_dep);
        assert_eq!(
            sources.create_child_input_domain(first_dep, "nested"),
            Err(SourceError::InvalidProjectDomain)
        );
        assert_eq!(
            sources.add_to_project_domain(first_dep, "invalid.srx", ""),
            Err(SourceError::InvalidProjectDomain)
        );
        assert_eq!(
            sources.create_project_domain(first, "std"),
            Err(SourceError::ReservedInputAlias)
        );
        assert_eq!(
            sources.create_project_domain(first, "dep"),
            Err(SourceError::DuplicateInputAlias)
        );
        let nested = sources
            .create_project_domain(first, "nested")
            .unwrap();
        assert!(
            sources
                .add_to_project_domain(nested, "nested/main.srx", "")
                .is_ok()
        );
    }
}
