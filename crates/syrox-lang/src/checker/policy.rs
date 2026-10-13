use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::{resolver::ResolvedItem, source::SourceDomainId};

/// Maximum checker operations under the default policy.
pub const MAX_CHECK_WORK: usize = 4_000_000;
/// Maximum expanded aliases in one type.
pub const MAX_ALIAS_DEPTH: usize = 128;
/// Maximum nested generic specialization depth.
pub const MAX_SPECIALIZATION_DEPTH: usize = 64;
/// Maximum distinct concrete generic specializations checked in one program.
pub const MAX_GENERIC_INSTANCES: usize = 4_096;
/// Maximum checked expression and contextual-pattern metadata records.
pub const MAX_METADATA_UNITS: usize = 65_536;
/// Maximum unique entries in a checking policy.
pub const MAX_POLICY_ENTRIES: usize = 4_096;
/// Maximum UTF-8 bytes retained by a checking policy.
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrimitiveType {
    Int,
    Str,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PredicateRule {
    pub name: String,
    pub input: PrimitiveType,
}

/// How a structure declaring a named ownership scope treats its enclosing scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeRule {
    /// Open a fresh boundary whenever a structure declares this scope.
    Private,
    /// Keep using the nearest enclosing boundary (the root boundary at minimum).
    Inherited,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ErasureRule {
    pub source: CanonicalItemIdentity,
    pub target: CanonicalItemIdentity,
}

/// Domain-qualified canonical item identity used by authority-bearing policy rules.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalItemIdentity {
    domain: SourceDomainId,
    path: Vec<String>,
}

impl CanonicalItemIdentity {
    pub fn new(
        domain: SourceDomainId,
        path: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, PolicyError> {
        let mut checked = Vec::new();
        let mut bytes = 0_usize;
        for segment in path {
            if checked.len() >= MAX_POLICY_ENTRIES {
                return Err(PolicyError::TooManyEntries);
            }
            let segment = segment.into();
            if !valid_identifier(&segment) {
                return Err(PolicyError::InvalidItemIdentity);
            }
            bytes = bytes
                .checked_add(segment.len())
                .ok_or(PolicyError::TooManyBytes)?;
            if bytes > MAX_POLICY_BYTES {
                return Err(PolicyError::TooManyBytes);
            }
            checked.push(segment);
        }
        if checked.is_empty() {
            return Err(PolicyError::InvalidItemIdentity);
        }
        Ok(Self {
            domain,
            path: checked,
        })
    }

    pub fn from_resolved(item: &ResolvedItem) -> Self {
        Self {
            domain: item.domain(),
            path: item.path().segments().to_vec(),
        }
    }

    pub const fn domain(&self) -> SourceDomainId {
        self.domain
    }

    pub fn path(&self) -> &[String] {
        &self.path
    }

    fn byte_len(&self) -> usize {
        self.path.iter().map(String::len).sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    TooManyEntries,
    TooManyBytes,
    ConflictingPredicate {
        name: String,
    },
    ConflictingScope {
        name: String,
    },
    InvalidName,
    InvalidItemIdentity,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries => write!(formatter, "checking policy has too many entries"),
            Self::TooManyBytes => write!(formatter, "checking policy is too large"),
            Self::ConflictingPredicate {
                name,
            } => {
                write!(
                    formatter,
                    "predicate `{name}` has conflicting declarations"
                )
            }
            Self::ConflictingScope {
                name,
            } => {
                write!(formatter, "scope `{name}` has conflicting rules")
            }
            Self::InvalidName => write!(
                formatter,
                "policy name is not a canonical source path"
            ),
            Self::InvalidItemIdentity => write!(formatter, "canonical item path cannot be empty"),
        }
    }
}

impl std::error::Error for PolicyError {}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct PolicyFingerprint([u64; 2]);

impl PolicyFingerprint {
    pub const fn words(self) -> [u64; 2] {
        self.0
    }
}

/// Closed caller-owned vocabulary used by checking and later evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckPolicy {
    pub(super) identity: String,
    pub(super) predicates: BTreeMap<String, PrimitiveType>,
    pub(super) scopes: BTreeMap<String, ScopeRule>,
    pub(super) erasures: BTreeSet<ErasureRule>,
    bytes: usize,
}

impl Default for CheckPolicy {
    fn default() -> Self {
        Self::new("syrox.empty").expect("the built-in empty policy is bounded")
    }
}

impl CheckPolicy {
    pub fn new(identity: impl Into<String>) -> Result<Self, PolicyError> {
        let identity = identity.into();
        if identity.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::TooManyBytes);
        }
        let bytes = identity.len();
        Ok(Self {
            identity,
            predicates: BTreeMap::new(),
            scopes: BTreeMap::new(),
            erasures: BTreeSet::new(),
            bytes,
        })
    }

    pub fn with_predicate(
        mut self,
        name: impl Into<String>,
        input: PrimitiveType,
    ) -> Result<Self, PolicyError> {
        let name = name.into();
        if !valid_policy_path(&name) {
            return Err(PolicyError::InvalidName);
        }
        if let Some(existing) = self.predicates.get(&name) {
            return if *existing == input {
                Ok(self)
            } else {
                Err(PolicyError::ConflictingPredicate {
                    name,
                })
            };
        }
        self.reserve_entry(name.len())?;
        self.predicates.insert(name, input);
        Ok(self)
    }

    pub fn with_scope(self, name: impl Into<String>) -> Result<Self, PolicyError> {
        self.insert_scope(name.into(), ScopeRule::Private)
    }

    pub fn with_scope_rule(
        self,
        name: impl Into<String>,
        rule: ScopeRule,
    ) -> Result<Self, PolicyError> {
        self.insert_scope(name.into(), rule)
    }

    fn insert_scope(mut self, name: String, rule: ScopeRule) -> Result<Self, PolicyError> {
        if !valid_identifier(&name) {
            return Err(PolicyError::InvalidName);
        }
        if let Some(existing) = self.scopes.get(&name) {
            return if *existing == rule {
                Ok(self)
            } else {
                Err(PolicyError::ConflictingScope {
                    name,
                })
            };
        }
        if !self.scopes.contains_key(&name) {
            self.reserve_entry(name.len())?;
            self.scopes.insert(name, rule);
        }
        Ok(self)
    }

    pub fn with_erasure(
        mut self,
        source: CanonicalItemIdentity,
        target: CanonicalItemIdentity,
    ) -> Result<Self, PolicyError> {
        let rule = ErasureRule {
            source,
            target,
        };
        if !self.erasures.contains(&rule) {
            self.reserve_entry(
                rule.source
                    .byte_len()
                    .saturating_add(rule.target.byte_len()),
            )?;
            self.erasures.insert(rule);
        }
        Ok(self)
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn predicates(&self) -> impl ExactSizeIterator<Item = PredicateRule> + '_ {
        self.predicates
            .iter()
            .map(|(name, &input)| PredicateRule {
                name: name.clone(),
                input,
            })
    }

    pub fn scopes(&self) -> impl ExactSizeIterator<Item = (&String, ScopeRule)> {
        self.scopes
            .iter()
            .map(|(name, &rule)| (name, rule))
    }

    pub(crate) fn scope_rule(&self, name: &str) -> Option<ScopeRule> {
        self.scopes.get(name).copied()
    }

    pub fn erasures(&self) -> impl ExactSizeIterator<Item = &ErasureRule> {
        self.erasures.iter()
    }

    fn reserve_entry(&mut self, bytes: usize) -> Result<(), PolicyError> {
        let entries = self
            .predicates
            .len()
            .saturating_add(self.scopes.len())
            .saturating_add(self.erasures.len());
        if entries >= MAX_POLICY_ENTRIES {
            return Err(PolicyError::TooManyEntries);
        }
        let total = self
            .bytes
            .checked_add(bytes)
            .ok_or(PolicyError::TooManyBytes)?;
        if total > MAX_POLICY_BYTES {
            return Err(PolicyError::TooManyBytes);
        }
        self.bytes = total;
        Ok(())
    }

    pub fn fingerprint(&self) -> PolicyFingerprint {
        let mut first = 0xcbf2_9ce4_8422_2325_u64;
        let mut second = 0x8422_2325_cbf2_9ce4_u64;
        let mut feed = |bytes: &[u8]| {
            for &byte in bytes {
                first = (first ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
                second = (second ^ u64::from(byte).wrapping_add(1)).wrapping_mul(0x100_0000_01b3);
            }
            first = (first ^ 0xff).wrapping_mul(0x100_0000_01b3);
            second = (second ^ 0x7f).wrapping_mul(0x100_0000_01b3);
        };
        feed(self.identity.as_bytes());
        for (name, input) in &self.predicates {
            feed(b"predicate");
            feed(name.as_bytes());
            feed(match input {
                PrimitiveType::Int => b"int",
                PrimitiveType::Str => b"str",
            });
        }
        for (scope, rule) in &self.scopes {
            feed(b"scope");
            feed(scope.as_bytes());
            feed(match rule {
                ScopeRule::Private => b"private",
                ScopeRule::Inherited => b"inherited",
            });
        }
        for erasure in &self.erasures {
            feed(b"erasure");
            feed(&erasure.source.domain.as_u32().to_le_bytes());
            for segment in &erasure.source.path {
                feed(segment.as_bytes());
            }
            feed(&erasure.target.domain.as_u32().to_le_bytes());
            for segment in &erasure.target.path {
                feed(segment.as_bytes());
            }
        }
        PolicyFingerprint([first, second])
    }
}
fn valid_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_policy_path(name: &str) -> bool {
    !name.is_empty() && name.split("::").all(valid_identifier)
}
