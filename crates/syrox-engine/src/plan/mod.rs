//! Turning checked values into descriptions of acquisition, builds and consumers.
//!
//! This stage walks the graph and checks its limits before any effects. Shared
//! recipe identity is preserved in the plan; equal names in different projects
//! do not make packages equal. [`crate::realize`] uses the resulting descriptions
//! to acquire sources and execute selected builds.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::mem::size_of;

use syrox_lang::{
    checker::CanonicalItemIdentity, evaluator::CanonicalType, evaluator::MemoId,
    evaluator::PrimitiveValue, evaluator::RealizedProgram, evaluator::RealizedRootOutcome,
    evaluator::ResourceClaim, evaluator::Value,
};

use crate::project::AuthenticatedStandardLibrary;
use crate::store::{ContentDigest, MAX_STORE_BLOB_BYTES};

mod builds;
mod imports;
pub use imports::PlanImportedResult;
mod recipes;
pub use builds::PlanBuild;
mod outputs;
pub use outputs::PlanOutputRef;
mod apps;
pub use apps::{PlanCommand, PlanCommandRef, PlanRuntimeFile};
mod consumers;
pub use consumers::{
    PlanCommandArgument, PlanCommandEnvironment, PlanConfigFile, PlanConsumer, PlanConsumerKind,
    PlanPackageSelection, PlanService, PlanServiceCommand, PlanServiceProcess, PlanServiceState,
};
mod display;
use display::canonical_display_bytes;

pub const MAX_PLAN_PACKAGE_NODES: usize = 65_536;
pub const MAX_PLAN_PACKAGE_EDGES: usize = 262_144;
pub const MAX_PLAN_PACKAGE_WORK: usize = 4_000_000;
pub const MAX_PACKAGE_ID_BYTES: usize = 255;
pub const MAX_PLAN_SOURCE_REQUESTS: usize = 262_144;
const ACQUISITION_PATH: &[&str] = &["std", "pkg", "Acquisition"];
const SOURCE_REQUEST_PATH: &[&str] = &["std", "pkg", "SourceRequest"];
const SOURCE_URL_PATH: &[&str] = &["std", "pkg", "SourceUrl"];
const SOURCE_DIGEST_PATH: &[&str] = &["std", "pkg", "SourceDigest"];
const SOURCE_LIMIT_PATH: &[&str] = &["std", "pkg", "SourceLimit"];
/// Maximum nodes and strings visited while projecting a realized program.
pub const MAX_PLAN_PROJECTION_WORK: usize = 4_000_000;
/// Maximum accounted bytes retained by a projected plan.
pub const MAX_PLAN_RETAINED_BYTES: usize = 64 * 1024 * 1024;
/// Maximum bytes in the canonical `Plan` display encoding.
pub const MAX_PLAN_DISPLAY_BYTES: usize = 64 * 1024 * 1024;

const PACKAGE_PATH: &[&str] = &["std", "pkg", "Package"];
const PACKAGE_ID_PATH: &[&str] = &["std", "pkg", "PackageId"];
const DEPENDENCY_PATH: &[&str] = &["std", "pkg", "Dependency"];

/// A graph node identified by its selected root, with package metadata for
/// diagnostics. Labels may repeat; comparisons always include the node path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanPackageId {
    label: String,
    domain: u32,
    path: Vec<String>,
}

impl PlanPackageId {
    pub fn as_str(&self) -> &str {
        &self.label
    }

    pub const fn domain(&self) -> u32 {
        self.domain
    }

    pub fn path(&self) -> &[String] {
        &self.path
    }

    fn new(
        identity: &CanonicalItemIdentity,
        label: &str,
        budget: &mut ProjectionBudget,
    ) -> Result<Self, PlanError> {
        budget.node::<Self>()?;
        Ok(Self {
            label: budget.string(label)?,
            domain: identity.domain().as_u32(),
            path: plan_path(identity.path(), budget)?,
        })
    }

    fn copy(&self, budget: &mut ProjectionBudget) -> Result<Self, PlanError> {
        budget.node::<Self>()?;
        Ok(Self {
            label: budget.string(&self.label)?,
            domain: self.domain,
            path: plan_path(&self.path, budget)?,
        })
    }
}

impl fmt::Display for PlanPackageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.label)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanPackage {
    id: PlanPackageId,
    recipe_owner: Option<syrox_lang::source::SourceDomainId>,
    export: Option<String>,
    aliases: Vec<String>,
    dependencies: Vec<PlanPackageId>,
}

impl PlanPackage {
    pub const fn recipe_owner(&self) -> Option<syrox_lang::source::SourceDomainId> {
        self.recipe_owner
    }
    pub const fn id(&self) -> &PlanPackageId {
        &self.id
    }

    pub fn dependencies(&self) -> impl ExactSizeIterator<Item = &PlanPackageId> {
        self.dependencies.iter()
    }

    /// Root project export selectable by the public reference syntax.
    pub fn export(&self) -> Option<&str> {
        self.export.as_deref()
    }

    pub fn has_export(&self, name: &str) -> bool {
        self.export() == Some(name) || self.aliases.iter().any(|alias| alias == name)
    }
}

/// A pinned source requested by one explicit acquisition operation, not a graph edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSourceRequest {
    url: String,
    digest: ContentDigest,
    maximum_bytes: u64,
    owner: Option<syrox_lang::source::SourceDomainId>,
}

impl PlanSourceRequest {
    pub fn url(&self) -> &str {
        &self.url
    }
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }
    pub const fn owner(&self) -> Option<syrox_lang::source::SourceDomainId> {
        self.owner
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanAcquisition {
    package: PlanPackageId,
    sources: Vec<PlanSourceRequest>,
}

impl PlanAcquisition {
    pub const fn package(&self) -> &PlanPackageId {
        &self.package
    }
    pub fn sources(&self) -> impl ExactSizeIterator<Item = &PlanSourceRequest> {
        self.sources.iter()
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("consumer {root:?} is invalid: {reason}")]
    InvalidConsumer {
        root: String,
        reason: &'static str,
    },
    #[error("service {service:?} in consumer {root:?} is invalid: {reason}")]
    InvalidService {
        root: String,
        service: String,
        reason: &'static str,
    },
    #[error(
        "configuration file {path:?} in service {service:?} of consumer {root:?} is invalid: {reason}"
    )]
    InvalidConfigFile {
        root: String,
        service: String,
        path: String,
        reason: &'static str,
    },
    #[error("invalid recipe root `{root}`: {reason}")]
    InvalidRecipe {
        root: String,
        reason: &'static str,
    },
    #[error("function values cannot be serialized into a plan")]
    FunctionValue,
    #[error("build root `{root}` is invalid: {reason}")]
    InvalidBuild {
        root: String,
        reason: &'static str,
    },
    #[error("command root `{root}` is invalid: {reason}")]
    InvalidCommand {
        root: String,
        reason: &'static str,
    },
    #[error("acquisition root `{root}` has malformed exact std::pkg::Acquisition value: {reason}")]
    MalformedAcquisition {
        root: String,
        reason: &'static str,
    },
    #[error("acquisition for `{package}` has invalid source request: {reason}")]
    InvalidSourceRequest {
        package: PlanPackageId,
        reason: &'static str,
    },
    #[error("acquisition source count exceeds the {MAX_PLAN_SOURCE_REQUESTS}-request limit")]
    SourceRequestLimit,
    #[error("realized root `{root}` did not produce a value")]
    UnrealizedRoot {
        root: String,
    },
    #[error("realized root `{root}` has no canonical type")]
    MissingRootType {
        root: String,
    },
    #[error("package root `{root}` has malformed exact std::pkg::Package value: {reason}")]
    MalformedPackage {
        root: String,
        reason: &'static str,
    },
    #[error("invalid package ID `{id}`; expected ASCII [a-z0-9][a-z0-9+._-]{{0,254}}")]
    InvalidPackageId {
        id: String,
    },
    #[error("duplicate package ID `{id}`")]
    DuplicatePackageId {
        id: PlanPackageId,
    },
    #[error("package `{package}` repeats dependency `{dependency}`")]
    DuplicateDependency {
        package: PlanPackageId,
        dependency: PlanPackageId,
    },
    #[error("package `{package}` depends on missing package `{dependency}`")]
    MissingDependency {
        package: PlanPackageId,
        dependency: PlanPackageId,
    },
    #[error("package dependency cycle: {}", display_cycle(.packages))]
    Cycle {
        packages: Vec<PlanPackageId>,
    },
    #[error("package dependency graph exceeds the {MAX_PLAN_PACKAGE_NODES}-node limit")]
    NodeLimit,
    #[error("package dependency graph exceeds the {MAX_PLAN_PACKAGE_EDGES}-edge limit")]
    EdgeLimit,
    #[error("package dependency graph exceeds the {MAX_PLAN_PACKAGE_WORK}-work-unit limit")]
    WorkLimit,
    #[error("plan projection exceeds its {limit}-work-unit limit")]
    ProjectionWorkLimit {
        limit: usize,
    },
    #[error("plan projection exceeds its {limit}-retained-byte limit")]
    ProjectionRetainedBytesLimit {
        limit: usize,
    },
    #[error("canonical plan display exceeds its {limit}-byte limit")]
    DisplayBytesLimit {
        limit: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanStandardLibrary {
    digest: [u8; 32],
}

impl PlanStandardLibrary {
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlanType {
    Unit,
    Int,
    Str,
    Nominal {
        domain: u32,
        path: Vec<String>,
    },
    Specialization {
        domain: u32,
        path: Vec<String>,
        arguments: Vec<PlanType>,
    },
    List(Box<PlanType>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlanValue {
    Reference {
        domain: u32,
        path: Vec<String>,
    },
    Unit,
    Int(i64),
    Str(String),
    Nominal {
        ty: PlanType,
        value: Box<PlanValue>,
        resource: bool,
    },
    List {
        ty: PlanType,
        items: Vec<PlanValue>,
    },
    Struct {
        ty: PlanType,
        fields: Vec<(String, PlanValue)>,
    },
    Variant {
        ty: PlanType,
        index: u32,
        payload: Vec<PlanValue>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanClaim {
    ty: PlanType,
    value: PlanValue,
    scope_root_domain: u32,
    scope_root_path: Vec<String>,
    scope_name: Option<String>,
    boundary: u64,
}

impl PlanClaim {
    pub const fn ty(&self) -> &PlanType {
        &self.ty
    }

    pub const fn value(&self) -> &PlanValue {
        &self.value
    }

    pub const fn scope_root_domain(&self) -> u32 {
        self.scope_root_domain
    }

    pub fn scope_root_path(&self) -> &[String] {
        &self.scope_root_path
    }

    pub fn scope_name(&self) -> Option<&str> {
        self.scope_name.as_deref()
    }

    pub const fn boundary(&self) -> u64 {
        self.boundary
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanRoot {
    name: String,
    domain: u32,
    path: Vec<String>,
    ty: PlanType,
    value: PlanValue,
    claims: Vec<PlanClaim>,
}

impl PlanRoot {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn domain(&self) -> u32 {
        self.domain
    }

    pub fn path(&self) -> &[String] {
        &self.path
    }

    pub const fn ty(&self) -> &PlanType {
        &self.ty
    }

    pub const fn value(&self) -> &PlanValue {
        &self.value
    }

    pub fn claims(&self) -> impl ExactSizeIterator<Item = &PlanClaim> {
        self.claims.iter()
    }
}

/// Pure, bounded description of a selected graph. Physical project locations,
/// snapshot ownership and execution leases belong to `PreparedPlan` and consumers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    lock_digest: [u8; 32],
    policy_identity: String,
    standard_library: Option<PlanStandardLibrary>,
    packages: Vec<PlanPackage>,
    acquisitions: Vec<PlanAcquisition>,
    builds: Vec<PlanBuild>,
    imports: Vec<PlanImportedResult>,
    commands: Vec<PlanCommand>,
    consumers: Vec<PlanConsumer>,
    package_edges: usize,
    roots: Vec<PlanRoot>,
    canonical_display_bytes: usize,
}

impl Plan {
    pub const fn lock_digest(&self) -> &[u8; 32] {
        &self.lock_digest
    }

    pub fn policy_identity(&self) -> &str {
        &self.policy_identity
    }

    pub const fn standard_library(&self) -> Option<&PlanStandardLibrary> {
        self.standard_library.as_ref()
    }

    /// Packages in dependency-first topological order, with lexical ties.
    pub fn packages(&self) -> impl ExactSizeIterator<Item = &PlanPackage> {
        self.packages.iter()
    }

    pub fn acquisitions(&self) -> impl ExactSizeIterator<Item = &PlanAcquisition> {
        self.acquisitions.iter()
    }

    pub fn imports(&self) -> impl ExactSizeIterator<Item = &PlanImportedResult> {
        self.imports.iter()
    }

    pub fn builds(&self) -> impl ExactSizeIterator<Item = &PlanBuild> {
        self.builds.iter()
    }

    pub fn commands(&self) -> impl ExactSizeIterator<Item = &PlanCommand> {
        self.commands.iter()
    }

    /// Pure deployment descriptions; their presence does not activate a consumer.
    pub fn consumers(&self) -> impl ExactSizeIterator<Item = &PlanConsumer> {
        self.consumers.iter()
    }

    pub fn roots(&self) -> impl ExactSizeIterator<Item = &PlanRoot> {
        self.roots.iter()
    }

    pub(crate) fn from_realized(
        realized: &RealizedProgram,
        lock_digest: [u8; 32],
        policy_identity: &str,
        standard_library: Option<&AuthenticatedStandardLibrary>,
    ) -> Result<Self, PlanError> {
        let mut budget = ProjectionBudget::new(MAX_PLAN_PROJECTION_WORK, MAX_PLAN_RETAINED_BYTES);
        budget.node::<Plan>()?;
        let policy_identity = budget.string(policy_identity)?;
        let plan_standard_library = standard_library
            .map(|library| {
                budget.node::<PlanStandardLibrary>()?;
                Ok(PlanStandardLibrary {
                    digest: *library.digest(),
                })
            })
            .transpose()?;
        let roots = project_roots(realized, &mut budget)?;
        let components = recipes::components(realized, standard_library, &mut budget)?;
        let references = package_references(&components, &mut budget)?;
        let (packages, package_edges) = extract_packages(
            &components,
            &references,
            standard_library,
            &mut budget,
        )?;
        let package_index = PackageIndex::new(&packages, &mut budget)?;
        let acquisitions = extract_acquisitions(
            &components,
            &package_index,
            standard_library,
            &mut budget,
        )?;
        let imports = imports::extract(&components, &package_index, &mut budget)?;
        let builds = builds::extract(
            &components,
            &package_index,
            &acquisitions,
            &imports,
            &references,
            standard_library,
            &mut budget,
        )?;
        let commands = apps::extract(
            &components,
            &package_index,
            &builds,
            &imports,
            &references,
            standard_library,
            &mut budget,
        )?;
        builds::validate_execution_graph(&builds, &mut budget)?;
        let consumers = consumers::extract(
            &components,
            &references,
            &builds,
            &imports,
            &commands,
            standard_library,
            &mut budget,
        )?;
        let mut plan = Self {
            lock_digest,
            policy_identity,
            standard_library: plan_standard_library,
            packages,
            acquisitions,
            builds,
            imports,
            commands,
            consumers,
            package_edges,
            roots,
            canonical_display_bytes: 0,
        };
        plan.canonical_display_bytes = canonical_display_bytes(&plan, MAX_PLAN_DISPLAY_BYTES)?;
        Ok(plan)
    }
}

fn project_roots(
    realized: &RealizedProgram,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanRoot>, PlanError> {
    let references = selected_references(realized, budget)?;
    let root_count = realized.roots().len();
    let mut roots = budget.collection::<PlanRoot>(root_count)?;
    for root in realized.roots() {
        budget.node::<PlanRoot>()?;
        let RealizedRootOutcome::Value(value) = root.outcome() else {
            return Err(PlanError::UnrealizedRoot {
                root: budget.string(root.name())?,
            });
        };
        let Some(ty) = root.ty() else {
            return Err(PlanError::MissingRootType {
                root: budget.string(root.name())?,
            });
        };
        let identity = root.identity();
        let mut claims = budget.collection::<PlanClaim>(root.claims().len())?;
        for claim in root.claims() {
            claims.push(plan_claim(claim, budget)?);
        }
        claims.sort();
        roots.push(PlanRoot {
            name: budget.string(root.name())?,
            domain: identity.domain().as_u32(),
            path: plan_path(identity.path(), budget)?,
            ty: plan_type(ty, budget)?,
            value: plan_value_with_refs(value, budget, &references)?,
            claims,
        });
    }
    roots.sort_by(|left, right| (&left.domain, &left.path).cmp(&(&right.domain, &right.path)));
    Ok(roots)
}

fn selected_references<'a>(
    realized: &'a RealizedProgram,
    budget: &mut ProjectionBudget,
) -> Result<BTreeMap<&'a MemoId, &'a CanonicalItemIdentity>, PlanError> {
    let mut references = BTreeMap::new();
    for root in realized.roots() {
        if let Some(id) = root.selected_reference() {
            budget.node::<(&MemoId, &CanonicalItemIdentity)>()?;
            references.insert(id, root.identity());
        }
    }
    Ok(references)
}

#[derive(Debug)]
struct PackageCandidate {
    id: PlanPackageId,
    export: Option<String>,
    aliases: Vec<String>,
    dependencies: Vec<PlanPackageId>,
}

#[derive(Debug)]
struct Work(usize);

impl Work {
    fn charge(&mut self) -> Result<(), PlanError> {
        self.0 = self
            .0
            .checked_add(1)
            .ok_or(PlanError::WorkLimit)?;
        if self.0 > MAX_PLAN_PACKAGE_WORK {
            return Err(PlanError::WorkLimit);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ProjectionBudget {
    work: usize,
    retained_bytes: usize,
    work_limit: usize,
    retained_bytes_limit: usize,
}

impl ProjectionBudget {
    const fn new(work_limit: usize, retained_bytes_limit: usize) -> Self {
        Self {
            work: 0,
            retained_bytes: 0,
            work_limit,
            retained_bytes_limit,
        }
    }

    fn charge_work(&mut self) -> Result<(), PlanError> {
        self.charge_work_units(1)
    }

    fn charge_work_units(&mut self, units: usize) -> Result<(), PlanError> {
        self.work = self
            .work
            .checked_add(units)
            .ok_or(PlanError::ProjectionWorkLimit {
                limit: self.work_limit,
            })?;
        if self.work > self.work_limit {
            return Err(PlanError::ProjectionWorkLimit {
                limit: self.work_limit,
            });
        }
        Ok(())
    }

    fn bytes(&mut self, bytes: usize) -> Result<(), PlanError> {
        self.retained_bytes = self.retained_bytes.checked_add(bytes).ok_or(
            PlanError::ProjectionRetainedBytesLimit {
                limit: self.retained_bytes_limit,
            },
        )?;
        if self.retained_bytes > self.retained_bytes_limit {
            return Err(PlanError::ProjectionRetainedBytesLimit {
                limit: self.retained_bytes_limit,
            });
        }
        Ok(())
    }

    fn node<T>(&mut self) -> Result<(), PlanError> {
        self.charge_work()?;
        self.bytes(size_of::<T>())
    }

    fn collection<T>(&mut self, len: usize) -> Result<Vec<T>, PlanError> {
        let bytes =
            len.checked_mul(size_of::<T>())
                .ok_or(PlanError::ProjectionRetainedBytesLimit {
                    limit: self.retained_bytes_limit,
                })?;
        self.bytes(bytes)?;
        Ok(Vec::with_capacity(len))
    }

    fn string(&mut self, value: &str) -> Result<String, PlanError> {
        self.charge_work()?;
        self.bytes(size_of::<String>())?;
        self.bytes(value.len())?;
        Ok(value.to_owned())
    }
}

fn package_references<'a>(
    components: &'a [recipes::Component<'a>],
    budget: &mut ProjectionBudget,
) -> Result<BTreeMap<&'a MemoId, PlanPackageId>, PlanError> {
    let mut references = BTreeMap::new();
    for root in components {
        if !exact_nominal(root.ty(), PACKAGE_PATH) || !root.belongs_to_plan() {
            continue;
        }
        if let Some(reference) = root.reference() {
            budget.node::<(&MemoId, PlanPackageId)>()?;
            let package = match root.value() {
                Value::Struct {
                    fields,
                    ..
                } => fields
                    .first()
                    .and_then(|(_, value)| decode_package_id(value)),
                _ => None,
            }
            .ok_or_else(|| PlanError::MalformedPackage {
                root: root.name().to_owned(),
                reason: "selected reference has no package ID",
            })?;
            references.insert(
                reference,
                PlanPackageId::new(root.identity(), package, budget)?,
            );
        }
    }
    Ok(references)
}

fn extract_packages(
    components: &[recipes::Component<'_>],
    references: &BTreeMap<&MemoId, PlanPackageId>,
    standard_library: Option<&AuthenticatedStandardLibrary>,
    budget: &mut ProjectionBudget,
) -> Result<(Vec<PlanPackage>, usize), PlanError> {
    if standard_library.is_none() {
        return Ok((Vec::new(), 0));
    }

    let mut exact_roots: Vec<_> = components
        .iter()
        .filter(|root| root.belongs_to_plan() && exact_nominal(root.ty(), PACKAGE_PATH))
        .collect();
    exact_roots.sort_by(|left, right| {
        (left.identity(), left.name()).cmp(&(right.identity(), right.name()))
    });
    if exact_roots.len() > MAX_PLAN_PACKAGE_NODES {
        return Err(PlanError::NodeLimit);
    }

    let mut work = Work(0);
    let mut edge_count = 0_usize;
    let mut candidates = Vec::with_capacity(exact_roots.len());
    let mut owners = BTreeMap::new();
    for root in exact_roots {
        work.charge()?;
        let value = root.value();
        let mut candidate = decode_package(
            root.name(),
            root.identity(),
            value,
            references,
            &mut edge_count,
            &mut work,
            budget,
        )?;
        if root.identity().path().len() == 1 || root.is_selected() {
            candidate.export = Some(budget.string(root.name())?);
        }
        for alias in root
            .aliases()
            .filter(|alias| *alias != root.name())
        {
            candidate.aliases.push(budget.string(alias)?);
        }
        owners.insert(candidate.id.copy(budget)?, root.recipe_owner());
        candidates.push(candidate);
    }
    candidates.sort_by(|left, right| {
        (&left.id, &left.dependencies).cmp(&(&right.id, &right.dependencies))
    });

    let mut invalid = BTreeSet::new();
    for candidate in &candidates {
        work.charge()?;
        if !valid_package_id(candidate.id.as_str()) {
            invalid.insert(candidate.id.as_str());
        }
        for dependency in &candidate.dependencies {
            work.charge()?;
            if !valid_package_id(dependency.as_str()) {
                invalid.insert(dependency.as_str());
            }
        }
    }
    if let Some(id) = invalid.into_iter().next() {
        return Err(PlanError::InvalidPackageId {
            id: budget.string(id)?,
        });
    }

    for pair in candidates.windows(2) {
        work.charge()?;
        if pair[0].id == pair[1].id {
            return Err(PlanError::DuplicatePackageId {
                id: pair[0].id.copy(budget)?,
            });
        }
    }

    let mut duplicate_edges = BTreeSet::new();
    for candidate in &mut candidates {
        candidate.dependencies.sort_unstable();
        for pair in candidate.dependencies.windows(2) {
            work.charge()?;
            if pair[0] == pair[1] {
                duplicate_edges.insert((candidate.id.clone(), pair[0].clone()));
            }
        }
    }
    if let Some((package, dependency)) = duplicate_edges.into_iter().next() {
        return Err(PlanError::DuplicateDependency {
            package,
            dependency,
        });
    }

    let mut nodes = BTreeMap::new();
    let mut exports = BTreeMap::new();
    let mut aliases = BTreeMap::new();
    for candidate in candidates {
        work.charge()?;
        exports.insert(candidate.id.clone(), candidate.export);
        aliases.insert(candidate.id.clone(), candidate.aliases);
        nodes.insert(candidate.id, candidate.dependencies);
    }
    let mut missing = BTreeSet::new();
    for (package, dependencies) in &nodes {
        for dependency in dependencies {
            work.charge()?;
            if !nodes.contains_key(dependency) {
                missing.insert((package.clone(), dependency.clone()));
            }
        }
    }
    if let Some((package, dependency)) = missing.into_iter().next() {
        return Err(PlanError::MissingDependency {
            package,
            dependency,
        });
    }

    let mut indegree = BTreeMap::new();
    let mut dependents: BTreeMap<&PlanPackageId, Vec<&PlanPackageId>> = BTreeMap::new();
    for (package, dependencies) in &nodes {
        work.charge()?;
        indegree.insert(package, dependencies.len());
        for dependency in dependencies {
            work.charge()?;
            dependents
                .entry(dependency)
                .or_default()
                .push(package);
        }
    }
    let mut ready = BTreeSet::new();
    for (&package, &count) in &indegree {
        work.charge()?;
        if count == 0 {
            ready.insert(package);
        }
    }
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(package) = ready.pop_first() {
        work.charge()?;
        order.push(package);
        if let Some(items) = dependents.get(package) {
            for dependent in items {
                work.charge()?;
                let count = indegree
                    .get_mut(dependent)
                    .expect("validated package dependency has an indegree");
                *count -= 1;
                if *count == 0 {
                    ready.insert(dependent);
                }
            }
        }
    }
    if order.len() != nodes.len() {
        let mut unresolved = BTreeSet::new();
        for (&package, &count) in &indegree {
            work.charge()?;
            if count > 0 {
                unresolved.insert(package);
            }
        }
        let packages = cycle_witness(&nodes, &unresolved, &mut work, budget)?;
        return Err(PlanError::Cycle {
            packages,
        });
    }

    let mut packages = budget.collection::<PlanPackage>(order.len())?;
    for id in order {
        budget.node::<PlanPackage>()?;
        let mut dependencies = budget.collection::<PlanPackageId>(nodes[id].len())?;
        for dependency in &nodes[id] {
            budget.node::<PlanPackageId>()?;
            dependencies.push(dependency.copy(budget)?);
        }
        budget.node::<PlanPackageId>()?;
        packages.push(PlanPackage {
            id: id.copy(budget)?,
            recipe_owner: owners[id],
            export: exports[id]
                .as_deref()
                .map(|name| budget.string(name))
                .transpose()?,
            aliases: aliases
                .remove(id)
                .expect("indexed package aliases"),
            dependencies,
        });
    }
    Ok((packages, edge_count))
}

fn extract_acquisitions(
    components: &[recipes::Component<'_>],
    packages: &PackageIndex<'_>,
    standard_library: Option<&AuthenticatedStandardLibrary>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanAcquisition>, PlanError> {
    if standard_library.is_none() {
        return Ok(Vec::new());
    }
    let mut roots: Vec<_> = components
        .iter()
        .filter(|root| root.belongs_to_plan() && exact_nominal(root.ty(), ACQUISITION_PATH))
        .collect();
    roots.sort_by(|left, right| {
        (left.identity(), left.name()).cmp(&(right.identity(), right.name()))
    });
    if roots.len() > MAX_PLAN_PACKAGE_NODES {
        return Err(PlanError::NodeLimit);
    }
    let mut acquisitions = budget.collection::<PlanAcquisition>(roots.len())?;
    let mut source_count = 0_usize;
    for root in roots {
        budget.node::<PlanAcquisition>()?;
        let root_name = budget.string(root.name())?;
        let malformed = |reason| PlanError::MalformedAcquisition {
            root: root_name.clone(),
            reason,
        };
        let Value::Struct {
            ty,
            fields,
            ..
        } = root.value()
        else {
            return Err(malformed("value is not a struct"));
        };
        if !exact_nominal(ty, ACQUISITION_PATH) || fields.len() != 1 || fields[0].0 != "sources" {
            return Err(malformed("fields are not exactly `sources`"));
        }
        let package_id = packages.component(root)?.id().copy(budget)?;
        let Value::List {
            ty,
            items,
        } = &fields[0].1
        else {
            return Err(malformed("`sources` is not a list"));
        };
        if !matches!(ty.as_ref(), CanonicalType::List(item) if exact_nominal(item, SOURCE_REQUEST_PATH))
        {
            return Err(malformed("`sources` has the wrong list type"));
        }
        source_count = source_count
            .checked_add(items.len())
            .ok_or(PlanError::SourceRequestLimit)?;
        if source_count > MAX_PLAN_SOURCE_REQUESTS {
            return Err(PlanError::SourceRequestLimit);
        }
        let mut sources = budget.collection::<PlanSourceRequest>(items.len())?;
        for item in items {
            budget.node::<PlanSourceRequest>()?;
            let invalid = |reason| PlanError::InvalidSourceRequest {
                package: package_id.clone(),
                reason,
            };
            let Value::Struct {
                ty,
                fields,
                owner,
            } = item
            else {
                return Err(invalid("value is not a SourceRequest struct"));
            };
            if !exact_nominal(ty, SOURCE_REQUEST_PATH)
                || fields.len() != 3
                || fields[0].0 != "url"
                || fields[1].0 != "sha256"
                || fields[2].0 != "maximum_bytes"
            {
                return Err(invalid(
                    "fields are not exactly `url`, `sha256`, `maximum_bytes`",
                ));
            }
            let url = decode_nominal_string(&fields[0].1, SOURCE_URL_PATH)
                .ok_or_else(|| invalid("`url` is not SourceUrl"))?;
            if !valid_source_url(url) {
                return Err(invalid("unsupported or malformed source URL"));
            }
            let digest_text = decode_nominal_string(&fields[1].1, SOURCE_DIGEST_PATH)
                .ok_or_else(|| invalid("`sha256` is not SourceDigest"))?;
            let digest = digest_text
                .parse()
                .map_err(|_| invalid("invalid SHA-256 digest"))?;
            let limit = match &fields[2].1 {
                Value::Nominal {
                    ty,
                    value: PrimitiveValue::Int(value),
                    resource: false,
                } if exact_nominal(ty, SOURCE_LIMIT_PATH) => {
                    u64::try_from(*value).map_err(|_| invalid("negative source byte limit"))?
                }
                _ => return Err(invalid("`maximum_bytes` is not SourceLimit")),
            };
            if limit > MAX_STORE_BLOB_BYTES {
                return Err(invalid(
                    "source byte limit exceeds the Store maximum",
                ));
            }
            sources.push(PlanSourceRequest {
                url: budget.string(url)?,
                digest,
                maximum_bytes: limit,
                owner: *owner,
            });
        }
        acquisitions.push(PlanAcquisition {
            package: package_id,
            sources,
        });
    }
    acquisitions.sort_by(|left, right| left.package.cmp(&right.package));
    Ok(acquisitions)
}

/// Components inherit their root recipe's node; metadata labels never select
/// an owner. Share one borrowed index across all component projections.
struct PackageIndex<'a>(BTreeMap<(u32, &'a [String]), &'a PlanPackage>);

impl<'a> PackageIndex<'a> {
    fn new(packages: &'a [PlanPackage], budget: &mut ProjectionBudget) -> Result<Self, PlanError> {
        let mut index = BTreeMap::new();
        for package in packages {
            budget.node::<((u32, &[String]), &PlanPackage)>()?;
            budget.bytes(6 * size_of::<usize>())?;
            index.insert(
                (package.id.domain, package.id.path.as_slice()),
                package,
            );
        }
        Ok(Self(index))
    }

    fn component(&self, root: &recipes::Component<'_>) -> Result<&'a PlanPackage, PlanError> {
        self.0
            .get(&(
                root.identity().domain().as_u32(),
                root.identity().path(),
            ))
            .copied()
            .ok_or_else(|| PlanError::InvalidRecipe {
                root: root.name().to_owned(),
                reason: "component must belong to a Recipe",
            })
    }
}

fn decode_nominal_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    match value {
        Value::Nominal {
            ty,
            value: PrimitiveValue::Str(value),
            resource: false,
        } if exact_nominal(ty, path) => Some(value),
        _ => None,
    }
}

fn valid_source_url(value: &str) -> bool {
    if let Some(path) = value.strip_prefix("project:") {
        return crate::build::relative_path(path);
    }
    if value.starts_with("file:///") {
        return crate::acquire::local::parse_file_url(value).is_ok();
    }
    crate::acquire::https::validate_https_url(value).is_ok()
}

fn decode_package(
    root: &str,
    identity: &CanonicalItemIdentity,
    value: &Value,
    references: &BTreeMap<&MemoId, PlanPackageId>,
    edge_count: &mut usize,
    work: &mut Work,
    budget: &mut ProjectionBudget,
) -> Result<PackageCandidate, PlanError> {
    let Value::Struct {
        ty,
        fields,
        ..
    } = value
    else {
        return Err(malformed_package(
            root,
            "value is not a struct",
            budget,
        )?);
    };
    if !exact_nominal(ty, PACKAGE_PATH) {
        return Err(malformed_package(
            root,
            "struct has the wrong canonical type",
            budget,
        )?);
    }
    if fields.len() != 2 || fields[0].0 != "id" || fields[1].0 != "dependencies" {
        return Err(malformed_package(
            root,
            "fields are not exactly `id`, `dependencies`",
            budget,
        )?);
    }
    let Some(id) = decode_package_id(&fields[0].1) else {
        return Err(malformed_package(
            root,
            "`id` is not PackageId",
            budget,
        )?);
    };
    let Value::List {
        ty: dependencies_ty,
        items,
    } = &fields[1].1
    else {
        return Err(malformed_package(
            root,
            "`dependencies` is not a list",
            budget,
        )?);
    };
    if !matches!(dependencies_ty.as_ref(), CanonicalType::List(item) if exact_nominal(item, DEPENDENCY_PATH))
    {
        return Err(malformed_package(
            root,
            "`dependencies` has the wrong list type",
            budget,
        )?);
    }
    *edge_count = edge_count
        .checked_add(items.len())
        .ok_or(PlanError::EdgeLimit)?;
    if *edge_count > MAX_PLAN_PACKAGE_EDGES {
        return Err(PlanError::EdgeLimit);
    }
    let mut dependencies = Vec::with_capacity(items.len());
    for dependency in items {
        work.charge()?;
        let Value::Struct {
            ty,
            fields,
            ..
        } = dependency
        else {
            return Err(malformed_package(
                root,
                "dependency is not a Dependency struct",
                budget,
            )?);
        };
        if !exact_nominal(ty, DEPENDENCY_PATH) || fields.len() != 1 || fields[0].0 != "recipe" {
            return Err(malformed_package(
                root,
                "dependency is not exact std::pkg::Dependency",
                budget,
            )?);
        }
        let Some(reference) = decode_recipe_ref(&fields[0].1) else {
            return Err(malformed_package(
                root,
                "dependency `recipe` is not a RecipeRef",
                budget,
            )?);
        };
        let dependency = references
            .get(reference)
            .ok_or_else(|| PlanError::MalformedPackage {
                root: root.to_owned(),
                reason: "dependency reference has no selected recipe",
            })?;
        dependencies.push(dependency.copy(budget)?);
    }
    Ok(PackageCandidate {
        id: PlanPackageId::new(identity, id, budget)?,
        export: None,
        aliases: Vec::new(),
        dependencies,
    })
}

fn malformed_package(
    root: &str,
    reason: &'static str,
    budget: &mut ProjectionBudget,
) -> Result<PlanError, PlanError> {
    Ok(PlanError::MalformedPackage {
        root: budget.string(root)?,
        reason,
    })
}

fn decode_package_id(value: &Value) -> Option<&str> {
    match value {
        Value::Nominal {
            ty,
            value: PrimitiveValue::Str(value),
            resource: false,
        } if exact_nominal(ty, PACKAGE_ID_PATH) => Some(value),
        _ => None,
    }
}

fn decode_recipe_ref(value: &Value) -> Option<&MemoId> {
    let Value::Struct {
        ty,
        fields,
        ..
    } = value
    else {
        return None;
    };
    if !matches!(ty.as_ref(), CanonicalType::Specialization { template, arguments }
        if template.domain() == syrox_lang::source::SourceDomainId::standard_library()
            && template.path() == ["std", "recipe", "RecipeRef"]
            && matches!(arguments.as_slice(), [recipe] if exact_nominal(recipe, &["std", "pkg", "Recipe"])))
    {
        return None;
    }
    match fields.as_slice() {
        [
            (
                name,
                Value::MemoizedFunction {
                    id,
                    ..
                },
            ),
        ] if name == "factory" => Some(id),
        _ => None,
    }
}

fn decode_output_ref(value: &Value) -> Option<(&MemoId, &str)> {
    let Value::Struct {
        ty,
        fields,
        ..
    } = value
    else {
        return None;
    };
    if !matches!(ty.as_ref(), CanonicalType::Specialization { template, arguments }
        if template.domain() == syrox_lang::source::SourceDomainId::standard_library()
            && template.path() == ["std", "recipe", "OutputRef"]
            && matches!(arguments.as_slice(), [recipe] if exact_nominal(recipe, &["std", "pkg", "Recipe"])))
    {
        return None;
    }
    match fields.as_slice() {
        [(recipe, value), (output, name)] if recipe == "recipe" && output == "output" => Some((
            decode_recipe_ref(value)?,
            decode_nominal_string(name, &["std", "pkg", "OutputName"])?,
        )),
        _ => None,
    }
}

fn exact_nominal(ty: &CanonicalType, path: &[&str]) -> bool {
    matches!(ty, CanonicalType::Nominal(identity)
        if identity.domain() == syrox_lang::source::SourceDomainId::standard_library()
            && identity.path().iter().map(String::as_str).eq(path.iter().copied()))
}

pub(crate) fn valid_package_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_PACKAGE_ID_BYTES
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().skip(1).all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'+' | b'.' | b'_' | b'-')
        })
}

fn cycle_witness(
    nodes: &BTreeMap<PlanPackageId, Vec<PlanPackageId>>,
    unresolved: &BTreeSet<&PlanPackageId>,
    work: &mut Work,
    budget: &mut ProjectionBudget,
) -> Result<Vec<PlanPackageId>, PlanError> {
    let mut state: BTreeMap<&PlanPackageId, u8> = BTreeMap::new();
    for &start in unresolved {
        work.charge()?;
        if state.get(start).copied().unwrap_or(0) != 0 {
            continue;
        }
        state.insert(start, 1);
        let mut path = vec![start];
        let mut stack = vec![(start, 0_usize)];
        while let Some((node, next)) = stack.last_mut() {
            work.charge()?;
            let dependencies = &nodes[*node];
            while *next < dependencies.len() && !unresolved.contains(&dependencies[*next]) {
                work.charge()?;
                *next += 1;
            }
            if *next == dependencies.len() {
                state.insert(node, 2);
                stack.pop();
                path.pop();
                continue;
            }
            let dependency = &dependencies[*next];
            *next += 1;
            match state.get(dependency).copied().unwrap_or(0) {
                0 => {
                    state.insert(dependency, 1);
                    path.push(dependency);
                    stack.push((dependency, 0));
                }
                1 => {
                    let begin = path
                        .iter()
                        .position(|item| *item == dependency)
                        .expect("gray dependency is on the iterative DFS path");
                    let mut cycle: Vec<_> = path[begin..].to_vec();
                    let minimum = cycle
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, id)| *id)
                        .expect("a cycle is nonempty")
                        .0;
                    cycle.rotate_left(minimum);
                    let mut result = Vec::new();
                    for id in cycle {
                        budget.node::<PlanPackageId>()?;
                        result.push(id.copy(budget)?);
                    }
                    return Ok(result);
                }
                _ => {}
            }
        }
    }
    unreachable!("unresolved Kahn nodes contain a cycle")
}

fn display_cycle(packages: &[PlanPackageId]) -> String {
    packages
        .iter()
        .map(PlanPackageId::as_str)
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn plan_path(path: &[String], budget: &mut ProjectionBudget) -> Result<Vec<String>, PlanError> {
    let mut projected = budget.collection::<String>(path.len())?;
    for component in path {
        projected.push(budget.string(component)?);
    }
    Ok(projected)
}

fn plan_identity(
    identity: &CanonicalItemIdentity,
    budget: &mut ProjectionBudget,
) -> Result<(u32, Vec<String>), PlanError> {
    Ok((
        identity.domain().as_u32(),
        plan_path(identity.path(), budget)?,
    ))
}

fn plan_type(ty: &CanonicalType, budget: &mut ProjectionBudget) -> Result<PlanType, PlanError> {
    budget.node::<PlanType>()?;
    Ok(match ty {
        CanonicalType::Unit => PlanType::Unit,
        CanonicalType::Int => PlanType::Int,
        CanonicalType::Str => PlanType::Str,
        CanonicalType::Nominal(item) => {
            let (domain, path) = plan_identity(item, budget)?;
            PlanType::Nominal {
                domain,
                path,
            }
        }
        CanonicalType::Specialization {
            template,
            arguments,
        } => {
            let (domain, path) = plan_identity(template, budget)?;
            let mut plan_arguments = budget.collection::<PlanType>(arguments.len())?;
            for argument in arguments {
                plan_arguments.push(plan_type(argument, budget)?);
            }
            PlanType::Specialization {
                domain,
                path,
                arguments: plan_arguments,
            }
        }
        CanonicalType::List(item) => PlanType::List(Box::new(plan_type(item, budget)?)),
        CanonicalType::Function {
            ..
        } => return Err(PlanError::FunctionValue),
    })
}

fn primitive(
    value: &PrimitiveValue,
    budget: &mut ProjectionBudget,
) -> Result<PlanValue, PlanError> {
    budget.node::<PlanValue>()?;
    Ok(match value {
        PrimitiveValue::Int(value) => PlanValue::Int(*value),
        PrimitiveValue::Str(value) => PlanValue::Str(budget.string(value)?),
    })
}

#[cfg(test)]
fn plan_value(value: &Value, budget: &mut ProjectionBudget) -> Result<PlanValue, PlanError> {
    plan_value_with_refs(value, budget, &BTreeMap::new())
}

fn plan_value_with_refs(
    value: &Value,
    budget: &mut ProjectionBudget,
    references: &BTreeMap<&MemoId, &CanonicalItemIdentity>,
) -> Result<PlanValue, PlanError> {
    budget.node::<PlanValue>()?;
    Ok(match value {
        Value::MemoizedFunction {
            id,
            ..
        } => {
            let identity = references
                .get(id)
                .ok_or(PlanError::FunctionValue)?;
            PlanValue::Reference {
                domain: identity.domain().as_u32(),
                path: plan_path(identity.path(), budget)?,
            }
        }
        Value::Function {
            ..
        }
        | Value::Closure {
            ..
        }
        | Value::VariantConstructor {
            ..
        } => {
            return Err(PlanError::FunctionValue);
        }
        Value::Unit => PlanValue::Unit,
        Value::Int(value) => PlanValue::Int(*value),
        Value::Str(value) => PlanValue::Str(budget.string(value)?),
        Value::Nominal {
            ty,
            value,
            resource,
        } => PlanValue::Nominal {
            ty: plan_type(ty, budget)?,
            value: Box::new(primitive(value, budget)?),
            resource: *resource,
        },
        Value::List {
            ty,
            items,
        } => {
            let mut plan_items = budget.collection::<PlanValue>(items.len())?;
            for item in items {
                plan_items.push(plan_value_with_refs(item, budget, references)?);
            }
            PlanValue::List {
                ty: plan_type(ty, budget)?,
                items: plan_items,
            }
        }
        Value::Struct {
            ty,
            fields,
            ..
        } => {
            let mut plan_fields = budget.collection::<(String, PlanValue)>(fields.len())?;
            for (name, value) in fields {
                plan_fields.push((
                    budget.string(name)?,
                    plan_value_with_refs(value, budget, references)?,
                ));
            }
            PlanValue::Struct {
                ty: plan_type(ty, budget)?,
                fields: plan_fields,
            }
        }
        Value::Variant {
            ty,
            index,
            payload,
        } => {
            let mut fields = budget.collection::<PlanValue>(payload.len())?;
            for field in payload {
                fields.push(plan_value_with_refs(field, budget, references)?);
            }
            PlanValue::Variant {
                ty: plan_type(ty, budget)?,
                index: *index,
                payload: fields,
            }
        }
    })
}

fn plan_claim(
    claim: &ResourceClaim,
    budget: &mut ProjectionBudget,
) -> Result<PlanClaim, PlanError> {
    budget.node::<PlanClaim>()?;
    let (scope_root_domain, scope_root_path) = plan_identity(&claim.key.scope.root, budget)?;
    Ok(PlanClaim {
        ty: plan_type(&claim.key.ty, budget)?,
        value: primitive(&claim.key.value, budget)?,
        scope_root_domain,
        scope_root_path,
        scope_name: claim
            .key
            .scope
            .name
            .as_deref()
            .map(|name| budget.string(name))
            .transpose()?,
        boundary: claim.key.scope.boundary,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn nominal(path: &[&str]) -> Arc<CanonicalType> {
        Arc::new(CanonicalType::Nominal(Arc::new(
            CanonicalItemIdentity::new(
                syrox_lang::source::SourceDomainId::standard_library(),
                path.iter().copied(),
            )
            .unwrap(),
        )))
    }

    #[test]
    fn malformed_exact_package_value_is_not_ignored() {
        let value = Value::Struct {
            owner: None,
            ty: nominal(PACKAGE_PATH),
            fields: vec![(
                "id".to_owned(),
                Value::Str("not nominal".to_owned()),
            )],
        };
        let mut edges = 0;
        let error = decode_package(
            "root",
            &CanonicalItemIdentity::new(
                syrox_lang::source::SourceDomainId::project(),
                ["root"],
            )
            .unwrap(),
            &value,
            &BTreeMap::new(),
            &mut edges,
            &mut Work(0),
            &mut ProjectionBudget::new(usize::MAX, usize::MAX),
        )
        .unwrap_err();
        assert_eq!(
            error,
            PlanError::MalformedPackage {
                root: "root".to_owned(),
                reason: "fields are not exactly `id`, `dependencies`",
            }
        );
    }

    #[test]
    fn package_id_grammar_has_exact_ascii_and_length_boundaries() {
        assert!(valid_package_id("0"));
        assert!(valid_package_id("a+._-09"));
        assert!(valid_package_id(
            &"a".repeat(MAX_PACKAGE_ID_BYTES)
        ));
        for invalid in ["", "A", "a/", "a:", "é"] {
            assert!(!valid_package_id(invalid), "{invalid}");
        }
        assert!(!valid_package_id(
            &"a".repeat(MAX_PACKAGE_ID_BYTES + 1)
        ));
    }

    #[test]
    fn package_work_limit_is_checked_before_more_work() {
        let mut at_limit = Work(MAX_PLAN_PACKAGE_WORK);
        assert_eq!(at_limit.charge(), Err(PlanError::WorkLimit));
        let mut below_limit = Work(MAX_PLAN_PACKAGE_WORK - 1);
        assert_eq!(below_limit.charge(), Ok(()));
    }

    #[test]
    fn projection_work_has_an_exact_boundary() {
        let mut exact = ProjectionBudget::new(1, usize::MAX);
        assert_eq!(exact.string("x").unwrap(), "x");
        assert_eq!(
            exact.string("y"),
            Err(PlanError::ProjectionWorkLimit {
                limit: 1
            })
        );
    }

    #[test]
    fn projection_retained_bytes_are_charged_before_string_clone() {
        let exact_limit = size_of::<String>() + 3;
        let mut exact = ProjectionBudget::new(1, exact_limit);
        assert_eq!(exact.string("abc").unwrap(), "abc");

        let mut over = ProjectionBudget::new(1, exact_limit - 1);
        assert_eq!(
            over.string("abc"),
            Err(PlanError::ProjectionRetainedBytesLimit {
                limit: exact_limit - 1
            })
        );
    }

    #[test]
    fn recursive_value_projection_charges_every_node_and_string() {
        let value = Value::List {
            ty: Arc::new(CanonicalType::Unit),
            items: vec![Value::Str("x".to_owned())],
        };
        let mut exact = ProjectionBudget::new(4, usize::MAX);
        assert!(plan_value(&value, &mut exact).is_ok());

        let mut over = ProjectionBudget::new(3, usize::MAX);
        assert_eq!(
            plan_value(&value, &mut over),
            Err(PlanError::ProjectionWorkLimit {
                limit: 3
            })
        );
    }

    #[test]
    fn canonical_display_has_an_exact_byte_boundary_without_rendering_a_copy() {
        let mut plan = Plan {
            lock_digest: [0; 32],
            policy_identity: "test".to_owned(),
            standard_library: None,
            packages: Vec::new(),
            acquisitions: Vec::new(),
            builds: Vec::new(),
            imports: Vec::new(),
            commands: Vec::new(),
            consumers: Vec::new(),
            package_edges: 0,
            roots: Vec::new(),
            canonical_display_bytes: 0,
        };
        let bytes = canonical_display_bytes(&plan, usize::MAX).unwrap();
        assert_eq!(canonical_display_bytes(&plan, bytes), Ok(bytes));
        assert_eq!(
            canonical_display_bytes(&plan, bytes - 1),
            Err(PlanError::DisplayBytesLimit {
                limit: bytes - 1
            })
        );

        plan.canonical_display_bytes = bytes;
        assert_eq!(plan.to_string().len(), bytes);
    }
}
