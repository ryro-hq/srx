use std::{collections::BTreeMap, mem::size_of, path::Path, sync::Arc};

use syrox_lang::{
    checker::CheckedProgram, checker::Ty, evaluator::CanonicalType,
    evaluator::EvaluationQueryError, evaluator::EvaluationSession, evaluator::MemoId,
    evaluator::RealizedRoot, evaluator::Value, source::SourceDomainId,
};

use super::{
    CheckConfiguration, CheckFailure, LoadedProject, ProjectOperationError, analyze, compare_lock,
    loader, map_generated_lock_error, project_plan, read_graph_lock, read_lock,
    validate_lock_policy, validate_project_limits,
};

/// A checked project whose root and transitive snapshots have been verified
/// against their Locks. Its source domains are local to this loaded graph;
/// they are not persistent recipe or Action identities.
#[derive(Debug)]
pub struct LockedProject {
    pub(super) loaded: LoadedProject,
    pub(super) checked: CheckedProgram,
    pub(super) configuration: CheckConfiguration,
    pub(super) digest: [u8; 32],
}

impl LockedProject {
    pub const fn loaded(&self) -> &LoadedProject {
        &self.loaded
    }
    pub const fn lock_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(super) fn check_report(&self) -> super::CheckReport {
        super::CheckReport {
            path: self.loaded.path().to_path_buf(),
            declarations: self
                .checked
                .resolved()
                .parsed()
                .declaration_count(),
            realized_roots: 0,
        }
    }

    pub fn evaluation(&self) -> Result<ProjectEvaluation<'_>, ProjectOperationError> {
        let session = EvaluationSession::new(
            &self.checked,
            &self.configuration.policy,
            &self.configuration.environment,
            self.configuration.evaluation_limits,
        )
        .map_err(|source| CheckFailure::EvaluationSetup {
            source,
        })?;
        Ok(ProjectEvaluation {
            project: self,
            session,
            catalog: None,
            discover_reference_aliases: true,
        })
    }
}

#[derive(Debug)]
pub struct ProjectEvaluation<'a> {
    project: &'a LockedProject,
    session: EvaluationSession<'a>,
    catalog: Option<CatalogState>,
    // Consumer selection follows typed references without enumerating unrelated
    // library publications merely to attach diagnostic aliases.
    discover_reference_aliases: bool,
}

type CatalogIndex = BTreeMap<String, CatalogEntry>;

#[cfg(test)]
mod budget_tests {

    #[test]
    fn catalog_metadata_exhaustion_poisoning_prevents_retries_and_partial_plans() {
        let project = tempfile::tempdir().unwrap();
        for source in [
            r#"mod catalog { mod one { pub fn recipe() -> std::Recipe { std::Recipe { package = std::Package { id = "one"; dependencies = []; }; } } } }
                pub publish(catalog, recipe): std::Recipe;"#,
            r#"pub let one = recipe_ref(make);
                fn make() -> Recipe { Recipe { package = Package { id = "one"; dependencies = []; }; } }"#,
        ] {
            std::fs::write(project.path().join("main.srx"), source).unwrap();
            let config = crate::project::CheckConfiguration {
                standard_library: Some(crate::project::AuthenticatedStandardLibrary::bundled()),
                ..crate::project::CheckConfiguration::default()
            };
            crate::project::lock_project_with(project.path(), &config).unwrap();
            let locked = crate::project::open_locked_project_with(project.path(), &config).unwrap();
            for work in [false, true] {
                let mut evaluation = locked.evaluation().unwrap();
                assert!(evaluation.select_package("one").unwrap());
                if work {
                    evaluation
                        .session
                        .reserve_metadata_work(evaluation.session.remaining_metadata_work())
                        .unwrap();
                } else {
                    evaluation
                        .session
                        .reserve_metadata_bytes(evaluation.session.remaining_metadata_bytes())
                        .unwrap();
                }
                assert!(evaluation.catalog_names().is_err());
                assert!(evaluation.select_package("one").is_err());
                assert!(evaluation.into_selected_plan().is_err());
            }
        }
    }
}

#[derive(Clone, Debug)]
struct RecipeHandle {
    id: MemoId,
    result: Arc<CanonicalType>,
}

#[derive(Clone, Debug)]
struct CatalogEntry {
    reference: RecipeHandle,
    binding: bool,
}

#[derive(Debug)]
enum CatalogState {
    Absent,
    Present {
        entries: CatalogIndex,
        references: BTreeMap<MemoId, String>,
    },
}

impl ProjectEvaluation<'_> {
    pub fn root_names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.session.root_names()
    }
    pub fn root_type(&self, name: &str) -> Option<&Ty> {
        self.session.root_type(name)
    }

    pub fn evaluate_root(&mut self, name: &str) -> Result<&RealizedRoot, ProjectOperationError> {
        self.session
            .evaluate_root(name)
            .map_err(|error| match error {
                EvaluationQueryError::UnknownRoot => ProjectOperationError::MissingOutput {
                    name: name.to_owned(),
                },
                EvaluationQueryError::InvalidSelection => {
                    invalid_catalog("invalid selected reference")
                }
                EvaluationQueryError::Evaluation(errors) => CheckFailure::Evaluation {
                    input: self.project.loaded.sources().clone(),
                    errors,
                    failed_roots: vec![name.to_owned()],
                }
                .into(),
                EvaluationQueryError::Setup(source) => CheckFailure::EvaluationSetup {
                    source,
                }
                .into(),
            })
    }

    pub fn evaluate_all(&mut self) -> Result<(), ProjectOperationError> {
        self.session.evaluate_all().map_err(|source| {
            CheckFailure::EvaluationSetup {
                source,
            }
            .into()
        })
    }

    /// Include one authenticated Os/Shell output, without forcing unrelated
    /// outputs. Finish with `into_selected_prepared_plan` to retain only the
    /// explicit selections and their referenced recipes.
    pub fn select_consumer(&mut self, name: &str) -> Result<(), ProjectOperationError> {
        self.require_consumer(name)?;
        self.discover_reference_aliases = false;
        self.session
            .include_root(name)
            .map_err(|error| match error {
                EvaluationQueryError::UnknownRoot => ProjectOperationError::MissingOutput {
                    name: name.to_owned(),
                },
                EvaluationQueryError::InvalidSelection => {
                    ProjectOperationError::InvalidConsumerOutput {
                        name: name.to_owned(),
                    }
                }
                EvaluationQueryError::Evaluation(errors) => CheckFailure::Evaluation {
                    input: self.project.loaded.sources().clone(),
                    errors,
                    failed_roots: vec![name.to_owned()],
                }
                .into(),
                EvaluationQueryError::Setup(source) => CheckFailure::EvaluationSetup {
                    source,
                }
                .into(),
            })
    }

    fn require_consumer(&self, name: &str) -> Result<(), ProjectOperationError> {
        let ty = self
            .root_type(name)
            .ok_or_else(|| ProjectOperationError::MissingOutput {
                name: name.to_owned(),
            })?;
        if !["Os", "Shell"].iter().any(|contract| {
            is_std_nominal(
                ty,
                &self.project.checked,
                &["std", "deployment", contract],
            )
        }) {
            return Err(ProjectOperationError::InvalidConsumerOutput {
                name: name.to_owned(),
            });
        }
        Ok(())
    }

    /// Enumerate public recipe references visible in the root domain. Factories
    /// remain unevaluated, and imported libraries are not implicit catalogs.
    pub fn catalog_names(&mut self) -> Result<Option<Vec<String>>, ProjectOperationError> {
        self.catalog()?;
        let (work, bytes) = self.catalog_entries().map_or((0, 0), |entries| {
            entries
                .keys()
                .fold((0usize, 0usize), |(work, bytes), key| {
                    (
                        work.saturating_add(key.len() + 1),
                        bytes.saturating_add(key.len() + size_of::<String>()),
                    )
                })
        });
        self.session
            .reserve_metadata_work(work)
            .map_err(|source| CheckFailure::EvaluationSetup {
                source,
            })?;
        self.session
            .reserve_metadata_bytes(bytes)
            .map_err(|source| CheckFailure::EvaluationSetup {
                source,
            })?;
        Ok(self
            .catalog_entries()
            .map(|entries| entries.keys().cloned().collect()))
    }

    /// Return a lazy reference to one published recipe. This does not force its
    /// factory or enumerate imports that are not reexported by the root library.
    pub fn catalog_reference(&mut self, key: &str) -> Result<Option<Value>, ProjectOperationError> {
        self.catalog()?;
        if !self
            .catalog_entries()
            .is_some_and(|entries| entries.contains_key(key))
        {
            return Ok(None);
        }
        self.select_catalog_reference(key)
            .map(Some)
            .map_err(|error| selection_error(error, self.project, key))
    }

    /// Force one published recipe and prepare only its reachable graph.
    /// Returns false when this project has no published recipe members.
    pub fn select_package(&mut self, key: &str) -> Result<bool, ProjectOperationError> {
        self.catalog()?;
        let Some(entries) = self.catalog_entries() else {
            return Ok(false);
        };
        let selected =
            entries.get(key).ok_or_else(
                || ProjectOperationError::MissingPackageReference {
                    key: key.to_owned(),
                },
            )?;
        let canonical = self
            .catalog_references()
            .and_then(|entries| entries.get(&selected.reference.id))
            .expect("indexed published reference")
            .clone();
        self.force_catalog_reference(&canonical)?;
        if key != canonical {
            self.force_catalog_reference(key)?;
        }
        Ok(true)
    }

    /// Select every entry of the typed catalog in one evaluation operation.
    /// Discovery stays lazy; this explicitly requested Plan forces each recipe.
    pub fn select_all_packages(&mut self) -> Result<bool, ProjectOperationError> {
        let Some(names) = self.catalog_names()? else {
            return Ok(false);
        };
        for name in names {
            self.select_package(&name)?;
        }
        Ok(true)
    }

    /// A full Plan includes only authenticated Os/Shell destinations alongside
    /// explicitly selected library recipes. Libraries are not output values.
    pub fn include_project_outputs(&mut self) -> Result<(), ProjectOperationError> {
        let names: Vec<_> = self.root_names().map(str::to_owned).collect();
        for name in &names {
            self.require_consumer(name)?;
        }
        for name in names {
            self.select_consumer(&name)?;
        }
        Ok(())
    }

    pub fn into_selected_plan(self) -> Result<crate::plan::Plan, ProjectOperationError> {
        self.into_selected_prepared_plan()
            .map(super::PreparedPlan::into_plan)
    }

    /// Finish selection and bind its pure Plan to this evaluation's live sources.
    pub fn into_selected_prepared_plan(self) -> Result<super::PreparedPlan, ProjectOperationError> {
        let mut evaluation = self;
        let mut cursor = 0;
        let mut edges = 0_usize;
        let mut work = 0_usize;
        loop {
            let required = {
                let Some(root) = evaluation.session.planning_root(cursor) else {
                    break;
                };
                let value = root
                    .value()
                    .ok_or_else(|| CheckFailure::Evaluation {
                        input: evaluation.project.loaded.sources().clone(),
                        errors: root.diagnostics().to_vec(),
                        failed_roots: vec![root.name().to_owned()],
                    })?;
                required_packages(value, &mut work)?
            };
            edges = edges.saturating_add(required.len());
            if edges > crate::plan::MAX_PLAN_PACKAGE_EDGES {
                return Err(invalid_catalog(
                    "selected dependencies exceed limit",
                ));
            }
            for reference in required {
                evaluation.select_reference(reference)?;
                if evaluation.session.selected_roots().len() > crate::plan::MAX_PLAN_PACKAGE_NODES {
                    return Err(invalid_catalog(
                        "selected package count exceeds limit",
                    ));
                }
            }
            cursor += 1;
        }
        let realized = evaluation
            .session
            .into_selected()
            .map_err(|source| CheckFailure::EvaluationSetup {
                source,
            })?;
        project_plan(
            &evaluation.project.loaded,
            &realized,
            evaluation.project.digest,
            &evaluation.project.configuration,
        )
    }

    fn select_reference(&mut self, reference: RecipeHandle) -> Result<(), ProjectOperationError> {
        if self
            .session
            .selected_reference(&reference.id)
            .is_some()
        {
            return Ok(());
        }
        if self.discover_reference_aliases {
            self.catalog()?;
        }
        if let Some(key) = self
            .catalog_references()
            .and_then(|entries| entries.get(&reference.id))
            .cloned()
        {
            self.select_package(&key)?;
        } else {
            self.session
                .force_dependency(&reference.id, reference.result)
                .map_err(|error| match error {
                    EvaluationQueryError::Setup(source) => CheckFailure::EvaluationSetup {
                        source,
                    }
                    .into(),
                    _ => invalid_catalog("invalid dependency reference"),
                })?;
        }
        Ok(())
    }

    /// Index root-visible publications once per operation. Creating references
    /// does not invoke their factories; shared metadata budgets cover the index.
    fn catalog(&mut self) -> Result<(), ProjectOperationError> {
        self.session
            .reserve_metadata_work(1)
            .map_err(|source| CheckFailure::EvaluationSetup {
                source,
            })?;
        if self.catalog.is_some() {
            return Ok(());
        }
        let (count, work, bytes) = self.recipe_names().fold(
            (0usize, 0usize, 0usize),
            |(count, work, bytes), (name, _)| {
                (
                    count.saturating_add(1),
                    work.saturating_add(name.len() + 1),
                    bytes.saturating_add(name.len() + size_of::<String>() + size_of::<bool>()),
                )
            },
        );
        self.session
            .reserve_metadata_work(work)
            .map_err(|source| CheckFailure::EvaluationSetup {
                source,
            })?;
        self.session
            .reserve_metadata_bytes(bytes)
            .map_err(|source| CheckFailure::EvaluationSetup {
                source,
            })?;
        if count > crate::plan::MAX_PLAN_PACKAGE_NODES {
            return Err(invalid_catalog(
                "published recipe count exceeds limit",
            ));
        }
        if count == 0 {
            self.catalog = Some(CatalogState::Absent);
            return Ok(());
        }
        let names: Vec<_> = self
            .recipe_names()
            .map(|(name, binding)| (name.to_owned(), binding))
            .collect();
        let mut index = CatalogIndex::new();
        let mut references: BTreeMap<MemoId, String> = BTreeMap::new();
        for (key, binding) in names {
            let levels = index.len().checked_ilog2().unwrap_or(0) as usize + 1;
            self.session
                .reserve_metadata_work((key.len() + 1).saturating_mul(levels + 1))
                .map_err(|source| CheckFailure::EvaluationSetup {
                    source,
                })?;
            let value = if binding {
                self.session.select_reference_binding(&key)
            } else {
                self.session.select_published(&key)
            }
            .map_err(|error| selection_error(error, self.project, &key))?;
            let reference = recipe_handle(&value)?;
            let bytes = key
                .len()
                .saturating_add(size_of::<(String, CatalogEntry)>())
                .saturating_add(6 * size_of::<usize>());
            self.session
                .reserve_metadata_bytes(bytes.saturating_mul(2))
                .map_err(|source| CheckFailure::EvaluationSetup {
                    source,
                })?;
            if let Some(previous) = index.get(&key) {
                if previous.reference.id != reference.id {
                    return Err(invalid_catalog(
                        "conflicting published recipe names",
                    ));
                }
                continue;
            }
            references
                .entry(reference.id.clone())
                .and_modify(|canonical| {
                    // Existing publications retain their canonical identity
                    // when a public global becomes an additional alias.
                    let previous = index[canonical.as_str()].binding;
                    if (binding, key.as_str()) < (previous, canonical.as_str()) {
                        key.clone_into(canonical);
                    }
                })
                .or_insert_with(|| key.clone());
            index.insert(
                key,
                CatalogEntry {
                    reference,
                    binding,
                },
            );
        }
        self.catalog = Some(CatalogState::Present {
            entries: index,
            references,
        });
        Ok(())
    }

    fn recipe_names(&self) -> impl Iterator<Item = (&str, bool)> {
        self.session
            .published_members()
            .filter(|member| is_recipe_type(member.result_type()))
            .map(|member| (member.name(), false))
            .chain(
                self.session
                    .reference_bindings()
                    .filter(|binding| is_recipe_type(binding.result_type()))
                    .map(|binding| (binding.name(), true)),
            )
    }

    fn select_catalog_reference(&mut self, key: &str) -> Result<Value, EvaluationQueryError> {
        if self
            .catalog_entries()
            .and_then(|entries| entries.get(key))
            .is_some_and(|entry| entry.binding)
        {
            self.session.select_reference_binding(key)
        } else {
            self.session.select_published(key)
        }
    }

    fn force_catalog_reference(&mut self, key: &str) -> Result<(), ProjectOperationError> {
        if self
            .catalog_entries()
            .and_then(|entries| entries.get(key))
            .is_some_and(|entry| entry.binding)
        {
            self.session.force_reference_binding(key)
        } else {
            self.session.force_published(key)
        }
        .map(|_| ())
        .map_err(|error| selection_error(error, self.project, key))
    }

    fn catalog_entries(&self) -> Option<&CatalogIndex> {
        match self.catalog.as_ref()? {
            CatalogState::Absent => None,
            CatalogState::Present {
                entries,
                ..
            } => Some(entries),
        }
    }

    fn catalog_references(&self) -> Option<&BTreeMap<MemoId, String>> {
        match self.catalog.as_ref()? {
            CatalogState::Absent => None,
            CatalogState::Present {
                references,
                ..
            } => Some(references),
        }
    }

    pub fn into_plan(self) -> Result<crate::plan::Plan, ProjectOperationError> {
        self.into_prepared_plan()
            .map(super::PreparedPlan::into_plan)
    }

    pub fn into_prepared_plan(mut self) -> Result<super::PreparedPlan, ProjectOperationError> {
        let names: Vec<_> = self
            .session
            .evaluated_roots()
            .map(|root| root.name().to_owned())
            .collect();
        for name in names {
            self.select_consumer(&name)?;
        }
        self.into_selected_prepared_plan()
    }
}

fn is_recipe_type(ty: &CanonicalType) -> bool {
    matches!(ty, CanonicalType::Nominal(identity)
        if identity.domain() == SourceDomainId::standard_library()
            && identity.path() == ["std", "pkg", "Recipe"])
}

fn selection_error(
    error: EvaluationQueryError,
    project: &LockedProject,
    name: &str,
) -> ProjectOperationError {
    match error {
        EvaluationQueryError::Evaluation(errors) => CheckFailure::Evaluation {
            input: project.loaded.sources().clone(),
            errors,
            failed_roots: vec![name.to_owned()],
        }
        .into(),
        EvaluationQueryError::Setup(source) => CheckFailure::EvaluationSetup {
            source,
        }
        .into(),
        _ => invalid_catalog("invalid published recipe selection"),
    }
}

fn is_std_nominal(ty: &Ty, program: &CheckedProgram, path: &[&str]) -> bool {
    matches!(ty, Ty::Nominal(id) if program.resolved().item(*id).is_some_and(|item| {
        item.domain() == SourceDomainId::standard_library()
            && item.path().segments().iter().map(String::as_str).eq(path.iter().copied())
    }))
}

fn std_specialization(ty: &CanonicalType, path: &[&str], arity: usize) -> bool {
    matches!(ty, CanonicalType::Specialization { template, arguments }
        if template.domain() == SourceDomainId::standard_library()
            && template.path().iter().map(String::as_str).eq(path.iter().copied())
            && arguments.len() == arity)
}

fn invalid_catalog(reason: &'static str) -> ProjectOperationError {
    ProjectOperationError::InvalidCatalog {
        reason,
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Struct {
        fields,
        ..
    } = value
    else {
        return None;
    };
    fields
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value)
}

fn recipe_handle(value: &Value) -> Result<RecipeHandle, ProjectOperationError> {
    let Some(Value::MemoizedFunction {
        id,
        ty,
    }) = field(value, "factory")
    else {
        return Err(invalid_catalog(
            "invalid recipe reference factory",
        ));
    };
    let CanonicalType::Function {
        parameters,
        result,
        once: false,
    } = ty.as_ref()
    else {
        return Err(invalid_catalog("invalid recipe factory type"));
    };
    if !parameters.is_empty() {
        return Err(invalid_catalog(
            "invalid recipe factory parameters",
        ));
    }
    Ok(RecipeHandle {
        id: id.clone(),
        result: result.clone(),
    })
}

fn required_packages(
    value: &Value,
    work: &mut usize,
) -> Result<Vec<RecipeHandle>, ProjectOperationError> {
    let mut required = Vec::new();
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        *work += 1;
        if *work > crate::plan::MAX_PLAN_PACKAGE_WORK {
            return Err(invalid_catalog(
                "reference traversal exceeds limit",
            ));
        }
        match value {
            Value::Struct {
                ty,
                ..
            } if std_specialization(ty, &["std", "recipe", "RecipeRef"], 1) => {
                if required.len() >= crate::plan::MAX_PLAN_PACKAGE_EDGES {
                    return Err(invalid_catalog(
                        "selected dependencies exceed limit",
                    ));
                }
                required.push(recipe_handle(value)?);
            }
            Value::Struct {
                fields,
                ..
            } => {
                pending.extend(fields.iter().rev().map(|(_, value)| value));
            }
            Value::List {
                items,
                ..
            }
            | Value::Variant {
                payload: items,
                ..
            } => {
                pending.extend(items.iter().rev());
            }
            _ => {}
        }
    }
    Ok(required)
}

/// Load once, authenticate the complete graph, and check every source. No
/// output expression or recipe factory is evaluated until a query is made.
pub fn open_locked_project_with(
    path: &Path,
    configuration: &CheckConfiguration,
) -> Result<LockedProject, ProjectOperationError> {
    validate_project_limits(configuration.project_limits)?;
    validate_lock_policy(configuration)?;
    let loaded = loader::load_project_linux(path, configuration)?;
    let expected = crate::project::lock::LockManifest::generate(
        &loaded,
        configuration.standard_library.as_ref(),
    )
    .map_err(map_generated_lock_error)?;
    let actual = read_lock(&loaded)?.ok_or(ProjectOperationError::MissingLock {
        name: crate::project::lock::LOCK_FILE_NAME,
    })?;
    compare_lock(&actual, &expected)?;
    if read_graph_lock(&loaded)?.is_some() {
        return Err(ProjectOperationError::GraphDrift);
    }
    let checked = analyze::check_loaded(&loaded, configuration)?;
    let mut configuration = configuration.clone();
    configuration.environment = analyze::asset_environment(&loaded, &configuration.environment);
    Ok(LockedProject {
        loaded,
        checked,
        configuration,
        digest: *actual.digest(),
    })
}
