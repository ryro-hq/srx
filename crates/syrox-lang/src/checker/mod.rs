//! Checking types, policy rules and value consumption.
//!
//! [`check`] accepts a resolved program and returns a [`CheckedProgram`] on success.
//! Editor analysis also keeps partial facts, with uncertainty preserved for queries
//! on incomplete code. [`crate::evaluator`] requires successful checking and the
//! same policy.
//!
//! # Checking bodies within one budget
//!
//! Bodies are checked separately, but work, diagnostics and generic instances
//! count toward the same run. [`bodies`](../../src/syrox_lang/checker/bodies/mod.rs.html) owns each body's facts and observed cost;
//! its effect records compare decisions without installing facts or skipping
//! checking. Publishing those facts does not create a cache across revisions.

mod bodies;
mod declarations;
mod editor;
mod enums;
mod expressions;
mod functions;
mod index;
mod inference;
mod model;
mod ownership;
mod packages;
mod policy;
mod relocation;
mod types;

pub use bodies::{BodyBudget, BodyEffects, BodyReplayState};
pub(crate) use bodies::{BodyPublication, BodyPublications};
pub use editor::FieldInfo;
pub(crate) use editor::{NominalShape, RepresentationAuthority, substitute_type};
pub(crate) use model::EditorFacts;
pub use model::{
    CheckLimits, CheckedExpression, CheckedLocal, CheckedPattern, CheckedProgram, Elaboration,
    OwnershipUse, OwnershipUseKind, OwnershipUseStatus, ParameterHint, PolicyMismatch, Ty,
    TypeStatus, check, check_with_limits,
};
pub use policy::{
    CanonicalItemIdentity, CheckPolicy, ErasureRule, MAX_ALIAS_DEPTH, MAX_CHECK_WORK,
    MAX_GENERIC_INSTANCES, MAX_METADATA_UNITS, MAX_POLICY_BYTES, MAX_POLICY_ENTRIES,
    MAX_SPECIALIZATION_DEPTH, PolicyError, PolicyFingerprint, PredicateRule, PrimitiveType,
    ScopeRule,
};
pub(crate) use relocation::FactMapper;
pub use relocation::OwnerCheckedFacts;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{
    MAX_DIAGNOSTICS, diagnostic::Diagnostic, resolver::ItemId, resolver::LocalId,
    resolver::ModuleId, resolver::ReferenceKind, resolver::ResolvedItem,
    resolver::ResolvedItemKind, resolver::ResolvedProgram, resolver::ResolvedTarget,
    source::SourceDomainId, source::Span, syntax::Block, syntax::Enum, syntax::Expression,
    syntax::ExpressionKind, syntax::Function, syntax::Item, syntax::ItemKind, syntax::Literal,
    syntax::MatchArm, syntax::OutputKind, syntax::ParsedSource, syntax::Path, syntax::Pattern,
    syntax::Primitive, syntax::PrimitiveDeclaration, syntax::RefinementKind, syntax::StatementKind,
    syntax::StringLiteral, syntax::StringPart, syntax::Struct, syntax::StructField, syntax::Type,
    syntax::TypeAlias, syntax::TypeKind,
};
use bodies::BodyState;

#[derive(Clone, Copy)]
struct Context {
    domain: SourceDomainId,
    module: ModuleId,
}

#[derive(Clone)]
struct StructInfo<'a> {
    declaration: &'a Struct,
    context: Context,
    parameters: Vec<LocalId>,
}

#[derive(Clone)]
struct AliasInfo<'a> {
    declaration: &'a TypeAlias,
    parameters: Vec<LocalId>,
}

#[derive(Clone, Copy)]
struct FunctionInfo<'a> {
    declaration: &'a Function,
    context: Context,
}

#[derive(Clone, Copy)]
struct PrimitiveInfo<'a> {
    declaration: &'a PrimitiveDeclaration,
}

#[derive(Clone, Debug)]
enum RawTy {
    Concrete(Ty),
    Parameter(LocalId),
    Specialization {
        template: ItemId,
        arguments: Vec<RawTy>,
    },
    List(Box<RawTy>),
    Function {
        parameters: Vec<RawTy>,
        result: Box<RawTy>,
        once: bool,
    },
}

#[derive(Clone)]
struct Binding {
    constant: Option<std::sync::Arc<str>>,
    ty: Ty,
    affine: bool,
    moved: Option<Span>,
    declaration: Span,
    conditional: bool,
    status: TypeStatus,
    ownership_unknown: bool,
}

struct Checker<'a> {
    program: &'a ResolvedProgram,
    policy: &'a CheckPolicy,
    limits: CheckLimits,
    work: usize,
    exhausted: bool,
    diagnostics: Vec<Diagnostic>,
    expressions: Vec<CheckedExpression>,
    patterns: Vec<CheckedPattern>,
    collection_metadata_units: usize,
    references: BTreeMap<(u32, u32, u32), ResolvedTarget>,
    local_at: BTreeMap<(u32, u32, u32), LocalId>,
    item_at: BTreeMap<(u32, u32, u32), ItemId>,
    module_by_path: BTreeMap<SourceDomainId, BTreeMap<&'a [String], ModuleId>>,
    item_context: BTreeMap<ItemId, Context>,
    aliases: BTreeMap<ItemId, AliasInfo<'a>>,
    structs: BTreeMap<ItemId, StructInfo<'a>>,
    enums: BTreeMap<ItemId, &'a Enum>,
    primitives: BTreeMap<ItemId, PrimitiveInfo<'a>>,
    functions: BTreeMap<ItemId, FunctionInfo<'a>>,
    output_values: BTreeMap<ItemId, &'a Type>,
    published_types: BTreeMap<ItemId, Ty>,
    carriers: BTreeSet<ItemId>,
    generic_instances: BTreeSet<Ty>,
    struct_fields: BTreeMap<ItemId, Vec<(String, RawTy, bool)>>,
    function_types: BTreeMap<ItemId, (Vec<Ty>, Ty)>,
    body: BodyState,
    prior_diagnostics: usize,
    prior_metadata: usize,
    #[cfg(test)]
    unpartitioned_bodies: bool,
    incomplete_bodies: BTreeSet<(u32, u32, u32)>,
    cancellation: Option<&'a crate::analysis::AnalysisCancellation>,
    editor: EditorFacts,
    publications: BodyPublications,
    effect_retention: bodies::EffectRetention,
    reference_inventory: Option<std::sync::Arc<[Span]>>,
}

impl<'a> Checker<'a> {
    pub(super) fn new(
        program: &'a ResolvedProgram,
        policy: &'a CheckPolicy,
        limits: CheckLimits,
    ) -> Self {
        Self {
            program,
            policy,
            limits,
            work: 0,
            exhausted: false,
            diagnostics: Vec::new(),
            expressions: Vec::new(),
            patterns: Vec::new(),
            collection_metadata_units: 0,
            references: BTreeMap::new(),
            local_at: BTreeMap::new(),
            item_at: BTreeMap::new(),
            module_by_path: BTreeMap::new(),
            item_context: BTreeMap::new(),
            aliases: BTreeMap::new(),
            structs: BTreeMap::new(),
            enums: BTreeMap::new(),
            primitives: BTreeMap::new(),
            functions: BTreeMap::new(),
            output_values: BTreeMap::new(),
            published_types: BTreeMap::new(),
            carriers: BTreeSet::new(),
            generic_instances: BTreeSet::new(),
            struct_fields: BTreeMap::new(),
            function_types: BTreeMap::new(),
            body: BodyState::default(),
            prior_diagnostics: 0,
            prior_metadata: 0,
            #[cfg(test)]
            unpartitioned_bodies: false,
            incomplete_bodies: BTreeSet::new(),
            cancellation: None,
            editor: EditorFacts::default(),
            publications: BodyPublications::default(),
            effect_retention: bodies::EffectRetention::default(),
            reference_inventory: None,
        }
    }

    pub(super) fn run(&mut self) {
        self.index_resolution_metadata();
        if self.exhausted {
            return;
        }
        self.index();
        if self.exhausted {
            return;
        }
        self.validate_declarations();
        if self.exhausted {
            return;
        }
        self.propagate_carriers();
        if self.exhausted {
            return;
        }
        self.collect_function_types();
        self.collect_editor_types();
        if self.exhausted {
            return;
        }
        self.check_defaults();
        if self.exhausted {
            return;
        }
        self.check_functions();
        if self.exhausted {
            return;
        }
        self.check_outputs();
    }
}

pub(crate) struct PartialCheck {
    pub bodies: BodyPublications,
    pub expressions: Vec<CheckedExpression>,
    pub functions: BTreeMap<ItemId, Ty>,
    pub diagnostics: Vec<Diagnostic>,
    pub editor: EditorFacts,
}

pub(crate) fn check_partial(
    resolved: &ResolvedProgram,
    policy: &CheckPolicy,
    incomplete_bodies: BTreeSet<(u32, u32, u32)>,
    cancellation: &crate::analysis::AnalysisCancellation,
    limits: CheckLimits,
) -> PartialCheck {
    let mut checker = Checker::new(resolved, policy, limits);
    checker.incomplete_bodies = incomplete_bodies;
    checker.cancellation = Some(cancellation);
    checker.run();
    checker.editor.patterns = std::mem::take(&mut checker.patterns);
    PartialCheck {
        bodies: checker.publications,
        expressions: checker.expressions,
        functions: checker
            .function_types
            .into_iter()
            .map(|(id, (parameters, result))| {
                (
                    id,
                    Ty::Function {
                        parameters,
                        result: Box::new(result),
                        once: false,
                    },
                )
            })
            .collect(),
        diagnostics: checker.diagnostics,
        editor: checker.editor,
    }
}

pub(super) fn span_key(span: Span) -> (u32, u32, u32) {
    (
        u32::try_from(span.source_id().index()).expect("source IDs are u32"),
        span.start(),
        span.end(),
    )
}

#[cfg(test)]
mod tests;
