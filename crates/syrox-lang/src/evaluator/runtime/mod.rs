use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    mem::size_of,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

use super::{
    CanonicalType, EvaluationEnvironment, EvaluationLimits, GoverningScope, PrimitiveValue,
    ResourceClaim, ResourceClaimKey, Value, environment::PredicateCallback, index::ProgramIndex,
    span_key,
};
use crate::{
    checker::CanonicalItemIdentity, checker::CheckPolicy, checker::CheckedProgram,
    checker::Elaboration, checker::ScopeRule, checker::Ty, diagnostic::Diagnostic,
    evaluator::EvaluationSetupError, resolver::ItemId, resolver::LocalId, resolver::ResolvedTarget,
    source::Span, syntax::Block, syntax::Expression, syntax::ExpressionKind, syntax::Literal,
    syntax::MatchArm, syntax::Pattern, syntax::PrimitiveDeclaration, syntax::RefinementKind,
    syntax::StatementKind, syntax::StringLiteral, syntax::StringPart,
};

mod calls;
mod construction;
mod expressions;
mod memo;
mod outputs;
mod values;
pub(super) use memo::MemoArena;
pub use memo::MemoId;

#[derive(Clone)]
struct OpenScope {
    name: Option<Arc<str>>,
    boundary: u64,
}

pub(super) struct Halt;
pub(super) type Eval<T> = Result<T, Halt>;

pub(super) struct CachedOutput {
    value: Value,
    shareable: bool,
}

// Calls use several evaluator frames per expression. Fold releases each call
// before the next item, independently of this native-stack protection.
const MAX_CALL_DEPTH: usize = 32;

pub(super) struct Evaluator<'a> {
    pub(super) checked: &'a CheckedProgram,
    policy: &'a CheckPolicy,
    environment: &'a EvaluationEnvironment,
    pub(super) index: &'a ProgramIndex<'a>,
    pub(super) limits: EvaluationLimits,
    root: Arc<CanonicalItemIdentity>,
    project_context: crate::source::SourceDomainId,
    pub(super) diagnostics: Vec<Diagnostic>,
    locals: BTreeMap<LocalId, Value>,
    active_outputs: BTreeSet<ItemId>,
    memo_outputs: BTreeMap<ItemId, CachedOutput>,
    pub(super) memos: MemoArena,
    scopes: Vec<OpenScope>,
    pub(super) claims: BTreeMap<ResourceClaimKey, Span>,
    // Includes reads of root-scoped cached outputs, whose claims were already
    // recorded. A reusable payload alone does not imply a pure computation.
    claim_effects: usize,
    pub(super) canonical_types: BTreeMap<Ty, Arc<CanonicalType>>,
    next_boundary: u64,
    pub(super) steps: usize,
    depth: usize,
    call_depth: usize,
    pub(super) expansion: usize,
    pub(super) operation_error: Option<EvaluationSetupError>,
}

impl<'a> Evaluator<'a> {
    pub(super) fn enter_call(&mut self, span: Span) -> Eval<()> {
        if self.call_depth >= MAX_CALL_DEPTH.min(self.limits.max_depth) {
            return self.fail(span, "function call depth limit reached");
        }
        self.call_depth += 1;
        Ok(())
    }

    pub(super) fn enter_project_context(&mut self, span: Span) -> crate::source::SourceDomainId {
        let previous = self.project_context;
        // A std helper acts on behalf of its caller; a project function or
        // imported output changes the current asset authority to its owner.
        if let Some(owner) = self
            .checked
            .resolved()
            .parsed()
            .owner(span.source_id())
        {
            self.project_context = owner;
        }
        previous
    }

    pub(super) fn inherit_outputs(&mut self, outputs: BTreeMap<ItemId, CachedOutput>) {
        self.memo_outputs = outputs;
    }

    pub(super) fn take_shareable_outputs(&mut self) -> BTreeMap<ItemId, CachedOutput> {
        // A later sibling failure or claim cannot change an already completed
        // claim-free value. Retaining it also preserves lazy instance identity.
        self.memo_outputs
            .retain(|_, output| output.shareable);
        std::mem::take(&mut self.memo_outputs)
    }

    pub(super) fn new(
        checked: &'a CheckedProgram,
        policy: &'a CheckPolicy,
        environment: &'a EvaluationEnvironment,
        index: &'a ProgramIndex<'a>,
        limits: EvaluationLimits,
        span: Span,
        root: Arc<CanonicalItemIdentity>,
    ) -> Self {
        let scope_count = policy.scopes().len().saturating_add(1);
        let scope_bytes = scope_count.saturating_mul(size_of::<OpenScope>());
        let scopes_fit = scope_bytes <= limits.max_expansion_bytes;
        let mut evaluator = Self {
            checked,
            policy,
            environment,
            index,
            limits,
            root,
            project_context: crate::source::SourceDomainId::project(),
            diagnostics: Vec::new(),
            locals: BTreeMap::new(),
            active_outputs: BTreeSet::new(),
            memo_outputs: BTreeMap::new(),
            memos: MemoArena::default(),
            scopes: if scopes_fit {
                Vec::with_capacity(scope_count)
            } else {
                Vec::new()
            },
            claims: BTreeMap::new(),
            claim_effects: 0,
            canonical_types: BTreeMap::new(),
            next_boundary: 0,
            steps: 0,
            depth: 0,
            call_depth: 0,
            expansion: scope_bytes,
            operation_error: None,
        };
        if !scopes_fit {
            evaluator.error(span, "evaluation expansion byte limit reached");
            return evaluator;
        }
        if scope_bytes > limits.max_retained_expansion_bytes {
            evaluator.operation_error =
                Some(EvaluationSetupError::EvaluationRetainedExpansionLimit);
            return evaluator;
        }
        evaluator.push_scope(None, span);
        for (name, _) in policy.scopes() {
            let scope = index.scope_name(name).map_or_else(
                || {
                    evaluator.error(span, "policy scope identity is unavailable");
                    None
                },
                Some,
            );
            evaluator.push_scope(scope, span);
        }
        evaluator
    }

    pub(super) fn push_scope(&mut self, name: Option<Arc<str>>, span: Span) {
        let boundary = self.next_boundary;
        if let Some(next) = self.next_boundary.checked_add(1) {
            self.next_boundary = next;
            self.scopes.push(OpenScope {
                name,
                boundary,
            });
        } else {
            self.error(span, "scope boundary identity overflow");
        }
    }

    pub(super) fn tick(&mut self, span: Span) -> Eval<()> {
        self.charge_steps(1, span)
    }

    pub(super) fn charge_steps(&mut self, amount: usize, span: Span) -> Eval<()> {
        self.steps = self.steps.saturating_add(amount);
        if self.steps > self.limits.max_total_steps {
            self.operation_error = Some(EvaluationSetupError::EvaluationWorkLimit);
            return Err(Halt);
        }
        if self.steps > self.limits.max_steps_per_root {
            return self.fail(span, "evaluation step limit reached");
        }
        Ok(())
    }

    pub(super) fn expand(&mut self, bytes: usize, span: Span) -> Eval<()> {
        self.expansion = self.expansion.saturating_add(bytes);
        if self.expansion > self.limits.max_retained_expansion_bytes {
            self.operation_error = Some(EvaluationSetupError::EvaluationRetainedExpansionLimit);
            return Err(Halt);
        }
        if self.expansion > self.limits.max_expansion_bytes {
            return self.fail(span, "evaluation expansion byte limit reached");
        }
        Ok(())
    }

    pub(super) fn fail<T>(&mut self, span: Span, message: impl Into<String>) -> Eval<T> {
        self.error(span, message);
        Err(Halt)
    }

    pub(super) fn error(&mut self, span: Span, message: impl Into<String>) {
        if self.diagnostics.len() < self.limits.max_diagnostics {
            self.diagnostics.push(
                Diagnostic::error(message, span)
                    .with_code(crate::diagnostic::DiagnosticCode::Evaluation),
            );
        }
    }
}

fn primitive_value(value: Value) -> Option<PrimitiveValue> {
    match value {
        Value::Int(value) => Some(PrimitiveValue::Int(value)),
        Value::Str(value) => Some(PrimitiveValue::Str(value)),
        Value::Nominal {
            value,
            resource: false,
            ..
        } => Some(value),
        _ => None,
    }
}

fn static_string_equals(literal: &StringLiteral, expected: &str) -> bool {
    if literal
        .parts
        .iter()
        .any(|part| matches!(part, StringPart::Interpolation { .. }))
    {
        return false;
    }
    let mut expected = expected.chars();
    for part in &literal.parts {
        if let StringPart::Text {
            source,
            ..
        } = part
        {
            let mut source = source.chars();
            while let Some(character) = source.next() {
                let decoded = if character == '\\' {
                    match source.next() {
                        Some('"') => '"',
                        Some('\\') => '\\',
                        Some('n') => '\n',
                        Some('r') => '\r',
                        Some('t') => '\t',
                        Some('$') => '$',
                        _ => return false,
                    }
                } else {
                    character
                };
                if expected.next() != Some(decoded) {
                    return false;
                }
            }
        }
    }
    expected.next().is_none()
}

fn literal_equals(literal: &Literal, value: &PrimitiveValue) -> bool {
    match (literal, value) {
        (Literal::Integer(left), PrimitiveValue::Int(right)) => left.value == *right,
        (Literal::String(left), PrimitiveValue::Str(right)) => static_string_equals(left, right),
        _ => false,
    }
}

fn decode_text_into(source: &str, result: &mut String) -> Option<()> {
    let mut chars = source.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            result.push(character);
            continue;
        }
        result.push(match chars.next()? {
            '"' => '"',
            '\\' => '\\',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            '$' => '$',
            _ => return None,
        });
    }
    Some(())
}

fn decimal_len(value: i64) -> usize {
    if value == 0 {
        return 1;
    }
    let mut magnitude = value.unsigned_abs();
    let mut length = usize::from(value.is_negative());
    while magnitude != 0 {
        magnitude /= 10;
        length += 1;
    }
    length
}
