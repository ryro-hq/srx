//! Follow callable values used by module initializers without realizing recipes.
//!
//! Closures and memoized factories are deferred. Only invocation visits their
//! bodies, with symbolic arguments/captures and the checked call's branch facts.
//! No predicates, acquisition, evaluator callbacks or host operations run here.

use super::{
    BTreeMap, BTreeSet, Block, CheckedExpression, Checker, Diagnostic, Elaboration, Expression,
    ExpressionKind, ItemId, LocalId, Pattern, ResolvedItemKind, ResolvedTarget, Span,
    StatementKind, StaticFacts, StringPart, Ty, span_key,
};
use crate::syntax::{Literal, Parameter, Path, StructField};
use std::sync::Arc;

type Environment<'a> = BTreeMap<LocalId, Symbolic<'a>>;

#[derive(Clone)]
enum Symbolic<'a> {
    Unknown,
    Integer(i64),
    Text(Arc<str>),
    Variant(ItemId, u32, Arc<[Self]>),
    Record(Arc<BTreeMap<&'a str, Self>>),
    List(Arc<[Self]>),
    Function(ItemId),
    Constructor(ItemId, u32),
    Closure {
        parameters: &'a [Parameter],
        body: &'a Block,
        captures: Arc<Environment<'a>>,
        facts: Arc<[Arc<StaticFacts>]>,
    },
    Choices(Arc<[Self]>),
}

struct Failure {
    span: Span,
    reason: &'static str,
    path: Vec<(Span, String)>,
    exhausted: bool,
}

struct Analysis<'c, 'a> {
    checker: &'c Checker<'a>,
    facts: BTreeMap<(u32, u32, u32), &'c CheckedExpression>,
    specializations: Vec<Arc<StaticFacts>>,
    texts: BTreeMap<(u32, u32, u32), Arc<str>>,
    globals: BTreeMap<ItemId, Symbolic<'a>>,
    active: BTreeSet<ItemId>,
    path: Vec<(Span, String)>,
    work: usize,
    units: usize,
    depth: usize,
}

impl Checker<'_> {
    pub(super) fn check_global_effects(&mut self) {
        if self.exhausted || self.global_values.is_empty() || !self.diagnostics.is_empty() {
            return;
        }
        let mut analysis = Analysis {
            checker: self,
            facts: BTreeMap::new(),
            specializations: Vec::new(),
            texts: BTreeMap::new(),
            globals: BTreeMap::new(),
            active: BTreeSet::new(),
            path: Vec::new(),
            work: self.work,
            units: self.budget_position().metadata,
            depth: 0,
        };
        let mut diagnostics = Vec::new();
        let mut exhausted = false;
        for (&item, (binding, _)) in &self.global_values {
            analysis.path = vec![(binding.name.span, binding.name.text.clone())];
            let result = (|| {
                if analysis.facts.is_empty() {
                    for fact in &self.expressions {
                        analysis.reserve(fact.span, 1)?;
                        analysis.facts.insert(span_key(fact.span), fact);
                    }
                }
                analysis.global(item, binding.value.span)
            })();
            if let Err(failure) = result {
                let path = failure
                    .path
                    .iter()
                    .map(|(_, name)| name.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ");
                let mut diagnostic = Diagnostic::error(failure.reason, binding.value.span)
                    .with_note(format!("call path: {path}"));
                for (span, label) in failure.path.into_iter().skip(1) {
                    diagnostic = diagnostic.with_related(span, format!("called here: {label}"));
                }
                diagnostic = diagnostic.with_related(
                    failure.span,
                    "resource effect or unresolved invocation originates here",
                );
                diagnostics.push(diagnostic);
                exhausted |= failure.exhausted;
                if exhausted || diagnostics.len() >= crate::MAX_DIAGNOSTICS {
                    break;
                }
            }
        }
        let work = analysis.work;
        let units = analysis
            .units
            .saturating_sub(self.budget_position().metadata);
        drop(analysis);
        self.work = work;
        self.collection_metadata_units += units;
        self.exhausted |= exhausted;
        for diagnostic in diagnostics {
            self.push_diagnostic(diagnostic);
        }
    }
}

impl<'a> Analysis<'_, 'a> {
    fn failure(&self, span: Span, reason: &'static str, exhausted: bool) -> Failure {
        Failure {
            span,
            reason,
            path: self.path.clone(),
            exhausted,
        }
    }

    fn reserve(&mut self, span: Span, units: usize) -> Result<(), Failure> {
        self.work = self.work.saturating_add(1);
        self.units = self.units.saturating_add(units);
        if self
            .checker
            .cancellation
            .is_some_and(|cancel| cancel.check().is_err())
            || self.work > self.checker.limits.max_work
        {
            return Err(self.failure(
                span,
                "global effect analysis work limit reached",
                true,
            ));
        }
        if self.units > self.checker.limits.max_metadata_units {
            return Err(self.failure(
                span,
                "global effect analysis metadata limit reached",
                true,
            ));
        }
        Ok(())
    }

    fn bytes(&mut self, span: Span, length: usize, retained: bool) -> Result<(), Failure> {
        self.work = self.work.saturating_add(length);
        self.reserve(
            span,
            if retained {
                length
                    .div_ceil(size_of::<Symbolic<'a>>())
                    .saturating_add(1)
            } else {
                0
            },
        )
    }

    fn literal_text(&mut self, string: &crate::syntax::StringLiteral) -> Result<Arc<str>, Failure> {
        let key = span_key(string.span);
        if let Some(text) = self.texts.get(&key) {
            return Ok(text.clone());
        }
        self.bytes(string.span, string.source.len(), true)?;
        let text = super::constants::decode_string(string).ok_or_else(|| {
            self.failure(
                string.span,
                "cannot determine a checked string literal while checking global effects",
                false,
            )
        })?;
        self.texts.insert(key, text.clone());
        Ok(text)
    }

    fn metadata(&self, span: Span) -> Option<&CheckedExpression> {
        self.specializations
            .iter()
            .rev()
            .find_map(|facts| facts.expressions.get(&span_key(span)))
            .or_else(|| self.facts.get(&span_key(span)).copied())
    }

    fn global(&mut self, item: ItemId, span: Span) -> Result<Symbolic<'a>, Failure> {
        self.reserve(span, 0)?;
        if let Some(value) = self.globals.get(&item) {
            return Ok(value.clone());
        }
        if !self.active.insert(item) {
            return Err(self.failure(
                span,
                "cycle while checking global callback effects",
                false,
            ));
        }
        let expression = self
            .checker
            .global_values
            .get(&item)
            .map(|(binding, _)| &binding.value)
            .or_else(|| {
                self.checker
                    .output_initializers
                    .get(&item)
                    .copied()
            });
        let result = if let Some(expression) = expression {
            self.expression(expression, &Environment::new())
        } else {
            Ok(Symbolic::Unknown)
        };
        self.active.remove(&item);
        if let Ok(value) = &result {
            self.reserve(span, 1)?;
            self.globals.insert(item, value.clone());
        }
        result
    }

    fn path_value(
        &mut self,
        path: &Path,
        env: &Environment<'a>,
        constructor: bool,
    ) -> Result<Symbolic<'a>, Failure> {
        match self.checker.target(path.span) {
            Some(ResolvedTarget::Local(local)) => Ok(env
                .get(local)
                .cloned()
                .unwrap_or(Symbolic::Unknown)),
            Some(ResolvedTarget::Item(item)) => {
                if let Some(member) = self.checker.program.published_member(*item) {
                    return Ok(Symbolic::Record(Arc::new(BTreeMap::from([(
                        "factory",
                        Symbolic::Function(member.factory()),
                    )]))));
                }
                if self.checker.functions.contains_key(item)
                    || self.checker.primitives.contains_key(item)
                {
                    Ok(Symbolic::Function(*item))
                } else {
                    self.global(*item, path.span)
                }
            }
            Some(ResolvedTarget::EnumVariant {
                enumeration,
                index,
            }) => Ok(
                if constructor
                    || self
                        .metadata(path.span)
                        .is_some_and(|fact| matches!(fact.ty(), Ty::Function { .. }))
                {
                    Symbolic::Constructor(*enumeration, *index)
                } else {
                    Symbolic::Variant(*enumeration, *index, Arc::from([]))
                },
            ),
            Some(ResolvedTarget::ContextualEnumVariant) => {
                if let Some(Elaboration::ContextualVariant {
                    enumeration,
                    index,
                }) = self
                    .metadata(path.span)
                    .and_then(|fact| fact.elaboration())
                {
                    Ok(Symbolic::Variant(
                        *enumeration,
                        *index,
                        Arc::from([]),
                    ))
                } else {
                    Ok(Symbolic::Unknown)
                }
            }
            _ => Ok(Symbolic::Unknown),
        }
    }

    fn expression(
        &mut self,
        expression: &'a Expression,
        env: &Environment<'a>,
    ) -> Result<Symbolic<'a>, Failure> {
        self.reserve(expression.span, 1)?;
        if self.depth >= self.checker.limits.max_specialization_depth {
            return Err(self.failure(
                expression.span,
                "global effect analysis depth limit reached",
                true,
            ));
        }
        self.depth += 1;
        let value = self.expression_inner(expression, env);
        self.depth -= 1;
        value
    }

    fn expression_inner(
        &mut self,
        expression: &'a Expression,
        env: &Environment<'a>,
    ) -> Result<Symbolic<'a>, Failure> {
        match &expression.kind {
            ExpressionKind::Integer(integer) => Ok(Symbolic::Integer(integer.value)),
            ExpressionKind::String(string) => {
                for part in &string.parts {
                    if let StringPart::Interpolation {
                        path,
                        ..
                    } = part
                    {
                        self.path_value(path, env, false)?;
                    }
                }
                if string
                    .parts
                    .iter()
                    .any(|part| matches!(part, StringPart::Interpolation { .. }))
                {
                    return Ok(Symbolic::Unknown);
                }
                self.literal_text(string).map(Symbolic::Text)
            }
            ExpressionKind::Path(path) => self.path_value(path, env, false),
            ExpressionKind::Specialize {
                function,
                ..
            } => self.path_value(function, env, true),
            ExpressionKind::Closure {
                parameters,
                body,
                once,
                ..
            } => {
                if *once {
                    return Err(self.failure(
                        expression.span,
                        "global initializer cannot construct an affine closure through a callback",
                        false,
                    ));
                }
                self.reserve(
                    expression.span,
                    env.len()
                        .saturating_add(self.specializations.len()),
                )?;
                Ok(Symbolic::Closure {
                    parameters,
                    body,
                    captures: Arc::new(env.clone()),
                    facts: self.specializations.clone().into(),
                })
            }
            ExpressionKind::Memoize(value)
            | ExpressionKind::Group(value)
            | ExpressionKind::Erase {
                value,
                ..
            } => self.expression(value, env),
            ExpressionKind::Let(block) => {
                self.reserve(block.span, env.len())?;
                self.block(block, env.clone())
            }
            ExpressionKind::Call {
                callee,
                arguments,
            } => {
                let callable = self.path_value(callee, env, true)?;
                let values = self.arguments(arguments, env)?;
                self.invoke_at(
                    callable,
                    values,
                    expression.span,
                    callee.span,
                    callee
                        .segments
                        .iter()
                        .map(|part| part.text.as_str())
                        .collect::<Vec<_>>()
                        .join("::"),
                )
            }
            ExpressionKind::Apply {
                callee,
                arguments,
            } => {
                let callable = self.expression(callee, env)?;
                let values = self.arguments(arguments, env)?;
                self.invoke_at(
                    callable,
                    values,
                    expression.span,
                    callee.span,
                    "callback".into(),
                )
            }
            ExpressionKind::MethodCall {
                receiver,
                method,
                arguments,
            } => {
                if let Some(ResolvedTarget::Item(item)) = self.checker.target(method.span) {
                    let callable = if self.checker.functions.contains_key(item)
                        || self.checker.primitives.contains_key(item)
                    {
                        Symbolic::Function(*item)
                    } else {
                        self.global(*item, method.span)?
                    };
                    let values = self.arguments(arguments, env)?;
                    return self.invoke_at(
                        callable,
                        values,
                        expression.span,
                        method.span,
                        method.text.clone(),
                    );
                }
                let value = self.expression(receiver, env)?;
                let mut values = self.arguments(arguments, env)?;
                let function =
                    self.metadata(expression.span)
                        .and_then(|fact| match fact.elaboration() {
                            Some(Elaboration::StaticCall {
                                function,
                                ..
                            }) => Some(*function),
                            Some(Elaboration::TraitCall {
                                implementation,
                            }) => Some(*implementation),
                            _ => None,
                        });
                let callable = if let Some(function) = function {
                    values.insert(0, value);
                    Symbolic::Function(function)
                } else {
                    self.field(value, &method.text, method.span)?
                };
                self.invoke_at(
                    callable,
                    values,
                    expression.span,
                    method.span,
                    method.text.clone(),
                )
            }
            ExpressionKind::Struct {
                path,
                fields,
                record_span,
                ..
            } => {
                let callable = !path.segments.is_empty() && self.checker.target(path.span).is_some_and(|target| !matches!(target, ResolvedTarget::Item(item) if self.checker.structs.contains_key(item)));
                let value = self.record(
                    fields,
                    if callable {
                        *record_span
                    } else {
                        expression.span
                    },
                    env,
                )?;
                if callable {
                    let function = self.path_value(path, env, true)?;
                    self.invoke_at(
                        function,
                        vec![value],
                        expression.span,
                        path.span,
                        path.segments
                            .iter()
                            .map(|part| part.text.as_str())
                            .collect::<Vec<_>>()
                            .join("::"),
                    )
                } else {
                    Ok(value)
                }
            }
            ExpressionKind::Field {
                value,
                fields,
            } => {
                let mut value = self.expression(value, env)?;
                for field in fields {
                    value = self.field(value, &field.text, field.span)?;
                }
                Ok(value)
            }
            ExpressionKind::List(items) => Ok(Symbolic::List(self.arguments(items, env)?.into())),
            ExpressionKind::Concat(parts) => {
                let mut values = Vec::new();
                let mut known = true;
                for part in parts {
                    if let Symbolic::List(items) = self.expression(part, env)? {
                        values.extend(items.iter().cloned());
                    } else {
                        known = false;
                    }
                }
                self.reserve(expression.span, values.len())?;
                Ok(if known {
                    Symbolic::List(values.into())
                } else {
                    Symbolic::Unknown
                })
            }
            ExpressionKind::If {
                condition,
                branches,
            } => {
                let condition = self.expression(condition, env)?;
                if let Symbolic::Variant(_, index, _) = condition {
                    self.expression(&branches[usize::from(index == 0)], env)
                } else {
                    let values = branches
                        .iter()
                        .map(|branch| self.expression(branch, env))
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(Symbolic::Choices(values.into()))
                }
            }
            ExpressionKind::Equality {
                left,
                right,
                negated,
            } => {
                let left = self.expression(left, env)?;
                let right = self.expression(right, env)?;
                let equal = self
                    .compare(&left, &right, expression.span)?
                    .map(std::cmp::Ordering::is_eq);
                Ok(equal
                    .and_then(|equal| {
                        self.metadata(expression.span)
                            .and_then(|fact| fact.ty().nominal_head())
                            .map(|item| {
                                Symbolic::Variant(item, u32::from(equal != *negated), Arc::from([]))
                            })
                    })
                    .unwrap_or(Symbolic::Unknown))
            }
            ExpressionKind::Compare {
                left,
                right,
                branches,
            } => {
                let left = self.expression(left, env)?;
                let right = self.expression(right, env)?;
                if let Some(order) = self.compare(&left, &right, expression.span)? {
                    self.expression(
                        &branches[match order {
                            std::cmp::Ordering::Less => 0,
                            std::cmp::Ordering::Equal => 1,
                            std::cmp::Ordering::Greater => 2,
                        }],
                        env,
                    )
                } else {
                    Ok(Symbolic::Choices(
                        branches
                            .iter()
                            .map(|branch| self.expression(branch, env))
                            .collect::<Result<Vec<_>, _>>()?
                            .into(),
                    ))
                }
            }
            ExpressionKind::Match {
                value,
                arms,
            } => {
                let value = self.expression(value, env)?;
                let mut possible = Vec::new();
                for arm in arms {
                    let selected = self.pattern_matches(&arm.pattern, &value)?;
                    if selected == Some(false) {
                        continue;
                    }
                    self.reserve(arm.span, env.len())?;
                    let mut bindings = env.clone();
                    if let Pattern::Variant {
                        bindings: names,
                        ..
                    } = &arm.pattern
                    {
                        for (index, name) in names.iter().enumerate() {
                            if let Some(local) = self.checker.local_id(name.span) {
                                let payload = match &value {
                                    Symbolic::Variant(_, _, values) => values.get(index).cloned(),
                                    _ => None,
                                };
                                bindings.insert(local, payload.unwrap_or(Symbolic::Unknown));
                            }
                        }
                    }
                    possible.push(self.expression(&arm.value, &bindings)?);
                    if selected == Some(true) {
                        break;
                    }
                }
                Ok(if possible.len() == 1 {
                    possible.pop().expect("one arm")
                } else {
                    Symbolic::Choices(possible.into())
                })
            }
            ExpressionKind::Fold {
                items,
                initial,
                step,
            } => {
                let items = self.expression(items, env)?;
                let accumulator = self.expression(initial, env)?;
                let step = self.expression(step, env)?;
                self.fold(items, accumulator, step, expression.span)
            }

            ExpressionKind::SortByKeys {
                items,
                keys,
            } => {
                let items = self.expression(items, env)?;
                let keys = self.expression(keys, env)?;
                if let (Symbolic::List(items), Symbolic::List(keys)) = (items, keys) {
                    if items.len() != keys.len()
                        || keys
                            .iter()
                            .any(|key| !matches!(key, Symbolic::Integer(_) | Symbolic::Text(_)))
                    {
                        return Ok(Symbolic::Unknown);
                    }
                    self.reserve(expression.span, items.len().saturating_mul(2))?;
                    let pairs = keys
                        .iter()
                        .cloned()
                        .zip(items.iter().cloned())
                        .collect::<Vec<_>>();
                    let pairs = self.sorted_pairs(pairs, expression.span)?;
                    Ok(Symbolic::List(
                        pairs.into_iter().map(|(_, item)| item).collect(),
                    ))
                } else {
                    Ok(Symbolic::Unknown)
                }
            }
            ExpressionKind::ModuleExports {
                mapper,
                ..
            } => {
                let mapper = self.expression(mapper, env)?;
                let mut values = Vec::new();
                if let Some(entries) = self
                    .checker
                    .program
                    .module_exports(expression.span)
                {
                    for entry in entries {
                        self.bytes(expression.span, entry.key().len(), true)?;
                        values.push(self.invoke_at(
                            mapper.clone(),
                            vec![
                                Symbolic::Text(entry.key().into()),
                                Symbolic::Function(entry.item()),
                            ],
                            expression.span,
                            expression.span,
                            "module mapper".into(),
                        )?);
                    }
                }
                Ok(Symbolic::List(values.into()))
            }
        }
    }

    fn fold(
        &mut self,
        items: Symbolic<'a>,
        mut accumulator: Symbolic<'a>,
        step: Symbolic<'a>,
        span: Span,
    ) -> Result<Symbolic<'a>, Failure> {
        self.reserve(span, 1)?;
        if self.depth >= self.checker.limits.max_specialization_depth {
            return Err(self.failure(
                span,
                "global effect analysis depth limit reached",
                true,
            ));
        }
        self.depth += 1;
        let result = (|| match items {
            Symbolic::List(items) => {
                for item in items.iter() {
                    accumulator = self.invoke_at(
                        step.clone(),
                        vec![accumulator, item.clone()],
                        span,
                        span,
                        "fold callback".into(),
                    )?;
                }
                Ok(accumulator)
            }
            Symbolic::Choices(choices) => choices
                .iter()
                .map(|items| {
                    self.fold(
                        items.clone(),
                        accumulator.clone(),
                        step.clone(),
                        span,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map(|values| Symbolic::Choices(values.into())),
            // An unknown list can iterate again with a different accumulator;
            // its initial value cannot constrain all subsequent iterations.
            _ => self.invoke_at(
                step,
                vec![Symbolic::Unknown, Symbolic::Unknown],
                span,
                span,
                "fold callback".into(),
            ),
        })();
        self.depth -= 1;
        result
    }

    fn arguments(
        &mut self,
        expressions: &'a [Expression],
        env: &Environment<'a>,
    ) -> Result<Vec<Symbolic<'a>>, Failure> {
        expressions
            .iter()
            .map(|expression| self.expression(expression, env))
            .collect()
    }

    fn block(
        &mut self,
        block: &'a Block,
        mut env: Environment<'a>,
    ) -> Result<Symbolic<'a>, Failure> {
        self.reserve(block.span, env.len())?;
        for statement in &block.statements {
            match &statement.kind {
                StatementKind::Let {
                    name,
                    value,
                    ..
                } => {
                    let value = self.expression(value, &env)?;
                    if let Some(local) = self.checker.local_id(name.span) {
                        env.insert(local, value);
                    }
                }
                StatementKind::Expression(expression) => {
                    self.expression(expression, &env)?;
                }
                StatementKind::Recovery {
                    ..
                } => {}
            }
        }
        block
            .tail
            .as_ref()
            .map_or(Ok(Symbolic::Unknown), |tail| {
                self.expression(tail, &env)
            })
    }

    fn record(
        &mut self,
        fields: &'a [StructField],
        span: Span,
        env: &Environment<'a>,
    ) -> Result<Symbolic<'a>, Failure> {
        let mut values = BTreeMap::new();
        for field in fields {
            values.insert(
                field.name.text.as_str(),
                self.expression(&field.value, env)?,
            );
        }
        if let Some(item) = self
            .metadata(span)
            .and_then(|fact| fact.ty().nominal_head())
            && let Some(info) = self.checker.structs.get(&item)
        {
            for field in &info.declaration.fields {
                if !values.contains_key(field.name.text.as_str())
                    && let Some(default) = &field.default
                {
                    values.insert(
                        field.name.text.as_str(),
                        self.expression(default, &Environment::new())?,
                    );
                }
            }
        }
        self.reserve(span, values.len())?;
        Ok(Symbolic::Record(Arc::new(values)))
    }

    fn field(
        &mut self,
        value: Symbolic<'a>,
        name: &str,
        span: Span,
    ) -> Result<Symbolic<'a>, Failure> {
        self.reserve(span, 1)?;
        if self.depth >= self.checker.limits.max_specialization_depth {
            return Err(self.failure(
                span,
                "global effect analysis depth limit reached",
                true,
            ));
        }
        self.depth += 1;
        let result = match value {
            Symbolic::Record(fields) => Ok(fields
                .get(name)
                .cloned()
                .unwrap_or(Symbolic::Unknown)),
            Symbolic::Choices(values) => values
                .iter()
                .map(|value| self.field(value.clone(), name, span))
                .collect::<Result<Vec<_>, _>>()
                .map(|values| Symbolic::Choices(values.into())),
            _ => Ok(Symbolic::Unknown),
        };
        self.depth -= 1;
        result
    }

    fn invoke_at(
        &mut self,
        callable: Symbolic<'a>,
        arguments: Vec<Symbolic<'a>>,
        expression: Span,
        span: Span,
        mut name: String,
    ) -> Result<Symbolic<'a>, Failure> {
        self.reserve(span, arguments.len())?;
        let elaboration = self
            .metadata(expression)
            .and_then(|fact| fact.elaboration());
        let callable = match elaboration {
            Some(Elaboration::StaticCall {
                function,
                ..
            }) => Symbolic::Function(*function),
            Some(Elaboration::TraitCall {
                implementation,
            }) => Symbolic::Function(*implementation),
            _ => callable,
        };
        let facts = elaboration.and_then(|elaboration| match elaboration {
            Elaboration::StaticCall {
                facts,
                ..
            } => Some(facts.clone()),
            _ => None,
        });
        if let Some(facts) = &facts {
            self.specializations.push(facts.clone());
        }
        if let Some((end, _)) = name.char_indices().nth(160) {
            name.truncate(end);
        }
        self.path.push((span, name));
        let result = self.invoke(callable, arguments, span);
        self.path.pop();
        if facts.is_some() {
            self.specializations.pop();
        }
        result
    }

    fn invoke(
        &mut self,
        callable: Symbolic<'a>,
        arguments: Vec<Symbolic<'a>>,
        span: Span,
    ) -> Result<Symbolic<'a>, Failure> {
        self.reserve(span, arguments.len())?;
        if self.depth >= self.checker.limits.max_specialization_depth {
            return Err(self.failure(
                span,
                "global effect analysis depth limit reached",
                true,
            ));
        }
        self.depth += 1;
        let result = self.invoke_inner(callable, arguments, span);
        self.depth -= 1;
        result
    }

    fn invoke_inner(
        &mut self,
        callable: Symbolic<'a>,
        arguments: Vec<Symbolic<'a>>,
        span: Span,
    ) -> Result<Symbolic<'a>, Failure> {
        match callable {
            Symbolic::Function(item) => {
                if self
                    .checker
                    .program
                    .item(item)
                    .is_some_and(|item| item.kind() == ResolvedItemKind::Resource)
                {
                    return Err(self.failure(span, "global initializer cannot consume or construct an affine resource through a callback", false));
                }
                if self.checker.primitives.contains_key(&item) {
                    return Ok(arguments
                        .into_iter()
                        .next()
                        .unwrap_or(Symbolic::Unknown));
                }
                let Some(info) = self.checker.functions.get(&item) else {
                    return Err(self.failure(
                        span,
                        "cannot establish resource-free global initialization for this callback",
                        false,
                    ));
                };
                let env = info
                    .declaration
                    .parameters
                    .iter()
                    .zip(arguments)
                    .filter_map(|(parameter, value)| {
                        self.checker
                            .local_id(parameter.name.span)
                            .map(|local| (local, value))
                    })
                    .collect();
                self.block(&info.declaration.body, env)
            }
            Symbolic::Closure {
                parameters,
                body,
                captures,
                facts,
            } => {
                self.reserve(
                    body.span,
                    captures.len().saturating_add(facts.len()),
                )?;
                let mut env = (*captures).clone();
                for (parameter, value) in parameters.iter().zip(arguments) {
                    if let Some(local) = self.checker.local_id(parameter.name.span) {
                        env.insert(local, value);
                    }
                }
                let previous = std::mem::replace(&mut self.specializations, facts.to_vec());
                let result = self.block(body, env);
                self.specializations = previous;
                result.map_err(|mut failure| {
                    failure.path.insert(
                        failure.path.len().saturating_sub(1),
                        (body.span, "callback body".into()),
                    );
                    failure
                })
            }
            Symbolic::Constructor(item, index) => {
                Ok(Symbolic::Variant(item, index, arguments.into()))
            }
            Symbolic::Choices(values) => {
                let results = values
                    .iter()
                    .map(|value| self.invoke(value.clone(), arguments.clone(), span))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Symbolic::Choices(results.into()))
            }
            _ => Err(self.failure(
                span,
                "cannot establish resource-free global initialization for this callback",
                false,
            )),
        }
    }

    fn compare(
        &mut self,
        left: &Symbolic<'_>,
        right: &Symbolic<'_>,
        span: Span,
    ) -> Result<Option<std::cmp::Ordering>, Failure> {
        self.reserve(span, 0)?;
        Ok(match (left, right) {
            (Symbolic::Integer(left), Symbolic::Integer(right)) => Some(left.cmp(right)),
            (Symbolic::Text(left), Symbolic::Text(right)) => {
                if Arc::ptr_eq(left, right) {
                    Some(std::cmp::Ordering::Equal)
                } else {
                    self.bytes(span, left.len().min(right.len()), false)?;
                    Some(left.cmp(right))
                }
            }
            (Symbolic::Variant(left, li, _), Symbolic::Variant(right, ri, _)) if left == right => {
                Some(li.cmp(ri))
            }
            _ => None,
        })
    }

    // A fallible stable merge keeps comparison work bounded without feeding a
    // partially ordered comparator to the standard sort after budget exhaustion.
    fn sorted_pairs(
        &mut self,
        mut pairs: Vec<(Symbolic<'a>, Symbolic<'a>)>,
        span: Span,
    ) -> Result<Vec<(Symbolic<'a>, Symbolic<'a>)>, Failure> {
        let mut buffer = pairs.clone();
        let mut width = 1usize;
        while width < pairs.len() {
            for start in (0..pairs.len()).step_by(width * 2) {
                let middle = (start + width).min(pairs.len());
                let end = (middle + width).min(pairs.len());
                let mut left = start;
                let mut right = middle;
                for target in &mut buffer[start..end] {
                    self.reserve(span, 0)?;
                    let take_left = right == end
                        || left < middle
                            && self.compare(&pairs[left].0, &pairs[right].0, span)?
                                != Some(std::cmp::Ordering::Greater);
                    let selected = if take_left {
                        let selected = left;
                        left += 1;
                        selected
                    } else {
                        let selected = right;
                        right += 1;
                        selected
                    };
                    *target = pairs[selected].clone();
                }
            }
            std::mem::swap(&mut pairs, &mut buffer);
            width *= 2;
        }
        Ok(pairs)
    }

    fn pattern_matches(
        &mut self,
        pattern: &Pattern,
        value: &Symbolic<'_>,
    ) -> Result<Option<bool>, Failure> {
        Ok(match pattern {
            Pattern::Wildcard(_) => Some(true),
            Pattern::Literal(Literal::Integer(integer)) => match value {
                Symbolic::Integer(value) => Some(*value == integer.value),
                _ => None,
            },
            Pattern::Literal(Literal::String(string)) => match value {
                Symbolic::Text(value) => {
                    let expected = self.literal_text(string)?;
                    self.compare(
                        &Symbolic::Text(expected),
                        &Symbolic::Text(value.clone()),
                        string.span,
                    )?
                    .map(std::cmp::Ordering::is_eq)
                }
                _ => None,
            },
            Pattern::Path(path)
            | Pattern::Variant {
                path,
                ..
            } => {
                let pattern = self
                    .specializations
                    .iter()
                    .rev()
                    .find_map(|facts| facts.patterns.get(&span_key(path.span)))
                    .or_else(|| {
                        self.checker
                            .patterns
                            .iter()
                            .find(|pattern| pattern.span == path.span)
                    });
                match (pattern, value) {
                    (Some(pattern), Symbolic::Variant(item, index, _)) => {
                        Some(pattern.enumeration == *item && pattern.index == *index)
                    }
                    _ => None,
                }
            }
        })
    }
}
