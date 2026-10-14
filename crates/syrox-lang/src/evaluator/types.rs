use std::{collections::BTreeMap, mem::size_of, sync::Arc};

use super::{
    CanonicalType,
    runtime::{Eval, Evaluator, Halt},
};
use crate::{
    checker::CanonicalItemIdentity, checker::Ty, resolver::ItemId, resolver::LocalId, source::Span,
    syntax::Expression,
};

impl Evaluator<'_> {
    pub(super) fn substitute_bindings(
        &mut self,
        bindings: &BTreeMap<LocalId, Ty>,
        outer: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<BTreeMap<LocalId, Ty>> {
        self.expand(
            bindings
                .len()
                .saturating_mul(size_of::<(LocalId, Ty)>()),
            span,
        )?;
        bindings
            .iter()
            .map(|(id, ty)| Ok((*id, self.substitute_ty(ty, outer, span)?)))
            .collect()
    }
    pub(super) fn canonical_expression_type(
        &mut self,
        expression: &Expression,
    ) -> Option<Arc<CanonicalType>> {
        let metadata = self.checked.expression(expression.span)?;
        self.canonical_ty(metadata.ty(), &BTreeMap::new(), expression.span)
            .ok()
    }

    pub(super) fn specialization_substitutions(
        &mut self,
        item: ItemId,
        ty: &Ty,
        outer: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<BTreeMap<LocalId, Ty>> {
        let Some(declaration) = self.index.structures.get(&item).copied() else {
            return self.fail(span, "generic default declaration is unavailable");
        };
        if declaration.type_parameters.is_empty() {
            return Ok(BTreeMap::new());
        }
        let Ty::Specialization {
            arguments,
            ..
        } = ty
        else {
            return self.fail(
                span,
                "generic default has no concrete specialization",
            );
        };
        if arguments.len() != declaration.type_parameters.len() {
            return self.fail(
                span,
                "generic default substitution arity mismatch",
            );
        }
        let mut result = BTreeMap::new();
        for (parameter, argument) in declaration.type_parameters.iter().zip(arguments) {
            let Some(local) = self.index.local(parameter.name.span) else {
                return self.fail(
                    parameter.span,
                    "generic default parameter metadata is missing",
                );
            };
            let argument = self.substitute_ty(argument, outer, span)?;
            self.expand(size_of::<(LocalId, Ty)>(), span)?;
            result.insert(local, argument);
        }
        Ok(result)
    }

    pub(super) fn substitute_ty(
        &mut self,
        ty: &Ty,
        substitutions: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<Ty> {
        self.substitute_ty_inner(ty, substitutions, span, 0)
    }

    fn substitute_ty_inner(
        &mut self,
        ty: &Ty,
        substitutions: &BTreeMap<LocalId, Ty>,
        span: Span,
        depth: usize,
    ) -> Eval<Ty> {
        if depth >= self.limits.max_depth {
            return self.fail(
                span,
                "generic default substitution depth limit reached",
            );
        }
        match ty {
            Ty::Parameter(parameter) => {
                let replacement = substitutions.get(parameter).ok_or_else(|| {
                    self.error(span, "generic default substitution is missing");
                    Halt
                })?;
                self.substitute_ty_inner(replacement, substitutions, span, depth + 1)
            }
            Ty::Specialization {
                template,
                arguments,
            } => {
                self.expand(
                    arguments.len().saturating_mul(size_of::<Ty>()),
                    span,
                )?;
                let arguments = arguments
                    .iter()
                    .map(|argument| {
                        self.substitute_ty_inner(argument, substitutions, span, depth + 1)
                    })
                    .collect::<Eval<Vec<_>>>()?;
                Ok(Ty::Specialization {
                    template: *template,
                    arguments,
                })
            }
            Ty::List(element) => {
                self.expand(size_of::<Ty>(), span)?;
                Ok(Ty::List(Box::new(self.substitute_ty_inner(
                    element,
                    substitutions,
                    span,
                    depth + 1,
                )?)))
            }
            Ty::Function {
                parameters,
                result,
                once,
            } => {
                self.expand(
                    parameters.len().saturating_mul(size_of::<Ty>()),
                    span,
                )?;
                Ok(Ty::Function {
                    once: *once,
                    parameters: parameters
                        .iter()
                        .map(|ty| self.substitute_ty_inner(ty, substitutions, span, depth + 1))
                        .collect::<Eval<Vec<_>>>()?,
                    result: Box::new(self.substitute_ty_inner(
                        result,
                        substitutions,
                        span,
                        depth + 1,
                    )?),
                })
            }
            Ty::Unit | Ty::Int | Ty::Str | Ty::Nominal(_) => Ok(ty.clone()),
            Ty::Error => self.fail(span, "checked expression contains an error type"),
        }
    }

    pub(super) fn canonical_ty(
        &mut self,
        ty: &Ty,
        substitutions: &BTreeMap<LocalId, Ty>,
        span: Span,
    ) -> Eval<Arc<CanonicalType>> {
        let ty = self.substitute_ty(ty, substitutions, span)?;
        if let Some(canonical) = self
            .canonical_types
            .get(&ty)
            .cloned()
            .or_else(|| self.index.canonical_type(&ty))
        {
            return Ok(canonical);
        }
        let canonical = self.canonical_concrete_ty(&ty, span, 0)?;
        self.expand(
            size_of::<(Ty, Arc<CanonicalType>)>().saturating_add(type_allocation_bytes(&ty)),
            span,
        )?;
        self.canonical_types.insert(ty, canonical.clone());
        Ok(canonical)
    }

    fn canonical_concrete_ty(
        &mut self,
        ty: &Ty,
        span: Span,
        depth: usize,
    ) -> Eval<Arc<CanonicalType>> {
        if depth >= self.limits.max_depth {
            return self.fail(span, "canonical type depth limit reached");
        }
        match ty {
            Ty::Unit => self.canonical_leaf(CanonicalType::Unit, span),
            Ty::Int => self.canonical_leaf(CanonicalType::Int, span),
            Ty::Str => self.canonical_leaf(CanonicalType::Str, span),
            Ty::Nominal(item) => {
                let identity = self.item_identity(*item, span)?;
                self.canonical_leaf(CanonicalType::Nominal(identity), span)
            }
            Ty::Specialization {
                template,
                arguments,
            } => {
                self.expand(
                    arguments
                        .len()
                        .saturating_mul(size_of::<Arc<CanonicalType>>()),
                    span,
                )?;
                let mut canonical = Vec::with_capacity(arguments.len());
                for argument in arguments {
                    canonical.push(self.canonical_concrete_ty(argument, span, depth + 1)?);
                }
                let template = self.item_identity(*template, span)?;
                self.canonical_leaf(
                    CanonicalType::Specialization {
                        template,
                        arguments: canonical,
                    },
                    span,
                )
            }
            Ty::List(element) => {
                let element = self.canonical_concrete_ty(element, span, depth + 1)?;
                self.canonical_leaf(CanonicalType::List(element), span)
            }
            Ty::Function {
                parameters,
                result,
                once,
            } => {
                self.expand(
                    parameters
                        .len()
                        .saturating_mul(size_of::<Arc<CanonicalType>>()),
                    span,
                )?;
                let parameters = parameters
                    .iter()
                    .map(|ty| self.canonical_concrete_ty(ty, span, depth + 1))
                    .collect::<Eval<Vec<_>>>()?;
                let result = self.canonical_concrete_ty(result, span, depth + 1)?;
                self.canonical_leaf(
                    CanonicalType::Function {
                        parameters,
                        result,
                        once: *once,
                    },
                    span,
                )
            }
            Ty::Parameter(_) => self.fail(
                span,
                "canonical type contains an unsubstituted parameter",
            ),
            Ty::Error => self.fail(
                span,
                "canonical type contains checked error metadata",
            ),
        }
    }

    fn canonical_leaf(&mut self, ty: CanonicalType, span: Span) -> Eval<Arc<CanonicalType>> {
        self.expand(size_of::<CanonicalType>(), span)?;
        Ok(Arc::new(ty))
    }

    fn item_identity(&mut self, item: ItemId, span: Span) -> Eval<Arc<CanonicalItemIdentity>> {
        self.index.identity(item).ok_or_else(|| {
            self.error(span, "canonical item identity is unavailable");
            Halt
        })
    }
}

pub(super) fn type_allocation_bytes(ty: &Ty) -> usize {
    match ty {
        Ty::Specialization {
            arguments,
            ..
        } => arguments
            .len()
            .saturating_mul(size_of::<Ty>())
            .saturating_add(
                arguments
                    .iter()
                    .map(type_allocation_bytes)
                    .sum::<usize>(),
            ),
        Ty::List(element) => size_of::<Ty>().saturating_add(type_allocation_bytes(element)),
        Ty::Function {
            parameters,
            result,
            ..
        } => parameters
            .len()
            .saturating_mul(size_of::<Ty>())
            .saturating_add(
                parameters
                    .iter()
                    .map(type_allocation_bytes)
                    .sum::<usize>(),
            )
            .saturating_add(type_allocation_bytes(result)),
        Ty::Unit | Ty::Int | Ty::Str | Ty::Parameter(_) | Ty::Nominal(_) | Ty::Error => 0,
    }
}
