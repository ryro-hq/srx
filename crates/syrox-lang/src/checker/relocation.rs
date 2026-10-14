//! Exhaustive coordinate conversion of inspection facts; never constructs a
//! `CheckedProgram` or publishes into a checker. Budget replay is a separate task.
use super::{
    CheckedExpression, CheckedLocal, CheckedPattern, Elaboration, OwnershipUse, ParameterHint, Ty,
};
use crate::{diagnostic::Diagnostic, resolver::ItemId, resolver::LocalId, source::Span};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Inspection facts in the receiving snapshot's coordinates. No production API
/// installs these facts or converts them into an executable program.
pub struct OwnerCheckedFacts {
    pub diagnostics: Vec<Diagnostic>,
    pub expressions: Vec<CheckedExpression>,
    pub patterns: Vec<CheckedPattern>,
    pub locals: BTreeMap<LocalId, CheckedLocal>,
    pub ownership: Vec<OwnershipUse>,
    pub fields: Vec<(Span, Span, Ty)>,
    pub arguments: Vec<ParameterHint>,
    pub outputs: BTreeMap<ItemId, Ty>,
}

pub(crate) trait FactMapper {
    fn reference_scan(&mut self, references: &[Span]) -> Option<std::sync::Arc<[Span]>>;
    fn span(&mut self, span: Span) -> Option<Span>;
    fn item(&mut self, item: ItemId) -> Option<ItemId>;
    fn local(&mut self, local: LocalId) -> Option<LocalId>;
    fn reserve(&mut self, bytes: usize) -> Option<()>;

    fn ty(&mut self, ty: &Ty) -> Option<Ty> {
        self.reserve(0)?;
        Some(match ty {
            Ty::Unit => Ty::Unit,
            Ty::Int => Ty::Int,
            Ty::Str => Ty::Str,
            Ty::Error => Ty::Error,
            Ty::Parameter(id) => Ty::Parameter(self.local(*id)?),
            Ty::Nominal(id) => Ty::Nominal(self.item(*id)?),
            Ty::Specialization {
                template,
                arguments,
            } => Ty::Specialization {
                template: self.item(*template)?,
                arguments: arguments
                    .iter()
                    .map(|ty| self.ty(ty))
                    .collect::<Option<_>>()?,
            },
            Ty::List(inner) => Ty::List(Box::new(self.ty(inner)?)),
            Ty::Function {
                parameters,
                result,
                once,
            } => Ty::Function {
                parameters: parameters
                    .iter()
                    .map(|ty| self.ty(ty))
                    .collect::<Option<_>>()?,
                result: Box::new(self.ty(result)?),
                once: *once,
            },
        })
    }

    fn elaboration(&mut self, elaboration: &Elaboration) -> Option<Elaboration> {
        self.reserve(0)?;
        Some(match elaboration {
            Elaboration::PackageSelection {
                factory,
            } => Elaboration::PackageSelection {
                factory: self.item(*factory)?,
            },
            Elaboration::ModuleExports {
                key,
                function,
            } => Elaboration::ModuleExports {
                key: self.item(*key)?,
                function: self.ty(function)?,
            },
            Elaboration::VariantConstructor {
                index,
            } => Elaboration::VariantConstructor {
                index: *index,
            },
            Elaboration::ContextualVariant {
                enumeration,
                index,
            } => Elaboration::ContextualVariant {
                enumeration: self.item(*enumeration)?,
                index: *index,
            },
            Elaboration::ValueLiteral(id) => Elaboration::ValueLiteral(self.item(*id)?),
            Elaboration::Erasure {
                source,
            } => Elaboration::Erasure {
                source: self.ty(source)?,
            },
            Elaboration::FunctionSpecialization {
                substitutions,
            } => Elaboration::FunctionSpecialization {
                substitutions: substitutions
                    .iter()
                    .map(|(id, ty)| Some((self.local(*id)?, self.ty(ty)?)))
                    .collect::<Option<_>>()?,
            },
        })
    }

    fn expression(&mut self, value: &CheckedExpression) -> Option<CheckedExpression> {
        Some(CheckedExpression {
            span: self.span(value.span)?,
            ty: self.ty(&value.ty)?,
            elaboration: optional(value.elaboration.as_ref(), |e| {
                self.elaboration(e)
            })?,
            expected: optional(value.expected.as_ref(), |ty| self.ty(ty))?,
            status: value.status,
        })
    }

    fn pattern(&mut self, value: &CheckedPattern) -> Option<CheckedPattern> {
        Some(CheckedPattern {
            span: self.span(value.span)?,
            enumeration: self.item(value.enumeration)?,
            index: value.index,
        })
    }

    fn binding(&mut self, value: &CheckedLocal) -> Option<CheckedLocal> {
        Some(CheckedLocal {
            id: self.local(value.id)?,
            declaration: self.span(value.declaration)?,
            ty: self.ty(&value.ty)?,
            affine: value.affine,
            annotated: value.annotated,
            status: value.status,
        })
    }

    fn ownership(&mut self, value: &OwnershipUse) -> Option<OwnershipUse> {
        Some(OwnershipUse {
            local: self.local(value.local)?,
            span: self.span(value.span)?,
            kind: value.kind,
            affine: value.affine,
            status: value.status,
            previous_move: optional(value.previous_move, |span| self.span(span))?,
            conditional: value.conditional,
            closure: optional(value.closure, |span| self.span(span))?,
        })
    }

    fn diagnostic(&mut self, value: &Diagnostic) -> Option<Diagnostic> {
        self.reserve(value.message.len() + value.note.as_ref().map_or(0, String::len))?;
        Some(Diagnostic {
            span: self.span(value.span)?,
            message: value.message.clone(),
            code: value.code,
            severity: value.severity,
            expected: value.expected,
            note: value.note.clone(),
            related: value
                .related
                .iter()
                .map(|related| {
                    self.reserve(related.message.len())?;
                    Some(crate::diagnostic::RelatedDiagnostic {
                        span: self.span(related.span)?,
                        message: related.message.clone(),
                    })
                })
                .collect::<Option<_>>()?,
        })
    }

    fn argument(&mut self, value: &ParameterHint) -> Option<ParameterHint> {
        self.reserve(value.name.len())?;
        Some(ParameterHint {
            argument: self.span(value.argument)?,
            parameter: self.span(value.parameter)?,
            name: value.name.clone(),
        })
    }
}

// Distinguish an absent optional fact from failure to relocate a present fact.
#[allow(clippy::option_option)]
fn optional<T, U>(value: Option<T>, map: impl FnOnce(T) -> Option<U>) -> Option<Option<U>> {
    match value {
        Some(value) => Some(Some(map(value)?)),
        None => Some(None),
    }
}
