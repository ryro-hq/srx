use super::{BTreeMap, Checker, Context, RawTy, Ty};
use crate::{
    resolver::ItemId, resolver::LocalId, resolver::ModuleId, resolver::ResolvedProgram,
    source::SourceDomainId, source::Span,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldInfo {
    pub name: String,
    pub declaration: Span,
    pub ty: Ty,
    pub has_default: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NominalShape {
    pub literal_constructor: bool,
    pub parameters: Vec<LocalId>,
    pub authority: RepresentationAuthority,
    pub fields: Vec<FieldInfo>,
    pub variants: Vec<(String, Span, Vec<Ty>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RepresentationAuthority {
    pub domain: SourceDomainId,
    pub module: ModuleId,
    pub opaque: bool,
    pub owner_parameter: Option<usize>,
}

impl RepresentationAuthority {
    pub(super) fn for_struct(info: &super::StructInfo<'_>) -> Self {
        Self {
            domain: info.context.domain,
            module: info.context.module,
            opaque: info.declaration.opaque,
            owner_parameter: info
                .declaration
                .type_parameters
                .iter()
                .position(|parameter| parameter.owner),
        }
    }

    pub(super) const fn open(context: Context) -> Self {
        Self {
            domain: context.domain,
            module: context.module,
            opaque: false,
            owner_parameter: None,
        }
    }

    pub fn permits(&self, program: &ResolvedProgram, ty: &Ty, requester: ModuleId) -> bool {
        let Some(context) = program.modules().nth(requester.index()) else {
            return false;
        };
        let descendant = |module: ModuleId| {
            program
                .modules()
                .nth(module.index())
                .is_some_and(|owner| {
                    context.domain() == owner.domain()
                        && context
                            .path()
                            .segments()
                            .starts_with(owner.path().segments())
                })
        };
        if !self.opaque || context.domain() == self.domain && descendant(self.module) {
            return true;
        }
        let owner = self
            .owner_parameter
            .and_then(|index| match ty {
                Ty::Specialization {
                    arguments,
                    ..
                } => arguments.get(index),
                _ => None,
            })
            .and_then(Ty::nominal_head)
            .and_then(|id| program.items().nth(id.index()));
        owner.is_some_and(|owner| owner.domain() == self.domain && descendant(owner.module()))
    }
}

impl Checker<'_> {
    pub(super) fn record_arguments(
        &mut self,
        item: ItemId,
        arguments: &[crate::syntax::Expression],
    ) {
        if self.cancellation.is_some()
            && let Some(info) = self.functions.get(&item).copied()
        {
            for (argument, parameter) in arguments.iter().zip(&info.declaration.parameters) {
                if self.reserve_editor_metadata(argument.span) {
                    self.editor.arguments.push(super::ParameterHint {
                        argument: argument.span,
                        parameter: parameter.name.span,
                        name: parameter.name.text.clone(),
                    });
                }
            }
        }
    }
    pub(super) fn collect_editor_types(&mut self) {
        self.collect_published_editor_types();
        if self.cancellation.is_none() {
            return;
        }
        for (id, info) in self.structs.clone() {
            let raw_fields = self
                .struct_fields
                .get(&id)
                .cloned()
                .unwrap_or_default();
            let fields = info
                .declaration
                .fields
                .iter()
                .zip(&raw_fields)
                .filter_map(|(field, (_, raw, _))| {
                    if !self.reserve_editor_metadata(field.span) {
                        return None;
                    }
                    Some(FieldInfo {
                        name: field.name.text.clone(),
                        declaration: field.name.span,
                        ty: self.retain_symbolic_type(raw)?,
                        has_default: field.default.is_some(),
                    })
                })
                .collect();
            if !self.reserve_editor_metadata(info.declaration.name.span) {
                break;
            }
            self.editor.shapes.insert(
                id,
                NominalShape {
                    literal_constructor: !self
                        .policy
                        .erasures
                        .iter()
                        .any(|rule| rule.target == self.item_identity(id)),
                    authority: RepresentationAuthority::for_struct(&info),
                    parameters: info.parameters,
                    fields,
                    variants: Vec::new(),
                },
            );
        }
        for (id, declaration) in self.enums.clone() {
            let parameters = self.nominal_parameters(id);
            let raw_fields = self
                .struct_fields
                .get(&id)
                .cloned()
                .unwrap_or_default();
            let mut payloads = raw_fields.iter();
            let variants = declaration
                .variants
                .iter()
                .filter_map(|variant| {
                    if !self.reserve_editor_metadata(variant.name.span) {
                        return None;
                    }
                    let types = variant
                        .payload
                        .iter()
                        .map(|_| self.retain_symbolic_type(&payloads.next()?.1))
                        .collect::<Option<Vec<_>>>()?;
                    Some((
                        variant.name.text.clone(),
                        variant.name.span,
                        types,
                    ))
                })
                .collect();
            if !self.reserve_editor_metadata(declaration.name.span) {
                break;
            }
            let context = self.item_context[&id];
            self.editor.shapes.insert(
                id,
                NominalShape {
                    literal_constructor: false,
                    parameters,
                    variants,
                    fields: Vec::new(),
                    authority: RepresentationAuthority::open(context),
                },
            );
        }
    }

    fn collect_published_editor_types(&mut self) {
        let program = self.program;
        for item in program.items() {
            let Some(member) = program.published_member(item.id()) else {
                continue;
            };
            let span = item.span();
            if !self.charge(span) || !self.reserve_metadata(span) {
                return;
            }
            self.collection_metadata_units += 1;
            let ty = self.published_member_type(member.factory(), span);
            let available = self.limits.max_metadata_units.saturating_sub(
                self.collection_metadata_units
                    .saturating_add(self.expressions.len())
                    .saturating_add(self.patterns.len())
                    .saturating_add(self.prior_metadata),
            );
            let mut remaining = available;
            let Some(retained) = substitute_type(&ty, &BTreeMap::new(), &mut remaining) else {
                self.exhausted = true;
                self.error("checked metadata limit reached", span);
                return;
            };
            self.collection_metadata_units += available - remaining;
            self.published_types.insert(item.id(), retained);
            if self.reserve_editor_metadata(span)
                && let Some(ty) = self.retain_editor_type(&ty)
            {
                self.editor.outputs.insert(item.id(), ty);
            }
        }
    }

    pub(super) fn reserve_editor_metadata(&mut self, span: Span) -> bool {
        self.observe_effect(span, super::bodies::EffectOperation::EditorUnit);
        let Some(cancellation) = self.cancellation else {
            return false;
        };
        if cancellation.check().is_err() {
            return false;
        }
        if self.editor.units >= self.limits.max_metadata_units {
            self.editor.truncated = true;
            return false;
        }
        self.editor.units += 1;
        true
    }

    fn retain_symbolic_type(&mut self, raw: &RawTy) -> Option<Ty> {
        debug_assert!(
            !self.body.active,
            "symbolic shapes are built outside body checking"
        );
        let mut budget = self
            .limits
            .max_metadata_units
            .saturating_sub(self.editor.units);
        let ty = symbolic_type(raw, &mut budget);
        self.editor.units = self.limits.max_metadata_units - budget;
        self.editor.truncated |= ty.is_none();
        ty
    }

    pub(super) fn retain_editor_type(&mut self, ty: &Ty) -> Option<Ty> {
        self.cancellation?;
        let before = self.budget_position();
        let mut budget = self
            .limits
            .max_metadata_units
            .saturating_sub(self.editor.units);
        let ty = substitute_type(ty, &BTreeMap::new(), &mut budget);
        self.editor.units = self.limits.max_metadata_units - budget;
        self.editor.truncated |= ty.is_none();
        if let Some(span) = self.body.effect_anchor {
            self.observe_effect_at(
                before,
                span,
                super::bodies::EffectOperation::EditorType(
                    self.editor
                        .units
                        .saturating_sub(before.editor_metadata),
                ),
            );
        }
        ty
    }

    pub(super) fn record_field(&mut self, span: Span, declaration: Span, ty: &Ty) {
        if self.reserve_editor_metadata(span)
            && let Some(ty) = self.retain_editor_type(ty)
        {
            self.editor.fields.push((span, declaration, ty));
        }
    }
}

fn symbolic_type(raw: &RawTy, budget: &mut usize) -> Option<Ty> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    Some(match raw {
        RawTy::Concrete(ty) => substitute_type(ty, &BTreeMap::new(), budget)?,
        RawTy::Parameter(id) => Ty::Parameter(*id),
        RawTy::List(inner) => Ty::List(Box::new(symbolic_type(inner, budget)?)),
        RawTy::Specialization {
            template,
            arguments,
        } => Ty::Specialization {
            template: *template,
            arguments: arguments
                .iter()
                .map(|ty| symbolic_type(ty, budget))
                .collect::<Option<_>>()?,
        },
        RawTy::Function {
            parameters,
            result,
            once,
        } => Ty::Function {
            parameters: parameters
                .iter()
                .map(|ty| symbolic_type(ty, budget))
                .collect::<Option<_>>()?,
            result: Box::new(symbolic_type(result, budget)?),
            once: *once,
        },
    })
}

pub(crate) fn substitute_type(
    ty: &Ty,
    substitutions: &BTreeMap<LocalId, Ty>,
    budget: &mut usize,
) -> Option<Ty> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    Some(match ty {
        Ty::Parameter(id) if substitutions.contains_key(id) => {
            substitute_type(&substitutions[id], &BTreeMap::new(), budget)?
        }
        Ty::List(inner) => Ty::List(Box::new(substitute_type(
            inner,
            substitutions,
            budget,
        )?)),
        Ty::Specialization {
            template,
            arguments,
        } => Ty::Specialization {
            template: *template,
            arguments: arguments
                .iter()
                .map(|ty| substitute_type(ty, substitutions, budget))
                .collect::<Option<_>>()?,
        },
        Ty::Function {
            parameters,
            result,
            once,
        } => Ty::Function {
            parameters: parameters
                .iter()
                .map(|ty| substitute_type(ty, substitutions, budget))
                .collect::<Option<_>>()?,
            result: Box::new(substitute_type(result, substitutions, budget)?),
            once: *once,
        },
        _ => ty.clone(),
    })
}
