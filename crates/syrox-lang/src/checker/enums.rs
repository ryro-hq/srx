use super::{
    BTreeMap, Checker, Constant, Elaboration, ItemId, LocalId, Pattern, RawTy, Span, Ty, Type,
};

impl Checker<'_> {
    pub(super) fn bind_variant_pattern(
        &mut self,
        pattern: &Pattern,
        scrutinee: &Ty,
        index: u32,
        constant: Option<&Constant>,
    ) {
        let payload = self.variant_payload(scrutinee, index);
        let bindings = match pattern {
            Pattern::Variant {
                bindings,
                ..
            } => bindings.as_slice(),
            _ => &[],
        };
        for (position, (binding, ty)) in bindings.iter().zip(payload).enumerate() {
            if let Some(local) = self.local_id(binding.span) {
                self.bind_local(local, ty, binding.span, false);
                if let Some(Constant::Variant {
                    payload,
                    ..
                }) = constant
                {
                    self.body
                        .bindings
                        .get_mut(&local)
                        .expect("bound pattern")
                        .constant = payload.get(position).cloned().flatten();
                }
            }
        }
    }

    pub(super) fn nominal_parameters(&self, item: ItemId) -> Vec<LocalId> {
        if let Some(info) = self.structs.get(&item) {
            return info.parameters.clone();
        }
        self.enums
            .get(&item)
            .into_iter()
            .flat_map(|item| &item.type_parameters)
            .filter_map(|parameter| self.local_id(parameter.name.span))
            .collect()
    }

    pub(super) fn validate_enums(&mut self) {
        let enums: Vec<_> = self
            .enums
            .iter()
            .map(|(&id, &item)| (id, item))
            .collect();
        for (id, item) in enums {
            let params = self
                .nominal_parameters(id)
                .into_iter()
                .map(|id| (id, RawTy::Parameter(id)))
                .collect();
            let mut fields = Vec::new();
            for variant in &item.variants {
                for ty in &variant.payload {
                    if !self.charge(ty.span) {
                        return;
                    }
                    let raw = self.resolve_raw_type(ty, &params, 0);
                    if let Some(concrete) = self.concretize(raw.clone(), &BTreeMap::new(), ty.span)
                    {
                        self.track_generic_instances(&concrete, ty.span);
                    }
                    fields.push((variant.name.text.clone(), raw, false));
                }
            }
            // Carrier analysis traverses every alternative; a value is affine
            // if any variant may contain a resource or a consumable closure.
            self.struct_fields.insert(id, fields);
        }
    }

    pub(super) fn variant_payload(&mut self, ty: &Ty, index: u32) -> Vec<Ty> {
        let Some(item) = Ty::nominal_head(ty) else {
            return Vec::new();
        };
        let Some(declaration) = self.enums.get(&item).copied() else {
            return Vec::new();
        };
        let Some(variant) = declaration.variants.get(index as usize) else {
            return Vec::new();
        };
        let substitutions = self.specialization_substitutions(item, ty);
        variant
            .payload
            .iter()
            .map(|ty| self.resolve_type(ty, &substitutions, 0))
            .collect()
    }

    pub(super) fn variant_constructor(
        &mut self,
        enumeration: ItemId,
        index: u32,
        arguments: &[Type],
        span: Span,
        elaboration: &mut Option<Elaboration>,
    ) -> Ty {
        let params = self
            .body
            .type_parameters
            .iter()
            .map(|(&id, ty)| (id, super::types::raw_from_ty(ty.clone())))
            .collect();
        let raw = self.expand_item_type(enumeration, arguments, &params, 0, span);
        let ty = self
            .concretize(raw, &self.body.type_parameters.clone(), span)
            .unwrap_or(Ty::Error);
        self.validate_concrete_type(&ty, span);
        self.track_generic_instances(&ty, span);
        let parameters = self.variant_payload(&ty, index);
        *elaboration = Some(Elaboration::VariantConstructor {
            index,
        });
        Ty::Function {
            parameters,
            result: Box::new(ty),
            once: false,
        }
    }

    pub(super) fn empty_variant(
        &mut self,
        enumeration: ItemId,
        index: u32,
        expected: Option<&Ty>,
        span: Span,
    ) -> Ty {
        let ty = match expected {
            Some(ty) if Ty::nominal_head(ty) == Some(enumeration) => ty.clone(),
            _ if self.nominal_parameters(enumeration).is_empty() => Ty::Nominal(enumeration),
            _ => {
                self.error(
                    "generic enum variant requires a contextual type or explicit type arguments",
                    span,
                );
                return Ty::Error;
            }
        };
        if !self.variant_payload(&ty, index).is_empty() {
            self.error(
                "enum variant payload requires a constructor call",
                span,
            );
        }
        ty
    }
}
