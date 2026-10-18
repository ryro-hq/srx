//! Concrete static implementations, checked before any evaluator is constructed.
use super::{
    BTreeMap, BTreeSet, Checker, Context, Elaboration, Expression, LocalId, ModuleId,
    ResolvedTarget, Span, Ty,
};
use crate::syntax::ModuleContract;

impl Checker<'_> {
    pub(super) fn index_traits(&mut self) {
        let functions: Vec<_> = self.functions.values().copied().collect();
        for function in functions {
            for parameter in &function.declaration.type_parameters {
                let Some(local) = self.local_id(parameter.name.span) else {
                    continue;
                };
                let mut bounds = Vec::new();
                for path in &parameter.bounds {
                    if !self.charge(path.span) {
                        return;
                    }
                    if let Some(ResolvedTarget::Module(module)) = self.target(path.span).cloned() {
                        if matches!(
                            self.module_contracts.get(&module),
                            Some(ModuleContract::Trait { .. })
                        ) {
                            bounds.push(module);
                        } else {
                            self.error("generic bound must name a trait", path.span);
                        }
                    } else {
                        self.error("generic bound must name a trait", path.span);
                    }
                }
                self.type_bounds.insert(local, bounds);
            }
        }
        let contracts: Vec<_> = self
            .module_contracts
            .iter()
            .map(|(&module, &contract)| (module, contract))
            .collect();
        for (module, contract) in contracts {
            if let ModuleContract::Methods {
                target,
            } = contract
            {
                let ty = self.resolve_type(target, &BTreeMap::new(), 0);
                let own = ty
                    .nominal_head()
                    .and_then(|id| self.program.item(id))
                    .is_some_and(|item| {
                        item.domain()
                            == self
                                .program
                                .modules()
                                .nth(module.index())
                                .expect("methods module")
                                .domain()
                    });
                if !own {
                    self.error(
                        "methods must belong to their target type's source domain",
                        target.span,
                    );
                }
                self.methods.entry(ty).or_default().push(module);
                continue;
            }
            let ModuleContract::Implementation {
                trait_path,
                target,
            } = contract
            else {
                continue;
            };
            let Some(ResolvedTarget::Module(trait_id)) = self.target(trait_path.span).cloned()
            else {
                self.error("impl requires a trait", trait_path.span);
                continue;
            };
            if !matches!(
                self.module_contracts.get(&trait_id),
                Some(ModuleContract::Trait { .. })
            ) {
                self.error("impl requires a trait", trait_path.span);
                continue;
            }
            let ty = self.resolve_type(target, &BTreeMap::new(), 0);
            let Some(item) = ty.nominal_head() else {
                self.error("static impl requires a nominal type", target.span);
                continue;
            };
            let owner = self
                .program
                .modules()
                .nth(module.index())
                .expect("implementation module")
                .domain();
            if self
                .program
                .modules()
                .nth(trait_id.index())
                .expect("trait module")
                .domain()
                != owner
                && self
                    .program
                    .item(item)
                    .expect("implementation type")
                    .domain()
                    != owner
            {
                self.error(
                    "impl must own its trait or its target type",
                    target.span,
                );
            }
            if self
                .implementations
                .contains_key(&(trait_id, ty.clone()))
            {
                self.error(
                    "ambiguous duplicate trait implementation",
                    target.span,
                );
            } else {
                self.implementations
                    .insert((trait_id, ty), module);
            }
        }
    }

    fn trait_closure(&mut self, roots: &[ModuleId], span: Span) -> Vec<ModuleId> {
        let mut result = BTreeSet::new();
        let mut pending = roots.to_vec();
        while let Some(module) = pending.pop() {
            if !self.charge(span) {
                break;
            }
            if !result.insert(module) {
                continue;
            }
            if let Some(ModuleContract::Trait {
                parents,
                ..
            }) = self.module_contracts.get(&module)
            {
                for parent in parents {
                    if let Some(ResolvedTarget::Module(parent_id)) = self.target(parent.span) {
                        if matches!(
                            self.module_contracts.get(parent_id),
                            Some(ModuleContract::Trait { .. })
                        ) {
                            pending.push(*parent_id);
                        } else {
                            self.error("parent must name a trait", parent.span);
                        }
                    } else {
                        self.error("parent must name a trait", parent.span);
                    }
                }
            }
        }
        result.into_iter().collect()
    }

    pub(super) fn associated_type(
        &mut self,
        local: LocalId,
        concrete: Option<&Ty>,
        name: &str,
        span: Span,
    ) -> Ty {
        let roots = self
            .type_bounds
            .get(&local)
            .cloned()
            .unwrap_or_default();
        self.associated_from_bounds(&roots, concrete, name, span)
    }

    fn associated_from_bounds(
        &mut self,
        roots: &[ModuleId],
        concrete: Option<&Ty>,
        name: &str,
        span: Span,
    ) -> Ty {
        let candidates: Vec<_> = self.trait_closure(roots, span).into_iter().filter(|module| matches!(self.module_contracts.get(module), Some(ModuleContract::Trait { associated, .. }) if associated.iter().any(|member| member.text == name))).collect();
        let [trait_id] = candidates.as_slice() else {
            self.error("unknown or ambiguous associated type", span);
            return Ty::Error;
        };
        let Some(concrete) = concrete.filter(|ty| !matches!(ty, Ty::Parameter(_) | Ty::Error))
        else {
            return Ty::Error;
        };
        let Some(&implementation) = self
            .implementations
            .get(&(*trait_id, concrete.clone()))
        else {
            self.error(
                "type does not implement the associated type's trait",
                span,
            );
            return Ty::Error;
        };
        let alias = self.aliases.keys().copied().find(|id| {
            self.item_context[id].module == implementation
                && self.aliases[id].declaration.name.text == name
        });
        if let Some(id) = alias {
            self.resolve_type(
                &self.aliases[&id].declaration.ty,
                &BTreeMap::new(),
                0,
            )
        } else {
            self.error(
                "trait implementation is missing an associated type",
                span,
            );
            Ty::Error
        }
    }

    pub(super) fn implementation_associated_type(
        &mut self,
        module: ModuleId,
        name: &str,
        span: Span,
    ) -> Ty {
        let Some(ModuleContract::Implementation {
            target,
            trait_path,
        }) = self.module_contracts.get(&module).copied()
        else {
            self.error(
                "associated type requires a trait implementation",
                span,
            );
            return Ty::Error;
        };
        let ty = self.resolve_type(target, &BTreeMap::new(), 0);
        let Some(ResolvedTarget::Module(trait_id)) = self.target(trait_path.span).cloned() else {
            return Ty::Error;
        };
        self.associated_from_bounds(&[trait_id], Some(&ty), name, span)
    }

    pub(super) fn validate_bounds(&mut self, substitutions: &BTreeMap<LocalId, Ty>, span: Span) {
        for (&local, ty) in substitutions {
            let roots = self
                .type_bounds
                .get(&local)
                .cloned()
                .unwrap_or_default();
            for bound in self.trait_closure(&roots, span) {
                if !self
                    .implementations
                    .contains_key(&(bound, ty.clone()))
                {
                    self.error(
                        "generic argument does not satisfy its trait bound",
                        span,
                    );
                }
            }
        }
    }

    pub(super) fn validate_traits(&mut self) {
        let traits: Vec<_> = self
            .module_contracts
            .iter()
            .filter_map(|(&module, &contract)| {
                if let ModuleContract::Trait {
                    parents,
                    ..
                } = contract
                {
                    Some((module, parents))
                } else {
                    None
                }
            })
            .collect();
        for (module, parents) in traits {
            for parent in parents {
                if let Some(ResolvedTarget::Module(parent_id)) = self.target(parent.span).cloned()
                    && self
                        .trait_closure(&[parent_id], parent.span)
                        .contains(&module)
                {
                    self.error("cyclic trait inheritance", parent.span);
                }
            }
        }
        let functions: Vec<_> = self.functions.values().copied().collect();
        for info in functions {
            if info.declaration.abstract_member
                && !matches!(
                    self.module_contracts.get(&info.context.module),
                    Some(ModuleContract::Trait { .. })
                )
            {
                self.error(
                    "method signatures without bodies are only valid in traits",
                    info.declaration.name.span,
                );
            }
        }
        let implementations: Vec<_> = self
            .implementations
            .iter()
            .map(|((trait_id, ty), &module)| (*trait_id, ty.clone(), module))
            .collect();
        for (trait_id, ty, module) in implementations {
            let ModuleContract::Trait {
                associated,
                parents,
            } = self.module_contracts[&trait_id]
            else {
                continue;
            };
            let span = match self.module_contracts[&module] {
                ModuleContract::Implementation {
                    target,
                    ..
                } => target.span,
                _ => continue,
            };
            let required: BTreeSet<_> = associated
                .iter()
                .map(|member| member.text.as_str())
                .collect();
            let given: BTreeSet<_> = self
                .aliases
                .iter()
                .filter(|(id, _)| self.item_context[id].module == module)
                .map(|(_, info)| info.declaration.name.text.as_str())
                .filter(|name| *name != "Self")
                .collect();
            if required != given {
                self.error(
                    "trait implementation must define exactly its associated types",
                    span,
                );
            }
            for parent in parents {
                if let Some(ResolvedTarget::Module(parent_id)) = self.target(parent.span)
                    && !self
                        .implementations
                        .contains_key(&(*parent_id, ty.clone()))
                {
                    self.error("implementation is missing its parent trait", span);
                }
            }
            let abstract_methods: Vec<_> = self
                .functions
                .iter()
                .filter(|(_, info)| info.context.module == trait_id)
                .map(|(&id, &info)| (id, info))
                .collect();
            let concrete_methods: Vec<_> = self
                .functions
                .iter()
                .filter(|(_, info)| info.context.module == module)
                .map(|(&id, &info)| (id, info))
                .collect();
            if abstract_methods.len() != concrete_methods.len() {
                self.error(
                    "trait implementation must define exactly its required methods",
                    span,
                );
            }
            for (_, declaration) in abstract_methods {
                let Some((method, _)) = concrete_methods.iter().find(|(_, info)| {
                    info.declaration.name.text == declaration.declaration.name.text
                }) else {
                    self.error(
                        format!(
                            "trait implementation is missing method `{}`",
                            declaration.declaration.name.text
                        ),
                        span,
                    );
                    continue;
                };
                if declaration.declaration.type_parameters.len() != 1
                    || !self.functions[method]
                        .declaration
                        .type_parameters
                        .is_empty()
                {
                    self.error(
                        "static trait methods do not support method type parameters",
                        span,
                    );
                    continue;
                }
                let self_id = self
                    .local_id(
                        declaration.declaration.type_parameters[0]
                            .name
                            .span,
                    )
                    .expect("Self parameter");
                let substitutions = BTreeMap::from([(self_id, ty.clone())]);
                let parameters: Vec<_> = declaration
                    .declaration
                    .parameters
                    .iter()
                    .map(|parameter| self.resolve_type(&parameter.ty, &substitutions, 0))
                    .collect();
                let result = declaration
                    .declaration
                    .result
                    .as_ref()
                    .map_or(Ty::Unit, |result| {
                        self.resolve_type(result, &substitutions, 0)
                    });
                let (actual_parameters, actual_result) = self.function_types[method].clone();
                if parameters != actual_parameters || result != actual_result {
                    self.error(
                        "trait method signature differs from its contract",
                        self.functions[method].declaration.name.span,
                    );
                }
            }
        }
    }

    pub(super) fn check_trait_call(
        &mut self,
        trait_id: ModuleId,
        name: &str,
        arguments: &[Expression],
        context: Context,
        span: Span,
        elaboration: &mut Option<Elaboration>,
    ) -> Ty {
        let Some(receiver) = arguments.first() else {
            self.error("static trait dispatch requires a receiver", span);
            return Ty::Error;
        };
        let receiver_ty = self.check_expr(receiver, None, context, true);
        let Some(&module) = self
            .implementations
            .get(&(trait_id, receiver_ty.clone()))
        else {
            self.error(
                "receiver does not implement the selected trait",
                span,
            );
            return Ty::Error;
        };
        let Some(method) = self
            .functions
            .iter()
            .find(|(_, info)| info.context.module == module && info.declaration.name.text == name)
            .map(|(&id, _)| id)
        else {
            self.error("missing static trait method", span);
            return Ty::Error;
        };
        let (parameters, result) = self.function_types[&method].clone();
        if let Some(want) = parameters.first() {
            self.expect_same(
                want,
                &receiver_ty,
                receiver.span,
                "trait receiver",
            );
        }
        self.check_arguments(
            &arguments[1..],
            &parameters[parameters.len().min(1)..],
            context,
            span,
        );
        *elaboration = Some(Elaboration::TraitCall {
            implementation: method,
        });
        result
    }

    pub(super) fn bounded_method(
        &mut self,
        local: LocalId,
        name: &str,
        span: Span,
    ) -> Option<ModuleId> {
        let roots = self
            .type_bounds
            .get(&local)
            .cloned()
            .unwrap_or_default();
        let candidates: Vec<_> = self
            .trait_closure(&roots, span)
            .into_iter()
            .filter(|module| {
                self.functions.values().any(|info| {
                    info.context.module == *module && info.declaration.name.text == name
                })
            })
            .collect();
        if let [trait_id] = candidates.as_slice() {
            Some(*trait_id)
        } else {
            self.error("unknown or ambiguous bounded trait method", span);
            None
        }
    }

    pub(super) fn check_method_call(
        &mut self,
        receiver: &Expression,
        method: &crate::syntax::Ident,
        arguments: &[Expression],
        expected: Option<&Ty>,
        context: Context,
        elaboration: &mut Option<Elaboration>,
    ) -> Ty {
        if matches!(
            self.target(method.span),
            Some(ResolvedTarget::Item(_))
        ) {
            let callee = crate::syntax::Path {
                segments: vec![method.clone()],
                span: method.span,
            };
            return self.check_call(&callee, arguments, expected, context, elaboration);
        }
        let receiver_ty = self.check_expr(receiver, None, context, false);
        let modules = self
            .methods
            .get(&receiver_ty)
            .cloned()
            .unwrap_or_default();
        let mut candidates = Vec::new();
        let functions: Vec<_> = self
            .functions
            .iter()
            .map(|(&id, &info)| (id, info))
            .collect();
        for (id, info) in functions {
            if !self.charge(method.span) {
                return Ty::Error;
            }
            if modules.contains(&info.context.module) && info.declaration.name.text == method.text {
                candidates.push(id);
            }
        }
        if let [function] = candidates.as_slice() {
            let mut arguments = arguments.to_vec();
            arguments.insert(0, receiver.clone());
            let (parameters, mut result) = self.function_types[function].clone();
            if self.functions[function].declaration.is_static()
                || self.functions[function].declaration.has_bounds()
            {
                result = self.check_static_call(
                    *function,
                    &arguments,
                    context,
                    method.span,
                    elaboration,
                );
            } else {
                self.check_arguments(&arguments, &parameters, context, method.span);
                *elaboration = Some(Elaboration::TraitCall {
                    implementation: *function,
                });
            }
            self.record_field(
                method.span,
                self.functions[function].declaration.name.span,
                &Ty::Function {
                    parameters,
                    result: Box::new(result.clone()),
                    once: false,
                },
            );
            return result;
        }
        if !candidates.is_empty() {
            self.error("ambiguous type method", method.span);
            return Ty::Error;
        }
        let callback = self.project(&receiver_ty, &method.text, context, method.span);
        if let Ty::Function {
            parameters,
            result,
            ..
        } = callback
        {
            // Calling a stored closure consumes the same receiver as an explicit
            // field projection. Method lookup above only borrowed its type.
            self.check_expr(receiver, None, context, true);
            self.check_arguments(arguments, &parameters, context, method.span);
            *result
        } else {
            self.error("method or callable field is absent", method.span);
            Ty::Error
        }
    }
}
