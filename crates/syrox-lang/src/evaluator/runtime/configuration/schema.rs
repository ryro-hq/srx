use super::super::{CanonicalType, ResolvedTarget};
use super::{
    BTreeMap, BTreeSet, Eval, Evaluator, Halt, ItemId, LocalId, PrimitiveValue, Span, Ty, Value,
};
use crate::{
    source::SourceDomainId,
    syntax::{Primitive, Type, TypeKind},
};
use serde_json::{Map, Value as Data};
use std::mem::size_of;

impl Evaluator<'_> {
    pub(super) fn validate_config_schema(
        &mut self,
        schema: &Ty,
        span: Span,
        depth: usize,
        seen: &mut BTreeSet<Ty>,
    ) -> Eval<()> {
        self.tick(span)?;
        if depth >= self.limits.max_depth {
            return self.fail(span, "configuration schema nesting limit reached");
        }
        self.expand(size_of::<Ty>(), span)?;
        if !seen.insert(schema.clone()) {
            return Ok(());
        }
        match schema {
            Ty::Int | Ty::Str => return Ok(()),
            Ty::List(inner) => return self.validate_config_schema(inner, span, depth + 1, seen),
            _ => {}
        }
        let Some(item) = schema.nominal_head() else {
            return self.fail(
                span,
                "functions and resources are not configuration data",
            );
        };
        if let Some(primitive) = self.index.primitives.get(&item) {
            return if primitive.resource {
                self.fail(span, "resources are not configuration data")
            } else {
                Ok(())
            };
        }
        if self.config_std(item, &["std", "Bool"]) {
            return Ok(());
        }
        if self.config_std(item, &["std", "option", "Option"])
            || self.config_std(item, &["std", "maps", "OrderedMap"])
        {
            let Ty::Specialization {
                arguments,
                ..
            } = schema
            else {
                return self.fail(span, "configuration type arguments are missing");
            };
            for argument in arguments {
                self.validate_config_schema(argument, span, depth + 1, seen)?;
            }
            return Ok(());
        }
        let Some(declaration) = self.index.structures.get(&item).copied() else {
            return self.fail(span, "type is not configuration data");
        };
        if self.config_std(item, &["std", "pkg", "Recipe"])
            || declaration.opaque
            || !declaration.scopes.is_empty()
        {
            return self.fail(
                span,
                "recipes, opaque values and resources are not configuration data",
            );
        }
        let substitutions =
            self.specialization_substitutions(item, schema, &BTreeMap::new(), span)?;
        for field in &declaration.fields {
            let ty = self.config_type(&field.ty, &substitutions, 0)?;
            self.validate_config_schema(&ty, field.span, depth + 1, seen)?;
        }
        Ok(())
    }

    pub(super) fn config_head(&self, ty: &CanonicalType) -> Option<ItemId> {
        let identity = match ty {
            CanonicalType::Nominal(id) => id,
            CanonicalType::Specialization {
                template,
                ..
            } => template,
            _ => return None,
        };
        self.index.item_for_identity(identity)
    }

    pub(super) fn config_data(&mut self, value: &Value, span: Span, depth: usize) -> Eval<Data> {
        self.tick(span)?;
        if depth >= self.limits.max_depth {
            return self.fail(span, "configuration nesting limit reached");
        }
        match value {
            Value::Int(value)
            | Value::Nominal {
                value: PrimitiveValue::Int(value),
                resource: false,
                ..
            } => Ok(Data::from(*value)),
            Value::Str(value)
            | Value::Nominal {
                value: PrimitiveValue::Str(value),
                resource: false,
                ..
            } => {
                self.expand(value.len(), span)?;
                Ok(Data::String(value.clone()))
            }
            Value::List {
                items,
                ..
            } => {
                let mut data = Vec::new();
                for item in items {
                    data.push(self.config_data(item, span, depth + 1)?);
                }
                Ok(Data::Array(data))
            }
            Value::Struct {
                ty,
                fields,
                ..
            } => {
                let item = self.config_head(ty).ok_or(Halt)?;
                let id = self.index.identity(item).ok_or(Halt)?;
                if id.domain() == SourceDomainId::standard_library()
                    && id.path().iter().any(|p| p == "OrderedMap")
                {
                    let Some((
                        _,
                        Value::List {
                            items,
                            ..
                        },
                    )) = fields.first()
                    else {
                        return self.fail(span, "invalid map");
                    };
                    let mut result = Map::new();
                    for entry in items {
                        let Value::Variant {
                            payload,
                            ..
                        } = entry
                        else {
                            return self.fail(span, "invalid map entry");
                        };
                        let [
                            Value::Nominal {
                                value: PrimitiveValue::Str(key),
                                ..
                            },
                            value,
                        ] = payload.as_slice()
                        else {
                            return self.fail(span, "invalid map entry");
                        };
                        if result
                            .insert(
                                key.clone(),
                                self.config_data(value, span, depth + 1)?,
                            )
                            .is_some()
                        {
                            return self.fail(span, "duplicate map key");
                        }
                    }
                    return Ok(Data::Object(result));
                }
                let declaration = self.index.structures[&item];
                if self.config_std(item, &["std", "pkg", "Recipe"])
                    || declaration.opaque
                    || !declaration.scopes.is_empty()
                {
                    return self.fail(
                        span,
                        "opaque values and resources are not configuration data",
                    );
                }
                let mut data = Map::new();
                for (name, value) in fields {
                    let field = declaration
                        .fields
                        .iter()
                        .find(|f| &f.name.text == name)
                        .ok_or(Halt)?;
                    let data_value = self.config_data(value, span, depth + 1)?;
                    data.insert(
                        field.key.as_ref().unwrap_or(name).clone(),
                        data_value,
                    );
                }
                Ok(Data::Object(data))
            }
            Value::Variant {
                ty,
                index,
                payload,
            } => {
                let item = self.config_head(ty).ok_or(Halt)?;
                if self.config_std(item, &["std", "Bool"]) {
                    return Ok(Data::Bool(*index == 1));
                }
                if self.config_std(item, &["std", "option", "Option"]) {
                    return match payload.first() {
                        Some(value) => self.config_data(value, span, depth + 1),
                        None => Ok(Data::Null),
                    };
                }
                self.fail(
                    span,
                    "only Bool and Option enums are configuration data",
                )
            }
            _ => self.fail(
                span,
                "functions, recipes and resources are not configuration data",
            ),
        }
    }

    pub(super) fn config_std(&self, item: ItemId, path: &[&str]) -> bool {
        self.index.identity(item).is_some_and(|id| {
            id.domain() == SourceDomainId::standard_library()
                && id
                    .path()
                    .iter()
                    .map(String::as_str)
                    .eq(path.iter().copied())
        })
    }

    pub(super) fn config_type(
        &mut self,
        syntax: &Type,
        substitutions: &BTreeMap<LocalId, Ty>,
        depth: usize,
    ) -> Eval<Ty> {
        self.tick(syntax.span)?;
        if depth >= self.limits.max_depth {
            return self.fail(
                syntax.span,
                "configuration type nesting limit reached",
            );
        }
        match &syntax.kind {
            TypeKind::List(inner) => Ok(Ty::List(Box::new(self.config_type(
                inner,
                substitutions,
                depth + 1,
            )?))),
            TypeKind::Named {
                path,
                arguments,
            } => {
                if path.segments.len() == 1 {
                    match path.segments[0].text.as_str() {
                        "str" => return Ok(Ty::Str),
                        "int" => return Ok(Ty::Int),
                        _ => {}
                    }
                }
                match self.index.target(path.span).cloned() {
                    Some(ResolvedTarget::Local(local)) => {
                        substitutions.get(&local).cloned().ok_or(Halt)
                    }
                    Some(ResolvedTarget::Item(item)) => {
                        let arguments = arguments
                            .iter()
                            .map(|a| self.config_type(a, substitutions, depth + 1))
                            .collect::<Eval<Vec<_>>>()?;
                        if let Some(alias) = self.index.aliases.get(&item).copied() {
                            let mut bindings = BTreeMap::new();
                            for (p, a) in alias.type_parameters.iter().zip(arguments) {
                                bindings.insert(self.index.local(p.name.span).ok_or(Halt)?, a);
                            }
                            self.config_type(&alias.ty, &bindings, depth + 1)
                        } else if arguments.is_empty() {
                            Ok(Ty::Nominal(item))
                        } else {
                            Ok(Ty::Specialization {
                                template: item,
                                arguments,
                            })
                        }
                    }
                    _ => self.fail(
                        syntax.span,
                        "configuration field type is unavailable",
                    ),
                }
            }
            TypeKind::Function {
                ..
            } => self.fail(
                syntax.span,
                "function types are not configuration data",
            ),
        }
    }

    pub(super) fn config_value(
        &mut self,
        schema: &Ty,
        data: &Data,
        open: bool,
        path: &str,
        span: Span,
        depth: usize,
    ) -> Eval<Value> {
        self.tick(span)?;
        self.expand(size_of::<Value>(), span)?;
        if depth >= self.limits.max_depth {
            return self.fail(
                span,
                format!("{path}: configuration nesting limit reached"),
            );
        }
        if data
            .as_object()
            .is_some_and(|object| object.contains_key("\0unsupported-config-value"))
        {
            return self.fail(
                span,
                format!("{path}: unsupported typed configuration value"),
            );
        }
        match (schema, data) {
            (Ty::Int, Data::Number(number)) if number.as_i64().is_some() => {
                return Ok(Value::Int(number.as_i64().unwrap()));
            }
            (Ty::Str, Data::String(text)) => {
                self.expand(text.len(), span)?;
                return Ok(Value::Str(text.clone()));
            }
            (Ty::List(inner), Data::Array(items)) => {
                let mut values = Vec::new();
                for (index, data) in items.iter().enumerate() {
                    values.push(self.config_value(
                        inner,
                        data,
                        open,
                        &format!("{path}[{index}]"),
                        span,
                        depth + 1,
                    )?);
                }
                return Ok(Value::List {
                    ty: self.canonical_ty(schema, &BTreeMap::new(), span)?,
                    items: values,
                });
            }
            _ => {}
        }
        let Some(item) = schema.nominal_head() else {
            return self.fail(span, format!("{path}: expected {schema:?}"));
        };
        if let Some(info) = self.index.primitives.get(&item) {
            if info.resource {
                return self.fail(
                    span,
                    format!("{path}: resources are not configuration data"),
                );
            }
            let primitive = match (info.declaration.primitive, data) {
                (Primitive::Int, Data::Number(n)) if n.as_i64().is_some() => {
                    PrimitiveValue::Int(n.as_i64().unwrap())
                }
                (Primitive::Str, Data::String(s)) => {
                    self.expand(s.len(), span)?;
                    PrimitiveValue::Str(s.clone())
                }
                _ => {
                    return self.fail(
                        span,
                        format!("{path}: incompatible configuration value"),
                    );
                }
            };
            let start = self.diagnostics.len();
            let value = self.construct_primitive(item, primitive, span, true);
            for diagnostic in &mut self.diagnostics[start..] {
                diagnostic.message = format!("{path}: {}", diagnostic.message);
            }
            return value;
        }
        let canonical = self.canonical_ty(schema, &BTreeMap::new(), span)?;
        if self.config_std(item, &["std", "Bool"]) {
            let Some(value) = data.as_bool() else {
                return self.fail(span, format!("{path}: expected boolean"));
            };
            return Ok(Value::Variant {
                ty: canonical,
                index: u32::from(value),
                payload: Vec::new(),
            });
        }
        if self.config_std(item, &["std", "option", "Option"]) {
            let Ty::Specialization {
                arguments,
                ..
            } = schema
            else {
                return Err(Halt);
            };
            return if data.is_null() {
                Ok(Value::Variant {
                    ty: canonical,
                    index: 0,
                    payload: Vec::new(),
                })
            } else {
                let value = self.config_value(&arguments[0], data, open, path, span, depth + 1)?;
                Ok(Value::Variant {
                    ty: canonical,
                    index: 1,
                    payload: vec![value],
                })
            };
        }
        let Some(declaration) = self.index.structures.get(&item).copied() else {
            return self.fail(
                span,
                format!("{path}: type is not configuration data"),
            );
        };
        if self.config_std(item, &["std", "maps", "OrderedMap"]) {
            return self.config_map(schema, data, open, path, span, depth);
        }
        if self.config_std(item, &["std", "pkg", "Recipe"])
            || declaration.opaque
            || !declaration.scopes.is_empty()
        {
            return self.fail(
                span,
                format!("{path}: opaque values and resources are not configuration data"),
            );
        }
        let Some(data) = data.as_object() else {
            return self.fail(span, format!("{path}: expected record"));
        };
        let substitutions =
            self.specialization_substitutions(item, schema, &BTreeMap::new(), span)?;
        if !open {
            for key in data.keys() {
                if !declaration
                    .fields
                    .iter()
                    .any(|f| f.key.as_ref().unwrap_or(&f.name.text) == key)
                {
                    return self.fail(
                        span,
                        format!("{path}.{key}: unknown configuration field"),
                    );
                }
            }
        }
        let mut fields = Vec::new();
        for field in &declaration.fields {
            let key = field.key.as_ref().unwrap_or(&field.name.text);
            let field_path = format!("{path}.{key}");
            let ty = self.config_type(&field.ty, &substitutions, 0)?;
            let value = if let Some(data) = data.get(key) {
                self.config_value(&ty, data, open, &field_path, span, depth + 1)?
            } else if let Some(default) = &field.default {
                self.expression(default, &substitutions)?
            } else if ty
                .nominal_head()
                .is_some_and(|i| self.config_std(i, &["std", "option", "Option"]))
            {
                self.config_value(
                    &ty,
                    &Data::Null,
                    open,
                    &field_path,
                    span,
                    depth + 1,
                )?
            } else {
                return self.fail(
                    span,
                    format!("{field_path}: missing configuration field"),
                );
            };
            fields.push((field.name.text.clone(), value));
        }
        Ok(Value::Struct {
            ty: canonical,
            fields,
            owner: Some(self.project_context),
        })
    }

    pub(super) fn config_map(
        &mut self,
        schema: &Ty,
        data: &Data,
        open: bool,
        path: &str,
        span: Span,
        depth: usize,
    ) -> Eval<Value> {
        let Ty::Specialization {
            template,
            arguments,
        } = schema
        else {
            return Err(Halt);
        };
        let Some(entries) = data.as_object() else {
            return self.fail(span, format!("{path}: expected map"));
        };
        let declaration = self.index.structures[template];
        let substitutions =
            self.specialization_substitutions(*template, schema, &BTreeMap::new(), span)?;
        let entries_type = self.config_type(&declaration.fields[0].ty, &substitutions, 0)?;
        let Ty::List(entry_type) = &entries_type else {
            return Err(Halt);
        };
        // MapKey is authenticated alongside OrderedMap.
        self.charge_steps(self.checked.resolved().items().len(), span)?;
        let key_item = self
            .checked
            .resolved()
            .items()
            .find(|item| {
                item.domain() == SourceDomainId::standard_library()
                    && item
                        .path()
                        .segments()
                        .iter()
                        .map(String::as_str)
                        .eq(["std", "maps", "MapKey"])
            })
            .map(crate::resolver::ResolvedItem::id)
            .ok_or(Halt)?;
        let mut items = Vec::new();
        for (key, data) in entries {
            let key = self.construct_primitive(
                key_item,
                PrimitiveValue::Str(key.clone()),
                span,
                true,
            )?;
            let value = self.config_value(&arguments[0], data, open, path, span, depth + 1)?;
            items.push(Value::Variant {
                ty: self.canonical_ty(entry_type, &BTreeMap::new(), span)?,
                index: 0,
                payload: vec![key, value],
            });
        }
        let entries = Value::List {
            ty: self.canonical_ty(&entries_type, &BTreeMap::new(), span)?,
            items,
        };
        Ok(Value::Struct {
            ty: self.canonical_ty(schema, &BTreeMap::new(), span)?,
            fields: vec![("entries".into(), entries)],
            owner: None,
        })
    }
}
