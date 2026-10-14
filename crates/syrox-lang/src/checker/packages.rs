//! Compile-time selection of a catalog factory before configuration inference.

use super::{
    Checker, Context, Elaboration, Expression, ExpressionKind, ItemId, ResolvedTarget, StringPart,
    Ty,
};

impl Checker<'_> {
    pub(super) fn package_constant(&self, expression: &Expression) -> Option<std::sync::Arc<str>> {
        match &expression.kind {
            ExpressionKind::String(value) => {
                let mut result = String::new();
                for part in &value.parts {
                    let StringPart::Text {
                        source,
                        ..
                    } = part
                    else {
                        return None;
                    };
                    let mut chars = source.chars();
                    while let Some(ch) = chars.next() {
                        result.push(if ch == '\\' {
                            match chars.next()? {
                                'n' => '\n',
                                'r' => '\r',
                                't' => '\t',
                                ch @ ('"' | '\\' | '$') => ch,
                                _ => return None,
                            }
                        } else {
                            ch
                        });
                    }
                }
                Some(result.into())
            }
            ExpressionKind::Group(value) => self.package_constant(value),
            ExpressionKind::Path(path) => match self.target(path.span) {
                Some(ResolvedTarget::Local(local)) => {
                    self.body.bindings.get(local)?.constant.clone()
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub(super) fn check_package_selection(
        &mut self,
        default: ItemId,
        arguments: &[Expression],
        elaboration: &mut Option<Elaboration>,
        context: Context,
    ) -> Ty {
        let info = self.functions[&default];
        let identity = info
            .declaration
            .package
            .as_ref()
            .expect("package factory");
        let mut selected = identity
            .each_ref()
            .map(|literal| literal.source[1..literal.source.len() - 1].to_owned());
        let [argument] = arguments else {
            self.error(
                "package selection requires one attribute set",
                info.declaration.name.span,
            );
            return Ty::Error;
        };
        let ExpressionKind::Struct {
            path,
            fields,
            recovery,
            ..
        } = &argument.kind
        else {
            self.error(
                "package selection requires an attribute set",
                argument.span,
            );
            return Ty::Error;
        };
        if !path.segments.is_empty() || !recovery.is_empty() {
            return Ty::Error;
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut location = argument.span;
        for field in fields {
            if !seen.insert(&field.name.text) {
                self.error(
                    "duplicate package selection field",
                    field.name.span,
                );
            }
            let index = match field.name.text.as_str() {
                "version" => 1,
                "variant" => 2,
                "system" => 3,
                _ => {
                    self.error(
                        format!(
                            "unknown package selection field `{}`",
                            field.name.text
                        ),
                        field.name.span,
                    );
                    continue;
                }
            };
            let ty = self.check_expr(&field.value, Some(&Ty::Str), context, true);
            let string_value = matches!(&ty, Ty::Nominal(item) if self.item_kind(*item) == Some(super::ResolvedItemKind::Value) && self.primitives.get(item).is_some_and(|info| info.declaration.primitive == super::Primitive::Str));
            if !string_value {
                self.expect_same(
                    &Ty::Str,
                    &ty,
                    field.value.span,
                    "package identity",
                );
            }
            let Some(value) = self.package_constant(&field.value) else {
                self.error(
                    "package version, variant and system must be literals or constants",
                    field.value.span,
                );
                return Ty::Error;
            };
            if value.len() > 128
                || value.is_empty()
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                self.error(
                    "package identity is not a bounded literal component",
                    field.value.span,
                );
                return Ty::Error;
            }
            selected[index] = value.to_string();
            if index == 1 {
                location = field.value.span;
            }
        }
        let mut candidates = Vec::new();
        for (&item, candidate) in &self.functions {
            if candidate.context.domain != info.context.domain {
                continue;
            }
            let Some(identity) = &candidate.declaration.package else {
                continue;
            };
            if identity
                .iter()
                .zip(&selected)
                .all(|(literal, selected)| literal.source[1..literal.source.len() - 1] == *selected)
            {
                candidates.push(item);
            }
        }
        for _ in 0..self.functions.len() {
            if !self.charge(argument.span) {
                return Ty::Error;
            }
        }
        let [factory] = candidates.as_slice() else {
            self.error(
                format!(
                    "unknown or ambiguous package selection: {} {} ({}, {})",
                    selected[0], selected[1], selected[2], selected[3]
                ),
                location,
            );
            return Ty::Error;
        };
        if !self.functions[factory]
            .declaration
            .parameters
            .is_empty()
            || !self.function_parameters(*factory).is_empty()
        {
            self.error(
                "versioned package factories must have no parameters",
                location,
            );
            return Ty::Error;
        }
        *elaboration = Some(Elaboration::PackageSelection {
            factory: *factory,
        });
        self.function_types[factory].1.clone()
    }
}
