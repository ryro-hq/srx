//! Branch checking shares the same affine bindings and budgets as ordinary bodies.

use super::{
    BTreeSet, Checker, Context, Expression, Literal, MatchArm, Pattern, Primitive,
    ResolvedItemKind, Span, Ty,
};

impl Checker<'_> {
    pub(super) fn boolean_type(&mut self, span: Span) -> Ty {
        // The standard Bool is nominal; arbitrary two-case enums are not booleans.
        let item = self.enums.keys().copied().find(|id| {
            self.program.item(*id).is_some_and(|item| {
                item.domain() == crate::source::SourceDomainId::standard_library()
                    && item.path().segments() == ["std", "Bool"]
            })
        });
        item.map_or_else(
            || {
                self.error("boolean expressions require std::Bool", span);
                Ty::Error
            },
            Ty::Nominal,
        )
    }

    pub(super) fn check_equality(
        &mut self,
        left: &Expression,
        right: &Expression,
        context: Context,
    ) -> Ty {
        let ty = self.check_expr(left, None, context, true);
        let other = self.check_expr(right, Some(&ty), context, true);
        self.expect_same(&ty, &other, right.span, "equality operand");
        let boolean = self.boolean_type(left.span);
        if !self.literal_match_type(&ty) && ty != boolean && ty != Ty::Error {
            self.error(
                "equality requires reusable strings, integers or booleans",
                left.span,
            );
        }
        boolean
    }

    pub(super) fn check_if(
        &mut self,
        condition: &Expression,
        branches: &[Box<Expression>; 2],
        expected: Option<&Ty>,
        context: Context,
    ) -> Ty {
        let boolean = self.boolean_type(condition.span);
        let condition_ty = self.check_expr(condition, Some(&boolean), context, true);
        self.expect_same(
            &boolean,
            &condition_ty,
            condition.span,
            "if condition",
        );
        if self.static_mode
            && let Some(super::Constant::Boolean(value)) = self.constant_value(condition, 0)
        {
            return self.check_expr(
                &branches[usize::from(!value)],
                expected,
                context,
                true,
            );
        }
        let baseline = self.body.bindings.clone();
        let mut merged = baseline.clone();
        let mut result = expected.cloned();
        for (index, branch) in branches.iter().enumerate() {
            for _ in baseline.values() {
                if !self.charge(branch.span) {
                    return Ty::Error;
                }
            }
            self.body.bindings = baseline.clone();
            let ty = self.check_expr(branch, result.as_ref(), context, true);
            if let Some(want) = &result {
                self.expect_same(want, &ty, branch.span, "if branch");
            } else {
                result = Some(ty);
            }
            self.join_branch(&mut merged, index == 0);
        }
        self.body.bindings = merged;
        result.unwrap_or(Ty::Error)
    }

    pub(super) fn literal_match_type(&self, ty: &Ty) -> bool {
        matches!(ty, Ty::Str | Ty::Int)
            || matches!(ty, Ty::Nominal(id) if self.item_kind(*id) == Some(ResolvedItemKind::Value) && self.primitives.contains_key(id))
    }

    pub(super) fn check_literal_match(
        &mut self,
        ty: &Ty,
        value: &Expression,
        arms: &[MatchArm],
        expected: Option<&Ty>,
        context: Context,
    ) -> Ty {
        if self.static_mode
            && let Some(constant) = self.constant_value(value, 0)
        {
            for arm in arms {
                if !self.charge(arm.span) {
                    return Ty::Error;
                }
                if self.static_pattern_matches(&arm.pattern, &constant, arm.span) {
                    return self.check_expr(&arm.value, expected, context, true);
                }
            }
            self.error(
                "static match has no applicable case",
                *self.static_calls.last().expect("static call"),
            );
            return Ty::Error;
        }
        let primitive = match ty {
            Ty::Int => Primitive::Int,
            Ty::Str => Primitive::Str,
            Ty::Nominal(id) => self.primitives[id].declaration.primitive,
            _ => return Ty::Error,
        };
        let baseline = self.body.bindings.clone();
        let mut merged = baseline.clone();
        let mut seen = BTreeSet::new();
        let mut wildcard = false;
        let mut result = expected.cloned();
        for (index, arm) in arms.iter().enumerate() {
            if !self.charge(arm.span) {
                return Ty::Error;
            }
            if wildcard {
                self.error(
                    "match arm is unreachable after wildcard",
                    arm.span,
                );
            }
            match &arm.pattern {
                Pattern::Wildcard(_) => wildcard = true,
                Pattern::Literal(literal) => {
                    let key = match literal {
                        Literal::Integer(integer) if primitive == Primitive::Int => {
                            Some(integer.value.to_string())
                        }
                        Literal::String(string) if primitive == Primitive::Str => self
                            .string_constant(&Expression {
                                span: string.span,
                                kind: super::ExpressionKind::String(string.clone()),
                            })
                            .map(|text| text.to_string()),
                        _ => {
                            self.error(
                                "literal pattern type differs from match value",
                                arm.span,
                            );
                            None
                        }
                    };
                    if let Some(key) = key
                        && !seen.insert(key)
                    {
                        self.error("literal is covered more than once", arm.span);
                    }
                }
                _ => self.error(
                    "string and integer matches require literal patterns or `_`",
                    arm.span,
                ),
            }
            for _ in baseline.values() {
                if !self.charge(arm.span) {
                    return Ty::Error;
                }
            }
            self.body.bindings = baseline.clone();
            let actual = self.check_expr(&arm.value, result.as_ref(), context, true);
            if let Some(want) = &result {
                self.expect_same(want, &actual, arm.value.span, "match arm");
            } else {
                result = Some(actual);
            }
            self.join_branch(&mut merged, index == 0);
        }
        self.body.bindings = merged;
        if !wildcard {
            self.error(
                "match is not exhaustive; string and integer matches require `_`",
                value.span,
            );
        }
        result.unwrap_or(Ty::Error)
    }
}
