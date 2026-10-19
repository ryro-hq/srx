use super::{BTreeMap, Checker, Context, Elaboration, Expression, Span, Ty};
use crate::{resolver::ItemId, source::SourceDomainId, syntax::ExpressionKind};

impl Checker<'_> {
    pub(super) fn configuration_operation(&self, item: ItemId) -> Option<String> {
        let identity = self.item_identity(item);
        let path = identity.path();
        if identity.domain() == SourceDomainId::standard_library()
            && path.len() == 3
            && path[0] == "std"
            && matches!(path[1].as_str(), "yaml" | "toml")
        {
            Some(path[2].clone())
        } else {
            None
        }
    }

    pub(super) fn check_configuration_patch(
        &mut self,
        item: ItemId,
        arguments: &[Expression],
        context: Context,
        elaboration: &mut Option<Elaboration>,
        span: Span,
    ) -> Ty {
        let [document, changes] = arguments else {
            self.error(
                "patch expects a document and a partial record",
                span,
            );
            return Ty::Error;
        };
        let doc = self.check_expr(document, None, context, true);
        let Ty::Specialization {
            template,
            arguments,
        } = &doc
        else {
            self.error(
                "patch requires a typed configuration document",
                document.span,
            );
            return Ty::Error;
        };
        let operation = self.item_identity(item);
        let identity = self.item_identity(*template);
        if identity.path().len() != 3
            || identity.domain() != operation.domain()
            || identity.path()[..2] != operation.path()[..2]
            || identity.path().last().map(String::as_str) != Some("Document")
            || arguments.len() != 1
        {
            self.error(
                "patch requires a document of the same format",
                document.span,
            );
            return Ty::Error;
        }
        let target = &arguments[0];
        let previous = self.partial_record;
        let mut record = changes;
        while let ExpressionKind::Group(inner) = &record.kind {
            record = inner;
        }
        if let ExpressionKind::Struct {
            path,
            ..
        } = &record.kind
        {
            self.partial_record = Some(path.span);
        }
        let got = self.check_expr(changes, Some(target), context, true);
        self.partial_record = previous;
        self.expect_same(target, &got, changes.span, "configuration patch");
        let parameters = self.function_parameters(item);
        let substitutions: BTreeMap<_, _> = parameters
            .keys()
            .map(|p| (*p, target.clone()))
            .collect();
        *elaboration = Some(Elaboration::FunctionSpecialization {
            substitutions,
        });
        doc
    }
}
