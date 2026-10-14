use super::{
    Block, Diagnostic, Enum, Field, Function, Ident, Input, Inputs, Item, ItemKind, Keyword,
    MAX_DIAGNOSTICS, Module, Output, OutputKind, Outputs, Parameter, Parser, Primitive,
    PrimitiveDeclaration, Refinement, RefinementKind, Span, Statement, StatementKind, Struct,
    SyntaxKind, Token, TokenKind, Type, TypeAlias, TypeKind, TypeParameter, Use,
};

impl Parser<'_> {
    pub(super) fn parse_items(&mut self, nested: bool) -> Vec<Item> {
        let mut items = Vec::new();
        let mut services = Vec::new();
        let mut service_span = None;
        while self.peek().is_some() && !(nested && self.at(TokenKind::RightBrace)) {
            if !nested
                && self.peek().is_some_and(|token| {
                    token.kind == TokenKind::Ident && self.text(token.span) == "services"
                })
            {
                if let Some((service, span)) = self.syntax(
                    SyntaxKind::Declaration,
                    Self::parse_service_configuration,
                ) {
                    service_span = Some(service_span.map_or(span, |start: Span| start.join(span)));
                    services.push(service);
                } else {
                    self.recover_item(self.at, nested);
                }
                continue;
            }
            // The lexer already diagnosed these tokens. Keep them in the
            // lossless stream without cascading an item error for each one.
            if self.at(TokenKind::Invalid) || self.at(TokenKind::Unparsed) {
                self.advance();
                continue;
            }
            let before = self.at;
            let item = self.syntax(SyntaxKind::Declaration, |parser| {
                let item = parser.parse_item();
                if item.is_none() {
                    parser.recover_item(before, nested);
                }
                item
            });
            if let Some(item) = item {
                items.push(item);
            }
            if self.at == before {
                self.advance();
            }
            if self.errors.len() == MAX_DIAGNOSTICS {
                break;
            }
        }
        if let Some(span) = service_span {
            items.push(Self::service_output(services, span));
        }
        items
    }

    fn generated_path(span: Span, segments: &[&str]) -> super::Path {
        super::Path {
            span,
            segments: segments
                .iter()
                .map(|text| Ident {
                    text: (*text).to_owned(),
                    span,
                })
                .collect(),
        }
    }

    fn parse_service_configuration(&mut self) -> Option<(super::Expression, Span)> {
        let start = self.advance()?.span;
        self.expect(
            TokenKind::Dot,
            "expected service name after `services`",
        )?;
        let name = self.ident("expected service name")?;
        self.expect(
            TokenKind::Equal,
            "expected `=` after service name",
        )?;
        let open = self.peek()?.span;
        let configuration = self.parse_struct_literal(
            super::Path {
                segments: Vec::new(),
                span: open,
            },
            Vec::new(),
        )?;
        let end = self
            .expect(
                TokenKind::Semicolon,
                "expected `;` after service configuration",
            )?
            .span;
        let super::ExpressionKind::Struct {
            fields,
            recovery,
            ..
        } = configuration.kind
        else {
            return None;
        };
        if !recovery.is_empty() {
            return None;
        }
        let point = |offset| {
            Span::new(
                start.source_id(),
                start.start() + offset,
                start.start() + offset + 1,
            )
        };
        let mut package = None;
        let mut settings = None;
        let mut enable = None;
        for field in fields {
            let slot = match field.name.text.as_str() {
                "package" => &mut package,
                "settings" => &mut settings,
                "enable" => &mut enable,
                _ => {
                    self.error(Diagnostic::error(
                        format!("unknown service option `{}`", field.name.text),
                        field.name.span,
                    ));
                    continue;
                }
            };
            if slot.is_some() {
                self.error(Diagnostic::error(
                    "duplicate service option",
                    field.name.span,
                ));
            }
            *slot = Some(field.value);
        }
        let Some(package) = package else {
            self.error(Diagnostic::error(
                "service requires a selected package",
                name.span,
            ));
            return None;
        };
        let settings = settings.unwrap_or(super::Expression {
            span: point(1),
            kind: super::ExpressionKind::Struct {
                path: super::Path {
                    segments: Vec::new(),
                    span: point(1),
                },
                type_arguments: Vec::new(),
                fields: Vec::new(),
                recovery: Vec::new(),
            },
        });
        let enable = enable.unwrap_or(super::Expression {
            span: point(0),
            kind: super::ExpressionKind::Path(Self::generated_path(
                point(0),
                &["std", "Bool", "True"],
            )),
        });
        let id = super::Expression {
            span: name.span,
            kind: super::ExpressionKind::String(super::StringLiteral {
                source: format!("\"{}\"", name.text),
                parts: vec![super::StringPart::Text {
                    source: name.text,
                    span: name.span,
                }],
                span: name.span,
            }),
        };
        Some((
            super::Expression {
                span: start.join(configuration.span),
                kind: super::ExpressionKind::Call {
                    callee: Self::generated_path(start, &["std", "package_service"]),
                    arguments: vec![package, settings, enable, id],
                },
            },
            start.join(end),
        ))
    }

    fn service_output(services: Vec<super::Expression>, span: Span) -> Item {
        let point = |offset| {
            Span::new(
                span.source_id(),
                span.start() + offset,
                span.start() + offset + 1,
            )
        };
        let fields = vec![
            super::StructField {
                name: Ident {
                    text: "pkgs".to_owned(),
                    span: point(2),
                },
                value: super::Expression {
                    span: point(2),
                    kind: super::ExpressionKind::List(Vec::new()),
                },
                span: point(2),
            },
            super::StructField {
                name: Ident {
                    text: "services".to_owned(),
                    span: point(3),
                },
                value: super::Expression {
                    span: point(3),
                    kind: super::ExpressionKind::List(services),
                },
                span: point(3),
            },
        ];
        Item {
            public: false,
            span,
            kind: ItemKind::Outputs(Outputs {
                entries: vec![Output {
                    span,
                    kind: OutputKind::Value {
                        name: Ident {
                            text: "os".to_owned(),
                            span: Span::new(span.source_id(), span.end(), span.end()),
                        },
                        ty: Type {
                            span: point(6),
                            kind: TypeKind::Named {
                                path: Self::generated_path(point(6), &["std", "Os"]),
                                arguments: Vec::new(),
                            },
                        },
                        value: super::Expression {
                            span,
                            kind: super::ExpressionKind::Struct {
                                path: Self::generated_path(point(5), &["std", "Os"]),
                                type_arguments: Vec::new(),
                                fields,
                                recovery: Vec::new(),
                            },
                        },
                    },
                }],
            }),
        }
    }

    pub(super) fn parse_item(&mut self) -> Option<Item> {
        let start_depth = self.depth;
        let diagnostics = self.errors.len();
        let item = self.parse_item_inner();
        self.depth = start_depth;
        if item.is_none() && self.errors.len() == diagnostics {
            self.error(Diagnostic::error(
                "incomplete declaration",
                self.peek()
                    .map_or_else(|| self.eof_span(), |token| token.span),
            ));
        }
        item
    }

    fn parse_item_inner(&mut self) -> Option<Item> {
        let token = self.advance()?;
        let public = token.kind == TokenKind::Keyword(Keyword::Pub);
        let declaration = if public {
            self.advance()?
        } else {
            token
        };
        let TokenKind::Keyword(keyword) = declaration.kind else {
            self.error(
                Diagnostic::error("expected a declaration", token.span).with_note(
                    "declarations start with mod, use, inputs, outputs, type, struct, opaque, enum, resource, value or fn",
                ),
            );
            return None;
        };
        if public
            && !matches!(
                keyword,
                Keyword::Fn
                    | Keyword::Struct
                    | Keyword::Type
                    | Keyword::Enum
                    | Keyword::Value
                    | Keyword::Resource
                    | Keyword::Opaque
                    | Keyword::Use
                    | Keyword::Publish
            )
        {
            self.error(Diagnostic::error(
                "`pub` requires a type, value, function or import declaration",
                declaration.span,
            ));
            return None;
        }
        let start = token.span;
        let (kind, end) = match keyword {
            Keyword::Mod => self.parse_module(start)?,
            Keyword::Use => self.parse_use(start)?,
            Keyword::Inputs => self.parse_inputs(start)?,
            Keyword::Outputs => self.parse_outputs(start)?,
            Keyword::Publish => {
                if !public || !self.module.is_empty() {
                    self.error(Diagnostic::error(
                        "publication requires top-level `pub publish`",
                        start,
                    ));
                    return None;
                }
                self.expect(
                    TokenKind::LeftParen,
                    "expected `(` after `publish`",
                )?;
                let namespace = self.parse_path("expected publication namespace")?;
                self.expect(
                    TokenKind::Comma,
                    "expected `,` after publication namespace",
                )?;
                let export = self.ident("expected published factory name")?;
                self.expect(
                    TokenKind::RightParen,
                    "expected `)` after publication factory",
                )?;
                self.expect(
                    TokenKind::Colon,
                    "expected `:` before publication result type",
                )?;
                let result = self.parse_type()?;
                let end = self.expect(
                    TokenKind::Semicolon,
                    "expected `;` after publication",
                )?;
                (
                    ItemKind::Publication(crate::syntax::Publication {
                        result,
                        namespace,
                        export,
                    }),
                    end.span,
                )
            }
            Keyword::Type => self.parse_type_alias(start)?,
            Keyword::Struct => self.parse_struct(start, false)?,
            Keyword::Opaque => {
                self.expect_keyword(
                    Keyword::Struct,
                    "expected `struct` after `opaque`",
                )?;
                self.parse_struct(start, true)?
            }
            Keyword::Enum => self.parse_enum(start)?,
            Keyword::Resource => self.parse_primitive_declaration(start, true)?,
            Keyword::Value => self.parse_primitive_declaration(start, false)?,
            Keyword::Fn => self.parse_function(start, public)?,
            _ => {
                self.error(Diagnostic::error("expected a declaration", start));
                return None;
            }
        };
        Some(Item {
            kind,
            public,
            span: start.join(end),
        })
    }

    fn parse_module(&mut self, start: Span) -> Option<(ItemKind, Span)> {
        let path = self.parse_path("expected module path")?;
        let open = self.expect(
            TokenKind::LeftBrace,
            "expected `{` after module path",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let mut child = self.module.to_vec();
        child.extend(
            path.segments
                .iter()
                .map(|segment| segment.text.clone()),
        );
        let parent = std::mem::replace(&mut self.module, child.into());
        let items = self.parse_items(true);
        self.module = parent;
        let close = self.expect(
            TokenKind::RightBrace,
            "expected `}` after module body",
        );
        self.leave();
        let end = close.map_or_else(|| self.eof_span(), |token| token.span);
        let _ = start;
        Some((
            ItemKind::Module(Module {
                path,
                items,
            }),
            end,
        ))
    }

    fn parse_use(&mut self, _start: Span) -> Option<(ItemKind, Span)> {
        let path = self.parse_path("expected import path")?;
        let names = if self.at(TokenKind::ColonColon)
            && self
                .peek_n(1)
                .is_some_and(|token| token.kind == TokenKind::LeftBrace)
        {
            self.advance();
            let open = self.advance()?;
            if !self.enter(open.span) {
                return None;
            }
            let names = self.comma_idents(TokenKind::RightBrace, false);
            let close = self.expect(
                TokenKind::RightBrace,
                "expected `}` after imported names",
            );
            self.leave();
            close?;
            Some(names?)
        } else {
            None
        };
        let end = self.expect(TokenKind::Semicolon, "expected `;` after import")?;
        Some((
            ItemKind::Use(Use {
                path,
                names,
            }),
            end.span,
        ))
    }

    fn parse_inputs(&mut self, _start: Span) -> Option<(ItemKind, Span)> {
        let open = self.expect(
            TokenKind::LeftBrace,
            "expected `{` after `inputs`",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let mut entries = Vec::new();
        while self.peek().is_some() && !self.at(TokenKind::RightBrace) {
            let name = self.ident("expected input name")?;
            self.expect(TokenKind::Equal, "expected `=` after input name")?;
            let value = self.string_literal()?;
            let end = self.expect(TokenKind::Semicolon, "expected `;` after input")?;
            entries.push(Input {
                span: name.span.join(end.span),
                name,
                value,
            });
        }
        let close = self.expect(TokenKind::RightBrace, "expected `}` after inputs");
        self.leave();
        let close = close?;
        Some((
            ItemKind::Inputs(Inputs {
                entries,
            }),
            close.span,
        ))
    }

    fn parse_outputs(&mut self, _start: Span) -> Option<(ItemKind, Span)> {
        let open = self.expect(
            TokenKind::LeftBrace,
            "expected `{` after `outputs`",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let (entries, valid) = self.semicolon_entries(SyntaxKind::Output, |parser| {
            let entry_start = parser.peek()?.span;
            let kind = if parser.consume_keyword(Keyword::Type).is_some() {
                let name = parser.ident("expected exported type name")?;
                parser.expect(
                    TokenKind::Equal,
                    "expected `=` after exported type name",
                )?;
                let ty = parser.parse_type()?;
                OutputKind::Type {
                    name,
                    ty,
                }
            } else {
                let name = parser.ident("expected output name")?;
                parser.expect(TokenKind::Colon, "expected `:` after output name")?;
                let ty = parser.parse_type()?;
                parser.expect(TokenKind::Equal, "expected `=` after output type")?;
                let value = parser.parse_expression()?;
                OutputKind::Value {
                    name,
                    ty,
                    value,
                }
            };
            let end = parser.expect(TokenKind::Semicolon, "expected `;` after output")?;
            Some(Output {
                kind,
                span: entry_start.join(end.span),
            })
        });
        let close = self.expect(
            TokenKind::RightBrace,
            "expected `}` after outputs",
        );
        self.leave();
        let close = close?;
        valid.then_some((
            ItemKind::Outputs(Outputs {
                entries,
            }),
            close.span,
        ))
    }

    fn parse_type_alias(&mut self, _start: Span) -> Option<(ItemKind, Span)> {
        let name = self.ident("expected type alias name")?;
        let type_parameters = if self.at(TokenKind::LeftAngle) {
            self.parse_type_parameters()?
        } else {
            Vec::new()
        };
        self.expect(
            TokenKind::Equal,
            "expected `=` after type alias name",
        )?;
        let ty = self.parse_type()?;
        let end = self.expect(
            TokenKind::Semicolon,
            "expected `;` after type alias",
        )?;
        Some((
            ItemKind::TypeAlias(TypeAlias {
                name,
                type_parameters,
                ty,
            }),
            end.span,
        ))
    }

    fn parse_struct(&mut self, _start: Span, opaque: bool) -> Option<(ItemKind, Span)> {
        let name = self.ident("expected struct name")?;
        let type_parameters = if self.at(TokenKind::LeftAngle) {
            self.parse_type_parameters()?
        } else {
            Vec::new()
        };
        let scopes = if self.consume_keyword(Keyword::In).is_some() {
            let open = self.expect(TokenKind::LeftBracket, "expected `[` after `in`")?;
            if !self.enter(open.span) {
                return None;
            }
            let scopes = self.comma_idents(TokenKind::RightBracket, true);
            let close = self.expect(
                TokenKind::RightBracket,
                "expected `]` after scopes",
            );
            self.leave();
            close?;
            scopes?
        } else {
            Vec::new()
        };
        let open = self.expect(
            TokenKind::LeftBrace,
            "expected `{` before struct fields",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let (fields, valid) = self.semicolon_entries(SyntaxKind::Field, |parser| {
            let field_start = parser.peek()?.span;
            let field_name = parser.ident("expected field name")?;
            parser.expect(TokenKind::Colon, "expected `:` after field name")?;
            let ty = parser.parse_type()?;
            let default = if parser.consume(TokenKind::Equal).is_some() {
                Some(parser.parse_expression()?)
            } else {
                None
            };
            let end = parser.expect(TokenKind::Semicolon, "expected `;` after field")?;
            Some(Field {
                name: field_name,
                ty,
                default,
                span: field_start.join(end.span),
            })
        });
        let close = self.expect(
            TokenKind::RightBrace,
            "expected `}` after struct fields",
        );
        self.leave();
        let close = close?;
        valid.then_some((
            ItemKind::Struct(Struct {
                name,
                opaque,
                type_parameters,
                scopes,
                fields,
            }),
            close.span,
        ))
    }

    fn parse_type_parameters(&mut self) -> Option<Vec<TypeParameter>> {
        let open = self.expect(TokenKind::LeftAngle, "expected `<`")?;
        if !self.enter(open.span) {
            return None;
        }
        let mut parameters = Vec::new();
        loop {
            let start = self.peek()?.span;
            let owner = self.consume_keyword(Keyword::Owner).is_some();
            let name = self.ident("expected type parameter")?;
            parameters.push(TypeParameter {
                span: start.join(name.span),
                name,
                owner,
            });
            if self.consume(TokenKind::Comma).is_none() {
                break;
            }
            if self.at(TokenKind::RightAngle) {
                self.error(Diagnostic::error(
                    "type parameter lists do not allow a trailing comma",
                    self.peek()?.span,
                ));
                break;
            }
        }
        let close = self.expect(
            TokenKind::RightAngle,
            "expected `>` after type parameters",
        );
        self.leave();
        close?;
        Some(parameters)
    }

    fn parse_enum(&mut self, _start: Span) -> Option<(ItemKind, Span)> {
        let name = self.ident("expected enum name")?;
        let type_parameters = if self.at(TokenKind::LeftAngle) {
            self.parse_type_parameters()?
        } else {
            Vec::new()
        };
        let open = self.expect(
            TokenKind::LeftBrace,
            "expected `{` before enum variants",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let mut variants = Vec::new();
        while !self.at(TokenKind::RightBrace) {
            let name = self.ident("expected enum variant name")?;
            let payload = if let Some(open) = self.consume(TokenKind::LeftParen) {
                if !self.enter(open.span) {
                    return None;
                }
                let payload = if self.at(TokenKind::RightParen) {
                    Some(Vec::new())
                } else {
                    self.comma_types(TokenKind::RightParen, true)
                };
                let close = self.expect(
                    TokenKind::RightParen,
                    "expected `)` after variant payload",
                );
                self.leave();
                close?;
                payload?
            } else {
                Vec::new()
            };
            variants.push(crate::syntax::EnumVariant {
                name,
                payload,
            });
            if self.consume(TokenKind::Comma).is_none() {
                break;
            }
        }
        let close = self.expect(
            TokenKind::RightBrace,
            "expected `}` after enum variants",
        );
        self.leave();
        let close = close?;
        Some((
            ItemKind::Enum(Enum {
                name,
                type_parameters,
                variants,
            }),
            close.span,
        ))
    }

    fn parse_primitive_declaration(
        &mut self,
        _start: Span,
        resource: bool,
    ) -> Option<(ItemKind, Span)> {
        let name = self.ident("expected declaration name")?;
        let open = self.expect(
            TokenKind::LeftParen,
            "expected `(` after declaration name",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let primitive = match self.advance()? {
            Token {
                kind: TokenKind::Keyword(Keyword::Int),
                ..
            } => Primitive::Int,
            Token {
                kind: TokenKind::Keyword(Keyword::Str),
                ..
            } => Primitive::Str,
            token => {
                self.error(Diagnostic::error(
                    "expected primitive `int` or `str`",
                    token.span,
                ));
                self.leave();
                return None;
            }
        };
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after primitive",
        );
        self.leave();
        close?;
        let scope = if self.consume_keyword(Keyword::In).is_some() {
            Some(self.ident("expected scope name after `in`")?)
        } else {
            None
        };
        let mut refinements = Vec::new();
        if self.consume_keyword(Keyword::Where).is_some() {
            refinements.push(self.parse_refinement()?);
            while self.consume(TokenKind::Comma).is_some() {
                refinements.push(self.parse_refinement()?);
            }
        }
        let end = self.expect(
            TokenKind::Semicolon,
            "expected `;` after declaration",
        )?;
        let declaration = PrimitiveDeclaration {
            name,
            primitive,
            scope,
            refinements,
        };
        let kind = if resource {
            ItemKind::Resource(declaration)
        } else {
            ItemKind::Value(declaration)
        };
        Some((kind, end.span))
    }

    fn parse_refinement(&mut self) -> Option<Refinement> {
        let start = self.peek()?.span;
        if self.at(TokenKind::Integer) {
            let range_start = self.integer_literal()?;
            let inclusive = match self.advance()? {
                Token {
                    kind: TokenKind::DotDot,
                    ..
                } => false,
                Token {
                    kind: TokenKind::DotDotEqual,
                    ..
                } => true,
                token => {
                    self.error(Diagnostic::error(
                        "expected `..` or `..=` in range",
                        token.span,
                    ));
                    return None;
                }
            };
            let end = self.integer_literal()?;
            return Some(Refinement {
                span: start.join(end.span),
                kind: RefinementKind::Range {
                    start: range_start,
                    end,
                    inclusive,
                },
            });
        }
        if self.consume_keyword(Keyword::In).is_some() {
            let open = self.expect(TokenKind::LeftBracket, "expected `[` after `in`")?;
            if !self.enter(open.span) {
                return None;
            }
            let mut values = Vec::new();
            loop {
                values.push(self.parse_literal()?);
                if self.consume(TokenKind::Comma).is_none() || self.at(TokenKind::RightBracket) {
                    break;
                }
            }
            let close = self.expect(
                TokenKind::RightBracket,
                "expected `]` after refinement set",
            );
            self.leave();
            let close = close?;
            return Some(Refinement {
                kind: RefinementKind::Set(values),
                span: start.join(close.span),
            });
        }
        let path = self.parse_path("expected refinement")?;
        self.expect(
            TokenKind::LeftParen,
            "expected `(` after refinement predicate",
        )?;
        self.expect_keyword(
            Keyword::SelfValue,
            "expected `self` in refinement predicate",
        )?;
        let close = self.expect(TokenKind::RightParen, "expected `)` after `self`")?;
        Some(Refinement {
            kind: RefinementKind::Predicate(path),
            span: start.join(close.span),
        })
    }

    fn parse_function(&mut self, start: Span, public: bool) -> Option<(ItemKind, Span)> {
        let name = self.ident("expected function name")?;
        let type_parameters = if self.at(TokenKind::LeftAngle) {
            self.parse_type_parameters()?
        } else {
            Vec::new()
        };
        let open = self.expect(
            TokenKind::LeftParen,
            "expected `(` after function name",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let mut parameters = Vec::new();
        if !self.at(TokenKind::RightParen) {
            loop {
                let parameter_start = self.peek()?.span;
                let parameter_name = self.ident("expected parameter name")?;
                self.expect(
                    TokenKind::Colon,
                    "expected `:` after parameter name",
                )?;
                let ty = self.parse_type()?;
                parameters.push(Parameter {
                    span: parameter_start.join(ty.span),
                    name: parameter_name,
                    ty,
                });
                if self.consume(TokenKind::Comma).is_none() || self.at(TokenKind::RightParen) {
                    break;
                }
            }
        }
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after parameters",
        );
        self.leave();
        close?;
        let result = if self.consume(TokenKind::Arrow).is_some() {
            Some(self.parse_type()?)
        } else {
            None
        };
        self.signatures.push(super::FunctionSignature {
            module: self.module.clone(),
            public,
            name: name.clone(),
            type_parameters: type_parameters.clone(),
            parameters: parameters.clone(),
            result: result.clone(),
            span: start.join(self.tokens[self.at - 1].span),
        });
        let body_at = self.at;
        let package = if self.peek().is_some_and(|token| {
            token.kind == TokenKind::Ident && self.text(token.span) == "package"
        }) {
            self.advance();
            self.expect(
                TokenKind::LeftParen,
                "expected package identity tuple",
            )?;
            let mut identity = Vec::new();
            for index in 0..4 {
                if index > 0 {
                    self.expect(
                        TokenKind::Comma,
                        "expected `,` in package identity",
                    )?;
                }
                let literal = self.string_literal()?;
                if literal
                    .parts
                    .iter()
                    .any(|part| !matches!(part, super::StringPart::Text { .. }))
                {
                    self.error(Diagnostic::error(
                        "package identity must be literal",
                        literal.span,
                    ));
                }
                identity.push(literal);
            }
            self.expect(
                TokenKind::RightParen,
                "expected `)` after package identity",
            )?;
            Some(Box::new(identity.try_into().ok()?))
        } else {
            None
        };
        let body = if let Some(body) = self.parse_block() {
            body
        } else {
            self.incomplete_bodies.push(name.span);
            if self
                .tokens
                .get(body_at)
                .is_some_and(|token| token.kind == TokenKind::LeftBrace)
            {
                self.recover_item(body_at, true);
            }
            Block {
                incomplete: true,
                statements: Vec::new(),
                tail: None,
                // Retain the recovered body's lexical extent for editor scope
                // queries. `incomplete_bodies` still marks this AST unavailable.
                span: if self.at > body_at {
                    self.tokens[body_at]
                        .span
                        .join(self.tokens[self.at - 1].span)
                } else {
                    self.peek().map_or_else(
                        || self.eof_span(),
                        |token| {
                            Span::new(
                                token.span.source_id(),
                                token.span.start(),
                                token.span.start(),
                            )
                        },
                    )
                },
            }
        };
        let end = body.span;
        Some((
            ItemKind::Function(Function {
                name,
                type_parameters,
                parameters,
                result,
                package,
                body,
            }),
            end,
        ))
    }

    pub(super) fn parse_block(&mut self) -> Option<Block> {
        self.syntax(SyntaxKind::Block, Self::parse_block_inner)
    }

    fn parse_block_inner(&mut self) -> Option<Block> {
        let open = self.expect(TokenKind::LeftBrace, "expected function body")?;
        if !self.enter(open.span) {
            return None;
        }
        let mut statements = Vec::new();
        let mut tail = None;
        let mut incomplete = false;
        let errors_before = self.error_count;
        while self.peek().is_some() && !self.at(TokenKind::RightBrace) && !self.body_item_boundary()
        {
            let start_at = self.at;
            let start = self.peek()?.span;
            let mut binding = None;
            let statement = if self.consume_keyword(Keyword::Let).is_some() {
                self.parse_let_statement(start, &mut binding)
            } else {
                (|| {
                    let expression = self.parse_expression()?;
                    if let Some(end) = self.consume(TokenKind::Semicolon) {
                        Some(Statement {
                            kind: StatementKind::Expression(expression),
                            span: start.join(end.span),
                        })
                    } else if self.at(TokenKind::RightBrace) || self.peek().is_none() {
                        tail = Some(Box::new(expression));
                        None
                    } else {
                        self.expect(
                            TokenKind::Semicolon,
                            "expected `;` after expression",
                        )?;
                        None
                    }
                })()
            };
            if tail.is_some() {
                break;
            }
            if let Some(statement) = statement {
                statements.push(statement);
            } else {
                incomplete = true;
                self.recover_statement(start_at);
                let end = self
                    .tokens
                    .get(self.at.saturating_sub(1))
                    .map_or(start, |token| token.span);
                statements.push(Statement {
                    kind: StatementKind::Recovery {
                        binding,
                    },
                    span: start.join(end),
                });
                if self.at == start_at || self.errors.len() == MAX_DIAGNOSTICS {
                    break;
                }
            }
        }
        let complete = self.expect(
            TokenKind::RightBrace,
            "expected `}` after function body",
        );
        self.leave();
        let end = complete.map_or_else(
            || {
                self.tokens
                    .get(self.at.saturating_sub(1))
                    .map_or(open.span, |token| token.span)
            },
            |token| token.span,
        );
        Some(Block {
            statements,
            tail,
            span: open.span.join(end),
            incomplete: incomplete || complete.is_none() || errors_before != self.error_count,
        })
    }

    pub(super) fn parse_let_statement(
        &mut self,
        start: Span,
        recovered: &mut Option<crate::syntax::RecoveredBinding>,
    ) -> Option<Statement> {
        let name = self.ident("expected name after `let`")?;
        *recovered = Some(crate::syntax::RecoveredBinding {
            name: name.clone(),
            ty: None,
        });
        let ty = if self.consume(TokenKind::Colon).is_some() {
            Some(self.parse_type()?)
        } else {
            None
        };
        recovered.as_mut()?.ty.clone_from(&ty);
        self.expect(TokenKind::Equal, "expected `=` in let statement")?;
        let value = self.parse_expression()?;
        let end = self.expect(
            TokenKind::Semicolon,
            "expected `;` after let statement",
        );
        let end = match end {
            Some(end) => end.span,
            None if self.peek().is_none() => value.span,
            None => return None,
        };
        Some(Statement {
            kind: StatementKind::Let {
                name,
                ty,
                value,
            },
            span: start.join(end),
        })
    }

    fn body_item_boundary(&self) -> bool {
        matches!(
            self.peek().map(|token| token.kind),
            Some(TokenKind::Keyword(
                Keyword::Pub
                    | Keyword::Mod
                    | Keyword::Use
                    | Keyword::Publish
                    | Keyword::Inputs
                    | Keyword::Outputs
                    | Keyword::Type
                    | Keyword::Struct
                    | Keyword::Opaque
                    | Keyword::Enum
                    | Keyword::Resource
                    | Keyword::Value
            ))
        ) || self.at_keyword(Keyword::Fn)
            && self
                .tokens
                .get(self.at + 1)
                .is_some_and(|token| token.kind == TokenKind::Ident)
    }

    fn recover_statement(&mut self, start: usize) {
        // Braces delimit scopes. Missing parentheses/brackets may synchronize at
        // a semicolon, but a nested closure/struct body must never escape its scope.
        let mut braces = 0usize;
        for token in &self.tokens[start..self.at] {
            if self.cancelled() {
                return;
            }
            match token.kind {
                TokenKind::LeftBrace => braces += 1,
                TokenKind::RightBrace => braces = braces.saturating_sub(1),
                _ => {}
            }
        }
        self.events
            .push(super::Event::Start(SyntaxKind::Error));
        while let Some(token) = self.peek() {
            if braces == 0 {
                if token.kind == TokenKind::Semicolon {
                    self.advance();
                    break;
                }
                if token.kind == TokenKind::RightBrace
                    || self.at_keyword(Keyword::Let)
                    || self.body_item_boundary()
                {
                    break;
                }
            }
            match token.kind {
                TokenKind::LeftBrace => braces += 1,
                TokenKind::RightBrace => braces = braces.saturating_sub(1),
                _ => {}
            }
            self.advance();
        }
        self.events.push(super::Event::Finish {
            failed: true,
        });
    }

    pub(super) fn parse_type(&mut self) -> Option<Type> {
        self.syntax(SyntaxKind::Type, |parser| {
            let span = parser
                .peek()
                .map_or_else(|| parser.eof_span(), |token| token.span);
            if !parser.enter(span) {
                return None;
            }
            parser.parse_type_inner()
        })
    }

    fn parse_type_inner(&mut self) -> Option<Type> {
        let once = self.consume_keyword(Keyword::Once);
        if once.is_some() && !self.at_keyword(Keyword::Fn) {
            self.expect_keyword(Keyword::Fn, "expected `fn` after `once`")?;
        }
        if let Some(start) = self.consume_keyword(Keyword::Fn) {
            let open = self.expect(
                TokenKind::LeftParen,
                "expected `(` after `fn` type",
            )?;
            if !self.enter(open.span) {
                return None;
            }
            let parameters = if self.at(TokenKind::RightParen) {
                Some(Vec::new())
            } else {
                self.comma_types(TokenKind::RightParen, false)
            };
            let close = self.expect(
                TokenKind::RightParen,
                "expected `)` after function parameters",
            );
            self.leave();
            close?;
            self.expect(
                TokenKind::Arrow,
                "expected `->` after function parameters",
            )?;
            let result = self.parse_type()?;
            return Some(Type {
                span: once
                    .map_or(start.span, |token| token.span)
                    .join(result.span),
                kind: TypeKind::Function {
                    once: once.is_some(),
                    parameters: parameters?,
                    result: Box::new(result),
                },
            });
        }
        if let Some(open) = self.consume(TokenKind::LeftBracket) {
            if !self.enter(open.span) {
                return None;
            }
            let element = self.parse_type()?;
            let close = self.expect(
                TokenKind::RightBracket,
                "expected `]` after list type",
            );
            self.leave();
            let close = close?;
            return Some(Type {
                kind: TypeKind::List(Box::new(element)),
                span: open.span.join(close.span),
            });
        }
        let mut path = self.parse_path("expected type")?;
        if path.segments.len() == 1 && path.segments[0].text == "bool" {
            path.segments = ["std", "Bool"]
                .into_iter()
                .map(|text| Ident {
                    text: text.to_owned(),
                    span: path.span,
                })
                .collect();
        }
        let start = path.span;
        let (arguments, end) = if let Some(open) = self.consume(TokenKind::LeftAngle) {
            if !self.enter(open.span) {
                return None;
            }
            let arguments = self.comma_types(TokenKind::RightAngle, false);
            let close = self.expect(
                TokenKind::RightAngle,
                "expected `>` after type arguments",
            );
            self.leave();
            let close = close?;
            (arguments?, close.span)
        } else {
            (Vec::new(), path.span)
        };
        Some(Type {
            kind: TypeKind::Named {
                path,
                arguments,
            },
            span: start.join(end),
        })
    }
}
