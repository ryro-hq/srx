use super::{
    Diagnostic, Expression, ExpressionKind, Ident, IntegerLiteral, Keyword, Literal, MatchArm,
    Parameter, Parser, Path, Pattern, Span, StringLiteral, StringPart, StructField, SyntaxKind,
    TokenKind, Type, is_keyword,
};

impl Parser<'_> {
    pub(super) fn parse_expression(&mut self) -> Option<Expression> {
        self.parse_concat(true)
    }

    fn parse_concat(&mut self, allow_struct: bool) -> Option<Expression> {
        self.syntax(SyntaxKind::Expression, |parser| {
            parser.parse_concat_inner(allow_struct)
        })
    }

    fn parse_concat_inner(&mut self, allow_struct: bool) -> Option<Expression> {
        let first = self.parse_postfix(allow_struct)?;
        if !self.at(TokenKind::PlusPlus) {
            return Some(first);
        }
        let start = first.span;
        let mut expressions = vec![first];
        while self.consume(TokenKind::PlusPlus).is_some() {
            expressions.push(self.parse_postfix(allow_struct)?);
        }
        let span = start.join(expressions.last()?.span);
        Some(Expression {
            kind: ExpressionKind::Concat(expressions),
            span,
        })
    }

    fn parse_postfix(&mut self, allow_struct: bool) -> Option<Expression> {
        self.syntax(SyntaxKind::PostfixExpression, |parser| {
            parser.parse_postfix_inner(allow_struct)
        })
    }

    fn parse_postfix_inner(&mut self, allow_struct: bool) -> Option<Expression> {
        let mut expression = self.parse_primary(allow_struct)?;
        let mut links = 0;
        loop {
            if self.at(TokenKind::Dot) {
                let field = self.syntax(SyntaxKind::FieldAccess, |parser| {
                    parser.advance();
                    parser.ident("expected field name after `.`")
                })?;
                if let ExpressionKind::Path(path) = &expression.kind {
                    if field.text == "forSystem" && self.at(TokenKind::LeftParen) {
                        let open = self.advance()?.span;
                        if !self.enter(open) {
                            return None;
                        }
                        let system = self.parse_expression()?;
                        self.expect(TokenKind::RightParen, "expected `)` after system")?;
                        self.expect(
                            TokenKind::Dot,
                            "expected package after `forSystem`",
                        )?;
                        let member = self.ident("expected package name")?;
                        let mut callee = path.clone();
                        callee.span = callee.span.join(member.span);
                        callee.segments.push(member);
                        let start = self.peek()?.span;
                        let mut request = self.parse_struct_literal(
                            Path {
                                segments: Vec::new(),
                                span: start,
                            },
                            Vec::new(),
                        )?;
                        let ExpressionKind::Struct {
                            fields,
                            ..
                        } = &mut request.kind
                        else {
                            return None;
                        };
                        fields.insert(
                            0,
                            StructField {
                                name: Ident {
                                    text: "system".to_owned(),
                                    span: field.span,
                                },
                                span: field.span.join(system.span),
                                value: system,
                            },
                        );
                        self.leave();
                        expression = Expression {
                            span: expression.span.join(request.span),
                            kind: ExpressionKind::Call {
                                callee,
                                arguments: vec![request],
                            },
                        };
                        continue;
                    }
                    if allow_struct && self.at(TokenKind::LeftBrace) {
                        let mut callee = path.clone();
                        callee.span = callee.span.join(field.span);
                        callee.segments.push(field);
                        let arguments = if self.at(TokenKind::LeftBrace) {
                            let open = self.peek()?.span;
                            vec![self.parse_struct_literal(
                                Path {
                                    segments: Vec::new(),
                                    span: open,
                                },
                                Vec::new(),
                            )?]
                        } else {
                            let open = self.advance()?.span;
                            if !self.enter(open) {
                                return None;
                            }
                            let arguments = self.comma_expressions(TokenKind::RightParen)?;
                            self.expect(
                                TokenKind::RightParen,
                                "expected `)` after arguments",
                            )?;
                            self.leave();
                            arguments
                        };
                        let end = self.tokens[self.at - 1].span;
                        expression = Expression {
                            span: expression.span.join(end),
                            kind: ExpressionKind::Call {
                                callee,
                                arguments,
                            },
                        };
                        continue;
                    }
                }
                if let ExpressionKind::Field {
                    fields,
                    ..
                } = &mut expression.kind
                {
                    expression.span = expression.span.join(field.span);
                    fields.push(field);
                } else {
                    links += 1;
                    if links >= crate::MAX_DEPTH {
                        self.error(Diagnostic::error(
                            "postfix chain exceeds syntax nesting limit",
                            field.span,
                        ));
                        return None;
                    }
                    expression = Expression {
                        span: expression.span.join(field.span),
                        kind: ExpressionKind::Field {
                            value: Box::new(expression),
                            fields: vec![field],
                        },
                    };
                }
            } else if let Some(open) = self.consume(TokenKind::LeftParen) {
                links += 1;
                if links >= crate::MAX_DEPTH {
                    self.error(Diagnostic::error(
                        "functional call chain exceeds syntax nesting limit",
                        open.span,
                    ));
                    return None;
                }
                if !self.enter(open.span) {
                    return None;
                }
                let arguments = self.comma_expressions(TokenKind::RightParen);
                let close = self.expect(
                    TokenKind::RightParen,
                    "expected `)` after call arguments",
                );
                self.leave();
                let close = close?;
                expression = Expression {
                    span: expression.span.join(close.span),
                    kind: ExpressionKind::Apply {
                        callee: Box::new(expression),
                        arguments: arguments?,
                    },
                };
            } else {
                return Some(expression);
            }
        }
    }

    fn parse_primary(&mut self, allow_struct: bool) -> Option<Expression> {
        self.syntax(SyntaxKind::PrimaryExpression, |parser| {
            parser.parse_primary_inner(allow_struct)
        })
    }

    fn parse_primary_inner(&mut self, allow_struct: bool) -> Option<Expression> {
        let Some(token) = self.peek() else {
            self.error(
                Diagnostic::error("expected expression", self.eof_span())
                    .with_expected(crate::diagnostic::SyntaxExpectation::Expression),
            );
            self.missing(SyntaxKind::MissingExpression);
            return None;
        };
        match token.kind {
            TokenKind::Integer => self.integer_literal().map(|literal| Expression {
                span: literal.span,
                kind: ExpressionKind::Integer(literal),
            }),
            TokenKind::String => self.string_literal().map(|literal| Expression {
                span: literal.span,
                kind: ExpressionKind::String(literal),
            }),
            TokenKind::Ident => self.parse_path_expression(allow_struct),
            TokenKind::LeftBrace => {
                let span = token.span;
                self.parse_struct_literal(
                    Path {
                        segments: Vec::new(),
                        span,
                    },
                    Vec::new(),
                )
            }
            TokenKind::Keyword(Keyword::Let) => self.parse_let_expression(),
            TokenKind::LeftBracket => self.parse_list(),
            TokenKind::LeftParen => self.parse_group(),
            TokenKind::Keyword(Keyword::Erase) => self.parse_erase(),
            TokenKind::Keyword(Keyword::Match) => self.parse_match(),
            TokenKind::Keyword(Keyword::Fn | Keyword::Once) => self.parse_closure(),
            TokenKind::Keyword(Keyword::Fold) => self.parse_fold(),
            TokenKind::Keyword(Keyword::SortByKeys) => self.parse_sort_by_keys(),
            TokenKind::Keyword(Keyword::Compare) => self.parse_compare(),
            TokenKind::Keyword(Keyword::ModuleExports) => self.parse_module_exports(),
            TokenKind::Keyword(Keyword::Memoize) => self.parse_memoize(),
            _ => {
                self.error(
                    Diagnostic::error("expected expression", token.span)
                        .with_expected(crate::diagnostic::SyntaxExpectation::Expression),
                );
                self.missing(SyntaxKind::MissingExpression);
                None
            }
        }
    }

    fn parse_closure(&mut self) -> Option<Expression> {
        let once = self.consume_keyword(Keyword::Once);
        let start = self
            .expect_keyword(Keyword::Fn, "expected anonymous function")?
            .span;
        let open = self.expect(
            TokenKind::LeftParen,
            "expected `(` after anonymous `fn`",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let mut parameters = Vec::new();
        while !self.at(TokenKind::RightParen) {
            let name = self.ident("expected closure parameter")?;
            self.expect(
                TokenKind::Colon,
                "expected `:` after closure parameter",
            )?;
            let ty = self.parse_type()?;
            parameters.push(Parameter {
                span: name.span.join(ty.span),
                name,
                ty,
            });
            if self.consume(TokenKind::Comma).is_none() {
                break;
            }
        }
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after closure parameters",
        );
        self.leave();
        close?;
        self.expect(
            TokenKind::Arrow,
            "expected `->` after closure parameters",
        )?;
        let result = self.parse_type()?;
        let body = self.parse_block()?;
        Some(Expression {
            span: once
                .map_or(start, |token| token.span)
                .join(body.span),
            kind: ExpressionKind::Closure {
                once: once.is_some(),
                parameters,
                result,
                body,
            },
        })
    }

    fn parse_let_expression(&mut self) -> Option<Expression> {
        let start = self.peek()?.span;
        if !self.enter(start) {
            return None;
        }
        let mut statements = Vec::new();
        loop {
            let binding = self
                .expect_keyword(Keyword::Let, "expected `let` binding")?
                .span;
            statements.push(self.parse_let_statement(binding, &mut None)?);
            if self.at_keyword(Keyword::In) {
                break;
            }
            // Subsequent bindings may omit the repeated `let`.
            if !self.at_keyword(Keyword::Let) {
                while !self.at_keyword(Keyword::In) {
                    let binding = self.peek()?.span;
                    statements.push(self.parse_let_statement(binding, &mut None)?);
                }
                break;
            }
        }
        self.expect_keyword(Keyword::In, "expected `in` after bindings")?;
        let tail = self.parse_expression()?;
        self.leave();
        let span = start.join(tail.span);
        Some(Expression {
            kind: ExpressionKind::Let(crate::syntax::Block {
                statements,
                tail: Some(Box::new(tail)),
                span,
                incomplete: false,
            }),
            span,
        })
    }

    fn parse_memoize(&mut self) -> Option<Expression> {
        let start = self.advance()?.span;
        let open = self.expect(
            TokenKind::LeftParen,
            "expected `(` after `memoize`",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let value = self.parse_expression();
        self.consume(TokenKind::Comma);
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after memoized function",
        );
        self.leave();
        Some(Expression {
            span: start.join(close?.span),
            kind: ExpressionKind::Memoize(Box::new(value?)),
        })
    }

    fn parse_module_exports(&mut self) -> Option<Expression> {
        let start = self.advance()?.span;
        let open = self.expect(
            TokenKind::LeftParen,
            "expected `(` after `module_exports`",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let namespace = self.parse_path("expected module namespace")?;
        self.expect(
            TokenKind::Comma,
            "expected `,` after module namespace",
        )?;
        let export = self.ident("expected public export name")?;
        self.expect(TokenKind::Comma, "expected `,` after export name")?;
        let mapper = self.parse_expression()?;
        self.consume(TokenKind::Comma);
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after module mapper",
        );
        self.leave();
        Some(Expression {
            span: start.join(close?.span),
            kind: ExpressionKind::ModuleExports {
                namespace,
                export,
                mapper: Box::new(mapper),
            },
        })
    }

    fn parse_compare(&mut self) -> Option<Expression> {
        let start = self.advance()?.span;
        let open = self.expect(
            TokenKind::LeftParen,
            "expected `(` after `compare`",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let arguments = self.comma_expressions(TokenKind::RightParen);
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after comparison branches",
        );
        self.leave();
        let span = start.join(close?.span);
        let Ok([left, right, less, equal, greater]) = <[Expression; 5]>::try_from(arguments?)
        else {
            self.error(Diagnostic::error(
                "compare expects two operands and three result branches",
                span,
            ));
            return None;
        };
        Some(Expression {
            span,
            kind: ExpressionKind::Compare {
                left: Box::new(left),
                right: Box::new(right),
                branches: [
                    Box::new(less),
                    Box::new(equal),
                    Box::new(greater),
                ],
            },
        })
    }

    fn parse_fold(&mut self) -> Option<Expression> {
        let start = self.advance()?.span;
        let open = self.expect(TokenKind::LeftParen, "expected `(` after `fold`")?;
        if !self.enter(open.span) {
            return None;
        }
        let items = self.parse_expression()?;
        self.expect(TokenKind::Comma, "expected `,` after fold list")?;
        let initial = self.parse_expression()?;
        self.expect(
            TokenKind::Comma,
            "expected `,` after fold accumulator",
        )?;
        let step = self.parse_expression()?;
        self.consume(TokenKind::Comma);
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after fold step",
        );
        self.leave();
        Some(Expression {
            span: start.join(close?.span),
            kind: ExpressionKind::Fold {
                items: Box::new(items),
                initial: Box::new(initial),
                step: Box::new(step),
            },
        })
    }

    fn parse_sort_by_keys(&mut self) -> Option<Expression> {
        let start = self.advance()?.span;
        let open = self.expect(
            TokenKind::LeftParen,
            "expected `(` after `sort_by_keys`",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let arguments = self.comma_expressions(TokenKind::RightParen);
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after sort keys",
        );
        self.leave();
        let span = start.join(close?.span);
        let Ok([items, keys]) = <[Expression; 2]>::try_from(arguments?) else {
            self.error(Diagnostic::error(
                "sort_by_keys expects an item list and a key list",
                span,
            ));
            return None;
        };
        Some(Expression {
            span,
            kind: ExpressionKind::SortByKeys {
                items: Box::new(items),
                keys: Box::new(keys),
            },
        })
    }

    fn parse_path_expression(&mut self, allow_struct: bool) -> Option<Expression> {
        let mut path = self.parse_path("expected path")?;
        if path.segments.len() == 1 && matches!(path.segments[0].text.as_str(), "true" | "false") {
            let variant = if path.segments[0].text == "true" {
                "True"
            } else {
                "False"
            };
            path.segments = ["std", "Bool", variant]
                .into_iter()
                .map(|text| Ident {
                    text: text.to_owned(),
                    span: path.span,
                })
                .collect();
        }
        let start = path.span;
        if let Some(open) = self.consume(TokenKind::LeftParen) {
            if !self.enter(open.span) {
                return None;
            }
            let arguments = self.comma_expressions(TokenKind::RightParen);
            let close = self.expect(
                TokenKind::RightParen,
                "expected `)` after call arguments",
            );
            self.leave();
            let close = close?;
            return Some(Expression {
                kind: ExpressionKind::Call {
                    callee: path,
                    arguments: arguments?,
                },
                span: start.join(close.span),
            });
        }
        let type_arguments = if self.at(TokenKind::LeftAngle) {
            let open = self.advance()?;
            if !self.enter(open.span) {
                return None;
            }
            let arguments = self.comma_types(TokenKind::RightAngle, false);
            let close = self.expect(
                TokenKind::RightAngle,
                "expected `>` after type arguments",
            );
            self.leave();
            close?;
            arguments?
        } else {
            Vec::new()
        };
        if allow_struct && self.at(TokenKind::LeftBrace) {
            return self.parse_struct_literal(path, type_arguments);
        }
        if !type_arguments.is_empty() {
            let end = self.tokens[self.at - 1].span;
            return Some(Expression {
                span: start.join(end),
                kind: ExpressionKind::Specialize {
                    function: path,
                    arguments: type_arguments,
                },
            });
        }
        Some(Expression {
            kind: ExpressionKind::Path(path),
            span: start,
        })
    }

    pub(super) fn parse_struct_literal(
        &mut self,
        path: Path,
        type_arguments: Vec<Type>,
    ) -> Option<Expression> {
        self.syntax(SyntaxKind::StructLiteral, |parser| {
            parser.parse_struct_literal_inner(path, type_arguments)
        })
    }

    fn parse_struct_literal_inner(
        &mut self,
        path: Path,
        type_arguments: Vec<Type>,
    ) -> Option<Expression> {
        let start = path.span;
        let open = self.expect(
            TokenKind::LeftBrace,
            "expected `{` in struct literal",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let (fields, mut recovery) = self.recoverable_entries(SyntaxKind::FieldValue, |parser| {
            let field_start = parser.peek()?.span;
            let name = parser.ident("expected struct field name")?;
            parser.expect(
                TokenKind::Equal,
                "expected `=` after struct field name",
            )?;
            let value = parser.parse_expression()?;
            let end = parser.expect(
                TokenKind::Semicolon,
                "expected `;` after struct field",
            )?;
            Some(StructField {
                name,
                value,
                span: field_start.join(end.span),
            })
        });
        let close = self.expect(
            TokenKind::RightBrace,
            "expected `}` after struct literal",
        );
        self.leave();
        let end = if let Some(close) = close {
            close.span
        } else {
            let end = self.eof_span();
            recovery.push(end);
            end
        };
        Some(Expression {
            kind: ExpressionKind::Struct {
                path,
                type_arguments,
                fields,
                recovery,
            },
            span: start.join(end),
        })
    }

    fn parse_list(&mut self) -> Option<Expression> {
        let open = self.expect(TokenKind::LeftBracket, "expected `[")?;
        if !self.enter(open.span) {
            return None;
        }
        let values = self.comma_expressions(TokenKind::RightBracket);
        let close = self.expect(TokenKind::RightBracket, "expected `]` after list");
        self.leave();
        let close = close?;
        Some(Expression {
            kind: ExpressionKind::List(values?),
            span: open.span.join(close.span),
        })
    }

    fn parse_group(&mut self) -> Option<Expression> {
        let open = self.expect(TokenKind::LeftParen, "expected `(`")?;
        if !self.enter(open.span) {
            return None;
        }
        let value = self.parse_expression();
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after expression",
        );
        self.leave();
        let (value, close) = (value?, close?);
        Some(Expression {
            kind: ExpressionKind::Group(Box::new(value)),
            span: open.span.join(close.span),
        })
    }

    fn parse_erase(&mut self) -> Option<Expression> {
        let start = self
            .expect_keyword(Keyword::Erase, "expected `erase`")?
            .span;
        let open = self.expect(TokenKind::LeftAngle, "expected `<` after `erase`")?;
        if !self.enter(open.span) {
            return None;
        }
        let ty = self.parse_type()?;
        let close = self.expect(
            TokenKind::RightAngle,
            "expected `>` after erased type",
        );
        self.leave();
        close?;
        let open = self.expect(
            TokenKind::LeftParen,
            "expected `(` after erased type",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let value = self.parse_expression();
        let close = self.expect(
            TokenKind::RightParen,
            "expected `)` after erased value",
        );
        self.leave();
        let (value, close) = (value?, close?);
        Some(Expression {
            kind: ExpressionKind::Erase {
                ty,
                value: Box::new(value),
            },
            span: start.join(close.span),
        })
    }

    fn parse_match(&mut self) -> Option<Expression> {
        let start = self
            .expect_keyword(Keyword::Match, "expected `match`")?
            .span;
        if !self.enter(start) {
            return None;
        }
        // A bare `{` after the scrutinee starts the match body, not a struct literal.
        let value = self.parse_concat(false)?;
        let open = self.expect(
            TokenKind::LeftBrace,
            "expected `{` after match value",
        )?;
        if !self.enter(open.span) {
            return None;
        }
        let mut arms = Vec::new();
        while self.peek().is_some() && !self.at(TokenKind::RightBrace) {
            let arm_start = self.peek()?.span;
            let pattern = self.parse_pattern()?;
            self.expect(
                TokenKind::FatArrow,
                "expected `=>` after match pattern",
            )?;
            let arm_value = self.parse_expression()?;
            let arm_end = arm_value.span;
            arms.push(MatchArm {
                pattern,
                value: arm_value,
                span: arm_start.join(arm_end),
            });
            if self.consume(TokenKind::Comma).is_none() {
                break;
            }
        }
        if arms.is_empty() {
            self.error(Diagnostic::error(
                "match requires at least one arm",
                open.span,
            ));
        }
        let close = self.expect(
            TokenKind::RightBrace,
            "expected `}` after match arms",
        );
        self.leave();
        let close = close?;
        let expression = Expression {
            kind: ExpressionKind::Match {
                value: Box::new(value),
                arms,
            },
            span: start.join(close.span),
        };
        self.leave();
        Some(expression)
    }

    fn parse_pattern(&mut self) -> Option<Pattern> {
        if self
            .peek()
            .is_some_and(|token| token.kind == TokenKind::Ident && self.text(token.span) == "_")
        {
            return self
                .advance()
                .map(|token| Pattern::Wildcard(token.span));
        }
        let path = self.parse_path("expected match pattern")?;
        if let Some(open) = self.consume(TokenKind::LeftParen) {
            if !self.enter(open.span) {
                return None;
            }
            let bindings = if self.at(TokenKind::RightParen) {
                Some(Vec::new())
            } else {
                self.comma_idents(TokenKind::RightParen, true)
            };
            let close = self.expect(
                TokenKind::RightParen,
                "expected `)` after pattern bindings",
            );
            self.leave();
            close?;
            Some(Pattern::Variant {
                path,
                bindings: bindings?,
            })
        } else {
            Some(Pattern::Path(path))
        }
    }

    pub(super) fn parse_literal(&mut self) -> Option<Literal> {
        match self.peek()?.kind {
            TokenKind::Integer => self.integer_literal().map(Literal::Integer),
            TokenKind::String => self.string_literal().map(Literal::String),
            _ => {
                self.error(Diagnostic::error(
                    "expected integer or string literal",
                    self.peek()?.span,
                ));
                None
            }
        }
    }

    pub(super) fn integer_literal(&mut self) -> Option<IntegerLiteral> {
        let token = self.expect(TokenKind::Integer, "expected integer")?;
        let source = self.text(token.span).to_owned();
        let Ok(value) = source.parse::<i64>() else {
            self.error(Diagnostic::error(
                "integer literal exceeds i64",
                token.span,
            ));
            return None;
        };
        Some(IntegerLiteral {
            source,
            value,
            span: token.span,
        })
    }

    pub(super) fn string_literal(&mut self) -> Option<StringLiteral> {
        let token = self.expect(TokenKind::String, "expected string literal")?;
        let raw = self.text(token.span).to_owned();
        let bytes = raw.as_bytes();
        let delimiter = if bytes.starts_with(b"\"\"\"") {
            3
        } else {
            1
        };
        if bytes.len() < 2 * delimiter || bytes.last() != Some(&b'"') {
            return None;
        }
        let end = bytes.len() - delimiter;
        let mut parts = Vec::new();
        let mut at = delimiter;
        let mut text_start = at;
        while at < end {
            if self.cancelled() {
                return None;
            }
            if bytes[at] == b'\\' {
                at += 2;
                continue;
            }
            if bytes[at] == b'$' && bytes.get(at + 1) == Some(&b'{') {
                if text_start < at {
                    parts.push(StringPart::Text {
                        source: raw[text_start..at].to_owned(),
                        span: Self::subspan(token.span, text_start, at),
                    });
                }
                let interpolation_start = at;
                at += 2;
                let path_start = at;
                while at < end && bytes[at] != b'}' {
                    if self.cancelled() {
                        return None;
                    }
                    at += 1;
                }
                if at >= end {
                    self.error(Diagnostic::error(
                        "unterminated string interpolation",
                        Self::subspan(token.span, interpolation_start, at),
                    ));
                    return None;
                }
                let path = self.interpolation_path(token.span, &raw, path_start, at)?;
                at += 1;
                parts.push(StringPart::Interpolation {
                    path,
                    span: Self::subspan(token.span, interpolation_start, at),
                });
                text_start = at;
            } else {
                at += 1;
            }
        }
        if text_start < end {
            parts.push(StringPart::Text {
                source: raw[text_start..end].to_owned(),
                span: Self::subspan(token.span, text_start, end),
            });
        }
        Some(StringLiteral {
            source: raw,
            parts,
            span: token.span,
        })
    }

    fn interpolation_path(
        &mut self,
        token_span: Span,
        raw: &str,
        start: usize,
        end: usize,
    ) -> Option<Path> {
        let bytes = raw.as_bytes();
        let mut segments = Vec::new();
        let mut at = start;
        while at < end {
            let segment_start = at;
            if !bytes[at].is_ascii_alphabetic() && bytes[at] != b'_' {
                self.error(Diagnostic::error(
                    "interpolation must contain a local name and optional fields",
                    Self::subspan(token_span, start, end),
                ));
                return None;
            }
            at += 1;
            while at < end && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
            let span = Self::subspan(token_span, segment_start, at);
            let text = &raw[segment_start..at];
            if is_keyword(text) {
                self.error(Diagnostic::error(
                    "interpolation names cannot be reserved keywords",
                    span,
                ));
                return None;
            }
            segments.push(Ident {
                text: text.to_owned(),
                span,
            });
            if at == end {
                break;
            }
            if bytes[at] != b'.' {
                self.error(Diagnostic::error(
                    "interpolation fields must be separated by `.`",
                    Self::subspan(token_span, start, end),
                ));
                return None;
            }
            at += 1;
        }
        if segments.is_empty() || raw.as_bytes().get(end.saturating_sub(1)) == Some(&b'.') {
            self.error(Diagnostic::error(
                "interpolation requires a name after `.`",
                Self::subspan(token_span, start, end),
            ));
            return None;
        }
        let span = Self::subspan(token_span, start, end);
        Some(Path {
            segments,
            span,
        })
    }
}
