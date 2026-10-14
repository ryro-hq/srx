use super::{SourceId, Span, Token, TokenKind};

/// Grammar contexts retained even when their semantic AST cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntaxKind {
    File,
    Declaration,
    Output,
    Field,
    FieldValue,
    Block,
    Type,
    Path,
    Expression,
    PrimaryExpression,
    PostfixExpression,
    FieldAccess,
    Arguments,
    Argument,
    StructLiteral,
    Error,
    MissingToken(TokenKind),
    MissingExpression,
}

#[derive(Clone, Debug)]
pub(super) enum Event {
    Start(SyntaxKind),
    Finish {
        failed: bool,
    },
    Token,
}

#[derive(Clone, Copy, Debug)]
enum Element {
    Node(usize),
    Token(usize),
}

#[derive(Clone, Debug)]
struct Node {
    kind: SyntaxKind,
    span: Span,
    parent: Option<usize>,
    children: Vec<Element>,
    has_errors: bool,
}

/// Immutable, file-local syntax arena. Tokens appear exactly once in the tree.
/// The flat arena also bounds destruction stack usage for deeply nested input.
#[derive(Clone, Debug)]
pub struct SyntaxTree {
    nodes: Vec<Node>,
    tokens: Vec<Token>,
}

#[derive(Clone, Copy, Debug)]
pub struct SyntaxNode<'a> {
    tree: &'a SyntaxTree,
    index: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum SyntaxElement<'a> {
    Node(SyntaxNode<'a>),
    Token(&'a Token),
}

impl SyntaxNode<'_> {
    pub fn kind(self) -> SyntaxKind {
        self.tree.nodes[self.index].kind
    }

    pub fn span(self) -> Span {
        self.tree.nodes[self.index].span
    }

    pub fn has_errors(self) -> bool {
        self.tree.nodes[self.index].has_errors
    }
}

impl<'a> SyntaxNode<'a> {
    pub fn parent(self) -> Option<Self> {
        self.tree.nodes[self.index]
            .parent
            .map(|index| Self {
                tree: self.tree,
                index,
            })
    }

    pub fn children(
        self,
    ) -> impl DoubleEndedIterator<Item = SyntaxElement<'a>> + ExactSizeIterator {
        self.tree.nodes[self.index]
            .children
            .iter()
            .map(move |element| match *element {
                Element::Node(index) => SyntaxElement::Node(Self {
                    tree: self.tree,
                    index,
                }),
                Element::Token(index) => SyntaxElement::Token(&self.tree.tokens[index]),
            })
    }
}

impl SyntaxTree {
    pub fn root(&self) -> SyntaxNode<'_> {
        SyntaxNode {
            tree: self,
            index: 0,
        }
    }

    /// Nodes in preorder, including the root and zero-width missing nodes.
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = SyntaxNode<'_>> {
        (0..self.nodes.len()).map(|index| SyntaxNode {
            tree: self,
            index,
        })
    }

    pub fn tokens(&self) -> impl ExactSizeIterator<Item = &Token> {
        self.tokens.iter()
    }

    /// Deepest grammar context at a byte offset. Missing syntax wins at an
    /// insertion point; otherwise the node on the right wins at a boundary.
    /// At EOF a node ending at the cursor remains eligible.
    pub fn context_at(&self, offset: u32) -> Option<SyntaxNode<'_>> {
        if offset > self.root().span().end() {
            return None;
        }
        let mut best = (3, usize::MAX, 0);
        let mut pending = vec![(0, 0usize)];
        while let Some((index, depth)) = pending.pop() {
            let node = &self.nodes[index];
            let rank = match node.kind {
                SyntaxKind::MissingToken(_) | SyntaxKind::MissingExpression => 0,
                SyntaxKind::Error => 3,
                _ if offset < node.span.end() => 1,
                _ => 2,
            };
            let candidate = (rank, usize::MAX - depth, index);
            if candidate < best {
                best = candidate;
            }
            let children = &self.nodes[index].children;
            let first =
                children.partition_point(|element| self.element_span(*element).end() < offset);
            for element in &children[first..] {
                if self.element_span(*element).start() > offset {
                    break;
                }
                if let Element::Node(child) = *element {
                    pending.push((child, depth + 1));
                }
            }
        }
        Some(SyntaxNode {
            tree: self,
            index: best.2,
        })
    }

    fn element_span(&self, element: Element) -> Span {
        match element {
            Element::Node(index) => self.nodes[index].span,
            Element::Token(index) => self.tokens[index].span,
        }
    }

    pub(super) fn build(
        source: SourceId,
        end: u32,
        tokens: Vec<Token>,
        events: Vec<Event>,
        cancellation: Option<&crate::analysis::AnalysisCancellation>,
    ) -> Result<Self, crate::analysis::AnalysisCancelled> {
        let mut tree = Self {
            nodes: vec![Node {
                kind: SyntaxKind::File,
                span: Span::new(source, 0, end),
                parent: None,
                children: Vec::new(),
                has_errors: false,
            }],
            tokens,
        };
        let mut stack = vec![0];
        let mut cursor = 0;
        for event in events {
            if let Some(cancel) = cancellation {
                cancel.check()?;
            }
            let parent = *stack.last().expect("file node is always open");
            match event {
                Event::Start(kind) => {
                    // Leading trivia belongs to the enclosing grammar context.
                    while tree
                        .tokens
                        .get(cursor)
                        .is_some_and(|token| token.kind.is_trivia())
                    {
                        if let Some(cancel) = cancellation {
                            cancel.check()?;
                        }
                        tree.push_token(parent, cursor);
                        cursor += 1;
                    }
                    let start = tree
                        .tokens
                        .get(cursor)
                        .map_or(end, |token| token.span.start());
                    let index = tree.nodes.len();
                    tree.nodes.push(Node {
                        kind,
                        span: Span::new(source, start, start),
                        parent: Some(parent),
                        children: Vec::new(),
                        has_errors: matches!(
                            kind,
                            SyntaxKind::Error
                                | SyntaxKind::MissingToken(_)
                                | SyntaxKind::MissingExpression
                        ),
                    });
                    tree.nodes[parent]
                        .children
                        .push(Element::Node(index));
                    stack.push(index);
                }
                Event::Finish {
                    failed,
                } => {
                    let index = stack.pop().expect("balanced syntax events");
                    let parent = *stack
                        .last()
                        .expect("parser cannot close the file node");
                    tree.nodes[index].has_errors |= failed;
                    let span = tree.nodes[index].span;
                    tree.nodes[parent].span = tree.nodes[parent].span.join(span);
                    tree.nodes[parent].has_errors |= tree.nodes[index].has_errors;
                }
                Event::Token => {
                    while tree
                        .tokens
                        .get(cursor)
                        .is_some_and(|token| token.kind.is_trivia())
                    {
                        if let Some(cancel) = cancellation {
                            cancel.check()?;
                        }
                        tree.push_token(parent, cursor);
                        cursor += 1;
                    }
                    tree.push_token(parent, cursor);
                    cursor += 1;
                }
            }
        }
        assert_eq!(stack, [0], "balanced syntax events");
        while cursor < tree.tokens.len() {
            if let Some(cancel) = cancellation {
                cancel.check()?;
            }
            tree.push_token(0, cursor);
            cursor += 1;
        }
        Ok(tree)
    }

    fn push_token(&mut self, parent: usize, index: usize) {
        let token = self.tokens[index];
        self.nodes[parent]
            .children
            .push(Element::Token(index));
        self.nodes[parent].span = self.nodes[parent].span.join(token.span);
        self.nodes[parent].has_errors |= matches!(
            token.kind,
            TokenKind::Invalid | TokenKind::Unparsed
        );
    }
}
