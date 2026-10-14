//! Syntax for `.srx` files, with spans into the original text.
//!
//! [`parse_sources`] accepts a source set for the language pipeline and reports
//! syntax errors before resolution. [`parse_file`] also retains tokens, comments
//! and incomplete regions for editor queries. A recovered tree lets a query
//! continue; it does not make the file valid.
//!
//! See [`parser`] for recovery and resource limits, then [`crate::resolver`] for
//! binding names in a successfully parsed source set.

pub mod lexer;
pub mod parser;

pub use parser::{
    FunctionSignature, ParsedFile, SyntaxElement, SyntaxKeyword, SyntaxKind, SyntaxNode,
    SyntaxToken, SyntaxTokenKind, SyntaxTree, analyze, parse_file, parse_sources,
};

use std::collections::BTreeMap;

use crate::{source::SourceDomainId, source::SourceId, source::Span};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedSources {
    pub(crate) sources: Vec<ParsedSource>,
    pub(crate) input_domains: BTreeMap<SourceDomainId, BTreeMap<String, SourceDomainId>>,
    pub(crate) project_roots: std::collections::BTreeSet<SourceDomainId>,
}

impl ParsedSources {
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ParsedSource> {
        self.sources.iter()
    }

    pub fn get(&self, source_id: SourceId) -> Option<&ParsedProgram> {
        self.sources
            .get(source_id.index())
            .filter(|source| source.source_id == source_id)
            .map(|source| &source.program)
    }

    /// Project root that owns a source, including sources in its local modules.
    pub fn owner(&self, source_id: SourceId) -> Option<SourceDomainId> {
        let domain = self.sources.get(source_id.index())?.domain;
        if domain == SourceDomainId::project() || self.project_roots.contains(&domain) {
            return Some(domain);
        }
        self.input_domains
            .iter()
            .find_map(|(parent, aliases)| {
                aliases
                    .values()
                    .any(|candidate| *candidate == domain)
                    .then_some(*parent)
            })
    }

    pub fn declaration_count(&self) -> usize {
        self.sources
            .iter()
            .map(|source| source.program.declaration_count())
            .sum()
    }

    pub(crate) fn input_domain(
        &self,
        parent: SourceDomainId,
        alias: &str,
    ) -> Option<SourceDomainId> {
        self.input_domains
            .get(&parent)?
            .get(alias)
            .copied()
    }

    pub(crate) fn is_input_domain(&self, domain: SourceDomainId) -> bool {
        self.input_domains.values().any(|aliases| {
            aliases
                .values()
                .any(|candidate| *candidate == domain)
        })
    }

    pub(crate) fn is_project_root(&self, domain: SourceDomainId) -> bool {
        domain == SourceDomainId::project() || self.project_roots.contains(&domain)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedSource {
    pub(crate) source_id: SourceId,
    pub(crate) domain: SourceDomainId,
    pub(crate) module: Vec<String>,
    pub(crate) program: ParsedProgram,
}

impl ParsedSource {
    pub const fn source_id(&self) -> SourceId {
        self.source_id
    }

    pub const fn domain(&self) -> SourceDomainId {
        self.domain
    }

    pub const fn program(&self) -> &ParsedProgram {
        &self.program
    }

    pub fn module(&self) -> &[String] {
        &self.module
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedProgram {
    pub items: Vec<Item>,
}

impl ParsedProgram {
    pub fn declaration_count(&self) -> usize {
        self.items.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    pub text: String,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    pub segments: Vec<Ident>,
    pub span: Span,
}

impl Path {
    pub(crate) fn display(&self) -> String {
        self.segments
            .iter()
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>()
            .join("::")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub kind: ItemKind,
    pub public: bool,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemKind {
    Module(Module),
    Use(Use),
    Inputs(Inputs),
    Outputs(Outputs),
    Publication(Publication),
    TypeAlias(TypeAlias),
    Struct(Struct),
    Enum(Enum),
    Resource(PrimitiveDeclaration),
    Value(PrimitiveDeclaration),
    Function(Function),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    pub path: Path,
    pub items: Vec<Item>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Use {
    pub path: Path,
    pub names: Option<Vec<Ident>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub entries: Vec<Input>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub name: Ident,
    pub value: StringLiteral,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outputs {
    pub entries: Vec<Output>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub kind: OutputKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publication {
    pub result: Type,
    pub namespace: Path,
    pub export: Ident,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputKind {
    Value {
        name: Ident,
        ty: Type,
        value: Expression,
    },
    Type {
        name: Ident,
        ty: Type,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeAlias {
    pub name: Ident,
    pub type_parameters: Vec<TypeParameter>,
    pub ty: Type,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Struct {
    pub name: Ident,
    pub opaque: bool,
    pub type_parameters: Vec<TypeParameter>,
    pub scopes: Vec<Ident>,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeParameter {
    pub name: Ident,
    pub owner: bool,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: Ident,
    pub ty: Type,
    pub default: Option<Expression>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enum {
    pub name: Ident,
    pub type_parameters: Vec<TypeParameter>,
    pub variants: Vec<EnumVariant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumVariant {
    pub name: Ident,
    pub payload: Vec<Type>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Primitive {
    Int,
    Str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrimitiveDeclaration {
    pub name: Ident,
    pub primitive: Primitive,
    pub scope: Option<Ident>,
    pub refinements: Vec<Refinement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refinement {
    pub kind: RefinementKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefinementKind {
    Range {
        start: IntegerLiteral,
        end: IntegerLiteral,
        inclusive: bool,
    },
    Set(Vec<Literal>),
    Predicate(Path),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub name: Ident,
    pub type_parameters: Vec<TypeParameter>,
    pub parameters: Vec<Parameter>,
    pub result: Option<Type>,
    /// Compile-time family, version, variant and result system of a package factory.
    pub package: Option<Box<[StringLiteral; 4]>>,
    pub body: Block,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub name: Ident,
    pub ty: Type,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub statements: Vec<Statement>,
    pub tail: Option<Box<Expression>>,
    pub span: Span,
    /// Contains recovery nodes or a missing closing delimiter; never executable.
    pub incomplete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub kind: StatementKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementKind {
    /// An unknown statement fragment, retained only by recoverable analysis.
    Recovery {
        binding: Option<RecoveredBinding>,
    },
    Let {
        name: Ident,
        ty: Option<Type>,
        value: Expression,
    },
    Expression(Expression),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredBinding {
    pub name: Ident,
    pub ty: Option<Type>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type {
    pub kind: TypeKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeKind {
    Named {
        path: Path,
        arguments: Vec<Type>,
    },
    List(Box<Type>),
    Function {
        parameters: Vec<Type>,
        result: Box<Type>,
        once: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expression {
    pub kind: ExpressionKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpressionKind {
    Let(Block),
    Memoize(Box<Expression>),
    /// Reorder items by a parallel list of reusable primitive keys. Items are
    /// moved, so sorting also supports affine elements without copying them.
    SortByKeys {
        items: Box<Expression>,
        keys: Box<Expression>,
    },
    ModuleExports {
        namespace: Path,
        export: Ident,
        mapper: Box<Expression>,
    },
    Compare {
        left: Box<Expression>,
        right: Box<Expression>,
        branches: [Box<Expression>; 3],
    },
    Integer(IntegerLiteral),
    String(StringLiteral),
    Path(Path),
    Specialize {
        function: Path,
        arguments: Vec<Type>,
    },
    Fold {
        items: Box<Expression>,
        initial: Box<Expression>,
        step: Box<Expression>,
    },
    Call {
        callee: Path,
        arguments: Vec<Expression>,
    },
    Apply {
        callee: Box<Expression>,
        arguments: Vec<Expression>,
    },
    Closure {
        parameters: Vec<Parameter>,
        result: Type,
        body: Block,
        once: bool,
    },
    Struct {
        path: Path,
        type_arguments: Vec<Type>,
        fields: Vec<StructField>,
        /// Query-only malformed field fragments; strict parsing rejects these.
        recovery: Vec<Span>,
    },
    List(Vec<Expression>),
    Erase {
        ty: Type,
        value: Box<Expression>,
    },
    Match {
        value: Box<Expression>,
        arms: Vec<MatchArm>,
    },
    Group(Box<Expression>),
    Field {
        value: Box<Expression>,
        fields: Vec<Ident>,
    },
    Concat(Vec<Expression>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructField {
    pub name: Ident,
    pub value: Expression,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub value: Expression,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    Wildcard(Span),
    Path(Path),
    Variant {
        path: Path,
        bindings: Vec<Ident>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Literal {
    Integer(IntegerLiteral),
    String(StringLiteral),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegerLiteral {
    pub source: String,
    pub value: i64,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringLiteral {
    /// Exact source spelling, including quotes and escapes.
    pub source: String,
    pub parts: Vec<StringPart>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StringPart {
    /// Exact source spelling between interpolations, excluding the outer quotes.
    Text {
        source: String,
        span: Span,
    },
    Interpolation {
        path: Path,
        span: Span,
    },
}
