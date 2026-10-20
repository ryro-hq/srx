//! Reading, checking and evaluating `.srx` programs.
//!
//! Start with the source pipeline below. Host effects, including acquisition and
//! build execution, belong to `syrox-engine`.
//!
//! # Sources and name resolution
//!
//! [`source`] owns text and the coordinates used by every stage's diagnostics.
//! [`syntax`] parses that text while preserving spans. [`resolver`] then binds
//! names to declarations within the project's source domains. Keep the source
//! set with any spans you intend to inspect.
//!
//! # Checking and evaluation
//!
//! [`checker`] checks types, policy and value consumption, producing a
//! [`checker::CheckedProgram`]. [`evaluator`] uses that program with the same
//! policy and an explicit environment. Its values describe recipes and resources;
//! the engine decides how to realize them.
//!
//! This example stops at checking, so it needs neither a Store nor a build host:
//!
//! ```rust
//! use syrox_lang::{checker, resolver, source::SourceSet, syntax};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut sources = SourceSet::new();
//! sources.add("main.srx", "value Number(int); outputs { answer: Number = Number(42); }")?;
//!
//! let parsed = syntax::parse_sources(&sources).map_err(|errors| format!("{errors:?}"))?;
//! let resolved = resolver::resolve(parsed).map_err(|errors| format!("{errors:?}"))?;
//! let _checked = checker::check(resolved, &checker::CheckPolicy::default())
//!     .map_err(|errors| format!("{errors:?}"))?;
//! # Ok(())
//! # }
//! ```
//!
//! # Editor snapshots and formatting
//!
//! [`analysis`] answers queries against snapshots, including incomplete text.
//! Those partial facts help editing; evaluation still requires a checked program.
//! Keep the snapshot with the query result and check its revision before publishing.
//!
//! [`formatter`] needs complete syntax and checks that formatting preserves tokens.
//! It works on one source without resolving imports or evaluating a project.

pub mod analysis;
pub mod checker;
pub mod diagnostic;
pub mod evaluator;
pub mod formatter;
pub mod line_index;
pub mod resolver;
pub mod source;
pub mod syntax;

/// Maximum bytes per source file.
pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
/// Maximum files in a source set.
pub const MAX_SOURCES: usize = 65_536;
/// Maximum tokens per file, including comments and whitespace.
pub const MAX_TOKENS: usize = 262_144;
/// Maximum nesting depth of delimiters and modules.
pub const MAX_DEPTH: usize = 128;
/// Syntax recursion is bounded separately to fit a two-megabyte editor worker stack.
pub const MAX_SYNTAX_DEPTH: usize = 64;
/// Maximum diagnostics per analysis stage.
pub const MAX_DIAGNOSTICS: usize = 256;
