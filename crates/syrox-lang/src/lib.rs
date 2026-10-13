//! Leitura, checagem e avaliação dos arquivos `.srx`.
//!
//! O fluxo começa em [`syntax`], resolve os nomes em [`resolver`], checa tipos e
//! uso de valores em [`checker`] e avalia o programa em [`evaluator`]. Os efeitos
//! no host ficam na engine. [`source`] guarda o texto e as coordenadas usadas
//! pelos diagnósticos de todas essas etapas.
//!
//! Para o editor, [`analysis`] trabalha com snapshots e texto ainda incompleto.
//! Esses resultados ajudam a editar; a avaliação recebe um programa checado.
//!
//! ```rust
//! use syrox_lang::{checker, resolver, source::SourceSet, syntax};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut sources = SourceSet::new();
//! sources.add("main.srx", "value Numero(int); outputs { resposta: Numero = Numero(42); }")?;
//!
//! let parsed = syntax::parse_sources(&sources).map_err(|errors| format!("{errors:?}"))?;
//! let resolved = resolver::resolve(parsed).map_err(|errors| format!("{errors:?}"))?;
//! let _checked = checker::check(resolved, &checker::CheckPolicy::default())
//!     .map_err(|errors| format!("{errors:?}"))?;
//! # Ok(())
//! # }
//! ```

pub mod analysis;
pub mod checker;
pub mod diagnostic;
pub mod evaluator;
pub mod formatter;
pub mod line_index;
pub mod resolver;
pub mod source;
pub mod syntax;

/// Limite de bytes por arquivo de fonte.
pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
/// Limite de arquivos num conjunto de fontes.
pub const MAX_SOURCES: usize = 65_536;
/// Limite de tokens por arquivo, incluindo comentários e espaços.
pub const MAX_TOKENS: usize = 262_144;
/// Limite de aninhamento de delimitadores e módulos.
pub const MAX_DEPTH: usize = 128;
/// Limite de diagnósticos por etapa da análise.
pub const MAX_DIAGNOSTICS: usize = 256;
