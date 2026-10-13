//! Acesso aos recursos de Linux usados pela engine.
//!
//! Os handles e descritores ficam com os módulos que os abriram. Uma observação
//! do kernel ajuda a conferir identidade ou estado, mas a autorização para agir
//! continua com a operação que pediu essa observação.

pub mod linux;
