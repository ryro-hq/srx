//! Consumo de um plano em uma sessão Shell ou instalação Os.
//!
//! A preparação reúne comandos, pacotes e configuração. Shell usa uma sessão
//! temporária; Os mantém gerações e um journal para aplicar ou recuperar a
//! instalação. Cada percurso conserva seus recursos até terminar o fechamento.

pub mod manifest;
pub mod os;
pub mod shell;
