//! Entrada do comando `srx`.
//!
//! `cli` lê os argumentos e chama as operações da engine. `lsp` atende o editor
//! com snapshots da linguagem. A execução interna tem outro binário, em
//! `worker.rs`, para que mudanças na CLI não mudem a identidade do worker.

mod cli;
#[cfg(target_os = "linux")]
#[path = "../elf_release.rs"]
mod elf_release;
#[cfg(target_os = "linux")]
mod lsp;
mod signals;

fn main() -> std::process::ExitCode {
    cli::main()
}
