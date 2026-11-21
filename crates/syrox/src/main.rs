//! The `srx` command entry point.
//!
//! # Dispatching commands
//!
//! Start with [`cli`], which parses arguments, selects configuration and dispatches
//! engine operations. Its command handlers translate results into CLI output and
//! exit status.
//!
//! # Serving the editor
//!
//! [`lsp`] serves editor requests from language snapshots. Its analysis and
//! formatting workers return versioned results that the session checks before
//! publication.
//!
//! Internal execution uses a separate binary, [the worker](../syrox_worker/index.html),
//! so CLI changes do not change the worker's identity. Its entry explains modes
//! and admission; the engine owns the execution protocols.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::undocumented_unsafe_blocks,
        reason = "tests assert with unwrap and drive raw syscalls; non-test builds keep both lints"
    )
)]

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
