#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::undocumented_unsafe_blocks,
        reason = "tests assert with unwrap and drive raw syscalls; non-test builds keep both lints"
    )
)]
pub mod vm_support;

fn main() {
    if let Err(error) = vm_support::host::main(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("SYROX VM TESTS: {error}");
        std::process::exit(1);
    }
}
