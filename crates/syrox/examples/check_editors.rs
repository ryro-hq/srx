#[path = "../tests/vm_support/mod.rs"]
pub mod vm_support;

fn main() -> vm_support::Result<()> {
    vm_support::editors::main(&std::env::args().skip(1).collect::<Vec<_>>())
}
