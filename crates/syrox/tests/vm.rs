pub mod vm_support;

fn main() {
    if let Err(error) = vm_support::host::main(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("SYROX VM TESTS: {error}");
        std::process::exit(1);
    }
}
