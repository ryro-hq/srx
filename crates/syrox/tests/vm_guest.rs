pub mod vm_support;

fn main() {
    if let Err(error) = vm_support::guest::main(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("SYROX VM GUEST: {error}");
        std::process::exit(1);
    }
}
