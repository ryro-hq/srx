//! Record the source and executable identities shared by release and VM jobs.
#[path = "../tests/vm_support/mod.rs"]
pub mod vm_support;

fn main() -> vm_support::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [directory, target] = args.as_slice() else {
        return Err("usage: ci_candidates /absolute/release-directory TARGET".into());
    };
    vm_support::candidate_bundle::record(
        &vm_support::config::root(),
        &std::path::PathBuf::from(directory).canonicalize()?,
        target.to_str().ok_or("invalid target")?,
    )
}
