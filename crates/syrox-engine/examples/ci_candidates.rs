//! Bind release bytes to their sources without compiling the microVM SDK.
#[path = "../../syrox/tests/vm_support/candidate_bundle.rs"]
pub mod candidate_bundle;
#[path = "../../syrox/tests/vm_support/common.rs"]
pub mod common;
#[path = "../../syrox/tests/vm_support/snapshot.rs"]
pub mod snapshot;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [directory, target] = args.as_slice() else {
        return Err("usage: ci_candidates /absolute/release-directory TARGET".into());
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    candidate_bundle::record(
        &root,
        &std::path::PathBuf::from(directory).canonicalize()?,
        target.to_str().ok_or("invalid target")?,
    )
}
