//! Inventory exact Rust tests and attach existing run evidence, using Cargo only.
#[path = "../tests/vm_support/mod.rs"]
pub mod vm_support;

fn main() -> vm_support::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args
        .next()
        .ok_or("usage: audit_tests EVIDENCE RESULTS_LOG | --snapshot EVIDENCE")?;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    if first == "--snapshot" {
        let evidence = std::path::PathBuf::from(args.next().ok_or("snapshot evidence required")?);
        if args.next().is_some() || evidence.exists() {
            return Err("fresh snapshot evidence required".into());
        }
        vm_support::common::private(&evidence)?;
        let sources = vm_support::snapshot::snapshot(&root, &evidence.join("sources"))?;
        vm_support::common::save(&evidence.join("source-manifest.json"), &sources)?;
        println!("Captured sources: {}", evidence.display());
        return Ok(());
    }
    let evidence = std::path::PathBuf::from(first);
    let results = std::path::PathBuf::from(args.next().ok_or("results log required")?);
    if args.next().is_some() {
        return Err("unexpected inventory argument".into());
    }
    vm_support::inventory::run(&root, &evidence, &results)
}
