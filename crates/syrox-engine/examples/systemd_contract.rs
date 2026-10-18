//! Export the host interface specification for catalog maintenance and CI.
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        serde_json::to_string_pretty(&syrox_engine::systemd::interface_contract()?)?
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("systemd interface contracts require the Linux engine");
    std::process::exit(1);
}
