#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let _ = syrox_engine::result::ResultManifest::parse(data);
    let _ = syrox_engine::build::BuildProgram::decode(data);
    if let Ok(lock) = serde_json::from_slice::<syrox_engine::catalog::CatalogLock>(data) {
        let _ = lock.encode();
    }
});
