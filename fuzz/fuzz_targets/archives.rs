#![no_main]
use libfuzzer_sys::fuzz_target;
use syrox_engine::{
    acquire::archive::{ArchiveFormat, ArchiveLimits, inspect_archive},
    store::{ContentDigest, Store},
};
fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Some((&selector, data)) = data.split_first() else {
        return;
    };
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let Ok(store) = Store::initialize(directory.path()) else {
        return;
    };
    let digest = ContentDigest::sha256(data);
    let Ok(operation) = store.operation() else {
        return;
    };
    if operation.ingest(data, digest, 64 * 1024).is_err() {
        return;
    }
    let format = if selector % 2 == 0 {
        ArchiveFormat::GzipTar
    } else {
        ArchiveFormat::XzTar
    };
    let limits = ArchiveLimits {
        compressed_bytes: 64 * 1024,
        expanded_bytes: 1024 * 1024,
        file_bytes: 256 * 1024,
        entries: 256,
        decoder_memory_bytes: if selector % 2 == 0 {
            0
        } else {
            8 * 1024 * 1024
        },
    };
    let _ = inspect_archive(&store, digest, format, limits);
});
