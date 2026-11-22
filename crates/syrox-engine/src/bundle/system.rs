//! Budgeted transport of v3 results and their complete chunk closure.

use super::{BundleError, CancellableRead, check, read_u32};
use crate::{
    cancellation::Cancellation,
    result::{AdmittedResult, MAX_RESULT_MANIFEST_BYTES, ResultManifest, admit_system_result},
    store::{ContentDigest, MAX_ROOT_REFERENCES, RootName, Store, chunked::CHUNK_BYTES},
    system::budget::AdmittedBudget,
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};
use syrox_encoding::formats;

const HEADER: &[u8] = formats::SYSTEM_BUNDLE_LINE.as_bytes();

/// Every object is ordered by its digest, including chunk manifests. The result
/// is pinned separately and travels first. Receipt/source/toolchain closures are
/// deliberately not represented as local builds by this consumption transport.
pub fn export_system_bundle(
    store: &Store,
    root: &RootName,
    manifest_digest: ContentDigest,
    output: &mut impl Write,
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<(), BundleError> {
    check(cancellation)?;
    let admitted = AdmittedResult::open(store, root, manifest_digest, cancellation)?;
    admitted.manifest().check_system_budget(budget)?;
    let objects = object_limits(admitted.manifest())?;
    let bytes = admitted.manifest().encode()?;
    let maximum = transport_limit(budget)?;
    let mut total = HEADER.len() as u64 + 8 + bytes.len() as u64;
    let operation = store.operation()?;
    output.write_all(HEADER)?;
    output.write_all(
        &u32::try_from(bytes.len())
            .expect("bounded manifest")
            .to_le_bytes(),
    )?;
    output.write_all(&bytes)?;
    output.write_all(
        &u32::try_from(objects.len())
            .expect("bounded references")
            .to_le_bytes(),
    )?;
    let mut buffer = vec![0; 64 * 1024];
    for (pin, bound) in objects {
        check(cancellation)?;
        let mut reader = operation
            .open_verified_checked(pin, bound, || {
                cancellation
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())
            })?
            .ok_or(BundleError::Invalid(
                "missing system bundle object",
            ))?;
        charge(&mut total, reader.size(), maximum)?;
        output.write_all(pin.as_bytes())?;
        output.write_all(&reader.size().to_le_bytes())?;
        loop {
            check(cancellation)?;
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count])?;
        }
    }
    Ok(())
}

/// Import only an explicitly authorized result pin and administrator budget.
/// Malformed framing, missing objects, corruption or cancellation cannot publish
/// a result root. Earlier verified objects remain inert and collectible by GC.
pub fn import_system_bundle(
    store: &Store,
    root: &RootName,
    expected_manifest: ContentDigest,
    input: &mut impl Read,
    budget: &AdmittedBudget,
    cancellation: &Cancellation,
) -> Result<AdmittedResult, BundleError> {
    check(cancellation)?;
    let mut header = [0; HEADER.len()];
    input.read_exact(&mut header)?;
    if header != HEADER {
        return Err(BundleError::Invalid(
            "unsupported system bundle framing",
        ));
    }
    let size = u64::from(read_u32(input)?);
    if size > MAX_RESULT_MANIFEST_BYTES {
        return Err(BundleError::Invalid(
            "system manifest exceeds transport limit",
        ));
    }
    let mut bytes = vec![0; usize::try_from(size).expect("bounded manifest")];
    CancellableRead {
        inner: &mut *input,
        cancellation,
    }
    .read_exact(&mut bytes)?;
    if ContentDigest::sha256(&bytes) != expected_manifest {
        return Err(BundleError::Invalid(
            "manifest does not match authorized digest",
        ));
    }
    let manifest = ResultManifest::parse(&bytes)?;
    manifest.check_system_budget(budget)?;
    let objects = object_limits(&manifest)?;
    if usize::try_from(read_u32(input)?).ok() != Some(objects.len()) {
        return Err(BundleError::Invalid(
            "system object count disagrees with manifest",
        ));
    }
    let maximum = transport_limit(budget)?;
    let mut total = HEADER.len() as u64 + 8 + size;
    let operation = store.operation()?;
    for (expected, bound) in objects {
        check(cancellation)?;
        let mut pin = [0; 32];
        input.read_exact(&mut pin)?;
        if &pin != expected.as_bytes() {
            return Err(BundleError::Invalid(
                "system object identity or order disagrees with manifest",
            ));
        }
        let mut length = [0; 8];
        input.read_exact(&mut length)?;
        let length = u64::from_le_bytes(length);
        if length > bound {
            return Err(BundleError::Invalid(
                "system bundle object exceeds its byte limit",
            ));
        }
        charge(&mut total, length, maximum)?;
        let object = operation.ingest(
            CancellableRead {
                inner: input.by_ref().take(length),
                cancellation,
            },
            expected,
            length,
        )?;
        if object.size() != length {
            return Err(BundleError::Invalid(
                "truncated system bundle object",
            ));
        }
    }
    check(cancellation)?;
    if input.read(&mut [0])? != 0 {
        return Err(BundleError::Invalid(
            "trailing system bundle bytes",
        ));
    }
    // No cancellation check after publication: return the real publication state.
    Ok(admit_system_result(
        store,
        root,
        &manifest,
        expected_manifest,
        budget,
        cancellation,
    )?)
}

fn object_limits(manifest: &ResultManifest) -> Result<BTreeMap<ContentDigest, u64>, BundleError> {
    let mut objects = BTreeMap::new();
    for output in manifest.outputs().values() {
        if let Some(chunked) = &output.chunked {
            let descriptor = chunked.decoded()?;
            insert(
                &mut objects,
                output.artifact,
                descriptor.canonical_bytes().len() as u64,
            );
            for (index, pin) in descriptor.chunks().iter().enumerate() {
                let size =
                    (descriptor.size() - index as u64 * CHUNK_BYTES as u64).min(CHUNK_BYTES as u64);
                insert(&mut objects, *pin, size);
            }
        } else {
            insert(
                &mut objects,
                output.artifact,
                crate::result::artifact::MAX_OUTPUT_BYTES,
            );
        }
    }
    if objects.len() as u64 >= MAX_ROOT_REFERENCES {
        return Err(BundleError::Invalid(
            "system object closure exceeds root reference limit",
        ));
    }
    Ok(objects)
}

fn insert(objects: &mut BTreeMap<ContentDigest, u64>, pin: ContentDigest, bound: u64) {
    objects
        .entry(pin)
        .and_modify(|previous| *previous = (*previous).min(bound))
        .or_insert(bound);
}

fn transport_limit(budget: &AdmittedBudget) -> Result<u64, BundleError> {
    // Payload budget plus bounded embedded/CAS manifests and per-object frames.
    budget
        .request()
        .output_bytes
        .checked_add(2 * MAX_RESULT_MANIFEST_BYTES + MAX_ROOT_REFERENCES * 40 + 64)
        .ok_or(BundleError::Invalid(
            "system bundle budget overflows",
        ))
}

fn charge(total: &mut u64, size: u64, maximum: u64) -> Result<(), BundleError> {
    *total = total
        .checked_add(40 + size)
        .filter(|total| *total <= maximum)
        .ok_or(BundleError::Invalid(
            "system bundle exceeds admitted transport budget",
        ))?;
    Ok(())
}
