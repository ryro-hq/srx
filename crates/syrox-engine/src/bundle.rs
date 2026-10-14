use std::collections::BTreeSet;
use std::io::{Read, Write};

use thiserror::Error;

use crate::result::{AdmittedResult, ResultError, ResultManifest, admit_result};
use crate::{
    cancellation::Cancellation, store::ContentDigest, store::RootName, store::Store,
    store::StoreError,
};

const HEADER: &[u8] = b"syrox-runtime-bundle-v1\n";
pub const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = crate::result::MAX_RESULT_MANIFEST_BYTES;

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("bundle operation cancelled")]
    Cancelled,
    #[error("invalid runtime bundle: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Result(ResultError),
    #[error(transparent)]
    Store(StoreError),
    #[error(transparent)]
    Io(std::io::Error),
}

impl From<ResultError> for BundleError {
    fn from(error: ResultError) -> Self {
        match error {
            ResultError::Cancelled => Self::Cancelled,
            other => Self::Result(other),
        }
    }
}

impl From<StoreError> for BundleError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Io(ref source) if crate::cancellation::is_cancellation_io(source) => {
                Self::Cancelled
            }
            other => Self::Store(other),
        }
    }
}

impl From<std::io::Error> for BundleError {
    fn from(error: std::io::Error) -> Self {
        if crate::cancellation::is_cancellation_io(&error) {
            Self::Cancelled
        } else {
            Self::Io(error)
        }
    }
}

fn check(cancellation: &Cancellation) -> Result<(), BundleError> {
    cancellation
        .check()
        .map_err(|_| BundleError::Cancelled)
}

/// Export only the manifest and its runtime artifacts. Build receipts, source
/// archives and compiler inventories are deliberately absent from this format.
pub fn export_bundle(
    store: &Store,
    root: &RootName,
    manifest_digest: ContentDigest,
    output: &mut impl Write,
    cancellation: &Cancellation,
) -> Result<(), BundleError> {
    check(cancellation)?;
    let lease = store.operation()?;
    let admitted = AdmittedResult::open(store, root, manifest_digest, cancellation)?;
    let manifest = admitted.manifest().encode()?;
    if manifest.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(BundleError::Invalid(
            "manifest exceeds transport limit",
        ));
    }
    let artifacts = admitted
        .manifest()
        .outputs()
        .values()
        .map(|output| output.artifact)
        .collect::<BTreeSet<_>>();
    output.write_all(HEADER)?;
    output.write_all(
        &u32::try_from(manifest.len())
            .expect("bounded manifest")
            .to_le_bytes(),
    )?;
    output.write_all(&manifest)?;
    output.write_all(
        &u32::try_from(artifacts.len())
            .map_err(|_| BundleError::Invalid("too many artifacts"))?
            .to_le_bytes(),
    )?;
    let mut total = HEADER.len() as u64 + 8 + manifest.len() as u64;
    let mut buffer = vec![0; 64 * 1024];
    for digest in artifacts {
        check(cancellation)?;
        let mut source = lease
            .open_verified_checked(digest, crate::build::MAX_OUTPUT_BYTES, || {
                cancellation
                    .check()
                    .map_err(|_| crate::cancellation::cancellation_io())
            })?
            .ok_or(BundleError::Invalid("missing artifact"))?;
        total = total
            .checked_add(40 + source.size())
            .filter(|size| *size <= MAX_BUNDLE_BYTES)
            .ok_or(BundleError::Invalid("bundle exceeds byte limit"))?;
        output.write_all(digest.as_bytes())?;
        output.write_all(&source.size().to_le_bytes())?;
        loop {
            check(cancellation)?;
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count])?;
        }
    }
    Ok(())
}

/// The pin is supplied by local policy, never learned from the transport.
/// Partial imports may leave unrooted CAS objects for GC; no usable root is
/// published until framing, digests and the complete manifest are validated.
pub fn import_bundle(
    store: &Store,
    root: &RootName,
    expected_manifest: ContentDigest,
    input: &mut impl Read,
    cancellation: &Cancellation,
) -> Result<AdmittedResult, BundleError> {
    check(cancellation)?;
    let lease = store.operation()?;
    let mut header = vec![0; HEADER.len()];
    input.read_exact(&mut header)?;
    if header != HEADER {
        return Err(BundleError::Invalid("unsupported framing"));
    }
    let size = u64::from(read_u32(input)?);
    if size > MAX_MANIFEST_BYTES {
        return Err(BundleError::Invalid(
            "manifest exceeds byte limit",
        ));
    }
    let mut bytes = vec![0; usize::try_from(size).expect("bounded manifest")];
    input.read_exact(&mut bytes)?;
    if ContentDigest::sha256(&bytes) != expected_manifest {
        return Err(BundleError::Invalid(
            "manifest does not match authorized digest",
        ));
    }
    let manifest = ResultManifest::parse(&bytes)?;
    let artifacts = manifest
        .outputs()
        .values()
        .map(|output| output.artifact)
        .collect::<BTreeSet<_>>();
    if usize::try_from(read_u32(input)?).ok() != Some(artifacts.len()) {
        return Err(BundleError::Invalid(
            "artifact count disagrees with manifest",
        ));
    }
    let mut total = HEADER.len() as u64 + 8 + size;
    for expected in artifacts {
        check(cancellation)?;
        let mut digest = [0; 32];
        input.read_exact(&mut digest)?;
        if &digest != expected.as_bytes() {
            return Err(BundleError::Invalid(
                "artifact order or identity disagrees with manifest",
            ));
        }
        let mut length = [0; 8];
        input.read_exact(&mut length)?;
        let length = u64::from_le_bytes(length);
        if length > crate::build::MAX_OUTPUT_BYTES {
            return Err(BundleError::Invalid(
                "artifact exceeds byte limit",
            ));
        }
        total = total
            .checked_add(40 + length)
            .filter(|size| *size <= MAX_BUNDLE_BYTES)
            .ok_or(BundleError::Invalid("bundle exceeds byte limit"))?;
        let frame = input.by_ref().take(length);
        let object = lease
            .ingest(
                CancellableRead {
                    inner: frame,
                    cancellation,
                },
                expected,
                length,
            )
            .map_err(|error| match error {
                StoreError::Io(ref source) if crate::cancellation::is_cancellation_io(source) => {
                    BundleError::Cancelled
                }
                other => BundleError::Store(other),
            })?;
        if object.size() != length {
            return Err(BundleError::Invalid("truncated artifact"));
        }
    }
    check(cancellation)?;
    let mut trailing = [0];
    if input.read(&mut trailing)? != 0 {
        return Err(BundleError::Invalid("trailing bytes"));
    }
    // No cancellation check after durable publication: report the real state.
    Ok(admit_result(
        store,
        root,
        &manifest,
        expected_manifest,
        cancellation,
    )?)
}

fn read_u32(input: &mut impl Read) -> std::io::Result<u32> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

struct CancellableRead<'a, R> {
    inner: R,
    cancellation: &'a Cancellation,
}

impl<R: Read> Read for CancellableRead<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.cancellation
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        self.inner.read(buffer)
    }
}
