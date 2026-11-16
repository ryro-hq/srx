use super::{LocalAcquisition, LocalSourceError, check_cancellation, map_store_cancel};
use crate::{
    cancellation::{CancellableReader, Cancellation},
    store::{ContentDigest, MAX_STORE_BLOB_BYTES, RootName, Store},
};
use std::io::Read;

/// Import caller-authorized bytes against an independently selected source pin.
/// Always consumes and verifies this stream, including when the Store already
/// contains the digest. The stream does not change the source URL or lock.
/// Publication occurs only after EOF, the size limit and SHA-256 are verified.
pub fn import_source_stream(
    store: &Store,
    source: impl Read,
    expected: ContentDigest,
    maximum_bytes: u64,
    root: &RootName,
    cancellation: &Cancellation,
) -> Result<LocalAcquisition, LocalSourceError> {
    if maximum_bytes > MAX_STORE_BLOB_BYTES {
        return Err(LocalSourceError::InvalidLimit {
            maximum_bytes,
        });
    }
    check_cancellation(cancellation)?;
    let lease = store.operation()?;
    let object = lease
        .ingest(
            CancellableReader {
                source,
                cancellation,
            },
            expected,
            maximum_bytes,
        )
        .map_err(|error| map_store_cancel(error, cancellation))?;
    check_cancellation(cancellation)?;
    let root = lease.publish_root(root, &[expected])?;
    Ok(LocalAcquisition {
        object,
        cache_hit: false,
        root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoreError;

    #[test]
    fn a_bad_stream_never_publishes_a_root_even_if_the_pin_is_cached() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let pin = ContentDigest::sha256(b"source");
        let cancel = Cancellation::default();
        let root = RootName::new("source").unwrap();
        import_source_stream(&store, &b"source"[..], pin, 6, &root, &cancel).unwrap();
        let bad_root = RootName::new("bad").unwrap();
        assert!(matches!(
            import_source_stream(&store, &b"forged"[..], pin, 6, &bad_root, &cancel),
            Err(LocalSourceError::Store(
                StoreError::DigestMismatch { .. }
            ))
        ));
        assert!(
            !directory
                .path()
                .join("roots/retained/bad")
                .exists()
        );
        assert!(
            store
                .operation()
                .unwrap()
                .verify(pin)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn cancellation_during_a_stream_discards_staging() {
        struct Interrupted<'a> {
            cancellation: &'a Cancellation,
        }
        impl Read for Interrupted<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if buffer.is_empty() {
                    return Ok(0);
                }
                buffer[0] = b'x';
                self.cancellation.cancel();
                Ok(1)
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let cancel = Cancellation::default();
        let root = RootName::new("source").unwrap();
        let expected = ContentDigest::sha256(b"xx");
        assert!(matches!(
            import_source_stream(
                &store,
                Interrupted {
                    cancellation: &cancel
                },
                expected,
                2,
                &root,
                &cancel
            ),
            Err(LocalSourceError::Cancelled)
        ));
        assert!(
            !directory
                .path()
                .join("roots/retained/source")
                .exists()
        );
        assert!(
            store
                .operation()
                .unwrap()
                .verify(expected)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn oversized_and_cancelled_sources_publish_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let root = RootName::new("source").unwrap();
        let pin = ContentDigest::sha256(b"source");
        assert!(
            import_source_stream(
                &store,
                &b"source"[..],
                pin,
                5,
                &root,
                &Cancellation::default()
            )
            .is_err()
        );
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            import_source_stream(&store, &b"source"[..], pin, 6, &root, &cancel),
            Err(LocalSourceError::Cancelled)
        ));
        assert!(
            !directory
                .path()
                .join("roots/retained/source")
                .exists()
        );
        assert!(
            store
                .operation()
                .unwrap()
                .verify(pin)
                .unwrap()
                .is_none()
        );
    }
}
