//! Lê uma fonte fixada por digest dentro de um diretório autorizado.
//!
//! A URL aponta para os bytes. A permissão para lê-los vem do diretório já aberto,
//! com os componentes conferidos sem seguir symlinks. Um path do projeto não
//! serve como prova de identidade da Store.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::store::{
    ContentDigest, MAX_STORE_BLOB_BYTES, RootName, RootPublicationState, Store, StoreError,
    StoreObject,
};

/// Maximum length of a local source URL, including its `file://` prefix.
pub const MAX_LOCAL_SOURCE_URL_BYTES: usize = 4096;

/// A pure, pinned request. It confers no filesystem authority by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalSourceRequest {
    url: String,
    path: PathBuf,
    digest: ContentDigest,
    maximum_bytes: u64,
}

impl LocalSourceRequest {
    pub fn new(
        url: &str,
        digest: ContentDigest,
        maximum_bytes: u64,
    ) -> Result<Self, LocalSourceError> {
        if maximum_bytes > MAX_STORE_BLOB_BYTES {
            return Err(LocalSourceError::InvalidLimit {
                maximum_bytes,
            });
        }
        let path = parse_file_url(url)?;
        Ok(Self {
            url: url.to_owned(),
            path,
            digest,
            maximum_bytes,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    pub fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }
}

/// An explicitly opened local directory. Only paths beneath its retained descriptor are read.
#[derive(Debug)]
pub struct AuthorizedLocalDirectory {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    directory: crate::platform::linux::fd::OpenedPath,
}

impl AuthorizedLocalDirectory {
    pub fn open(path: &Path) -> Result<Self, LocalSourceError> {
        #[cfg(target_os = "linux")]
        {
            validate_absolute(path)?;
            let directory =
                crate::platform::linux::fd::open_top_directory(path).map_err(map_open_error)?;
            Ok(Self {
                path: path.to_path_buf(),
                directory,
            })
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Acquires a verified local object and durably creates or confirms its flat named root.
/// The shared lease spans cache verification, source access, publication and root publication.
pub fn acquire_local(
    store: &Store,
    authority: &AuthorizedLocalDirectory,
    request: &LocalSourceRequest,
    root_name: &RootName,
) -> Result<LocalAcquisition, LocalSourceError> {
    acquire_local_with_cancellation(
        store,
        authority,
        request,
        root_name,
        &crate::cancellation::Cancellation::default(),
    )
}

pub fn acquire_local_with_cancellation(
    store: &Store,
    authority: &AuthorizedLocalDirectory,
    request: &LocalSourceRequest,
    root_name: &RootName,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<LocalAcquisition, LocalSourceError> {
    #[cfg(target_os = "linux")]
    {
        check_cancellation(cancellation)?;
        let relative = request
            .path
            .strip_prefix(&authority.path)
            .map_err(|_| LocalSourceError::OutsideAuthorizedDirectory)?;
        if relative.as_os_str().is_empty() {
            return Err(LocalSourceError::OutsideAuthorizedDirectory);
        }
        let lease = store.operation()?;
        let verified = lease
            .verify_checked(request.digest, MAX_STORE_BLOB_BYTES, || {
                if cancellation.is_cancelled() {
                    Err(crate::cancellation::cancellation_io())
                } else {
                    Ok(())
                }
            })
            .map_err(|error| map_store_cancel(error, cancellation))?;
        let (object, cache_hit) = if let Some(verified) = verified {
            if verified.size() > request.maximum_bytes {
                return Err(LocalSourceError::CachedObjectTooLarge {
                    limit: request.maximum_bytes,
                });
            }
            (verified, true)
        } else {
            let source =
                crate::platform::linux::fd::open_beneath(authority.directory.fd(), relative, false)
                    .map_err(map_open_error)?;
            if source.metadata().file_type() != crate::platform::linux::fd::FileType::Regular {
                return Err(LocalSourceError::NonRegularSource);
            }
            // Ingest reads one byte beyond the configured limit and requires EOF before finish.
            let reader = crate::cancellation::CancellableReader {
                source: source.into_file(),
                cancellation,
            };
            let object = lease
                .ingest(reader, request.digest, request.maximum_bytes)
                .map_err(|error| map_store_cancel(error, cancellation))?;
            (object, false)
        };
        check_cancellation(cancellation)?;
        let root = lease.publish_root(root_name, &[request.digest])?;
        Ok(LocalAcquisition {
            object,
            cache_hit,
            root,
        })
    }
}

#[cfg(target_os = "linux")]
fn check_cancellation(
    cancellation: &crate::cancellation::Cancellation,
) -> Result<(), LocalSourceError> {
    if cancellation.is_cancelled() {
        Err(LocalSourceError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn map_store_cancel(
    error: StoreError,
    cancellation: &crate::cancellation::Cancellation,
) -> LocalSourceError {
    // Cleanup or publication errors take precedence over the signal.
    if cancellation.is_cancelled()
        && matches!(error, StoreError::Io(ref source) if crate::cancellation::is_cancellation_io(source))
    {
        LocalSourceError::Cancelled
    } else {
        LocalSourceError::Store(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalAcquisition {
    object: StoreObject,
    cache_hit: bool,
    root: RootPublicationState,
}

impl LocalAcquisition {
    pub fn object(&self) -> StoreObject {
        self.object
    }

    pub fn cache_hit(&self) -> bool {
        self.cache_hit
    }

    pub fn root_state(&self) -> RootPublicationState {
        self.root
    }
}

#[derive(Debug, Error)]
pub enum LocalSourceError {
    #[error("local source acquisition cancelled")]
    Cancelled,
    #[error(
        "local source URL must be an absolute file URL with empty authority and a canonical path"
    )]
    InvalidUrl,
    #[error("local source directory must be an absolute path without '.' or '..' components")]
    InvalidAuthority,
    #[error("source path is outside the explicitly authorized directory")]
    OutsideAuthorizedDirectory,
    #[error("local source is not a regular file")]
    NonRegularSource,
    #[error("local source byte limit {maximum_bytes} exceeds the store hard limit")]
    InvalidLimit {
        maximum_bytes: u64,
    },
    #[error("verified cached object exceeds the source request's {limit}-byte limit")]
    CachedObjectTooLarge {
        limit: u64,
    },
    #[error("local source path crosses a symbolic link")]
    SymbolicLink,
    #[error("secure local source traversal is unavailable: {0}")]
    UnsupportedKernel(io::Error),
    #[error("local source I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[cfg(target_os = "linux")]
fn map_open_error(error: crate::platform::linux::fd::OpenError) -> LocalSourceError {
    match error {
        crate::platform::linux::fd::OpenError::Unsupported(source) => {
            LocalSourceError::UnsupportedKernel(source)
        }
        crate::platform::linux::fd::OpenError::Symlink => LocalSourceError::SymbolicLink,
        crate::platform::linux::fd::OpenError::Other(source) => LocalSourceError::Io(source),
    }
}

#[cfg(target_os = "linux")]
fn validate_absolute(path: &Path) -> Result<(), LocalSourceError> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = path.as_os_str().as_bytes();
    if !bytes.starts_with(b"/")
        || bytes.contains(&0)
        || bytes != b"/"
            && bytes
                .split(|byte| *byte == b'/')
                .skip(1)
                .any(|part| part.is_empty() || matches!(part, b"." | b".."))
    {
        return Err(LocalSourceError::InvalidAuthority);
    }
    Ok(())
}

pub(crate) fn parse_file_url(url: &str) -> Result<PathBuf, LocalSourceError> {
    let input = url.as_bytes();
    if input.len() > MAX_LOCAL_SOURCE_URL_BYTES || !input.is_ascii() {
        return Err(LocalSourceError::InvalidUrl);
    }
    // This spelling deliberately refuses nonempty authority, query, fragment and opaque paths.
    let encoded = input
        .strip_prefix(b"file:///")
        .ok_or(LocalSourceError::InvalidUrl)?;
    if encoded.is_empty() || encoded.contains(&b'?') || encoded.contains(&b'#') {
        return Err(LocalSourceError::InvalidUrl);
    }
    let mut decoded = Vec::with_capacity(encoded.len() + 1);
    decoded.push(b'/');
    let mut index = 0;
    while index < encoded.len() {
        let escaped = encoded[index] == b'%';
        let byte = if escaped {
            let pair = encoded
                .get(index + 1..index + 3)
                .ok_or(LocalSourceError::InvalidUrl)?;
            index += 3;
            (hex(pair[0])? << 4) | hex(pair[1])?
        } else {
            let byte = encoded[index];
            index += 1;
            byte
        };
        if byte == 0 || byte == b'\\' || byte.is_ascii_control() || byte == b'/' && escaped {
            return Err(LocalSourceError::InvalidUrl);
        }
        decoded.push(byte);
    }
    let text = String::from_utf8(decoded).map_err(|_| LocalSourceError::InvalidUrl)?;
    if text
        .split('/')
        .skip(1)
        .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(LocalSourceError::InvalidUrl);
    }
    let path = PathBuf::from(text);
    Ok(path)
}

fn hex(byte: u8) -> Result<u8, LocalSourceError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(LocalSourceError::InvalidUrl),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::store::{GcRequest, RootPublicationState};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        path: PathBuf,
        source: PathBuf,
        store: Store,
        authority: AuthorizedLocalDirectory,
    }

    impl Fixture {
        fn new(bytes: &[u8]) -> Self {
            let path = std::env::temp_dir().join(format!(
                "syrox-local-source-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let source = path.join("source.tar");
            fs::write(&source, bytes).unwrap();
            let store_root = path.join("store");
            fs::create_dir(&store_root).unwrap();
            let store = Store::open(&store_root).unwrap();
            let authority = AuthorizedLocalDirectory::open(&path).unwrap();
            Self {
                path,
                source,
                store,
                authority,
            }
        }

        fn request(&self, bytes: &[u8], limit: u64) -> LocalSourceRequest {
            LocalSourceRequest::new(
                &format!("file://{}", self.source.display()),
                ContentDigest::sha256(bytes),
                limit,
            )
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    #[test]
    fn file_url_validation_is_bounded_and_unambiguous() {
        let digest = ContentDigest::sha256(b"x");
        for url in [
            "file://host/tmp/a",
            "file://localhost/tmp/a",
            "file:relative",
            "file:///",
            "file:////tmp/a",
            "file:///tmp//a",
            "file:///tmp/./a",
            "file:///tmp/%2e%2e/a",
            "file:///tmp/a%2fb",
            "file:///tmp/a%5cb",
            "file:///tmp/a%00b",
            "file:///tmp/a%",
            "file:///tmp/a?query",
            "file:///tmp/a#fragment",
            "file:///tmp/é",
        ] {
            assert!(
                matches!(
                    LocalSourceRequest::new(url, digest, 1),
                    Err(LocalSourceError::InvalidUrl)
                ),
                "unexpectedly accepted {url}"
            );
        }
        assert!(matches!(
            LocalSourceRequest::new("file:///tmp/a", digest, MAX_STORE_BLOB_BYTES + 1),
            Err(LocalSourceError::InvalidLimit { .. })
        ));
        assert!(matches!(
            LocalSourceRequest::new(
                &format!("file:///tmp/{}", "x".repeat(4096)),
                digest,
                1
            ),
            Err(LocalSourceError::InvalidUrl)
        ));
        assert_eq!(
            LocalSourceRequest::new("file:///tmp/a%20b", digest, 1)
                .unwrap()
                .path,
            Path::new("/tmp/a b")
        );
    }

    #[test]
    fn local_acquisition_publishes_retained_blob_and_reuses_verified_cache() {
        let bytes = b"pinned upstream bytes";
        let fixture = Fixture::new(bytes);
        let request = fixture.request(bytes, bytes.len() as u64);
        let root = RootName::new("source_a").unwrap();
        let first = acquire_local(
            &fixture.store,
            &fixture.authority,
            &request,
            &root,
        )
        .unwrap();
        assert!(!first.cache_hit());
        assert_eq!(
            first.root_state(),
            RootPublicationState::Published
        );
        assert_eq!(first.object().digest(), request.digest());
        fs::remove_file(&fixture.source).unwrap();
        let second = acquire_local(
            &fixture.store,
            &fixture.authority,
            &request,
            &root,
        )
        .unwrap();
        assert!(second.cache_hit());
        assert_eq!(
            second.root_state(),
            RootPublicationState::Existing
        );
        let mut maintenance = fixture.store.maintenance().unwrap();
        assert!(
            maintenance
                .garbage_collect(&GcRequest {
                    collect: true,
                    ..GcRequest::default()
                })
                .unwrap()
                .removed_objects
                .is_empty()
        );
    }

    #[test]
    fn pre_cancelled_local_acquisition_does_not_publish() {
        let fixture = Fixture::new(b"source");
        let request = fixture.request(b"source", 6);
        let cancellation = crate::cancellation::Cancellation::default();
        cancellation.cancel();
        assert!(matches!(
            acquire_local_with_cancellation(
                &fixture.store,
                &fixture.authority,
                &request,
                &RootName::new("cancelled_local").unwrap(),
                &cancellation,
            ),
            Err(LocalSourceError::Cancelled)
        ));
        assert!(
            !fixture
                .path
                .join("store/roots/retained/cancelled_local")
                .exists()
        );
    }

    #[test]
    fn source_access_requires_explicit_directory_and_rejects_symlinks() {
        let fixture = Fixture::new(b"x");
        let root = RootName::new("source").unwrap();
        let request = fixture.request(b"x", 1);
        let narrower = AuthorizedLocalDirectory::open(&fixture.path.join("store")).unwrap();
        for path in [
            Path::new("relative"),
            Path::new("/tmp/./source"),
            Path::new("/tmp/../source"),
            Path::new("/tmp//source"),
            Path::new("/tmp/source/"),
        ] {
            assert!(matches!(
                AuthorizedLocalDirectory::open(path),
                Err(LocalSourceError::InvalidAuthority)
            ));
        }
        assert!(matches!(
            acquire_local(&fixture.store, &narrower, &request, &root),
            Err(LocalSourceError::OutsideAuthorizedDirectory)
        ));
        let link = fixture.path.join("linked.tar");
        symlink(&fixture.source, &link).unwrap();
        let request = LocalSourceRequest::new(
            &format!("file://{}", link.display()),
            ContentDigest::sha256(b"x"),
            1,
        )
        .unwrap();
        assert!(matches!(
            acquire_local(
                &fixture.store,
                &fixture.authority,
                &request,
                &root
            ),
            Err(LocalSourceError::SymbolicLink)
        ));
        let directory_request = LocalSourceRequest::new(
            &format!("file://{}", fixture.path.join("store").display()),
            ContentDigest::sha256(b"x"),
            1,
        )
        .unwrap();
        assert!(matches!(
            acquire_local(
                &fixture.store,
                &fixture.authority,
                &directory_request,
                &root
            ),
            Err(LocalSourceError::NonRegularSource)
        ));
    }

    #[test]
    fn mismatches_limits_and_corrupt_cache_do_not_publish_roots() {
        let fixture = Fixture::new(b"actual");
        let root = RootName::new("source").unwrap();
        let request = fixture.request(b"expected", 6);
        assert!(matches!(
            acquire_local(
                &fixture.store,
                &fixture.authority,
                &request,
                &root
            ),
            Err(LocalSourceError::Store(
                StoreError::DigestMismatch { .. }
            ))
        ));
        let request = fixture.request(b"actual", 5);
        assert!(matches!(
            acquire_local(
                &fixture.store,
                &fixture.authority,
                &request,
                &root
            ),
            Err(LocalSourceError::Store(
                StoreError::BlobTooLarge { .. }
            ))
        ));
        assert!(
            !fixture
                .path
                .join("store/roots/retained/source")
                .exists()
        );

        let request = fixture.request(b"actual", 6);
        acquire_local(
            &fixture.store,
            &fixture.authority,
            &request,
            &root,
        )
        .unwrap();
        let object = fixture
            .path
            .join("store/objects/sha256")
            .join(&request.digest().to_string()[..2])
            .join(request.digest().to_string());
        fs::write(object, b"corrupt").unwrap();
        fs::remove_file(&fixture.source).unwrap();
        assert!(matches!(
            acquire_local(
                &fixture.store,
                &fixture.authority,
                &request,
                &root
            ),
            Err(LocalSourceError::Store(
                StoreError::CorruptObject { .. }
            ))
        ));
    }

    #[test]
    fn maintenance_contention_prevents_acquisition() {
        let fixture = Fixture::new(b"x");
        let maintenance = fixture.store.maintenance().unwrap();
        assert!(matches!(
            acquire_local(
                &fixture.store,
                &fixture.authority,
                &fixture.request(b"x", 1),
                &RootName::new("source").unwrap()
            ),
            Err(LocalSourceError::Store(StoreError::Busy))
        ));
        drop(maintenance);
    }

    #[test]
    fn empty_source_and_cached_limit_are_enforced_without_source_access() {
        let fixture = Fixture::new(b"");
        let empty = fixture.request(b"", 0);
        acquire_local(
            &fixture.store,
            &fixture.authority,
            &empty,
            &RootName::new("empty").unwrap(),
        )
        .unwrap();

        fs::write(&fixture.source, b"two").unwrap();
        let request = fixture.request(b"two", 3);
        acquire_local(
            &fixture.store,
            &fixture.authority,
            &request,
            &RootName::new("original").unwrap(),
        )
        .unwrap();
        fs::remove_file(&fixture.source).unwrap();
        let too_small = fixture.request(b"two", 2);
        assert!(matches!(
            acquire_local(
                &fixture.store,
                &fixture.authority,
                &too_small,
                &RootName::new("unpublished").unwrap()
            ),
            Err(LocalSourceError::CachedObjectTooLarge {
                limit: 2
            })
        ));
        assert!(
            !fixture
                .path
                .join("store/roots/retained/unpublished")
                .exists()
        );
    }
}
