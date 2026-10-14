//! Fetching an HTTPS source and checking its digest before Store admission.
//!
//! TLS checks the server; the digest checks the bytes. Redirects, reads and
//! cancellation share one acquisition deadline, with limits on size and the
//! number of redirects.

#[cfg(target_os = "linux")]
use std::future::Future;
use std::time::Duration;
#[cfg(target_os = "linux")]
mod dns;

use thiserror::Error;

#[cfg(target_os = "linux")]
use crate::store::StoreStaging;
use crate::store::{
    ContentDigest, MAX_STORE_BLOB_BYTES, RootName, RootPublicationState, Store, StoreError,
    StoreObject,
};

pub const MAX_HTTPS_URL_BYTES: usize = 4096;
pub const MAX_HTTPS_REDIRECTS: u8 = 8;
pub const MAX_HTTPS_DEADLINE_SECONDS: u64 = 300;
pub const MAX_HTTPS_HEADER_BYTES: usize = 16 * 1024;

/// A pure pinned request; the caller's network/egress policy is independent of the digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsSourceRequest {
    url: String,
    digest: ContentDigest,
    maximum_bytes: u64,
}

impl HttpsSourceRequest {
    pub fn new(url: &str, digest: ContentDigest, maximum_bytes: u64) -> Result<Self, HttpsError> {
        validate_https_url(url)?;
        if maximum_bytes > MAX_STORE_BLOB_BYTES {
            return Err(HttpsError::InvalidLimit);
        }
        Ok(Self {
            url: url.to_owned(),
            digest,
            maximum_bytes,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }
}

/// Defaults to no proxy, no automatic decompression, and one 30-second absolute deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpsTransportPolicy {
    pub deadline: Duration,
    pub maximum_redirects: u8,
}

impl Default for HttpsTransportPolicy {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(30),
            maximum_redirects: MAX_HTTPS_REDIRECTS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpsAcquisition {
    object: StoreObject,
    cache_hit: bool,
    root: RootPublicationState,
}

impl HttpsAcquisition {
    pub const fn object(&self) -> StoreObject {
        self.object
    }
    pub const fn cache_hit(&self) -> bool {
        self.cache_hit
    }
    pub const fn root_state(&self) -> RootPublicationState {
        self.root
    }
}

#[derive(Debug, Error)]
pub enum HttpsError {
    #[error("source URL must be bounded HTTPS with a host, no credentials and no fragment")]
    InvalidUrl,
    #[error("invalid HTTPS deadline or redirect limit")]
    InvalidPolicy,
    #[error("source byte limit exceeds the Store maximum")]
    InvalidLimit,
    #[error("verified cached object exceeds the source byte limit")]
    CachedObjectTooLarge,
    #[error("HTTPS transport or TLS validation failed")]
    Transport,
    #[error("host name resolution policy is unsupported: {0}")]
    UnsupportedResolverPolicy(&'static str),
    #[error("host name resolution failed: {0}")]
    Resolution(&'static str),
    #[error("absolute HTTPS deadline elapsed")]
    Deadline,
    #[error("HTTPS acquisition cancelled")]
    Cancelled,
    #[error("HTTPS response status is not successful")]
    ResponseStatus,
    #[error(
        "HTTPS response headers exceed the configured limit or include unsupported content encoding"
    )]
    ResponseHeaders,
    #[error("HTTPS response redirects exceed the configured limit")]
    RedirectLimit,
    #[error("HTTPS redirect has no valid HTTPS target")]
    UnsafeRedirect,
    #[error("transport failed ({primary}) and staging cleanup also failed: {cleanup}")]
    TransportAndCleanup {
        primary: Box<HttpsError>,
        cleanup: StoreError,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub(crate) fn validate_https_url(value: &str) -> Result<url::Url, HttpsError> {
    if value.len() > MAX_HTTPS_URL_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b' ' | b'\\'))
    {
        return Err(HttpsError::InvalidUrl);
    }
    let authority = value
        .strip_prefix("https://")
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .ok_or(HttpsError::InvalidUrl)?;
    if authority.is_empty() {
        return Err(HttpsError::InvalidUrl);
    }
    let url = url::Url::parse(value).map_err(|_| HttpsError::InvalidUrl)?;
    if url.scheme() != "https"
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(HttpsError::InvalidUrl);
    }
    Ok(url)
}

/// Rehashes cache hits, or streams a fully completed TLS response to private staging before
/// publishing it. A durable flat named root is committed under the same shared Store lease.
pub fn acquire_https(
    store: &Store,
    request: &HttpsSourceRequest,
    root_name: &RootName,
    policy: HttpsTransportPolicy,
) -> Result<HttpsAcquisition, HttpsError> {
    acquire_https_with_cancellation(
        store,
        request,
        root_name,
        policy,
        &crate::cancellation::Cancellation::default(),
    )
}

/// Cancellable acquisition; the connection future and staging are owned by
/// this operation and dropped together on cancellation.
pub fn acquire_https_with_cancellation(
    store: &Store,
    request: &HttpsSourceRequest,
    root_name: &RootName,
    policy: HttpsTransportPolicy,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<HttpsAcquisition, HttpsError> {
    #[cfg(target_os = "linux")]
    {
        acquire_https_cancellable(
            store,
            request,
            root_name,
            policy,
            None,
            cancellation,
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
fn acquire_https_impl(
    store: &Store,
    request: &HttpsSourceRequest,
    root_name: &RootName,
    policy: HttpsTransportPolicy,
    test_certificate: Option<rustls::pki_types::CertificateDer<'static>>,
) -> Result<HttpsAcquisition, HttpsError> {
    acquire_https_cancellable(
        store,
        request,
        root_name,
        policy,
        test_certificate,
        &crate::cancellation::Cancellation::default(),
    )
}

#[cfg(target_os = "linux")]
fn check_cancellation(cancellation: &crate::cancellation::Cancellation) -> Result<(), HttpsError> {
    if cancellation.is_cancelled() {
        Err(HttpsError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn acquire_https_cancellable(
    store: &Store,
    request: &HttpsSourceRequest,
    root_name: &RootName,
    policy: HttpsTransportPolicy,
    test_certificate: Option<rustls::pki_types::CertificateDer<'static>>,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<HttpsAcquisition, HttpsError> {
    use std::time::Instant;

    validate_policy(policy)?;
    check_cancellation(cancellation)?;
    let lease = store.operation()?;
    let verified = lease
        .verify_checked(request.digest, MAX_STORE_BLOB_BYTES, || {
            if cancellation.is_cancelled() {
                Err(crate::cancellation::cancellation_io())
            } else {
                Ok(())
            }
        })
        .map_err(|error| {
            if cancellation.is_cancelled()
                && matches!(error, StoreError::Io(ref source) if crate::cancellation::is_cancellation_io(source))
            {
                HttpsError::Cancelled
            } else {
                HttpsError::Store(error)
            }
        })?;
    let (object, cache_hit) = if let Some(object) = verified {
        if object.size() > request.maximum_bytes {
            return Err(HttpsError::CachedObjectTooLarge);
        }
        (object, true)
    } else {
        let start = Instant::now();
        let staging = lease.begin_staging(request.digest, request.maximum_bytes)?;
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return Err(abort_with_error(staging, HttpsError::Transport));
        };
        let staging = runtime.block_on(stream_https(
            &request.url,
            request.maximum_bytes,
            policy,
            test_certificate,
            start,
            cancellation,
            staging,
        ))?;
        drop(runtime);
        if let Err(error) = check_cancellation(cancellation) {
            return Err(abort_with_error(staging, error));
        }
        (staging.finish()?, false)
    };
    // Once the bytes are committed, keep their root publication independent of
    // cancellation; a failed/uncertain root must still be reported by the Store.
    check_cancellation(cancellation)?;
    let root = lease.publish_root(root_name, &[request.digest])?;
    Ok(HttpsAcquisition {
        object,
        cache_hit,
        root,
    })
}

#[cfg(target_os = "linux")]
fn validate_policy(policy: HttpsTransportPolicy) -> Result<(), HttpsError> {
    if policy.deadline.is_zero()
        || policy.deadline > Duration::from_secs(MAX_HTTPS_DEADLINE_SECONDS)
        || policy.maximum_redirects > MAX_HTTPS_REDIRECTS
    {
        return Err(HttpsError::InvalidPolicy);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn stream_https(
    requested_url: &str,
    maximum_bytes: u64,
    policy: HttpsTransportPolicy,
    test_certificate: Option<rustls::pki_types::CertificateDer<'static>>,
    start: std::time::Instant,
    cancellation: &crate::cancellation::Cancellation,
    mut staging: StoreStaging,
) -> Result<StoreStaging, HttpsError> {
    let result = download_https(
        DownloadRequest {
            url: requested_url,
            maximum_bytes,
            policy,
            test_certificate,
            accept: None,
            hosts: None,
        },
        start,
        cancellation,
        |chunk| staging.append(chunk).map_err(HttpsError::from),
    )
    .await;
    match result {
        Ok(()) => Ok(staging),
        Err(error) => Err(abort_with_error(staging, error)),
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct DownloadRequest<'a> {
    pub(crate) url: &'a str,
    pub(crate) maximum_bytes: u64,
    pub(crate) policy: HttpsTransportPolicy,
    pub(crate) test_certificate: Option<rustls::pki_types::CertificateDer<'static>>,
    pub(crate) accept: Option<&'a str>,
    pub(crate) hosts: Option<&'a [&'a str]>,
}

/// The caller explicitly authenticates the origin of these initially unpinned
/// bytes. This does not publish an object or assert a content identity.
#[cfg(target_os = "linux")]
pub(crate) fn download_authenticated(
    request: DownloadRequest<'_>,
    start: std::time::Instant,
    cancellation: &crate::cancellation::Cancellation,
) -> Result<Vec<u8>, HttpsError> {
    let mut bytes = Vec::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| HttpsError::Transport)?;
    runtime.block_on(download_https(
        request,
        start,
        cancellation,
        |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        },
    ))?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
async fn download_https(
    request: DownloadRequest<'_>,
    start: std::time::Instant,
    cancellation: &crate::cancellation::Cancellation,
    mut append: impl FnMut(&[u8]) -> Result<(), HttpsError>,
) -> Result<(), HttpsError> {
    validate_policy(request.policy)?;
    check_cancellation(cancellation)?;
    let DownloadRequest {
        url: requested_url,
        maximum_bytes,
        policy,
        test_certificate,
        accept,
        hosts,
    } = request;
    let mut url = validate_https_url(requested_url)?;
    let mut roots = rustls::RootCertStore::empty();
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        roots
            .add(der.clone())
            .map_err(|_| HttpsError::Transport)?;
    }
    if let Some(certificate) = test_certificate {
        roots
            .add(certificate)
            .map_err(|_| HttpsError::Transport)?;
    }
    // Choose a provider per connection, independent of Cargo feature unification
    // and any process-global provider installed by an embedding application.
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| HttpsError::Transport)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut redirects = 0_u8;
    let mut response = loop {
        if hosts.is_some_and(|hosts| {
            !hosts.contains(&url.host_str().unwrap_or_default())
                || url.port_or_known_default() != Some(443)
        }) {
            return Err(HttpsError::UnsafeRedirect);
        }
        let remaining = policy
            .deadline
            .checked_sub(start.elapsed())
            .ok_or(HttpsError::Deadline)?;
        if remaining.is_zero() {
            return Err(HttpsError::Deadline);
        }
        // Resolve each redirect target under our ownership. Reqwest's
        // default resolver uses blocking getaddrinfo in Tokio's threadpool;
        // dropping its request cannot cancel or settle that worker.
        let host = url.host_str().ok_or(HttpsError::Transport)?;
        let addresses = dns::resolve_host(host, cancellation, start, policy.deadline).await?;
        let builder = reqwest::Client::builder()
            .tls_backend_preconfigured(tls.clone())
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .http1_only()
            .http1_max_headers(32)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .resolve_to_addrs(host, &addresses)
            .user_agent("syrox/0.1");
        let client = builder
            .build()
            .map_err(|_| HttpsError::Transport)?;
        let mut request = client
            .get(url.clone())
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .timeout(remaining);
        if let Some(accept) = accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }
        let response = await_transport(
            request.send(),
            cancellation,
            start,
            policy.deadline,
        )
        .await?;
        check_headers(response.headers())?;
        let status = response.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if redirects >= policy.maximum_redirects {
                return Err(HttpsError::RedirectLimit);
            }
            redirects += 1;
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .filter(|value| value.len() <= MAX_HTTPS_URL_BYTES)
                .ok_or(HttpsError::UnsafeRedirect)?;
            let next = url
                .join(location)
                .map_err(|_| HttpsError::UnsafeRedirect)?;
            url = validate_https_url(next.as_str()).map_err(|_| HttpsError::UnsafeRedirect)?;
            continue;
        }
        if status != 200 {
            return Err(HttpsError::ResponseStatus);
        }
        if response
            .content_length()
            .is_some_and(|length| length > maximum_bytes)
        {
            return Err(HttpsError::Store(StoreError::BlobTooLarge {
                limit: maximum_bytes,
            }));
        }
        break response;
    };
    let mut received = 0_u64;
    loop {
        let Some(chunk) = await_transport(
            response.chunk(),
            cancellation,
            start,
            policy.deadline,
        )
        .await?
        else {
            break;
        };
        received = received.saturating_add(chunk.len() as u64);
        if received > maximum_bytes {
            return Err(HttpsError::Store(StoreError::BlobTooLarge {
                limit: maximum_bytes,
            }));
        }
        append(&chunk)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn await_transport<T>(
    future: impl Future<Output = Result<T, reqwest::Error>>,
    cancellation: &crate::cancellation::Cancellation,
    start: std::time::Instant,
    deadline: Duration,
) -> Result<T, HttpsError> {
    let mut future = Box::pin(future);
    loop {
        check_cancellation(cancellation)?;
        let remaining = deadline
            .checked_sub(start.elapsed())
            .ok_or(HttpsError::Deadline)?;
        if remaining.is_zero() {
            return Err(HttpsError::Deadline);
        }
        if let Ok(result) = tokio::time::timeout(
            remaining.min(Duration::from_millis(50)),
            &mut future,
        )
        .await
        {
            return result.map_err(|error| {
                if error.is_timeout() || start.elapsed() >= deadline {
                    HttpsError::Deadline
                } else {
                    HttpsError::Transport
                }
            });
        }
    }
}

#[cfg(target_os = "linux")]
fn check_headers(headers: &reqwest::header::HeaderMap) -> Result<(), HttpsError> {
    let mut size = 0_usize;
    for (name, value) in headers {
        size = size
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .ok_or(HttpsError::ResponseHeaders)?;
        if size > MAX_HTTPS_HEADER_BYTES {
            return Err(HttpsError::ResponseHeaders);
        }
    }
    if headers
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err(HttpsError::ResponseHeaders);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn abort_with_error(staging: StoreStaging, primary: HttpsError) -> HttpsError {
    match staging.abort() {
        Ok(()) => primary,
        Err(cleanup) => HttpsError::TransportAndCleanup {
            primary: Box::new(primary),
            cleanup,
        },
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        path: std::path::PathBuf,
        store: Store,
    }

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "syrox-https-source-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let store = Store::open(&path).unwrap();
            Self {
                path,
                store,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    fn serve(
        responses: Vec<Vec<u8>>,
    ) -> (
        String,
        rustls::pki_types::CertificateDer<'static>,
        thread::JoinHandle<()>,
    ) {
        serve_delayed(
            responses
                .into_iter()
                .map(|response| (response, Duration::ZERO))
                .collect(),
        )
    }

    fn serve_delayed(
        responses: Vec<(Vec<u8>, Duration)>,
    ) -> (
        String,
        rustls::pki_types::CertificateDer<'static>,
        thread::JoinHandle<()>,
    ) {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = issued.cert.der().clone();
        // Use the same explicit provider as production, including VM builds.
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![issued.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into()),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://localhost:{}/object",
            listener.local_addr().unwrap().port()
        );
        let worker = thread::spawn(move || {
            for (response, delay) in responses {
                let start = std::time::Instant::now();
                let (socket, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && start.elapsed() < Duration::from_secs(3) =>
                        {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                        Err(error) => panic!("TLS test server failed to accept: {error}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(std::sync::Arc::new(config.clone())).unwrap(),
                    socket,
                );
                let mut request = [0_u8; 8192];
                let mut length = 0;
                while length < request.len()
                    && !request[..length]
                        .windows(4)
                        .any(|window| window == b"\r\n\r\n")
                {
                    match stream.read(&mut request[length..]) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => length += read,
                    }
                }
                if delay.is_zero() {
                    let _ = stream.write_all(&response);
                } else {
                    let header_end = response
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map_or(response.len(), |position| position + 4);
                    let _ = stream.write_all(&response[..header_end]);
                    let _ = stream.flush();
                    thread::sleep(delay);
                    let _ = stream.write_all(&response[header_end..]);
                }
                let _ = stream.flush();
            }
        });
        (url, certificate, worker)
    }

    fn response(body: &[u8]) -> Vec<u8> {
        let mut result = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        result.extend_from_slice(body);
        result
    }

    #[test]
    fn initially_unpinned_bytes_use_verified_tls_and_explicit_origin_scope() {
        let body = b"1111111111111111111111111111111111111111";
        let (url, certificate, server) = serve(vec![response(body)]);
        let cancellation = crate::cancellation::Cancellation::default();
        let bytes = download_authenticated(
            DownloadRequest {
                url: &url,
                maximum_bytes: 40,
                policy: HttpsTransportPolicy::default(),
                test_certificate: Some(certificate),
                accept: Some("application/vnd.github.sha"),
                hosts: None,
            },
            std::time::Instant::now(),
            &cancellation,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(bytes, body);
        let result = download_authenticated(
            DownloadRequest {
                url: "https://example.org/unauthorized",
                maximum_bytes: 40,
                policy: HttpsTransportPolicy::default(),
                test_certificate: None,
                accept: None,
                hosts: Some(&["api.github.com", "codeload.github.com"]),
            },
            std::time::Instant::now(),
            &cancellation,
        );
        assert!(matches!(result, Err(HttpsError::UnsafeRedirect)));
    }

    #[test]
    fn rejects_unsafe_urls_and_policy_before_network() {
        let digest = ContentDigest::sha256(b"");
        for value in [
            "http://example.org/x",
            "https://user:pass@example.org/x",
            "https://example.org/x#fragment",
            "https:///x",
            "https://example.org/é",
            "https://example.org/a b",
            "https://example.org/a\\b",
        ] {
            assert!(matches!(
                HttpsSourceRequest::new(value, digest, 1),
                Err(HttpsError::InvalidUrl)
            ));
        }
        let fixture = Fixture::new();
        let request = HttpsSourceRequest::new("https://example.org/x", digest, 0).unwrap();
        assert!(matches!(
            acquire_https(
                &fixture.store,
                &request,
                &RootName::new("x").unwrap(),
                HttpsTransportPolicy {
                    deadline: Duration::ZERO,
                    ..HttpsTransportPolicy::default()
                }
            ),
            Err(HttpsError::InvalidPolicy)
        ));
    }

    #[test]
    fn verified_tls_response_publishes_and_offline_cache_hit_retains_bytes() {
        let fixture = Fixture::new();
        let body = b"verified tls bytes";
        let (url, certificate, server) = serve(vec![response(body)]);
        let request = HttpsSourceRequest::new(
            &url,
            ContentDigest::sha256(body),
            body.len() as u64,
        )
        .unwrap();
        let root = RootName::new("https_source").unwrap();
        let first = acquire_https_impl(
            &fixture.store,
            &request,
            &root,
            HttpsTransportPolicy::default(),
            Some(certificate),
        )
        .unwrap();
        server.join().unwrap();
        assert!(!first.cache_hit());
        assert_eq!(
            first.root_state(),
            RootPublicationState::Published
        );
        let second = acquire_https(
            &fixture.store,
            &request,
            &root,
            HttpsTransportPolicy::default(),
        )
        .unwrap();
        assert!(second.cache_hit());
        assert_eq!(
            second.root_state(),
            RootPublicationState::Existing
        );
        assert_eq!(
            fixture
                .store
                .operation()
                .unwrap()
                .read_verified(request.digest(), body.len() as u64)
                .unwrap()
                .unwrap()
                .as_bytes(),
            body
        );
    }

    #[test]
    fn bundled_roots_do_not_accept_an_unlisted_local_certificate() {
        let fixture = Fixture::new();
        let body = b"untrusted";
        let (url, _certificate, server) = serve(vec![response(body)]);
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(body), 64).unwrap();
        assert!(matches!(
            acquire_https_impl(
                &fixture.store,
                &request,
                &RootName::new("untrusted").unwrap(),
                HttpsTransportPolicy::default(),
                None,
            ),
            Err(HttpsError::Transport)
        ));
        server.join().unwrap();
        assert!(
            !fixture
                .path
                .join("roots/retained/untrusted")
                .exists()
        );
    }

    #[test]
    fn cancellation_during_tls_body_returns_promptly_without_publication() {
        let fixture = Fixture::new();
        let body = b"late response body";
        let (url, certificate, server) =
            serve_delayed(vec![(response(body), Duration::from_secs(2))]);
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(body), 64).unwrap();
        let root = RootName::new("cancelled_https").unwrap();
        let cancellation = crate::cancellation::Cancellation::default();
        let cancel = cancellation.clone();
        let signal = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            cancel.cancel();
        });
        let start = std::time::Instant::now();
        let result = acquire_https_cancellable(
            &fixture.store,
            &request,
            &root,
            HttpsTransportPolicy {
                deadline: Duration::from_secs(5),
                maximum_redirects: 0,
            },
            Some(certificate),
            &cancellation,
        );
        assert!(matches!(result, Err(HttpsError::Cancelled)));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(
            !fixture
                .path
                .join("roots/retained/cancelled_https")
                .exists()
        );
        assert!(
            fixture
                .store
                .operation()
                .unwrap()
                .verify(request.digest())
                .unwrap()
                .is_none()
        );
        signal.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn cancellation_keeps_staging_cleanup_failure_visible() {
        let fixture = Fixture::new();
        let body = b"late cleanup";
        let (url, certificate, server) =
            serve_delayed(vec![(response(body), Duration::from_millis(350))]);
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(body), 64).unwrap();
        let cancellation = crate::cancellation::Cancellation::default();
        let signal = cancellation.clone();
        let trigger = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            signal.cancel();
        });
        crate::platform::linux::fd::fail_next_atomic(
            crate::platform::linux::fd::AtomicFault::CleanupUnlink,
        );
        let result = acquire_https_cancellable(
            &fixture.store,
            &request,
            &RootName::new("cleanup_error").unwrap(),
            HttpsTransportPolicy::default(),
            Some(certificate),
            &cancellation,
        );
        assert!(
            matches!(
                &result,
                Err(HttpsError::TransportAndCleanup { primary, cleanup: StoreError::CleanupUncertain { .. } })
                    if matches!(**primary, HttpsError::Cancelled)
            ),
            "{result:?}"
        );
        trigger.join().unwrap();
        server.join().unwrap();
        assert!(
            !fixture
                .path
                .join("roots/retained/cleanup_error")
                .exists()
        );
    }

    #[test]
    fn root_publication_uncertainty_is_not_relabelled_as_cancellation() {
        let fixture = Fixture::new();
        let bytes = b"already cached";
        let digest = ContentDigest::sha256(bytes);
        fixture
            .store
            .operation()
            .unwrap()
            .ingest(bytes.as_slice(), digest, 64)
            .unwrap();
        let request = HttpsSourceRequest::new("https://example.org/cached", digest, 64).unwrap();
        crate::platform::linux::fd::fail_next_atomic(
            crate::platform::linux::fd::AtomicFault::DirectorySync,
        );
        let result = acquire_https_with_cancellation(
            &fixture.store,
            &request,
            &RootName::new("uncertain_root").unwrap(),
            HttpsTransportPolicy::default(),
            &crate::cancellation::Cancellation::default(),
        );
        assert!(
            matches!(
                &result,
                Err(HttpsError::Store(
                    StoreError::PublicationUncertain { .. }
                ))
            ),
            "{result:?}"
        );
    }

    #[test]
    fn cancellation_during_tls_handshake_drops_the_connection() {
        let fixture = Fixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://localhost:{}/object",
            listener.local_addr().unwrap().port()
        );
        let (connected, ready) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let started = std::time::Instant::now();
            let (socket, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && started.elapsed() < Duration::from_secs(3) =>
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("TLS test server did not accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut socket = socket;
            let mut buffer = [0_u8; 512];
            // Consume the ClientHello and then keep TLS pending.
            assert!(socket.read(&mut buffer).unwrap() > 0);
            connected.send(()).unwrap();
            let start = std::time::Instant::now();
            let closed = loop {
                match socket.read(&mut buffer) {
                    Ok(0) => break true,
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                        break true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break false,
                    Ok(_) => {}
                    Err(error) => panic!("TLS test read failed: {error}"),
                }
            };
            (closed, start.elapsed())
        });
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(b"absent"), 64).unwrap();
        let cancellation = crate::cancellation::Cancellation::default();
        let signal = cancellation.clone();
        let trigger = thread::spawn(move || {
            ready
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            thread::sleep(Duration::from_millis(150));
            signal.cancel();
        });
        let start = std::time::Instant::now();
        assert!(matches!(
            acquire_https_with_cancellation(
                &fixture.store,
                &request,
                &RootName::new("pending_tls").unwrap(),
                HttpsTransportPolicy {
                    deadline: Duration::from_secs(5),
                    maximum_redirects: 0
                },
                &cancellation,
            ),
            Err(HttpsError::Cancelled)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        let (closed, elapsed) = server.join().unwrap();
        assert!(closed && elapsed < Duration::from_secs(1));
        trigger.join().unwrap();
        assert!(
            !fixture
                .path
                .join("roots/retained/pending_tls")
                .exists()
        );
    }

    #[test]
    fn tls_hostname_failure_and_https_only_redirect_leave_no_root() {
        let fixture = Fixture::new();
        let (url, certificate, server) = serve(vec![response(b"unauthorized")]);
        let wrong_host = url.replace("localhost", "127.0.0.1");
        let request = HttpsSourceRequest::new(
            &wrong_host,
            ContentDigest::sha256(b"unauthorized"),
            12,
        )
        .unwrap();
        let root = RootName::new("denied").unwrap();
        assert!(matches!(
            acquire_https_impl(
                &fixture.store,
                &request,
                &root,
                HttpsTransportPolicy::default(),
                Some(certificate)
            ),
            Err(HttpsError::Transport)
        ));
        server.join().unwrap();
        assert!(
            !fixture
                .path
                .join("roots/retained/denied")
                .exists()
        );

        let (url, certificate, server) = serve(vec![
            b"HTTP/1.1 302 Found\r\nLocation: http://example.org/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        ]);
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(b""), 0).unwrap();
        assert!(matches!(
            acquire_https_impl(
                &fixture.store,
                &request,
                &root,
                HttpsTransportPolicy::default(),
                Some(certificate)
            ),
            Err(HttpsError::UnsafeRedirect)
        ));
        server.join().unwrap();
        assert!(
            !fixture
                .path
                .join("roots/retained/denied")
                .exists()
        );
    }

    #[test]
    fn response_limit_and_digest_mismatch_never_publish() {
        let fixture = Fixture::new();
        let (url, certificate, server) = serve(vec![response(b"too long")]);
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(b"too long"), 2).unwrap();
        assert!(matches!(
            acquire_https_impl(
                &fixture.store,
                &request,
                &RootName::new("oversized").unwrap(),
                HttpsTransportPolicy::default(),
                Some(certificate)
            ),
            Err(HttpsError::Store(StoreError::BlobTooLarge { .. }))
        ));
        server.join().unwrap();
        assert!(
            !fixture
                .path
                .join("roots/retained/oversized")
                .exists()
        );

        let (url, certificate, server) = serve(vec![response(b"wrong digest")]);
        let request =
            HttpsSourceRequest::new(&url, ContentDigest::sha256(b"expected"), 100).unwrap();
        assert!(matches!(
            acquire_https_impl(
                &fixture.store,
                &request,
                &RootName::new("mismatch").unwrap(),
                HttpsTransportPolicy::default(),
                Some(certificate)
            ),
            Err(HttpsError::Store(
                StoreError::DigestMismatch { .. }
            ))
        ));
        server.join().unwrap();
        assert!(
            !fixture
                .path
                .join("roots/retained/mismatch")
                .exists()
        );
    }

    #[test]
    fn bounded_https_redirects_and_one_deadline() {
        let fixture = Fixture::new();
        let redirect = b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let (url, certificate, server) = serve(vec![redirect, response(b"redirected")]);
        let request =
            HttpsSourceRequest::new(&url, ContentDigest::sha256(b"redirected"), 10).unwrap();
        assert!(
            !acquire_https_impl(
                &fixture.store,
                &request,
                &RootName::new("redirected").unwrap(),
                HttpsTransportPolicy {
                    deadline: Duration::from_secs(2),
                    ..HttpsTransportPolicy::default()
                },
                Some(certificate)
            )
            .unwrap()
            .cache_hit()
        );
        server.join().unwrap();

        let (url, certificate, server) = serve(vec![b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()]);
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(b"absent"), 6).unwrap();
        assert!(matches!(
            acquire_https_impl(
                &fixture.store,
                &request,
                &RootName::new("limited").unwrap(),
                HttpsTransportPolicy {
                    maximum_redirects: 0,
                    ..HttpsTransportPolicy::default()
                },
                Some(certificate)
            ),
            Err(HttpsError::RedirectLimit)
        ));
        server.join().unwrap();

        let (url, certificate, server) = serve_delayed(vec![(
            response(b"late"),
            Duration::from_millis(350),
        )]);
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(b"late"), 4).unwrap();
        assert!(matches!(
            acquire_https_impl(
                &fixture.store,
                &request,
                &RootName::new("late").unwrap(),
                HttpsTransportPolicy {
                    deadline: Duration::from_millis(100),
                    maximum_redirects: 0
                },
                Some(certificate)
            ),
            Err(HttpsError::Deadline)
        ));
        server.join().unwrap();
        assert!(!fixture.path.join("roots/retained/late").exists());
    }

    #[test]
    fn content_encoding_and_response_headers_are_bounded() {
        let fixture = Fixture::new();
        let invalid_encoding = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec();
        let (url, certificate, server) = serve(vec![invalid_encoding]);
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(b"x"), 1).unwrap();
        let root = RootName::new("encoded").unwrap();
        assert!(matches!(
            acquire_https_impl(
                &fixture.store,
                &request,
                &root,
                HttpsTransportPolicy::default(),
                Some(certificate)
            ),
            Err(HttpsError::ResponseHeaders)
        ));
        server.join().unwrap();

        let big_header = format!(
            "HTTP/1.1 200 OK\r\nX-Padding: {}\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
            "a".repeat(MAX_HTTPS_HEADER_BYTES)
        )
        .into_bytes();
        let (url, certificate, server) = serve(vec![big_header]);
        let request = HttpsSourceRequest::new(&url, ContentDigest::sha256(b"x"), 1).unwrap();
        assert!(matches!(
            acquire_https_impl(
                &fixture.store,
                &request,
                &RootName::new("headers").unwrap(),
                HttpsTransportPolicy::default(),
                Some(certificate)
            ),
            Err(HttpsError::ResponseHeaders)
        ));
        server.join().unwrap();
        assert!(
            !fixture
                .path
                .join("roots/retained/headers")
                .exists()
        );
    }
}
