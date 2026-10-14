use crate::{execution::journal::SessionId, store::ContentDigest};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

pub(crate) const ENDPOINT: &str = "/syrox/commands/broker.sock";
pub(crate) const MAX_CONTEXT_BYTES: usize = 8192;

/// Public addressing metadata. The broker independently validates the peer,
/// current session authority and selected alias; this digest is not a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProxyContext {
    version: u32,
    session: String,
    index: String,
    endpoint: String,
    endpoint_device: u64,
    endpoint_inode: u64,
    working_directory: String,
}
impl ProxyContext {
    pub(crate) fn new(
        session: &SessionId,
        index: ContentDigest,
        endpoint: crate::platform::linux::fd::FileIdentity,
        working_directory: &Path,
    ) -> io::Result<Self> {
        let working_directory = working_directory.to_str().ok_or_else(invalid)?;
        if working_directory.len() > 4096 {
            return Err(invalid());
        }
        let value = Self {
            version: 2,
            session: session.to_string(),
            index: index.to_string(),
            endpoint: ENDPOINT.into(),
            endpoint_device: endpoint.device,
            endpoint_inode: endpoint.inode,
            working_directory: working_directory.into(),
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn canonical_bytes(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_CONTEXT_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_CONTEXT_BYTES {
            return Err(invalid());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if value.canonical_bytes()? != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
    pub(crate) fn session(&self) -> io::Result<SessionId> {
        SessionId::parse(&self.session).map_err(|_| invalid())
    }
    pub(crate) fn index(&self) -> io::Result<ContentDigest> {
        self.index.parse().map_err(|_| invalid())
    }
    pub(crate) fn endpoint_identity(&self) -> crate::platform::linux::fd::FileIdentity {
        crate::platform::linux::fd::FileIdentity {
            device: self.endpoint_device,
            inode: self.endpoint_inode,
        }
    }
    pub(crate) fn working_directory(&self) -> &Path {
        Path::new(&self.working_directory)
    }
    fn validate(&self) -> io::Result<()> {
        let cwd = self.working_directory();
        if !cwd.is_absolute()
            || self.working_directory.len() > 4096
            || self.working_directory.as_bytes().contains(&0)
            || self
                .working_directory
                .split('/')
                .skip(1)
                .any(|part| matches!(part, "" | "." | ".."))
            || !crate::execution::resources::valid_managed_working_directory(cwd)
            || cwd.starts_with("/syrox")
            || self.version != 2
            || self.endpoint_inode == 0
            || self.endpoint != ENDPOINT
            || self.session()?.to_string() != self.session
        {
            return Err(invalid());
        }
        self.index()?;
        Ok(())
    }
}
fn invalid() -> io::Error {
    io::Error::other("invalid command proxy context")
}

#[cfg(test)]
mod tests {
    use super::{ENDPOINT, MAX_CONTEXT_BYTES, ProxyContext};
    use crate::{execution::journal::SessionId, store::ContentDigest};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;
    #[test]
    fn working_directory_is_public_canonical_bounded_and_not_runtime_private() {
        let session = SessionId::parse(&"1".repeat(32)).unwrap();
        let make = |path: &Path| {
            ProxyContext::new(
                &session,
                ContentDigest::sha256(b"index"),
                crate::platform::linux::fd::FileIdentity {
                    device: 1,
                    inode: 2,
                },
                path,
            )
        };
        for path in [
            "relative",
            "/",
            "/tmp",
            "/proc/self",
            "/dev/pts",
            "/sys/a",
            "/syrox/secrets/s",
            "/work/../other",
            "/work/./a",
            "/work//a",
            "/work/",
        ] {
            assert!(make(Path::new(path)).is_err(), "{path}");
        }
        let limit = format!("/{}", "x".repeat(4095));
        let context = make(Path::new(&limit)).unwrap();
        assert_eq!(
            ProxyContext::decode(&context.canonical_bytes().unwrap())
                .unwrap()
                .working_directory(),
            Path::new(&limit)
        );
        assert!(make(Path::new(&format!("{limit}x"))).is_err());
        assert!(
            make(Path::new(std::ffi::OsStr::from_bytes(
                b"/work/\xff"
            )))
            .is_err()
        );
    }
    #[test]
    fn context_is_canonical_bounded_and_never_redirects_the_broker() {
        let session = SessionId::parse(&"1".repeat(32)).unwrap();
        let endpoint = crate::platform::linux::fd::FileIdentity {
            device: 1,
            inode: 2,
        };
        let context = ProxyContext::new(
            &session,
            ContentDigest::sha256(b"public index"),
            endpoint,
            Path::new("/workspace/project"),
        )
        .unwrap();
        let bytes = context.canonical_bytes().unwrap();
        assert_eq!(ProxyContext::decode(&bytes).unwrap(), context);
        assert_eq!(
            ProxyContext::decode(&bytes)
                .unwrap()
                .endpoint_identity(),
            endpoint
        );
        let text = String::from_utf8(bytes.clone()).unwrap();
        for changed in [
            text.replace(ENDPOINT, "/host/socket"),
            text.replace("\"version\":2", "\"version\":1"),
            text.replace("\"version\":2", "\"version\":2,\"grant\":true"),
            text.replace("\"endpoint_inode\":2", "\"endpoint_inode\":0"),
            format!(" {text}"),
        ] {
            assert!(ProxyContext::decode(changed.as_bytes()).is_err());
        }
        assert!(ProxyContext::decode(&vec![b' '; MAX_CONTEXT_BYTES + 1]).is_err());
    }
}
