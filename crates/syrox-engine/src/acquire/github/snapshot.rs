use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use super::{GithubConfiguration, GithubError, GithubLocator, GithubPin};
use crate::acquire::archive::{MemberKind, parse_member, validate_global_comment};
use crate::{store::ContentDigest, store::RootName, store::Store};

const MAX_COMPRESSED: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_COMPRESSED: u64 = 64 * 1024 * 1024;
const MAX_EXPANDED: u64 = 128 * 1024 * 1024;
const MAX_ENTRIES: usize = 65_536;
const MAX_SNAPSHOTS: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputMode {
    Offline,
    Refresh,
    Fetch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acquire::github::tests::{compressed, member};

    const COMMIT: &str = "1111111111111111111111111111111111111111";

    fn tree(contents: &[u8]) -> Vec<u8> {
        let prefix = format!("repo-{COMMIT}");
        let mut tar = member(&format!("{prefix}/"), b"", b'5');
        tar.extend(member(
            &format!("{prefix}/main.srx"),
            contents,
            b'0',
        ));
        tar
    }

    #[test]
    fn github_archive_rejects_traversal_links_duplicates_roots_and_commit_substitution() {
        let directory = tempfile::tempdir().unwrap();
        for entry in [
            member("../escape", b"", b'0'),
            member("/absolute", b"", b'0'),
            member(&format!("repo-{COMMIT}/link"), b"", b'2'),
            member(&format!("repo-{COMMIT}/hard"), b"", b'1'),
            member(&format!("repo-{COMMIT}/device"), b"", b'3'),
            member(
                &format!("repo-{COMMIT}/main.srx"),
                b"duplicate",
                b'0',
            ),
            member("other/root", b"", b'0'),
        ] {
            let mut tar = tree(b"pub struct P {}");
            tar.extend(entry);
            let mut session = GithubSession::new(
                directory.path(),
                &GithubConfiguration::default(),
                InputMode::Offline,
            );
            assert!(
                session
                    .extract(
                        &compressed(tar),
                        GithubPin::new(COMMIT, [0; 32]).unwrap()
                    )
                    .is_err()
            );
        }
        let mut session = GithubSession::new(
            directory.path(),
            &GithubConfiguration::default(),
            InputMode::Offline,
        );
        let mut wrong = member(
            "pax_global_header",
            b"52 comment=2222222222222222222222222222222222222222\n",
            b'g',
        );
        wrong.extend(tree(b""));
        assert!(matches!(
            session.extract(
                &compressed(wrong),
                GithubPin::new(COMMIT, [0; 32]).unwrap()
            ),
            Err(GithubError::ContentMismatch)
        ));
        let mut trailing = tree(b"");
        trailing.extend_from_slice(&[0; 1024]);
        trailing.push(1);
        assert!(
            session
                .extract(
                    &compressed(trailing),
                    GithubPin::new(COMMIT, [0; 32]).unwrap()
                )
                .is_err()
        );
    }

    #[test]
    fn github_snapshot_budgets_are_cumulative_and_exhaustion_is_terminal() {
        let directory = tempfile::tempdir().unwrap();
        let cache = directory.path().join(".syrox/github");
        let store = Store::initialize(&cache).unwrap();
        let mut pins = Vec::new();
        for text in [b"a", b"b", b"c"] {
            let bytes = compressed(tree(text));
            let digest = ContentDigest::sha256(&bytes);
            store
                .operation()
                .unwrap()
                .ingest(bytes.as_slice(), digest, MAX_COMPRESSED)
                .unwrap();
            pins.push((
                GithubPin::new(COMMIT, *digest.as_bytes()).unwrap(),
                bytes.len() as u64,
            ));
        }
        let locator = GithubLocator::parse("github:example/repo").unwrap();
        for dimension in 0..3 {
            let mut session = GithubSession::new(
                directory.path(),
                &GithubConfiguration::default(),
                InputMode::Offline,
            );
            match dimension {
                0 => session.compressed = MAX_TOTAL_COMPRESSED - pins[0].1 - pins[1].1,
                1 => session.expanded = MAX_EXPANDED - 2 * (tree(b"a").len() as u64 + 1024),
                _ => session.entries = MAX_ENTRIES - 4,
            }
            session.load(&locator, Some(&pins[0].0)).unwrap();
            session.load(&locator, Some(&pins[1].0)).unwrap();
            assert!(session.load(&locator, Some(&pins[2].0)).is_err());
            assert!(matches!(
                session.load(&locator, Some(&pins[0].0)),
                Err(GithubError::FailedSession)
            ));
        }
    }
}

/// Private extraction owned by the loaded graph and any Plan using its assets.
/// The persistent cache contains only content-addressed, retained archive bytes.
#[derive(Debug)]
pub(crate) struct Snapshot {
    _directory: tempfile::TempDir,
    root: PathBuf,
    pub(crate) pin: GithubPin,
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.pin == other.pin
    }
}
impl Eq for Snapshot {}

impl Snapshot {
    pub(crate) fn path(&self) -> &Path {
        &self.root
    }
}

pub(crate) struct GithubSession {
    pub(crate) mode: InputMode,
    configuration: GithubConfiguration,
    cache: PathBuf,
    store: Option<Store>,
    started: Instant,
    resolved: BTreeMap<GithubLocator, GithubPin>,
    snapshots: BTreeMap<(String, String, GithubPin), Arc<Snapshot>>,
    compressed: u64,
    expanded: u64,
    entries: usize,
    failed: bool,
}

impl GithubSession {
    pub(crate) fn new(path: &Path, configuration: &GithubConfiguration, mode: InputMode) -> Self {
        Self {
            mode,
            configuration: configuration.clone(),
            cache: configuration
                .cache
                .clone()
                .unwrap_or_else(|| path.join(".syrox/github")),
            store: None,
            started: Instant::now(),
            resolved: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            compressed: 0,
            expanded: 0,
            entries: 0,
            failed: false,
        }
    }

    pub(crate) fn load(
        &mut self,
        locator: &GithubLocator,
        pinned: Option<&GithubPin>,
    ) -> Result<Arc<Snapshot>, GithubError> {
        if self.failed {
            return Err(GithubError::FailedSession);
        }
        let result = self.load_snapshot(locator, pinned);
        self.failed = result.is_err();
        result
    }

    fn resolve(&mut self, locator: &GithubLocator) -> Result<GithubPin, GithubError> {
        if self.mode != InputMode::Refresh {
            return Err(GithubError::Unpinned(locator.origin.clone()));
        }
        if let Some(pin) = self.resolved.get(locator) {
            return Ok(pin.clone());
        }
        if self.resolved.len() >= MAX_SNAPSHOTS {
            return Err(GithubError::Limit);
        }
        let bytes = self.fetch(
            &locator.commit_url(),
            41,
            Some("application/vnd.github.sha"),
        )?;
        let commit = std::str::from_utf8(&bytes)
            .map_err(|_| GithubError::InvalidCommit)?
            .trim_end_matches('\n');
        let pin = self
            .snapshots
            .iter()
            .find(|((owner, repository, pin), _)| {
                owner == &locator.owner && repository == &locator.repository && pin.commit == commit
            })
            .map(|(_, snapshot)| snapshot.pin.clone())
            .unwrap_or(GithubPin::new(commit, [0; 32])?);
        Ok(pin)
    }

    fn load_snapshot(
        &mut self,
        locator: &GithubLocator,
        pinned: Option<&GithubPin>,
    ) -> Result<Arc<Snapshot>, GithubError> {
        self.check_cancelled()?;
        let mut pin = if let Some(pin) = pinned {
            pin.clone()
        } else {
            self.resolve(locator)?
        };
        let key = |pin: &GithubPin| {
            (
                locator.owner.clone(),
                locator.repository.clone(),
                pin.clone(),
            )
        };
        if let Some(snapshot) = self.snapshots.get(&key(&pin)) {
            if pinned.is_none() {
                self.resolved.insert(locator.clone(), pin);
            }
            return Ok(Arc::clone(snapshot));
        }
        if self.snapshots.len() >= MAX_SNAPSHOTS {
            return Err(GithubError::Limit);
        }
        let maximum_bytes =
            MAX_COMPRESSED.min(MAX_TOTAL_COMPRESSED.saturating_sub(self.compressed));
        if maximum_bytes == 0 {
            return Err(GithubError::Limit);
        }
        let known = pinned.is_some() || self.resolved.contains_key(locator);
        let digest = ContentDigest::from_sha256_hash(pin.archive);
        let lease = self.store()?.operation()?;
        let cached = if known {
            lease.read_verified(digest, maximum_bytes)?
        } else {
            None
        };
        let downloaded;
        let bytes = if let Some(bytes) = &cached {
            bytes.as_bytes()
        } else {
            if self.mode == InputMode::Offline {
                return Err(GithubError::MissingSnapshot(digest.to_string()));
            }
            downloaded = self.fetch(&locator.archive_url(&pin), maximum_bytes, None)?;
            &downloaded
        };
        let acquired = if cached.is_some() {
            digest
        } else {
            ContentDigest::sha256(bytes)
        };
        if known && acquired != digest {
            return Err(GithubError::ContentMismatch);
        }
        self.compressed = self
            .compressed
            .checked_add(bytes.len() as u64)
            .filter(|bytes| *bytes <= MAX_TOTAL_COMPRESSED)
            .ok_or(GithubError::Limit)?;
        pin.archive = *acquired.as_bytes();
        let snapshot = Arc::new(self.extract(bytes, pin.clone())?);
        self.check_cancelled()?;
        let digest = ContentDigest::from_sha256_hash(pin.archive);
        if cached.is_none() {
            lease.ingest(bytes, digest, MAX_COMPRESSED)?;
        }
        self.check_cancelled()?;
        lease.publish_root(
            &RootName::new(format!("github-{digest}")).expect("bounded digest root"),
            &[digest],
        )?;
        self.snapshots
            .insert(key(&pin), Arc::clone(&snapshot));
        if pinned.is_none() {
            self.resolved.insert(locator.clone(), pin);
        }
        Ok(snapshot)
    }

    fn store(&mut self) -> Result<&Store, GithubError> {
        if self.store.is_none() {
            if self.mode == InputMode::Offline && !self.cache.try_exists()? {
                return Err(GithubError::MissingSnapshot(
                    self.cache.display().to_string(),
                ));
            }
            self.store = Some(if self.mode == InputMode::Offline {
                Store::open(&self.cache)?
            } else {
                // Normalize an already validated project spelling (e.g. ../catalog)
                // without granting symlink authority to Store initialization.
                let absolute = std::path::absolute(&self.cache)?;
                let mut normalized = PathBuf::new();
                for part in absolute.components() {
                    match part {
                        std::path::Component::ParentDir => {
                            normalized.pop();
                        }
                        part => normalized.push(part.as_os_str()),
                    }
                }
                Store::initialize(&normalized)?
            });
        }
        Ok(self
            .store
            .as_ref()
            .expect("initialized input store"))
    }

    fn check_cancelled(&self) -> Result<(), GithubError> {
        if self.configuration.cancellation.is_cancelled() {
            Err(GithubError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn fetch(
        &self,
        url: &str,
        maximum_bytes: u64,
        accept: Option<&str>,
    ) -> Result<Vec<u8>, GithubError> {
        self.check_cancelled()?;
        #[cfg(test)]
        if let Some(result) = super::tests::fetch(url, maximum_bytes) {
            return result;
        }
        crate::acquire::https::download_authenticated(
            crate::acquire::https::DownloadRequest {
                url,
                maximum_bytes,
                policy: self.configuration.transport,
                test_certificate: None,
                accept,
                hosts: Some(&["api.github.com", "codeload.github.com"]),
            },
            self.started,
            &self.configuration.cancellation,
        )
        .map_err(|error| {
            if matches!(
                error,
                crate::acquire::https::HttpsError::Cancelled
            ) {
                GithubError::Cancelled
            } else {
                GithubError::Https(error)
            }
        })
    }

    fn extract(&mut self, bytes: &[u8], pin: GithubPin) -> Result<Snapshot, GithubError> {
        let directory = tempfile::Builder::new()
            .prefix("syrox-github-")
            .tempdir()?;
        let limit = MAX_EXPANDED - self.expanded + 1;
        let mut reader = flate2::read::MultiGzDecoder::new(bytes).take(limit);
        let mut header = [0_u8; 512];
        let mut seen = BTreeSet::new();
        let mut root = None;
        let mut count = 0;
        loop {
            self.check_cancelled()?;
            reader.read_exact(&mut header)?;
            if header == [0; 512] {
                reader.read_exact(&mut header)?;
                if header != [0; 512] {
                    return Err(GithubError::InvalidArchive);
                }
                break;
            }
            count += 1;
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err(GithubError::Limit);
            }
            let (path, size, kind) = parse_member(&header, true)?;
            if kind == MemberKind::GlobalComment {
                let comment = validate_global_comment(&mut reader, size, count)?;
                if comment != pin.commit.as_bytes() {
                    return Err(GithubError::ContentMismatch);
                }
                continue;
            }
            if !seen.insert(path.clone()) {
                return Err(GithubError::InvalidArchive);
            }
            let first = path.split('/').next().expect("validated path");
            if root.as_deref().is_some_and(|root| root != first) {
                return Err(GithubError::InvalidArchive);
            }
            if root.is_none() {
                if !first.ends_with(&format!("-{}", pin.commit)) || kind != MemberKind::Directory {
                    return Err(GithubError::InvalidArchive);
                }
                root = Some(first.to_owned());
            }
            if size > MAX_EXPANDED || size > reader.limit() {
                return Err(GithubError::Limit);
            }
            let target = directory.path().join(&path);
            match kind {
                MemberKind::Directory => std::fs::create_dir_all(target)?,
                MemberKind::File => {
                    std::fs::create_dir_all(target.parent().expect("archive member parent"))?;
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(target)?;
                    let mut remaining = size;
                    let mut buffer = [0_u8; 16 * 1024];
                    while remaining > 0 {
                        self.check_cancelled()?;
                        let length = usize::try_from(remaining.min(buffer.len() as u64))
                            .expect("buffer length");
                        reader.read_exact(&mut buffer[..length])?;
                        file.write_all(&buffer[..length])?;
                        remaining -= length as u64;
                    }
                    let padding = usize::try_from((512 - size % 512) % 512).expect("tar padding");
                    reader.read_exact(&mut buffer[..padding])?;
                    if buffer[..padding].iter().any(|b| *b != 0) {
                        return Err(GithubError::InvalidArchive);
                    }
                }
                _ => return Err(GithubError::InvalidArchive),
            }
        }
        loop {
            self.check_cancelled()?;
            let read = reader.read(&mut header)?;
            if read == 0 {
                break;
            }
            if header[..read].iter().any(|b| *b != 0) {
                return Err(GithubError::InvalidArchive);
            }
        }
        if reader.limit() == 0 {
            return Err(GithubError::Limit);
        }
        self.expanded += limit - reader.limit();
        let root = directory
            .path()
            .join(root.ok_or(GithubError::InvalidArchive)?);
        Ok(Snapshot {
            _directory: directory,
            root,
            pin,
        })
    }
}
