use std::path::{Component, Path, PathBuf};

use crate::platform::linux::boot::BootId;
use crate::store::ContentDigest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const HEADER: &[u8] = b"syrox-shell-operation-v2\n";
const MAX_METADATA_BYTES: usize = 16 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub(super) enum RecordError {
    #[error("invalid Shell operation record: {0}")]
    Invalid(&'static str),
    #[error("invalid Shell operation metadata: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("invalid Shell snapshot: {0}")]
    Snapshot(#[from] crate::deployment::os::GenerationError),
}

#[derive(Debug)]
pub(super) struct SessionRecord {
    boot: BootId,
    configuration: PathBuf,
    state: Option<PathBuf>,
    cwd: PathBuf,
    #[cfg(test)]
    snapshot: Vec<u8>,
}
impl SessionRecord {
    pub(super) const fn boot(&self) -> &BootId {
        &self.boot
    }
    pub(super) fn configuration(&self) -> &Path {
        &self.configuration
    }
    pub(super) fn state(&self) -> Option<&Path> {
        self.state.as_deref()
    }
    pub(super) fn cwd(&self) -> &Path {
        &self.cwd
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u32,
    boot: BootId,
    configuration: String,
    cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[cfg(test)]
pub(super) fn encode(
    boot: &BootId,
    snapshot: &[u8],
    configuration: &Path,
    cwd: &Path,
) -> Result<Vec<u8>, RecordError> {
    encode_with_state(boot, snapshot, configuration, cwd, None)
}

pub(super) fn encode_with_state(
    boot: &BootId,
    snapshot: &[u8],
    configuration: &Path,
    cwd: &Path,
    state: Option<&Path>,
) -> Result<Vec<u8>, RecordError> {
    validate_snapshot(snapshot)?;
    let metadata = Metadata {
        version: 2,
        boot: boot.clone(),
        configuration: path_text(configuration)?.into(),
        cwd: path_text(cwd)?.into(),
        state: state
            .map(path_text)
            .transpose()?
            .map(str::to_owned),
    };
    validate_metadata(&metadata)?;
    let metadata = serde_json::to_vec(&metadata)?;
    metadata_budget(metadata.len())?;
    let mut bytes = Vec::with_capacity(HEADER.len() + metadata.len() + 1 + snapshot.len());
    bytes.extend_from_slice(HEADER);
    bytes.extend_from_slice(&metadata);
    bytes.push(b'\n');
    bytes.extend_from_slice(snapshot);
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8], pin: ContentDigest) -> Result<SessionRecord, RecordError> {
    if bytes.len() > MAX_METADATA_BYTES + MAX_SNAPSHOT_BYTES {
        return Err(RecordError::Invalid("record exceeds byte bound"));
    }
    if ContentDigest::sha256(bytes) != pin {
        return Err(RecordError::Invalid("record pin mismatch"));
    }
    let body = bytes
        .strip_prefix(HEADER)
        .ok_or(RecordError::Invalid(
            "unsupported record domain or version",
        ))?;
    // Search only the bounded prefix before any JSON parsing or allocation.
    let newline = body
        .iter()
        .take(MAX_METADATA_BYTES - HEADER.len())
        .position(|byte| *byte == b'\n')
        .ok_or(RecordError::Invalid(
            "metadata newline missing or beyond bound",
        ))?;
    metadata_budget(newline)?;
    let metadata_bytes = &body[..newline];
    let metadata: Metadata = serde_json::from_slice(metadata_bytes)?;
    validate_metadata(&metadata)?;
    if serde_json::to_vec(&metadata)? != metadata_bytes {
        return Err(RecordError::Invalid("noncanonical metadata"));
    }
    let snapshot = &body[newline + 1..];
    validate_snapshot(snapshot)?;
    Ok(SessionRecord {
        boot: metadata.boot,
        configuration: metadata.configuration.into(),
        state: metadata.state.map(PathBuf::from),
        cwd: metadata.cwd.into(),
        #[cfg(test)]
        snapshot: snapshot.to_vec(),
    })
}

fn metadata_budget(length: usize) -> Result<(), RecordError> {
    if length > MAX_METADATA_BYTES - HEADER.len() - 1 {
        return Err(RecordError::Invalid(
            "metadata exceeds byte bound",
        ));
    }
    Ok(())
}
fn validate_snapshot(snapshot: &[u8]) -> Result<(), RecordError> {
    if snapshot.is_empty() || snapshot.len() > MAX_SNAPSHOT_BYTES {
        return Err(RecordError::Invalid(
            "snapshot size bound exceeded",
        ));
    }
    crate::deployment::os::ShellSessionManifest::decode_bounded(
        snapshot,
        ContentDigest::sha256(snapshot),
    )?;
    Ok(())
}
fn validate_metadata(metadata: &Metadata) -> Result<(), RecordError> {
    if metadata.version != 2 {
        return Err(RecordError::Invalid(
            "unsupported metadata version",
        ));
    }
    path_text(Path::new(&metadata.configuration))?;
    if let Some(state) = &metadata.state {
        let state = Path::new(state);
        path_text(state)?;
        if crate::execution::configuration::paths_overlap(state, Path::new(&metadata.cwd))
            || crate::execution::configuration::paths_overlap(
                state,
                Path::new(&metadata.configuration),
            )
        {
            return Err(RecordError::Invalid(
                "session state overlaps other resources",
            ));
        }
    }
    let cwd = Path::new(&metadata.cwd);
    path_text(cwd)?;
    if !crate::execution::resources::valid_managed_working_directory(cwd) {
        return Err(RecordError::Invalid(
            "working directory overlaps managed filesystems",
        ));
    }
    Ok(())
}
fn path_text(path: &Path) -> Result<&str, RecordError> {
    let text = path
        .to_str()
        .ok_or(RecordError::Invalid("path is not UTF-8"))?;
    if !path.is_absolute() || text.len() > 4096 || text.contains('\0') {
        return Err(RecordError::Invalid(
            "path must be absolute and bounded",
        ));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => normalized.push(component),
            _ => return Err(RecordError::Invalid("path is not canonical")),
        }
    }
    if normalized.as_os_str() != path.as_os_str() {
        return Err(RecordError::Invalid("path is not canonical"));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt as _;

    fn snapshot() -> Vec<u8> {
        format!(
            concat!(
                "syrox-shell-session-v2\n",
                "{{\"launcher\":{{\"digest\":\"{}\",\"protocol\":1}},",
                "\"outputs\":{{}},\"provenance\":{{}},\"services\":[],\"selections\":[],",
                "\"commands\":{{}},\"exposures\":{{}},\"configs\":{{}},\"processes\":{{}}}}"
            ),
            ContentDigest::sha256(b"launcher bytes")
        )
        .into_bytes()
    }
    fn decode_untrusted(bytes: &[u8]) -> Result<SessionRecord, RecordError> {
        decode(bytes, ContentDigest::sha256(bytes))
    }
    fn envelope(metadata: &str, snapshot: &[u8]) -> Vec<u8> {
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(metadata.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(snapshot);
        bytes
    }

    #[test]
    fn canonical_roundtrip_preserves_raw_snapshot_and_paths_without_filesystem_access() {
        let snapshot = snapshot();
        let configuration = Path::new("/absent/configuration-123");
        let cwd = Path::new("/tmp/declared-work");
        let bytes = encode(&boot(), &snapshot, configuration, cwd).unwrap();
        let record = decode_untrusted(&bytes).unwrap();
        assert_eq!(record.configuration(), configuration);
        assert_eq!(record.cwd(), cwd);
        assert_eq!(record.boot(), &boot());
        assert_eq!(record.snapshot(), snapshot);
        assert_eq!(
            encode(
                &boot(),
                record.snapshot(),
                record.configuration(),
                record.cwd()
            )
            .unwrap(),
            bytes
        );
        assert!(bytes.ends_with(&snapshot));
        assert!(decode(&bytes, ContentDigest::sha256(b"wrong")).is_err());
    }

    #[test]
    fn rejects_unknown_duplicate_noncanonical_versions_and_truncation() {
        let snapshot = snapshot();
        let metadata = r#"{"version":2,"boot":"01234567-89ab-cdef-0123-456789abcdef","configuration":"/config","cwd":"/work"}"#;
        for invalid in [
            metadata.replace("\"version\":2", "\"version\":3"),
            metadata.replace("\"version\":2", "\"version\":2,\"version\":2"),
            metadata.replace("\"version\":2", "\"version\":2,\"extra\":true"),
            format!("{metadata} "),
            r#"{"configuration":"/config","version":2,"boot":"01234567-89ab-cdef-0123-456789abcdef","cwd":"/work"}"#.into(),
        ] {
            assert!(decode_untrusted(&envelope(&invalid, &snapshot)).is_err());
        }
        let bytes = envelope(metadata, &snapshot);
        for end in [
            0,
            HEADER.len() - 1,
            HEADER.len(),
            HEADER.len() + metadata.len(),
            bytes.len() - 1,
        ] {
            assert!(decode_untrusted(&bytes[..end]).is_err());
        }
        let changed = String::from_utf8(bytes).unwrap().replace(
            "syrox-shell-operation-v2",
            "syrox-shell-operation-v1",
        );
        assert!(decode_untrusted(changed.as_bytes()).is_err());
    }

    #[test]
    fn rejects_noncanonical_or_reserved_paths_and_os_snapshot_confusion() {
        let snapshot = snapshot();
        for path in [
            "relative",
            "/x/../config",
            "/x/./config",
            "/x//config",
            "/config/",
            "/x\0y",
        ] {
            assert!(
                encode(
                    &boot(),
                    &snapshot,
                    Path::new(path),
                    Path::new("/work")
                )
                .is_err(),
                "{path:?}"
            );
            let metadata = Metadata {
                version: 2,
                state: None,
                boot: boot(),
                configuration: path.into(),
                cwd: "/work".into(),
            };
            assert!(
                decode_untrusted(&envelope(
                    &serde_json::to_string(&metadata).unwrap(),
                    &snapshot
                ))
                .is_err()
            );
        }
        for cwd in [
            "/",
            "/tmp",
            "/proc",
            "/proc/self",
            "/dev",
            "/dev/pts",
        ] {
            assert!(
                encode(
                    &boot(),
                    &snapshot,
                    Path::new("/config"),
                    Path::new(cwd)
                )
                .is_err()
            );
            let metadata = format!(
                r#"{{"version":2,"boot":"01234567-89ab-cdef-0123-456789abcdef","configuration":"/config","cwd":"{cwd}"}}"#
            );
            assert!(decode_untrusted(&envelope(&metadata, &snapshot)).is_err());
        }
        let invalid_utf8 = PathBuf::from(std::ffi::OsString::from_vec(
            b"/work/\xff".to_vec(),
        ));
        assert!(
            encode(
                &boot(),
                &snapshot,
                Path::new("/config"),
                &invalid_utf8
            )
            .is_err()
        );
        let os = String::from_utf8(snapshot)
            .unwrap()
            .replace("syrox-shell-session-v2", "syrox-generation-v2");
        assert!(
            encode(
                &boot(),
                os.as_bytes(),
                Path::new("/config"),
                Path::new("/work")
            )
            .is_err()
        );
        assert!(
            decode_untrusted(&envelope(
                r#"{"version":2,"boot":"01234567-89ab-cdef-0123-456789abcdef","configuration":"/config","cwd":"/work"}"#,
                os.as_bytes()
            ))
            .is_err()
        );
    }

    #[test]
    fn metadata_and_record_limits_precede_deserialization() {
        assert!(metadata_budget(MAX_METADATA_BYTES - HEADER.len() - 1).is_ok());
        assert!(metadata_budget(MAX_METADATA_BYTES - HEADER.len()).is_err());
        let bytes = envelope(&" ".repeat(MAX_METADATA_BYTES), &snapshot());
        assert!(matches!(
            decode_untrusted(&bytes),
            Err(RecordError::Invalid(
                "metadata newline missing or beyond bound"
            ))
        ));
        // The combined bound is checked before hashing or inspecting the record.
        let bytes = vec![0; MAX_METADATA_BYTES + MAX_SNAPSHOT_BYTES + 1];
        assert!(matches!(
            decode(&bytes, ContentDigest::sha256(b"wrong")),
            Err(RecordError::Invalid("record exceeds byte bound"))
        ));
        let excessive_escaping = format!("/{}", "\u{1}".repeat(4000));
        assert!(matches!(
            encode(
                &boot(),
                &snapshot(),
                Path::new(&excessive_escaping),
                Path::new("/work")
            ),
            Err(RecordError::Invalid(
                "metadata exceeds byte bound"
            ))
        ));
    }

    fn boot() -> BootId {
        BootId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap()
    }

    #[test]
    fn boot_provenance_is_authenticated_and_cannot_be_omitted_or_forged() {
        let snapshot = snapshot();
        let first = encode(
            &boot(),
            &snapshot,
            Path::new("/config"),
            Path::new("/work"),
        )
        .unwrap();
        let next = BootId::parse("11234567-89ab-cdef-0123-456789abcdef").unwrap();
        let second = encode(
            &next,
            &snapshot,
            Path::new("/config"),
            Path::new("/work"),
        )
        .unwrap();
        assert_ne!(
            ContentDigest::sha256(&first),
            ContentDigest::sha256(&second)
        );
        assert!(decode(&second, ContentDigest::sha256(&first)).is_err());
        let text = String::from_utf8(first).unwrap();
        for invalid in [
            text.replace(
                boot().as_str(),
                "00000000-0000-0000-0000-000000000000",
            ),
            text.replace(&format!("\"boot\":\"{}\",", boot().as_str()), ""),
            text.replace(
                "syrox-shell-operation-v2",
                "syrox-shell-operation-v1",
            ),
        ] {
            assert!(decode_untrusted(invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn session_state_hint_is_retained_separately_and_does_not_authorize_cleanup() {
        let snapshot = snapshot();
        let bytes = encode_with_state(
            &boot(),
            &snapshot,
            Path::new("/config"),
            Path::new("/work"),
            Some(Path::new("/private/session-data-one")),
        )
        .unwrap();
        let record = decode(&bytes, ContentDigest::sha256(&bytes)).unwrap();
        assert_eq!(
            record.state(),
            Some(Path::new("/private/session-data-one"))
        );
        assert!(
            encode_with_state(
                &boot(),
                &snapshot,
                Path::new("/config"),
                Path::new("/work"),
                Some(Path::new("/work/state"))
            )
            .is_err()
        );
    }
}
