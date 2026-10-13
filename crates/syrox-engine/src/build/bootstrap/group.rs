use crate::build::cancellation::BuildControl;
use crate::result::artifact;
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use super::records::NamedOutput;
use super::{BuildError, MAX_OUTPUT_BYTES};
use crate::store::ContentDigest;

const HEADER: &[u8] = b"syrox-output-group\n";
pub(in crate::build) const MAX_GROUP_BYTES: u64 = 2 * MAX_OUTPUT_BYTES + 4096;

/// A metadata manifest fixes each frame length; payload bytes are read once.
/// The parent independently validates the complete stream before publication.
pub(in crate::build) fn pack(
    roots: &[(&str, &Path)],
    output: &mut impl std::io::Write,
) -> Result<(), BuildError> {
    if roots.is_empty()
        || roots.len() > 9
        || roots[0].0 != "out"
        || roots
            .windows(2)
            .skip(1)
            .any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err(BuildError::Output);
    }
    output.write_all(HEADER)?;
    output.write_all(&[u8::try_from(roots.len()).map_err(|_| BuildError::Output)?])?;
    for &(name, root) in roots {
        if name.is_empty()
            || name.len() > 32
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(BuildError::Output);
        }
        let artifact = artifact::PreparedArtifact::new(root)?;
        output.write_all(&[u8::try_from(name.len()).map_err(|_| BuildError::Output)?])?;
        output.write_all(name.as_bytes())?;
        output.write_all(&artifact.size().to_le_bytes())?;
        artifact.write(output)?;
    }
    Ok(())
}

pub(in crate::build) struct GroupOutput {
    pub admission: crate::store::StoreAdmission,
    pub digest: ContentDigest,
    pub size: u64,
    pub files: usize,
}

/// Validate, hash and write each record directly to Store staging in one pass.
/// Staging names are recoverable but invisible as CAS objects until the entire
/// settled group has been accepted. An incomplete group yields no result.
pub(in crate::build) fn unpack(
    mut framed: impl std::io::Read,
    entries: &BTreeMap<String, String>,
    lease: &crate::store::OperationLease,
    cancellation: &dyn BuildControl,
) -> Result<BTreeMap<String, GroupOutput>, BuildError> {
    cancellation.check()?;
    let mut header = [0; HEADER.len()];
    framed
        .read_exact(&mut header)
        .map_err(|_| BuildError::Output)?;
    if header != HEADER || usize::from(byte(&mut framed)?) != entries.len() || entries.len() > 9 {
        return Err(BuildError::Output);
    }
    let mut outputs = BTreeMap::new();
    if !entries.contains_key("out") {
        return Err(BuildError::Output);
    }
    for (expected, entry) in entries
        .iter()
        .filter(|(name, _)| name.as_str() == "out")
        .chain(
            entries
                .iter()
                .filter(|(name, _)| name.as_str() != "out"),
        )
    {
        let len = usize::from(byte(&mut framed)?);
        if len == 0 || len > 32 {
            return Err(BuildError::Output);
        }
        let mut name = vec![0; len];
        framed
            .read_exact(&mut name)
            .map_err(|_| BuildError::Output)?;
        if name != expected.as_bytes() {
            return Err(BuildError::Output);
        }
        let mut size = [0; 8];
        framed
            .read_exact(&mut size)
            .map_err(|_| BuildError::Output)?;
        let size = u64::from_le_bytes(size);
        if size == 0 || size > MAX_OUTPUT_BYTES {
            return Err(BuildError::Output);
        }
        let mut admission = lease.begin_admission(size)?;
        let reader = AdmittingRead {
            input: framed.by_ref().take(size),
            admission: &mut admission,
            cancellation,
        };
        // Buffer outside the tee so small header reads share one admission/hash
        // update. Every payload byte crosses this reader only once.
        let result = artifact::validate_stream_checked(
            std::io::BufReader::with_capacity(64 * 1024, reader),
            entry,
            cancellation,
        );
        let count = match result {
            Ok(count) if admission.size() == size => count,
            result => {
                admission.abort()?;
                return Err(result
                    .err()
                    .map_or(BuildError::Output, BuildError::from));
            }
        };
        let digest = admission.digest();
        outputs.insert(
            expected.clone(),
            GroupOutput {
                admission,
                digest,
                size,
                files: count,
            },
        );
    }
    if framed.read(&mut [0])? != 0 {
        return Err(BuildError::Output);
    }
    Ok(outputs)
}

struct AdmittingRead<'a, R> {
    input: R,
    admission: &'a mut crate::store::StoreAdmission,
    cancellation: &'a dyn BuildControl,
}
impl<R: std::io::Read> std::io::Read for AdmittingRead<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(crate::cancellation::cancellation_io());
        }
        let read = self.input.read(buffer)?;
        self.admission
            .append(&buffer[..read])
            .map_err(std::io::Error::other)?;
        Ok(read)
    }
}

fn byte(input: &mut impl std::io::Read) -> Result<u8, BuildError> {
    let mut byte = [0];
    input
        .read_exact(&mut byte)
        .map_err(|_| BuildError::Output)?;
    Ok(byte[0])
}

pub(in crate::build) fn named_output(group: &GroupOutput) -> NamedOutput {
    NamedOutput {
        artifact: group.digest,
        files: group.files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn cancellation_during_admission_never_publishes_a_partial_object() {
        struct Cancelling<'a> {
            input: &'a [u8],
            flag: &'a crate::cancellation::Cancellation,
            read: usize,
        }
        impl std::io::Read for Cancelling<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let count = self.input.read(buffer)?;
                self.read += count;
                if self.read > 32 * 1024 {
                    self.flag.cancel();
                }
                Ok(count)
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("output");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("payload"), vec![42; 256 * 1024]).unwrap();
        let mut bytes = Vec::new();
        pack(&[("out", &root)], &mut bytes).unwrap();
        let store = crate::store::Store::initialize(&temp.path().join("store")).unwrap();
        let lease = store.operation().unwrap();
        let flag = super::super::Cancellation::default();
        let mut reader = Cancelling {
            input: &bytes,
            flag: &flag,
            read: 0,
        };
        assert!(matches!(
            unpack(
                &mut reader,
                &BTreeMap::from([("out".into(), String::new())]),
                &lease,
                &flag
            ),
            Err(BuildError::Cancelled)
        ));
        assert!(reader.read < bytes.len());
        let mut encoded = Vec::new();
        artifact::pack(&root, &mut encoded).unwrap();
        assert!(
            lease
                .verify(ContentDigest::sha256(&encoded))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read_dir(temp.path().join("store/objects/sha256/00"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn one_group_yields_independent_validated_artifacts_or_no_result() {
        let temporary = tempfile::tempdir().unwrap();
        let store = crate::store::Store::initialize(&temporary.path().join("store")).unwrap();
        let lease = store.operation().unwrap();
        let cancellation = super::super::Cancellation::default();
        let primary = tempfile::tempdir().unwrap();
        fs::create_dir(primary.path().join("bin")).unwrap();
        let binary = primary.path().join("bin/hello");
        fs::write(&binary, b"program").unwrap();
        fs::set_permissions(binary, fs::Permissions::from_mode(0o755)).unwrap();
        let dev = tempfile::tempdir().unwrap();
        fs::write(dev.path().join("header.h"), b"header").unwrap();
        let mut channel = Vec::new();
        pack(
            &[
                ("out", primary.path()),
                ("dev", dev.path()),
            ],
            &mut channel,
        )
        .unwrap();
        let entries = BTreeMap::from([
            ("dev".into(), String::new()),
            ("out".into(), "bin/hello".into()),
        ]);
        let outputs = unpack(
            channel.as_slice(),
            &entries,
            &lease,
            &cancellation,
        )
        .unwrap();
        assert_eq!(outputs["out"].files, 1);
        for (name, output) in outputs {
            assert!(lease.verify(output.digest).unwrap().is_none());
            let mut encoded = Vec::new();
            artifact::pack(
                if name == "out" {
                    primary.path()
                } else {
                    dev.path()
                },
                &mut encoded,
            )
            .unwrap();
            assert_eq!(output.digest, ContentDigest::sha256(&encoded));
            let published = output.admission.finish().unwrap();
            assert_eq!(published.digest(), output.digest);
            assert_eq!(
                lease
                    .read_verified(output.digest, output.size)
                    .unwrap()
                    .unwrap()
                    .as_bytes(),
                encoded
            );
        }
        assert!(
            unpack(
                &channel[..channel.len() - 1],
                &entries,
                &lease,
                &cancellation
            )
            .is_err()
        );
        let mut extra = channel;
        extra.push(0);
        assert!(unpack(extra.as_slice(), &entries, &lease, &cancellation).is_err());
    }
}
