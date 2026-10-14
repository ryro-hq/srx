use crate::cancellation::OperationControl;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::io::SeekFrom;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

pub(crate) const MAX_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ArtifactError {
    #[error("invalid, missing, or oversized build output")]
    Output,
    #[error("artifact operation cancelled")]
    Cancelled,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub(crate) fn relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 255
        && path.split('/').count() <= 32
        && path.split('/').all(|part| {
            !part.is_empty()
                && !matches!(part, "." | "..")
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-@,".contains(&b))
        })
}

pub(crate) const HEADER: &[u8] = b"syrox-artifact\n";
pub(crate) const MAX_FILES: usize = 16_384;

/// A borrowed, fully validated record for fixture assertions.
#[derive(Clone, Copy, Debug)]
#[cfg(test)]
pub(crate) struct ArtifactFile<'a> {
    pub path: &'a str,
    pub executable: bool,
    pub bytes: &'a [u8],
    pub alias: Option<&'a str>,
}

/// Regular files and contained relative aliases share one encoding.
#[cfg(test)]
pub(crate) fn pack(root: &Path, output: &mut impl std::io::Write) -> Result<(), ArtifactError> {
    PreparedArtifact::new(root)?.write(output)
}

/// A metadata-only manifest fixes the frame length without reading any payload.
/// Emission reopens each regular file beneath the pinned root and compares its
/// identity, size and mode with the manifest before reading it exactly once.
pub(crate) struct PreparedArtifact {
    opened: crate::platform::linux::fd::OpenedPath,
    files: Vec<(std::path::PathBuf, Option<String>, fs::Metadata)>,
    size: u64,
}

impl PreparedArtifact {
    pub(crate) fn new(root: &Path) -> Result<Self, ArtifactError> {
        let opened = crate::platform::linux::fd::open_top_directory(root)
            .map_err(|_| ArtifactError::Output)?;
        let mut files = enumerate(root)?;
        // Empty directories have no records in this format. Refuse before
        // emitting a frame that the admission validator would always reject.
        if files.is_empty() {
            return Err(ArtifactError::Output);
        }
        let mut size = HEADER.len() as u64 + 4;
        for (path, alias, metadata) in &mut files {
            *path = path
                .strip_prefix(root)
                .map_err(|_| ArtifactError::Output)?
                .to_owned();
            let path_length = path.to_str().ok_or(ArtifactError::Output)?.len() as u64;
            let payload = alias
                .as_ref()
                .map_or(metadata.len(), |target| target.len() as u64);
            size = size
                .checked_add(11 + path_length)
                .and_then(|size| size.checked_add(payload))
                .filter(|size| *size <= MAX_OUTPUT_BYTES)
                .ok_or(ArtifactError::Output)?;
        }
        Ok(Self {
            opened,
            files,
            size,
        })
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn write(&self, output: &mut impl std::io::Write) -> Result<(), ArtifactError> {
        let mut output = BoundedWriter {
            inner: output,
            written: 0,
        };
        output.append(HEADER)?;
        output.append(
            &u32::try_from(self.files.len())
                .map_err(|_| ArtifactError::Output)?
                .to_le_bytes(),
        )?;
        for (relative, alias, expected) in &self.files {
            let path = relative.to_str().ok_or(ArtifactError::Output)?;
            if let Some(target) = alias {
                let target_path = resolve_alias(path, target).ok_or(ArtifactError::Output)?;
                let opened_target = crate::platform::linux::fd::open_beneath(
                    self.opened.fd(),
                    Path::new(&target_path),
                    false,
                )
                .map_err(|_| ArtifactError::Output)?;
                if opened_target.metadata().file_type()
                    != crate::platform::linux::fd::FileType::Regular
                    || opened_target.metadata().links() != 1
                {
                    return Err(ArtifactError::Output);
                }
                append_record(&mut output, path, 2, target.as_bytes())?;
                continue;
            }
            let opened_file =
                crate::platform::linux::fd::open_beneath(self.opened.fd(), relative, false)
                    .map_err(|_| ArtifactError::Output)?;
            if opened_file.metadata().file_type() != crate::platform::linux::fd::FileType::Regular {
                return Err(ArtifactError::Output);
            }
            let metadata = opened_file.metadata();
            if metadata.links() != 1
                || metadata.mode() != expected.mode()
                || metadata.identity().device != expected.dev()
                || metadata.identity().inode != expected.ino()
                || metadata.size() != expected.len()
            {
                return Err(ArtifactError::Output);
            }
            let size = metadata.size();
            let kind = u8::from(metadata.mode() & 0o111 != 0);
            output.reserve(
                (11 + path.len() as u64)
                    .checked_add(size)
                    .ok_or(ArtifactError::Output)?,
            )?;
            output.append(
                &u16::try_from(path.len())
                    .map_err(|_| ArtifactError::Output)?
                    .to_le_bytes(),
            )?;
            output.append(path.as_bytes())?;
            output.append(&[kind])?;
            output.append(&size.to_le_bytes())?;
            let copied = std::io::copy(
                &mut opened_file.into_file().take(size + 1),
                &mut output,
            )?;
            if copied != size {
                return Err(ArtifactError::Output);
            }
        }
        // The receiver still validates the entire encoding and alias expansion
        // before publication; a failed worker may have sent only a partial stream.
        if output.written != self.size {
            return Err(ArtifactError::Output);
        }
        Ok(())
    }
}

fn enumerate(
    root: &Path,
) -> Result<Vec<(std::path::PathBuf, Option<String>, fs::Metadata)>, ArtifactError> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            visited += 1;
            if visited > MAX_FILES {
                return Err(ArtifactError::Output);
            }
            let entry = entry?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| ArtifactError::Output)?;
            if !relative.to_str().is_some_and(relative_path) {
                return Err(ArtifactError::Output);
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.mode() & 0o7000 != 0 {
                return Err(ArtifactError::Output);
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() && metadata.nlink() == 1 {
                files.push((path, None, metadata));
            } else if metadata.is_symlink() {
                let target = fs::read_link(&path)?;
                let target = target.to_str().ok_or(ArtifactError::Output)?;
                if resolve_alias(
                    relative.to_str().ok_or(ArtifactError::Output)?,
                    target,
                )
                .is_none()
                {
                    return Err(ArtifactError::Output);
                }
                files.push((path, Some(target.to_owned()), metadata));
            } else {
                return Err(ArtifactError::Output);
            }
        }
    }
    // The on-disk protocol orders raw UTF-8 path bytes, not Path's component
    // ordering (`types.h` must precede `types/wint_t.h`). All relative paths
    // have already passed the canonical ASCII grammar above.
    files.sort_by(|left, right| {
        use std::os::unix::ffi::OsStrExt as _;
        left.0
            .as_os_str()
            .as_bytes()
            .cmp(right.0.as_os_str().as_bytes())
    });
    Ok(files)
}

struct BoundedWriter<'a, W> {
    inner: &'a mut W,
    written: u64,
}

impl<W: std::io::Write> BoundedWriter<'_, W> {
    fn reserve(&self, bytes: u64) -> Result<(), ArtifactError> {
        if self
            .written
            .checked_add(bytes)
            .is_none_or(|sum| sum > MAX_OUTPUT_BYTES)
        {
            return Err(ArtifactError::Output);
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), ArtifactError> {
        self.reserve(bytes.len() as u64)?;
        self.inner.write_all(bytes)?;
        self.written += bytes.len() as u64;
        Ok(())
    }
}

impl<W: std::io::Write> std::io::Write for BoundedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let available = usize::try_from(MAX_OUTPUT_BYTES - self.written)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        if available == 0 {
            return Err(std::io::Error::other(
                "artifact exceeds output bound",
            ));
        }
        let wrote = self.inner.write(&bytes[..available])?;
        self.written += wrote as u64;
        Ok(wrote)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn append_record(
    output: &mut BoundedWriter<'_, impl std::io::Write>,
    path: &str,
    kind: u8,
    content: &[u8],
) -> Result<(), ArtifactError> {
    output.reserve(11 + path.len() as u64 + content.len() as u64)?;
    output.append(
        &u16::try_from(path.len())
            .map_err(|_| ArtifactError::Output)?
            .to_le_bytes(),
    )?;
    output.append(path.as_bytes())?;
    output.append(&[kind])?;
    output.append(&(content.len() as u64).to_le_bytes())?;
    output.append(content)?;
    Ok(())
}

/// Resolve a relative link without touching the filesystem. A target may
/// traverse parent directories but must end at a canonical path inside this
/// one output; the target file is checked separately and chains are refused.
pub(crate) fn resolve_alias(path: &str, target: &str) -> Option<String> {
    if target.is_empty() || target.len() > 255 || target.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = path.split('/').collect();
    parts.pop()?;
    for component in target.split('/') {
        match component {
            ".." => {
                parts.pop()?;
            }
            "." | "" => return None,
            name if relative_path(name) && !name.contains('/') => parts.push(name),
            _ => return None,
        }
    }
    let resolved = parts.join("/");
    relative_path(&resolved).then_some(resolved)
}

/// Re-validate bytes crossing out of the sandbox; the worker's success is not
/// sufficient evidence of a valid artifact. The expected entry must be executable.
#[cfg(test)]
pub(crate) fn validate(bytes: &[u8], expected_entry: &str) -> Result<usize, ArtifactError> {
    Ok(decode(bytes, expected_entry)?.len())
}

/// Validate a complete Artifact without buffering its file contents. The
/// archive and expanded-view budgets are independent: aliases count the size
/// of their resolved target again.
#[cfg(test)]
pub(crate) fn validate_stream(
    input: impl std::io::Read,
    expected_entry: &str,
) -> Result<usize, ArtifactError> {
    Ok(scan(input, expected_entry)?.len())
}

pub(crate) fn validate_stream_checked(
    input: impl std::io::Read,
    expected_entry: &str,
    cancellation: &(impl OperationControl + ?Sized),
) -> Result<usize, ArtifactError> {
    let result = scan(
        CancellableRead {
            input,
            cancellation,
        },
        expected_entry,
    );
    if cancellation.is_cancelled() {
        return Err(ArtifactError::Cancelled);
    }
    Ok(result?.len())
}

struct CancellableRead<'a, R, C: OperationControl + ?Sized> {
    input: R,
    cancellation: &'a C,
}

impl<R: std::io::Read, C: OperationControl + ?Sized> std::io::Read for CancellableRead<'_, R, C> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(crate::cancellation::cancellation_io());
        }
        self.input.read(buffer)
    }
}

struct Positioned<R> {
    input: R,
    position: u64,
}

impl<R: std::io::Read> std::io::Read for Positioned<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.input.read(buffer)?;
        self.position += count as u64;
        Ok(count)
    }
}

fn scan(input: impl std::io::Read, expected_entry: &str) -> Result<ArtifactIndex, ArtifactError> {
    let mut input = Positioned {
        input: input.take(MAX_OUTPUT_BYTES + 1),
        position: 0,
    };
    let mut header = [0_u8; HEADER.len()];
    input
        .read_exact(&mut header)
        .map_err(|_| ArtifactError::Output)?;
    if header != HEADER {
        return Err(ArtifactError::Output);
    }
    let count = u32::from_le_bytes(read_fixed::<4>(&mut input)?) as usize;
    if count == 0 || count > MAX_FILES {
        return Err(ArtifactError::Output);
    }
    let mut files = ArtifactIndex {
        paths: String::new(),
        records: Vec::with_capacity(count),
    };
    let mut aliases = Vec::new();
    let mut path_buffer = [0_u8; 255];
    let mut target_buffer = [0_u8; 255];
    for _ in 0..count {
        let len = usize::from(u16::from_le_bytes(read_fixed::<2>(&mut input)?));
        if len == 0 || len > 255 {
            return Err(ArtifactError::Output);
        }
        let path = &mut path_buffer[..len];
        input
            .read_exact(path)
            .map_err(|_| ArtifactError::Output)?;
        let path = std::str::from_utf8(path).map_err(|_| ArtifactError::Output)?;
        if !relative_path(path)
            || files
                .records
                .last()
                .is_some_and(|previous| path <= files.path(previous))
        {
            return Err(ArtifactError::Output);
        }
        let mut ancestor = path;
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            if files.find(parent).is_some() {
                return Err(ArtifactError::Output);
            }
            ancestor = parent;
        }
        let kind = read_fixed::<1>(&mut input)?[0];
        if kind > 2 {
            return Err(ArtifactError::Output);
        }
        let size = u64::from_le_bytes(read_fixed::<8>(&mut input)?);
        if size > MAX_OUTPUT_BYTES || size > input.input.limit() {
            return Err(ArtifactError::Output);
        }
        let offset = input.position;
        let alias = if kind == 2 {
            if size == 0 || size > 255 {
                return Err(ArtifactError::Output);
            }
            let target =
                &mut target_buffer[..usize::try_from(size).map_err(|_| ArtifactError::Output)?];
            input
                .read_exact(target)
                .map_err(|_| ArtifactError::Output)?;
            let target = std::str::from_utf8(target).map_err(|_| ArtifactError::Output)?;
            Some(resolve_alias(path, target).ok_or(ArtifactError::Output)?)
        } else {
            let copied = std::io::copy(
                &mut input.by_ref().take(size),
                &mut std::io::sink(),
            )?;
            if copied != size {
                return Err(ArtifactError::Output);
            }
            None
        };
        if let Some(target) = alias {
            aliases.push((files.len(), target));
        }
        let path_start = u32::try_from(files.paths.len()).map_err(|_| ArtifactError::Output)?;
        files.paths.push_str(path);
        files.records.push(FileRecord {
            path_start,
            path_len: u16::try_from(path.len()).map_err(|_| ArtifactError::Output)?,
            kind,
            executable: kind == 1,
            offset,
            size,
            alias_target: false,
        });
    }
    let mut trailing = [0];
    if input.read(&mut trailing)? != 0 {
        return Err(ArtifactError::Output);
    }
    let mut expanded = 0_u64;
    let mut entry = false;
    // Keep the wire kind independent from the public "is referenced" marker.
    // An alias must never become a valid target merely because it was resolved
    // earlier in this loop, and several aliases may refer to one regular file.
    for (index, target) in aliases {
        let target_index = files
            .position(&target)
            .ok_or(ArtifactError::Output)?;
        if files.records[target_index].kind == 2 {
            return Err(ArtifactError::Output);
        }
        let source = files.records[target_index];
        files.records[target_index].alias_target = true;
        files.records[index].offset = source.offset;
        files.records[index].size = source.size;
        files.records[index].executable = source.executable;
    }
    for file in files.iter() {
        expanded = expanded
            .checked_add(file.size)
            .filter(|total| *total <= MAX_OUTPUT_BYTES)
            .ok_or(ArtifactError::Output)?;
        entry |= file.path == expected_entry && file.executable && file.size != 0;
    }
    if !expected_entry.is_empty() && !entry {
        return Err(ArtifactError::Output);
    }
    Ok(files)
}

fn read_fixed<const N: usize>(input: &mut impl std::io::Read) -> Result<[u8; N], ArtifactError> {
    let mut bytes = [0; N];
    input
        .read_exact(&mut bytes)
        .map_err(|_| ArtifactError::Output)?;
    Ok(bytes)
}

/// Metadata of a validated regular file (aliases point at the target's bytes).
#[derive(Clone, Copy, Debug)]
pub(crate) struct IndexedFile<'a> {
    pub path: &'a str,
    pub executable: bool,
    pub offset: u64,
    pub size: u64,
    pub alias_target: bool,
}

#[derive(Clone, Copy, Debug)]
struct FileRecord {
    path_start: u32,
    path_len: u16,
    kind: u8,
    executable: bool,
    offset: u64,
    size: u64,
    alias_target: bool,
}

/// One UTF-8 arena and contiguous sorted records. All offsets are produced by
/// scan; consumers borrow names without cloning or retaining per-name owners.
#[derive(Debug)]
pub(crate) struct ArtifactIndex {
    paths: String,
    records: Vec<FileRecord>,
}
impl ArtifactIndex {
    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }
    fn path(&self, file: &FileRecord) -> &str {
        let start = file.path_start as usize;
        &self.paths[start..start + usize::from(file.path_len)]
    }
    fn view(&self, file: &FileRecord) -> IndexedFile<'_> {
        IndexedFile {
            path: self.path(file),
            offset: file.offset,
            size: file.size,
            executable: file.executable,
            alias_target: file.alias_target,
        }
    }
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = IndexedFile<'_>> {
        self.records.iter().map(|file| self.view(file))
    }
    fn position(&self, path: &str) -> Option<usize> {
        self.records
            .binary_search_by(|file| self.path(file).cmp(path))
            .ok()
    }
    pub(crate) fn find(&self, path: &str) -> Option<IndexedFile<'_>> {
        self.position(path)
            .map(|index| self.view(&self.records[index]))
    }
}

/// Keep the verified Store inode open while reading bounded file ranges. The
/// streaming validator checks paths, aliases, modes and expanded size before
/// offsets are exposed; no archive payload is retained in memory.
pub(crate) struct IndexedArtifact<R> {
    input: R,
    files: ArtifactIndex,
}

impl<R: std::io::Read + std::io::Seek> IndexedArtifact<R> {
    #[cfg(test)]
    pub fn open(mut input: R, entry: &str) -> Result<Self, ArtifactError> {
        input.rewind()?;
        let files = scan(
            std::io::BufReader::with_capacity(64 * 1024, &mut input),
            entry,
        )?;
        Ok(Self {
            input,
            files,
        })
    }

    pub fn open_checked(
        mut input: R,
        entry: &str,
        cancellation: &(impl OperationControl + ?Sized),
    ) -> Result<Self, ArtifactError> {
        if cancellation.is_cancelled() {
            return Err(ArtifactError::Cancelled);
        }
        input.rewind()?;
        let result = scan(
            std::io::BufReader::with_capacity(
                64 * 1024,
                CancellableRead {
                    input: &mut input,
                    cancellation,
                },
            ),
            entry,
        );
        if cancellation.is_cancelled() {
            return Err(ArtifactError::Cancelled);
        }
        Ok(Self {
            input,
            files: result?,
        })
    }

    pub fn files(&self) -> &ArtifactIndex {
        &self.files
    }

    /// Split immutable validated metadata from the mutable reader cursor.
    pub fn parts(&mut self) -> (&ArtifactIndex, &mut R) {
        (&self.files, &mut self.input)
    }

    pub fn reader_from<'a>(
        input: &'a mut R,
        file: &IndexedFile<'_>,
    ) -> std::io::Result<impl std::io::Read + 'a> {
        input.seek(SeekFrom::Start(file.offset))?;
        Ok(input.by_ref().take(file.size))
    }
}

impl IndexedArtifact<crate::store::VerifiedReader> {
    pub fn range_from(
        input: &crate::store::VerifiedReader,
        file: &IndexedFile<'_>,
        start: usize,
        length: usize,
        cancellation: &(impl OperationControl + ?Sized),
    ) -> std::io::Result<Vec<u8>> {
        let end = (start as u64)
            .checked_add(length as u64)
            .filter(|end| *end <= file.size)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        let _ = end;
        let absolute = file
            .offset
            .checked_add(start as u64)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        input.read_range_checked(absolute, length, || {
            if cancellation.is_cancelled() {
                Err(crate::cancellation::cancellation_io())
            } else {
                Ok(())
            }
        })
    }
}

#[cfg(test)]
pub(crate) fn decode<'a>(
    mut bytes: &'a [u8],
    expected_entry: &str,
) -> Result<Vec<ArtifactFile<'a>>, ArtifactError> {
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(ArtifactError::Output);
    }
    if !bytes.starts_with(HEADER) {
        return Err(ArtifactError::Output);
    }
    bytes = &bytes[HEADER.len()..];
    let count = u32::from_le_bytes(take(&mut bytes, 4)?.try_into().unwrap()) as usize;
    if count == 0 || count > MAX_FILES {
        return Err(ArtifactError::Output);
    }
    let mut previous = "";
    let mut seen = BTreeSet::new();
    let mut files = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u16::from_le_bytes(take(&mut bytes, 2)?.try_into().unwrap()) as usize;
        let path =
            std::str::from_utf8(take(&mut bytes, len)?).map_err(|_| ArtifactError::Output)?;
        if !relative_path(path) || path <= previous {
            return Err(ArtifactError::Output);
        }
        let mut parent = path;
        while let Some((ancestor, _)) = parent.rsplit_once('/') {
            if seen.contains(ancestor) {
                return Err(ArtifactError::Output);
            }
            parent = ancestor;
        }
        seen.insert(path);
        previous = path;
        let mode = take(&mut bytes, 1)?[0];
        if mode > 2 {
            return Err(ArtifactError::Output);
        }
        let size = u64::from_le_bytes(take(&mut bytes, 8)?.try_into().unwrap());
        let content = take(
            &mut bytes,
            usize::try_from(size).map_err(|_| ArtifactError::Output)?,
        )?;
        files.push(ArtifactFile {
            path,
            executable: mode == 1,
            bytes: if mode == 2 {
                &[]
            } else {
                content
            },
            alias: if mode == 2 {
                Some(std::str::from_utf8(content).map_err(|_| ArtifactError::Output)?)
            } else {
                None
            },
        });
    }
    if !bytes.is_empty() {
        return Err(ArtifactError::Output);
    }
    let expanded = expand(&files)?;
    if !expected_entry.is_empty()
        && !expanded
            .iter()
            .any(|file| file.path == expected_entry && file.executable && !file.bytes.is_empty())
    {
        return Err(ArtifactError::Output);
    }
    Ok(files)
}

/// Expand aliases into regular-file records only after validating every target.
/// This is also the strict materialized-size bound for a view.
#[cfg(test)]
pub(crate) fn expand<'a>(
    files: &[ArtifactFile<'a>],
) -> Result<Vec<ArtifactFile<'a>>, ArtifactError> {
    let mut total = 0_u64;
    let mut expanded = Vec::with_capacity(files.len());
    let by_path = files
        .iter()
        .map(|file| (file.path, file))
        .collect::<BTreeMap<_, _>>();
    for file in files {
        let (bytes, executable) = if let Some(target) = file.alias {
            let full = resolve_alias(file.path, target).ok_or(ArtifactError::Output)?;
            let target = by_path
                .get(full.as_str())
                .filter(|entry| entry.alias.is_none())
                .ok_or(ArtifactError::Output)?;
            (target.bytes, target.executable)
        } else {
            (file.bytes, file.executable)
        };
        total = total
            .checked_add(bytes.len() as u64)
            .filter(|sum| *sum <= MAX_OUTPUT_BYTES)
            .ok_or(ArtifactError::Output)?;
        expanded.push(ArtifactFile {
            path: file.path,
            executable,
            bytes,
            alias: None,
        });
    }
    Ok(expanded)
}

#[cfg(test)]
fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], ArtifactError> {
    let (value, rest) = bytes
        .split_at_checked(length)
        .ok_or(ArtifactError::Output)?;
    *bytes = rest;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[test]
    fn empty_directory_output_is_refused_before_emission() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("empty")).unwrap();
        let mut output = Vec::new();
        assert!(matches!(
            pack(root.path(), &mut output),
            Err(ArtifactError::Output)
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn artifact_observation_requires_no_build_publication_authority() {
        #[derive(Debug)]
        struct Observer;
        impl OperationControl for Observer {
            fn is_cancelled(&self) -> bool {
                true
            }
        }
        assert!(matches!(
            validate_stream_checked(&b"unread"[..], "bin/hello", &Observer),
            Err(ArtifactError::Cancelled)
        ));
    }

    #[test]
    fn artifact_is_normalized_and_rejects_links_missing_entry_and_truncation() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("bin")).unwrap();
        let file = root.path().join("bin/hello");
        fs::write(&file, b"executable content").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        let mut bytes = Vec::new();
        pack(root.path(), &mut bytes).unwrap();
        assert_eq!(validate(&bytes, "bin/hello").unwrap(), 1);
        assert!(validate(&bytes, "bin/missing").is_err());
        assert!(validate(&bytes[..bytes.len() - 1], "bin/hello").is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(validate(&extra, "bin/hello").is_err());
        symlink("/etc/passwd", root.path().join("escape")).unwrap();
        assert!(pack(root.path(), &mut Vec::new()).is_err());
    }

    #[test]
    fn aliases_expand_only_same_directory_regular_targets() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("lib")).unwrap();
        let binary = root.path().join("lib/libanswer.so.1.2");
        fs::write(&binary, b"ELF fixture").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(
            "libanswer.so.1.2",
            root.path().join("lib/libanswer.so.1"),
        )
        .unwrap();
        let mut encoded = Vec::new();
        pack(root.path(), &mut encoded).unwrap();
        assert!(encoded.starts_with(HEADER));
        let decoded = decode(&encoded, "lib/libanswer.so.1").unwrap();
        assert_eq!(decoded[0].alias, Some("libanswer.so.1.2"));
        let expanded = expand(&decoded).unwrap();
        assert_eq!(expanded[0].bytes, b"ELF fixture");
        assert!(expanded[0].executable);
        assert!(
            decode(
                &encoded[..encoded.len() - 1],
                "lib/libanswer.so.1"
            )
            .is_err()
        );
        symlink("libanswer.so.1", root.path().join("lib/chain.so")).unwrap();
        assert!(pack(root.path(), &mut Vec::new()).is_err());
        fs::remove_file(root.path().join("lib/chain.so")).unwrap();
        fs::remove_file(root.path().join("lib/libanswer.so.1")).unwrap();
        symlink(
            "../outside",
            root.path().join("lib/libanswer.so.1"),
        )
        .unwrap();
        assert!(pack(root.path(), &mut Vec::new()).is_err());
    }

    #[test]
    fn cancellation_interrupts_artifact_payload_scan() {
        struct CancellingReader<'a> {
            input: std::io::Cursor<Vec<u8>>,
            cancellation: &'a crate::cancellation::Cancellation,
            read: usize,
        }
        impl std::io::Read for CancellingReader<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let count = self.input.read(buffer)?;
                self.read += count;
                if self.read > 32 * 1024 {
                    self.cancellation.cancel();
                }
                Ok(count)
            }
        }
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("payload"), vec![42; 1024 * 1024]).unwrap();
        let mut encoded = Vec::new();
        pack(root.path(), &mut encoded).unwrap();
        let cancellation = crate::cancellation::Cancellation::default();
        let mut reader = CancellingReader {
            input: std::io::Cursor::new(encoded),
            cancellation: &cancellation,
            read: 0,
        };
        assert!(matches!(
            validate_stream_checked(&mut reader, "", &cancellation),
            Err(ArtifactError::Cancelled)
        ));
        assert!(reader.read < 1024 * 1024);
    }

    #[test]
    fn multiple_aliases_share_a_regular_target_but_chains_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("z"), b"regular").unwrap();
        symlink("z", root.path().join("a")).unwrap();
        symlink("z", root.path().join("b")).unwrap();
        let mut bytes = Vec::new();
        pack(root.path(), &mut bytes).unwrap();
        let index = IndexedArtifact::open(std::io::Cursor::new(&bytes), "").unwrap();
        assert_eq!(
            index
                .files()
                .iter()
                .filter(|file| file.alias_target)
                .count(),
            1
        );
        let records = index.files().iter().collect::<Vec<_>>();
        assert_eq!(records[0].offset, records[1].offset);
        assert_eq!(records[1].offset, records[2].offset);

        // The writer rejects chains. Forge one in the canonical stream to
        // exercise the reader independently of the writer's guard.
        let mut chain = bytes.clone();
        // Locate the second alias payload by walking the length-prefixed records.
        let mut cursor = HEADER.len() + 4;
        for ordinal in 0..3 {
            let length = u16::from_le_bytes(chain[cursor..cursor + 2].try_into().unwrap()) as usize;
            cursor += 2 + length + 1;
            let size = usize::try_from(u64::from_le_bytes(
                chain[cursor..cursor + 8].try_into().unwrap(),
            ))
            .unwrap();
            cursor += 8;
            if ordinal == 1 {
                chain[cursor] = b'a';
            }
            cursor += size;
        }
        assert!(validate_stream(chain.as_slice(), "").is_err());
        assert!(IndexedArtifact::open(std::io::Cursor::new(chain), "").is_err());
    }

    #[test]
    fn streaming_validation_agrees_with_the_test_decoder_for_aliases_and_corruption() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("lib")).unwrap();
        fs::write(
            root.path().join("lib/liba.so.1"),
            vec![42; 1024 * 1024],
        )
        .unwrap();
        fs::set_permissions(
            root.path().join("lib/liba.so.1"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink("liba.so.1", root.path().join("lib/liba.so")).unwrap();
        let mut bytes = Vec::new();
        pack(root.path(), &mut bytes).unwrap();
        assert_eq!(
            validate_stream(bytes.as_slice(), "lib/liba.so").unwrap(),
            validate(&bytes, "lib/liba.so").unwrap()
        );
        for corrupted in [&bytes[..bytes.len() - 1], &bytes[..20]] {
            assert!(validate_stream(corrupted, "lib/liba.so").is_err());
        }
        bytes.push(0);
        assert!(validate_stream(bytes.as_slice(), "lib/liba.so").is_err());
    }

    #[test]
    fn indexed_reader_resolves_alias_and_reads_only_selected_ranges() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("usr/lib")).unwrap();
        fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        fs::write(root.path().join("usr/lib/ld.so"), b"loader").unwrap();
        fs::set_permissions(
            root.path().join("usr/lib/ld.so"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink("../lib/ld.so", root.path().join("usr/bin/ld.so")).unwrap();
        let mut bytes = Vec::new();
        pack(root.path(), &mut bytes).unwrap();
        let mut indexed =
            IndexedArtifact::open(std::io::Cursor::new(&bytes), "usr/bin/ld.so").unwrap();
        let (files, input) = indexed.parts();
        let alias = files
            .iter()
            .find(|file| file.path == "usr/bin/ld.so")
            .unwrap();
        let target = files
            .iter()
            .find(|file| file.path == "usr/lib/ld.so")
            .unwrap();
        assert_eq!(
            (alias.offset, alias.size),
            (target.offset, target.size)
        );
        assert!(target.alias_target);
        let mut selected = Vec::new();
        IndexedArtifact::<std::io::Cursor<&Vec<u8>>>::reader_from(input, &alias)
            .unwrap()
            .read_to_end(&mut selected)
            .unwrap();
        assert_eq!(selected, b"loader");
        assert!(
            IndexedArtifact::open(
                std::io::Cursor::new(&bytes[..bytes.len() - 1]),
                "usr/bin/ld.so"
            )
            .is_err()
        );
    }

    #[test]
    fn streaming_validation_charges_alias_expansion_and_rejects_missing_target() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("lib")).unwrap();
        let binary = root.path().join("lib/liblong.so.1");
        fs::write(&binary, vec![7; 65 * 1024 * 1024]).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        symlink("liblong.so.1", root.path().join("lib/liblong.so")).unwrap();
        let mut bytes = Vec::new();
        pack(root.path(), &mut bytes).unwrap();
        assert!(validate_stream(bytes.as_slice(), "lib/liblong.so").is_err());
        assert!(validate(&bytes, "lib/liblong.so").is_err());
        // The alias must resolve to a file in its own directory, never a
        // second alias or a file outside the verified tree.
        let small = tempfile::tempdir().unwrap();
        fs::create_dir(small.path().join("lib")).unwrap();
        fs::write(small.path().join("lib/liblong.so.1"), b"test").unwrap();
        fs::set_permissions(
            small.path().join("lib/liblong.so.1"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink(
            "liblong.so.1",
            small.path().join("lib/liblong.so"),
        )
        .unwrap();
        let mut encoded = Vec::new();
        pack(small.path(), &mut encoded).unwrap();
        let offset = encoded
            .windows(b"liblong.so.1".len())
            .rposition(|part| part == b"liblong.so.1")
            .unwrap();
        encoded[offset..offset + b"liblong.so.1".len()].copy_from_slice(b"libghost.so1");
        assert!(validate_stream(encoded.as_slice(), "lib/liblong.so").is_err());
    }

    #[test]
    fn contained_cross_directory_link_expands_without_following_escape_or_chain() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        fs::create_dir_all(root.path().join("usr/lib")).unwrap();
        let loader = root.path().join("usr/lib/ld-linux-x86-64.so.2");
        fs::write(&loader, b"loader").unwrap();
        fs::set_permissions(&loader, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(
            "../lib/ld-linux-x86-64.so.2",
            root.path().join("usr/bin/ld.so"),
        )
        .unwrap();
        let mut bytes = Vec::new();
        pack(root.path(), &mut bytes).unwrap();
        assert!(bytes.starts_with(HEADER));
        assert_eq!(
            validate_stream(bytes.as_slice(), "usr/bin/ld.so").unwrap(),
            2
        );
        let decoded = decode(&bytes, "usr/bin/ld.so").unwrap();
        assert_eq!(expand(&decoded).unwrap()[0].bytes, b"loader");
        let mut old_header = bytes.clone();
        old_header[..HEADER.len()].copy_from_slice(b"syrox-artifactx");
        assert!(validate_stream(old_header.as_slice(), "usr/bin/ld.so").is_err());
        assert!(decode(&old_header, "usr/bin/ld.so").is_err());
        fs::remove_file(root.path().join("usr/bin/ld.so")).unwrap();
        for target in [
            "../../../etc/passwd",
            "/etc/passwd",
            "../lib/../bin/ld.so",
        ] {
            symlink(target, root.path().join("usr/bin/ld.so")).unwrap();
            assert!(
                pack(root.path(), &mut Vec::new()).is_err(),
                "{target}"
            );
            fs::remove_file(root.path().join("usr/bin/ld.so")).unwrap();
        }
        symlink(
            "ld-linux-x86-64.so.2",
            root.path().join("usr/lib/ld.so"),
        )
        .unwrap();
        symlink("../lib/ld.so", root.path().join("usr/bin/ld.so")).unwrap();
        assert!(pack(root.path(), &mut Vec::new()).is_err());
    }
}
#[test]
fn manifest_refuses_replaced_or_resized_files() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("payload");
    fs::write(&path, b"original").unwrap();
    let manifest = PreparedArtifact::new(temp.path()).unwrap();
    fs::write(&path, b"longer than original").unwrap();
    assert!(manifest.write(&mut Vec::new()).is_err());
    fs::write(&path, b"original").unwrap();
    let replacement = temp.path().join("replacement");
    fs::write(&replacement, b"original").unwrap();
    fs::rename(replacement, path).unwrap();
    assert!(manifest.write(&mut Vec::new()).is_err());
}
