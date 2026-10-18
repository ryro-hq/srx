//! Binding inputs and the standard library to verified bytes.
//!
//! Reading validates identities and limits. Writing uses stable ordering so the
//! lock pin does not depend on the order in which inputs were discovered.
//! Updating the lock is an explicit project operation.

use std::fmt::Write as _;
use std::mem::size_of;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    project::AuthenticatedStandardLibrary, project::AuthenticatedStandardSource,
    project::LoadedProject,
};

pub(crate) mod graph;
use graph::{MAX_PROJECT_EDGES, ProjectEdge};

pub const LOCK_FILE_NAME: &str = "Syrox.lock";
pub const MAX_LOCK_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockStatus {
    Created,
    Updated,
    Unchanged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LockedFile {
    path: Vec<u8>,
    size: u64,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LockedInput {
    name: Vec<u8>,
    locator: Vec<u8>,
    files: Vec<LockedFile>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LockedStandardLibrary {
    files: Vec<LockedFile>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LockManifest {
    main: LockedFile,
    inputs: Vec<LockedInput>,
    standard_library: Option<LockedStandardLibrary>,
    edges: Vec<ProjectEdge>,
    assets: Vec<LockedFile>,
    project_digest: [u8; 32],
    data: Vec<u8>,
    digest: [u8; 32],
}

impl LockManifest {
    pub(crate) fn generate(
        project: &LoadedProject,
        standard_library: Option<&AuthenticatedStandardLibrary>,
    ) -> Result<Self, LockFormatError> {
        let mut budget = LockProjectionBudget::new(MAX_LOCK_BYTES);
        let main = project.main_source();
        let main = LockedFile {
            path: b"main.srx".to_vec(),
            size: main.text().len() as u64,
            digest: hash(main.text().as_bytes()),
        };
        let input_count = project.inputs().len();
        budget.collection::<LockedInput>(input_count)?;
        let mut inputs = Vec::with_capacity(input_count);
        for input in project.inputs() {
            let file_count = input.files().len();
            budget.collection::<LockedFile>(file_count)?;
            let mut files = Vec::with_capacity(file_count);
            for file in input.files() {
                let source = project
                    .sources()
                    .get(file.source_id())
                    .expect("loaded input source id is retained");
                let path = path_bytes(file.relative_path())?;
                budget.bytes(path.len())?;
                files.push(LockedFile {
                    path,
                    size: source.text().len() as u64,
                    digest: hash(source.text().as_bytes()),
                });
            }
            files.sort_by(|left, right| left.path.cmp(&right.path));
            let name = budget.copy(input.name().as_bytes())?;
            let locator = budget.copy(input.locator().as_bytes())?;
            let digest = input_digest(&name, &locator, &files);
            inputs.push(LockedInput {
                name,
                locator,
                files,
                digest,
            });
        }
        inputs.sort_by(|left, right| left.name.cmp(&right.name));
        let project_digest = project_digest(&main, &inputs);
        let standard_library = standard_library
            .map(|library| {
                let source_count = library.sources().len();
                budget.collection::<LockedFile>(source_count)?;
                let mut files = Vec::with_capacity(source_count);
                for source in library.sources() {
                    let name = source.name().as_bytes();
                    files.push(LockedFile {
                        path: budget.copy(name)?,
                        size: source.text().len() as u64,
                        digest: hash(source.text().as_bytes()),
                    });
                }
                Ok(LockedStandardLibrary {
                    files,
                    digest: *library.digest(),
                })
            })
            .transpose()?;
        let mut assets = Vec::with_capacity(project.assets().len());
        budget.collection::<LockedFile>(project.assets().len())?;
        for asset in project.assets() {
            let path = path_bytes(asset.relative_path())?;
            budget.bytes(path.len())?;
            assets.push(LockedFile {
                path,
                size: asset.size(),
                digest: *asset.digest(),
            });
        }
        let edges = project.child_edges();
        if edges.len() > MAX_PROJECT_EDGES {
            return Err(LockFormatError::InvalidField);
        }
        budget.collection::<ProjectEdge>(edges.len())?;
        for edge in edges {
            budget.bytes(
                edge.alias()
                    .len()
                    .saturating_add(edge.origin().len()),
            )?;
            if let Some(pin) = edge.github_pin() {
                budget.bytes(pin.commit.len())?;
            }
        }
        let mut edges = edges.to_vec();
        edges.sort_by(|left, right| left.alias().cmp(right.alias()));
        ensure_sorted_unique(edges.iter().map(ProjectEdge::alias))?;
        let mut manifest = Self {
            main,
            inputs,
            standard_library,
            edges,
            assets,
            project_digest,
            data: Vec::new(),
            digest: [0; 32],
        };
        manifest.data = manifest.encode()?;
        manifest.digest = hash(&manifest.data);
        Ok(manifest)
    }

    pub(crate) fn parse(data: &[u8]) -> Result<Self, LockFormatError> {
        if data.len() > MAX_LOCK_BYTES {
            return Err(LockFormatError::TooLarge);
        }
        if data.is_empty()
            || !data.ends_with(b"\n")
            || data
                .iter()
                .any(|byte| *byte == b'\r' || *byte == b'\t' || !byte.is_ascii())
        {
            return Err(LockFormatError::NonCanonical);
        }
        let text = std::str::from_utf8(data).map_err(|_| LockFormatError::NonCanonical)?;
        let mut lines = text[..text.len() - 1].split('\n');
        let version = match next_line(&mut lines)? {
            "syrox-lock" => 1,
            "syrox-lock-v2" => 2,
            "syrox-lock-v3" => 3,
            "syrox-lock-v4" => 4,
            _ => return Err(LockFormatError::UnknownRecord),
        };
        expect_line(&mut lines, "hash sha256")?;
        let expected_project_digest = parse_digest_line(next_line(&mut lines)?, "project")?;
        let main_parts = parts(next_line(&mut lines)?, "main", 3)?;
        let main = LockedFile {
            path: b"main.srx".to_vec(),
            size: source_size(main_parts[1])?,
            digest: digest(main_parts[2])?,
        };
        let input_count = count_line(next_line(&mut lines)?, "inputs")?;
        let mut inputs = Vec::with_capacity(input_count);
        let mut total_files = 1_usize;
        for _ in 0..input_count {
            let input_parts = parts(next_line(&mut lines)?, "input", 5)?;
            let name = hex(input_parts[1])?;
            let locator = hex(input_parts[2])?;
            if name.is_empty() || std::str::from_utf8(&name).is_err() || !valid_locator(&locator) {
                return Err(LockFormatError::InvalidField);
            }
            let file_count = count(input_parts[3])?;
            total_files = total_files
                .checked_add(file_count)
                .filter(|total| *total <= syrox_lang::MAX_SOURCES)
                .ok_or(LockFormatError::InvalidField)?;
            let expected_digest = digest(input_parts[4])?;
            let files = parse_files(&mut lines, "file", file_count)?;
            if input_digest(&name, &locator, &files) != expected_digest {
                return Err(LockFormatError::InconsistentDigest);
            }
            inputs.push(LockedInput {
                name,
                locator,
                files,
                digest: expected_digest,
            });
        }
        let standard_library = parse_standard_library(&mut lines, total_files)?;
        let edges = if version >= 2 {
            parse_project_edges(&mut lines, &inputs, version)?
        } else {
            Vec::new()
        };
        let assets = if version >= 3 {
            parse_assets(&mut lines)?
        } else {
            Vec::new()
        };
        expect_line(&mut lines, "end")?;
        if lines.next().is_some() {
            return Err(LockFormatError::UnknownRecord);
        }
        ensure_sorted_unique(inputs.iter().map(|input| input.name.as_slice()))?;
        for input in &inputs {
            ensure_sorted_unique(
                input
                    .files
                    .iter()
                    .map(|file| file.path.as_slice()),
            )?;
        }
        if let Some(standard) = &standard_library {
            ensure_sorted_unique(
                standard
                    .files
                    .iter()
                    .map(|file| file.path.as_slice()),
            )?;
        }
        let actual_project = project_digest(&main, &inputs);
        if actual_project != expected_project_digest {
            return Err(LockFormatError::InconsistentDigest);
        }
        let mut manifest = Self {
            main,
            inputs,
            standard_library,
            edges,
            assets,
            project_digest: expected_project_digest,
            data: data.to_vec(),
            digest: hash(data),
        };
        if manifest.encode()? != data {
            return Err(LockFormatError::NonCanonical);
        }
        manifest.data = data.to_vec();
        Ok(manifest)
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) fn edge(&self, alias: &str, origin: &str) -> Option<&ProjectEdge> {
        self.edges
            .iter()
            .find(|edge| edge.alias() == alias.as_bytes() && edge.origin() == origin.as_bytes())
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn drift(&self, expected: &Self) -> Option<LockDrift> {
        if self.project_digest != expected.project_digest
            || self.main != expected.main
            || self.inputs != expected.inputs
        {
            Some(LockDrift::Project)
        } else if self.standard_library != expected.standard_library {
            Some(LockDrift::StandardLibrary)
        } else if self.edges != expected.edges {
            Some(LockDrift::Graph)
        } else if self.assets != expected.assets || self.data != expected.data {
            Some(LockDrift::Project)
        } else {
            None
        }
    }

    // A configuration edit may change only main.srx and its derived digest.
    // In particular, do not resolve a mutable input again as an incidental
    // consequence of applying a service configuration.
    pub(super) fn drift_except_main(&self, expected: &Self) -> Option<LockDrift> {
        if self.standard_library != expected.standard_library {
            Some(LockDrift::StandardLibrary)
        } else if self.edges != expected.edges {
            Some(LockDrift::Graph)
        } else if self.inputs != expected.inputs || self.assets != expected.assets {
            Some(LockDrift::Project)
        } else {
            None
        }
    }

    fn encode(&self) -> Result<Vec<u8>, LockFormatError> {
        self.encode_with_limit(MAX_LOCK_BYTES)
    }

    fn encode_with_limit(&self, limit: usize) -> Result<Vec<u8>, LockFormatError> {
        let mut output = LockEncoder::new(limit);
        let github = self
            .edges
            .iter()
            .any(|edge| edge.github_pin().is_some());
        output.push_str(if github {
            "syrox-lock-v4\nhash sha256\nproject "
        } else if !self.assets.is_empty() {
            "syrox-lock-v3\nhash sha256\nproject "
        } else if self.edges.is_empty() {
            "syrox-lock\nhash sha256\nproject "
        } else {
            "syrox-lock-v2\nhash sha256\nproject "
        })?;
        hex_into(&mut output, &self.project_digest)?;
        write!(&mut output, "\nmain {} ", self.main.size).map_err(|_| LockFormatError::TooLarge)?;
        hex_into(&mut output, &self.main.digest)?;
        write!(&mut output, "\ninputs {}\n", self.inputs.len())
            .map_err(|_| LockFormatError::TooLarge)?;
        for input in &self.inputs {
            output.push_str("input ")?;
            hex_into(&mut output, &input.name)?;
            output.push_str(" ")?;
            hex_into(&mut output, &input.locator)?;
            write!(&mut output, " {} ", input.files.len())
                .map_err(|_| LockFormatError::TooLarge)?;
            hex_into(&mut output, &input.digest)?;
            output.push_str("\n")?;
            encode_files(&mut output, "file", &input.files)?;
        }
        if let Some(standard) = &self.standard_library {
            write!(
                &mut output,
                "std present {} ",
                standard.files.len()
            )
            .map_err(|_| LockFormatError::TooLarge)?;
            hex_into(&mut output, &standard.digest)?;
            output.push_str("\n")?;
            encode_files(&mut output, "std-file", &standard.files)?;
        } else {
            output.push_str("std absent\n")?;
        }
        if !self.edges.is_empty() || !self.assets.is_empty() {
            writeln!(&mut output, "edges {}", self.edges.len())
                .map_err(|_| LockFormatError::TooLarge)?;
            for edge in &self.edges {
                edge.encode(&mut output)?;
            }
        }
        if !self.assets.is_empty() || github {
            writeln!(&mut output, "assets {}", self.assets.len())
                .map_err(|_| LockFormatError::TooLarge)?;
            encode_files(&mut output, "asset", &self.assets)?;
        }
        output.push_str("end\n")?;
        Ok(output.finish())
    }
}

#[derive(Debug)]
struct LockProjectionBudget {
    retained: usize,
    limit: usize,
}

impl LockProjectionBudget {
    const fn new(limit: usize) -> Self {
        Self {
            retained: 0,
            limit,
        }
    }

    fn bytes(&mut self, bytes: usize) -> Result<(), LockFormatError> {
        self.retained = self
            .retained
            .checked_add(bytes)
            .filter(|retained| *retained <= self.limit)
            .ok_or(LockFormatError::TooLarge)?;
        Ok(())
    }

    fn collection<T>(&mut self, count: usize) -> Result<(), LockFormatError> {
        let bytes = count
            .checked_mul(size_of::<T>())
            .ok_or(LockFormatError::TooLarge)?;
        self.bytes(bytes)
    }

    fn copy(&mut self, bytes: &[u8]) -> Result<Vec<u8>, LockFormatError> {
        self.bytes(bytes.len())?;
        Ok(bytes.to_vec())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockDrift {
    Project,
    StandardLibrary,
    Graph,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LockFormatError {
    #[error("lock exceeds the {MAX_LOCK_BYTES}-byte limit")]
    TooLarge,
    #[error("lock is not canonical ASCII with LF line endings")]
    NonCanonical,
    #[error("lock contains an unsupported or unknown record")]
    UnknownRecord,
    #[error("lock contains an invalid or oversized field")]
    InvalidField,
    #[error("lock records are duplicate or out of canonical order")]
    Misordered,
    #[error("lock contains an internally inconsistent digest")]
    InconsistentDigest,
}

pub(crate) fn standard_library_digest(sources: &[AuthenticatedStandardSource]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    framed(&mut hasher, b"syrox-std");
    hasher.update((sources.len() as u64).to_be_bytes());
    for source in sources {
        framed(&mut hasher, source.name().as_bytes());
        hasher.update((source.text().len() as u64).to_be_bytes());
        framed(&mut hasher, &hash(source.text().as_bytes()));
    }
    hasher.finalize().into()
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn input_digest(name: &[u8], locator: &[u8], files: &[LockedFile]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    framed(&mut hasher, b"syrox-input");
    framed(&mut hasher, name);
    framed(&mut hasher, locator);
    hasher.update((files.len() as u64).to_be_bytes());
    for file in files {
        framed(&mut hasher, &file.path);
        hasher.update(file.size.to_be_bytes());
        framed(&mut hasher, &file.digest);
    }
    hasher.finalize().into()
}

fn project_digest(main: &LockedFile, inputs: &[LockedInput]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    framed(&mut hasher, b"syrox-project");
    hasher.update(main.size.to_be_bytes());
    framed(&mut hasher, &main.digest);
    hasher.update((inputs.len() as u64).to_be_bytes());
    for input in inputs {
        framed(&mut hasher, &input.name);
        framed(&mut hasher, &input.locator);
        framed(&mut hasher, &input.digest);
    }
    hasher.finalize().into()
}

fn standard_digest(files: &[LockedFile]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    framed(&mut hasher, b"syrox-std");
    hasher.update((files.len() as u64).to_be_bytes());
    for file in files {
        framed(&mut hasher, &file.path);
        hasher.update(file.size.to_be_bytes());
        framed(&mut hasher, &file.digest);
    }
    hasher.finalize().into()
}

fn path_bytes(path: &std::path::Path) -> Result<Vec<u8>, LockFormatError> {
    #[cfg(unix)]
    let bytes = path.as_os_str().as_bytes();
    #[cfg(not(unix))]
    let bytes = path
        .as_os_str()
        .to_str()
        .ok_or(LockFormatError::InvalidField)?
        .as_bytes();
    if !is_canonical_logical_path(bytes) {
        return Err(LockFormatError::InvalidField);
    }
    Ok(bytes.to_vec())
}

pub(crate) fn is_canonical_logical_path(path: &[u8]) -> bool {
    std::str::from_utf8(path).is_ok()
        && !path.is_empty()
        && !path.starts_with(b"/")
        && !path.ends_with(b"/")
        && !path.contains(&0)
        && path
            .split(|byte| *byte == b'/')
            .all(|component| !matches!(component, b"" | b"." | b".."))
}

fn valid_locator(locator: &[u8]) -> bool {
    std::str::from_utf8(locator).is_ok()
        && (locator
            .strip_prefix(b"path:")
            .or_else(|| locator.strip_prefix(b"modules:")))
        .is_some_and(is_canonical_logical_path)
}

#[derive(Debug)]
struct LockEncoder {
    output: Vec<u8>,
    limit: usize,
}

impl LockEncoder {
    const fn new(limit: usize) -> Self {
        Self {
            output: Vec::new(),
            limit,
        }
    }

    fn push_str(&mut self, value: &str) -> Result<(), LockFormatError> {
        self.push_bytes(value.as_bytes())
    }

    fn push_bytes(&mut self, value: &[u8]) -> Result<(), LockFormatError> {
        let required = self
            .output
            .len()
            .checked_add(value.len())
            .filter(|required| *required <= self.limit)
            .ok_or(LockFormatError::TooLarge)?;
        if required > self.output.capacity() {
            let capacity = self
                .output
                .capacity()
                .saturating_mul(2)
                .max(required)
                .min(self.limit);
            self.output
                .reserve_exact(capacity - self.output.len());
        }
        self.output.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.output
    }
}

impl std::fmt::Write for LockEncoder {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.push_str(value).map_err(|_| std::fmt::Error)
    }
}

fn encode_files(
    output: &mut LockEncoder,
    record: &str,
    files: &[LockedFile],
) -> Result<(), LockFormatError> {
    for file in files {
        write!(output, "{record} ").map_err(|_| LockFormatError::TooLarge)?;
        hex_into(output, &file.path)?;
        write!(output, " {} ", file.size).map_err(|_| LockFormatError::TooLarge)?;
        hex_into(output, &file.digest)?;
        output.push_str("\n")?;
    }
    Ok(())
}

fn hex_into(output: &mut LockEncoder, bytes: &[u8]) -> Result<(), LockFormatError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        let encoded = [
            HEX[usize::from(byte >> 4)],
            HEX[usize::from(byte & 15)],
        ];
        output.push_bytes(&encoded)?;
    }
    Ok(())
}

fn next_line<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Result<&'a str, LockFormatError> {
    lines.next().ok_or(LockFormatError::UnknownRecord)
}

fn expect_line<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    expected: &str,
) -> Result<(), LockFormatError> {
    if next_line(lines)? == expected {
        Ok(())
    } else {
        Err(LockFormatError::UnknownRecord)
    }
}

fn parts<'a>(line: &'a str, record: &str, length: usize) -> Result<Vec<&'a str>, LockFormatError> {
    if line.is_empty() || line.starts_with(' ') || line.ends_with(' ') || line.contains("  ") {
        return Err(LockFormatError::NonCanonical);
    }
    let parts: Vec<_> = line.split(' ').collect();
    if parts.len() != length || parts[0] != record {
        return Err(LockFormatError::UnknownRecord);
    }
    Ok(parts)
}

fn parse_digest_line(line: &str, record: &str) -> Result<[u8; 32], LockFormatError> {
    let parts = parts(line, record, 2)?;
    digest(parts[1])
}

fn count_line(line: &str, record: &str) -> Result<usize, LockFormatError> {
    let parts = parts(line, record, 2)?;
    count(parts[1])
}

fn decimal(value: &str) -> Result<u64, LockFormatError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LockFormatError::NonCanonical);
    }
    value
        .parse()
        .map_err(|_| LockFormatError::InvalidField)
}

fn count(value: &str) -> Result<usize, LockFormatError> {
    let value = usize::try_from(decimal(value)?).map_err(|_| LockFormatError::InvalidField)?;
    if value > syrox_lang::MAX_SOURCES {
        return Err(LockFormatError::InvalidField);
    }
    Ok(value)
}

fn source_size(value: &str) -> Result<u64, LockFormatError> {
    let size = decimal(value)?;
    if size > syrox_lang::MAX_SOURCE_BYTES as u64 {
        return Err(LockFormatError::InvalidField);
    }
    Ok(size)
}

fn asset_size(value: &str) -> Result<u64, LockFormatError> {
    let size = decimal(value)?;
    if size > crate::project::MAX_PROJECT_BYTES as u64 {
        return Err(LockFormatError::InvalidField);
    }
    Ok(size)
}

fn digest(value: &str) -> Result<[u8; 32], LockFormatError> {
    let decoded = hex(value)?;
    decoded
        .try_into()
        .map_err(|_| LockFormatError::InvalidField)
}

fn hex(value: &str) -> Result<Vec<u8>, LockFormatError> {
    if !value.len().is_multiple_of(2) || value.len() > syrox_lang::MAX_SOURCE_BYTES * 2 {
        return Err(LockFormatError::InvalidField);
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn nibble(byte: u8) -> Result<u8, LockFormatError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(LockFormatError::NonCanonical),
    }
}

fn parse_files<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    record: &str,
    count: usize,
) -> Result<Vec<LockedFile>, LockFormatError> {
    let mut files = Vec::with_capacity(count);
    for _ in 0..count {
        let file_parts = parts(next_line(lines)?, record, 4)?;
        let path = hex(file_parts[1])?;
        if !is_canonical_logical_path(&path) {
            return Err(LockFormatError::InvalidField);
        }
        files.push(LockedFile {
            path,
            size: if record == "asset" {
                asset_size(file_parts[2])?
            } else {
                source_size(file_parts[2])?
            },
            digest: digest(file_parts[3])?,
        });
    }
    Ok(files)
}

fn parse_standard_library<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    project_files: usize,
) -> Result<Option<LockedStandardLibrary>, LockFormatError> {
    let line = next_line(lines)?;
    if line == "std absent" {
        return Ok(None);
    }
    let fields = parts(line, "std", 4)?;
    if fields[1] != "present" {
        return Err(LockFormatError::UnknownRecord);
    }
    let file_count = count(fields[2])?;
    if file_count == 0
        || project_files
            .checked_add(file_count)
            .is_none_or(|total| total > syrox_lang::MAX_SOURCES)
    {
        return Err(LockFormatError::InvalidField);
    }
    let expected_digest = digest(fields[3])?;
    let files = parse_files(lines, "std-file", file_count)?;
    if standard_digest(&files) != expected_digest {
        return Err(LockFormatError::InconsistentDigest);
    }
    Ok(Some(LockedStandardLibrary {
        files,
        digest: expected_digest,
    }))
}

fn parse_assets<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
) -> Result<Vec<LockedFile>, LockFormatError> {
    let count = count_line(next_line(lines)?, "assets")?;
    let assets = parse_files(lines, "asset", count)?;
    ensure_sorted_unique(assets.iter().map(|file| file.path.as_slice()))?;
    if assets
        .iter()
        .any(|file| !file.path.starts_with(b"assets/") || file.path.len() <= b"assets/".len())
    {
        return Err(LockFormatError::InvalidField);
    }
    Ok(assets)
}

fn parse_project_edges<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    inputs: &[LockedInput],
    version: u8,
) -> Result<Vec<ProjectEdge>, LockFormatError> {
    let count = count_line(next_line(lines)?, "edges")?;
    if (version < 3 && count == 0) || count > MAX_PROJECT_EDGES {
        return Err(LockFormatError::InvalidField);
    }
    let mut edges = Vec::with_capacity(count);
    for _ in 0..count {
        let line = next_line(lines)?;
        let remote = version >= 4 && line.starts_with("github-edge ");
        let fields = parts(
            line,
            if remote {
                "github-edge"
            } else {
                "edge"
            },
            if remote {
                6
            } else {
                4
            },
        )?;
        let alias = hex(fields[1])?;
        let origin = hex(fields[2])?;
        let alias = std::str::from_utf8(&alias).map_err(|_| LockFormatError::InvalidField)?;
        let origin = std::str::from_utf8(&origin).map_err(|_| LockFormatError::InvalidField)?;
        let edge = if remote {
            let pin = crate::acquire::github::GithubPin::new(fields[4], digest(fields[5])?)
                .map_err(|_| LockFormatError::InvalidField)?;
            ProjectEdge::github(alias, origin, digest(fields[3])?, pin)?
        } else {
            ProjectEdge::new(alias, origin, digest(fields[3])?)?
        };
        if inputs
            .iter()
            .any(|input| input.name == edge.alias())
        {
            return Err(LockFormatError::InvalidField);
        }
        edges.push(edge);
    }
    ensure_sorted_unique(edges.iter().map(ProjectEdge::alias))?;
    Ok(edges)
}

fn ensure_sorted_unique<'a>(values: impl Iterator<Item = &'a [u8]>) -> Result<(), LockFormatError> {
    let mut previous: Option<&[u8]> = None;
    for value in values {
        if previous.is_some_and(|previous| previous >= value) {
            return Err(LockFormatError::Misordered);
        }
        previous = Some(value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> LockManifest {
        let main = LockedFile {
            path: b"main.srx".to_vec(),
            size: 1,
            digest: hash(b"x"),
        };
        let mut manifest = LockManifest {
            project_digest: project_digest(&main, &[]),
            main,
            inputs: Vec::new(),
            standard_library: None,
            edges: Vec::new(),
            assets: Vec::new(),
            data: Vec::new(),
            digest: [0; 32],
        };
        manifest.data = manifest.encode().unwrap();
        manifest.digest = hash(&manifest.data);
        manifest
    }

    #[test]
    fn canonical_lock_round_trips_byte_for_byte() {
        let manifest = minimal();
        let parsed = LockManifest::parse(manifest.data()).unwrap();
        assert_eq!(parsed.data(), manifest.data());
        assert_eq!(parsed.digest(), manifest.digest());
        assert!(
            std::str::from_utf8(manifest.data())
                .unwrap()
                .starts_with("syrox-lock\nhash sha256\nproject ")
        );
    }

    #[test]
    fn project_edges_round_trip_in_one_versioned_manifest_and_reject_tampering() {
        let mut manifest = minimal();
        manifest.edges = vec![
            ProjectEdge::new("a", "path:../a", hash(b"a lock")).unwrap(),
            ProjectEdge::new("z", "path:../z", hash(b"z lock")).unwrap(),
        ];
        let encoded = manifest.encode().unwrap();
        assert!(encoded.starts_with(b"syrox-lock-v2\n"));
        let parsed = LockManifest::parse(&encoded).unwrap();
        assert_eq!(parsed.edges, manifest.edges);
        assert_eq!(parsed.data(), encoded);
        let mut changed = encoded.clone();
        let position = changed
            .windows(5)
            .position(|part| part == b"edge ")
            .unwrap()
            + 5;
        changed[position] = b'0';
        assert!(LockManifest::parse(&changed).is_err());

        let text = String::from_utf8(encoded).unwrap();
        let first = text
            .lines()
            .find(|line| line.starts_with("edge "))
            .unwrap();
        let duplicate = text
            .lines()
            .map(|line| {
                if line.starts_with("edge ") {
                    first
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(
            LockManifest::parse(duplicate.as_bytes()),
            Err(LockFormatError::Misordered)
        );
        let mut reversed = manifest;
        reversed.edges.reverse();
        assert_eq!(
            LockManifest::parse(&reversed.encode().unwrap()),
            Err(LockFormatError::Misordered)
        );
    }

    #[test]
    fn binary_assets_have_a_canonical_versioned_inventory() {
        let mut manifest = minimal();
        manifest.assets.push(LockedFile {
            path: b"assets/fix.patch".to_vec(),
            size: 2,
            digest: hash(b"\0x"),
        });
        let data = manifest.encode().unwrap();
        assert!(data.starts_with(b"syrox-lock-v3\n"));
        assert_eq!(
            LockManifest::parse(&data).unwrap().assets,
            manifest.assets
        );
        let invalid = String::from_utf8(data)
            .unwrap()
            .replacen("assets 1", "assets 0", 1);
        assert!(LockManifest::parse(invalid.as_bytes()).is_err());
    }

    #[test]
    fn canonical_encoder_refuses_before_exceeding_its_limit() {
        let manifest = minimal();
        let canonical = manifest.encode().unwrap();
        assert_eq!(
            manifest
                .encode_with_limit(canonical.len())
                .unwrap(),
            canonical
        );
        assert_eq!(
            manifest.encode_with_limit(canonical.len() - 1),
            Err(LockFormatError::TooLarge)
        );
    }

    #[test]
    fn parser_rejects_noncanonical_framing_and_bad_digests() {
        for data in [
            b"".as_slice(),
            b"syrox-lock\r\n",
            b"syrox-lock 01\n",
            b"syrox-lock\nhash sha256\n",
        ] {
            assert!(LockManifest::parse(data).is_err());
        }

        let canonical = minimal().data;
        let mut no_final_newline = canonical.clone();
        no_final_newline.pop();
        assert_eq!(
            LockManifest::parse(&no_final_newline),
            Err(LockFormatError::NonCanonical)
        );
        let digest_start = canonical
            .windows(8)
            .position(|window| window == b"project ")
            .unwrap()
            + 8;
        let uppercase = canonical[digest_start..]
            .iter()
            .enumerate()
            .find(|(_, byte)| matches!(byte, b'a'..=b'f'))
            .map(|(index, _)| digest_start + index)
            .unwrap();
        let mut uppercase_data = canonical.clone();
        uppercase_data[uppercase] = uppercase_data[uppercase].to_ascii_uppercase();
        assert_eq!(
            LockManifest::parse(&uppercase_data),
            Err(LockFormatError::NonCanonical)
        );
        let inconsistent = canonical
            .windows(8)
            .position(|window| window == b"project ")
            .unwrap()
            + 8;
        let mut inconsistent_data = canonical;
        inconsistent_data[inconsistent] = if inconsistent_data[inconsistent] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert_eq!(
            LockManifest::parse(&inconsistent_data),
            Err(LockFormatError::InconsistentDigest)
        );
    }

    #[test]
    fn content_and_aggregate_digests_change_with_every_authenticated_field() {
        let file = LockedFile {
            path: b"a.srx".to_vec(),
            size: 1,
            digest: hash(b"a"),
        };
        let first = input_digest(b"dep", b"path:dep", std::slice::from_ref(&file));
        let second = input_digest(b"dep", b"path:other", std::slice::from_ref(&file));
        assert_ne!(first, second);
        assert_ne!(hash(b"a"), hash(b"b"));
        let other = LockedFile {
            path: b"b.srx".to_vec(),
            ..file.clone()
        };
        assert_ne!(
            standard_digest(std::slice::from_ref(&file)),
            standard_digest(&[other])
        );
    }

    #[test]
    fn standard_library_digest_matches_locked_file_framing() {
        let source = AuthenticatedStandardSource::from_authenticated("a.srx", "a").unwrap();
        let file = LockedFile {
            path: b"a.srx".to_vec(),
            size: 1,
            digest: hash(b"a"),
        };
        assert_eq!(
            standard_library_digest(&[source]),
            standard_digest(&[file])
        );
    }

    #[test]
    fn prelaunch_standard_contract_fields_are_not_accepted() {
        let file = LockedFile {
            path: b"std/pkg.srx".to_vec(),
            size: 1,
            digest: hash(b"a"),
        };
        let mut manifest = minimal();
        manifest.standard_library = Some(LockedStandardLibrary {
            digest: standard_digest(std::slice::from_ref(&file)),
            files: vec![file],
        });
        let current = String::from_utf8(manifest.encode().unwrap()).unwrap();
        let historical = current.replacen(
            "std present 1 ",
            "std present 1 7374642d302e312e30 1 ",
            1,
        );
        assert!(LockManifest::parse(historical.as_bytes()).is_err());
    }

    #[test]
    fn parser_rejects_non_utf8_and_noncanonical_logical_paths() {
        let canonical_file = LockedFile {
            path: b"a.srx".to_vec(),
            size: 1,
            digest: hash(b"a"),
        };
        for path in [
            b"".as_slice(),
            b"/a.srx",
            b"a.srx/",
            b"a//b.srx",
            b"./a.srx",
            b"a/../b.srx",
            b"a\0b.srx",
            b"\xff.srx",
        ] {
            let mut manifest = minimal();
            let name = b"dep".to_vec();
            let locator = b"path:dep".to_vec();
            let files = vec![LockedFile {
                path: path.to_vec(),
                ..canonical_file.clone()
            }];
            manifest.inputs = vec![LockedInput {
                digest: input_digest(&name, &locator, &files),
                name,
                locator,
                files,
            }];
            manifest.project_digest = project_digest(&manifest.main, &manifest.inputs);
            manifest.data = manifest.encode().unwrap();
            assert!(LockManifest::parse(&manifest.data).is_err());
        }
    }

    #[test]
    fn parser_rejects_invalid_input_locator_and_text_fields() {
        for (name, locator) in [
            (b"\xff".as_slice(), b"path:dep".as_slice()),
            (b"dep", b"path:"),
            (b"dep", b"path:../dep"),
            (b"dep", b"modules:../dep"),
            (b"dep", b"modules:"),
            (b"dep", b"path:\xff"),
            (b"dep", b"https:dep"),
        ] {
            let mut manifest = minimal();
            let files = vec![LockedFile {
                path: b"a.srx".to_vec(),
                size: 1,
                digest: hash(b"a"),
            }];
            manifest.inputs = vec![LockedInput {
                name: name.to_vec(),
                locator: locator.to_vec(),
                digest: input_digest(name, locator, &files),
                files,
            }];
            manifest.project_digest = project_digest(&manifest.main, &manifest.inputs);
            manifest.data = manifest.encode().unwrap();
            assert_eq!(
                LockManifest::parse(&manifest.data),
                Err(LockFormatError::InvalidField)
            );
        }
        assert!(valid_locator(b"modules:recipes/hello"));

        for path in [b"../std.srx".as_slice(), b"\xff.srx"] {
            let mut manifest = minimal();
            let files = vec![LockedFile {
                path: path.to_vec(),
                size: 1,
                digest: hash(b"a"),
            }];
            manifest.standard_library = Some(LockedStandardLibrary {
                digest: standard_digest(&files),
                files,
            });
            manifest.data = manifest.encode().unwrap();
            assert_eq!(
                LockManifest::parse(&manifest.data),
                Err(LockFormatError::InvalidField)
            );
        }
    }
}
