use super::{BuildError, Cancellation, ContentDigest, fd};
use sha2::{Digest as _, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::{
        fd::{AsFd as _, OwnedFd},
        unix::fs::{FileExt as _, MetadataExt as _},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn snapshot(file: &File, maximum: u64, mode: Option<u32>) -> Result<Snapshot, BuildError> {
    fd::require_readonly(file.as_fd())?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != fd::effective_uid()
        || m.nlink() != 1
        || m.len() > maximum
        || !mode.map_or_else(
            || matches!(m.mode() & 0o7777, 0o400 | 0o600),
            |wanted| m.mode() & 0o7777 == wanted,
        )
    {
        return Err(BuildError::InputChanged);
    }
    Ok(Snapshot {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        size: m.len(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}

#[derive(Debug)]
pub(super) struct Reader {
    file: File,
    snapshot: Snapshot,
    position: u64,
    cancellation: Cancellation,
}

impl Reader {
    pub fn verified(
        descriptor: OwnedFd,
        maximum: u64,
        expected: ContentDigest,
        mode: Option<u32>,
        cancellation: &Cancellation,
    ) -> Result<Self, BuildError> {
        cancellation.check()?;
        let file = File::from(descriptor);
        let before = snapshot(&file, maximum, mode)?;
        let mut reader = Self {
            file,
            snapshot: before,
            position: 0,
            cancellation: cancellation.clone(),
        };
        let mut digest = Sha256::new();
        let mut buffer = vec![0; 64 * 1024];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| cancelled_or_io(error, cancellation))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        if ContentDigest::from_sha256_hash(digest.finalize().into()) != expected {
            return Err(BuildError::InputChanged);
        }
        reader.position = 0;
        Ok(reader)
    }

    fn check(&self) -> io::Result<()> {
        self.cancellation
            .check()
            .map_err(|_| crate::cancellation::cancellation_io())?;
        if snapshot(
            &self.file,
            self.snapshot.size,
            Some(self.snapshot.mode & 0o7777),
        )
        .map_err(io::Error::other)?
            != self.snapshot
        {
            return Err(io::Error::other("resource descriptor changed"));
        }
        Ok(())
    }
}

impl Read for Reader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        if output.is_empty() {
            return Ok(0);
        }
        let count = output.len().min(64 * 1024).min(
            usize::try_from(self.snapshot.size.saturating_sub(self.position)).unwrap_or(usize::MAX),
        );
        if count == 0 {
            let mut extra = [0];
            loop {
                self.check()?;
                match self.file.read_at(&mut extra, self.snapshot.size) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    result => {
                        return if result? == 0 {
                            Ok(0)
                        } else {
                            Err(io::Error::other("resource grew"))
                        };
                    }
                }
            }
        }
        loop {
            self.check()?;
            match self
                .file
                .read_at(&mut output[..count], self.position)
            {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                result => {
                    let read = result?;
                    if read == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    self.check()?;
                    self.position += read as u64;
                    return Ok(read);
                }
            }
        }
    }
}

impl Seek for Reader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.check()?;
        let next = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.snapshot.size) + i128::from(n),
        };
        self.position =
            u64::try_from(next).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.position)
    }
}

pub(super) fn bytes(
    descriptor: OwnedFd,
    maximum: u64,
    expected: ContentDigest,
    mode: Option<u32>,
    cancellation: &Cancellation,
) -> Result<Vec<u8>, BuildError> {
    let mut reader = Reader::verified(descriptor, maximum, expected, mode, cancellation)?;
    let mut result = Vec::new();
    reader
        .read_to_end(&mut result)
        .map_err(|error| cancelled_or_io(error, cancellation))?;
    Ok(result)
}

fn cancelled_or_io(error: io::Error, cancellation: &Cancellation) -> BuildError {
    if cancellation.is_cancelled() {
        BuildError::Cancelled
    } else {
        BuildError::Io(error)
    }
}
