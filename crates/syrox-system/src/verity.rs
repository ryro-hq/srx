//! Bounded dm-verity format 1, SHA-256, 4096-byte data/hash blocks.
//!
//! No superblock, device paths, mounting or activation. The caller must bind
//! the resulting root hash and geometry to an authorized boot generation.
//! <https://docs.kernel.org/admin-guide/device-mapper/verity.html>

use sha2::{Digest as _, Sha256};
use std::io::{self, Read, Write};

pub const BLOCK_BYTES: usize = 4096;
const DIGEST_BYTES: usize = 32;
const DIGESTS_PER_BLOCK: u64 = (BLOCK_BYTES / DIGEST_BYTES) as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Geometry {
    data_bytes: u64,
    /// Bottom to top; serialization of the hash device reverses this order.
    level_blocks: Vec<u64>,
    hash_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum VerityError {
    #[error("verity data must be nonempty and aligned to 4096-byte blocks")]
    Alignment,
    #[error("verity geometry exceeds the supported integer range")]
    Overflow,
    #[error("verity source differs from its declared length or SHA-256")]
    Content,
    #[error("verity operation cancelled")]
    Cancelled,
    #[error("verity I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl Geometry {
    pub fn new(data_bytes: u64) -> Result<Self, VerityError> {
        if data_bytes == 0 || !data_bytes.is_multiple_of(BLOCK_BYTES as u64) {
            return Err(VerityError::Alignment);
        }
        let mut blocks = data_bytes / BLOCK_BYTES as u64;
        let mut level_blocks = Vec::new();
        let mut hash_blocks = 0_u64;
        while blocks > 1 {
            blocks = blocks.div_ceil(DIGESTS_PER_BLOCK);
            hash_blocks = hash_blocks
                .checked_add(blocks)
                .ok_or(VerityError::Overflow)?;
            level_blocks.push(blocks);
        }
        Ok(Self {
            data_bytes,
            level_blocks,
            hash_bytes: hash_blocks
                .checked_mul(BLOCK_BYTES as u64)
                .ok_or(VerityError::Overflow)?,
        })
    }

    pub const fn data_bytes(&self) -> u64 {
        self.data_bytes
    }
    pub const fn data_blocks(&self) -> u64 {
        self.data_bytes / BLOCK_BYTES as u64
    }
    pub const fn hash_bytes(&self) -> u64 {
        self.hash_bytes
    }
    pub fn level_blocks(&self) -> &[u64] {
        &self.level_blocks
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrittenLevel {
    pub blocks: u64,
    pub bytes: u64,
    /// Ordinary SHA-256 of the emitted stream, distinct from salted verity hashes.
    pub sha256: [u8; 32],
    /// Present at the top level, or for one data block requiring no hash device.
    pub root_hash: Option<[u8; 32]>,
}

/// Hash one level using two 4 KiB buffers. Salt is explicit and prepended, and
/// unused digest slots are zero-filled. Verify exact input length, EOF and its
/// ordinary SHA-256 before returning success. A one-block input produces just
/// its root digest and no hash blocks. Otherwise serialize levels root-first.
///
/// Output may contain a prefix on error. Callers must stage publication until
/// success. Cancellation is cooperative between bounded I/O calls; callers own
/// blocked-I/O deadlines and the budgets for storage/transport of every level.
pub fn write_level(
    source: &mut impl Read,
    data_bytes: u64,
    expected_sha256: [u8; 32],
    salt: &[u8; 32],
    output: &mut impl Write,
    mut cancelled: impl FnMut() -> bool,
) -> Result<WrittenLevel, VerityError> {
    check(&mut cancelled)?;
    let geometry = Geometry::new(data_bytes)?;
    let blocks = geometry
        .level_blocks
        .first()
        .copied()
        .unwrap_or(0);
    let mut source_hash = Sha256::new();
    let mut output_hash = Sha256::new();
    let mut data = [0; BLOCK_BYTES];
    let mut hashes = [0; BLOCK_BYTES];
    let mut used = 0;
    let mut root = None;
    for index in 0..geometry.data_blocks() {
        read_exact(source, &mut data, &mut cancelled)?;
        source_hash.update(data);
        let digest = block_digest(salt, &data);
        if blocks == 0 {
            root = Some(digest);
            break;
        }
        hashes[used..used + DIGEST_BYTES].copy_from_slice(&digest);
        used += DIGEST_BYTES;
        if used == BLOCK_BYTES || index + 1 == geometry.data_blocks() {
            check(&mut cancelled)?;
            output.write_all(&hashes)?;
            output_hash.update(hashes);
            if blocks == 1 {
                root = Some(block_digest(salt, &hashes));
            }
            hashes.fill(0);
            used = 0;
        }
    }
    let mut sentinel = [0];
    loop {
        check(&mut cancelled)?;
        match source.read(&mut sentinel) {
            Ok(0) => break,
            Ok(_) => return Err(VerityError::Content),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    if <[u8; 32]>::from(source_hash.finalize()) != expected_sha256 {
        return Err(VerityError::Content);
    }
    check(&mut cancelled)?;
    Ok(WrittenLevel {
        blocks,
        bytes: blocks * BLOCK_BYTES as u64,
        sha256: output_hash.finalize().into(),
        root_hash: root,
    })
}

fn block_digest(salt: &[u8; 32], block: &[u8; BLOCK_BYTES]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(salt);
    digest.update(block);
    digest.finalize().into()
}

fn check(cancelled: &mut impl FnMut() -> bool) -> Result<(), VerityError> {
    if cancelled() {
        Err(VerityError::Cancelled)
    } else {
        Ok(())
    }
}

fn read_exact(
    source: &mut impl Read,
    mut bytes: &mut [u8],
    cancelled: &mut impl FnMut() -> bool,
) -> Result<(), VerityError> {
    while !bytes.is_empty() {
        check(cancelled)?;
        match source.read(bytes) {
            Ok(0) => return Err(VerityError::Content),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
