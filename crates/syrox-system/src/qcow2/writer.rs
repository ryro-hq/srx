use super::{CLUSTER_BYTES, COPIED, Geometry, QcowError, REFCOUNT_ENTRIES, TABLE_ENTRIES};
use crate::budget::AdmittedBudget;
use sha2::{Digest as _, Sha256};
use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrittenQcow2 {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

impl Geometry {
    /// Stream a standalone qcow2 v3 disk from exact authenticated RAW bytes.
    /// All clusters are allocated with refcount one, including zero payloads;
    /// a final partial guest cluster is zero-padded. Metadata and I/O buffers
    /// stay within one 64 KiB cluster. No seeking, paths or utilities are used.
    /// Preflight complete encoded output and writer memory/file bounds. Check
    /// cancellation and duration between I/O calls; transports own blocked-I/O
    /// bounds. Errors may leave a prefix: publish only on complete success.
    pub fn write(
        &self,
        source: &mut impl Read,
        expected_sha256: [u8; 32],
        output: &mut impl Write,
        budget: &AdmittedBudget,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<WrittenQcow2, QcowError> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(u64::from(
                budget.request().duration_seconds,
            )))
            .ok_or(QcowError::Deadline)?;
        let mut sink = Sink {
            output,
            hash: Sha256::new(),
            bytes: 0,
            deadline,
            cancelled: &mut cancelled,
        };
        sink.check()?;
        if self.encoded_bytes() > budget.request().output_bytes {
            return Err(QcowError::Budget("output bytes"));
        }
        if budget.request().memory_bytes < 128 * 1024 {
            return Err(QcowError::Budget("memory bytes"));
        }
        if budget.request().files < 2 {
            return Err(QcowError::Budget("files"));
        }
        let mut buffer = vec![0; usize::try_from(CLUSTER_BYTES).expect("fixed cluster size")];
        buffer[..4].copy_from_slice(b"QFI\xfb");
        buffer[4..8].copy_from_slice(&3_u32.to_be_bytes());
        buffer[20..24].copy_from_slice(&16_u32.to_be_bytes());
        put64(&mut buffer, 24, self.virtual_bytes);
        buffer[36..40].copy_from_slice(
            &u32::try_from(self.l2_clusters)
                .expect("bounded L1 entries")
                .to_be_bytes(),
        );
        put64(&mut buffer, 40, CLUSTER_BYTES);
        put64(
            &mut buffer,
            48,
            self.refcount_table_start() * CLUSTER_BYTES,
        );
        buffer[56..60].copy_from_slice(
            &u32::try_from(self.refcount_table_clusters)
                .expect("bounded refcount table")
                .to_be_bytes(),
        );
        buffer[96..100].copy_from_slice(&4_u32.to_be_bytes());
        buffer[100..104].copy_from_slice(&104_u32.to_be_bytes());
        sink.append(&buffer)?;
        for cluster in 0..self.l1_clusters {
            buffer.fill(0);
            for entry in 0..TABLE_ENTRIES {
                let table = cluster * TABLE_ENTRIES + entry;
                if table < self.l2_clusters {
                    put64(
                        &mut buffer,
                        usize::try_from(entry * 8).expect("cluster offset"),
                        COPIED | ((self.l2_start() + table) * CLUSTER_BYTES),
                    );
                }
            }
            sink.append(&buffer)?;
        }
        for cluster in 0..self.refcount_table_clusters {
            buffer.fill(0);
            for entry in 0..TABLE_ENTRIES {
                let table = cluster * TABLE_ENTRIES + entry;
                if table < self.refcount_blocks {
                    put64(
                        &mut buffer,
                        usize::try_from(entry * 8).expect("cluster offset"),
                        (self.refcount_blocks_start() + table) * CLUSTER_BYTES,
                    );
                }
            }
            sink.append(&buffer)?;
        }
        for cluster in 0..self.refcount_blocks {
            buffer.fill(0);
            for entry in 0..REFCOUNT_ENTRIES {
                if cluster * REFCOUNT_ENTRIES + entry < self.total_clusters {
                    let offset = usize::try_from(entry * 2).expect("cluster offset");
                    buffer[offset..offset + 2].copy_from_slice(&1_u16.to_be_bytes());
                }
            }
            sink.append(&buffer)?;
        }
        for cluster in 0..self.l2_clusters {
            buffer.fill(0);
            for entry in 0..TABLE_ENTRIES {
                let guest = cluster * TABLE_ENTRIES + entry;
                if guest < self.data_clusters {
                    put64(
                        &mut buffer,
                        usize::try_from(entry * 8).expect("cluster offset"),
                        COPIED | ((self.data_start() + guest) * CLUSTER_BYTES),
                    );
                }
            }
            sink.append(&buffer)?;
        }
        let mut remaining = self.virtual_bytes;
        let mut hash = Sha256::new();
        while remaining != 0 {
            sink.check()?;
            let length =
                usize::try_from(remaining.min(CLUSTER_BYTES)).expect("bounded source read");
            let read = match source.read(&mut buffer[..length]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if read == 0 {
                return Err(QcowError::Content);
            }
            hash.update(&buffer[..read]);
            sink.append(&buffer[..read])?;
            remaining -= read as u64;
        }
        loop {
            sink.check()?;
            match source.read(&mut buffer[..1]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => {
                    if result? != 0 || <[u8; 32]>::from(hash.finalize()) != expected_sha256 {
                        return Err(QcowError::Content);
                    }
                    break;
                }
            }
        }
        buffer.fill(0);
        let padding = self.encoded_bytes() - sink.bytes;
        sink.append(&buffer[..usize::try_from(padding).expect("at most one partial cluster")])?;
        sink.check()?;
        debug_assert_eq!(sink.bytes, self.encoded_bytes());
        Ok(WrittenQcow2 {
            bytes: sink.bytes,
            sha256: sink.hash.finalize().into(),
        })
    }
}
fn put64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

struct Sink<'a, W, C> {
    output: &'a mut W,
    hash: Sha256,
    bytes: u64,
    deadline: Instant,
    cancelled: &'a mut C,
}
impl<W: Write, C: FnMut() -> bool> Sink<'_, W, C> {
    fn check(&mut self) -> Result<(), QcowError> {
        if (self.cancelled)() {
            return Err(QcowError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(QcowError::Deadline);
        }
        Ok(())
    }
    fn append(&mut self, mut bytes: &[u8]) -> Result<(), QcowError> {
        while !bytes.is_empty() {
            self.check()?;
            match self.output.write(bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(written) => {
                    self.hash.update(&bytes[..written]);
                    self.bytes += written as u64;
                    bytes = &bytes[written..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
