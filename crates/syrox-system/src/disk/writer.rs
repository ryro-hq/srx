use super::{DiskError, DiskLayout, TABLE_BYTES, format};
use crate::budget::AdmittedBudget;
use sha2::{Digest as _, Sha256};
use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};

/// Resolve only the authenticated stream selected for this GPT entry number.
/// The writer checks its complete length/hash/EOF independently and never opens
/// a host path. Implementations must bound blocked I/O and own input retention.
pub trait PartitionReader {
    fn open_partition(&mut self, number: u32) -> io::Result<Box<dyn Read + '_>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrittenDisk {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

impl DiskLayout {
    /// Write a complete RAW image, including protective MBR, primary/backup GPT,
    /// payloads and zero-filled gaps/tails. No seek, local temporary image,
    /// filesystem discovery, utility or privileged operation is required.
    /// Preflight budgets before opening inputs or writing output. Source/output
    /// I/O requests are at most 64 KiB. Cancellation/deadline checks occur between
    /// I/O calls; readers/writers must themselves bound blocked kernel I/O.
    /// A failure may leave a prefix: publish only after complete success.
    pub fn write_raw(
        &self,
        sources: &mut impl PartitionReader,
        output: &mut impl Write,
        budget: &AdmittedBudget,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<WrittenDisk, DiskError> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(u64::from(
                budget.request().duration_seconds,
            )))
            .ok_or(DiskError::Deadline)?;
        let mut sink = Sink {
            output,
            digest: Sha256::new(),
            bytes: 0,
            deadline,
            cancelled: &mut cancelled,
        };
        sink.check()?;
        if self.spec.bytes > budget.request().output_bytes {
            return Err(DiskError::Budget("output bytes"));
        }
        if self.spec.partitions.len() as u64 + 1 > budget.request().files {
            return Err(DiskError::Budget("files"));
        }
        if budget.request().memory_bytes < 128 * 1024 {
            return Err(DiskError::Budget("memory bytes"));
        }
        let table = format::table(self);
        let table_crc32 = format::crc32(&table);
        sink.append(&format::protective_mbr(self))?;
        sink.append(&format::header(self, table_crc32, false))?;
        sink.append(&table)?;
        let mut ordered: Vec<_> = self.spec.partitions.iter().collect();
        ordered.sort_by_key(|partition| partition.start_bytes);
        let mut buffer = vec![0; 64 * 1024];
        for partition in ordered {
            sink.pad_to(partition.start_bytes, &mut buffer)?;
            sink.check()?;
            let mut source = sources.open_partition(partition.number)?;
            let mut remaining = partition.image_bytes;
            let mut digest = Sha256::new();
            while remaining != 0 {
                sink.check()?;
                let length =
                    usize::try_from(remaining.min(buffer.len() as u64)).expect("bounded read");
                let read = match source.read(&mut buffer[..length]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if read == 0 {
                    return Err(DiskError::Content(partition.number));
                }
                digest.update(&buffer[..read]);
                sink.append(&buffer[..read])?;
                remaining -= read as u64;
            }
            loop {
                sink.check()?;
                match source.read(&mut buffer[..1]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    result => {
                        if result? != 0
                            || <[u8; 32]>::from(digest.finalize()) != partition.image_sha256
                        {
                            return Err(DiskError::Content(partition.number));
                        }
                        break;
                    }
                }
            }
            sink.pad_to(
                partition.start_bytes + partition.size_bytes,
                &mut buffer,
            )?;
        }
        let block = u64::from(self.spec.logical_block_bytes);
        sink.pad_to(
            self.spec.bytes - block - TABLE_BYTES as u64,
            &mut buffer,
        )?;
        sink.append(&table)?;
        sink.append(&format::header(self, table_crc32, true))?;
        sink.check()?;
        debug_assert_eq!(sink.bytes, self.spec.bytes);
        Ok(WrittenDisk {
            bytes: sink.bytes,
            sha256: sink.digest.finalize().into(),
        })
    }
}

struct Sink<'a, W, C> {
    output: &'a mut W,
    digest: Sha256,
    bytes: u64,
    deadline: Instant,
    cancelled: &'a mut C,
}
impl<W: Write, C: FnMut() -> bool> Sink<'_, W, C> {
    fn check(&mut self) -> Result<(), DiskError> {
        if (self.cancelled)() {
            return Err(DiskError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(DiskError::Deadline);
        }
        Ok(())
    }
    fn append(&mut self, mut bytes: &[u8]) -> Result<(), DiskError> {
        while !bytes.is_empty() {
            self.check()?;
            match self.output.write(bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(written) => {
                    self.digest.update(&bytes[..written]);
                    self.bytes += written as u64;
                    bytes = &bytes[written..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    fn pad_to(&mut self, end: u64, buffer: &mut [u8]) -> Result<(), DiskError> {
        if end < self.bytes {
            return Err(DiskError::Layout(
                "output extent order is inconsistent",
            ));
        }
        buffer.fill(0);
        while self.bytes < end {
            let length = usize::try_from((end - self.bytes).min(buffer.len() as u64))
                .expect("bounded padding");
            self.append(&buffer[..length])?;
        }
        Ok(())
    }
}
