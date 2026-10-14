use std::fs::File;
#[cfg(test)]
use std::io::Read as _;
use std::io::{self, Seek as _, Write as _};
use std::os::fd::AsFd;

#[derive(Debug)]
struct Disk {
    file: File,
    size: usize,
}

#[derive(Debug)]
pub(in crate::build) struct Capture<R> {
    reader: R,
    bytes: Vec<u8>,
    disk: Option<Disk>,
    maximum: usize,
    ring: Option<crate::platform::linux::fd::TailBuffer>,
    scratch: Option<crate::platform::linux::fd::ReadBuffer>,
    pub(in crate::build) overflow: bool,
    pub(in crate::build) eof: bool,
}

impl<R: AsFd> Capture<R> {
    pub(in crate::build) fn new(reader: R, maximum: usize, tail: bool) -> io::Result<Self> {
        crate::platform::linux::fd::set_nonblocking(reader.as_fd())?;
        Ok(Self {
            reader,
            bytes: Vec::new(),
            disk: None,
            maximum,
            ring: (tail && maximum > 0)
                .then(|| crate::platform::linux::fd::TailBuffer::new(maximum)),
            scratch: None,
            overflow: false,
            eof: false,
        })
    }

    pub(in crate::build) fn new_disk(reader: R, maximum: usize) -> io::Result<Self> {
        let mut capture = Self::new(reader, maximum, false)?;
        // Anonymous temp file: no path can be reopened or substituted during
        // validation/publication, and Drop cleans a failed capture automatically.
        capture.disk = Some(Disk {
            file: tempfile::tempfile()?,
            size: 0,
        });
        Ok(capture)
    }

    /// At most 64 KiB per tick, including under a continuously writing payload.
    /// The caller checks cancellation/deadline between ticks.
    pub(in crate::build) fn drain(&mut self) -> io::Result<bool> {
        let mut activity = false;
        for _ in 0..4 {
            if self.eof {
                break;
            }
            match self.read_chunk() {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(_) => {
                    activity = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(activity)
    }

    fn read_chunk(&mut self) -> io::Result<usize> {
        if let Some(ring) = &mut self.ring {
            let (read, discarded) = ring.read(self.reader.as_fd(), 16 * 1024)?;
            self.overflow |= discarded;
            return Ok(read);
        }
        let bytes = self
            .scratch
            .get_or_insert_with(|| crate::platform::linux::fd::ReadBuffer::new(16 * 1024))
            .read(self.reader.as_fd())?;
        if let Some(disk) = &mut self.disk {
            let retained = bytes.len().min(self.maximum - disk.size);
            self.overflow |= retained != bytes.len();
            disk.file.write_all(&bytes[..retained])?;
            disk.size += retained;
            return Ok(bytes.len());
        }
        self.overflow |= bytes.len() > self.maximum - self.bytes.len();
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(self.maximum - self.bytes.len())]);
        Ok(bytes.len())
    }

    pub(in crate::build) fn into_disk(self) -> io::Result<(File, u64)> {
        let mut disk = self
            .disk
            .ok_or_else(|| io::Error::other("not a disk capture"))?;
        disk.file.rewind()?;
        Ok((disk.file, disk.size as u64))
    }

    #[cfg(test)]
    pub(in crate::build) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(in crate::build) fn tail_bytes(&self, maximum: usize) -> Vec<u8> {
        let (first, second) = self.ring.as_ref().map_or_else(
            || {
                (
                    &self.bytes[self.bytes.len().saturating_sub(maximum)..],
                    &[][..],
                )
            },
            |ring| ring.tail(maximum),
        );
        let mut bytes = Vec::with_capacity(first.len() + second.len());
        bytes.extend_from_slice(first);
        bytes.extend_from_slice(second);
        bytes
    }

    pub(in crate::build) fn diagnostic(&self) -> String {
        let prefix = if self.overflow {
            "[earlier diagnostics truncated]\n"
        } else {
            ""
        };
        format!(
            "{prefix}{}",
            String::from_utf8_lossy(&self.tail_bytes(self.maximum))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn quiet_pipe_is_nonblocking_and_tail_keeps_the_final_failure() {
        let (read, mut write) = UnixStream::pair().unwrap();
        let mut capture = Capture::new(read, 8, true).unwrap();
        assert!(!capture.drain().unwrap());
        assert!(!capture.eof);
        write.write_all(b"noise noise FAILURE!").unwrap();
        drop(write);
        assert!(capture.drain().unwrap());
        assert!(capture.eof);
        assert!(capture.overflow);
        assert_eq!(
            capture.diagnostic(),
            "[earlier diagnostics truncated]\nFAILURE!"
        );
    }

    #[test]
    fn artifact_overflow_is_flagged_while_the_pipe_is_drained_to_eof() {
        let (read, mut write) = UnixStream::pair().unwrap();
        write.write_all(b"abcdef").unwrap();
        drop(write);
        let mut capture = Capture::new(read, 3, false).unwrap();
        capture.drain().unwrap();
        assert!(capture.overflow && capture.eof);
        assert_eq!(capture.into_bytes(), b"abc");
    }

    #[test]
    fn disk_capture_retains_exact_bytes_and_refuses_overflow() {
        let (read, mut write) = UnixStream::pair().unwrap();
        write.write_all(b"abcdef").unwrap();
        drop(write);
        let mut capture = Capture::new_disk(read, 6).unwrap();
        capture.drain().unwrap();
        assert!(!capture.overflow && capture.eof);
        let (mut file, size) = capture.into_disk().unwrap();
        assert_eq!(size, 6);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcdef");
        let (read, mut write) = UnixStream::pair().unwrap();
        write.write_all(b"abcdefg").unwrap();
        drop(write);
        let mut capture = Capture::new_disk(read, 6).unwrap();
        capture.drain().unwrap();
        assert!(capture.overflow);
    }

    #[test]
    fn pipe_capture_retains_exact_bytes_and_drains_excess() {
        for maximum in [127, 4096] {
            let (reader, mut writer) = io::pipe().unwrap();
            let bytes = (0..4096)
                .map(|n| u8::try_from(n % 251).unwrap())
                .collect::<Vec<_>>();
            writer.write_all(&bytes).unwrap();
            drop(writer);
            let mut capture = Capture::new_disk(reader, maximum).unwrap();
            while !capture.eof {
                capture.drain().unwrap();
            }
            assert_eq!(capture.overflow, maximum < bytes.len());
            let (mut file, size) = capture.into_disk().unwrap();
            assert_eq!(size, maximum as u64);
            let mut actual = Vec::new();
            file.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, bytes[..maximum]);
        }
    }
}
