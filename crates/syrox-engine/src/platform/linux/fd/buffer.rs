use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, BorrowedFd};

#[derive(Debug)]
pub(crate) struct ReadBuffer {
    bytes: Box<[MaybeUninit<u8>]>,
}
impl ReadBuffer {
    pub(crate) fn new(size: usize) -> Self {
        Self {
            bytes: Box::new_uninit_slice(size),
        }
    }
    pub(crate) fn read(&mut self, fd: BorrowedFd<'_>) -> io::Result<&[u8]> {
        // SAFETY: the exclusively borrowed allocation is writable for its full
        // length; read initializes exactly the returned prefix on success.
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                self.bytes.as_mut_ptr().cast(),
                self.bytes.len(),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = usize::try_from(count).expect("nonnegative read count");
        // SAFETY: these count bytes were initialized by read, and the slice
        // prevents another write while it is borrowed.
        Ok(unsafe { std::slice::from_raw_parts(self.bytes.as_ptr().cast(), count) })
    }
}

#[derive(Debug)]
pub(crate) struct TailBuffer {
    bytes: Box<[MaybeUninit<u8>]>,
    head: usize,
    len: usize,
}
impl TailBuffer {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            bytes: Box::new_uninit_slice(capacity),
            head: 0,
            len: 0,
        }
    }
    pub(crate) fn read(&mut self, fd: BorrowedFd<'_>, maximum: usize) -> io::Result<(usize, bool)> {
        let capacity = self.bytes.len();
        let start = (self.head + self.len) % capacity;
        let maximum = maximum.min(capacity);
        let first = maximum.min(capacity - start);
        let base = self.bytes.as_mut_ptr();
        let vectors = [
            libc::iovec {
                iov_base: base.wrapping_add(start).cast(),
                iov_len: first,
            },
            libc::iovec {
                iov_base: base.cast(),
                iov_len: maximum - first,
            },
        ];
        // SAFETY: the two ranges are disjoint and fit the owned allocation.
        // Only the returned number of bytes becomes initialized ring contents.
        let count = unsafe {
            libc::readv(
                fd.as_raw_fd(),
                vectors.as_ptr(),
                if first == maximum {
                    1
                } else {
                    2
                },
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = usize::try_from(count).expect("nonnegative readv count");
        let discarded = (self.len + count).saturating_sub(capacity);
        self.head = (self.head + discarded) % capacity;
        self.len = (self.len + count).min(capacity);
        Ok((count, discarded != 0))
    }
    pub(crate) fn tail(&self, maximum: usize) -> (&[u8], &[u8]) {
        let length = self.len.min(maximum);
        let start = (self.head + self.len - length) % self.bytes.len();
        let first = length.min(self.bytes.len() - start);
        // SAFETY: head/len describe only initialized bytes, including across a
        // wrap. The shared borrow excludes readv while either slice is alive.
        unsafe {
            (
                std::slice::from_raw_parts(self.bytes.as_ptr().add(start).cast(), first),
                std::slice::from_raw_parts(self.bytes.as_ptr().cast(), length - first),
            )
        }
    }
}

pub(crate) fn read_exact_at(
    fd: BorrowedFd<'_>,
    offset: u64,
    length: usize,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    check()?;
    let mut bytes = Vec::<u8>::with_capacity(length);
    let mut filled = 0;
    while filled < length {
        check()?;
        let position = offset
            .checked_add(filled as u64)
            .and_then(|value| libc::off_t::try_from(value).ok())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: filled <= length <= capacity; pread initializes only the
        // returned prefix. No references to uninitialized u8 are constructed.
        let count = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                bytes.as_mut_ptr().add(filled).cast(),
                (length - filled).min(64 * 1024),
                position,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += usize::try_from(count).expect("nonnegative pread count");
    }
    // SAFETY: successful pread calls initialized exactly length bytes.
    unsafe {
        bytes.set_len(length);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    #[test]
    fn ring_wraps_and_preserves_byte_order_across_partial_reads() {
        for capacity in [1, 7, 257, 4096] {
            let (reader, mut writer) = UnixStream::pair().unwrap();
            let mut ring = TailBuffer::new(capacity);
            let mut history = Vec::new();
            for length in [1, 3, 513, 8191, 16, 301] {
                let data = (0..length)
                    .map(|n| u8::try_from(n % 251).unwrap())
                    .collect::<Vec<_>>();
                writer.write_all(&data).unwrap();
                let mut offset = 0;
                while offset < data.len() {
                    let (read, overflow) = ring
                        .read(reader.as_fd(), (data.len() - offset).min(1000))
                        .unwrap();
                    assert!(read > 0);
                    history.extend_from_slice(&data[offset..offset + read]);
                    offset += read;
                    assert_eq!(overflow, history.len() > capacity);
                    for maximum in [0, 1, 100, capacity] {
                        let (first, second) = ring.tail(maximum);
                        assert_eq!(
                            [first, second].concat(),
                            history[history
                                .len()
                                .saturating_sub(capacity.min(maximum))..]
                        );
                    }
                }
            }
            drop(writer);
            assert_eq!(
                ring.read(reader.as_fd(), 100).unwrap(),
                (0, false)
            );
        }
    }

    #[test]
    fn pread_ranges_reject_eof_and_check_cancellation_between_chunks() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![42; 128 * 1024]).unwrap();
        assert_eq!(
            read_exact_at(file.as_fd(), 3, 17, || Ok(())).unwrap(),
            vec![42; 17]
        );
        assert_eq!(
            read_exact_at(file.as_fd(), 128 * 1024 - 1, 2, || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        let mut checks = 0;
        let error = read_exact_at(file.as_fd(), 0, 128 * 1024, || {
            checks += 1;
            if checks == 3 {
                Err(io::Error::other("cancelled"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "cancelled");
    }
}
