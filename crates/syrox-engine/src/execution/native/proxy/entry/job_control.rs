use std::io::{self, Read as _, Write as _};
use std::os::unix::net::UnixStream;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    Stopped(u64, i32),
    Prepare(u64),
    Paused(u64),
    Resume(u64),
}
impl Event {
    fn encode(self) -> io::Result<[u8; 13]> {
        let (tag, sequence, signal) = match self {
            Self::Stopped(sequence, signal)
                if matches!(
                    signal,
                    libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                ) =>
            {
                (b'S', sequence, signal)
            }
            Self::Prepare(sequence) => (b'A', sequence, 0),
            Self::Paused(sequence) => (b'P', sequence, 0),
            Self::Resume(sequence) => (b'R', sequence, 0),
            Self::Stopped(..) => return Err(invalid()),
        };
        if sequence == 0 {
            return Err(invalid());
        }
        let mut bytes = [0; 13];
        bytes[0] = tag;
        bytes[1..9].copy_from_slice(&sequence.to_le_bytes());
        bytes[9..].copy_from_slice(&signal.to_le_bytes());
        Ok(bytes)
    }
    fn decode(bytes: [u8; 13]) -> io::Result<Self> {
        let seq = u64::from_le_bytes(bytes[1..9].try_into().map_err(|_| invalid())?);
        let signal = i32::from_le_bytes(bytes[9..].try_into().map_err(|_| invalid())?);
        let event = match bytes[0] {
            b'S' => Self::Stopped(seq, signal),
            b'A' if signal == 0 => Self::Prepare(seq),
            b'P' if signal == 0 => Self::Paused(seq),
            b'R' if signal == 0 => Self::Resume(seq),
            _ => return Err(invalid()),
        };
        if event.encode()? != bytes {
            return Err(invalid());
        }
        Ok(event)
    }
}
pub(super) struct Channel {
    stream: UnixStream,
    incoming: [u8; 13],
    read: usize,
    outgoing: Option<([u8; 13], usize)>,
}
impl Channel {
    pub(super) fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            incoming: [0; 13],
            read: 0,
            outgoing: None,
        })
    }
    pub(super) fn send(&mut self, event: Event) -> io::Result<()> {
        if self.outgoing.is_some() {
            return Err(invalid());
        }
        self.outgoing = Some((event.encode()?, 0));
        self.flush()
    }
    pub(super) fn flush(&mut self) -> io::Result<()> {
        let Some((bytes, offset)) = &mut self.outgoing else {
            return Ok(());
        };
        match self.stream.write(&bytes[*offset..]) {
            Ok(0) => return Err(invalid()),
            Ok(count) => *offset += count,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
        if *offset == bytes.len() {
            self.outgoing = None;
        }
        Ok(())
    }
    pub(super) fn receive(&mut self) -> io::Result<Option<Event>> {
        self.flush()?;
        match self.stream.read(&mut self.incoming[self.read..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "job-control peer closed",
                ));
            }
            Ok(count) => self.read += count,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
        if self.read != self.incoming.len() {
            return Ok(None);
        }
        self.read = 0;
        Event::decode(self.incoming).map(Some)
    }
}
fn invalid() -> io::Error {
    io::Error::other("invalid private root job-control record")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_job_records_reject_malformed_and_zero_sequence() {
        for event in [
            Event::Stopped(1, libc::SIGSTOP),
            Event::Prepare(1),
            Event::Paused(1),
            Event::Resume(1),
        ] {
            let bytes = event.encode().unwrap();
            assert_eq!(Event::decode(bytes).unwrap(), event);
            let mut zero = bytes;
            zero[1..9].fill(0);
            assert!(Event::decode(zero).is_err());
        }
        assert!(Event::Stopped(1, libc::SIGKILL).encode().is_err());
        let mut extra = Event::Paused(1).encode().unwrap();
        extra[9] = 1;
        assert!(Event::decode(extra).is_err());
    }
}
