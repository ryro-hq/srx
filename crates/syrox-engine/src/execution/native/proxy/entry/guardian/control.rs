use std::io::{self, Read};

#[derive(Default)]
pub(super) struct Reader {
    record: [u8; 9],
    offset: usize,
}
impl Reader {
    pub(super) fn read(&mut self, input: &mut impl Read) -> io::Result<Option<(u8, u64)>> {
        // Read the tag separately so a one-byte Abort never consumes the next
        // record. Closing even mid-record means abort, never acknowledgement.
        let end = if self.offset == 0 {
            1
        } else {
            self.record.len()
        };
        match input.read(&mut self.record[self.offset..end]) {
            Ok(0) => return Ok(Some((b'B', 0))),
            Ok(count) => self.offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        let tag = self.record[0];
        if tag == b'B' {
            self.offset = 0;
            return Ok(Some((b'B', 0)));
        }
        if !matches!(tag, b'P' | b'R' | b'X') {
            return Err(io::Error::other("invalid root control"));
        }
        if self.offset != self.record.len() {
            return Ok(None);
        }
        self.offset = 0;
        Ok(Some((
            tag,
            u64::from_le_bytes(self.record[1..].try_into().expect("fixed record")),
        )))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragment_then_eof_aborts_instead_of_completing_control() {
        for tag in *b"PRX" {
            let bytes = [tag, 1, 0, 0];
            let mut input = bytes.as_slice();
            let mut reader = Reader::default();
            assert_eq!(reader.read(&mut input).unwrap(), None);
            assert_eq!(reader.read(&mut input).unwrap(), None);
            assert_eq!(reader.read(&mut input).unwrap(), Some((b'B', 0)));
        }
    }
    #[test]
    fn complete_records_and_abort_preserve_boundaries() {
        let mut bytes = vec![b'B'];
        for tag in *b"PRX" {
            bytes.push(tag);
            bytes.extend_from_slice(&7_u64.to_le_bytes());
        }
        let mut input = bytes.as_slice();
        let mut reader = Reader::default();
        assert_eq!(reader.read(&mut input).unwrap(), Some((b'B', 0)));
        for tag in *b"PRX" {
            assert_eq!(reader.read(&mut input).unwrap(), None);
            assert_eq!(reader.read(&mut input).unwrap(), Some((tag, 7)));
        }
        assert_eq!(reader.read(&mut input).unwrap(), Some((b'B', 0)));
    }
    #[test]
    fn invalid_tag_is_never_a_stop_or_abort_acknowledgement() {
        assert!(
            Reader::default()
                .read(&mut b"Q".as_slice())
                .is_err()
        );
    }
}
