use std::io::{self, BufRead, Read, Write};

use serde_json::Value;

const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const MAX_HEADER: u64 = 8192;

pub(super) fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut length = None;
    let mut used = 0;
    loop {
        let mut line = Vec::new();
        let count = reader
            .take(MAX_HEADER + 1 - used)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            return if used == 0 {
                Ok(None)
            } else {
                Err(invalid("truncated LSP header"))
            };
        }
        used += u64::try_from(count).expect("bounded header");
        if used > MAX_HEADER {
            return Err(invalid("LSP header exceeds limit"));
        }
        if line == b"\r\n" {
            break;
        }
        let line = std::str::from_utf8(&line).map_err(|_| invalid("invalid LSP header"))?;
        let (name, value) = line
            .trim_end()
            .split_once(':')
            .ok_or_else(|| invalid("invalid LSP header"))?;
        if name.eq_ignore_ascii_case("Content-Length") {
            if length.is_some() {
                return Err(invalid("duplicate Content-Length"));
            }
            let bytes: usize = value
                .trim()
                .parse()
                .map_err(|_| invalid("invalid Content-Length"))?;
            if bytes > MAX_MESSAGE {
                return Err(invalid("LSP message exceeds limit"));
            }
            length = Some(bytes);
        }
    }
    let mut body = vec![0; length.ok_or_else(|| invalid("missing Content-Length"))?];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

pub(super) fn write_message(writer: &mut impl Write, message: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(message)?;
    write!(writer, "Content-Length: {}\r\n\r\n", bytes.len())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_are_byte_counted_and_bounded() {
        let message = serde_json::json!({"text": "é 😀"});
        let mut bytes = Vec::new();
        write_message(&mut bytes, &message).unwrap();
        let body = read_frame(&mut bytes.as_slice())
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            message
        );
        for invalid in [
            "Content-Length: 999999999\r\n\r\n",
            "Content-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            "Content-Length: 3\r\n\r\nx",
            "Content-Length: -1\r\n\r\n",
        ] {
            assert!(read_frame(&mut invalid.as_bytes()).is_err());
        }
        assert!(read_frame(&mut "x".repeat(8193).as_bytes()).is_err());
    }
}
