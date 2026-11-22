//! Line records: a format tag on the first line, then one field per line.
//!
//! A field line is a key, a separator and a value, such as `action <digest>`
//! or `sha256=<digest>`. [`Writer`] emits the header from a registered
//! [`Format`] and appends fields; [`Reader`] checks the header and hands
//! back fields in the order its caller expects them.
//!
//! The codec only frames lines. Each owner still parses and bounds its values
//! and maps [`Error`] to its own error type, so the errors its callers observe
//! do not depend on this module. Owners that accept a record only when it
//! re-encodes to the same bytes keep doing so; [`Reader::finish`] is the
//! structural check for owners that need one without re-encoding.
//!
//! Lines split like [`str::lines`]: a `\r\n` terminator or an unterminated last
//! line still yields its text, so field-level errors stay the same for such
//! input. [`Reader::finish`] rejects both as [`Error::NonCanonical`].

use std::fmt::{self, Display, Write as _};

use crate::formats::Format;

/// Why a line record was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The first line is not a tag the reader accepts.
    Header,
    /// The record ended before an expected line.
    Missing,
    /// A line does not carry the expected key or shape.
    Unexpected,
    /// A value is well formed but out of range.
    Value,
    /// Spacing, a number or a line terminator is not in canonical form.
    NonCanonical,
    /// Lines remain after the last expected one.
    Trailing,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Header => "unsupported record header",
            Self::Missing => "record ends early",
            Self::Unexpected => "unexpected record line",
            Self::Value => "record value out of range",
            Self::NonCanonical => "record is not canonical",
            Self::Trailing => "record has trailing lines",
        })
    }
}

impl std::error::Error for Error {}

/// Builds a line record in memory.
#[derive(Debug)]
pub struct Writer {
    text: String,
    separator: char,
}

impl Writer {
    /// Start a record with the tag of `format` as its header line.
    /// Fields are separated from their key by a space.
    pub fn new(format: &Format) -> Self {
        let mut text = String::with_capacity(format.tag.len() + 1);
        text.push_str(format.tag);
        text.push('\n');
        Self {
            text,
            separator: ' ',
        }
    }

    /// Separate keys from values with `separator` instead of a space.
    #[must_use]
    pub fn with_separator(mut self, separator: char) -> Self {
        self.separator = separator;
        self
    }

    /// Append `key`, the separator, `value` and a newline.
    pub fn field(&mut self, key: &str, value: impl Display) -> &mut Self {
        write!(self.text, "{key}{}{value}", self.separator)
            .expect("writing to a String cannot fail");
        self.text.push('\n');
        self
    }

    /// The record text written so far.
    pub fn finish(self) -> String {
        self.text
    }

    /// The record bytes written so far.
    pub fn into_bytes(self) -> Vec<u8> {
        self.text.into_bytes()
    }
}

/// Reads a line record in order, one expected line at a time.
#[derive(Debug)]
pub struct Reader<'a> {
    rest: &'a str,
    separator: char,
    canonical: bool,
}

impl<'a> Reader<'a> {
    /// Accept `text` only when its first line is the tag of `format`.
    pub fn new(text: &'a str, format: &Format) -> Result<Self, Error> {
        let mut reader = Self {
            rest: text,
            separator: ' ',
            canonical: true,
        };
        if reader.line().map_err(|_| Error::Header)? != format.tag {
            return Err(Error::Header);
        }
        Ok(reader)
    }

    /// Split keys from values at `separator` instead of a space.
    #[must_use]
    pub fn with_separator(mut self, separator: char) -> Self {
        self.separator = separator;
        self
    }

    /// The next line, if any.
    pub fn next_line(&mut self) -> Option<&'a str> {
        if self.rest.is_empty() {
            return None;
        }
        let Some((line, rest)) = self.rest.split_once('\n') else {
            self.canonical = false;
            return Some(std::mem::take(&mut self.rest));
        };
        self.rest = rest;
        Some(line.strip_suffix('\r').map_or(line, |line| {
            self.canonical = false;
            line
        }))
    }

    /// The next line.
    pub fn line(&mut self) -> Result<&'a str, Error> {
        self.next_line().ok_or(Error::Missing)
    }

    /// Require the next line to be exactly `expected`.
    pub fn expect(&mut self, expected: &str) -> Result<(), Error> {
        if self.line()? == expected {
            Ok(())
        } else {
            Err(Error::Unexpected)
        }
    }

    /// The value of the next line, which must carry `key`.
    pub fn field(&mut self, key: &str) -> Result<&'a str, Error> {
        let line = self.line()?;
        self.value(line, key)
    }

    /// The value of the next line if one remains. Use it for a repeated field
    /// that runs to the end of the record.
    pub fn next_field(&mut self, key: &str) -> Option<Result<&'a str, Error>> {
        let line = self.next_line()?;
        Some(self.value(line, key))
    }

    /// The `N` space-separated words that follow `key` on the next line.
    /// See [`words`].
    pub fn words<const N: usize>(&mut self, key: &str) -> Result<[&'a str; N], Error> {
        words(self.line()?, key)
    }

    /// Require that every line was read and that every line, including the
    /// last, ended in a bare `\n`.
    pub fn finish(mut self) -> Result<(), Error> {
        if self.next_line().is_some() {
            return Err(Error::Trailing);
        }
        if self.canonical {
            Ok(())
        } else {
            Err(Error::NonCanonical)
        }
    }

    fn value(&self, line: &'a str, key: &str) -> Result<&'a str, Error> {
        line.strip_prefix(key)
            .and_then(|value| value.strip_prefix(self.separator))
            .ok_or(Error::Unexpected)
    }
}

/// Split `line` into `key` followed by exactly `N` words separated by single
/// spaces.
///
/// Leading, trailing or repeated spaces are [`Error::NonCanonical`]; a
/// different key or word count is [`Error::Unexpected`].
pub fn words<'a, const N: usize>(line: &'a str, key: &str) -> Result<[&'a str; N], Error> {
    if line.is_empty() || line.starts_with(' ') || line.ends_with(' ') || line.contains("  ") {
        return Err(Error::NonCanonical);
    }
    let mut parts = line.split(' ');
    if parts.next() != Some(key) {
        return Err(Error::Unexpected);
    }
    let mut words = [""; N];
    for word in &mut words {
        *word = parts.next().ok_or(Error::Unexpected)?;
    }
    if parts.next().is_some() {
        return Err(Error::Unexpected);
    }
    Ok(words)
}

/// Parse canonical decimal: ASCII digits without a sign or leading zero.
///
/// A malformed number is [`Error::NonCanonical`]; one that overflows `u64`
/// is [`Error::Value`].
pub fn decimal(text: &str) -> Result<u64, Error> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::NonCanonical);
    }
    text.parse().map_err(|_| Error::Value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats;

    fn sample() -> String {
        let mut record = Writer::new(&formats::BUILD_ATTEMPT);
        record
            .field("action", "00ff")
            .field("timeout", 30);
        record.finish()
    }

    #[test]
    fn written_records_read_back_in_order() {
        let text = sample();
        assert_eq!(
            text,
            format!(
                "{}\naction 00ff\ntimeout 30\n",
                formats::BUILD_ATTEMPT.tag
            )
        );
        let mut reader = Reader::new(&text, &formats::BUILD_ATTEMPT).unwrap();
        assert_eq!(reader.field("action"), Ok("00ff"));
        assert_eq!(reader.field("timeout"), Ok("30"));
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn separators_apply_to_both_directions() {
        let mut record = Writer::new(&formats::STORE_ROOT).with_separator('=');
        record
            .field("name", "main")
            .field("sha256", "aa")
            .field("sha256", "bb");
        let text = record.finish();
        assert_eq!(
            text,
            format!(
                "{}name=main\nsha256=aa\nsha256=bb\n",
                formats::STORE_ROOT_LINE
            )
        );
        let mut reader = Reader::new(&text, &formats::STORE_ROOT)
            .unwrap()
            .with_separator('=');
        assert_eq!(reader.field("name"), Ok("main"));
        let values: Vec<_> = std::iter::from_fn(|| reader.next_field("sha256")).collect();
        assert_eq!(values, [Ok("aa"), Ok("bb")]);
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn wrong_or_missing_header_is_refused() {
        let text = sample();
        assert_eq!(
            Reader::new(&text, &formats::BUILD_RESULT).unwrap_err(),
            Error::Header
        );
        assert_eq!(
            Reader::new("", &formats::BUILD_ATTEMPT).unwrap_err(),
            Error::Header
        );
    }

    #[test]
    fn missing_and_unexpected_fields_are_distinct() {
        let text = sample();
        let mut reader = Reader::new(&text, &formats::BUILD_ATTEMPT).unwrap();
        assert_eq!(reader.field("timeout"), Err(Error::Unexpected));
        assert_eq!(reader.field("timeout"), Ok("30"));
        assert_eq!(reader.field("timeout"), Err(Error::Missing));
        assert_eq!(reader.next_field("timeout"), None);
        let mut reader = Reader::new(&text, &formats::BUILD_ATTEMPT).unwrap();
        assert_eq!(reader.field("act"), Err(Error::Unexpected));
        assert_eq!(reader.expect("timeout 30"), Ok(()));
        assert_eq!(reader.expect("end"), Err(Error::Missing));
    }

    #[test]
    fn trailing_lines_are_refused() {
        let text = format!("{}extra\n", sample());
        let mut reader = Reader::new(&text, &formats::BUILD_ATTEMPT).unwrap();
        reader.field("action").unwrap();
        reader.field("timeout").unwrap();
        assert_eq!(reader.finish(), Err(Error::Trailing));
    }

    #[test]
    fn line_terminators_split_like_str_lines_but_are_not_canonical() {
        let crlf = sample().replace('\n', "\r\n");
        let mut reader = Reader::new(&crlf, &formats::BUILD_ATTEMPT).unwrap();
        assert_eq!(reader.field("action"), Ok("00ff"));
        assert_eq!(reader.field("timeout"), Ok("30"));
        assert_eq!(reader.finish(), Err(Error::NonCanonical));

        let unterminated = sample();
        let unterminated = unterminated.trim_end_matches('\n');
        let mut reader = Reader::new(unterminated, &formats::BUILD_ATTEMPT).unwrap();
        assert_eq!(reader.field("action"), Ok("00ff"));
        assert_eq!(reader.field("timeout"), Ok("30"));
        assert_eq!(reader.finish(), Err(Error::NonCanonical));

        let blank = format!("{}\n", sample());
        let mut reader = Reader::new(&blank, &formats::BUILD_ATTEMPT).unwrap();
        reader.field("action").unwrap();
        reader.field("timeout").unwrap();
        assert_eq!(reader.line(), Ok(""));
        assert_eq!(reader.finish(), Ok(()));

        for text in [
            "a\r\nb\n\nc\r",
            "a\n\r\n",
            "\r",
            "a\rb\n",
        ] {
            let lines: Vec<_> = text.lines().collect();
            let full = format!("{}\n{text}", formats::BUILD_ATTEMPT.tag);
            let mut reader = Reader::new(&full, &formats::BUILD_ATTEMPT).unwrap();
            let read: Vec<_> = std::iter::from_fn(|| reader.next_line()).collect();
            assert_eq!(read, lines, "{text:?}");
        }
    }

    #[test]
    fn words_require_single_spaces_and_an_exact_count() {
        assert_eq!(words::<2>("main 12 ab", "main"), Ok(["12", "ab"]));
        assert_eq!(words::<0>("end", "end"), Ok([]));
        assert_eq!(
            words::<2>("main  12 ab", "main"),
            Err(Error::NonCanonical)
        );
        assert_eq!(
            words::<2>(" main 12 ab", "main"),
            Err(Error::NonCanonical)
        );
        assert_eq!(
            words::<2>("main 12 ab ", "main"),
            Err(Error::NonCanonical)
        );
        assert_eq!(words::<2>("", "main"), Err(Error::NonCanonical));
        assert_eq!(
            words::<2>("main 12", "main"),
            Err(Error::Unexpected)
        );
        assert_eq!(
            words::<1>("main 12 ab", "main"),
            Err(Error::Unexpected)
        );
        assert_eq!(
            words::<2>("std 12 ab", "main"),
            Err(Error::Unexpected)
        );
    }

    #[test]
    fn decimals_are_canonical() {
        assert_eq!(decimal("0"), Ok(0));
        assert_eq!(decimal("1800"), Ok(1800));
        assert_eq!(decimal(&u64::MAX.to_string()), Ok(u64::MAX));
        for text in ["", "01", "+1", "-1", "1 ", "1a", "1_0"] {
            assert_eq!(
                decimal(text),
                Err(Error::NonCanonical),
                "{text:?}"
            );
        }
        assert_eq!(decimal("18446744073709551616"), Err(Error::Value));
    }
}
