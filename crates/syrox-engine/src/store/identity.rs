use super::MAX_ROOT_NAME_BYTES;
use sha2::{Digest as _, Sha256};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    pub fn sha256(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub(crate) const fn from_sha256_hash(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for ContentDigest {
    type Err = DigestParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(DigestParseError);
        }
        let mut digest = [0_u8; 32];
        for (destination, pair) in digest
            .iter_mut()
            .zip(value.as_bytes().as_chunks::<2>().0)
        {
            *destination = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(digest))
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("digest must be exactly 64 lowercase hexadecimal characters")]
pub struct DigestParseError;

fn nibble(byte: u8) -> Result<u8, DigestParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(DigestParseError),
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct RootName(String);

impl RootName {
    pub fn new(value: impl Into<String>) -> Result<Self, RootNameError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_ROOT_NAME_BYTES
            || !matches!(bytes[0], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
            || !bytes[1..].iter().all(
                |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
            )
        {
            return Err(RootNameError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RootName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("root name must match [A-Za-z0-9_][A-Za-z0-9._-]{{0,127}}")]
pub struct RootNameError;
