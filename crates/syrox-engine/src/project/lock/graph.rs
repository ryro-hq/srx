//! Edges from a project to the child projects whose locks it pins.

use std::fmt::Write as _;

use super::{LockFormatError, hex_into, is_canonical_logical_path};

pub(crate) const MAX_PROJECT_EDGES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProjectEdge {
    alias: Vec<u8>,
    origin: Vec<u8>,
    child_lock: [u8; 32],
    github: Option<crate::acquire::github::GithubPin>,
}

impl ProjectEdge {
    pub(crate) fn new(
        alias: &str,
        origin: &str,
        child_lock: [u8; 32],
    ) -> Result<Self, LockFormatError> {
        let alias = alias.as_bytes();
        if !valid_alias(alias) || !valid_origin(origin.as_bytes()) {
            return Err(LockFormatError::InvalidField);
        }
        Ok(Self {
            alias: alias.to_vec(),
            origin: origin.as_bytes().to_vec(),
            child_lock,
            github: None,
        })
    }

    pub(crate) fn github(
        alias: &str,
        origin: &str,
        child_lock: [u8; 32],
        pin: crate::acquire::github::GithubPin,
    ) -> Result<Self, LockFormatError> {
        crate::acquire::github::GithubLocator::parse(origin)
            .map_err(|_| LockFormatError::InvalidField)?;
        if !valid_alias(alias.as_bytes()) {
            return Err(LockFormatError::InvalidField);
        }
        Ok(Self {
            alias: alias.as_bytes().to_vec(),
            origin: origin.as_bytes().to_vec(),
            child_lock,
            github: Some(pin),
        })
    }

    pub(crate) const fn github_pin(&self) -> Option<&crate::acquire::github::GithubPin> {
        self.github.as_ref()
    }

    pub(super) fn encode(&self, output: &mut super::LockEncoder) -> Result<(), LockFormatError> {
        output.push_str(if self.github.is_some() {
            "github-edge "
        } else {
            "edge "
        })?;
        hex_into(output, self.alias())?;
        output.push_str(" ")?;
        hex_into(output, self.origin())?;
        output.push_str(" ")?;
        hex_into(output, self.child_lock())?;
        if let Some(pin) = &self.github {
            write!(output, " {} ", pin.commit).map_err(|_| LockFormatError::TooLarge)?;
            hex_into(output, &pin.archive)?;
        }
        output.push_str("\n")
    }

    pub(crate) fn alias(&self) -> &[u8] {
        &self.alias
    }
    pub(crate) fn origin(&self) -> &[u8] {
        &self.origin
    }
    pub(crate) const fn child_lock(&self) -> &[u8; 32] {
        &self.child_lock
    }
}

fn valid_alias(alias: &[u8]) -> bool {
    !alias.is_empty()
        && alias.len() <= 255
        && alias != b"std"
        && alias.iter().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || *byte == b'_' || (index > 0 && byte.is_ascii_digit())
        })
}

fn valid_origin(origin: &[u8]) -> bool {
    origin
        .strip_prefix(b"path:../")
        .is_some_and(is_canonical_logical_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edges_require_a_plain_alias_and_a_sibling_path_origin() {
        let child = super::super::hash(b"child lock");
        assert!(ProjectEdge::new("pkgs", "path:../syrox-pkgs", child).is_ok());
        assert!(ProjectEdge::new("pkgs", "path:recipes", child).is_err());
        assert!(ProjectEdge::new("pkgs", "path:../../escape", child).is_err());
        assert!(ProjectEdge::new("std", "path:../child", child).is_err());
        assert!(ProjectEdge::new("a", "path:../child/./bad", child).is_err());
        assert!(ProjectEdge::new("1a", "path:../child", child).is_err());
    }
}
