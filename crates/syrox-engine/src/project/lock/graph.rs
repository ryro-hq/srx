use sha2::{Digest, Sha256};
use std::fmt::Write as _;

use super::{
    LockFormatError, MAX_LOCK_BYTES, digest, ensure_sorted_unique, framed, hash, hex, hex_into,
    is_canonical_logical_path, next_line, parts,
};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GraphLock {
    parent: [u8; 32],
    edges: Vec<ProjectEdge>,
    data: Vec<u8>,
    digest: [u8; 32],
}

impl GraphLock {
    pub(crate) fn generate(
        parent: [u8; 32],
        mut edges: Vec<ProjectEdge>,
    ) -> Result<Self, LockFormatError> {
        if edges.len() > MAX_PROJECT_EDGES
            || edges
                .iter()
                .any(|edge| edge.github_pin().is_some())
        {
            return Err(LockFormatError::InvalidField);
        }
        edges.sort_by(|left, right| left.alias.cmp(&right.alias));
        ensure_sorted_unique(edges.iter().map(|edge| edge.alias.as_slice()))?;
        let mut manifest = Self {
            parent,
            edges,
            data: Vec::new(),
            digest: [0; 32],
        };
        manifest.data = manifest.encode()?;
        manifest.digest = hash(&manifest.data);
        Ok(manifest)
    }

    pub(crate) fn parse(data: &[u8]) -> Result<Self, LockFormatError> {
        if data.len() > MAX_LOCK_BYTES {
            return Err(LockFormatError::TooLarge);
        }
        if data.is_empty()
            || !data.ends_with(b"\n")
            || data
                .iter()
                .any(|byte| !byte.is_ascii() || *byte == b'\r' || *byte == b'\t')
        {
            return Err(LockFormatError::NonCanonical);
        }
        let text = std::str::from_utf8(data).map_err(|_| LockFormatError::NonCanonical)?;
        let mut lines = text[..text.len() - 1].split('\n');
        if next_line(&mut lines)? != "syrox-graph-lock-v2"
            || next_line(&mut lines)? != "hash sha256"
        {
            return Err(LockFormatError::UnknownRecord);
        }
        let parent = digest(parts(next_line(&mut lines)?, "parent", 2)?[1])?;
        let claimed = digest(parts(next_line(&mut lines)?, "graph", 2)?[1])?;
        let count = super::count_line(next_line(&mut lines)?, "edges")?;
        if count > MAX_PROJECT_EDGES {
            return Err(LockFormatError::InvalidField);
        }
        let mut edges = Vec::with_capacity(count);
        for _ in 0..count {
            let fields = parts(next_line(&mut lines)?, "edge", 4)?;
            let alias = hex(fields[1])?;
            let origin = hex(fields[2])?;
            let edge = ProjectEdge::new(
                std::str::from_utf8(&alias).map_err(|_| LockFormatError::InvalidField)?,
                std::str::from_utf8(&origin).map_err(|_| LockFormatError::InvalidField)?,
                digest(fields[3])?,
            )?;
            edges.push(edge);
        }
        if next_line(&mut lines)? != "end" || lines.next().is_some() {
            return Err(LockFormatError::UnknownRecord);
        }
        ensure_sorted_unique(edges.iter().map(|edge| edge.alias.as_slice()))?;
        if graph_digest(&parent, &edges) != claimed {
            return Err(LockFormatError::InconsistentDigest);
        }
        let manifest = Self::generate(parent, edges)?;
        if manifest.data != data {
            return Err(LockFormatError::NonCanonical);
        }
        Ok(manifest)
    }

    #[cfg(test)]
    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
    #[cfg(test)]
    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    fn encode(&self) -> Result<Vec<u8>, LockFormatError> {
        let mut output = super::LockEncoder::new(MAX_LOCK_BYTES);
        output.push_str("syrox-graph-lock-v2\nhash sha256\nparent ")?;
        hex_into(&mut output, &self.parent)?;
        output.push_str("\ngraph ")?;
        hex_into(
            &mut output,
            &graph_digest(&self.parent, &self.edges),
        )?;
        write!(&mut output, "\nedges {}\n", self.edges.len())
            .map_err(|_| LockFormatError::TooLarge)?;
        for edge in &self.edges {
            output.push_str("edge ")?;
            hex_into(&mut output, &edge.alias)?;
            output.push_str(" ")?;
            hex_into(&mut output, &edge.origin)?;
            output.push_str(" ")?;
            hex_into(&mut output, &edge.child_lock)?;
            output.push_str("\n")?;
        }
        output.push_str("end\n")?;
        Ok(output.finish())
    }
}

fn graph_digest(parent: &[u8; 32], edges: &[ProjectEdge]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    framed(&mut hasher, b"syrox-graph-lock-v2");
    framed(&mut hasher, parent);
    hasher.update((edges.len() as u64).to_be_bytes());
    for edge in edges {
        framed(&mut hasher, &edge.alias);
        framed(&mut hasher, &edge.origin);
        framed(&mut hasher, &edge.child_lock);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_edge_identity_binds_parent_origin_and_child_lock() {
        let child = hash(b"child lock");
        let edges = vec![ProjectEdge::new("pkgs", "path:../syrox-pkgs", child).unwrap()];
        let first = GraphLock::generate(hash(b"parent"), edges.clone()).unwrap();
        assert_eq!(GraphLock::parse(first.data()).unwrap(), first);
        assert_ne!(
            GraphLock::generate(hash(b"another parent"), edges.clone())
                .unwrap()
                .digest(),
            first.digest()
        );
        assert_ne!(
            GraphLock::generate(
                hash(b"parent"),
                vec![ProjectEdge::new("pkgs", "path:../other", child).unwrap()]
            )
            .unwrap()
            .digest(),
            first.digest()
        );
        assert_ne!(
            GraphLock::generate(
                hash(b"parent"),
                vec![
                    ProjectEdge::new(
                        "pkgs",
                        "path:../syrox-pkgs",
                        hash(b"changed child")
                    )
                    .unwrap()
                ]
            )
            .unwrap()
            .digest(),
            first.digest()
        );
        assert_ne!(
            GraphLock::generate(
                hash(b"parent"),
                vec![ProjectEdge::new("other", "path:../syrox-pkgs", child).unwrap()]
            )
            .unwrap()
            .digest(),
            first.digest()
        );
        assert!(
            GraphLock::generate(
                hash(b"parent"),
                vec![edges[0].clone(), edges[0].clone()]
            )
            .is_err()
        );
    }

    #[test]
    fn graph_lock_refuses_reordered_edges_and_tampering() {
        let edges = vec![
            ProjectEdge::new("z", "path:../z", hash(b"z")).unwrap(),
            ProjectEdge::new("a", "path:../a", hash(b"a")).unwrap(),
        ];
        let lock = GraphLock::generate(hash(b"parent"), edges).unwrap();
        assert_eq!(GraphLock::parse(lock.data()).unwrap(), lock);
        let mut changed = lock.data().to_vec();
        let position = changed
            .windows(5)
            .position(|window| window == b"edge ")
            .unwrap()
            + 5;
        changed[position] = if changed[position] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert!(GraphLock::parse(&changed).is_err());
        assert!(ProjectEdge::new("pkgs", "path:recipes", hash(b"x")).is_err());
        assert!(ProjectEdge::new("pkgs", "path:../../escape", hash(b"x")).is_err());
        assert!(ProjectEdge::new("std", "path:../child", hash(b"x")).is_err());
        assert!(ProjectEdge::new("a", "path:../child/./bad", hash(b"x")).is_err());
    }
}
