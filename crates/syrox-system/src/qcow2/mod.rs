//! Standalone qcow2 v3 images with fully allocated, uncompressed guest clusters.
//!
//! No backing paths, external data, encryption, snapshots or lazy refcounts.
//! Format contract: <https://www.qemu.org/docs/master/interop/qcow2.html>.

use std::io;

mod geometry;
mod writer;
pub use geometry::Geometry;
pub use writer::WrittenQcow2;

pub const CLUSTER_BYTES: u64 = 65_536;
const TABLE_ENTRIES: u64 = CLUSTER_BYTES / 8;
const REFCOUNT_ENTRIES: u64 = CLUSTER_BYTES / 2;
const COPIED: u64 = 1 << 63;

#[derive(Debug, thiserror::Error)]
pub enum QcowError {
    #[error("qcow2 input must be a nonempty whole number of 512-byte sectors")]
    InputSize,
    #[error("qcow2 geometry exceeds the supported format or QEMU metadata limits")]
    Geometry,
    #[error("qcow2 exceeds the admitted {0} budget")]
    Budget(&'static str),
    #[error("qcow2 source does not match its declared size and SHA-256")]
    Content,
    #[error("qcow2 construction cancelled")]
    Cancelled,
    #[error("qcow2 construction exceeded its duration budget")]
    Deadline,
    #[error("qcow2 I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests;
