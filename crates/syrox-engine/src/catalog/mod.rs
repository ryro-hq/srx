//! Version inventory, source provenance and reproducible catalog matrices.
//!
//! Catalog admission is pure. A matrix describes required builds; it never
//! establishes availability or authorizes publication of an unbuilt artifact.

mod files;
mod locks;
mod model;
mod provenance;
mod releases;
mod updates;
mod validation;

pub use model::{
    Catalog, CatalogError, CatalogLock, Channel, INDEX_FILE, LOCK_FILE, LockedVersion,
    PackageVersion,
};
