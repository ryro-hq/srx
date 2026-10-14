//! Acquiring sources selected by the project.
//!
//! The request pins the expected bytes and their maximum size. [`https`] also
//! checks server identity; [`local`] requires explicit access to a directory.
//! [`archive`] inspects archive contents before they are used in a build.
//! [`github`] resolves revisions during explicit lock updates.

pub mod archive;
pub mod github;
pub mod https;
pub mod local;
