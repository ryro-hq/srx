//! Coordinating admission and settlement of owners and services.
//!
//! Owner messages belong to this coordinator. Received resources, manager
//! observations and process observations are checked in separate stages before
//! gates are released or retention ends. [`service_coordinator`] handles service
//! admission and readiness through settlement.

pub(crate) use crate::execution::{resources as service_spec, transport};

mod admission;
pub(crate) mod coordinator;
pub(crate) mod owner;
#[allow(unsafe_code)]
pub(crate) mod services;
pub(crate) const RETENTION: &[u8] = syrox_encoding::formats::OWNER_RETENTION.as_bytes();
pub(crate) const PROCESSED: &[u8] = syrox_encoding::formats::OWNER_PROCESSED.as_bytes();
pub(crate) const COMMIT: &[u8] = syrox_encoding::formats::OWNER_COMMIT.as_bytes();
pub(crate) const CLOSE: &[u8] = syrox_encoding::formats::OWNER_CLOSE.as_bytes();
#[allow(unsafe_code)]
pub(crate) mod rendezvous;
#[allow(unsafe_code)]
pub(crate) mod service;
pub(crate) mod service_coordinator;
