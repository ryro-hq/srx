//! Coordinating admission and settlement of owners and services.
//!
//! Owner messages belong to this coordinator. Received resources, manager
//! observations and process observations are checked in separate stages before
//! gates are released or retention ends. [`service_coordinator`] handles service
//! admission and readiness through settlement.

pub(crate) use crate::execution::{resources as service_spec, transport};

mod admission;
pub(crate) mod coordinator;
#[allow(unsafe_code)]
pub(crate) mod os;
pub(crate) mod owner;
pub(crate) const RETENTION: &[u8] = b"syrox-owner-v1 retention";
pub(crate) const PROCESSED: &[u8] = b"syrox-owner-v1 processed";
pub(crate) const COMMIT: &[u8] = b"syrox-owner-v1 commit";
pub(crate) const CLOSE: &[u8] = b"syrox-owner-v1 close";
#[allow(unsafe_code)]
pub(crate) mod rendezvous;
#[allow(unsafe_code)]
pub(crate) mod service;
pub(crate) mod service_coordinator;
