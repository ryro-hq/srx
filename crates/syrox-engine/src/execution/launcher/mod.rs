//! Coordena a admissão e o fechamento de owners e serviços.
//!
//! As mensagens do owner pertencem a este coordenador. Os recursos recebidos e
//! as observações do manager e dos processos são conferidos em etapas separadas,
//! antes de liberar gates ou encerrar a retenção.

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
