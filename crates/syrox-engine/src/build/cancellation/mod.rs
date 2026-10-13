//! Cancelamento dos pedidos que compartilham o mesmo produtor de build.
//!
//! Cancelar um consumidor retira o interesse dele. O produtor só recebe o
//! cancelamento quando acaba o último interesse, para que outro pedido ainda
//! ativo possa receber o resultado.

pub(super) mod managed;
pub(super) use managed::with_managed_cancellation;

use super::{BuildError, shared::Interest};
use crate::cancellation::Cancellation;
use std::sync::Arc;

pub(crate) trait BuildControl: std::fmt::Debug + Send + Sync {
    fn check(&self) -> Result<(), BuildError>;
    fn check_publication(&self) -> Result<(), BuildError> {
        self.check()
    }
    fn is_cancelled(&self) -> bool {
        self.check().is_err()
    }
}

impl BuildControl for Cancellation {
    fn check(&self) -> Result<(), BuildError> {
        Cancellation::check(self).map_err(|_| BuildError::Cancelled)
    }
}

#[derive(Debug)]
pub(super) struct ProducerControl(pub(super) Arc<Interest>);

impl BuildControl for ProducerControl {
    fn check(&self) -> Result<(), BuildError> {
        self.0.check()
    }
    fn check_publication(&self) -> Result<(), BuildError> {
        self.check()?;
        self.0.check_publication()
    }
}

impl From<crate::cancellation::Cancelled> for BuildError {
    fn from(_: crate::cancellation::Cancelled) -> Self {
        Self::Cancelled
    }
}

impl<T: BuildControl + ?Sized> crate::cancellation::OperationControl for T {
    fn is_cancelled(&self) -> bool {
        BuildControl::is_cancelled(self)
    }
}
