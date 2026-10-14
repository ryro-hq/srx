pub(crate) mod channel;
mod context;
pub(crate) mod request;
pub(crate) mod wire;
pub(crate) use context::ProxyContext;

pub(crate) mod fragment;

pub(crate) const MAX_INVOCATIONS: usize = 16;

pub(crate) mod peer;

pub(crate) mod frontend;

pub(crate) mod guardian;

pub(crate) use crate::execution::command_evidence as settlement;

pub(crate) mod namespace_handoff;

pub(crate) mod launch_contract;

pub(crate) mod launch;
