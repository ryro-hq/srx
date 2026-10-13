use std::ffi::OsString;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::service_spec::{ServiceSpecError, receive_resources};
use super::transport::PacketChannel;
use crate::execution::journal::{AttemptBinding, SessionId};
use crate::{
    cancellation::Cancellation, systemd::SystemdNotifier, systemd::SystemdNotifyEndpoint,
    systemd::SystemdUnitName,
};
use thiserror::Error;

pub(super) const PROCESSED: &[u8] = b"syrox-service-v2 processed";
pub(super) const NAMESPACE: &[u8] = b"syrox-service-v2 namespace";
pub(super) const COMMIT: &[u8] = b"syrox-service-v2 commit";

mod protocol;
pub(crate) use protocol::{ServiceAttemptChallenge, ServiceLaunchHello, ServiceLaunchRequest};
pub(super) const DENIED: &[u8] = b"syrox-service-v2 denied";

#[derive(Debug, Error)]
pub enum ServiceWorkerError {
    #[error("managed service launch denied: {0}")]
    Denied(&'static str),
    #[error("invalid managed service: {0}")]
    Invalid(&'static str),
    #[error("managed service IPC failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Manager(#[from] crate::systemd::SystemdError),
    #[error(transparent)]
    Runtime(Box<crate::runtime::RuntimeError>),
}
impl From<ServiceSpecError> for ServiceWorkerError {
    fn from(error: ServiceSpecError) -> Self {
        match error {
            ServiceSpecError::Invalid(message) => invalid(message),
            ServiceSpecError::Io(error) => Self::Io(error),
            ServiceSpecError::Runtime(error) => Self::Runtime(Box::new(error)),
            ServiceSpecError::Encoding(_) => invalid("malformed service specification"),
        }
    }
}

/// # Safety
/// Dedicated single-threaded worker only; after return the process must exit.
/// Process-global namespaces and signal masks are deliberately not restored.
pub unsafe fn run_session_service(
    args: &[OsString],
    cancellation: &Cancellation,
) -> Result<i32, ServiceWorkerError> {
    let invocation =
        std::env::var("INVOCATION_ID").map_err(|_| invalid("missing invocation identifier"))?;
    let notify =
        std::env::var("NOTIFY_SOCKET").map_err(|_| invalid("missing notification endpoint"))?;
    let (socket, hello) = context(args, &invocation)?;
    let endpoint = SystemdNotifyEndpoint::new(&notify)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let channel = PacketChannel::connect(&socket, deadline, cancellation)?;
    let peer = channel.peer_credentials()?;
    let notifier = SystemdNotifier::connect(&endpoint, remaining(deadline)?, cancellation)?;
    channel.send(&hello.encode()?, &[], deadline, cancellation)?;
    let packet = channel.receive(peer, 0, deadline, cancellation)?;
    if packet.bytes == DENIED {
        return Err(ServiceWorkerError::Denied(
            "role admission revoked or unavailable",
        ));
    }
    let challenge = ServiceAttemptChallenge::parse(&packet.bytes)?;
    let request = hello.challenged(&challenge)?;
    channel.send(&request.encode()?, &[], deadline, cancellation)?;
    let resources = receive_resources(
        &channel,
        peer,
        request.command,
        deadline,
        cancellation,
    )?;
    let worker = resources
        .spec
        .worker_request(&resources.descriptors)?;
    let result = (|| {
        notifier.store_fd(
            "retention",
            resources.retention.as_fd(),
            remaining(deadline)?,
            cancellation,
        )?;
        notifier.barrier(remaining(deadline)?, cancellation)?;
        channel.send(PROCESSED, &[], deadline, cancellation)?;
        // SAFETY: this entry point requires the dedicated single-threaded worker.
        let mut runtime = unsafe { crate::execution::native::prepare_managed_runtime(&worker) }?;
        runtime.wait_prepared(deadline, cancellation)?;
        channel.send(
            NAMESPACE,
            &[runtime.namespace()],
            deadline,
            cancellation,
        )?;
        let commit = channel.receive(peer, 0, deadline, cancellation)?;
        if commit.bytes == DENIED {
            return Err(ServiceWorkerError::Denied("payload gate revoked"));
        }
        if commit.bytes != COMMIT {
            return Err(invalid("unexpected service commit"));
        }
        runtime.authorize(deadline, cancellation)?;
        notifier.ready(remaining(deadline)?, cancellation)?;
        // After commit, systemd's dependency on the session owner controls this
        // unit. The CLI packet channel is not a second service supervisor.
        let status = runtime.wait(|| {
            let _ = notifier.stopping(Duration::from_secs(1), &Cancellation::default());
        })?;
        Ok(payload_envelope(status))
    })();
    let _ = notifier.stopping(Duration::from_secs(1), &Cancellation::default());
    drop(resources); // namespace settled first, independent of manager FD store.
    result
}

fn payload_envelope(status: std::process::ExitStatus) -> i32 {
    eprintln!(
        "syrox service payload exit code={:?} signal={:?}",
        status.code(),
        status.signal()
    );
    i32::from(!status.success())
}

fn context(
    args: &[OsString],
    invocation: &str,
) -> Result<(PathBuf, ServiceLaunchHello), ServiceWorkerError> {
    let [
        socket,
        session,
        role,
        generation,
        command,
        unit,
        owner_unit,
        owner_invocation,
    ] = args
    else {
        return Err(invalid("expected eight service arguments"));
    };
    let socket = PathBuf::from(socket);
    if !socket.is_absolute()
        || socket
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(invalid("invalid service rendezvous path"));
    }
    let request = ServiceLaunchHello {
        session: SessionId::parse(string(session)?)
            .map_err(|_| invalid("invalid service session"))?,
        role: string(role)?
            .parse()
            .map_err(|_| invalid("invalid role pin"))?,
        generation: string(generation)?
            .parse()
            .map_err(|_| invalid("invalid generation pin"))?,
        command: string(command)?
            .parse()
            .map_err(|_| invalid("invalid command pin"))?,
        binding: binding(string(unit)?, invocation_bytes(invocation)?)?,
        owner: binding(
            string(owner_unit)?,
            invocation_bytes(string(owner_invocation)?)?,
        )?,
    };
    if request.binding.unit() == request.owner.unit() {
        return Err(invalid("service cannot own itself"));
    }
    Ok((socket, request))
}
fn string(value: &OsString) -> Result<&str, ServiceWorkerError> {
    value
        .to_str()
        .ok_or_else(|| invalid("non-UTF8 service argument"))
}
fn binding(unit: &str, invocation: [u8; 16]) -> Result<AttemptBinding, ServiceWorkerError> {
    AttemptBinding::new(SystemdUnitName::new(unit)?, invocation)
        .map_err(|_| invalid("zero invocation binding"))
}
fn invocation_bytes(text: &str) -> Result<[u8; 16], ServiceWorkerError> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("invalid invocation identifier"));
    }
    let mut result = [0; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("invalid invocation identifier"))?;
    }
    if result == [0; 16] {
        return Err(invalid("zero invocation identifier"));
    }
    Ok(result)
}
fn remaining(deadline: Instant) -> Result<Duration, ServiceWorkerError> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "service startup deadline",
        )
        .into())
    } else {
        Ok(timeout)
    }
}
fn invalid(message: &'static str) -> ServiceWorkerError {
    ServiceWorkerError::Invalid(message)
}

#[cfg(test)]
mod tests;
