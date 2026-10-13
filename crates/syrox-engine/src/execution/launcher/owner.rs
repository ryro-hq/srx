use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::admission::LaunchRequest;
use super::transport::{PacketChannel, Peer};
use crate::execution::journal::{AttemptBinding, AttemptId, SessionId};
use crate::{
    cancellation::Cancellation, systemd::SystemdNotifier, systemd::SystemdNotifyEndpoint,
    systemd::SystemdUnitName,
};
use thiserror::Error;

const STARTUP: Duration = Duration::from_secs(30);
const LIFE_POLL: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum SessionOwnerError {
    #[error("invalid session owner context: {0}")]
    Invalid(&'static str),
    #[error("session owner IPC failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Manager(#[from] crate::systemd::SystemdError),
}

/// Dedicated worker entry point. The explicit argv is socket, session, attempt,
/// manifest pin and unit. Only systemd's invocation and notification endpoint
/// are read from the process environment; they remain claims until the
/// coordinator verifies the unit, main PID and invocation independently.
pub fn run_session_owner(
    args: &[OsString],
    cancellation: &Cancellation,
) -> Result<(), SessionOwnerError> {
    let invocation = std::env::var("INVOCATION_ID")
        .map_err(|_| SessionOwnerError::Invalid("missing invocation identifier"))?;
    let notify = std::env::var("NOTIFY_SOCKET")
        .map_err(|_| SessionOwnerError::Invalid("missing notification endpoint"))?;
    let context = Context::parse(args, &invocation, &notify)?;
    let deadline = Instant::now() + STARTUP;
    let channel = PacketChannel::connect(&context.socket, deadline, cancellation)?;
    let peer = channel.peer_credentials()?;
    let notifier = SystemdNotifier::connect(
        &context.notify,
        remaining(deadline)?,
        cancellation,
    )?;
    let mut retention = None;
    let result = (|| {
        let bytes = context
            .request
            .encode()
            .map_err(|_| SessionOwnerError::Invalid("cannot encode launch request"))?;
        channel.send(&bytes, &[], deadline, cancellation)?;
        retention = Some(receive_lease(
            &channel,
            peer,
            deadline,
            cancellation,
        )?);
        let lease = retention.as_ref().expect("received lease");
        notifier.store_fd(
            "retention",
            lease.as_fd(),
            remaining(deadline)?,
            cancellation,
        )?;
        notifier.barrier(remaining(deadline)?, cancellation)?;
        channel.send(super::PROCESSED, &[], deadline, cancellation)?;
        let commit = channel.receive(peer, 0, deadline, cancellation)?;
        expect(&commit.bytes, super::COMMIT)?;
        // Commit follows coordinator reconciliation. Keep the local descriptor
        // until this owner exits, independently of observations of FD store count.
        notifier.ready(remaining(deadline)?, cancellation)?;
        wait_lifetime(&channel, peer, cancellation)
    })();
    // Notification failure must not prevent channel closure or lease release.
    // An independent short budget permits STOPPING even after cancellation.
    let _ = notifier.stopping(Duration::from_secs(1), &Cancellation::default());
    drop(retention);
    result
}

struct Context {
    socket: PathBuf,
    request: LaunchRequest,
    notify: SystemdNotifyEndpoint,
}
impl Context {
    fn parse(args: &[OsString], invocation: &str, notify: &str) -> Result<Self, SessionOwnerError> {
        let [socket, session, attempt, pin, unit] = args else {
            return Err(SessionOwnerError::Invalid(
                "expected five owner arguments",
            ));
        };
        let socket = PathBuf::from(socket);
        if !socket.is_absolute()
            || socket
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(SessionOwnerError::Invalid(
                "invalid rendezvous path",
            ));
        }
        let session = SessionId::parse(string(session)?)
            .map_err(|_| SessionOwnerError::Invalid("invalid session identifier"))?;
        let attempt = AttemptId::parse(string(attempt)?)
            .map_err(|_| SessionOwnerError::Invalid("invalid attempt identifier"))?;
        let manifest = string(pin)?
            .parse()
            .map_err(|_| SessionOwnerError::Invalid("invalid manifest pin"))?;
        let unit = SystemdUnitName::new(string(unit)?)?;
        let binding = AttemptBinding::new(unit, parse_invocation(invocation)?)
            .map_err(|_| SessionOwnerError::Invalid("invalid invocation binding"))?;
        Ok(Self {
            socket,
            request: LaunchRequest {
                session,
                attempt,
                manifest,
                binding,
            },
            notify: SystemdNotifyEndpoint::new(notify)?,
        })
    }
}
fn string(value: &OsString) -> Result<&str, SessionOwnerError> {
    value.to_str().ok_or(SessionOwnerError::Invalid(
        "non-UTF8 owner argument",
    ))
}
fn parse_invocation(text: &str) -> Result<[u8; 16], SessionOwnerError> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SessionOwnerError::Invalid(
            "invalid invocation identifier",
        ));
    }
    let mut bytes = [0; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| SessionOwnerError::Invalid("invalid invocation identifier"))?;
    }
    if bytes == [0; 16] {
        return Err(SessionOwnerError::Invalid(
            "zero invocation identifier",
        ));
    }
    Ok(bytes)
}
fn receive_lease(
    channel: &PacketChannel,
    peer: Peer,
    deadline: Instant,
    cancellation: &Cancellation,
) -> Result<OwnedFd, SessionOwnerError> {
    let mut packet = channel.receive(peer, 1, deadline, cancellation)?;
    expect(&packet.bytes, super::RETENTION)?;
    packet
        .descriptors
        .pop()
        .ok_or(SessionOwnerError::Invalid(
            "missing retention descriptor",
        ))
}
fn wait_lifetime(
    channel: &PacketChannel,
    peer: Peer,
    cancellation: &Cancellation,
) -> Result<(), SessionOwnerError> {
    loop {
        match channel.receive(peer, 0, Instant::now() + LIFE_POLL, cancellation) {
            Ok(packet) => return expect(&packet.bytes, super::CLOSE),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
            Err(error) => return Err(error.into()),
        }
    }
}
fn expect(actual: &[u8], expected: &[u8]) -> Result<(), SessionOwnerError> {
    if actual == expected {
        Ok(())
    } else {
        Err(SessionOwnerError::Invalid(
            "unexpected owner protocol message",
        ))
    }
}
fn remaining(deadline: Instant) -> Result<Duration, SessionOwnerError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(io::Error::new(io::ErrorKind::TimedOut, "owner startup deadline").into())
    } else {
        Ok(remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<OsString> {
        [
            "/tmp/syrox/owner.sock".into(),
            "01".repeat(16),
            "02".repeat(16),
            crate::store::ContentDigest::sha256(b"manifest").to_string(),
            "syrox-owner-test.service".into(),
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn invocation_and_worker_arguments_are_bounded_and_explicit() {
        let arguments = args();
        let context = Context::parse(&arguments, &"03".repeat(16), "@systemd-notify").unwrap();
        assert_eq!(context.request.binding.invocation(), &[3; 16]);
        for invalid in [
            String::new(),
            "00".repeat(16),
            "AB".repeat(16),
            "a".repeat(33),
            "é".repeat(16),
        ] {
            assert!(Context::parse(&arguments, &invalid, "@systemd-notify").is_err());
        }
        for index in 0..5 {
            let mut invalid = arguments.clone();
            invalid[index] = OsString::from("invalid");
            assert!(Context::parse(&invalid, &"03".repeat(16), "@systemd-notify").is_err());
        }
        assert!(
            Context::parse(
                &arguments[..4],
                &"03".repeat(16),
                "@systemd-notify"
            )
            .is_err()
        );
        let mut extra = arguments;
        extra.push("extra".into());
        assert!(Context::parse(&extra, &"03".repeat(16), "@systemd-notify").is_err());
    }
    #[test]
    fn messages_require_exact_version_and_phase() {
        for expected in [
            super::super::RETENTION,
            super::super::COMMIT,
            super::super::CLOSE,
        ] {
            assert!(expect(expected, expected).is_ok());
            let mut trailing = expected.to_vec();
            trailing.push(b'\n');
            assert!(expect(&trailing, expected).is_err());
            assert!(expect(b"commit", expected).is_err());
        }
        assert!(expect(super::super::PROCESSED, super::super::COMMIT).is_err());
    }
    #[test]
    fn expired_startup_never_acquires_another_wait_budget() {
        assert!(
            remaining(
                Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .unwrap()
            )
            .is_err()
        );
    }
}
