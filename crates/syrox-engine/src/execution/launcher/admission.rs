use std::time::Instant;

use super::transport::{PacketChannel, Peer};
use crate::execution::journal::{
    AttemptBinding, AttemptId, OwnershipError, SessionId, SessionJournal,
};
use crate::{cancellation::Cancellation, store::ContentDigest, systemd::SystemdUnitName};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LaunchRequest {
    pub session: SessionId,
    pub attempt: AttemptId,
    pub manifest: ContentDigest,
    pub binding: AttemptBinding,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    session: String,
    attempt: String,
    manifest: String,
    unit: String,
    invocation: [u8; 16],
}
impl LaunchRequest {
    pub(super) fn encode(&self) -> Result<Vec<u8>, OwnershipError> {
        serde_json::to_vec(&Record {
            version: 1,
            session: self.session.to_string(),
            attempt: self.attempt.to_string(),
            manifest: self.manifest.to_string(),
            unit: self.binding.unit().as_str().into(),
            invocation: *self.binding.invocation(),
        })
        .map_err(|_| OwnershipError::Invalid("cannot encode launcher request"))
    }
    fn parse(bytes: &[u8]) -> Result<Self, OwnershipError> {
        let record: Record = serde_json::from_slice(bytes)
            .map_err(|_| OwnershipError::Invalid("malformed launcher request"))?;
        if record.version != 1 {
            return Err(OwnershipError::Invalid(
                "unsupported launcher request",
            ));
        }
        let request = Self {
            session: SessionId::parse(&record.session)?,
            attempt: AttemptId::parse(&record.attempt)?,
            manifest: record
                .manifest
                .parse()
                .map_err(|_| OwnershipError::Invalid("invalid launcher manifest digest"))?,
            binding: AttemptBinding::new(
                SystemdUnitName::new(record.unit)
                    .map_err(|_| OwnershipError::Invalid("invalid launcher unit"))?,
                record.invocation,
            )?,
        };
        if request.encode()? != bytes {
            return Err(OwnershipError::Invalid(
                "noncanonical launcher request",
            ));
        }
        Ok(request)
    }
}

/// `peer` and `expected` must come from independent manager/installation
/// evidence, never from the packet itself. Received descriptors are forbidden
/// during this direction of the handshake. Durable consumption precedes any
/// resource transfer; a lost response cannot be retried as another admission.
/// The caller still owns lifecycle checks, retained resources and payload gate.
pub(super) fn admit_request(
    channel: &PacketChannel,
    peer: Peer,
    expected: &LaunchRequest,
    journal: &SessionJournal,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), OwnershipError> {
    let packet = channel
        .receive(peer, 0, deadline, cancellation)
        .map_err(|error| {
            if crate::cancellation::is_cancellation_io(&error) {
                OwnershipError::Cancelled
            } else if error.kind() == std::io::ErrorKind::TimedOut {
                OwnershipError::Deadline
            } else {
                OwnershipError::Io(error)
            }
        })?;
    let request = LaunchRequest::parse(&packet.bytes)?;
    if &request != expected {
        return Err(OwnershipError::State(
            "launcher request differs from expected attempt",
        ));
    }
    journal.consume_attempt(
        &request.session,
        &request.attempt,
        request.manifest,
        &request.binding,
        cancellation,
        deadline,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    fn fixture() -> (tempfile::TempDir, SessionJournal, LaunchRequest) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(
            directory.path(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let journal = SessionJournal::open(directory.path()).unwrap();
        let cancellation = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(2);
        let manifest = ContentDigest::sha256(b"verified fixture manifest");
        let session = journal
            .create(
                b"verified fixture manifest",
                manifest,
                &cancellation,
                deadline,
            )
            .unwrap();
        let attempt = journal
            .prepare_attempt(&session, "owner", &cancellation, deadline)
            .unwrap();
        let binding = AttemptBinding::new(
            SystemdUnitName::new("syrox-test-owner.service").unwrap(),
            [42; 16],
        )
        .unwrap();
        journal
            .authorize_attempt(
                &session,
                &attempt,
                &binding,
                &cancellation,
                deadline,
            )
            .unwrap();
        (
            directory,
            journal,
            LaunchRequest {
                session,
                attempt,
                manifest,
                binding,
            },
        )
    }
    fn send(channel: &PacketChannel, request: &LaunchRequest) {
        channel
            .send(
                &request.encode().unwrap(),
                &[],
                Instant::now() + Duration::from_secs(2),
                &Cancellation::default(),
            )
            .unwrap();
    }
    #[test]
    fn lost_admission_response_cannot_replay_after_reopening_journal() {
        let (directory, journal, request) = fixture();
        let (sender, receiver) = PacketChannel::pair().unwrap();
        send(&sender, &request);
        admit_request(
            &receiver,
            Peer::current(),
            &request,
            &journal,
            &Cancellation::default(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        let state = journal
            .snapshot(
                &request.session,
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        let attempt = state
            .attempts
            .iter()
            .find(|entry| entry.id == request.attempt)
            .unwrap();
        assert_eq!(
            attempt.phase,
            crate::execution::journal::AttemptPhase::Consumed
        );
        assert_eq!(attempt.binding.as_ref(), Some(&request.binding));
        drop(journal);
        let reopened = SessionJournal::open(directory.path()).unwrap();
        send(&sender, &request);
        assert!(
            admit_request(
                &receiver,
                Peer::current(),
                &request,
                &reopened,
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(2)
            )
            .is_err()
        );
    }
    #[test]
    fn closing_revokes_a_request_already_queued_on_the_socket() {
        let (_directory, journal, request) = fixture();
        let (sender, receiver) = PacketChannel::pair().unwrap();
        send(&sender, &request);
        journal
            .begin_closing(
                &request.session,
                "owner disconnected",
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert!(
            admit_request(
                &receiver,
                Peer::current(),
                &request,
                &journal,
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(2)
            )
            .is_err()
        );
    }
    #[test]
    fn mismatched_invocation_does_not_consume_the_expected_attempt() {
        let (_directory, journal, request) = fixture();
        let (sender, receiver) = PacketChannel::pair().unwrap();
        let mut wrong = request.clone();
        wrong.binding = AttemptBinding::new(request.binding.unit().clone(), [43; 16]).unwrap();
        send(&sender, &wrong);
        assert!(
            admit_request(
                &receiver,
                Peer::current(),
                &request,
                &journal,
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(2)
            )
            .is_err()
        );
        send(&sender, &request);
        assert!(
            admit_request(
                &receiver,
                Peer::current(),
                &request,
                &journal,
                &Cancellation::default(),
                Instant::now() + Duration::from_secs(2)
            )
            .is_ok()
        );
    }
    #[test]
    fn malformed_and_future_wire_requests_are_rejected() {
        let (_directory, _journal, request) = fixture();
        let bytes = request.encode().unwrap();
        assert_eq!(LaunchRequest::parse(&bytes).unwrap(), request);
        let text = String::from_utf8(bytes).unwrap();
        for invalid in [
            format!(" {text}"),
            text.replace("\"version\":1", "\"version\":2"),
            text.replace("\"version\":1", "\"version\":1,\"version\":1"),
        ] {
            assert!(LaunchRequest::parse(invalid.as_bytes()).is_err());
        }
    }
}
