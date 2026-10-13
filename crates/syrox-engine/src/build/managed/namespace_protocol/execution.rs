use super::{
    ObservedManagedBuildNamespace, PublishedManagedBuildNamespace, expected_hello, invalid,
    manager_error, observe_managed_build_binding, remaining, same_binding,
};
use crate::build::bootstrap::{capture::Capture, group};
use crate::build::journal::managed::{
    ManagedNamespaceSnapshot, consume_managed_commit, inspect_worker_attempt,
};
use crate::build::managed::{decode_json as decode, encode_json as encode};
use crate::build::{
    BuildError, managed::ManagedBuildWorkerInspection, managed::ObservedManagedBuildBinding,
};
use crate::execution::transport::{PacketChannel, Peer};
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
    systemd::SystemdManager, systemd::SystemdNotifier,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::os::fd::BorrowedFd;
use std::os::unix::process::ExitStatusExt as _;
use std::time::{Duration, Instant};

const COMMIT: &[u8] = b"syrox-managed-build-commit-v1\n";
const EXIT: &[u8] = b"syrox-managed-build-exit-v1\n";
const ACK: &[u8] = b"syrox-managed-build-exit-observed-v1\n";
const ACK_TIMEOUT: Duration = Duration::from_secs(5);
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Namespace {
    pid: u32,
    device: u64,
    inode: u64,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Commit {
    hello: String,
    resources: String,
    namespace: Namespace,
    timeout_seconds: u32,
}
impl Commit {
    fn encode(&self) -> Result<Vec<u8>, BuildError> {
        if !(1..=1800).contains(&self.timeout_seconds)
            || self.namespace.pid <= 1
            || self.namespace.pid > i32::MAX as u32
            || self.namespace.device == 0
            || self.namespace.inode == 0
        {
            return Err(invalid());
        }
        let _: ContentDigest = self.resources.parse().map_err(|_| invalid())?;
        encode(COMMIT, self, 2048)
    }
    fn decode(bytes: &[u8]) -> Result<Self, BuildError> {
        let value: Self = decode(COMMIT, bytes, 2048)?;
        if value.encode()? != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
    fn snapshot(&self) -> Result<ManagedNamespaceSnapshot, BuildError> {
        Ok(ManagedNamespaceSnapshot {
            resources: self.resources.parse().map_err(|_| invalid())?,
            pid: self.namespace.pid,
            device: self.namespace.device,
            inode: self.namespace.inode,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitMessage {
    commit: String,
    code: i32,
}
fn exit_bytes(commit: &[u8], code: i32) -> Result<Vec<u8>, BuildError> {
    if !(0..=255).contains(&code) {
        return Err(invalid());
    }
    encode(
        EXIT,
        &ExitMessage {
            commit: std::str::from_utf8(commit)
                .map_err(|_| invalid())?
                .into(),
            code,
        },
        4096,
    )
}
fn exit_code(bytes: &[u8], commit: &[u8]) -> Result<i32, BuildError> {
    let message: ExitMessage = decode(EXIT, bytes, 4096)?;
    if exit_bytes(commit, message.code)? != bytes {
        return Err(invalid());
    }
    Ok(message.code)
}
fn acknowledgement(exit: &[u8]) -> Vec<u8> {
    let mut bytes = ACK.to_vec();
    bytes.extend(ContentDigest::sha256(exit).to_string().as_bytes());
    bytes
}
/// Authenticated worker report after reaping namespace init. This is not a
/// receipt, artifact validation or proof that the manager released its FD store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManagedBuildExit {
    code: i32,
    message: ContentDigest,
}
impl ManagedBuildExit {
    fn code(self) -> i32 {
        self.code
    }
}
/// Keeps preparation, capture and both retention proofs alive after COMMIT.
/// A failed COMMIT send may already have authorized/started work; never replay.
#[derive(Debug)]
pub struct CommittedManagedBuild<'a> {
    observed: ObservedManagedBuildNamespace<'a>,
    commit: Vec<u8>,
    capture_taken: bool,
    exit: Option<ManagedBuildExit>,
    acknowledged: bool,
}
impl<'a> ObservedManagedBuildNamespace<'a> {
    pub fn authorize_execution(
        self,
        manager: &mut SystemdManager,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<CommittedManagedBuild<'a>, BuildError> {
        self.revalidate(cancel, deadline)?;
        let sent = &self.retention.sent;
        let fresh = observe_managed_build_binding(
            sent.prepared,
            &sent.specification,
            manager,
            cancel,
            deadline,
        )?;
        let peer = sent.channel.peer_credentials()?;
        if !same_binding(&fresh, &sent.binding)
            || peer.pid != fresh.main_pid()
            || peer.uid != fresh.context().uid
            || peer.gid != fresh.context().gid
        {
            return Err(invalid());
        }
        let identity = self.namespace.file_identity();
        let commit = Commit {
            hello: std::str::from_utf8(
                &expected_hello(
                    sent.prepared.operation_id(),
                    &sent.specification,
                    &fresh,
                )?
                .encode()?,
            )
            .map_err(|_| invalid())?
            .into(),
            resources: self.resources.to_string(),
            namespace: Namespace {
                pid: self.namespace.pid(),
                device: identity.device,
                inode: identity.inode,
            },
            timeout_seconds: sent.prepared.timeout_seconds(),
        }
        .encode()?;
        sent.prepared
            .authorize_execution(&self, cancel, deadline, || {
                sent.channel
                    .send(&commit, &[], deadline, cancel)?;
                Ok(())
            })?;
        Ok(CommittedManagedBuild {
            observed: self,
            commit,
            capture_taken: false,
            exit: None,
            acknowledged: false,
        })
    }
}
impl CommittedManagedBuild<'_> {
    pub fn action_digest(&self) -> ContentDigest {
        self.observed.action_digest()
    }
    pub(in crate::build) fn binding(&self) -> &ObservedManagedBuildBinding {
        self.observed.binding()
    }
    pub(in crate::build) fn namespace_pidfd(&self) -> BorrowedFd<'_> {
        self.observed.namespace.pidfd()
    }
    fn take_capture(
        &mut self,
    ) -> Result<crate::execution::native::build::BuildCapture, BuildError> {
        if self.capture_taken {
            return Err(invalid());
        }
        self.observed.capture.revalidate()?;
        let capture = crate::execution::native::build::BuildCapture::from_received(
            self.observed
                .capture
                .artifacts
                .try_clone()?
                .into(),
            self.observed.capture.logs.try_clone()?.into(),
        )?;
        self.capture_taken = true;
        Ok(capture)
    }
    fn poll_exit(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Option<ManagedBuildExit>, BuildError> {
        if self.exit.is_some() {
            return Ok(self.exit);
        }
        let sent = &self.observed.retention.sent;
        let peer = sent.channel.peer_credentials()?;
        if peer.pid != self.binding().main_pid()
            || peer.uid != self.binding().context().uid
            || peer.gid != self.binding().context().gid
        {
            return Err(invalid());
        }
        let tick = deadline.min(Instant::now() + Duration::from_millis(25));
        let Some(packet) = receive_tick(&sent.channel, peer, cancel, tick)? else {
            return Ok(None);
        };
        let code = exit_code(&packet, &self.commit)?;
        check_journal(
            &self.observed.inspection,
            &Commit::decode(&self.commit)?,
            true,
            cancel,
            deadline,
        )?;
        if !linux_fd::pidfd_exited(self.namespace_pidfd())? {
            return Err(invalid());
        }
        let exit = ManagedBuildExit {
            code,
            message: ContentDigest::sha256(&packet),
        };
        self.exit = Some(exit);
        Ok(Some(exit))
    }
    /// Caller additionally verifies both capture streams reached EOF. This ACK
    /// cannot certify systemd settlement or authorize result publication.
    fn acknowledge_exit(
        &mut self,
        exit: &ManagedBuildExit,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        if self.acknowledged
            || self.exit.as_ref() != Some(exit)
            || !linux_fd::pidfd_exited(self.namespace_pidfd())?
        {
            return Err(invalid());
        }
        let bytes = exit_bytes(&self.commit, exit.code)?;
        if ContentDigest::sha256(&bytes) != exit.message {
            return Err(invalid());
        }
        self.acknowledged = true;
        self.observed.retention.sent.channel.send(
            &acknowledgement(&bytes),
            &[],
            deadline,
            cancel,
        )?;
        Ok(())
    }
}
fn receive_tick(
    channel: &PacketChannel,
    peer: Peer,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, BuildError> {
    match channel.receive(peer, 0, deadline, cancel) {
        Ok(packet) => Ok(Some(packet.bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(None),
        Err(error) => {
            cancel.check()?;
            Err(error.into())
        }
    }
}
fn check_journal(
    original: &ManagedBuildWorkerInspection,
    commit: &Commit,
    consumed: bool,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<(), BuildError> {
    let current = inspect_worker_attempt(
        original.operation_path(),
        original.action_digest(),
        original.nonce(),
        cancel,
        deadline,
    )?;
    if !current.matches_original(original.record_bytes())?
        || current.namespace_snapshot()? != Some(commit.snapshot()?)
        || (consumed && !current.commit_consumed()?)
    {
        return Err(BuildError::InputChanged);
    }
    Ok(())
}
impl PublishedManagedBuildNamespace<'_> {
    pub(in crate::build) fn execute(
        mut self,
        notifier: &SystemdNotifier,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<i32, BuildError> {
        let commit = self.receive_commit(cancel, deadline)?;
        let runtime_deadline = consume_managed_commit(&mut self, cancel, deadline, |published| {
            published
                .namespace
                .release_gate(cancel, deadline)?;
            Ok(Instant::now() + Duration::from_secs(u64::from(commit.timeout_seconds)))
        })?;
        self.namespace
            .await_exec(cancel, runtime_deadline)?;
        notifier
            .ready(remaining(cancel, runtime_deadline)?, cancel)
            .map_err(|error| manager_error(&error))?;
        let code = self.await_status(&commit, cancel, runtime_deadline)?;
        let exit = exit_bytes(&commit.encode()?, code)?;
        let acknowledgement_deadline = Instant::now() + ACK_TIMEOUT;
        let received = &self.namespace.published.received;
        received
            .channel
            .send(&exit, &[], acknowledgement_deadline, cancel)?;
        self.await_exit_ack(&commit, &exit, cancel, acknowledgement_deadline)?;
        Ok(code)
    }
    fn receive_commit(
        &self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<Commit, BuildError> {
        loop {
            self.namespace.check_stop(cancel)?;
            remaining(cancel, deadline)?;
            let received = &self.namespace.published.received;
            // Poll the journal without hashing staged multi-megabyte files.
            let current = inspect_worker_attempt(
                self.inspection().operation_path(),
                self.action_digest(),
                self.inspection().nonce(),
                cancel,
                deadline,
            )?;
            if !current.matches_original(self.inspection().record_bytes())?
                || linux_fd::pidfd_exited(self.namespace_pidfd())?
            {
                return Err(invalid());
            }
            drop(current);
            let tick = deadline.min(Instant::now() + Duration::from_millis(100));
            let Some(bytes) = receive_tick(&received.channel, received.peer, cancel, tick)? else {
                continue;
            };
            let commit = Commit::decode(&bytes)?;
            if commit.hello.as_bytes() != received.hello
                || commit.resources != self.resources_digest().to_string()
            {
                return Err(invalid());
            }
            let identity = linux_fd::require_unique_pidfd(self.namespace_pidfd())?.identity();
            if commit.namespace.device != identity.device
                || commit.namespace.inode != identity.inode
            {
                return Err(invalid());
            }
            check_journal(
                self.inspection(),
                &commit,
                false,
                cancel,
                deadline,
            )?;
            return Ok(commit);
        }
    }
    fn await_status(
        &mut self,
        commit: &Commit,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<i32, BuildError> {
        loop {
            self.namespace.check_stop(cancel)?;
            remaining(cancel, deadline)?;
            check_journal(self.inspection(), commit, true, cancel, deadline)?;
            if let Some(status) = self.namespace.try_wait()? {
                return Ok(status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)));
            }
            let received = &self.namespace.published.received;
            let tick = deadline.min(Instant::now() + Duration::from_millis(100));
            if receive_tick(&received.channel, received.peer, cancel, tick)?.is_some() {
                return Err(invalid());
            }
        }
    }
    fn await_exit_ack(
        &self,
        commit: &Commit,
        exit: &[u8],
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), BuildError> {
        loop {
            self.namespace.check_stop(cancel)?;
            remaining(cancel, deadline)?;
            check_journal(self.inspection(), commit, true, cancel, deadline)?;
            let received = &self.namespace.published.received;
            let tick = deadline.min(Instant::now() + Duration::from_millis(100));
            if let Some(packet) = receive_tick(&received.channel, received.peer, cancel, tick)? {
                if packet != acknowledgement(exit) {
                    return Err(invalid());
                }
                return Ok(());
            }
        }
    }
}
/// Captured worker framing, still awaiting manager settlement and independent
/// artifact validation. This handle never represents an admitted build result.
#[derive(Debug)]
pub struct CapturedManagedBuildOutput {
    action: ContentDigest,
    file: File,
}
impl CapturedManagedBuildOutput {
    pub(in crate::build) fn into_file(self) -> File {
        self.file
    }
    pub fn action_digest(&self) -> ContentDigest {
        self.action
    }
}

struct Pipes {
    output: Capture<File>,
    log: Capture<File>,
}
impl Pipes {
    fn new(capture: crate::execution::native::build::BuildCapture) -> Result<Self, BuildError> {
        capture.revalidate()?;
        Ok(Self {
            output: Capture::new_disk(
                capture.artifacts,
                usize::try_from(group::MAX_GROUP_BYTES).expect("bounded output fits usize"),
            )?,
            log: Capture::new(capture.logs, 512 * 1024, true)?,
        })
    }
    fn drain(&mut self) -> Result<(), BuildError> {
        self.output.drain()?;
        self.log.drain()?;
        if self.output.overflow {
            return Err(BuildError::Output);
        }
        Ok(())
    }
    fn eof(&self) -> bool {
        self.output.eof && self.log.eof
    }
}

impl CommittedManagedBuild<'_> {
    /// Collect once, keeping the attempt and its retention in this handle on
    /// either success or error. Errors require revocation and explicit manager
    /// settlement by the coordinator. Success acknowledges only exit observation.
    pub fn collect_output(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<CapturedManagedBuildOutput, BuildError> {
        cancel.check()?;
        let mut pipes = Pipes::new(self.take_capture()?)?;
        let mut exit = None;
        loop {
            cancel.check()?;
            if Instant::now() >= deadline {
                return Err(BuildError::Timeout);
            }
            pipes.drain()?;
            if exit.is_none() {
                exit = self.poll_exit(cancel, deadline)?;
            }
            if let Some(observed) = &exit {
                if pipes.eof() && linux_fd::pidfd_exited(self.namespace_pidfd())? {
                    self.acknowledge_exit(observed, cancel, deadline)?;
                    if observed.code() != 0 {
                        return Err(BuildError::Execution(format!(
                            "managed worker exited with {}: {}",
                            observed.code(),
                            pipes.log.diagnostic()
                        )));
                    }
                    let (file, _) = pipes.output.into_disk()?;
                    return Ok(CapturedManagedBuildOutput {
                        action: self.action_digest(),
                        file,
                    });
                }
                // No more EXIT packets are expected. Keep cancellation latency
                // bounded while waiting for inherited pipe writers to close.
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    fn commit() -> Commit {
        Commit {
            hello: "authenticated hello".into(),
            resources: ContentDigest::sha256(b"resource").to_string(),
            namespace: Namespace {
                pid: 123,
                device: 1,
                inode: 456,
            },
            timeout_seconds: 30,
        }
    }
    #[test]
    fn commit_codec_requires_domain_canonical_fields_and_bounded_timeout() {
        let expected = commit();
        let bytes = expected.encode().unwrap();
        assert_eq!(Commit::decode(&bytes).unwrap(), expected);
        let mut extra = bytes.clone();
        extra.push(b' ');
        assert!(Commit::decode(&extra).is_err());
        assert!(Commit::decode(&bytes[1..]).is_err());
        let mut extra = bytes.clone();
        extra.pop();
        extra.extend(b",\"extra\":true}");
        assert!(Commit::decode(&extra).is_err());
        for timeout in [0, 1801, u32::MAX] {
            let mut value = commit();
            value.timeout_seconds = timeout;
            assert!(value.encode().is_err());
        }
        let mut value = commit();
        value.namespace.inode = 0;
        assert!(value.encode().is_err());
        let mut value = commit();
        value.hello = "x".repeat(4096);
        assert!(value.encode().is_err());
    }
    #[test]
    fn exit_and_ack_bind_full_commit_and_code_without_settlement_claim() {
        let commit = commit().encode().unwrap();
        let bytes = exit_bytes(&commit, 0).unwrap();
        assert_eq!(exit_code(&bytes, &commit).unwrap(), 0);
        let mut other = Commit::decode(&commit).unwrap();
        other.namespace.pid += 1;
        assert!(exit_code(&bytes, &other.encode().unwrap()).is_err());
        assert_ne!(
            acknowledgement(&bytes),
            acknowledgement(&exit_bytes(&commit, 1).unwrap())
        );
        for code in [-1, 256] {
            assert!(exit_bytes(&commit, code).is_err());
        }
        assert!(exit_code(&acknowledgement(&bytes), &commit).is_err());
    }
    #[test]
    fn protocol_packets_reject_descriptors_and_eof() {
        let (sender, receiver) = PacketChannel::pair().unwrap();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let file = File::open("/dev/null").unwrap();
        sender
            .send(
                &commit().encode().unwrap(),
                &[file.as_fd()],
                deadline,
                &cancel,
            )
            .unwrap();
        assert!(receive_tick(&receiver, Peer::current(), &cancel, deadline).is_err());
        drop(sender);
        assert!(receive_tick(&receiver, Peer::current(), &cancel, deadline).is_err());
    }

    use crate::execution::native::build::BuildCapture;
    use std::io::{PipeWriter, Read as _, Write as _};
    use std::os::fd::OwnedFd;

    fn channels() -> (BuildCapture, PipeWriter, PipeWriter) {
        let (output, output_writer) = std::io::pipe().unwrap();
        let (log, log_writer) = std::io::pipe().unwrap();
        crate::platform::linux::fd::set_nonblocking(output.as_fd()).unwrap();
        crate::platform::linux::fd::set_nonblocking(log.as_fd()).unwrap();
        let capture =
            BuildCapture::from_received(OwnedFd::from(output), OwnedFd::from(log)).unwrap();
        (capture, output_writer, log_writer)
    }

    fn limited(output_bytes: usize, log_bytes: usize) -> (Pipes, PipeWriter, PipeWriter) {
        let (capture, output, log) = channels();
        (
            Pipes {
                output: Capture::<File>::new_disk(capture.artifacts, output_bytes).unwrap(),
                log: Capture::<File>::new(capture.logs, log_bytes, true).unwrap(),
            },
            output,
            log,
        )
    }

    #[test]
    fn eof_requires_both_capture_channels_and_preserves_output_bytes() {
        let (capture, mut output, log) = channels();
        let mut pipes = Pipes::new(capture).unwrap();
        output
            .write_all(b"framed artifact bytes")
            .unwrap();
        drop(output);
        pipes.drain().unwrap();
        assert!(pipes.output.eof);
        assert!(!pipes.log.eof);
        assert!(!pipes.eof());
        drop(log);
        pipes.drain().unwrap();
        assert!(pipes.eof());
        let (mut file, size) = pipes.output.into_disk().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(size, 21);
        assert_eq!(bytes, b"framed artifact bytes");
    }

    #[test]
    fn output_overflow_is_rejected_even_if_both_pipes_reach_eof() {
        let (mut pipes, mut output, log) = limited(4, 8);
        output.write_all(b"12345").unwrap();
        drop((output, log));
        assert!(matches!(pipes.drain(), Err(BuildError::Output)));
        assert!(pipes.output.overflow);
        let (mut file, size) = pipes.output.into_disk().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(size, 4);
        assert_eq!(bytes, b"1234");
    }

    #[test]
    fn diagnostic_overflow_keeps_the_tail_without_rejecting_artifacts() {
        let (mut pipes, mut output, mut log) = limited(4, 8);
        output.write_all(b"1234").unwrap();
        for message in [
            b"discarded-prefix:".as_slice(),
            b"failure!",
        ] {
            log.write_all(message).unwrap();
            pipes.drain().unwrap();
        }
        drop((output, log));
        pipes.drain().unwrap();
        assert!(pipes.eof());
        assert!(!pipes.output.overflow);
        assert!(pipes.log.overflow);
        assert_eq!(pipes.log.tail_bytes(usize::MAX), b"failure!");
        assert_eq!(pipes.log.tail_bytes(4), b"ure!");
        assert_eq!(
            pipes.log.diagnostic(),
            "[earlier diagnostics truncated]\nfailure!"
        );
    }

    #[test]
    fn empty_capture_returns_while_writers_remain_open() {
        let (mut pipes, output, log) = limited(4, 8);
        let (sent, received) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let result = pipes.drain().map(|()| pipes.eof());
            sent.send(result).unwrap();
        });
        let result = received.recv_timeout(Duration::from_secs(2));
        // Release writers even on timeout so a blocking-read regression can settle.
        drop((output, log));
        reader.join().unwrap();
        assert!(
            !result
                .expect("capture blocked on idle writers")
                .unwrap()
        );
    }
}
