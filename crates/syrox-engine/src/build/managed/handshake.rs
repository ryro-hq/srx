use super::{
    BuildError,
    preparation::{ManagedBuildRetention, PreparedManagedBuild},
    resources::ManagedBuildResources,
    supervision::{
        ManagedBuildServiceSpecification, ObservedManagedBuildBinding,
        observe_managed_build_binding, prepare_local_service, validate_endpoint,
    },
    transfer,
    worker::{ManagedBuildWorkerInspection, inspect_managed_build_worker},
};
use crate::execution::launcher::{
    rendezvous::Listener,
    transport::{PacketChannel, Peer},
};
use crate::{
    cancellation::Cancellation, platform::linux::fd as linux_fd, store::ContentDigest,
    systemd::SystemdManager,
};
use serde::{Deserialize, Serialize};
use std::os::fd::AsFd as _;
use std::path::Path;
use std::time::Instant;

const DOMAIN: &[u8] = b"syrox-managed-build-hello-v1\n";
const MAX_HELLO: usize = 1024;
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::build) struct Hello {
    operation: String,
    action: String,
    nonce: String,
    invocation: [u8; 16],
}
impl Hello {
    fn validate(&self) -> Result<(), BuildError> {
        if !self
            .operation
            .strip_prefix("op-")
            .is_some_and(hex_id)
            || !hex_id(&self.nonce)
            || self.invocation.iter().all(|byte| *byte == 0)
        {
            return Err(invalid());
        }
        let _: ContentDigest = self.action.parse().map_err(|_| invalid())?;
        Ok(())
    }
    pub(in crate::build) fn encode(&self) -> Result<Vec<u8>, BuildError> {
        self.validate()?;
        crate::build::managed::encode_json(DOMAIN, self, MAX_HELLO)
    }
    fn decode(bytes: &[u8]) -> Result<Self, BuildError> {
        let value: Self = crate::build::managed::decode_json(DOMAIN, bytes, MAX_HELLO)?;
        if value.encode()? != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
}
fn hex_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}
/// Owns one private listener while borrowing all prepared input retention.
/// It exposes a candidate service description; it does not issue Start.
pub struct ManagedBuildHandshake<'a> {
    prepared: &'a PreparedManagedBuild,
    specification: ManagedBuildServiceSpecification,
    listener: Listener,
}
impl std::fmt::Debug for ManagedBuildHandshake<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedBuildHandshake")
            .field("specification", &self.specification)
            .finish_non_exhaustive()
    }
}
/// An authenticated initial connection, holding prepared retention through its
/// borrow. This historical observation does not authorize future FD transfers.
pub struct AuthenticatedManagedBuild<'a> {
    prepared: &'a PreparedManagedBuild,
    binding: ObservedManagedBuildBinding,
    channel: PacketChannel,
    specification: ManagedBuildServiceSpecification,
}
impl std::fmt::Debug for AuthenticatedManagedBuild<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedManagedBuild")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}
impl AuthenticatedManagedBuild<'_> {
    pub fn binding(&self) -> &ObservedManagedBuildBinding {
        &self.binding
    }
}
/// A sent claim only, without coordinator acknowledgement or payload authority.
pub struct ManagedBuildHelloSent<'a> {
    inspection: &'a ManagedBuildWorkerInspection,
    channel: PacketChannel,
    peer: Peer,
    hello: Hello,
}
impl std::fmt::Debug for ManagedBuildHelloSent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedBuildHelloSent")
            .finish_non_exhaustive()
    }
}
impl<'a> ManagedBuildHandshake<'a> {
    pub fn begin(
        prepared: &'a PreparedManagedBuild,
        manager: &mut SystemdManager,
        private_directory: &Path,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<Self, BuildError> {
        prepared.with_managed_preparation_cleanup(
            cancellation,
            deadline,
            |local| {
                super::remaining_request(cancellation, deadline)?;
                let name = format!("build-{}.sock", &prepared.operation_id()[3..]);
                validate_endpoint(&private_directory.join(&name))?;
                let mut listener = Listener::bind(private_directory, &name)?;
                let specification = match prepare_local_service(
                    prepared,
                    manager,
                    listener.path(),
                    cancellation,
                    deadline,
                    local,
                ) {
                    Ok(value) => value,
                    Err(primary) => {
                        return match listener.close() {
                            Ok(()) => Err(primary),
                            Err(cleanup) => Err(BuildError::FailureAndCleanup {
                                primary: Box::new(primary),
                                cleanup,
                            }),
                        };
                    }
                };
                Ok(Self {
                    prepared,
                    specification,
                    listener,
                })
            },
            |mut handshake| handshake.listener.close(),
        )
    }

    pub fn specification(&self) -> &ManagedBuildServiceSpecification {
        &self.specification
    }
    /// Consume the listener, observe the manager twice, authenticate the zero-FD
    /// Hello, and record Bound. A second acceptance is impossible on this handle.
    /// Failure can leave a durable Bound observation; it does not imply that the
    /// journal was unchanged and must not trigger an automatic replay.
    pub fn accept(
        mut self,
        manager: &mut SystemdManager,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<AuthenticatedManagedBuild<'a>, BuildError> {
        let result = (|| {
            let first = observe_managed_build_binding(
                self.prepared,
                &self.specification,
                manager,
                cancellation,
                deadline,
            )?;
            let pidfd = linux_fd::pidfd_open(first.main_pid())?;
            let channel = self.listener.accept(deadline, cancellation)?;
            let peer = channel.peer_credentials()?;
            let expected = expected_hello(
                self.prepared.operation_id(),
                &self.specification,
                &first,
            )?;
            receive_hello(
                &channel,
                peer,
                &expected,
                &first,
                cancellation,
                deadline,
            )?;
            let second = observe_managed_build_binding(
                self.prepared,
                &self.specification,
                manager,
                cancellation,
                deadline,
            )?;
            if !same_binding(&first, &second) || linux_fd::pidfd_exited(pidfd.as_fd())? {
                return Err(invalid());
            }
            self.prepared
                .bind_manager_observation(&second, cancellation, deadline)?;
            Ok((second, channel))
        })();
        match (result, self.listener.close()) {
            (Ok((binding, channel)), Ok(())) => Ok(AuthenticatedManagedBuild {
                prepared: self.prepared,
                binding,
                channel,
                specification: self.specification,
            }),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(cleanup)) => Err(BuildError::Cleanup(cleanup)),
            (Err(primary), Err(cleanup)) => Err(BuildError::FailureAndCleanup {
                primary: Box::new(primary),
                cleanup,
            }),
        }
    }
}
/// Send a claim from a revalidated staging inspection. Invocation is a claim to
/// be checked against manager/peer evidence by `accept()`, never trusted by itself.
pub fn connect_managed_build_worker<'a>(
    inspection: &'a ManagedBuildWorkerInspection,
    endpoint: &Path,
    invocation: [u8; 16],
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<ManagedBuildHelloSent<'a>, BuildError> {
    super::remaining_request(cancellation, deadline)?;
    validate_endpoint(endpoint)?;
    inspection.revalidate(cancellation, deadline)?;
    let hello = Hello {
        operation: inspection
            .operation_path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(invalid)?
            .into(),
        action: inspection.action_digest().to_string(),
        nonce: inspection.nonce().into(),
        invocation,
    };
    let bytes = hello.encode()?;
    let channel = PacketChannel::connect(endpoint, deadline, cancellation)?;
    let peer = channel.peer_credentials()?;
    if peer.uid != linux_fd::effective_uid() {
        return Err(invalid());
    }
    channel.send(&bytes, &[], deadline, cancellation)?;
    Ok(ManagedBuildHelloSent {
        inspection,
        channel,
        peer,
        hello,
    })
}
/// A completed resource send retaining both the coordinator's preparation and
/// independent descriptor package. No FDSTORE acknowledgement has occurred;
/// keep this handle alive until the later protocol explicitly settles ownership.
pub struct ManagedBuildResourcesSent<'a> {
    pub(in crate::build) prepared: &'a PreparedManagedBuild,
    _retention: ManagedBuildRetention,
    pub(in crate::build) resources: ManagedBuildResources,
    pub(in crate::build) channel: PacketChannel,
    pub(in crate::build) binding: ObservedManagedBuildBinding,
    pub(in crate::build) specification: ManagedBuildServiceSpecification,
}
impl std::fmt::Debug for ManagedBuildResourcesSent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedBuildResourcesSent")
            .field("resources", &self.resources)
            .finish_non_exhaustive()
    }
}
impl ManagedBuildResourcesSent<'_> {
    pub fn action_digest(&self) -> ContentDigest {
        self.resources.action_digest()
    }
}
/// A complete authenticated resource package and a historical Bound inspection.
/// This handle grants no mount, exec, COMMIT or readiness authority.
pub struct ReceivedManagedBuildResources {
    pub(in crate::build) inspection: ManagedBuildWorkerInspection,
    pub(in crate::build) resources: ManagedBuildResources,
    pub(in crate::build) channel: PacketChannel,
    pub(in crate::build) peer: Peer,
    pub(in crate::build) hello: Vec<u8>,
}
impl std::fmt::Debug for ReceivedManagedBuildResources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedManagedBuildResources")
            .field("resources", &self.resources)
            .finish_non_exhaustive()
    }
}
impl<'a> AuthenticatedManagedBuild<'a> {
    /// Derive retention and resources from this exact preparation, then recheck
    /// the current manager binding before sending. Arbitrary validated resource
    /// packages cannot substitute another Store. Errors can follow partial
    /// transfer; neither endpoint may execute.
    pub fn send_resources(
        self,
        manager: &mut SystemdManager,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<ManagedBuildResourcesSent<'a>, BuildError> {
        super::remaining_request(cancellation, deadline)?;
        let retention = self
            .prepared
            .retain_for_handoff(cancellation, deadline)?;
        let resources = self
            .prepared
            .prepare_resources(&retention, cancellation, deadline)?;
        let inspection = inspect_managed_build_worker(
            self.prepared.operation_path(),
            self.prepared.action_digest(),
            self.binding.nonce(),
            cancellation,
            deadline,
        )?;
        if inspection.bound_process()
            != Some((
                *self.binding.invocation(),
                self.binding.main_pid(),
            ))
        {
            return Err(invalid());
        }
        let observed = observe_managed_build_binding(
            self.prepared,
            &self.specification,
            manager,
            cancellation,
            deadline,
        )?;
        if !same_binding(&self.binding, &observed) {
            return Err(invalid());
        }
        validate_peer(self.channel.peer_credentials()?, &observed)?;
        inspection.revalidate(cancellation, deadline)?;
        let hello = expected_hello(
            self.prepared.operation_id(),
            &self.specification,
            &observed,
        )?;
        transfer::send(
            &self.channel,
            &hello.encode()?,
            &resources,
            cancellation,
            deadline,
        )?;
        Ok(ManagedBuildResourcesSent {
            prepared: self.prepared,
            _retention: retention,
            resources,
            channel: self.channel,
            binding: self.binding,
            specification: self.specification,
        })
    }
}
impl ManagedBuildHelloSent<'_> {
    /// Authenticate every frame against the socket peer fixed at connect time.
    /// The private endpoint and trusted same-UID Store define coordinator trust;
    /// this is not an independent coordinator executable identity proof.
    pub fn receive_resources(
        self,
        cancellation: &Cancellation,
        deadline: Instant,
    ) -> Result<ReceivedManagedBuildResources, BuildError> {
        let (inspection, resources) = transfer::receive(
            &self.channel,
            self.peer,
            &self.hello.encode()?,
            self.inspection,
            self.hello.invocation,
            cancellation,
            deadline,
        )?;
        Ok(ReceivedManagedBuildResources {
            inspection,
            resources,
            channel: self.channel,
            peer: self.peer,
            hello: self.hello.encode()?,
        })
    }
}
pub(in crate::build) fn expected_hello(
    operation: &str,
    specification: &ManagedBuildServiceSpecification,
    binding: &ObservedManagedBuildBinding,
) -> Result<Hello, BuildError> {
    if binding.context() != specification.context() || binding.nonce() != specification.nonce() {
        return Err(invalid());
    }
    Ok(Hello {
        operation: operation.into(),
        action: binding.context().action.to_string(),
        nonce: binding.nonce().into(),
        invocation: *binding.invocation(),
    })
}
fn receive_hello(
    channel: &PacketChannel,
    peer: Peer,
    expected: &Hello,
    binding: &ObservedManagedBuildBinding,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(), BuildError> {
    validate_peer(peer, binding)?;
    let packet = channel.receive(peer, 0, deadline, cancellation)?;
    match_claim(
        &Hello::decode(&packet.bytes)?,
        expected,
        peer,
        binding,
    )
}
fn validate_peer(peer: Peer, binding: &ObservedManagedBuildBinding) -> Result<(), BuildError> {
    if peer.pid != binding.main_pid()
        || peer.uid != binding.context().uid
        || peer.gid != binding.context().gid
    {
        return Err(invalid());
    }
    Ok(())
}
fn match_claim(
    actual: &Hello,
    expected: &Hello,
    peer: Peer,
    binding: &ObservedManagedBuildBinding,
) -> Result<(), BuildError> {
    validate_peer(peer, binding)?;
    if actual != expected {
        return Err(invalid());
    }
    Ok(())
}
pub(in crate::build) fn same_binding(
    first: &ObservedManagedBuildBinding,
    second: &ObservedManagedBuildBinding,
) -> bool {
    first.context() == second.context()
        && first.nonce() == second.nonce()
        && first.invocation() == second.invocation()
        && first.main_pid() == second.main_pid()
        && first.contract() == second.contract()
}

fn invalid() -> BuildError {
    BuildError::InvalidRequest
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::journal::managed::ManagedAttemptContext;
    use std::os::fd::AsFd;
    use std::time::Duration;
    fn hello() -> Hello {
        Hello {
            operation: "op-0123456789abcdef0123456789abcdef".into(),
            action: ContentDigest::sha256(b"action").to_string(),
            nonce: "1123456789abcdef0123456789abcdef".into(),
            invocation: [1; 16],
        }
    }
    fn binding() -> ObservedManagedBuildBinding {
        let peer = Peer::current();
        ObservedManagedBuildBinding::for_test(
            ManagedAttemptContext {
                action: hello().action.parse().unwrap(),
                worker: ContentDigest::sha256(b"worker"),
                boot: "12345678-1234-1234-1234-123456789abc".into(),
                manager: ContentDigest::sha256(b"manager"),
                scope: "user:/run/user/test/bus".into(),
                unit: crate::systemd::SystemdUnitName::new("syrox-build-test.service").unwrap(),
                uid: peer.uid,
                gid: peer.gid,
            },
            hello().nonce,
            [1; 16],
            peer.pid,
            ContentDigest::sha256(b"contract"),
        )
    }
    #[test]
    fn hello_is_bounded_canonical_and_build_domain_only() {
        let value = hello();
        let bytes = value.encode().unwrap();
        assert_eq!(Hello::decode(&bytes).unwrap(), value);
        for altered in [
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.as_slice(), b"\n"].concat(),
            [
                b"syrox-service-v1\n",
                &bytes[DOMAIN.len()..],
            ]
            .concat(),
            vec![b'x'; MAX_HELLO + 1],
        ] {
            assert!(Hello::decode(&altered).is_err());
        }
        let extra = String::from_utf8(bytes)
            .unwrap()
            .replace("\"operation\":", "\"extra\":true,\"operation\":");
        assert!(Hello::decode(extra.as_bytes()).is_err());
    }
    #[test]
    fn hello_rejects_invalid_operation_nonce_invocation_and_digest() {
        for change in 0..5 {
            let mut value = hello();
            match change {
                0 => value.operation = "../op-invalid".into(),
                1 => value.nonce = "0".repeat(32),
                2 => value.nonce = "A".repeat(32),
                3 => value.invocation = [0; 16],
                _ => value.action = "not-a-pin".into(),
            }
            assert!(value.encode().is_err());
        }
    }
    #[test]
    fn peer_and_claim_must_match_observed_binding() {
        let expected = hello();
        let binding = binding();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(1);
        let (sender, receiver) = PacketChannel::pair().unwrap();
        sender
            .send(
                &expected.encode().unwrap(),
                &[],
                deadline,
                &cancel,
            )
            .unwrap();
        receive_hello(
            &receiver,
            Peer::current(),
            &expected,
            &binding,
            &cancel,
            deadline,
        )
        .unwrap();
        let mut wrong = hello();
        wrong.invocation = [2; 16];
        sender
            .send(&wrong.encode().unwrap(), &[], deadline, &cancel)
            .unwrap();
        assert!(
            receive_hello(
                &receiver,
                Peer::current(),
                &expected,
                &binding,
                &cancel,
                deadline
            )
            .is_err()
        );
        let mut wrong_peer = Peer::current();
        wrong_peer.pid += 1;
        assert!(
            receive_hello(
                &receiver, wrong_peer, &expected, &binding, &cancel, deadline
            )
            .is_err()
        );
    }
    #[test]
    fn hello_rejects_descriptor_handoff_and_eof() {
        let (sender, receiver) = PacketChannel::pair().unwrap();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(1);
        let file = std::fs::File::open("/dev/null").unwrap();
        sender
            .send(
                &hello().encode().unwrap(),
                &[file.as_fd()],
                deadline,
                &cancel,
            )
            .unwrap();
        assert!(
            receive_hello(
                &receiver,
                Peer::current(),
                &hello(),
                &binding(),
                &cancel,
                deadline
            )
            .is_err()
        );
        drop(sender);
        assert!(
            receive_hello(
                &receiver,
                Peer::current(),
                &hello(),
                &binding(),
                &cancel,
                deadline
            )
            .is_err()
        );
    }
    #[test]
    fn cancelled_hello_does_not_consume_a_queued_claim() {
        let (sender, receiver) = PacketChannel::pair().unwrap();
        let cancel = Cancellation::default();
        let deadline = Instant::now() + Duration::from_secs(1);
        sender
            .send(&hello().encode().unwrap(), &[], deadline, &cancel)
            .unwrap();
        let stopped = Cancellation::default();
        stopped.cancel();
        assert!(
            receive_hello(
                &receiver,
                Peer::current(),
                &hello(),
                &binding(),
                &stopped,
                deadline
            )
            .is_err()
        );
        receive_hello(
            &receiver,
            Peer::current(),
            &hello(),
            &binding(),
            &cancel,
            deadline,
        )
        .unwrap();
    }
    #[test]
    fn endpoint_preflight_refuses_unbounded_or_noncanonical_paths() {
        for endpoint in [
            "relative.sock".into(),
            "/private/../hello.sock".into(),
            format!("/{}", "x".repeat(107)),
            "/private//hello.sock".into(),
        ] {
            assert!(validate_endpoint(Path::new(&endpoint)).is_err());
        }
    }

    #[test]
    fn changing_any_claim_or_kernel_peer_identity_is_rejected_without_ipc() {
        let expected = hello();
        let binding = binding();
        let peer = Peer::current();
        match_claim(&hello(), &expected, peer, &binding).unwrap();
        for field in 0..4 {
            let mut changed = hello();
            match field {
                0 => changed.operation = "op-2123456789abcdef0123456789abcdef".into(),
                1 => changed.action = ContentDigest::sha256(b"other-action").to_string(),
                2 => changed.nonce = "2123456789abcdef0123456789abcdef".into(),
                _ => changed.invocation = [2; 16],
            }
            assert!(match_claim(&changed, &expected, peer, &binding).is_err());
        }
        for changed in [
            Peer {
                pid: peer.pid + 1,
                ..peer
            },
            Peer {
                uid: peer.uid + 1,
                ..peer
            },
            Peer {
                gid: peer.gid + 1,
                ..peer
            },
        ] {
            assert!(match_claim(&hello(), &expected, changed, &binding).is_err());
        }
    }
    #[test]
    fn fresh_manager_observation_must_preserve_complete_binding_context() {
        let first = binding();
        assert!(same_binding(&first, &binding()));
        for field in 0..9 {
            let mut context = first.context().clone();
            let mut nonce = first.nonce().to_owned();
            let mut invocation = *first.invocation();
            let mut pid = first.main_pid();
            let mut contract = first.contract();
            match field {
                0 => context.action = ContentDigest::sha256(b"another-action"),
                1 => context.worker = ContentDigest::sha256(b"another-worker"),
                2 => context.manager = ContentDigest::sha256(b"another-manager"),
                3 => context.boot = "22345678-1234-1234-1234-123456789abc".into(),
                4 => {
                    context.unit =
                        crate::systemd::SystemdUnitName::new("syrox-other.service").unwrap();
                }
                5 => nonce = "2123456789abcdef0123456789abcdef".into(),
                6 => invocation = [2; 16],
                7 => pid += 1,
                _ => contract = ContentDigest::sha256(b"another-contract"),
            }
            let changed =
                ObservedManagedBuildBinding::for_test(context, nonce, invocation, pid, contract);
            assert!(!same_binding(&first, &changed));
        }
    }
}
