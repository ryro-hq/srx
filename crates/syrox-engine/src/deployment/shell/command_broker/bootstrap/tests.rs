use super::{
    BootstrapClient, BootstrapServer, Connection, MAX_ENVELOPE, Request, Response, Served, encode,
};
use crate::deployment::shell::command_broker::preparation::{
    BrokerPreparation, PreparedCommandBroker,
};
use crate::deployment::shell::{ShellSession, files::SessionFiles, secrets::SessionSecrets};
use crate::execution::transport::{PacketChannel, Peer};
use crate::{cancellation::Cancellation, store::ContentDigest};
use std::fs;
use std::os::fd::AsFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::time::{Duration, Instant};

const INVOCATION: &str = "1234567890abcdef1234567890abcdef";

fn request() -> Request {
    Request {
        version: 1,
        sequence: 7,
        invocation: INVOCATION.into(),
        alias: "public-command".into(),
        authorization: None,
    }
}

fn response(request: &Request, pin: Option<String>) -> Response {
    Response {
        version: 1,
        sequence: request.sequence,
        invocation: request.invocation.clone(),
        pin,
        authorized: None,
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn request_requires_canonical_invocation_sequence_and_alias() {
    let value = request();
    let bytes = encode(&value).unwrap();
    let decoded = Request::decode(&bytes, 7).unwrap();
    assert_eq!(decoded.alias, value.alias);
    assert_eq!(decoded.invocation, INVOCATION);
    assert_eq!(encode(&decoded).unwrap(), bytes);
    assert!(Request::decode(&bytes, 8).is_err());
    for alias in [
        "",
        ".",
        "..",
        "service/private",
        "/absolute",
        "with space",
    ] {
        let mut value = request();
        value.alias = alias.into();
        assert!(Request::decode(&encode(&value).unwrap(), 7).is_err());
    }
    let mut value = request();
    value.alias = "x".repeat(128);
    assert!(Request::decode(&encode(&value).unwrap(), 7).is_ok());
    value.alias.push('x');
    assert!(Request::decode(&encode(&value).unwrap(), 7).is_err());
    for invocation in [
        "0".repeat(32),
        INVOCATION.to_uppercase(),
        "short".into(),
    ] {
        let mut value = request();
        value.invocation = invocation;
        assert!(Request::decode(&encode(&value).unwrap(), 7).is_err());
    }
    let mut value = request();
    value.version = 2;
    assert!(Request::decode(&encode(&value).unwrap(), 7).is_err());
}

#[test]
fn response_matches_invocation_and_sequence_and_canonical_pin() {
    let request = request();
    let pin = ContentDigest::sha256(b"pinned specification").to_string();
    let granted = response(&request, Some(pin.clone()));
    assert_eq!(
        Response::decode(&encode(&granted).unwrap(), &request)
            .unwrap()
            .pin,
        Some(pin.clone())
    );
    assert!(
        Response::decode(
            &encode(&response(&request, None)).unwrap(),
            &request
        )
        .unwrap()
        .pin
        .is_none()
    );
    for pin in [
        String::new(),
        pin.to_uppercase(),
        "not-a-digest".into(),
    ] {
        assert!(
            Response::decode(
                &encode(&response(&request, Some(pin))).unwrap(),
                &request
            )
            .is_err()
        );
    }
    let mut wrong = response(&request, None);
    wrong.sequence += 1;
    assert!(Response::decode(&encode(&wrong).unwrap(), &request).is_err());
    wrong = response(&request, None);
    wrong.invocation = "abcdef1234567890abcdef1234567890".into();
    assert!(Response::decode(&encode(&wrong).unwrap(), &request).is_err());
    wrong = response(&request, None);
    wrong.version = 2;
    assert!(Response::decode(&encode(&wrong).unwrap(), &request).is_err());
}

#[test]
fn envelope_refuses_extra_fields_bytes_and_oversize_without_echoing_input() {
    let text = String::from_utf8(encode(&request()).unwrap()).unwrap();
    for body in [
        text.replace(
            "\"version\":1",
            "\"version\":1,\"configuration\":\"private-sentinel\"",
        ),
        text.replace("\"version\":1", "\"version\":1,\"version\":1"),
        format!("{text}\n"),
        text.trim_end().into(),
        text[..text.len() - 2].into(),
    ] {
        let error = Request::decode(body.as_bytes(), 7).err().unwrap();
        assert_eq!(
            error.to_string(),
            "invalid private command handoff"
        );
        assert!(!format!("{error:?}").contains("private-sentinel"));
    }
    assert!(Request::decode(&vec![b' '; MAX_ENVELOPE + 1], 7).is_err());
    let mut value = request();
    value.alias = "private-sentinel".repeat(MAX_ENVELOPE);
    assert_eq!(
        encode(&value).unwrap_err().to_string(),
        "invalid private command handoff"
    );
    let denied = encode(&response(&request(), None)).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&denied).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 4);
    assert!(json["pin"].is_null());
    assert!(json.get("error").is_none());
}

#[test]
fn handoff_error_preserves_cancellation_but_other_failure_is_redacted() {
    let cancel = Cancellation::default();
    let failure = super::handoff_error(&cancel);
    assert_eq!(
        failure.to_string(),
        "invalid private command handoff"
    );
    assert!(!crate::cancellation::is_cancellation_io(&failure));
    cancel.cancel();
    let failure = super::handoff_error(&cancel);
    assert!(crate::cancellation::is_cancellation_io(&failure));
}

#[test]
fn interrupted_exchange_poison_is_sticky_and_sequence_cannot_wrap() {
    // Active IPC test: sandbox refusal is a failure, never an ignored pass.
    let (left, _right) = PacketChannel::pair().expect("private bootstrap socketpair");
    let mut connection = Connection::new(left, Peer::current()).unwrap();
    assert_eq!(connection.begin().unwrap(), 0);
    assert!(
        connection.begin().is_err(),
        "unfinished exchange cannot restart"
    );
    connection.finish();
    assert_eq!(connection.begin().unwrap(), 1);
    connection.finish();
    connection.sequence = u64::MAX;
    assert!(connection.begin().is_err());
    assert_eq!(connection.sequence, u64::MAX);
}

#[test]
fn cancellation_or_invalid_alias_cannot_reuse_the_client_channel() {
    let (left, _right) = PacketChannel::pair().expect("private bootstrap socketpair");
    let mut client = BootstrapClient::new(left, Peer::current()).unwrap();
    let invocation = super::SessionId::parse(INVOCATION).unwrap();
    let cancelled = Cancellation::default();
    cancelled.cancel();
    let error = client
        .request(
            &invocation,
            "public-command",
            &cancelled,
            deadline(),
        )
        .err()
        .unwrap();
    assert!(crate::cancellation::is_cancellation_io(&error));
    let error = client
        .request(
            &invocation,
            "public-command",
            &Cancellation::default(),
            deadline(),
        )
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "invalid private command handoff"
    );
    let (left, _right) = PacketChannel::pair().expect("private bootstrap socketpair");
    let mut client = BootstrapClient::new(left, Peer::current()).unwrap();
    assert!(
        client
            .request(
                &invocation,
                "../private",
                &Cancellation::default(),
                deadline()
            )
            .is_err()
    );
    assert!(client.0.failed);
    assert!(
        client
            .request(
                &invocation,
                "public-command",
                &Cancellation::default(),
                deadline()
            )
            .is_err()
    );
}

#[test]
fn mismatched_response_poison_does_not_accept_a_later_retry() {
    let (left, right) = PacketChannel::pair().expect("private bootstrap socketpair");
    let peer = Peer::current();
    let sender = std::thread::spawn(move || {
        let cancel = Cancellation::default();
        let packet = right
            .receive(peer, 0, deadline(), &cancel)
            .unwrap();
        let request = Request::decode(&packet.bytes, 0).unwrap();
        let mut response = response(&request, None);
        response.sequence = 1;
        right
            .send(
                &encode(&response).unwrap(),
                &[],
                deadline(),
                &cancel,
            )
            .unwrap();
    });
    let mut client = BootstrapClient::new(left, peer).unwrap();
    let invocation = super::SessionId::parse(INVOCATION).unwrap();
    assert!(
        client
            .request(
                &invocation,
                "public-command",
                &Cancellation::default(),
                deadline()
            )
            .is_err()
    );
    sender.join().unwrap();
    assert!(client.0.failed);
    assert!(
        client
            .request(
                &invocation,
                "public-command",
                &Cancellation::default(),
                deadline()
            )
            .is_err()
    );
}

fn assert_same_launch(
    received: &crate::runtime::launch_preparation::PreparedRuntimeLaunch,
    expected: &crate::runtime::launch_preparation::PreparedRuntimeLaunch,
) {
    assert_eq!(
        received.spec.digest().unwrap(),
        expected.spec.digest().unwrap()
    );
    assert_eq!(
        received.descriptors.len(),
        expected.descriptors.len()
    );
    for (actual, expected) in received
        .descriptors
        .iter()
        .zip(&expected.descriptors)
    {
        assert_eq!(
            crate::platform::linux::fd::metadata(actual.as_fd())
                .unwrap()
                .identity(),
            crate::platform::linux::fd::metadata(expected.as_fd())
                .unwrap()
                .identity()
        );
    }
    received
        .spec
        .worker_request(&received.descriptors)
        .unwrap();
    assert!(received.retention.metadata().unwrap().is_file());
}

#[test]
fn real_handoff_retains_verified_descriptors_and_denial_is_not_a_transport_failure() {
    // Neither the fixture image nor a namespace payload is executed here.
    let (server_channel, client_channel) =
        PacketChannel::pair().expect("private bootstrap socketpair");
    let mut worker = crate::runtime::tests::elf(2, None, &[], None, None);
    worker[24..32].copy_from_slice(&0x0040_0100_u64.to_le_bytes());
    worker[68..72].copy_from_slice(&5_u32.to_le_bytes());
    let (root, prepared) =
        crate::deployment::manifest::tests::prepared_service_payload_fixture_with_source(
            &worker,
            r#"std::CommandArgument::File("nested/config")"#,
            "Shell",
            None,
            |text| {
                text.replace(
                    "name = \"serve\";",
                    "name = \"serve\"; expose = std::Option::Some(\"public-command\");",
                )
            },
        );
    let private = root.path().join("private");
    let cwd = root.path().join("work");
    fs::create_dir(&private).unwrap();
    fs::create_dir(&cwd).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    let cancel = Cancellation::default();
    let files = SessionFiles::new_retained_in(prepared.consumer(), &private, &cancel).unwrap();
    let shell = ShellSession {
        prepared,
        files,
        state: None,
        secrets: SessionSecrets::default(),
    };
    let broker = PreparedCommandBroker::prepare(
        &shell,
        BrokerPreparation {
            parent: &private,
            session: INVOCATION,
            socket_identity: crate::platform::linux::fd::FileIdentity {
                device: 1,
                inode: 2,
            },
            worker: &worker,
            worker_digest: ContentDigest::sha256(&worker),
            cwd: &cwd,
        },
        &cancel,
    )
    .unwrap();
    let expected = broker
        .prepare_invocation("public-command", &cancel)
        .unwrap();
    let peer = Peer::current();
    let client = std::thread::spawn(move || {
        let mut client = BootstrapClient::new(client_channel, peer).unwrap();
        let invocation = super::SessionId::parse(INVOCATION).unwrap();
        let cancel = Cancellation::default();
        assert!(
            client
                .request(&invocation, "serve", &cancel, deadline())
                .unwrap()
                .is_none()
        );
        let launch = client
            .request(&invocation, "public-command", &cancel, deadline())
            .unwrap()
            .unwrap();
        assert_eq!(client.0.sequence, 2);
        launch
    });
    let mut server = BootstrapServer::new(server_channel, peer).unwrap();
    assert_eq!(
        server
            .serve_with(&broker, &cancel, deadline(), |_, _, _| panic!(
                "resource fixture must not authorize a gate"
            ))
            .unwrap(),
        Served::Denied
    );
    assert_eq!(
        server
            .serve_with(&broker, &cancel, deadline(), |_, _, _| panic!(
                "resource fixture must not authorize a gate"
            ))
            .unwrap(),
        Served::Granted
    );
    let received = client.join().unwrap();
    assert_eq!(server.0.sequence, 2);
    assert_same_launch(&received, &expected);
    drop((received, expected));
    broker.close(&cancel).unwrap();
    shell.close().unwrap();
}

#[test]
fn incremental_reply_yields_without_response_and_cancellation_poison_is_sticky() {
    let (left, _silent_peer) = PacketChannel::pair().expect("private bootstrap socketpair");
    let mut client = BootstrapClient::new(left, Peer::current()).unwrap();
    let invocation = super::SessionId::parse(INVOCATION).unwrap();
    let cancel = Cancellation::default();
    client
        .begin_request(&invocation, "public-command", &cancel, deadline())
        .unwrap();
    // No peer sends a response: a blocking receive would time out and fail,
    // whereas each poll must return Pending for the monitor to service jobs.
    for _ in 0..2 {
        assert!(matches!(
            client.poll_reply(&cancel).unwrap(),
            super::BootstrapPoll::Pending
        ));
    }
    cancel.cancel();
    let error = client.poll_reply(&cancel).err().unwrap();
    assert!(crate::cancellation::is_cancellation_io(&error));
    assert!(client.1.is_none());
    assert!(
        client
            .begin_request(
                &invocation,
                "public-command",
                &Cancellation::default(),
                deadline()
            )
            .is_err()
    );
}

// Blocking convenience exists only in the IPC tests. Production drives the
// incremental interface from the monitor's shared event loop.
impl BootstrapClient {
    fn request(
        &mut self,
        invocation: &super::SessionId,
        alias: &str,
        cancel: &Cancellation,
        until: Instant,
    ) -> std::io::Result<Option<crate::runtime::launch_preparation::PreparedRuntimeLaunch>> {
        self.begin_request(invocation, alias, cancel, until)?;
        loop {
            match self.poll_reply(cancel)? {
                super::BootstrapPoll::Ready(launch) => return Ok(launch.map(|launch| *launch)),
                super::BootstrapPoll::Authorized(_) => return Err(super::invalid()),
                super::BootstrapPoll::Pending => {
                    crate::execution::native::ready(self.as_fd(), 1)?;
                }
            }
        }
    }
}

fn authorization_request() -> Request {
    let mut value = request();
    value.authorization = Some(super::Authorization {
        gate_sequence: 0,
        namespace_device: 1,
        namespace_inode: 2,
        spec: ContentDigest::sha256(b"admitted spec").to_string(),
    });
    value
}

#[test]
fn authorization_requires_bounded_sequence_namespace_identity_and_canonical_spec() {
    let request = authorization_request();
    assert!(Request::decode(&encode(&request).unwrap(), request.sequence).is_ok());
    for field in 0..4 {
        let mut request = authorization_request();
        let auth = request.authorization.as_mut().unwrap();
        match field {
            0 => auth.gate_sequence = u64::MAX,
            1 => auth.namespace_device = 0,
            2 => auth.namespace_inode = 0,
            _ => auth.spec = auth.spec.to_uppercase(),
        }
        assert!(Request::decode(&encode(&request).unwrap(), request.sequence).is_err());
    }
}

#[test]
fn resource_response_cannot_be_mistaken_for_final_gate_authority() {
    let request = authorization_request();
    let mut ack = response(&request, None);
    assert!(Response::decode(&encode(&ack).unwrap(), &request).is_err());
    ack.authorized = Some(true);
    assert!(Response::decode(&encode(&ack).unwrap(), &request).is_ok());
    let mut resources = authorization_request();
    resources.authorization = None;
    assert!(Response::decode(&encode(&ack).unwrap(), &resources).is_err());
    ack.pin = Some(ContentDigest::sha256(b"mixed response").to_string());
    assert!(Response::decode(&encode(&ack).unwrap(), &request).is_err());
}

#[test]
fn final_gate_matches_only_the_granted_invocation_alias_and_spec() {
    let grant = super::Grant {
        invocation: INVOCATION.into(),
        alias: "public-command".into(),
        spec: ContentDigest::sha256(b"admitted spec"),
    };
    assert!(grant.matches(&authorization_request()));
    for field in 0..3 {
        let mut request = authorization_request();
        match field {
            0 => request.invocation = "abcdef1234567890abcdef1234567890".into(),
            1 => request.alias = "another-command".into(),
            _ => {
                request.authorization.as_mut().unwrap().spec =
                    ContentDigest::sha256(b"other spec").to_string();
            }
        }
        assert!(!grant.matches(&request));
    }
    assert!(!grant.matches(&request()));
}
