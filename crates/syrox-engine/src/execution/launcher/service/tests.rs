use super::*;
use crate::execution::journal::AttemptId;
use crate::store::ContentDigest;
fn request() -> ServiceLaunchRequest {
    ServiceLaunchRequest {
        session: SessionId::parse(&"01".repeat(16)).unwrap(),
        role: ContentDigest::sha256(b"role"),
        attempt: AttemptId::parse(&"02".repeat(16)).unwrap(),
        generation: ContentDigest::sha256(b"generation"),
        command: ContentDigest::sha256(b"command"),
        binding: binding("syrox-test-service.service", [3; 16]).unwrap(),
        owner: binding("syrox-test-owner.service", [4; 16]).unwrap(),
    }
}
#[test]
fn service_envelope_pins_command_generation_and_distinct_invocations() {
    let request = request();
    let encoded = request.encode().unwrap();
    assert_eq!(
        ServiceLaunchRequest::parse(&encoded).unwrap(),
        request
    );
    let text = String::from_utf8(encoded).unwrap();
    for invalid in [
        format!(" {text}"),
        text.replace("\"version\":2", "\"version\":1"),
        text.replace(
            "syrox-test-service.service",
            "syrox-test-owner.service",
        ),
    ] {
        assert!(ServiceLaunchRequest::parse(invalid.as_bytes()).is_err());
    }
    let mut changed = request.clone();
    changed.command = ContentDigest::sha256(b"other command");
    assert_ne!(
        changed.encode().unwrap(),
        request.encode().unwrap()
    );
    changed = request.clone();
    changed.owner = binding("syrox-test-owner.service", [5; 16]).unwrap();
    assert_ne!(
        changed.encode().unwrap(),
        request.encode().unwrap()
    );
}
#[test]
fn service_context_refuses_zero_uppercase_and_extra_authority() {
    let request = request();
    let mut args: Vec<OsString> = vec![
        "/tmp/private/launch.sock".into(),
        request.session.to_string().into(),
        request.role.to_string().into(),
        request.generation.to_string().into(),
        request.command.to_string().into(),
        request.binding.unit().as_str().into(),
        request.owner.unit().as_str().into(),
        "04".repeat(16).into(),
    ];
    assert_eq!(
        context(&args, &"03".repeat(16)).unwrap().1,
        request.hello()
    );
    for invalid in [
        "00".repeat(16),
        "AA".repeat(16),
        "a".repeat(31),
    ] {
        assert!(context(&args, &invalid).is_err());
    }
    args.push("unexpected".into());
    assert!(context(&args, &"03".repeat(16)).is_err());
}

#[test]
fn challenge_binds_role_and_invocation_before_request_echo() {
    let request = request();
    let hello = request.hello();
    assert_eq!(
        ServiceLaunchHello::parse(&hello.encode().unwrap()).unwrap(),
        hello
    );
    let mut challenge = ServiceAttemptChallenge {
        role: request.role,
        attempt: request.attempt.clone(),
        binding: request.binding.clone(),
    };
    assert_eq!(
        ServiceAttemptChallenge::parse(&challenge.encode().unwrap()).unwrap(),
        challenge
    );
    assert_eq!(hello.challenged(&challenge).unwrap(), request);
    assert!(ServiceLaunchRequest::parse(&hello.encode().unwrap()).is_err());
    assert!(ServiceLaunchHello::parse(&request.encode().unwrap()).is_err());
    challenge.role = ContentDigest::sha256(b"other role");
    assert!(hello.challenged(&challenge).is_err());
    challenge.role = request.role;
    challenge.binding = binding("syrox-test-service.service", [9; 16]).unwrap();
    assert!(hello.challenged(&challenge).is_err());
}
#[test]
fn payload_status_cannot_forge_definitive_admission_denial() {
    assert_eq!(
        payload_envelope(std::process::ExitStatus::from_raw(0)),
        0
    );
    for raw in [78 << 8, 1 << 8, 255 << 8, 9] {
        assert_eq!(
            payload_envelope(std::process::ExitStatus::from_raw(raw)),
            1
        );
    }
}

#[test]
fn admission_envelopes_refuse_ambiguous_and_unbounded_records() {
    let request = request();
    let hello = request.hello().encode().unwrap();
    let challenge = ServiceAttemptChallenge {
        role: request.role,
        attempt: request.attempt.clone(),
        binding: request.binding.clone(),
    }
    .encode()
    .unwrap();
    for (kind, encoded) in [
        hello,
        request.encode().unwrap(),
        challenge,
    ]
    .into_iter()
    .enumerate()
    {
        let text = String::from_utf8(encoded).unwrap();
        let rejects = |bytes: &[u8]| match kind {
            0 => ServiceLaunchHello::parse(bytes).is_err(),
            1 => ServiceLaunchRequest::parse(bytes).is_err(),
            _ => ServiceAttemptChallenge::parse(bytes).is_err(),
        };
        for malformed in [
            text.replace("\"version\":2", "\"version\":1"),
            text.replacen('{', "{\"version\":2,", 1),
            text.replacen('{', "{\"authority\":true,", 1),
            format!("{text}\n"),
            text[..text.len() - 1].to_owned(),
            text.replace(
                "[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3]",
                "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            ),
        ] {
            assert!(
                rejects(malformed.as_bytes()),
                "accepted envelope {kind}"
            );
        }
        assert!(rejects(&vec![
            b' ';
            super::super::transport::MAX_BYTES
                + 1
        ]));
    }
}

#[test]
fn hello_cannot_preselect_an_attempt_and_request_requires_one() {
    let request = request();
    let hello = String::from_utf8(request.hello().encode().unwrap()).unwrap();
    for attempt in [
        format!("\"{}\"", request.attempt),
        "null".into(),
    ] {
        let supplied = hello.replacen('{', &format!("{{\"attempt\":{attempt},"), 1);
        assert!(ServiceLaunchHello::parse(supplied.as_bytes()).is_err());
    }
    let mut missing: serde_json::Value =
        serde_json::from_slice(&request.encode().unwrap()).unwrap();
    missing.as_object_mut().unwrap().remove("attempt");
    assert!(ServiceLaunchRequest::parse(&serde_json::to_vec(&missing).unwrap()).is_err());
}
