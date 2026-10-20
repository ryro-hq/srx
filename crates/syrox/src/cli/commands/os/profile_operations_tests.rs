use super::*;
use os::{
    OsStatusBinding, OsStatusEffect, OsStatusEpoch,
    profile::{OsProfile, ProfileScope},
};

fn profile(scope: ProfileScope) -> OsProfile {
    OsProfile {
        version: 1,
        name: "web".into(),
        project: "/project".into(),
        output: "os".into(),
        config: None,
        installation: "/installation".into(),
        installation_id: "1234567890abcdef1234567890abcdef".into(),
        store: "/store".into(),
        units: "/units".into(),
        cwd: "/work".into(),
        scope,
        uid: 1000,
        gid: 1000,
        start_timeout_seconds: 30,
        stop_timeout_seconds: 5,
    }
}
fn status() -> OsStatus {
    OsStatus {
        installation: "1234567890abcdef1234567890abcdef".into(),
        desired: None,
        active_operation: None,
        active_kind: None,
        boot_fences: Vec::new(),
        abandoned_operations: Vec::new(),
        pending_effects: Vec::new(),
        bindings: vec![OsStatusBinding {
            invocation: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            invocation_error: None,
            resource: "nginx/main".into(),
            generation: ContentDigest::sha256(b"generation"),
            pin: ContentDigest::sha256(b"binding"),
            unit: "syrox-example.service".into(),
            authorized: true,
            epoch: OsStatusEpoch {
                boot: "11111111-1111-4111-8111-111111111111".into(),
                manager: "recorded-manager".into(),
                scope: "user".into(),
            },
        }],
    }
}

#[test]
fn journal_filters_constrain_application_and_manager_records_to_the_owned_invocation() {
    let status = status();
    let user = profile(ProfileScope::User {
        bus_socket: "/run/user/1000/bus".into(),
    });
    let matches = journal_matches(&user, &status, Some("nginx")).unwrap();
    assert_eq!(
        matches,
        [
            "_SYSTEMD_USER_UNIT=syrox-example.service",
            "_SYSTEMD_INVOCATION_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "_UID=1000",
            "_BOOT_ID=11111111111141118111111111111111",
            "+",
            "USER_UNIT=syrox-example.service",
            "USER_INVOCATION_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "_UID=1000",
            "_BOOT_ID=11111111111141118111111111111111",
        ]
    );
    assert_eq!(
        journal_matches(&user, &status, Some("nginx/main")).unwrap(),
        matches
    );
    assert!(journal_matches(&user, &status, Some("ngin")).is_err());
    assert!(journal_matches(&user, &status, Some("--directory=/elsewhere")).is_err());
    let system = profile(ProfileScope::System);
    let matches = journal_matches(&system, &status, None).unwrap();
    assert_eq!(matches[0], "_SYSTEMD_UNIT=syrox-example.service");
    assert_eq!(matches[2], "_UID=1000");
    assert_eq!(matches[5], "UNIT=syrox-example.service");
    assert_eq!(
        matches[6],
        "INVOCATION_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(matches[7], "_UID=0");
}

#[test]
fn ambiguous_invocations_are_not_used_for_logs_and_pending_effects_block_new_operations() {
    let mut status = status();
    status.bindings[0].invocation = None;
    status.bindings[0].invocation_error = Some("ambiguous admitted attempts".into());
    assert!(journal_matches(&profile(ProfileScope::System), &status, None).is_err());
    assert!(require_settled(&status, "web").is_ok());
    status.active_operation = Some("1234567890abcdef1234567890abcdef".into());
    for phase in ["intent", "accepted", "unknown"] {
        status.pending_effects = vec![OsStatusEffect {
            operation: status.active_operation.clone().unwrap(),
            effect: "effect".into(),
            kind: "start",
            resource: "nginx/main".into(),
            target: ContentDigest::sha256(b"binding"),
            phase,
            job: None,
        }];
        let error = require_settled(&status, "web").unwrap_err();
        assert!(error.contains("srx os recover 1234567890abcdef1234567890abcdef --profile web"));
    }
}
