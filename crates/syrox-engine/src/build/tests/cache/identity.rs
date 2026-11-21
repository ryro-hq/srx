use super::*;

#[test]
fn action_identity_binds_builder_and_selected_inputs() {
    let current = action();
    assert_eq!(Action::parse(&current.encode()).unwrap(), current);
    let runtime = Action {
        inputs: vec![
            super::super::super::records::InputIdentity {
                origin: crate::result::OutputOrigin::Built {
                    receipt: ContentDigest::sha256(b"provider receipt"),
                },
                action: ContentDigest::sha256(b"provider action"),
                artifact: ContentDigest::sha256(b"provider artifact"),
                output: "out".into(),
            },
        ],
        ..current.clone()
    };
    assert_ne!(current.digest(), runtime.digest());
    assert_eq!(Action::parse(&runtime.encode()).unwrap(), runtime);
    let mut changed = current.clone();
    changed
        .program
        .steps
        .push(super::super::super::BuildStep::Directory(
            super::super::super::BuildPath::Work("other".into()),
        ));
    assert_ne!(current.digest(), changed.digest());
    assert_eq!(Action::parse(&changed.encode()).unwrap(), changed);
    assert!(Action::parse(b"syrox-build-action-v6\n").is_err());
    let altered = String::from_utf8(current.encode())
        .unwrap()
        .replace("memory 805306368", "memory 805306369");
    assert!(Action::parse(altered.as_bytes()).is_err());
}

#[test]
fn canonical_records_reject_wrong_settlement_counts_and_framing() {
    let action = action();
    assert_eq!(Action::parse(&action.encode()).unwrap(), action);
    let receipt = Receipt::new(&action, ContentDigest::sha256(b"artifact"), 1);
    assert_eq!(
        Receipt::parse(&receipt.encode()).unwrap(),
        receipt
    );
    for bytes in [
        receipt.encode()[..receipt.encode().len() - 1].to_vec(),
        String::from_utf8(receipt.encode())
            .unwrap()
            .replace("subreaper-echild", "unconfirmed")
            .into_bytes(),
        String::from_utf8(receipt.encode())
            .unwrap()
            .replace(
                &format!(" {} 1\n", receipt.output("out").unwrap().artifact),
                &format!(
                    " {} 01\n",
                    receipt.output("out").unwrap().artifact
                ),
            )
            .into_bytes(),
    ] {
        assert!(Receipt::parse(&bytes).is_err());
    }
    assert!(Action::parse(&action.encode()[..action.encode().len() - 1]).is_err());
}

#[test]
fn managed_action_and_receipt_roundtrip_without_host_inventory() {
    let host = action();
    let mut managed = host.clone();
    managed.program.profile = super::super::super::BuildProfile::Managed;
    managed.toolchain = None;
    assert_eq!(Action::parse(&managed.encode()).unwrap(), managed);
    assert_ne!(managed.digest(), host.digest());
    let receipt = Receipt::new(&managed, ContentDigest::sha256(b"artifact"), 1);
    assert_eq!(
        Receipt::parse(&receipt.encode()).unwrap(),
        receipt
    );
    assert!(
        !receipt
            .references()
            .contains(&host.toolchain.unwrap())
    );
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    lease
        .ingest(SOURCE, managed.source, SOURCE.len() as u64)
        .unwrap();
    receipt
        .verify_retained_inputs(&lease, &managed, || Ok(()))
        .unwrap();

    let mut invalid = managed.clone();
    invalid.toolchain = host.toolchain;
    assert!(Action::parse(&invalid.encode()).is_err());
    invalid = host;
    invalid.toolchain = None;
    assert!(Action::parse(&invalid.encode()).is_err());
    let text = String::from_utf8(managed.encode()).unwrap();
    assert!(
        Action::parse(
            text.replace(
                super::super::super::MANAGED_PROFILE,
                super::super::super::PROFILE
            )
            .as_bytes()
        )
        .is_err()
    );
}
