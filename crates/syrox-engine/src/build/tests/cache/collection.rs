use super::*;

#[test]
#[ignore = "explicit Store root-scan profile; publishes 1024 results"]
fn root_selection_profile_growing_store() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let cancellation = Cancellation::default();
    let mut previous = 0;
    let io = || -> (u64, u64) {
        let text = fs::read_to_string("/proc/self/io").unwrap();
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap()
                .trim()
                .parse::<u64>()
                .unwrap()
        };
        (field("rchar:"), field("syscr:"))
    };
    let cpu = || -> (u64, u64) {
        let text = fs::read_to_string("/proc/self/stat").unwrap();
        let fields = text
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        (
            fields[11].parse().unwrap(),
            fields[12].parse().unwrap(),
        )
    };
    for target in [0, 16, 64, 128, 512, 1024] {
        for index in previous..target {
            let mut candidate = action();
            candidate.directory = format!("other-{index}");
            retained(&lease, &candidate, b"executable");
        }
        let before_io = io();
        let before_cpu = cpu();
        let start = Instant::now();
        let mut absent = action();
        absent.directory = "absent".into();
        let present =
            has_retained_build_with_inputs(&lease, &description(&absent), &cancellation).unwrap();
        let elapsed = start.elapsed();
        let after_cpu = cpu();
        let after_io = io();
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let peak = status
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .unwrap();
        eprintln!(
            "root_scan roots={target} elapsed_us={} cpu_user_ticks={} cpu_sys_ticks={} rchar={} syscr={} {peak}",
            elapsed.as_micros(),
            after_cpu.0 - before_cpu.0,
            after_cpu.1 - before_cpu.1,
            after_io.0 - before_io.0,
            after_io.1 - before_io.1
        );
        assert!(!present);
        previous = target;
    }
}

#[test]
fn gc_removal_leaves_a_stale_hint_and_never_resurrects_collected_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    record(&lease, &action, &result).unwrap();
    let operation = super::super::super::journal::Operation::create(&lease).unwrap();
    operation
        .write_stage("source", SOURCE, false)
        .unwrap();
    let staging = operation.stage_path();
    drop(operation);
    drop(lease);
    let artifact = result.artifact;
    let root = result.root.clone();
    drop(result);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![root],
            ..GcRequest::default()
        })
        .unwrap();
    assert!(report.removed_objects.contains(&artifact));
    assert_eq!(fs::read(staging.join("source")).unwrap(), SOURCE);
    let lease = store.operation().unwrap();
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    assert!(
        fs::read_dir(directory.path().join("roots/retained"))
            .unwrap()
            .next()
            .is_none()
    );
    let new = retained(&lease, &action, b"new executable after eviction");
    record(&lease, &action, &new).unwrap();
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .artifact,
        new.artifact
    );
}

#[test]
fn dependent_result_retains_provider_after_its_independent_root_is_collected() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let mut provider_action = action();
    provider_action.directory = "provider".into();
    let provider = retained(&lease, &provider_action, b"provider ELF bytes");
    let references = lease
        .build_references(&provider.root)
        .unwrap()
        .unwrap();
    let mut consumer_action = action();
    consumer_action.directory = "consumer".into();
    consumer_action.inputs = vec![
        super::super::super::records::InputIdentity {
            origin: crate::result::OutputOrigin::Built {
                receipt: provider.receipt,
            },
            action: provider.action,
            artifact: provider.artifact,
            output: "out".into(),
        },
    ];
    let tree = tempfile::tempdir().unwrap();
    let path = tree.path().join("bin/hello");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"consumer ELF bytes").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let mut artifact = Vec::new();
    artifact::pack(tree.path(), &mut artifact).unwrap();
    let receipt = Receipt::new(
        &consumer_action,
        ContentDigest::sha256(&artifact),
        1,
    )
    .with_inputs(&consumer_action, references)
    .unwrap();
    for bytes in [
        &consumer_action.encode()[..],
        &artifact,
        &receipt.encode(),
    ] {
        lease
            .ingest(
                bytes,
                ContentDigest::sha256(bytes),
                bytes.len() as u64,
            )
            .unwrap();
    }
    lease
        .publish_root(&receipt.root(), &receipt.references())
        .unwrap();
    drop(lease);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![provider.root.clone()],
            ..GcRequest::default()
        })
        .unwrap();
    assert!(
        !report
            .removed_objects
            .contains(&provider.artifact)
    );
    let view =
        crate::result::materialize_artifact(&store, &receipt.root(), receipt.digest()).unwrap();
    assert_eq!(
        fs::read(view.directory().unwrap().join("bin/hello")).unwrap(),
        b"consumer ELF bytes"
    );
    drop(view);
    let provider_view = crate::result::materialize::materialize_provider(
        &store,
        &receipt.root(),
        receipt.digest(),
        provider.receipt,
    )
    .unwrap();
    assert_eq!(
        fs::read(
            provider_view
                .directory()
                .unwrap()
                .join("bin/hello")
        )
        .unwrap(),
        b"provider ELF bytes"
    );
    drop(provider_view);
    let digest = provider.artifact.to_string();
    fs::write(
        directory
            .path()
            .join("objects/sha256")
            .join(&digest[..2])
            .join(digest),
        b"tampered",
    )
    .unwrap();
    assert!(
        crate::result::materialize_artifact(&store, &receipt.root(), receipt.digest()).is_err()
    );
}

#[test]
fn runtime_closure_uses_consumer_root_after_provider_gc() {
    use crate::runtime::{RuntimeFile, RuntimeOutput, RuntimeRequest, tests::elf, verify_runtime};
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let mut provider_action = action();
    provider_action.directory = "provider".into();
    let provider = retained_with_library(
        &lease,
        &provider_action,
        &elf(3, None, &[], None, None),
        "libc.so.6",
        &elf(3, None, &[], Some("libc.so.6"), None),
    );
    let interpreter = format!(
        "/syrox/store/{}/out/{}",
        provider.action, "bin/hello"
    );
    let library_path = format!("/syrox/store/{}/out/usr/lib", provider.action);
    let tree = tempfile::tempdir().unwrap();
    let mut consumer_action = action();
    consumer_action.directory = "consumer".into();
    consumer_action.inputs = vec![
        super::super::super::records::InputIdentity {
            origin: crate::result::OutputOrigin::Built {
                receipt: provider.receipt,
            },
            action: provider.action,
            artifact: provider.artifact,
            output: "out".into(),
        },
    ];
    let path = tree.path().join("bin/hello");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        elf(
            3,
            Some(&interpreter),
            &["libc.so.6"],
            None,
            Some(&library_path),
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let mut artifact_bytes = Vec::new();
    artifact::pack(tree.path(), &mut artifact_bytes).unwrap();
    let references = lease
        .build_references(&provider.root)
        .unwrap()
        .unwrap();
    let receipt = Receipt::new(
        &consumer_action,
        ContentDigest::sha256(&artifact_bytes),
        1,
    )
    .with_inputs(&consumer_action, references)
    .unwrap();
    for bytes in [
        &consumer_action.encode()[..],
        &artifact_bytes,
        &receipt.encode(),
    ] {
        lease
            .ingest(
                bytes,
                ContentDigest::sha256(bytes),
                bytes.len() as u64,
            )
            .unwrap();
    }
    lease
        .publish_root(&receipt.root(), &receipt.references())
        .unwrap();
    drop(lease);
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![provider.root.clone()],
            ..GcRequest::default()
        })
        .unwrap();
    let request = RuntimeRequest {
        application: RuntimeFile {
            output: RuntimeOutput {
                root: receipt.root(),
                receipt: receipt.digest(),
                output: "out".into(),
            },
            path: "bin/hello".into(),
        },
        loader: Some(RuntimeFile {
            output: RuntimeOutput {
                root: provider.root.clone(),
                receipt: provider.receipt,
                output: "out".into(),
            },
            path: "bin/hello".into(),
        }),
        libraries: vec![RuntimeOutput {
            root: provider.root,
            receipt: provider.receipt,
            output: "out".into(),
        }],
    };
    let closure = verify_runtime(&store, &request).unwrap();
    assert_eq!(closure.mounts().unwrap().len(), 2);
}

#[test]
#[ignore = "set SYROX_RETAINED_STORE, SYROX_RETAINED_HELLO_RECEIPT, SYROX_RETAINED_GLIBC_RECEIPT, SYROX_RETAINED_SRX and SYROX_RETAINED_CATALOG"]
fn real_hello_runs_after_collecting_only_the_provider_root() {
    use crate::runtime::{RuntimeFile, RuntimeOutput, RuntimeRequest, run_runtime, verify_runtime};
    let source = Store::open(Path::new(
        &std::env::var("SYROX_RETAINED_STORE").unwrap(),
    ))
    .unwrap();
    let hello: ContentDigest = std::env::var("SYROX_RETAINED_HELLO_RECEIPT")
        .unwrap()
        .parse()
        .unwrap();
    let glibc: ContentDigest = std::env::var("SYROX_RETAINED_GLIBC_RECEIPT")
        .unwrap()
        .parse()
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let target = Store::open(temporary.path()).unwrap();
    let source_lease = source.operation().unwrap();
    let target_lease = target.operation().unwrap();
    for receipt in [hello, glibc] {
        let root = RootName::new(format!("build_{receipt}")).unwrap();
        let references = source_lease
            .build_references(&root)
            .unwrap()
            .unwrap();
        for digest in &references {
            let mut file = source_lease
                .open_verified(*digest, crate::store::MAX_STORE_BLOB_BYTES)
                .unwrap()
                .unwrap();
            let size = file.size();
            target_lease
                .ingest(&mut file, *digest, size)
                .unwrap();
        }
        target_lease
            .publish_root(&root, &references)
            .unwrap();
    }
    drop(source_lease);
    drop(target_lease);
    // A copied Store has no action-index hints. Explicitly reconstruct the
    // verified results before removing the provider's independent root.
    assert_eq!(rebuild(&target).unwrap().indexed, 2);
    let provider_root = RootName::new(format!("build_{glibc}")).unwrap();
    let report = target
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![provider_root.clone()],
            ..GcRequest::default()
        })
        .unwrap();
    assert!(report.removed_roots.contains(&provider_root));
    let lease = target.operation().unwrap();
    let owner_bytes = lease
        .read_verified(hello, MAX_RECORD_BYTES)
        .unwrap()
        .unwrap();
    let owner = Receipt::parse(owner_bytes.as_bytes()).unwrap();
    let action_bytes = lease
        .read_verified(owner.action, MAX_RECORD_BYTES)
        .unwrap()
        .unwrap();
    let action = Action::parse(action_bytes.as_bytes()).unwrap();
    let provider_bytes = lease
        .read_verified(glibc, MAX_RECORD_BYTES)
        .unwrap()
        .unwrap();
    let provider = Receipt::parse(provider_bytes.as_bytes()).unwrap();
    let provider_action_bytes = lease
        .read_verified(provider.action, MAX_RECORD_BYTES)
        .unwrap()
        .unwrap();
    let provider_action = Action::parse(provider_action_bytes.as_bytes()).unwrap();
    let query = RetainedQuery {
        application: description(&action),
        provider: description(&provider_action),
        worker: action.worker,
        toolchain: action.toolchain,
        input_outputs: action
            .inputs
            .iter()
            .map(|input| input.output.as_str())
            .collect(),
    };
    assert_eq!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default())
            .unwrap()
            .unwrap()
            .0
            .receipt,
        hello
    );
    drop(lease);
    let request = RuntimeRequest {
        application: RuntimeFile {
            output: RuntimeOutput {
                root: RootName::new(format!("build_{hello}")).unwrap(),
                receipt: hello,
                output: "out".into(),
            },
            path: "usr/bin/hello".into(),
        },
        loader: Some(RuntimeFile {
            output: RuntimeOutput {
                root: provider_root.clone(),
                receipt: glibc,
                output: "out".into(),
            },
            path: "usr/lib/ld-linux-x86-64.so.2".into(),
        }),
        libraries: vec![RuntimeOutput {
            root: provider_root,
            receipt: glibc,
            output: "out".into(),
        }],
    };
    let closure = verify_runtime(&target, &request).unwrap();
    let working = tempfile::tempdir().unwrap();
    assert!(
        run_runtime(
            &closure,
            &["--greeting".into(), "Olá".into()],
            working.path()
        )
        .unwrap()
        .success()
    );
    drop(closure);
    let catalog = std::env::var("SYROX_RETAINED_CATALOG").unwrap();
    let config = working.path().join("config.toml");
    fs::write(
        &config,
        format!(
            "[catalog]\npath = '{catalog}'\nlock-sha256 = '{}'\n[build]\nhost-toolchain = '/usr'\n",
            ContentDigest::sha256(&fs::read(Path::new(&catalog).join("Syrox.lock")).unwrap())
        ),
    )
    .unwrap();
    let output = std::process::Command::new(std::env::var("SYROX_RETAINED_SRX").unwrap())
        .args([
            "run",
            "hello",
            "--command",
            "hello",
            "--config",
        ])
        .arg(&config)
        .arg("--store")
        .arg(temporary.path())
        .args(["-o", "--", "--greeting", "Olá"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, "Olá\n".as_bytes());
    assert!(
        !temporary
            .path()
            .join("roots/retained")
            .join(format!("build_{glibc}"))
            .exists()
    );
}
