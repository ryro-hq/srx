use super::*;
use crate::store::GcRequest;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

const SOURCE: &[u8] = b"fixture source";
const TOOLCHAIN: &[u8] = b"syrox-host-toolchain\nfixture toolchain";

#[test]
fn inverse_shard_pairs_and_coincident_shards_serialize_without_deadlock() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let digest = |prefix: &str| -> ContentDigest {
        format!("{prefix}{}", "0".repeat(62))
            .parse()
            .unwrap()
    };
    for ((first_a, first_b), (second_a, second_b), coincident) in [
        (
            (digest("10"), digest("f0")),
            (digest("f0"), digest("10")),
            false,
        ),
        (
            (digest("10"), digest("10")),
            (digest("10"), digest("10")),
            true,
        ),
    ] {
        let barrier = Arc::new(Barrier::new(3));
        let (acquired, received) = mpsc::channel();
        let mut releases = Vec::new();
        let handles: Vec<_> = [(first_a, first_b), (second_a, second_b)]
            .into_iter()
            .enumerate()
            .map(|(index, (application, provider))| {
                let (release, permit) = mpsc::channel::<()>();
                releases.push(release);
                let barrier = Arc::clone(&barrier);
                let acquired = acquired.clone();
                let lease = lease.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let guards = index_shards(
                        &lease,
                        application,
                        provider,
                        &Cancellation::default(),
                    )
                    .unwrap();
                    assert_eq!(guards.1.is_none(), coincident);
                    acquired.send(index).unwrap();
                    permit
                        .recv_timeout(Duration::from_secs(3))
                        .unwrap();
                    drop(guards);
                })
            })
            .collect();
        barrier.wait();
        let first = received
            .recv_timeout(Duration::from_secs(3))
            .expect("first pair must acquire");
        assert!(
            received
                .recv_timeout(Duration::from_millis(80))
                .is_err(),
            "second pair bypassed held shard"
        );
        releases[first].send(()).unwrap();
        received
            .recv_timeout(Duration::from_secs(3))
            .expect("second pair must acquire after release");
        releases[1 - first].send(()).unwrap();
        for handle in handles {
            handle.join().unwrap();
        }
    }
}

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

pub(crate) fn action() -> Action {
    Action {
        program: super::super::BuildProgram {
            profile: super::super::BuildProfile::HostBootstrap,
            resources: super::super::BuildResources::Standard,
            source_format: super::super::BuildSourceFormat::Gzip,
            outputs: vec!["out".into()],
            steps: vec![super::super::BuildStep::Directory(
                super::super::BuildPath::Work("source".into()),
            )],
        },
        source: ContentDigest::sha256(SOURCE),
        toolchain: Some(ContentDigest::sha256(TOOLCHAIN)),
        worker: ContentDigest::sha256(b"trusted worker"),
        directory: "fixture".into(),
        inputs: Vec::new(),
    }
}

fn description(action: &Action) -> BuildDescription<'_> {
    BuildDescription {
        source: action.source,
        program: &action.program,
        directory: &action.directory,
    }
}

#[test]
fn action_identity_binds_builder_and_selected_inputs() {
    let current = action();
    assert_eq!(Action::parse(&current.encode()).unwrap(), current);
    let runtime = Action {
        inputs: vec![super::super::records::InputIdentity {
            origin: crate::result::OutputOrigin::Built {
                receipt: ContentDigest::sha256(b"provider receipt"),
            },
            action: ContentDigest::sha256(b"provider action"),
            artifact: ContentDigest::sha256(b"provider artifact"),
            output: "out".into(),
        }],
        ..current.clone()
    };
    assert_ne!(current.digest(), runtime.digest());
    assert_eq!(Action::parse(&runtime.encode()).unwrap(), runtime);
    let mut changed = current.clone();
    changed
        .program
        .steps
        .push(super::super::BuildStep::Directory(
            super::super::BuildPath::Work("other".into()),
        ));
    assert_ne!(current.digest(), changed.digest());
    assert_eq!(Action::parse(&changed.encode()).unwrap(), changed);
    assert!(Action::parse(b"syrox-build-action-v6\n").is_err());
    let altered = String::from_utf8(current.encode())
        .unwrap()
        .replace("memory 805306368", "memory 805306369");
    assert!(Action::parse(altered.as_bytes()).is_err());
}

pub(crate) fn retained(lease: &OperationLease, action: &Action, content: &[u8]) -> BuildResult {
    retained_at(lease, action, "bin/hello", content)
}

pub(crate) fn retained_at(
    lease: &OperationLease,
    action: &Action,
    path: &str,
    content: &[u8],
) -> BuildResult {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let mut artifact = Vec::new();
    artifact::pack(directory.path(), &mut artifact).unwrap();
    let receipt = Receipt::new(action, ContentDigest::sha256(&artifact), 1);
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    for bytes in [
        SOURCE,
        TOOLCHAIN,
        &action_bytes,
        &artifact,
        &receipt_bytes,
    ] {
        lease
            .ingest(
                bytes,
                ContentDigest::sha256(bytes),
                bytes.len() as u64,
            )
            .unwrap();
    }
    let root = receipt.root();
    lease
        .publish_root(&root, &receipt.references())
        .unwrap();
    BuildResult {
        retention: lease
            .retain_objects(&receipt.references(), &[])
            .unwrap(),
        execution: BuildExecution::Built {
            operation: "test-producer".into(),
        },
        action: receipt.action,
        artifact: receipt.output("out").unwrap().artifact,
        receipt: receipt.digest(),
        toolchain: receipt.toolchain,
        files: receipt.output("out").unwrap().files,
        root,
    }
}

#[test]
fn retained_provider_can_be_verified_without_views_and_rejects_missing_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    let (found, receipt) = retained_result(
        &lease,
        &result.root,
        result.receipt,
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(found, action);
    assert_eq!(receipt.digest(), result.receipt);
    assert!(
        !directory
            .path()
            .join(".syrox-store/views")
            .exists()
    );
    let digest = ContentDigest::sha256(SOURCE).to_string();
    fs::remove_file(
        directory
            .path()
            .join("objects/sha256")
            .join(&digest[..2])
            .join(digest),
    )
    .unwrap();
    assert!(
        retained_result(
            &lease,
            &result.root,
            result.receipt,
            &Cancellation::default()
        )
        .is_err()
    );
}

pub(crate) fn retained_with_library(
    lease: &OperationLease,
    action: &Action,
    content: &[u8],
    soname: &str,
    library: &[u8],
) -> BuildResult {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("bin")).unwrap();
    fs::create_dir_all(directory.path().join("usr/lib")).unwrap();
    fs::write(directory.path().join("bin/hello"), content).unwrap();
    fs::write(
        directory.path().join("usr/lib").join(soname),
        library,
    )
    .unwrap();
    fs::set_permissions(
        directory.path().join("bin/hello"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut artifact = Vec::new();
    artifact::pack(directory.path(), &mut artifact).unwrap();
    let receipt = Receipt::new(action, ContentDigest::sha256(&artifact), 2);
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    for bytes in [
        SOURCE,
        TOOLCHAIN,
        &action_bytes,
        &artifact,
        &receipt_bytes,
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
    BuildResult {
        retention: lease
            .retain_objects(&receipt.references(), &[])
            .unwrap(),
        execution: BuildExecution::Cached,
        action: action.digest(),
        artifact: receipt.output("out").unwrap().artifact,
        receipt: receipt.digest(),
        toolchain: receipt.toolchain,
        files: 2,
        root: receipt.root(),
    }
}

pub(crate) fn retained_with_library_alias(
    lease: &OperationLease,
    action: &Action,
    content: &[u8],
    soname: &str,
    versioned: &str,
    library: &[u8],
) -> BuildResult {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("bin")).unwrap();
    fs::create_dir_all(directory.path().join("usr/lib")).unwrap();
    fs::write(directory.path().join("bin/hello"), content).unwrap();
    fs::write(
        directory.path().join("usr/lib").join(versioned),
        library,
    )
    .unwrap();
    fs::write(
        directory.path().join("usr/lib/libdevel.so"),
        b"GROUP ( libanswer.so.1 )\n",
    )
    .unwrap();
    symlink(
        versioned,
        directory.path().join("usr/lib").join(soname),
    )
    .unwrap();
    fs::set_permissions(
        directory.path().join("bin/hello"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut artifact = Vec::new();
    artifact::pack(directory.path(), &mut artifact).unwrap();
    let receipt = Receipt::new(action, ContentDigest::sha256(&artifact), 4);
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    for bytes in [
        SOURCE,
        TOOLCHAIN,
        &action_bytes,
        &artifact,
        &receipt_bytes,
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
    BuildResult {
        retention: lease
            .retain_objects(&receipt.references(), &[])
            .unwrap(),
        execution: BuildExecution::Cached,
        action: action.digest(),
        artifact: receipt.output("out").unwrap().artifact,
        receipt: receipt.digest(),
        toolchain: receipt.toolchain,
        files: 4,
        root: receipt.root(),
    }
}

fn index_path(root: &Path, action: &Action) -> PathBuf {
    let digest = action.digest().to_string();
    root.join(".syrox-store/actions")
        .join(&digest[..2])
        .join(digest)
}
fn object_path(root: &Path, digest: ContentDigest) -> PathBuf {
    let digest = digest.to_string();
    root.join("objects/sha256")
        .join(&digest[..2])
        .join(digest)
}

#[test]
fn complete_results_reuse_with_explicit_retention_and_input_changes_miss() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let cancellation = Cancellation::default();
    let result = retained(&lease, &action, b"executable");
    // A visible root without a committed index does not turn into an implicit hit.
    assert!(
        lookup(&lease, &action, None, &cancellation)
            .unwrap()
            .is_none()
    );
    record(&lease, &action, &result).unwrap();
    let caller_root = RootName::new("caller_retention").unwrap();
    let hit = lookup(&lease, &action, Some(&caller_root), &cancellation)
        .unwrap()
        .unwrap();
    assert!(matches!(hit.execution, BuildExecution::Cached));
    assert_eq!(
        (hit.action, hit.artifact, hit.receipt, hit.root),
        (
            result.action,
            result.artifact,
            result.receipt,
            caller_root.clone()
        )
    );
    assert_eq!(
        lease.build_references(&caller_root).unwrap(),
        lease.build_references(&result.root).unwrap()
    );
    assert!(
        !directory
            .path()
            .join(".syrox-store/builds")
            .exists()
    );
    for field in [
        "source",
        "worker",
        "toolchain",
        "directory",
        "resources",
    ] {
        let mut other = action.clone();
        match field {
            "source" => other.source = ContentDigest::sha256(b"another source"),
            "worker" => other.worker = ContentDigest::sha256(b"another worker"),
            "toolchain" => other.toolchain = Some(ContentDigest::sha256(b"another toolchain")),
            "directory" => other.directory = "other".into(),
            _ => other.program.resources = super::super::BuildResources::Large,
        }
        assert!(
            lookup(&lease, &other, None, &cancellation)
                .unwrap()
                .is_none(),
            "{field}"
        );
    }
    cancellation.cancel();
    assert!(matches!(
        lookup(&lease, &action, None, &cancellation),
        Err(BuildError::Cancelled)
    ));
}

#[test]
fn gc_removal_leaves_a_stale_hint_and_never_resurrects_collected_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    record(&lease, &action, &result).unwrap();
    let operation = super::super::journal::Operation::create(&lease).unwrap();
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
    consumer_action.inputs = vec![super::super::records::InputIdentity {
        origin: crate::result::OutputOrigin::Built {
            receipt: provider.receipt,
        },
        action: provider.action,
        artifact: provider.artifact,
        output: "out".into(),
    }];
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
fn incomplete_provider_closure_is_not_authorized() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let provider = retained(&lease, &action(), b"provider");
    let mut consumer_action = action();
    consumer_action.directory = "consumer".into();
    consumer_action.inputs = vec![super::super::records::InputIdentity {
        origin: crate::result::OutputOrigin::Built {
            receipt: provider.receipt,
        },
        action: provider.action,
        artifact: provider.artifact,
        output: "out".into(),
    }];
    assert!(
        Receipt::new(&consumer_action, provider.artifact, 1)
            .with_inputs(&consumer_action, vec![provider.receipt])
            .is_err()
    );
    let mut incomplete = vec![
        provider.receipt,
        provider.action,
        provider.artifact,
    ];
    incomplete.sort_unstable();
    let receipt = Receipt::new(&consumer_action, provider.artifact, 1)
        .with_inputs(&consumer_action, incomplete)
        .unwrap();
    assert!(
        receipt
            .verify_inputs(&lease, &consumer_action, &Cancellation::default())
            .is_err()
    );
}

#[test]
fn orphaned_autotools_provider_reuses_only_without_a_divergence_marker() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let mut provider_action = action();
    provider_action.directory = "provider".into();
    let inventory = b"syrox-host-toolchain\nindependent cache provider";
    let producer_inventory = ContentDigest::sha256(inventory);
    lease
        .ingest(
            &inventory[..],
            producer_inventory,
            inventory.len() as u64,
        )
        .unwrap();
    provider_action.worker = ContentDigest::sha256(b"independent cache provider worker");
    provider_action.toolchain = Some(producer_inventory);

    let provider = retained(&lease, &provider_action, b"provider");
    let provider_references = lease
        .build_references(&provider.root)
        .unwrap()
        .unwrap();
    let mut consumer = action();
    assert_ne!(provider_action.worker, consumer.worker);
    assert_ne!(provider_action.toolchain, consumer.toolchain);
    // The independent provider and application must share the same index
    // shard without trying to acquire its flock twice through separate fds.
    let prefix = &provider_action.digest().to_string()[..2];
    consumer.directory = (0..4096)
        .map(|index| format!("consumer-{index}"))
        .find(|package| {
            consumer.directory = package.clone();
            consumer.inputs = vec![super::super::records::InputIdentity {
                origin: crate::result::OutputOrigin::Built {
                    receipt: provider.receipt,
                },
                action: provider.action,
                artifact: provider.artifact,
                output: "out".into(),
            }];
            consumer.digest().to_string().starts_with(prefix)
        })
        .expect("one-byte shard collision");
    consumer.inputs = vec![super::super::records::InputIdentity {
        origin: crate::result::OutputOrigin::Built {
            receipt: provider.receipt,
        },
        action: provider.action,
        artifact: provider.artifact,
        output: "out".into(),
    }];
    assert_eq!(&consumer.digest().to_string()[..2], prefix);
    let publish = |lease: &OperationLease, content: &[u8]| {
        let tree = tempfile::tempdir().unwrap();
        let path = tree.path().join("bin/hello");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut artifact = Vec::new();
        artifact::pack(tree.path(), &mut artifact).unwrap();
        let receipt = Receipt::new(&consumer, ContentDigest::sha256(&artifact), 1)
            .with_inputs(&consumer, provider_references.clone())
            .unwrap();
        for bytes in [
            &consumer.encode()[..],
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
        BuildResult {
            retention: lease
                .retain_objects(&receipt.references(), &[])
                .unwrap(),
            execution: BuildExecution::Cached,
            action: consumer.digest(),
            artifact: receipt.output("out").unwrap().artifact,
            receipt: receipt.digest(),
            toolchain: consumer.toolchain,
            files: 1,
            root: receipt.root(),
        }
    };
    let first = publish(&lease, b"first");
    record(&lease, &consumer, &first).unwrap();
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
    let lease = store.operation().unwrap();
    let query = RetainedQuery {
        application: description(&consumer),
        provider: description(&provider_action),
        worker: consumer.worker,
        toolchain: consumer.toolchain,
        input_outputs: vec!["out"],
    };
    // The fast path cannot accept an independent provider root before its own
    // index has been published, even when the consumer is already indexed.
    lease
        .publish_root(&provider.root, &provider_references)
        .unwrap();
    assert!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    record(&lease, &provider_action, &provider).unwrap();
    assert_eq!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default())
            .unwrap()
            .unwrap()
            .0
            .receipt,
        first.receipt
    );
    drop(lease);
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![provider.root],
            ..GcRequest::default()
        })
        .unwrap();
    let lease = store.operation().unwrap();
    // A visible retained result without a successfully published index must
    // not become a cache hit merely because its provider root was collected.
    fs::remove_file(index_path(directory.path(), &consumer)).unwrap();
    assert!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    record(&lease, &consumer, &first).unwrap();
    assert_eq!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default())
            .unwrap()
            .unwrap()
            .0
            .receipt,
        first.receipt
    );
    let inventory_path = object_path(directory.path(), producer_inventory);
    fs::write(&inventory_path, b"corrupt independent inventory").unwrap();
    assert!(retained_build_with_inputs(&lease, &query, &Cancellation::default()).is_err());
    fs::write(&inventory_path, inventory).unwrap();
    let second = publish(&lease, b"divergent");
    assert!(matches!(
        record(&lease, &consumer, &second),
        Err(BuildError::DivergentResults { .. })
    ));
    assert!(matches!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default()),
        Err(BuildError::DivergentResults { .. })
    ));
    drop(lease);
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![second.root],
            ..GcRequest::default()
        })
        .unwrap();
    let lease = store.operation().unwrap();
    assert!(matches!(
        retained_build_with_inputs(&lease, &query, &Cancellation::default()),
        Err(BuildError::DivergentResults { .. })
    ));
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
    consumer_action.inputs = vec![super::super::records::InputIdentity {
        origin: crate::result::OutputOrigin::Built {
            receipt: provider.receipt,
        },
        action: provider.action,
        artifact: provider.artifact,
        output: "out".into(),
    }];
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

#[test]
fn current_result_index_ignores_prelaunch_receipt_in_the_same_store() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"current executable");
    let current = lease
        .read_verified(result.receipt, MAX_RECORD_BYTES)
        .unwrap()
        .unwrap();
    let old = String::from_utf8(current.into_bytes())
        .unwrap()
        .replacen(
            "syrox-build-result-v4\n",
            "syrox-build-result\n",
            1,
        )
        .replacen("inputs 0\n", "", 1);
    let digest = ContentDigest::sha256(old.as_bytes());
    lease
        .ingest(old.as_bytes(), digest, old.len() as u64)
        .unwrap();
    let root = RootName::new(format!("build_{digest}")).unwrap();
    lease.publish_root(&root, &[digest]).unwrap();
    record(&lease, &action, &result).unwrap();
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        result.receipt
    );
}

#[test]
fn every_retained_object_and_root_relationship_is_verified_before_a_hit() {
    for corrupt in [
        "source",
        "toolchain",
        "action",
        "artifact",
        "receipt",
        "root",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let lease = store.operation().unwrap();
        let action = action();
        let result = retained(&lease, &action, b"executable");
        record(&lease, &action, &result).unwrap();
        let digest = match corrupt {
            "source" => action.source,
            "toolchain" => action.toolchain.unwrap(),
            "action" => result.action,
            "artifact" => result.artifact,
            _ => result.receipt,
        };
        if corrupt == "root" {
            let path = directory
                .path()
                .join("roots/retained")
                .join(result.root.as_str());
            let text = fs::read_to_string(&path).unwrap();
            fs::write(
                path,
                text.replace(&format!("{}\n", result.artifact), ""),
            )
            .unwrap();
        } else {
            fs::write(object_path(directory.path(), digest), b"corrupt").unwrap();
        }
        assert!(
            lookup(&lease, &action, None, &Cancellation::default()).is_err(),
            "{corrupt}"
        );
    }
}

#[test]
fn corrupt_unsafe_and_misbound_index_entries_are_errors_not_misses() {
    for damage in [
        "truncated",
        "symlink",
        "hardlink",
        "action",
        "receipt",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let lease = store.operation().unwrap();
        let action = action();
        let result = retained(&lease, &action, b"executable");
        record(&lease, &action, &result).unwrap();
        let path = index_path(directory.path(), &action);
        let bytes = fs::read(&path).unwrap();
        let other = directory.path().join("outside");
        fs::write(&other, &bytes).unwrap();
        match damage {
            "truncated" => fs::write(&path, &bytes[..bytes.len() - 1]).unwrap(),
            "symlink" => {
                fs::remove_file(&path).unwrap();
                symlink(&other, &path).unwrap();
            }
            "hardlink" => {
                fs::remove_file(&path).unwrap();
                fs::hard_link(&other, &path).unwrap();
            }
            "action" => fs::write(
                &path,
                String::from_utf8(bytes.clone()).unwrap().replace(
                    &action.digest().to_string(),
                    &ContentDigest::sha256(b"wrong action").to_string(),
                ),
            )
            .unwrap(),
            _ => fs::write(
                &path,
                String::from_utf8(bytes.clone()).unwrap().replace(
                    &format!("result {} ", result.receipt),
                    &format!(
                        "result {} ",
                        ContentDigest::sha256(b"missing receipt")
                    ),
                ),
            )
            .unwrap(),
        }
        assert!(
            lookup(&lease, &action, None, &Cancellation::default()).is_err(),
            "{damage}"
        );
        assert_eq!(fs::read(other).unwrap(), bytes);
    }
}

#[test]
fn conflicting_concurrent_publications_preserve_both_roots_and_refuse_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let first = retained(&lease, &action, b"first executable");
    let second = retained(&lease, &action, b"second executable");
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            record(&lease, &action, &first)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            record(&lease, &action, &second)
        });
        let results = [a.join().unwrap(), b.join().unwrap()];
        assert!(results.iter().filter(|r| r.is_ok()).count() <= 1);
        assert!(
            results
                .iter()
                .filter(|r| matches!(r, Err(BuildError::DivergentResults { .. })))
                .count()
                >= 1
        );
    });
    assert!(matches!(
        lookup(&lease, &action, None, &Cancellation::default()),
        Err(BuildError::DivergentResults { .. })
    ));
    assert!(
        lease
            .build_references(&first.root)
            .unwrap()
            .is_some()
    );
    assert!(
        lease
            .build_references(&second.root)
            .unwrap()
            .is_some()
    );
    let report = rebuild(&store).unwrap();
    assert_eq!(report.conflicts, [action.digest()]);
}

#[test]
fn losing_the_index_cannot_hide_a_retained_divergent_result() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let first = retained(&lease, &action, b"first");
    record(&lease, &action, &first).unwrap();
    fs::remove_file(index_path(directory.path(), &action)).unwrap();
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    let second = retained(&lease, &action, b"different rebuild");
    assert!(matches!(
        record(&lease, &action, &second),
        Err(BuildError::DivergentResults { .. })
    ));
    assert!(matches!(
        lookup(&lease, &action, None, &Cancellation::default()),
        Err(BuildError::DivergentResults { .. })
    ));
    assert!(
        lease
            .build_references(&first.root)
            .unwrap()
            .is_some()
    );
    assert!(
        lease
            .build_references(&second.root)
            .unwrap()
            .is_some()
    );
}

#[test]
fn reconstruction_uses_retained_receipts_and_identical_writers_converge() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    std::thread::scope(|scope| {
        let a = scope.spawn(|| record(&lease, &action, &result));
        let b = scope.spawn(|| record(&lease, &action, &result));
        a.join().unwrap().unwrap();
        b.join().unwrap().unwrap();
    });
    fs::remove_dir_all(directory.path().join(".syrox-store/actions")).unwrap();
    let report = rebuild(&store).unwrap();
    assert_eq!(report.indexed, 1);
    assert!(report.conflicts.is_empty());
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        result.receipt
    );
}

#[test]
fn uncertain_root_publication_is_not_automatically_indexed_and_index_failure_keeps_root() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    let references = lease
        .build_references(&result.root)
        .unwrap()
        .unwrap();
    fs::remove_file(
        directory
            .path()
            .join("roots/retained")
            .join(result.root.as_str()),
    )
    .unwrap();
    fd::fail_next_atomic(fd::AtomicFault::DirectorySync);
    assert!(matches!(
        lease.publish_root(&result.root, &references),
        Err(crate::store::StoreError::PublicationUncertain { .. })
    ));
    // Inject a real post-rename durability failure. Visibility alone is not an
    // automatic cache hit, even though every blob and root name is present.
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    lease
        .publish_root(&result.root, &references)
        .unwrap();
    fd::fail_next_lock_before_rename();
    assert!(record(&lease, &action, &result).is_err());
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    assert!(
        lease
            .build_references(&result.root)
            .unwrap()
            .is_some()
    );
    fd::fail_next_lock_after_rename();
    assert!(record(&lease, &action, &result).is_err());
    // Index durability was uncertain; the underlying result was fully committed.
    // A new hit independently verifies and reconfirms durable retention.
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        result.receipt
    );
}

#[test]
fn uncertain_publication_requires_rebuild_before_hit_and_gc_prunes_its_index() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"uncertain build result");
    let references = lease
        .build_references(&result.root)
        .unwrap()
        .unwrap();
    fs::remove_file(
        directory
            .path()
            .join("roots/retained")
            .join(result.root.as_str()),
    )
    .unwrap();
    fd::fail_next_atomic(fd::AtomicFault::DirectorySync);
    assert!(matches!(
        lease.publish_root(&result.root, &references),
        Err(crate::store::StoreError::PublicationUncertain { .. })
    ));
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    drop(lease);

    let report = rebuild(&store).unwrap();
    assert_eq!(report.indexed, 1);
    let lease = store.operation().unwrap();
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        result.receipt
    );
    drop(lease);

    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![result.root],
            ..GcRequest::default()
        })
        .unwrap();
    let lease = store.operation().unwrap();
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_none()
    );
    drop(lease);
    assert_eq!(rebuild(&store).unwrap().removed_stale, 1);
    assert!(!index_path(directory.path(), &action).exists());
}

#[test]
fn reindex_repairs_bounded_malformed_hints_and_prunes_only_unretained_entries() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let result = retained(&lease, &action, b"executable");
    record(&lease, &action, &result).unwrap();
    let path = index_path(directory.path(), &action);
    fs::write(&path, b"truncated").unwrap();
    assert!(lookup(&lease, &action, None, &Cancellation::default()).is_err());
    assert_eq!(rebuild(&store).unwrap().indexed, 1);
    assert!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .is_some()
    );
    drop(lease);
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![result.root],
            ..GcRequest::default()
        })
        .unwrap();
    assert_eq!(rebuild(&store).unwrap().removed_stale, 1);
    assert!(!path.exists());
}

#[test]
fn a_divergence_marker_stays_closed_until_explicit_reconstruction() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let lease = store.operation().unwrap();
    let action = action();
    let first = retained(&lease, &action, b"first");
    record(&lease, &action, &first).unwrap();
    let second = retained(&lease, &action, b"second");
    assert!(matches!(
        record(&lease, &action, &second),
        Err(BuildError::DivergentResults { .. })
    ));
    drop(lease);
    store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![second.root],
            ..GcRequest::default()
        })
        .unwrap();
    let lease = store.operation().unwrap();
    assert!(matches!(
        lookup(&lease, &action, None, &Cancellation::default()),
        Err(BuildError::DivergentResults { .. })
    ));
    assert_eq!(rebuild(&store).unwrap().indexed, 1);
    assert_eq!(
        lookup(&lease, &action, None, &Cancellation::default())
            .unwrap()
            .unwrap()
            .receipt,
        first.receipt
    );
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

/// Two independently mountable outputs from one receipt for runtime closure tests.
pub(crate) fn retained_split_runtime(
    store: &Store,
    loader_bytes: &[u8],
    library_bytes: &[u8],
) -> (RootName, ContentDigest, ContentDigest) {
    use crate::build::records::NamedOutput;
    let mut action = action();
    action.directory = "split-loader-library".into();
    action.program.outputs = vec!["lib".into(), "out".into()];
    let pack = |path: &str, bytes: &[u8]| {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        let mut result = Vec::new();
        artifact::pack(directory.path(), &mut result).unwrap();
        result
    };
    let loader_artifact = pack("bin/hello", loader_bytes);
    let library_artifact = pack("usr/lib/libsplit.so.1", library_bytes);
    let receipt = Receipt::new(
        &action,
        ContentDigest::sha256(&loader_artifact),
        1,
    )
    .with_outputs(
        &action,
        BTreeMap::from([(
            "lib".into(),
            NamedOutput {
                artifact: ContentDigest::sha256(&library_artifact),
                files: 1,
            },
        )]),
    )
    .unwrap();
    let action_bytes = action.encode();
    let receipt_bytes = receipt.encode();
    let lease = store.operation().unwrap();
    for bytes in [
        &b"fixture source"[..],
        &b"syrox-host-toolchain\nfixture toolchain"[..],
        &action_bytes,
        &loader_artifact,
        &library_artifact,
        &receipt_bytes,
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
    (receipt.root(), receipt.digest(), action.digest())
}

#[test]
fn managed_action_and_receipt_roundtrip_without_host_inventory() {
    let host = action();
    let mut managed = host.clone();
    managed.program.profile = super::super::BuildProfile::Managed;
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
                super::super::MANAGED_PROFILE,
                super::super::PROFILE
            )
            .as_bytes()
        )
        .is_err()
    );
}
