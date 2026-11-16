use super::*;
use crate::{
    result::{ResultManifest, admit_system_result},
    store::{GcRequest, RootName},
    system::budget::{BuildBudget, BuilderLimits},
};
use std::{
    fs::{self, File},
    io::Cursor,
    os::unix::fs::symlink,
};

fn budget(bytes: u64, files: u64) -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: 64 * 1024 * 1024,
        cpu_percent: 100,
        processes: 16,
        descriptors: 64,
        scratch_bytes: 1024 * 1024,
        files,
        output_bytes: bytes,
        duration_seconds: 60,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}
fn action() -> ContentDigest {
    ContentDigest::sha256(b"independently authenticated action")
}
fn names() -> BTreeSet<String> {
    BTreeSet::from(["a".into(), "z".into()])
}
fn packet(budget: &AdmittedBudget, size: usize) -> Vec<u8> {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    fs::create_dir(first.path().join("share")).unwrap();
    fs::write(first.path().join("share/data"), vec![0x5a; size]).unwrap();
    symlink("data", first.path().join("share/link")).unwrap();
    fs::write(second.path().join("data"), b"second").unwrap();
    let cancel = Cancellation::default();
    let streams = BTreeMap::from([
        (
            "a".into(),
            SystemOutputStream::from_directory(File::open(first.path()).unwrap(), budget, &cancel)
                .unwrap(),
        ),
        (
            "z".into(),
            SystemOutputStream::from_directory(
                File::open(second.path()).unwrap(),
                budget,
                &cancel,
            )
            .unwrap(),
        ),
    ]);
    let mut bytes = Vec::new();
    write_system_outputs(&mut bytes, action(), streams, budget, &cancel).unwrap();
    bytes
}
fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(directory.path()).unwrap();
    (directory, store)
}
fn empty_objects(directory: &Path) -> bool {
    fs::read_dir(directory.join("objects/sha256"))
        .unwrap()
        .all(|entry| {
            fs::read_dir(entry.unwrap().path())
                .unwrap()
                .next()
                .is_none()
        })
}
use std::path::Path;

#[test]
fn version_one_packet_and_budget_binding_have_fixed_wire_identities() {
    // Independently assembled using the documented LE integer/record framing.
    let limits = budget(4096, 10);
    let bytes = packet(&limits, 17);
    assert_eq!(bytes.len(), 303);
    assert_eq!(
        ContentDigest::sha256(&bytes).to_string(),
        "9985771dade5fd6896d66114cc2ee169f0ab44da1b8ac5faec5197d2341040b2"
    );
    assert_eq!(
        budget_pin(&limits).to_string(),
        "ba4541f59af8088a4b8efa9fdbfbfc9d8db13607120f23d4ea77476347612013"
    );
}

#[test]
fn multiple_actual_outputs_cross_chunks_and_admit_as_a_v3_consumption_result() {
    let limits = budget(32 * 1024 * 1024, 100);
    let size = crate::store::chunked::CHUNK_BYTES + 17;
    let bytes = packet(&limits, size);
    let (_directory, store) = store();
    let cancel = Cancellation::default();
    let outputs = receive_system_outputs(
        &store,
        &mut bytes.as_slice(),
        action(),
        &names(),
        &limits,
        &cancel,
    )
    .unwrap();
    assert_eq!(outputs.len(), 2);
    assert_eq!(
        outputs["a"].artifact().manifest().chunks().len(),
        2
    );
    let manifest = ResultManifest::for_system(
        outputs
            .iter()
            .map(|(name, value)| (name.clone(), value.metadata().clone()))
            .collect(),
        BTreeMap::new(),
        &limits,
    )
    .unwrap();
    let pin = manifest.digest().unwrap();
    let root = RootName::new("received_system_outputs").unwrap();
    let admitted = admit_system_result(&store, &root, &manifest, pin, &limits, &cancel).unwrap();
    let view = admitted
        .output("a")
        .unwrap()
        .open(&store, &cancel)
        .unwrap();
    assert_eq!(
        view.read_file("share/link", size as u64, &cancel)
            .unwrap(),
        vec![0x5a; size]
    );
    assert_eq!(
        admitted
            .output("z")
            .unwrap()
            .open(&store, &cancel)
            .unwrap()
            .read_file("data", 6, &cancel)
            .unwrap(),
        b"second"
    );
}

struct ShortIo<T> {
    inner: T,
    calls: usize,
}
impl<R: Read> Read for ShortIo<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls % 4 == 1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let take = bytes.len().min(7);
        self.inner.read(&mut bytes[..take])
    }
}
impl<W: Write> Write for ShortIo<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls % 4 == 1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.inner.write(&bytes[..bytes.len().min(5)])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn short_interrupted_io_preserves_the_exact_canonical_packet() {
    let limits = budget(4096, 10);
    let bytes = packet(&limits, 17);
    let (_directory, store) = store();
    receive_system_outputs(
        &store,
        &mut ShortIo {
            inner: bytes.as_slice(),
            calls: 0,
        },
        action(),
        &names(),
        &limits,
        &Cancellation::default(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("data"), b"payload").unwrap();
    let cancel = Cancellation::default();
    let make = || {
        SystemOutputStream::from_directory(
            File::open(directory.path()).unwrap(),
            &limits,
            &cancel,
        )
        .unwrap()
    };
    let mut expected = Vec::new();
    write_system_outputs(
        &mut expected,
        action(),
        BTreeMap::from([("out".into(), make())]),
        &limits,
        &cancel,
    )
    .unwrap();
    let mut actual = ShortIo {
        inner: Vec::new(),
        calls: 0,
    };
    write_system_outputs(
        &mut actual,
        action(),
        BTreeMap::from([("out".into(), make())]),
        &limits,
        &cancel,
    )
    .unwrap();
    assert_eq!(expected, actual.inner);
}

#[test]
fn selection_action_policy_and_every_budget_dimension_are_checked_before_upload() {
    let limits = budget(4096, 10);
    let bytes = packet(&limits, 17);
    let (directory, store) = store();
    let cancel = Cancellation::default();
    assert!(
        receive_system_outputs(
            &store,
            &mut bytes.as_slice(),
            ContentDigest::sha256(b"other"),
            &names(),
            &limits,
            &cancel
        )
        .is_err()
    );
    assert!(
        receive_system_outputs(
            &store,
            &mut bytes.as_slice(),
            action(),
            &BTreeSet::from(["a".into()]),
            &limits,
            &cancel
        )
        .is_err()
    );
    for n in 0..8 {
        let mut request = *limits.request();
        match n {
            0 => request.memory_bytes += 1,
            1 => request.cpu_percent += 1,
            2 => request.processes += 1,
            3 => request.descriptors += 1,
            4 => request.scratch_bytes += 1,
            5 => request.files += 1,
            6 => request.output_bytes += 1,
            7 => request.duration_seconds += 1,
            _ => unreachable!(),
        }
        let changed = BuilderLimits::new(request)
            .unwrap()
            .admit(request)
            .unwrap();
        assert!(
            receive_system_outputs(
                &store,
                &mut bytes.as_slice(),
                action(),
                &names(),
                &changed,
                &cancel
            )
            .is_err()
        );
    }
    let mut maximum = *limits.request();
    maximum.memory_bytes *= 2;
    let different_policy = BuilderLimits::new(maximum)
        .unwrap()
        .admit(*limits.request())
        .unwrap();
    assert!(
        receive_system_outputs(
            &store,
            &mut bytes.as_slice(),
            action(),
            &names(),
            &different_policy,
            &cancel
        )
        .is_err()
    );
    assert!(empty_objects(directory.path()));
}

#[test]
fn writer_preflights_aggregate_limits_and_consumed_streams_before_emitting_bytes() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("data"), b"payload").unwrap();
    let cancel = Cancellation::default();
    let large = budget(4096, 100);
    let make = || {
        SystemOutputStream::from_directory(
            File::open(directory.path()).unwrap(),
            &large,
            &cancel,
        )
        .unwrap()
    };
    let one = make().encoded_size();
    for denied in [
        budget(one * 2 - 1, 100),
        budget(4096, 3),
    ] {
        let mut bytes = Vec::new();
        assert!(
            write_system_outputs(
                &mut bytes,
                action(),
                BTreeMap::from([
                    ("a".into(), make()),
                    ("z".into(), make())
                ]),
                &denied,
                &cancel
            )
            .is_err()
        );
        assert!(bytes.is_empty());
    }
    let mut consumed = make();
    assert_ne!(consumed.read(&mut [0; 1]).unwrap(), 0);
    let mut bytes = Vec::new();
    assert!(
        write_system_outputs(
            &mut bytes,
            action(),
            BTreeMap::from([("out".into(), consumed)]),
            &large,
            &cancel
        )
        .is_err()
    );
    assert!(bytes.is_empty());
}

#[test]
fn receiver_rechecks_aggregate_alias_expansion_and_inodes_and_failure_uploads_are_collectible() {
    let large = budget(4096, 100);
    let valid = packet(&large, 100);
    for limits in [budget(4096, 5), budget(205, 100)] {
        let (directory, store) = store();
        let mut bytes = valid.clone();
        let start = HEADER.len() + 32;
        bytes[start..start + 32].copy_from_slice(budget_pin(&limits).as_bytes());
        assert!(
            receive_system_outputs(
                &store,
                &mut bytes.as_slice(),
                action(),
                &names(),
                &limits,
                &Cancellation::default()
            )
            .is_err()
        );
        assert_eq!(
            fs::read_dir(directory.path().join("roots/retained"))
                .unwrap()
                .count(),
            0
        );
        let report = store
            .maintenance()
            .unwrap()
            .garbage_collect(&GcRequest {
                collect: true,
                ..GcRequest::default()
            })
            .unwrap();
        assert!(!report.uncertain);
        assert!(report.failures.is_empty());
        assert!(empty_objects(directory.path()));
    }
}

#[test]
fn checksum_length_truncation_trailing_bytes_and_name_order_cannot_publish_a_result() {
    let limits = budget(4096, 10);
    let bytes = packet(&limits, 17);
    let body = HEADER.len() + 32 + 32 + 2 + 1 + 1 + 8;
    let mut bad = Vec::new();
    for cut in [
        0,
        HEADER.len() - 1,
        body - 1,
        body + 1,
        bytes.len() - 1,
    ] {
        bad.push(bytes[..cut].to_vec());
    }
    let mut corrupt = bytes.clone();
    corrupt[body + 16] ^= 1;
    bad.push(corrupt);
    let mut trailer = bytes.clone();
    *trailer.last_mut().unwrap() ^= 1;
    bad.push(trailer);
    let mut length = bytes.clone();
    length[body - 8..body].copy_from_slice(&u64::MAX.to_le_bytes());
    bad.push(length);
    let mut trailing = bytes.clone();
    trailing.push(0);
    bad.push(trailing);
    let mut name = bytes.clone();
    name[body - 9] = b'z';
    bad.push(name);
    let (directory, store) = store();
    for bytes in bad {
        assert!(
            receive_system_outputs(
                &store,
                &mut bytes.as_slice(),
                action(),
                &names(),
                &limits,
                &Cancellation::default()
            )
            .is_err()
        );
        assert_eq!(
            fs::read_dir(directory.path().join("roots/retained"))
                .unwrap()
                .count(),
            0
        );
    }
}

struct CancelRead<'a> {
    input: Cursor<Vec<u8>>,
    cancellation: &'a Cancellation,
    at: u64,
}
impl Read for CancelRead<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.input.position() >= self.at {
            self.cancellation.cancel();
            return Err(crate::cancellation::cancellation_io());
        }
        let take = bytes.len().min(11);
        self.input.read(&mut bytes[..take])
    }
}

#[test]
fn cancellation_during_a_frame_leaves_no_consumer_root_or_live_upload_interest() {
    let limits = budget(4096, 10);
    let (directory, store) = store();
    let cancel = Cancellation::default();
    let mut input = CancelRead {
        input: Cursor::new(packet(&limits, 100)),
        cancellation: &cancel,
        at: 150,
    };
    assert!(matches!(
        receive_system_outputs(
            &store,
            &mut input,
            action(),
            &names(),
            &limits,
            &cancel
        ),
        Err(ResultError::Cancelled)
    ));
    assert_eq!(
        fs::read_dir(directory.path().join("roots/retained"))
            .unwrap()
            .count(),
        0
    );
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain);
    assert!(report.failures.is_empty());
    assert!(empty_objects(directory.path()));
}
