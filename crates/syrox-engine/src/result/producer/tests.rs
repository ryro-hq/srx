use super::*;
use crate::{
    bundle::{export_system_bundle, import_system_bundle},
    result::{OutputOrigin, ResultManifest, admit_system_result, stage_system_output},
    store::{ContentDigest, GcRequest, RootName, Store, chunked::CHUNK_BYTES},
    system::budget::{BuildBudget, BuilderLimits},
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read as _, Seek as _, SeekFrom},
    os::unix::fs::{PermissionsExt as _, symlink},
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

fn stream<'a>(
    root: &Path,
    budget: &AdmittedBudget,
    cancellation: &'a Cancellation,
) -> SystemOutputStream<'a> {
    SystemOutputStream::from_directory(File::open(root).unwrap(), budget, cancellation).unwrap()
}

#[test]
fn small_frames_match_legacy_bytes_with_short_reads_aliases_empty_files_and_raw_order() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    fs::create_dir(root.join("types")).unwrap();
    fs::write(root.join("types/wint_t.h"), b"wide").unwrap();
    fs::write(root.join("types.h"), b"header").unwrap();
    fs::write(root.join("empty"), b"").unwrap();
    fs::write(root.join("run"), b"executable").unwrap();
    fs::set_permissions(
        root.join("run"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    symlink("../types.h", root.join("types/link")).unwrap();
    let cancel = Cancellation::default();
    let mut input = stream(root, &budget(4096, 20), &cancel);
    assert_eq!(input.files(), 5);
    let expected_size = input.encoded_size();
    let mut legacy = Vec::new();
    artifact::pack(root, &mut legacy).unwrap();
    let mut encoded = Vec::new();
    let mut buffer = [0; 13];
    loop {
        let count = input.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        encoded.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(encoded, legacy);
    assert_eq!(encoded.len() as u64, expected_size);
    assert_eq!(input.read(&mut buffer).unwrap(), 0);
}

#[test]
fn inode_and_encoding_limits_charge_root_empty_directories_headers_and_alias_expansion() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    fs::write(root.join("data"), b"payload").unwrap();
    fs::create_dir(root.join("empty")).unwrap();
    let cancel = Cancellation::default();
    let exact = stream(root, &budget(4096, 3), &cancel).encoded_size();
    for denied in [budget(4096, 2), budget(exact - 1, 3)] {
        assert!(
            SystemOutputStream::from_directory(File::open(root).unwrap(), &denied, &cancel)
                .is_err()
        );
    }
    let mut valid = stream(root, &budget(exact, 3), &cancel);
    assert_eq!(
        io::copy(&mut valid, &mut io::sink()).unwrap(),
        exact
    );
    fs::write(root.join("data"), vec![0; 1024]).unwrap();
    for n in 0..20 {
        symlink("data", root.join(format!("alias-{n}"))).unwrap();
    }
    assert!(
        SystemOutputStream::from_directory(
            File::open(root).unwrap(),
            &budget(4096, 24),
            &cancel
        )
        .is_err()
    );
}

#[test]
fn unsafe_paths_aliases_links_modes_and_empty_outputs_are_refused_before_staging() {
    let temporary = tempfile::tempdir().unwrap();
    let cancel = Cancellation::default();
    let limits = budget(4096, 50);
    assert!(
        SystemOutputStream::from_directory(
            File::open(temporary.path()).unwrap(),
            &limits,
            &cancel
        )
        .is_err()
    );
    for (n, target) in [
        "/etc/passwd",
        "../../outside",
        "missing",
        "chain",
    ]
    .into_iter()
    .enumerate()
    {
        let root = temporary.path().join(format!("alias-{n}"));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("data"), b"data").unwrap();
        symlink("data", root.join("chain")).unwrap();
        symlink(target, root.join("alias")).unwrap();
        assert!(
            SystemOutputStream::from_directory(File::open(root).unwrap(), &limits, &cancel)
                .is_err()
        );
    }
    for (n, name, mode, link) in [
        (0, "bad name", 0o644, false),
        (1, "data", 0o4755, false),
        (2, "data", 0o644, true),
    ] {
        let root = temporary.path().join(format!("file-{n}"));
        fs::create_dir(&root).unwrap();
        fs::write(root.join(name), b"data").unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(mode)).unwrap();
        if link {
            fs::hard_link(root.join(name), root.join("second")).unwrap();
        }
        assert!(
            SystemOutputStream::from_directory(File::open(root).unwrap(), &limits, &cancel)
                .is_err()
        );
    }
    let ordinary = temporary.path().join("file");
    fs::write(&ordinary, b"data").unwrap();
    assert!(
        SystemOutputStream::from_directory(File::open(ordinary).unwrap(), &limits, &cancel)
            .is_err()
    );
}

#[test]
fn a_changed_tree_or_file_poison_the_stream_and_cannot_resume_after_restoration() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let path = root.join("data");
    fs::write(&path, vec![0x55; 3 * 64 * 1024]).unwrap();
    let cancel = Cancellation::default();
    let limits = budget(1024 * 1024, 10);
    let mut input = stream(root, &limits, &cancel);
    let mut buffer = vec![0; 1024 * 1024];
    assert_ne!(input.read(&mut buffer).unwrap(), 0); // header
    assert_ne!(input.read(&mut buffer).unwrap(), 0); // record
    assert_eq!(input.read(&mut buffer).unwrap(), 64 * 1024); // payload bound
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all_at(b"changed consumed bytes", 0)
        .unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    assert!(io::copy(&mut input, &mut io::sink()).is_err());
    fs::write(&path, vec![0x55; 3 * 64 * 1024]).unwrap();
    assert!(input.read(&mut buffer).is_err());

    let mut input = stream(root, &limits, &cancel);
    fs::create_dir(root.join("new-empty-directory")).unwrap();
    assert!(input.read(&mut buffer).is_err());
    assert!(input.read(&mut buffer).is_err());
}

#[test]
fn pinned_root_is_used_and_later_symlink_replacement_never_reads_outside_the_tree() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("original");
    let saved = temporary.path().join("saved");
    let outside = temporary.path().join("outside");
    fs::create_dir(&original).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(original.join("data"), b"authorized tree").unwrap();
    fs::write(outside.join("data"), b"outside tree").unwrap();
    let pinned = File::open(&original).unwrap();
    fs::rename(&original, &saved).unwrap();
    symlink(&outside, &original).unwrap();
    let cancel = Cancellation::default();
    let limits = budget(4096, 10);
    let mut input = SystemOutputStream::from_directory(pinned, &limits, &cancel).unwrap();
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).unwrap();
    assert!(bytes.ends_with(b"authorized tree"));

    let mut input = stream(&saved, &limits, &cancel);
    fs::rename(saved.join("data"), saved.join("other")).unwrap();
    symlink(outside.join("data"), saved.join("data")).unwrap();
    assert!(input.read(&mut [0; 1]).is_err());
    assert_eq!(
        fs::read(outside.join("data")).unwrap(),
        b"outside tree"
    );
}

#[test]
fn cancellation_stops_preparation_and_emission_without_a_manifest_or_root() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(temporary.path().join("data"), b"data").unwrap();
    let limits = budget(4096, 10);
    let cancel = Cancellation::default();
    let mut input = stream(temporary.path(), &limits, &cancel);
    cancel.cancel();
    assert!(matches!(
        SystemOutputStream::from_directory(
            File::open(temporary.path()).unwrap(),
            &limits,
            &cancel
        ),
        Err(ResultError::Cancelled)
    ));
    assert!(input.read(&mut [0; 1]).is_err());
    let store_directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(store_directory.path()).unwrap();
    assert!(matches!(
        stage_system_output(
            &store,
            File::open(temporary.path()).unwrap(),
            ContentDigest::sha256(b"action"),
            "out",
            &limits,
            &cancel
        ),
        Err(ResultError::Cancelled)
    ));
    assert_eq!(
        fs::read_dir(store_directory.path().join("roots/retained"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn system_producer_exceeds_legacy_file_count_without_relaxing_legacy_encoder() {
    let temporary = tempfile::tempdir().unwrap();
    for n in 0..=artifact::MAX_FILES {
        File::create(temporary.path().join(format!("file-{n:05}"))).unwrap();
    }
    let cancel = Cancellation::default();
    assert!(artifact::PreparedArtifact::new(temporary.path()).is_err());
    let limits = budget(1024 * 1024, artifact::MAX_FILES as u64 + 2);
    let mut input = stream(temporary.path(), &limits, &cancel);
    assert_eq!(input.files(), artifact::MAX_FILES + 1);
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).unwrap();
    let index = artifact::scan_with_limits(
        bytes.as_slice(),
        "",
        super::super::staging::system_limits(&limits).unwrap(),
    )
    .unwrap();
    assert_eq!(index.len(), artifact::MAX_FILES + 1);
}

#[test]
fn actual_file_over_one_gibibyte_streams_into_chunks_and_round_trips_a_system_bundle() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload");
    let size = 1024 * 1024 * 1024 + 17;
    let file = File::create(&payload).unwrap();
    file.set_len(size).unwrap();
    file.write_all_at(b"first", 0).unwrap();
    file.write_all_at(b"last", size - 4).unwrap();
    drop(file);
    let store_directory = tempfile::tempdir().unwrap();
    let store = Store::initialize(store_directory.path()).unwrap();
    let cancel = Cancellation::default();
    let limits = budget(size + 4096, 10);
    assert!(artifact::PreparedArtifact::new(directory.path()).is_err());
    let prepared = stage_system_output(
        &store,
        File::open(directory.path()).unwrap(),
        ContentDigest::sha256(b"producer identity only"),
        "out",
        &limits,
        &cancel,
    )
    .unwrap();
    assert!(prepared.artifact().manifest().size() > crate::store::MAX_STORE_BLOB_BYTES);
    assert_eq!(prepared.metadata().files, 1);
    assert_eq!(
        prepared.artifact().manifest().chunks().len(),
        usize::try_from(prepared.artifact().manifest().size())
            .unwrap()
            .div_ceil(CHUNK_BYTES)
    );
    // Independent whole-frame hash, without a whole-frame allocation.
    let mut header = artifact::HEADER.to_vec();
    header.extend_from_slice(&1_u32.to_le_bytes());
    header.extend_from_slice(&7_u16.to_le_bytes());
    header.extend_from_slice(b"payload");
    header.push(0);
    header.extend_from_slice(&size.to_le_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&header);
    let mut source = File::open(payload).unwrap();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let n = source.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    assert_eq!(
        prepared.artifact().manifest().content_digest(),
        ContentDigest::from_sha256_hash(hasher.finalize().into())
    );
    let manifest = ResultManifest::for_system(
        BTreeMap::from([("data".into(), prepared.metadata().clone())]),
        BTreeMap::new(),
        &limits,
    )
    .unwrap();
    let pin = manifest.digest().unwrap();
    let root = RootName::new("system_producer_roundtrip").unwrap();
    let admitted = admit_system_result(&store, &root, &manifest, pin, &limits, &cancel).unwrap();
    assert!(
        matches!(admitted.output("data").unwrap().identity.origin, OutputOrigin::Imported { manifest } if manifest == pin)
    );
    assert!(manifest.references().unwrap().len() < 10);
    // The portable bundle shares the repeated zero chunks; no logical-size buffer.
    let mut transport = tempfile::tempfile().unwrap();
    export_system_bundle(
        &store,
        &root,
        pin,
        &mut transport,
        &limits,
        &cancel,
    )
    .unwrap();
    assert!(transport.metadata().unwrap().len() < 5 * CHUNK_BYTES as u64);
    transport.seek(SeekFrom::Start(0)).unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let destination = Store::initialize(destination_directory.path()).unwrap();
    let imported = import_system_bundle(
        &destination,
        &root,
        pin,
        &mut transport,
        &limits,
        &cancel,
    )
    .unwrap();
    assert_eq!(imported.manifest(), &manifest);
    drop(imported);
    drop(prepared);
    drop(admitted);
    let report = store
        .maintenance()
        .unwrap()
        .garbage_collect(&GcRequest {
            collect: true,
            remove_roots: vec![root],
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!report.uncertain);
    assert!(report.failures.is_empty());
    assert!(
        store
            .operation()
            .unwrap()
            .verify(pin)
            .unwrap()
            .is_none()
    );
}
