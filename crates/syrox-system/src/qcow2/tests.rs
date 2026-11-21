use super::*;
use crate::budget::{AdmittedBudget, BuildBudget, BuilderLimits};
use sha2::{Digest as _, Sha256};
use std::io::{Cursor, Read as _, Write as _};

fn budget(bytes: u64) -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: 32 * 1024 * 1024,
        cpu_percent: 100,
        processes: 8,
        descriptors: 32,
        scratch_bytes: 1024 * 1024,
        files: 8,
        output_bytes: bytes,
        duration_seconds: 120,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}

#[test]
fn geometry_includes_metadata_refcounts_and_handles_l2_and_refcount_boundaries() {
    assert!(Geometry::new(0).is_err());
    assert!(Geometry::new(513).is_err());
    assert!(Geometry::new(u64::MAX - 511).is_err());
    assert_eq!(
        Geometry::new(512).unwrap().encoded_bytes(),
        6 * CLUSTER_BYTES
    );
    assert_eq!(
        Geometry::new(CLUSTER_BYTES * TABLE_ENTRIES)
            .unwrap()
            .l2_tables(),
        1
    );
    assert_eq!(
        Geometry::new(CLUSTER_BYTES * TABLE_ENTRIES + 512)
            .unwrap()
            .l2_tables(),
        2
    );
    assert_eq!(
        Geometry::new(32760 * CLUSTER_BYTES)
            .unwrap()
            .refcount_blocks(),
        1
    );
    assert_eq!(
        Geometry::new(32761 * CLUSTER_BYTES)
            .unwrap()
            .refcount_blocks(),
        2
    );
}

#[test]
fn standard_cluster_mapping_refcounts_padding_and_hashes_are_consistent() {
    for length in [
        512,
        CLUSTER_BYTES,
        CLUSTER_BYTES + 512,
        3 * CLUSTER_BYTES,
    ] {
        let raw = vec![0x71; usize::try_from(length).unwrap()];
        let geometry = Geometry::new(length).unwrap();
        let mut output = Vec::new();
        let written = geometry
            .write(
                &mut Cursor::new(&raw),
                Sha256::digest(&raw).into(),
                &mut output,
                &budget(geometry.encoded_bytes()),
                || false,
            )
            .unwrap();
        assert_eq!(&output[..4], b"QFI\xfb");
        assert_eq!(syrox_encoding::u32_be_at(&output, 4).unwrap(), 3);
        assert_eq!(syrox_encoding::u64_be_at(&output, 8).unwrap(), 0);
        assert_eq!(
            syrox_encoding::u64_be_at(&output, 24).unwrap(),
            length
        );
        assert_eq!(syrox_encoding::u32_be_at(&output, 60).unwrap(), 0);
        assert!(output[72..96].iter().all(|byte| *byte == 0));
        assert_eq!(syrox_encoding::u32_be_at(&output, 96).unwrap(), 4);
        assert_eq!(
            syrox_encoding::u32_be_at(&output, 100).unwrap(),
            104
        );
        assert_eq!(written.bytes, geometry.encoded_bytes());
        assert_eq!(
            written.sha256,
            <[u8; 32]>::from(Sha256::digest(&output))
        );
        let l1 = usize::try_from(syrox_encoding::u64_be_at(&output, 40).unwrap()).unwrap();
        let offset_mask = 0x00ff_ffff_ffff_fe00;
        let mut decoded = Vec::new();
        for guest in 0..geometry.data_clusters() {
            let l1_entry = syrox_encoding::u64_be_at(
                &output,
                l1 + usize::try_from(guest / TABLE_ENTRIES * 8).unwrap(),
            )
            .unwrap();
            assert_ne!(l1_entry & COPIED, 0);
            let l2 = usize::try_from(l1_entry & offset_mask).unwrap();
            let descriptor = syrox_encoding::u64_be_at(
                &output,
                l2 + usize::try_from(guest % TABLE_ENTRIES * 8).unwrap(),
            )
            .unwrap();
            assert_ne!(descriptor & COPIED, 0);
            let data = usize::try_from(descriptor & offset_mask).unwrap();
            let take = usize::try_from((length - decoded.len() as u64).min(CLUSTER_BYTES)).unwrap();
            decoded.extend_from_slice(&output[data..data + take]);
            assert!(
                output[data + take..data + usize::try_from(CLUSTER_BYTES).unwrap()]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
        assert_eq!(Sha256::digest(&decoded), Sha256::digest(&raw));
        let ref_table = usize::try_from(syrox_encoding::u64_be_at(&output, 48).unwrap()).unwrap();
        for cluster in 0..written.bytes / CLUSTER_BYTES {
            let reference = usize::try_from(
                syrox_encoding::u64_be_at(
                    &output,
                    ref_table + usize::try_from(cluster / REFCOUNT_ENTRIES * 8).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            let offset = reference + usize::try_from(cluster % REFCOUNT_ENTRIES * 2).unwrap();
            assert_eq!(
                u16::from_be_bytes(output[offset..offset + 2].try_into().unwrap()),
                1
            );
        }
        let mut again = Vec::new();
        geometry
            .write(
                &mut Cursor::new(&raw),
                Sha256::digest(&raw).into(),
                &mut again,
                &budget(geometry.encoded_bytes()),
                || false,
            )
            .unwrap();
        assert_eq!(Sha256::digest(again), Sha256::digest(output));
    }
}

#[test]
fn bad_source_identity_length_eof_budget_and_cancellation_never_succeed() {
    let raw = vec![0x71; 512];
    let geometry = Geometry::new(512).unwrap();
    let pin = Sha256::digest(&raw).into();
    for input in [
        raw[..511].to_vec(),
        [raw.as_slice(), &[0]].concat(),
        vec![0x72; 512],
    ] {
        assert!(matches!(
            geometry.write(
                &mut Cursor::new(input),
                pin,
                &mut Vec::new(),
                &budget(geometry.encoded_bytes()),
                || false
            ),
            Err(QcowError::Content)
        ));
    }
    let mut source = Cursor::new(&raw);
    let mut output = Vec::new();
    assert!(matches!(
        geometry.write(
            &mut source,
            pin,
            &mut output,
            &budget(geometry.encoded_bytes() - 1),
            || false
        ),
        Err(QcowError::Budget(_))
    ));
    assert_eq!(source.position(), 0);
    assert!(output.is_empty());
    assert!(matches!(
        geometry.write(
            &mut source,
            pin,
            &mut output,
            &budget(geometry.encoded_bytes()),
            || true
        ),
        Err(QcowError::Cancelled)
    ));
    assert!(output.is_empty());
    let mut checks = 0;
    assert!(matches!(
        geometry.write(
            &mut source,
            pin,
            &mut output,
            &budget(geometry.encoded_bytes()),
            || {
                checks += 1;
                checks == 4
            }
        ),
        Err(QcowError::Cancelled)
    ));
    assert!(!output.is_empty() && (output.len() as u64) < geometry.encoded_bytes());
}

#[test]
#[ignore = "requires explicitly pinned SRX_QEMU_IMG and SRX_QEMU_IMG_SHA256; uses disposable regular images only"]
fn qemu_checks_refcounts_and_decodes_byte_identical_raw_content() {
    use std::{fs, process::Command};
    let tool = std::env::var("SRX_QEMU_IMG").expect("select a reference executable");
    let pin = std::env::var("SRX_QEMU_IMG_SHA256").expect("pin the reference executable");
    let metadata = fs::symlink_metadata(&tool).unwrap();
    assert!(metadata.is_file() && metadata.len() <= 32 * 1024 * 1024);
    assert_eq!(
        syrox_encoding::hex(&Sha256::digest(fs::read(&tool).unwrap())),
        pin
    );
    for length in [
        512,
        CLUSTER_BYTES + 512,
        3 * CLUSTER_BYTES,
        CLUSTER_BYTES * TABLE_ENTRIES + 512,
        32761 * CLUSTER_BYTES,
    ] {
        let geometry = Geometry::new(length).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let qcow_path = directory.path().join("disk.qcow2");
        let decoded_path = directory.path().join("decoded.raw");
        let mut source_hash = Sha256::new();
        let mut remaining = length;
        let buffer = vec![0x71; 64 * 1024];
        while remaining != 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
            source_hash.update(&buffer[..take]);
            remaining -= take as u64;
        }
        let raw_sha256: [u8; 32] = source_hash.finalize().into();
        let mut source = io::repeat(0x71).take(length);
        let mut file = fs::File::create(&qcow_path).unwrap();
        let written = geometry
            .write(
                &mut source,
                raw_sha256,
                &mut file,
                &budget(geometry.encoded_bytes()),
                || false,
            )
            .unwrap();
        file.flush().unwrap();
        for arguments in [
            vec!["check", "-f", "qcow2"],
            vec!["info", "--output=json", "-f", "qcow2"],
        ] {
            let result = Command::new(&tool)
                .args(arguments)
                .arg(&qcow_path)
                .output()
                .unwrap();
            assert!(result.status.success(), "{result:?}");
        }
        let result = Command::new(&tool)
            .args(["convert", "-f", "qcow2", "-O", "raw"])
            .arg(&qcow_path)
            .arg(&decoded_path)
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        assert_eq!(fs::metadata(&decoded_path).unwrap().len(), length);
        let mut decoded = fs::File::open(&decoded_path).unwrap();
        let mut hash = Sha256::new();
        let mut buffer = vec![0; 64 * 1024];
        loop {
            let read = decoded.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
        assert_eq!(<[u8; 32]>::from(hash.finalize()), raw_sha256);
        let mut encoded = fs::File::open(&qcow_path).unwrap();
        let mut hash = Sha256::new();
        loop {
            let read = encoded.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
        assert_eq!(<[u8; 32]>::from(hash.finalize()), written.sha256);
    }
}
