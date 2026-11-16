use super::*;
use crate::budget::{AdmittedBudget, BuildBudget, BuilderLimits};
use sha2::{Digest as _, Sha256};
use std::io::{Cursor, Read, Write};

fn budget(bytes: u64) -> AdmittedBudget {
    let request = BuildBudget {
        memory_bytes: 32 * 1024 * 1024,
        cpu_percent: 100,
        processes: 8,
        descriptors: 32,
        scratch_bytes: 1024 * 1024,
        files: 256,
        output_bytes: bytes,
        duration_seconds: 60,
    };
    BuilderLimits::new(request)
        .unwrap()
        .admit(request)
        .unwrap()
}

pub(super) fn fixture(block: u32) -> (DiskSpec, Sources) {
    // Canonical 00112233-4455-6677-8899-aabbccddeeff exercises mixed endianness.
    let guid = Guid([
        0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    let payload = b"a verified partition image".to_vec();
    let partition = Partition {
        number: 2,
        partition_type: Guid([0x11; 16]),
        guid: Guid([0x22; 16]),
        start_bytes: 1024 * 1024,
        size_bytes: 1024 * 1024,
        name: "root-α".into(),
        attributes: 1_u64 << 60,
        image_bytes: payload.len() as u64,
        image_sha256: Sha256::digest(&payload).into(),
    };
    (
        DiskSpec {
            bytes: 4 * 1024 * 1024,
            logical_block_bytes: block,
            guid,
            partitions: vec![partition],
        },
        Sources {
            payload,
            opens: vec![],
        },
    )
}

pub(super) struct Sources {
    payload: Vec<u8>,
    opens: Vec<u32>,
}
impl PartitionReader for Sources {
    fn open_partition(&mut self, number: u32) -> io::Result<Box<dyn Read + '_>> {
        self.opens.push(number);
        Ok(Box::new(Cursor::new(&self.payload)))
    }
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[test]
fn complete_images_have_consistent_primary_backup_guids_payload_padding_and_digest() {
    assert_eq!(format::crc32(b"123456789"), 0xcbf4_3926);
    for block in [512, 4096] {
        let (spec, mut source) = fixture(block);
        let layout = spec.clone().validate().unwrap();
        let mut output = Vec::new();
        let written = layout
            .write_raw(
                &mut source,
                &mut output,
                &budget(spec.bytes),
                || false,
            )
            .unwrap();
        assert_eq!(written.bytes, spec.bytes);
        assert_eq!(
            written.sha256,
            <[u8; 32]>::from(Sha256::digest(&output))
        );
        assert_eq!(source.opens, [2]);
        assert_eq!(&output[510..512], &[0x55, 0xaa]);
        assert_eq!(output[450], 0xee);
        let block = block as usize;
        let last = output.len() / block - 1;
        for (current, alternate, table_lba) in [
            (1, last, 2),
            (last, 1, last - TABLE_BYTES / block),
        ] {
            let header = &output[current * block..(current + 1) * block];
            assert_eq!(&header[..8], b"EFI PART");
            assert_eq!(u64_at(header, 24), current as u64);
            assert_eq!(u64_at(header, 32), alternate as u64);
            assert_eq!(u64_at(header, 72), table_lba as u64);
            assert_eq!(
                &header[56..72],
                &[
                    0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff
                ]
            );
            let mut checked = header[..92].to_vec();
            checked[16..20].fill(0);
            assert_eq!(format::crc32(&checked), u32_at(header, 16));
            assert!(header[92..].iter().all(|byte| *byte == 0));
            let table = &output[table_lba * block..table_lba * block + TABLE_BYTES];
            assert_eq!(format::crc32(table), u32_at(header, 88));
            assert!(table[..ENTRY_BYTES].iter().all(|byte| *byte == 0));
            assert_eq!(
                u64_at(&table[ENTRY_BYTES..], 32),
                1024 * 1024 / block as u64
            );
        }
        assert_eq!(
            &output[2 * block..2 * block + TABLE_BYTES],
            &output[last * block - TABLE_BYTES..last * block]
        );
        let start = usize::try_from(spec.partitions[0].start_bytes).unwrap();
        assert_eq!(
            &output[start..start + source.payload.len()],
            &source.payload
        );
        assert!(
            output[start + source.payload.len()..last * block - TABLE_BYTES]
                .iter()
                .all(|byte| *byte == 0)
        );
        let mut again = Vec::new();
        layout
            .write_raw(
                &mut source,
                &mut again,
                &budget(spec.bytes),
                || false,
            )
            .unwrap();
        assert_eq!(Sha256::digest(&output), Sha256::digest(&again));
    }
}

#[test]
fn invalid_geometry_identity_names_attributes_and_payloads_never_become_layouts() {
    let (valid, _) = fixture(512);
    for field in 0..14 {
        let mut invalid = valid.clone();
        match field {
            0 => invalid.logical_block_bytes = 0,
            1 => invalid.bytes -= 1,
            2 => invalid.bytes = 512,
            3 => invalid.guid = Guid([0; 16]),
            4 => invalid.partitions[0].number = 0,
            5 => invalid.partitions[0].guid = valid.guid,
            6 => invalid.partitions[0].partition_type = Guid([0; 16]),
            7 => invalid.partitions[0].start_bytes = 512,
            8 => invalid.partitions[0].size_bytes = u64::MAX,
            9 => invalid.partitions[0].image_bytes = invalid.bytes,
            10 => invalid.partitions[0].name = "x".repeat(36),
            11 => invalid.partitions[0].attributes = 8,
            12 => invalid.partitions[0].name = "bad\0name".into(),
            _ => invalid
                .partitions
                .push(invalid.partitions[0].clone()),
        }
        assert!(
            invalid.validate().is_err(),
            "invalid field {field}"
        );
    }
    let mut overlap = valid.clone();
    let mut second = overlap.partitions[0].clone();
    second.number = 3;
    second.guid = Guid([0x33; 16]);
    overlap.partitions.push(second);
    assert!(overlap.validate().is_err());
}

#[test]
fn source_identity_eof_preflight_and_cancelled_io_prevent_success() {
    let (spec, source) = fixture(512);
    let layout = spec.clone().validate().unwrap();
    for payload in [
        source.payload[..source.payload.len() - 1].to_vec(),
        [source.payload.as_slice(), &[0]].concat(),
        vec![0; source.payload.len()],
    ] {
        let mut source = Sources {
            payload,
            opens: vec![],
        };
        assert!(matches!(
            layout.write_raw(
                &mut source,
                &mut Vec::new(),
                &budget(spec.bytes),
                || false
            ),
            Err(DiskError::Content(2))
        ));
    }
    let mut source = Sources {
        payload: vec![],
        opens: vec![],
    };
    let mut output = Vec::new();
    assert!(matches!(
        layout.write_raw(
            &mut source,
            &mut output,
            &budget(spec.bytes - 1),
            || false
        ),
        Err(DiskError::Budget(_))
    ));
    assert!(source.opens.is_empty() && output.is_empty());
    assert!(matches!(
        layout.write_raw(
            &mut source,
            &mut output,
            &budget(spec.bytes),
            || true
        ),
        Err(DiskError::Cancelled)
    ));
    assert!(source.opens.is_empty() && output.is_empty());
    let mut checks = 0;
    assert!(matches!(
        layout.write_raw(
            &mut source,
            &mut output,
            &budget(spec.bytes),
            || {
                checks += 1;
                checks == 7
            }
        ),
        Err(DiskError::Cancelled)
    ));
    assert!(!output.is_empty() && (output.len() as u64) < spec.partitions[0].start_bytes);
}

#[test]
fn entry_numbers_do_not_determine_physical_order_and_empty_images_are_verified() {
    let (mut spec, mut sources) = fixture(512);
    let mut second = spec.partitions[0].clone();
    second.number = 1;
    second.guid = Guid([0x33; 16]);
    second.start_bytes = 3 * 1024 * 1024;
    second.size_bytes = 4096;
    spec.partitions.push(second);
    let layout = spec.clone().validate().unwrap();
    assert_eq!(layout.specification().partitions[0].number, 1);
    let mut output = Vec::new();
    layout
        .write_raw(
            &mut sources,
            &mut output,
            &budget(spec.bytes),
            || false,
        )
        .unwrap();
    assert_eq!(sources.opens, [2, 1]);
    for start in [1024 * 1024, 3 * 1024 * 1024] {
        assert_eq!(
            &output[start..start + sources.payload.len()],
            &sources.payload
        );
    }
    sources.payload.clear();
    for partition in &mut spec.partitions {
        partition.image_bytes = 0;
        partition.image_sha256 = Sha256::digest([]).into();
    }
    output.clear();
    spec.clone()
        .validate()
        .unwrap()
        .write_raw(
            &mut sources,
            &mut output,
            &budget(spec.bytes),
            || false,
        )
        .unwrap();
    assert!(
        output[1024 * 1024..3 * 1024 * 1024 + 4096]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn short_io_remains_bounded_and_interrupted_reads_observe_cancellation() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct Bounded(Cursor<Vec<u8>>);
    impl Read for Bounded {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(buffer.len() <= 64 * 1024);
            let take = buffer.len().min(11);
            self.0.read(&mut buffer[..take])
        }
    }
    struct Reader(Vec<u8>);
    impl PartitionReader for Reader {
        fn open_partition(&mut self, _: u32) -> io::Result<Box<dyn Read + '_>> {
            Ok(Box::new(Bounded(Cursor::new(self.0.clone()))))
        }
    }
    #[derive(Default)]
    struct ShortOutput(Vec<u8>);
    impl Write for ShortOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            assert!(bytes.len() <= 64 * 1024);
            let take = bytes.len().min(1009);
            self.0.extend_from_slice(&bytes[..take]);
            Ok(take)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct Interrupted(Arc<AtomicBool>);
    impl Read for Interrupted {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0.store(true, Ordering::Relaxed);
            Err(io::Error::from(io::ErrorKind::Interrupted))
        }
    }
    impl PartitionReader for Interrupted {
        fn open_partition(&mut self, _: u32) -> io::Result<Box<dyn Read + '_>> {
            Ok(Box::new(Interrupted(Arc::clone(&self.0))))
        }
    }
    let (mut spec, _) = fixture(4096);
    let payload = vec![0x71; 70_001];
    spec.partitions[0].image_bytes = payload.len() as u64;
    spec.partitions[0].image_sha256 = Sha256::digest(&payload).into();
    let layout = spec.clone().validate().unwrap();
    let mut output = ShortOutput::default();
    let written = layout
        .write_raw(
            &mut Reader(payload),
            &mut output,
            &budget(spec.bytes),
            || false,
        )
        .unwrap();
    assert_eq!(
        written.sha256,
        <[u8; 32]>::from(Sha256::digest(&output.0))
    );
    let cancel = Arc::new(AtomicBool::new(false));
    assert!(matches!(
        layout.write_raw(
            &mut Interrupted(Arc::clone(&cancel)),
            &mut Vec::new(),
            &budget(spec.bytes),
            || cancel.load(Ordering::Relaxed)
        ),
        Err(DiskError::Cancelled)
    ));
}

#[test]
#[ignore = "requires explicitly pinned SRX_SFDISK and SRX_SFDISK_SHA256; only reads disposable regular images"]
fn util_linux_recognizes_both_logical_sector_sizes_and_recovers_the_backup_table() {
    use std::{fs, process::Command};
    let tool = std::env::var("SRX_SFDISK").expect("select a reference executable");
    let pin = std::env::var("SRX_SFDISK_SHA256").expect("pin the reference executable");
    let metadata = fs::symlink_metadata(&tool).unwrap();
    assert!(metadata.is_file() && metadata.len() <= 16 * 1024 * 1024);
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&tool).unwrap())),
        pin
    );
    for block in [512, 4096] {
        let (spec, mut sources) = fixture(block);
        let mut image = tempfile::NamedTempFile::new().unwrap();
        spec.clone()
            .validate()
            .unwrap()
            .write_raw(
                &mut sources,
                image.as_file_mut(),
                &budget(spec.bytes),
                || false,
            )
            .unwrap();
        for backup in [false, true] {
            if backup {
                use std::io::{Seek as _, SeekFrom};
                image
                    .as_file_mut()
                    .seek(SeekFrom::Start(u64::from(block)))
                    .unwrap();
                image
                    .as_file_mut()
                    .write_all(b"corrupt!")
                    .unwrap();
            }
            let before = fs::read(image.path()).unwrap();
            let result = Command::new(&tool)
                .args([
                    "--json",
                    "--sector-size",
                    &block.to_string(),
                ])
                .arg(image.path())
                .output()
                .unwrap();
            assert!(result.status.success(), "{result:?}");
            assert_eq!(
                Sha256::digest(&before),
                Sha256::digest(fs::read(image.path()).unwrap()),
                "the reference must not repair the image"
            );
            let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            let table = &json["partitiontable"];
            assert_eq!(table["label"], "gpt");
            assert_eq!(
                table["id"].as_str().unwrap().to_ascii_lowercase(),
                spec.guid.to_string()
            );
            assert_eq!(table["sectorsize"], block);
            assert_eq!(
                table["partitions"][0]["start"],
                spec.partitions[0].start_bytes / u64::from(block)
            );
            assert_eq!(
                table["partitions"][0]["size"],
                spec.partitions[0].size_bytes / u64::from(block)
            );
            assert_eq!(table["partitions"][0]["name"], "root-α");
        }
    }
}
