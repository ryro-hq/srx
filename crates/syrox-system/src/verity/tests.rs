use super::*;
use std::fmt::Write as _;
use std::io::Cursor;

fn hexadecimal(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}

#[test]
fn two_level_golden_matches_pinned_veritysetup_2_8_8() {
    // Independent upstream output for 129 zero blocks, v1/SHA-256/4KiB,
    // no superblock and explicit salt 0x23 repeated 32 times.
    let bytes = vec![0; 129 * BLOCK_BYTES];
    let mut bottom = Vec::new();
    let first = write_level(
        &mut Cursor::new(&bytes),
        bytes.len() as u64,
        Sha256::digest(&bytes).into(),
        &[0x23; 32],
        &mut bottom,
        || false,
    )
    .unwrap();
    let mut top = Vec::new();
    let final_level = write_level(
        &mut Cursor::new(&bottom),
        bottom.len() as u64,
        first.sha256,
        &[0x23; 32],
        &mut top,
        || false,
    )
    .unwrap();
    let root = hexadecimal(&final_level.root_hash.unwrap());
    assert_eq!(
        root,
        "174aa0c2dfe859b1481e6e6c1c8325a626fe4bac39c3903f5664096736667953"
    );
    top.extend_from_slice(&bottom);
    assert_eq!(
        crate::hex(&Sha256::digest(&top)),
        "1ee5d2bfdb6818d7ffc72bd5765eceb96cf510655bf84a17cf31a228aefd881b"
    );
}

#[test]
fn geometry_handles_level_boundaries_without_overflow_or_extra_single_block_level() {
    for (blocks, levels) in [
        (1, vec![]),
        (2, vec![1]),
        (128, vec![1]),
        (129, vec![2, 1]),
        (16384, vec![128, 1]),
        (16385, vec![129, 2, 1]),
    ] {
        let geometry = Geometry::new(blocks * BLOCK_BYTES as u64).unwrap();
        assert_eq!(geometry.level_blocks(), levels);
        assert_eq!(
            geometry.hash_bytes(),
            levels.iter().sum::<u64>() * BLOCK_BYTES as u64
        );
    }
    assert!(Geometry::new(0).is_err());
    assert!(Geometry::new(4095).is_err());
    let maximum = u64::MAX / BLOCK_BYTES as u64 * BLOCK_BYTES as u64;
    assert!(Geometry::new(maximum).unwrap().hash_bytes() < maximum);
}

#[test]
fn exact_input_identity_eof_and_cancellation_are_mandatory() {
    let data = vec![7; BLOCK_BYTES * 2];
    let pin = Sha256::digest(&data).into();
    for bytes in [
        &data[..data.len() - 1],
        &[data.as_slice(), &[0]].concat(),
        &vec![8; data.len()],
    ] {
        assert!(matches!(
            write_level(
                &mut Cursor::new(bytes),
                data.len() as u64,
                pin,
                &[0; 32],
                &mut Vec::new(),
                || false
            ),
            Err(VerityError::Content)
        ));
    }
    let mut output = Vec::new();
    assert!(matches!(
        write_level(
            &mut Cursor::new(&data),
            data.len() as u64,
            pin,
            &[0; 32],
            &mut output,
            || true
        ),
        Err(VerityError::Cancelled)
    ));
    assert!(output.is_empty());
    let mut checks = 0;
    assert!(matches!(
        write_level(
            &mut Cursor::new(&data),
            data.len() as u64,
            pin,
            &[0; 32],
            &mut output,
            || {
                checks += 1;
                checks == 3
            }
        ),
        Err(VerityError::Cancelled)
    ));
    assert!(output.is_empty());
}

#[test]
fn single_data_block_has_no_hash_device_and_short_readers_never_request_large_buffers() {
    struct Short(Cursor<Vec<u8>>);
    impl Read for Short {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(buffer.len() <= BLOCK_BYTES);
            let length = buffer.len().min(17);
            self.0.read(&mut buffer[..length])
        }
    }
    let data = vec![0x71; BLOCK_BYTES];
    let pin = Sha256::digest(&data).into();
    let mut output = Vec::new();
    let written = write_level(
        &mut Short(Cursor::new(data)),
        BLOCK_BYTES as u64,
        pin,
        &[0x23; 32],
        &mut output,
        || false,
    )
    .unwrap();
    assert_eq!(written.bytes, 0);
    assert!(written.root_hash.is_some());
    assert!(output.is_empty());
}

#[test]
#[ignore = "requires explicitly pinned SRX_VERITYSETUP and SRX_VERITYSETUP_SHA256; formats/verifies disposable regular images only"]
fn upstream_veritysetup_accepts_byte_identical_trees_and_rejects_corruption() {
    use std::{
        fs,
        io::{Seek as _, Write as _},
        process::Command,
    };
    let tool = std::env::var("SRX_VERITYSETUP").expect("select a reference executable");
    let pin = std::env::var("SRX_VERITYSETUP_SHA256").expect("pin the reference executable");
    let metadata = fs::symlink_metadata(&tool).unwrap();
    assert!(metadata.is_file() && metadata.len() <= 16 * 1024 * 1024);
    assert_eq!(
        crate::hex(&Sha256::digest(fs::read(&tool).unwrap())),
        pin
    );
    let salt = [0x23; 32];
    let salt_text = "23".repeat(32);
    for blocks in [1_u64, 2, 127, 128, 129, 16384, 16385] {
        let directory = tempfile::tempdir().unwrap();
        let data_path = directory.path().join("data.raw");
        let reference = directory.path().join("upstream.hash");
        let ours = directory.path().join("srx.hash");
        let root_path = directory.path().join("root.txt");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&data_path)
            .unwrap();
        let mut digest = Sha256::new();
        for block in 0..blocks {
            let mut bytes = [0; BLOCK_BYTES];
            for (index, value) in bytes.iter_mut().enumerate() {
                *value = block
                    .wrapping_mul(37)
                    .wrapping_add(index as u64)
                    .to_le_bytes()[0];
            }
            file.write_all(&bytes).unwrap();
            digest.update(bytes);
        }
        file.rewind().unwrap();
        let mut input: Box<dyn Read> = Box::new(file);
        let mut input_pin = digest.finalize().into();
        let mut input_bytes = blocks * BLOCK_BYTES as u64;
        let mut levels = Vec::new();
        let root = loop {
            let mut output = Vec::new();
            let written = write_level(
                &mut input,
                input_bytes,
                input_pin,
                &salt,
                &mut output,
                || false,
            )
            .unwrap();
            input_pin = written.sha256;
            input_bytes = written.bytes;
            levels.push(output.clone());
            if let Some(root) = written.root_hash {
                break root;
            }
            input = Box::new(Cursor::new(output));
        };
        let hash_bytes: Vec<u8> = levels.into_iter().rev().flatten().collect();
        assert_eq!(
            hash_bytes.len() as u64,
            Geometry::new(blocks * BLOCK_BYTES as u64)
                .unwrap()
                .hash_bytes()
        );
        fs::write(&ours, &hash_bytes).unwrap();
        let options = [
            "--no-superblock",
            "--format=1",
            "--hash=sha256",
            "--data-block-size=4096",
            "--hash-block-size=4096",
        ];
        let format = Command::new(&tool)
            .args(options)
            .arg(format!("--salt={salt_text}"))
            .arg(format!("--data-blocks={blocks}"))
            .arg("--root-hash-file")
            .arg(&root_path)
            .arg("format")
            .arg(&data_path)
            .arg(&reference)
            .output()
            .unwrap();
        assert!(
            format.status.success(),
            "{}",
            String::from_utf8_lossy(&format.stderr)
        );
        assert!(
            fs::read(&reference).unwrap() == hash_bytes,
            "hash device differs for {blocks} blocks"
        );
        let root_text = hexadecimal(&root);
        assert_eq!(
            fs::read_to_string(&root_path).unwrap().trim(),
            root_text
        );
        let verify = || {
            Command::new(&tool)
                .args(options)
                .arg(format!("--salt={salt_text}"))
                .arg(format!("--data-blocks={blocks}"))
                .arg("verify")
                .arg(&data_path)
                .arg(&ours)
                .arg(&root_text)
                .output()
                .unwrap()
        };
        let verified = verify();
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
        let mut data = fs::OpenOptions::new()
            .write(true)
            .open(&data_path)
            .unwrap();
        data.write_all(&[0xff]).unwrap();
        assert!(!verify().status.success());
        data.rewind().unwrap();
        data.write_all(&[0]).unwrap();
        if !hash_bytes.is_empty() {
            let mut damaged = hash_bytes;
            damaged[0] ^= 1;
            fs::write(&ours, damaged).unwrap();
            assert!(!verify().status.success());
        }
    }
}
