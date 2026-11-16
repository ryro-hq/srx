use super::*;
use std::io::{Seek as _, SeekFrom, Write as _};

fn executable() -> Vec<u8> {
    let mut bytes = vec![0; 128];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x40_0078_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x40_0000_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&128_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&128_u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
    bytes
}

fn source(bytes: &[u8]) -> (tempfile::NamedTempFile, File, ToolPin) {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    let readonly = File::open(file.path()).unwrap();
    let pin = ToolPin {
        sha256: Sha256::digest(bytes).into(),
        size_bytes: bytes.len() as u64,
    };
    (file, readonly, pin)
}

#[test]
fn snapshot_preserves_exact_pin_independently_of_source_position_and_replacement() {
    let bytes = executable();
    let (mut original, mut source, pin) = source(&bytes);
    source.seek(SeekFrom::Start(75)).unwrap();
    let mut same_description = source.try_clone().unwrap();
    let tool = PinnedTool::snapshot(source, pin, || Ok(())).unwrap();
    assert_eq!(same_description.stream_position().unwrap(), 75);
    original.as_file_mut().rewind().unwrap();
    original.write_all(&[0; 128]).unwrap();
    original.close().unwrap();
    assert_eq!(tool.pin(), pin);
    let fd = tool.descriptor().unwrap();
    let file = File::from(fd.try_clone_to_owned().unwrap());
    let mut actual = [0; 128];
    file.read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(actual.as_slice(), bytes);
    assert!(file.set_len(0).is_err());
    // SAFETY: fcntl only observes the flags and seals of this live descriptor.
    unsafe {
        assert_ne!(
            libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC,
            0
        );
        assert_eq!(
            libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) & SEALS,
            SEALS
        );
    }
    assert!(
        file.set_permissions(std::fs::Permissions::from_mode(0o444))
            .is_err()
    );
    // Read bits remain mutable; validation catches changes despite frozen exec bits.
    file.set_permissions(std::fs::Permissions::from_mode(0o111))
        .unwrap();
    assert!(tool.descriptor().is_err());
    file.set_permissions(std::fs::Permissions::from_mode(0o555))
        .unwrap();
    tool.descriptor().unwrap();
}

#[test]
fn pin_admission_rejects_wrong_content_length_access_and_interrupted_preparation() {
    let (original, file, pin) = source(&executable());
    let mut wrong = pin;
    wrong.sha256[0] ^= 1;
    assert!(PinnedTool::snapshot(file.try_clone().unwrap(), wrong, || Ok(())).is_err());
    for bytes in [
        0,
        63,
        pin.size_bytes - 1,
        pin.size_bytes + 1,
        MAX_TOOL_BYTES + 1,
        u64::MAX,
    ] {
        assert!(
            PinnedTool::snapshot(
                file.try_clone().unwrap(),
                ToolPin {
                    size_bytes: bytes,
                    ..pin
                },
                || Ok(())
            )
            .is_err()
        );
    }
    assert!(PinnedTool::snapshot(original.reopen().unwrap(), pin, || Ok(())).is_err());
    let mut checks = 0;
    let error = PinnedTool::snapshot(file.try_clone().unwrap(), pin, || {
        checks += 1;
        if checks == 3 {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(checks, 3);
    for length in [64, 129] {
        original.as_file().set_len(128).unwrap();
        original
            .as_file()
            .write_all_at(&executable(), 0)
            .unwrap();
        let mut checks = 0;
        assert!(
            PinnedTool::snapshot(file.try_clone().unwrap(), pin, || {
                checks += 1;
                if checks == 2 {
                    original.as_file().set_len(length)?;
                }
                Ok(())
            })
            .is_err()
        );
    }
}

#[test]
fn narrow_static_contract_refuses_dynamic_interpreters_bad_ranges_and_executable_writes() {
    let mutations: &[fn(&mut Vec<u8>)] = &[
        |b| b[0] = 0,
        |b| b[4] = 1,
        |b| b[5] = 2,
        |b| b[7] = 9,
        |b| b[8] = 1,
        |b| b[16] = 3,
        |b| b[18] = 3,
        |b| b[20] = 2,
        |b| b[48] = 1,
        |b| b[52] = 0,
        |b| b[54] = 0,
        |b| b[56] = 0,
        |b| b[56..58].copy_from_slice(&129_u16.to_le_bytes()),
        |b| b[32..40].copy_from_slice(&u64::MAX.to_le_bytes()),
        |b| b[24..32].copy_from_slice(&u64::MAX.to_le_bytes()),
        |b| b[64] = 2,
        |b| b[64] = 3,
        |b| b[68] = 7,
        |b| b[96..104].copy_from_slice(&129_u64.to_le_bytes()),
        |b| b[104..112].copy_from_slice(&64_u64.to_le_bytes()),
        |b| b[112..120].copy_from_slice(&3_u64.to_le_bytes()),
        |b| b[72..80].copy_from_slice(&1_u64.to_le_bytes()),
        |b| b[80..88].copy_from_slice(&(u64::MAX - 127).to_le_bytes()),
        |b| {
            b[64..68].copy_from_slice(&0x6474_e551_u32.to_le_bytes());
            b[68] = 7;
        },
    ];
    for mutate in mutations {
        let mut bytes = executable();
        mutate(&mut bytes);
        let (_original, source, pin) = source(&bytes);
        assert_eq!(
            PinnedTool::snapshot(source, pin, || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
