use super::*;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn uapi_layout_and_zero_initialized_scratch_configuration_match_linux() {
    assert_eq!(size_of::<LoopInfo>(), 232);
    assert_eq!(std::mem::offset_of!(LoopInfo, flags), 52);
    assert_eq!(std::mem::offset_of!(LoopInfo, file_name), 56);
    assert_eq!(std::mem::offset_of!(LoopInfo, init), 216);
    assert_eq!(size_of::<LoopConfig>(), 304);
    // Kernel new_encode_dev, including minor bits above the old 8-bit range.
    for (major, minor, expected) in [
        (8, 1, 0x801),
        (259, 0x12345, 0x1231_0345),
        (0xfff, 0xfffff, u32::MAX),
    ] {
        assert_eq!(
            abi::encode_device(libc::makedev(major, minor)),
            u64::from(expected)
        );
    }
    let file = tempfile::tempfile().unwrap();
    let config = LoopConfig::scratch(file.as_fd(), 4096).unwrap();
    // ABI input is inspected as bytes only after every field was initialized.
    // SAFETY: config is initialized, has no uninitialized padding on x86_64 and
    // remains borrowed for the lifetime of this exact-sized byte slice.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&raw const config).cast::<u8>(),
            size_of::<LoopConfig>(),
        )
    };
    let mut expected = [0_u8; 304];
    expected[..4].copy_from_slice(
        &u32::try_from(file.as_raw_fd())
            .unwrap()
            .to_ne_bytes(),
    );
    expected[4..8].copy_from_slice(&4096_u32.to_ne_bytes());
    expected[40..48].copy_from_slice(&4096_u64.to_ne_bytes());
    expected[60..64].copy_from_slice(&AUTOCLEAR.to_ne_bytes());
    assert_eq!(bytes, expected);
}

#[test]
fn binding_verification_rejects_each_changed_identity_geometry_and_feature() {
    let identity = ImageIdentity {
        device: libc::makedev(259, 0x12345),
        inode: 27,
        bytes: 64 * 1024 * 1024,
    };
    // SAFETY: all-zero is valid for this integer/array-only UAPI structure.
    let mut info: LoopInfo = unsafe { std::mem::zeroed() };
    info.device = abi::encode_device(identity.device);
    info.inode = identity.inode;
    info.number = 37;
    info.size_limit = identity.bytes;
    info.flags = AUTOCLEAR;
    verify_binding(&info, 37, identity).unwrap();
    let mutations: &[fn(&mut LoopInfo)] = &[
        |i| i.device ^= 1,
        |i| i.inode += 1,
        |i| i.number += 1,
        |i| i.rdevice = 1,
        |i| i.offset = 4096,
        |i| i.size_limit -= 4096,
        |i| i.flags = 0,
        |i| i.flags |= 1,
        |i| i.flags |= 8,
        |i| i.flags |= 16,
        |i| i.encrypt_type = 1,
        |i| i.encrypt_key_size = 1,
        |i| i.file_name[0] = b'x',
        |i| i.crypt_name[0] = b'x',
        |i| i.encrypt_key[0] = 1,
        |i| i.init[0] = 1,
    ];
    for mutate in mutations {
        let mut changed = info;
        mutate(&mut changed);
        assert!(verify_binding(&changed, 37, identity).is_err());
    }
}

#[test]
fn non_device_descriptors_are_refused_before_any_device_ioctl() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("image");
    let image = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    image
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    image.set_len(4096).unwrap();
    assert!(LoopControl::from_file(image.try_clone().unwrap()).is_err());
    assert!(
        ScratchLoop::prepare(
            image.try_clone().unwrap(),
            0,
            image.try_clone().unwrap(),
            4096
        )
        .is_err()
    );
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    assert!(LoopControl::from_file(null.try_clone().unwrap()).is_err());
    assert!(ScratchLoop::prepare(null, 0, image.try_clone().unwrap(), 4096).is_err());
    for bytes in [0, 1, 4095, 4097, u64::MAX] {
        assert!(image_identity(&image, bytes).is_err());
    }
    assert!(image_identity(&File::open(&path).unwrap(), 4096).is_err());
    require_readwrite(image.as_fd()).unwrap();
    image
        .set_permissions(std::fs::Permissions::from_mode(0o666))
        .unwrap();
    assert!(image_identity(&image, 4096).is_err());
    image
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    std::fs::hard_link(&path, directory.path().join("alias")).unwrap();
    assert!(image_identity(&image, 4096).is_err());
    assert!(image_identity(&image, 8192).is_err());
    // This file is intentionally unprivileged; no loop devices are opened here.
}
