use super::*;

#[test]
fn geometry_rounds_down_and_never_exceeds_inode_ceiling() {
    for bytes in [
        64 << 20,
        128 << 20,
        (128 << 20) + 4096,
        1 << 30,
        128 << 30,
    ] {
        for ceiling in [16, 511, 512, 1000, 65_537, u64::MAX] {
            let granularity = (bytes / 4096_u64).div_ceil(32768) * 16;
            match Geometry::new(bytes, ceiling) {
                Ok(value) => {
                    assert_eq!(value.bytes, bytes);
                    assert!(value.inodes <= ceiling.min(u64::from(u32::MAX)));
                    assert!(value.inodes >= granularity);
                    assert!(value.inodes.is_multiple_of(granularity));
                }
                Err(_) => assert!(ceiling < granularity),
            }
        }
    }
    for bytes in [
        0,
        4096,
        (64 << 20) - 4096,
        (64 << 20) + 1,
        (128 << 30) + 4096,
        u64::MAX,
    ] {
        assert!(Geometry::new(bytes, 512).is_err());
    }
    assert!(Geometry::new(64 << 20, 0).is_err());
}

// Interpret the small BPF subset used by the production filter, checking real
// branch targets and both halves of 64-bit syscall arguments without installing
// seccomp in the test harness. Actual installation belongs to the guest probe.
fn decision(arch: u32, syscall: i64, args: [u64; 6]) -> u32 {
    let filter = policy::filter();
    let mut data = [0_u8; 64];
    data[..4].copy_from_slice(&i32::try_from(syscall).unwrap().to_ne_bytes());
    data[4..8].copy_from_slice(&arch.to_ne_bytes());
    for (index, value) in args.iter().enumerate() {
        data[16 + index * 8..24 + index * 8].copy_from_slice(&value.to_ne_bytes());
    }
    let mut pc = 0;
    let mut accumulator = 0;
    for _ in 0..=filter.len() {
        let instruction = &filter[pc];
        match instruction.code {
            0x20 => {
                let offset = instruction.k as usize;
                accumulator = u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap());
            }
            0x15 => {
                pc += usize::from(if accumulator == instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                });
            }
            0x06 => return instruction.k,
            _ => panic!("unsupported BPF instruction"),
        }
        pc += 1;
    }
    panic!("filter did not return")
}

#[test]
fn filter_denies_peer_authority_new_processes_and_unknown_abis() {
    const ARCH: u32 = 0xc000_003e;
    const ALLOW: u32 = 0x7fff_0000;
    const DENY: u32 = 0x0005_0001;
    for syscall in [
        libc::SYS_read,
        libc::SYS_openat,
        libc::SYS_execve,
        libc::SYS_exit_group,
    ] {
        assert_eq!(decision(ARCH, syscall, [0; 6]), ALLOW);
    }
    for syscall in [
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_pidfd_send_signal,
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_socket,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_fsopen,
        libc::SYS_quotactl,
        libc::SYS_quotactl_fd,
        libc::SYS_io_uring_setup,
        libc::SYS_keyctl,
        libc::SYS_bpf,
        libc::SYS_setrlimit,
        libc::SYS_ioctl,
        libc::SYS_setuid,
        libc::SYS_capset,
        libc::SYS_seccomp,
        libc::SYS_memfd_create,
        9999,
    ] {
        assert_eq!(
            decision(ARCH, syscall, [0; 6]),
            DENY,
            "syscall {syscall}"
        );
    }
    assert_eq!(
        decision(ARCH, libc::SYS_read | 0x4000_0000, [0; 6]),
        DENY
    );
    assert_eq!(
        decision(0x4000_0003, libc::SYS_read, [0; 6]),
        0x8000_0000
    );
    assert_eq!(decision(ARCH, libc::SYS_prlimit64, [0; 6]), ALLOW);
    for (index, value) in [
        (0, 1),
        (0, 1 << 32),
        (2, 1),
        (2, 1 << 32),
        (2, u64::MAX),
    ] {
        let mut args = [0; 6];
        args[index] = value;
        assert_eq!(decision(ARCH, libc::SYS_prlimit64, args), DENY);
    }
}

#[test]
fn invalid_image_is_refused_before_directory_effects() {
    let directory = tempfile::tempdir().unwrap();
    let image = tempfile::tempfile().unwrap();
    // Validation itself must reject unowned/non-private images before mount or
    // formatting; no actual root namespace or tool exec occurs in this test.
    assert!(
        validate(
            &image,
            &File::open(directory.path()).unwrap(),
            Operation::Check
        )
        .is_err()
    );
    assert!(!directory.path().join("tool-root").exists());
}

#[test]
#[ignore = "spawned only by collector tests with an explicit fixture mode"]
fn collector_child() {
    use std::io::Write as _;
    match std::env::var("SRX_EXT4_COLLECTOR_CASE")
        .unwrap()
        .as_str()
    {
        "kernel-filter" => kernel_filter_probe(),
        "bounded" => {
            io::stdout().write_all(b"SRX_OUT").unwrap();
            io::stderr().write_all(b"SRX_ERR").unwrap();
        }
        "overflow" => loop {
            let _ = io::stdout().write_all(&[b'x'; 8192]);
        },
        "cancel" => loop {
            std::thread::sleep(Duration::from_millis(20));
        },
        _ => panic!("unknown collector fixture"),
    }
}

fn kernel_filter_probe() {
    let mut filter = policy::filter();
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).unwrap(),
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        // SAFETY: this test runs only in a spawned child. The filter affects this
        // thread, grants no privilege and cannot modify the parent test process.
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    // SAFETY: initialized bounded BPF storage remains live during installation.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1_u32,
            0_u32,
            &raw const program,
        )
    };
    assert_eq!(
        result,
        0,
        "seccomp installation: {}",
        io::Error::last_os_error()
    );
    // SAFETY: signal zero observes permissions without sending a signal.
    assert_eq!(unsafe { libc::kill(libc::getppid(), 0) }, -1);
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    println!("SRX_EXT4_KERNEL_FILTER_OK");
}

#[test]
fn kernel_accepts_filter_in_unprivileged_child() {
    let output = collect(
        collector_fixture("kernel-filter"),
        Instant::now(),
        &mut || Ok(()),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("SRX_EXT4_KERNEL_FILTER_OK"));
}

#[test]
#[ignore = "requires explicit SRX_TOOL_STARTUP_EXECUTABLE and SRX_TOOL_STARTUP_SHA256"]
fn filter_permits_pinned_static_rust_startup() {
    use sha2::{Digest as _, Sha256};
    let path = std::env::var_os("SRX_TOOL_STARTUP_EXECUTABLE").expect("explicit executable");
    let expected = std::env::var("SRX_TOOL_STARTUP_SHA256").expect("explicit pin");
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.len() < 8 * 1024 * 1024);
    assert_eq!(crate::hex(&Sha256::digest(&bytes)), expected);
    assert_eq!(
        u16::from_le_bytes(bytes[16..18].try_into().unwrap()),
        2
    );
    let filter = policy::filter();
    let length = u16::try_from(filter.len()).unwrap();
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("SRX_TOOL_STARTUP_PROBE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the prepared filter is immutable. Only fixed prctl/seccomp calls
    // and stack storage execute between fork and exec; no parent state changes.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            let program = libc::sock_fprog {
                len: length,
                filter: filter.as_ptr().cast_mut(),
            };
            if libc::syscall(
                libc::SYS_seccomp,
                1_u32,
                0_u32,
                &raw const program,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = collect(
        command.spawn().unwrap(),
        Instant::now(),
        &mut || Ok(()),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"SRX_TOOL_STARTUP_OK\n");
}

fn collector_fixture(mode: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "ext4_tool::tests::collector_child",
            "--ignored",
            "--nocapture",
        ])
        .env("SRX_EXT4_COLLECTOR_CASE", mode)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn collector_bounds_both_streams_and_reaps_on_overflow_and_cancellation() {
    let output = collect(
        collector_fixture("bounded"),
        Instant::now(),
        &mut || Ok(()),
    )
    .unwrap();
    assert!(output.status.success());
    assert!(
        output
            .stdout
            .windows(7)
            .any(|bytes| bytes == b"SRX_OUT")
    );
    assert!(
        output
            .stderr
            .windows(7)
            .any(|bytes| bytes == b"SRX_ERR")
    );
    for mode in ["overflow", "cancel", "timeout"] {
        let child = collector_fixture(if mode == "timeout" {
            "cancel"
        } else {
            mode
        });
        let pid = i32::try_from(child.id()).unwrap();
        let mut check = || {
            if mode == "cancel" {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            }
        };
        let start = if mode == "timeout" {
            Instant::now().checked_sub(TIMEOUT).unwrap()
        } else {
            Instant::now()
        };
        let error = collect(child, start, &mut check).unwrap_err();
        assert_eq!(
            error.kind(),
            match mode {
                "cancel" => io::ErrorKind::Interrupted,
                "timeout" => io::ErrorKind::TimedOut,
                _ => io::ErrorKind::InvalidInput,
            }
        );
        assert_eq!(
            // SAFETY: WNOHANG query of this fixture's child; no signal or other PID.
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}
