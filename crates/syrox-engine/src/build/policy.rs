/// Linux `x86_64` cBPF, applied by setpriv after namespace construction. Reject
/// other ABIs (including x32), networking, namespace changes, kernel control,
/// tracing, keyrings and asynchronous kernel interfaces. Ordinary file/compile
/// syscalls remain allowed; Landlock independently restricts the filesystem.
pub(crate) fn seccomp_filter() -> Vec<u8> {
    let mut instructions: Vec<(u16, u8, u8, u32)> = vec![
        (0x20, 0, 0, 4), // architecture
        (0x15, 1, 0, 0xc000_003e),
        (0x06, 0, 0, 0x8000_0000), // kill non-x86_64
        (0x20, 0, 0, 0),
        (0x45, 0, 1, 0x4000_0000), // x32
        (0x06, 0, 0, 0x8000_0000),
    ];
    // clone3 must return ENOSYS so libc can fall back to clone for threads.
    instructions.extend([
        (0x15, 0, 1, 435),
        (0x06, 0, 0, 0x0005_0026),
    ]);
    // clone is allowed only without new namespace flags.
    instructions.extend([
        (0x15, 0, 4, 56),
        (0x20, 0, 0, 16),
        (0x45, 0, 1, 0x7e02_0000),
        (0x06, 0, 0, 0x0005_0001),
        (0x20, 0, 0, 0),
    ]);
    for number in [
        41, 42, 43, 44, 45, 49, 50, 53, // sockets
        101, 155, 161, 165, 166, 167, 168, 169, 172, 173, 175, 176, 246, 248, 249, 250, 272, 298,
        300, 303, 304, 308, 310, 311, 313, 321, 323, 425, 426, 427, 428, 429, 430, 431, 432, 433,
        438, 440, 442, // mount, pidfd_getfd, quotas
    ] {
        instructions.extend([
            (0x15, 0, 1, number),
            (0x06, 0, 0, 0x0005_0001),
        ]);
    }
    instructions.push((0x06, 0, 0, 0x7fff_0000));
    let mut bytes = Vec::new();
    for (code, jt, jf, k) in instructions {
        bytes.extend_from_slice(&code.to_le_bytes());
        bytes.extend_from_slice(&[jt, jf]);
        bytes.extend_from_slice(&k.to_le_bytes());
    }
    bytes
}
