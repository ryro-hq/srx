// Fixed x86_64 BPF allowlist. Unknown syscalls (including new kernel APIs) get
// EPERM, alternate architectures are killed, and x32 numbers cannot match.
// No clone/fork/vfork, signals to peers, ptrace/process_vm, sockets, namespaces,
// mounts, keyring, bpf, io_uring, quota, credentials or resource-limit mutations.
pub(super) fn filter() -> Vec<libc::sock_filter> {
    let mut code = vec![
        instruction(0x20, 0, 0, 4), // seccomp_data.arch
        instruction(0x15, 1, 0, 0xc000_003e),
        instruction(0x06, 0, 0, 0x8000_0000), // KILL_PROCESS
        instruction(0x20, 0, 0, 0),           // seccomp_data.nr
    ];
    for syscall in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_preadv2,
        libc::SYS_pwritev2,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_arch_prctl,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_futex,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        libc::SYS_time,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_getgroups,
        libc::SYS_capget,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getrlimit,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_getcwd,
        libc::SYS_getdents64,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_ftruncate,
        libc::SYS_fallocate,
        libc::SYS_umask,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_yield,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        code.push(instruction(
            0x15,
            0,
            1,
            u32::try_from(syscall).unwrap(),
        ));
        code.push(instruction(0x06, 0, 0, 0x7fff_0000)); // ALLOW
    }
    // Glibc uses prlimit64(0, resource, NULL, &old) for getrlimit. Permit
    // read-only self queries, never another PID or a new resource limit.
    code.push(instruction(
        0x15,
        0,
        8,
        u32::try_from(libc::SYS_prlimit64).unwrap(),
    ));
    code.extend([
        instruction(0x20, 0, 0, 16), // args[0] pid, low and high
        instruction(0x15, 0, 6, 0),
        instruction(0x20, 0, 0, 20),
        instruction(0x15, 0, 4, 0),
        instruction(0x20, 0, 0, 32), // args[2] new_limit, low and high
        instruction(0x15, 0, 2, 0),
        instruction(0x20, 0, 0, 36),
        instruction(0x15, 1, 0, 0),
    ]);
    code.push(instruction(0x06, 0, 0, 0x0005_0001)); // ERRNO EPERM
    code.push(instruction(0x06, 0, 0, 0x7fff_0000));
    code
}

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt,
        jf,
        k,
    }
}
