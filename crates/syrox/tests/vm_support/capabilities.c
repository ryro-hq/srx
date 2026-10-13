#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    int failed = getuid() == 0;
    if (failed) { fprintf(stderr, "non-root probe required\n"); }
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, 1);
    int landlock_errno = abi < 0 ? errno : 0;
    if (abi < 6) { fprintf(stderr, "Landlock ABI >=6 required: %ld errno=%d\n", abi, landlock_errno); failed = 1; }
    int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    struct statfs info;
    int pidfs = pidfd >= 0 && fstatfs(pidfd, &info) == 0 && info.f_type == 0x50494446;
    if (!pidfs) {
        fprintf(stderr, "unique pidfs required, errno=%d\n", errno); failed = 1;
    }
    printf("{\"uid\":%u,\"landlock_abi\":%ld,\"landlock_errno\":%d,\"pidfs\":%s,\"namespace_ioctls\":[", getuid(), abi, landlock_errno, pidfs ? "true" : "false");
    const unsigned long requests[] = {0xff03, 0xff05, 0xff09};
    for (unsigned int i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i) {
        int ns = pidfd < 0 ? -1 : ioctl(pidfd, requests[i], 0);
        int error = ns < 0 ? errno : 0;
        int valid = ns >= 0 && fstatfs(ns, &info) == 0 && info.f_type == 0x6e736673;
        printf("%s{\"request\":%lu,\"available\":%s,\"errno\":%d}", i ? "," : "", requests[i], valid ? "true" : "false", error);
        if (!valid) { failed = 1; }
        if (ns >= 0) { close(ns); }
    }
    if (pidfd >= 0) { close(pidfd); }
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    int pty = master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0;
    char *slave = pty ? ptsname(master) : NULL;
    int fd = slave ? open(slave, O_RDWR | O_NOCTTY) : -1;
    pty = fd >= 0 && isatty(fd);
    if (fd >= 0) { close(fd); }
    if (master >= 0) { close(master); }
    if (!pty) { failed = 1; }
    printf("],\"pty\":%s,\"passed\":%s}\n", pty ? "true" : "false", failed ? "false" : "true");
    return failed;
}
