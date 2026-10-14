/* Controlled Linux payload, never a shell. Build with an explicit static compiler.
 * Protocol: stdout records begin SYROX_SESSION_V1; stderr contains diagnostics.
 * config PATH EXPECTED: APP_CONFIG must equal PATH; reads exact public bytes and
 *   requires a read-only mount. No host path or inherited PATH is permitted.
 * config-wait PATH EXPECTED WITNESS [UID GID]: validates config, forks a child holding
 *   WITNESS, then writes CONFIG_READY there. TERM/INT must reach both payload
 *   and child; writes CONFIG_TERM_REAPED only after reaping the child cleanly.
 *   Run inside a managed service namespace; the manager supplies the deadline.
 * managed UID GID: validates caller identity and managed filesystem, returns 37.
 * restart78 WITNESS RELEASE: numbered O_EXCL markers, per-attempt release, exit78.
 * state DIR EXPECTED: requires a private RW/nosuid/nodev/noexec state mount;
 *   validates counter (absent for EXPECTED=0), writes EXPECTED+1 and fsyncs.
 * secret PATH VERSION: validates sealed private RO/nosuid/nodev/noexec file;
 *   VERSION is 1 or 2 and selects fixed test bytes, never supplied in argv/logs.
 * child WITNESS: child locks existing WITNESS, prints READY, accepts "reap\n";
 *   kills/reaps child and proves its lock released. EOF deliberately fails.
 * orphan WITNESS: double-forked setsid descendant locks existing WITNESS and
 *   ignores TERM. After READY parent accepts "exit\n" then returns 37; namespace
 *   owner must kill/reap the orphan before releasing retention. RUN IN SANDBOX.
 * reaping WITNESS: orphan exits 23; live parent verifies ESRCH and witness
 *   release, proving namespace init collects it. RUN IN SANDBOX.
 * terminal EXPECTED ROWS COLS: READY includes initial size; driver resizes then
 *   writes EXPECTED plus newline. Checks literal input, final size and foreground.
 * terminal-devtty UID GID: checks managed identity/filesystem, redirects stdin to an EOF pipe, then opens kernel /dev/tty;
 *   verifies foreground/session identity and writes DEVTTY OK through that fd.
 * All records are flushed writes. No wall-clock sleeps are readiness evidence.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <termios.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int fail(const char *message) {
    fprintf(stderr, "SYROX_SESSION_V1 ERROR %s\n", message);
    return 1;
}
static int write_all(int fd, const void *buffer, size_t length) {
    const char *bytes = buffer;
    while (length) {
        ssize_t n = write(fd, bytes, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        bytes += n;
        length -= (size_t)n;
    }
    return 0;
}
static int record(const char *text) { return write_all(STDOUT_FILENO, text, strlen(text)); }
static int read_byte(int fd, char *byte) {
    ssize_t n;
    do { n = read(fd, byte, 1); } while (n < 0 && errno == EINTR);
    return n == 1 ? 0 : -1;
}
static int line_equals(const char *expected) {
    size_t length = strlen(expected);
    if (length > 4096 || strchr(expected, '\n') || strchr(expected, '\r')) return -1;
    for (size_t i = 0; i <= length; ++i) {
        char byte;
        if (read_byte(STDIN_FILENO, &byte) || byte != (i == length ? '\n' : expected[i])) return -1;
    }
    return 0;
}
static pid_t wait_for(pid_t pid, int *status) {
    pid_t result;
    do { result = waitpid(pid, status, 0); } while (result < 0 && errno == EINTR);
    return result;
}
static int witness(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat metadata;
    if (fd < 0) return -1;
    if (fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) || flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd);
        return -1;
    }
    return fd;
}
static int config(const char *path, const char *expected) {
    const char *environment = getenv("APP_CONFIG");
    if (!environment || strcmp(path, environment) || getenv("PATH") || getenv("LD_PRELOAD"))
        return fail("configuration environment");
    size_t length = strlen(expected);
    if (length > 4096) return fail("configuration expected bytes limit");
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return fail("configuration open");
    struct stat metadata;
    struct statvfs mount;
    if (fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) ||
        fstatvfs(fd, &mount) || !(mount.f_flag & ST_RDONLY)) {
        close(fd);
        return fail("configuration not regular read-only mount");
    }
    char bytes[4097];
    size_t total = 0;
    while (total < sizeof(bytes)) {
        ssize_t n = read(fd, bytes + total, sizeof(bytes) - total);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { close(fd); return fail("configuration read"); }
        if (!n) break;
        total += (size_t)n;
    }
    close(fd);
    if (total != length || memcmp(bytes, expected, length)) return fail("configuration bytes differ");
    return record("SYROX_SESSION_V1 CONFIG OK\n") ? 1 : 0;
}
static int mark_witness(int fd, const char *text) {
    if (ftruncate(fd, 0) || lseek(fd, 0, SEEK_SET) < 0 ||
        write_all(fd, text, strlen(text)) || fsync(fd)) return -1;
    return 0;
}
static int state_counter(int directory, unsigned long expected) {
    int flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    if (!expected) flags |= O_CREAT | O_EXCL;
    int fd = openat(directory, "counter", flags, 0600);
    if (fd < 0) return fail("state counter open");
    struct stat metadata;
    if (fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1 ||
        metadata.st_uid != geteuid() || (metadata.st_mode & 0777) != 0600 ||
        flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd); return fail("state counter identity/lock");
    }
    char actual[32], wanted[32];
    int length = snprintf(wanted, sizeof wanted, "%lu\n", expected);
    ssize_t count;
    do { count = read(fd, actual, sizeof actual); } while (count < 0 && errno == EINTR);
    if ((!expected && count != 0) ||
        (expected && (count != length || memcmp(actual, wanted, (size_t)length)))) {
        close(fd); return fail("state previous counter differs");
    }
    length = snprintf(wanted, sizeof wanted, "%lu\n", expected + 1);
    if (lseek(fd, 0, SEEK_SET) < 0 || ftruncate(fd, 0) ||
        write_all(fd, wanted, (size_t)length) || fsync(fd) ||
        lseek(fd, 0, SEEK_SET) < 0) {
        close(fd); return fail("state counter write/fsync");
    }
    do { count = read(fd, actual, sizeof actual); } while (count < 0 && errno == EINTR);
    if (count != length || memcmp(actual, wanted, (size_t)length)) {
        close(fd); return fail("state counter readback differs");
    }
    struct stat named;
    if (fstatat(directory, "counter", &named, AT_SYMLINK_NOFOLLOW) ||
        !S_ISREG(named.st_mode) || named.st_dev != metadata.st_dev ||
        named.st_ino != metadata.st_ino || named.st_nlink != 1) {
        close(fd); return fail("state counter name replaced");
    }
    if (close(fd) || fsync(directory)) return fail("state directory fsync");
    char message[80];
    snprintf(message, sizeof message, "SYROX_SESSION_V1 STATE OK %lu\n", expected + 1);
    return record(message) ? 1 : 0;
}
static int state(const char *path, const char *expected_text) {
    if (!*expected_text || strlen(expected_text) > 7) return fail("state expected count");
    unsigned long expected = 0;
    for (const unsigned char *p = (const unsigned char *)expected_text; *p; ++p) {
        if (*p < '0' || *p > '9') return fail("state expected count");
        expected = expected * 10 + (*p - '0');
    }
    if (expected > 1000000 || (expected_text[0] == '0' && expected_text[1]))
        return fail("state expected count");
    const char prefix[] = "/syrox/state/";
    if (strncmp(path, prefix, sizeof prefix - 1) || !path[sizeof prefix - 1] ||
        strchr(path + sizeof prefix - 1, '/') ||
        !strcmp(path + sizeof prefix - 1, ".") ||
        !strcmp(path + sizeof prefix - 1, "..")) return fail("state logical path");
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return fail("state directory open");
    struct stat metadata;
    struct statvfs mount;
    unsigned long required = ST_NOSUID | ST_NODEV | ST_NOEXEC;
    if (fstat(directory, &metadata) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & 0777) != 0700 || fstatvfs(directory, &mount) ||
        (mount.f_flag & (required | ST_RDONLY)) != required) {
        close(directory); return fail("state directory mode/mount flags");
    }
    int result = state_counter(directory, expected);
    if (close(directory)) return fail("state directory close");
    return result;
}
static int secret_component(const char *name, size_t length) {
    if (!length || length > 128) return 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)name[i];
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) continue;
        if (i && (c == '.' || c == '_' || c == '-')) continue;
        return 0;
    }
    return 1;
}
static int secret_open(const char *service, size_t service_length, const char *name) {
    char owner[129];
    memcpy(owner, service, service_length);
    owner[service_length] = '\0';
    int parent = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) return -1;
    const char *components[] = {"syrox", "secrets", owner};
    for (size_t i = 0; i < sizeof components / sizeof components[0]; ++i) {
        int child = openat(parent, components[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(parent);
        if (child < 0) return -1;
        parent = child;
    }
    int file = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    close(parent);
    return file;
}
static int secret(const char *path, const char *version) {
    const char *expected;
    if (!strcmp(version, "1")) expected = "syrox-secret-fixture-v1\n";
    else if (!strcmp(version, "2")) expected = "syrox-secret-fixture-v2\n";
    else return fail("secret fixture version");
    const char prefix[] = "/syrox/secrets/";
    if (strncmp(path, prefix, sizeof prefix - 1)) return fail("secret logical path");
    const char *service = path + sizeof prefix - 1;
    const char *separator = strchr(service, '/');
    if (!separator || !secret_component(service, (size_t)(separator - service)) ||
        !secret_component(separator + 1, strlen(separator + 1)))
        return fail("secret logical path");
    int fd = secret_open(service, (size_t)(separator - service), separator + 1);
    if (fd < 0) return fail("secret open");
    struct stat metadata;
    struct statvfs mount;
    unsigned long required = ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC;
    int required_seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int seals = fcntl(fd, F_GET_SEALS);
    if (fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != geteuid() || metadata.st_nlink != 0 ||
        (metadata.st_mode & 07777) != 0400 ||
        metadata.st_size != (off_t)strlen(expected) || fstatvfs(fd, &mount) ||
        (mount.f_flag & required) != required || seals < 0 ||
        (seals & required_seals) != required_seals) {
        close(fd); return fail("secret metadata/mount/seals");
    }
    char bytes[64];
    size_t total = 0;
    while (total < sizeof bytes) {
        ssize_t count = read(fd, bytes + total, sizeof bytes - total);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(fd); return fail("secret read"); }
        if (!count) break;
        total += (size_t)count;
    }
    int valid = total == strlen(expected) && !memcmp(bytes, expected, total);
    explicit_bzero(bytes, sizeof bytes);
    if (close(fd) || !valid) return fail("secret fixture bytes differ");
    return record("SYROX_SESSION_V1 SECRET OK\n") ? 1 : 0;
}
static int managed_identity(const char *expected_uid, const char *expected_gid) {
    char uid[32], gid[32];
    snprintf(uid, sizeof uid, "%lu", (unsigned long)getuid());
    snprintf(gid, sizeof gid, "%lu", (unsigned long)getgid());
    if (getuid() == 0 || geteuid() != getuid() || getegid() != getgid() ||
        strcmp(uid, expected_uid) || strcmp(gid, expected_gid))
        return fail("service identity differs from caller");
    return 0;
}
static int managed_environment(void) {
    struct statvfs proc, tmp;
    struct stat metadata;
    unsigned long isolated = ST_NOSUID | ST_NODEV | ST_NOEXEC;
    if (statvfs("/proc", &proc) || (proc.f_flag & (isolated | ST_RDONLY)) != (isolated | ST_RDONLY) ||
        statvfs("/tmp", &tmp) || (tmp.f_flag & isolated) != isolated ||
        stat("/tmp", &metadata) || (metadata.st_mode & 0777) != 0700)
        return fail("service proc/tmp isolation");
    int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
    char byte;
    if (nullfd < 0) return fail("service null open");
    int nullok = read(nullfd, &byte, 1) == 0 && write(nullfd, "x", 1) == 1;
    close(nullfd);
    if (!nullok) return fail("service null semantics");
    const char *names[] = {"/dev/stdin", "/dev/stdout", "/dev/stderr"};
    for (unsigned int i = 0; i < 3; i++) {
        char actual[64], expected[64];
        ssize_t length = readlink(names[i], actual, sizeof actual - 1);
        if (length < 0) return fail("service stdio link");
        actual[length] = 0;
        snprintf(expected, sizeof expected, "/proc/self/fd/%u", i);
        if (strcmp(actual, expected)) return fail("service stdio target");
    }
    return 0;
}
static int config_wait(const char *path, const char *expected, const char *witness_path) {
    if (config(path, expected)) return 1;
    int marker = open(witness_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    struct stat metadata;
    if (marker < 0) return fail("service witness open");
    if (fstat(marker, &metadata) || !S_ISREG(metadata.st_mode)) {
        close(marker); return fail("service witness type");
    }
    sigset_t stops;
    sigemptyset(&stops); sigaddset(&stops, SIGTERM); sigaddset(&stops, SIGINT);
    if (sigprocmask(SIG_BLOCK, &stops, NULL)) {
        close(marker); return fail("service stop mask");
    }
    int ready[2];
    if (pipe2(ready, O_CLOEXEC)) { close(marker); return fail("service ready pipe"); }
    pid_t child = fork();
    if (child < 0) {
        close(marker); close(ready[0]); close(ready[1]); return fail("service fork");
    }
    if (!child) {
        close(marker); close(ready[0]);
        int retained = witness(witness_path);
        if (retained < 0 || write_all(ready[1], "R", 1)) _exit(21);
        close(ready[1]);
        int received = 0;
        if (sigwait(&stops, &received) || (received != SIGTERM && received != SIGINT)) _exit(22);
        close(retained);
        _exit(23);
    }
    close(ready[1]);
    char byte;
    int status = 0;
    if (read_byte(ready[0], &byte) || byte != 'R' || mark_witness(marker, "CONFIG_READY\n")) {
        close(ready[0]); close(marker); kill(child, SIGKILL); wait_for(child, &status);
        return fail("service child readiness");
    }
    close(ready[0]);
    int received = 0;
    if (sigwait(&stops, &received) || (received != SIGTERM && received != SIGINT)) {
        close(marker); kill(child, SIGKILL); wait_for(child, &status);
        return fail("service stop wait");
    }
    // Do not signal the child here: this tests namespace group propagation.
    if (wait_for(child, &status) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 23) {
        close(marker); return fail("service child stop/reap");
    }
    int result = mark_witness(marker, "CONFIG_TERM_REAPED\n");
    close(marker);
    return result ? fail("service termination witness") : 0;
}
static int children(const char *mode, const char *path) {
    int ready[2];
    if (pipe2(ready, O_CLOEXEC)) return fail("ready pipe");
    pid_t pid = fork();
    if (pid < 0) { close(ready[0]); close(ready[1]); return fail("fork"); }
    if (!pid) {
        close(ready[0]);
        if (!strcmp(mode, "orphan")) {
            if (setsid() < 0) _exit(20);
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(21);
            if (grandchild) _exit(0);
            if (signal(SIGTERM, SIG_IGN) == SIG_ERR) _exit(22);
        }
        int fd = witness(path);
        if (fd < 0 || write_all(ready[1], "R", 1)) _exit(24);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    int status = 0;
    if (read_byte(ready[0], &byte) || byte != 'R') {
        close(ready[0]); kill(pid, SIGKILL); wait_for(pid, &status);
        return fail("child readiness");
    }
    close(ready[0]);
    int probe = witness(path);
    if (probe >= 0) {
        close(probe); kill(pid, SIGKILL); wait_for(pid, &status);
        return fail("witness unexpectedly unlocked");
    }
    if (record("SYROX_SESSION_V1 READY witness-held\n")) {
        kill(pid, SIGKILL); wait_for(pid, &status);
        return fail("ready output");
    }
    if (!strcmp(mode, "orphan")) {
        if (wait_for(pid, &status) != pid || !WIFEXITED(status) || WEXITSTATUS(status))
            return fail("intermediate reap");
        if (line_equals("exit")) return fail("expected exit line");
        return 37;
    }
    int invalid_input = line_equals("reap");
    kill(pid, SIGKILL);
    if (wait_for(pid, &status) != pid || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL)
        return fail("child reap");
    if (invalid_input) return fail("expected reap line");
    errno = 0;
    if (waitpid(pid, &status, WNOHANG) != -1 || errno != ECHILD) return fail("child still waitable");
    probe = witness(path);
    if (probe < 0) return fail("witness retained after reap");
    close(probe);
    return record("SYROX_SESSION_V1 REAPED witness-free\n") ? 1 : 0;
}
/* The application cannot waitpid its orphaned grandchild. ESRCH while it is
 * still alive proves the namespace init adopted and collected the descendant.
 * Witness release alone would also hold for a zombie and is insufficient. */
static int reaping(const char *path) {
    int ready[2], release[2];
    if (pipe2(ready, O_CLOEXEC)) return fail("adoption ready pipe");
    if (pipe2(release, O_CLOEXEC)) { close(ready[0]); close(ready[1]); return fail("adoption release pipe"); }
    pid_t middle = fork();
    if (middle < 0) { close(ready[0]); close(ready[1]); close(release[0]); close(release[1]); return fail("adoption fork"); }
    if (!middle) {
        close(ready[0]); close(release[1]);
        pid_t grandchild = fork();
        if (grandchild < 0) _exit(20);
        if (grandchild) _exit(0);
        int fd = witness(path);
        pid_t identity = getpid();
        if (fd < 0 || write_all(ready[1], &identity, sizeof(identity))) _exit(21);
        close(ready[1]);
        char byte;
        if (read_byte(release[0], &byte) || byte != 'X') _exit(22);
        close(release[0]); close(fd);
        _exit(23);
    }
    close(ready[1]); close(release[0]);
    pid_t adopted = 0;
    unsigned char *bytes = (unsigned char *)&adopted;
    for (size_t i = 0; i < sizeof(adopted); ++i) {
        char byte;
        if (read_byte(ready[0], &byte)) {
            close(ready[0]); close(release[1]);
            int status; kill(middle, SIGKILL); wait_for(middle, &status);
            return fail("adoption identity read");
        }
        bytes[i] = (unsigned char)byte;
    }
    close(ready[0]);
    int status = 0;
    if (adopted <= 1 || wait_for(middle, &status) != middle || !WIFEXITED(status) || WEXITSTATUS(status)) {
        close(release[1]); return fail("adoption intermediate reap");
    }
    int probe = witness(path);
    if (probe >= 0) { close(probe); close(release[1]); return fail("adoption witness not held"); }
    if (record("SYROX_SESSION_V1 READY adopted-witness-held\n") || write_all(release[1], "X", 1)) {
        close(release[1]); return fail("adoption release");
    }
    close(release[1]);
    struct timespec start, now, pause_time = {0, 1000000};
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return fail("adoption clock");
    for (;;) {
        errno = 0;
        if (kill(adopted, 0) == -1) {
            if (errno == ESRCH) break;
            return fail("adoption identity observation");
        }
        if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 5)
            return fail("namespace init did not reap orphan while application lived");
        nanosleep(&pause_time, NULL);
    }
    probe = witness(path);
    if (probe < 0) return fail("adopted witness retained");
    close(probe);
    return record("SYROX_SESSION_V1 ADOPTED REAPED witness-free\n") ? 1 : 0;
}
static int dimension(const char *text, unsigned short *out) {
    if (!*text) return -1;
    unsigned long value = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return -1;
        value = value * 10 + (*p - '0');
        if (value > USHRT_MAX) return -1;
    }
    if (!value) return -1;
    *out = (unsigned short)value;
    return 0;
}
static int terminal(const char *expected, const char *rows, const char *columns) {
    unsigned short target_rows, target_columns;
    if (dimension(rows, &target_rows) || dimension(columns, &target_columns)) return fail("terminal dimensions");
    for (int fd = 0; fd < 3; ++fd)
        if (isatty(fd) != 1 || tcgetpgrp(fd) != getpgrp()) return fail("terminal foreground");
    struct winsize size;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size)) return fail("initial terminal size");
    char record_buffer[96];
    int length = snprintf(record_buffer, sizeof(record_buffer), "SYROX_SESSION_V1 READY terminal %u %u\n", size.ws_row, size.ws_col);
    if (length < 0 || (size_t)length >= sizeof(record_buffer) || record(record_buffer)) return fail("terminal ready output");
    if (line_equals(expected)) return fail("terminal input differs");
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) || size.ws_row != target_rows || size.ws_col != target_columns)
        return fail("terminal resize differs");
    if (tcgetpgrp(STDIN_FILENO) != getpgrp()) return fail("terminal foreground changed");
    return record("SYROX_SESSION_V1 TERMINAL OK\n") ? 1 : 0;
}
static int terminal_devtty(void) {
    pid_t session = getsid(0), group = getpgrp();
    if (session != getpid() || group != getpid()) return fail("devtty session leader");
    for (int fd = 0; fd < 3; ++fd)
        if (isatty(fd) != 1 || tcgetpgrp(fd) != group) return fail("devtty initial foreground");
    int channel[2];
    if (pipe2(channel, O_CLOEXEC)) return fail("devtty stdin pipe");
    if (dup2(channel[0], STDIN_FILENO) < 0) {
        close(channel[0]); close(channel[1]);
        return fail("devtty redirect stdin");
    }
    close(channel[0]); close(channel[1]);
    char byte;
    if (isatty(STDIN_FILENO) || read(STDIN_FILENO, &byte, 1) != 0)
        return fail("devtty stdin is not EOF pipe");
    int tty = open("/dev/tty", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY);
    if (tty < 0) return fail("devtty open after redirect");
    struct stat metadata;
    if (fstat(tty, &metadata) || !S_ISCHR(metadata.st_mode)
        || major(metadata.st_rdev) != 5 || minor(metadata.st_rdev) != 0
        || isatty(tty) != 1 || tcgetpgrp(tty) != group || tcgetsid(tty) != session) {
        close(tty);
        return fail("devtty controlling foreground/session");
    }
    const char witness[] = "SYROX_SESSION_V1 DEVTTY OK stdin-pipe foreground-session\n";
    int result = write_all(tty, witness, sizeof(witness) - 1);
    if (close(tty) || result) return fail("devtty witness");
    return 37;
}

/* Gate-only public marker protocol. Each attempt owns a different O_EXCL slot;
 * release.N cannot accidentally release attempt N+1. Never a settlement proof. */
static int restart_name(const char *name) {
    size_t n = strlen(name);
    if (!n || n > 48) return 0;
    for (size_t i = 0; i < n; ++i)
        if (!((name[i] >= 'a' && name[i] <= 'z') || name[i] == '-')) return 0;
    return 1;
}
static int restart78(const char *witness_prefix, const char *release_prefix) {
    if (!restart_name(witness_prefix) || !restart_name(release_prefix) ||
        !strcmp(witness_prefix, release_prefix)) return fail("restart names");
    int directory = open(".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat meta;
    if (directory < 0 || fstat(directory, &meta) || meta.st_uid != getuid() ||
        (meta.st_mode & 07777) != 0700) return fail("restart directory");
    char marker[80], release[80], line[80];
    int fd = -1;
    unsigned attempt;
    for (attempt = 1; attempt <= 8; ++attempt) {
        snprintf(marker, sizeof(marker), "%s.%u", witness_prefix, attempt);
        fd = openat(directory, marker, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) break;
        if (errno != EEXIST) { close(directory); return fail("restart marker create"); }
    }
    if (fd < 0) { close(directory); return fail("restart attempt budget"); }
    int length = snprintf(line, sizeof(line), "SYROX_RESTART_V1 %u\n", attempt);
    int error = write_all(fd, line, (size_t)length) || fsync(fd);
    if (close(fd) || error || fsync(directory)) { close(directory); return fail("restart marker sync"); }
    snprintf(release, sizeof(release), "%s.%u", release_prefix, attempt);
    struct timespec start, now, delay = { .tv_sec = 0, .tv_nsec = 10000000 };
    if (clock_gettime(CLOCK_MONOTONIC, &start)) { close(directory); return fail("restart clock"); }
    for (;;) {
        fd = openat(directory, release, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            char bytes[2];
            int valid = !fstat(fd, &meta) && S_ISREG(meta.st_mode) && meta.st_nlink == 1 &&
                meta.st_uid == getuid() && (meta.st_mode & 07777) == 0600 && meta.st_size == 1 &&
                read(fd, bytes, sizeof(bytes)) == 1 && bytes[0] == 'X';
            int closed = close(fd);
            close(directory);
            return valid && !closed ? 78 : fail("restart release");
        }
        if (errno != ENOENT || clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 45) {
            close(directory); return fail("restart release deadline");
        }
        nanosleep(&delay, NULL);
    }
}
int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "restart78")) return restart78(argv[2], argv[3]);
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return fail("SIGPIPE policy");
    if (argc == 2 && !strcmp(argv[1], "--help")) {
        return record("SYROX_SESSION_V1 config PATH EXPECTED | config-wait PATH EXPECTED WITNESS [UID GID] | managed UID GID | state DIR EXPECTED | secret PATH VERSION | child WITNESS | orphan WITNESS | reaping WITNESS | terminal EXPECTED ROWS COLS | terminal-devtty UID GID\n") ? 1 : 0;
    }
    if (argc == 4 && !strcmp(argv[1], "terminal-devtty")) {
        if (managed_identity(argv[2], argv[3]) || managed_environment()) return 1;
        return terminal_devtty();
    }
    if (argc == 4 && !strcmp(argv[1], "managed")) {
        if (managed_identity(argv[2], argv[3]) || managed_environment()) return 1;
        return record("SYROX_SESSION_V1 MANAGED OK\n") ? 1 : 37;
    }
    if (argc == 4 && !strcmp(argv[1], "config")) return config(argv[2], argv[3]);
    if (argc == 4 && !strcmp(argv[1], "state")) return state(argv[2], argv[3]);
    if (argc == 4 && !strcmp(argv[1], "secret")) return secret(argv[2], argv[3]);
    if ((argc == 5 || argc == 7) && !strcmp(argv[1], "config-wait")) {
        if (argc == 7) {
            if (managed_identity(argv[5], argv[6]) || managed_environment()) return 1;
        }
        return config_wait(argv[2], argv[3], argv[4]);
    }
    if (argc == 3 && !strcmp(argv[1], "reaping")) return reaping(argv[2]);
    if (argc == 3 && (!strcmp(argv[1], "child") || !strcmp(argv[1], "orphan")))
        return children(argv[1], argv[2]);
    if (argc == 5 && !strcmp(argv[1], "terminal")) return terminal(argv[2], argv[3], argv[4]);
    return fail("invalid mode or argument count; use --help");
}
