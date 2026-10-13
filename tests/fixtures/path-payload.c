/* Controlled PATH/argv/pipe fixture, NOT a shell. No external tools are invoked
 * except the explicitly named COMMAND through execvp and the caller's PATH.
 * driver COMMAND ID STATUS: exec helper, validate status.
 * pipeline COMMAND ID STATUS: same, also feed exact bytes through stdin pipe.
 * helper/pipeline-helper ID STATUS 'literal argument' '*;$()': internal protocol.
 * denied PATH: require EACCES/ENOENT opening PATH; prints no path or contents.
 * All runs have a five-second watchdog; child groups are killed before reaping.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;
static const char input[] = "controlled pipeline bytes\n";
static void interrupt(int signal_number) { interrupted = signal_number; }
static int fail(void) {
    fputs("SYROX_PATH_V1 ERROR\n", stderr);
    return 126;
}
static int status_value(const char *text) {
    if (!*text || strlen(text) > 3) return -1;
    unsigned value = 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9') return -1;
        value = value * 10 + (unsigned)(*text - '0');
    }
    return value <= 125 ? (int)value : -1;
}
static int identity(const char *text) {
    if (!*text || strlen(text) > 64) return 0;
    for (; *text; ++text)
        if (!((*text >= 'a' && *text <= 'z') || (*text >= '0' && *text <= '9') || *text == '-')) return 0;
    return 1;
}
static int helper(int argc, char **argv, int consume) {
    if (argc != 6 || !identity(argv[2]) || status_value(argv[3]) < 0 ||
        strcmp(argv[4], "literal argument") || strcmp(argv[5], "*;$()")) return fail();
    if (consume) {
        char bytes[sizeof input];
        size_t used = 0;
        while (used < sizeof bytes && !interrupted) {
            ssize_t count = read(STDIN_FILENO, bytes + used, sizeof bytes - used);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) return fail();
            if (!count) break;
            used += (size_t)count;
        }
        if (interrupted || used != sizeof input - 1 || memcmp(bytes, input, used)) return fail();
    }
    if (printf("SYROX_PATH_V1 HELPER %s ARGV OK%s\n", argv[2], consume ? " PIPE OK" : "") < 0 || fflush(stdout)) return fail();
    return status_value(argv[3]);
}
static int driver(char **argv, int pipeline) {
    if (!*argv[2] || strchr(argv[2], '/') || strlen(argv[2]) > 128 ||
        !identity(argv[3]) || status_value(argv[4]) < 0) return fail();
    int pipefd[2] = {-1, -1};
    if (pipeline && pipe2(pipefd, O_CLOEXEC)) return fail();
    int capture[2];
    if (pipe2(capture, O_CLOEXEC)) {
        if (pipeline) { close(pipefd[0]); close(pipefd[1]); }
        return fail();
    }
    int flags = fcntl(capture[0], F_GETFL);
    if (flags < 0 || fcntl(capture[0], F_SETFL, flags | O_NONBLOCK)) {
        close(capture[0]); close(capture[1]);
        if (pipeline) { close(pipefd[0]); close(pipefd[1]); }
        return fail();
    }
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) {
        close(capture[0]); close(capture[1]);
        if (pipeline) { close(pipefd[0]); close(pipefd[1]); }
        return fail();
    }
    if (!child) {
        close(capture[0]);
        if (dup2(capture[1], STDOUT_FILENO) < 0) _exit(126);
        if (capture[1] != STDOUT_FILENO) close(capture[1]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent || setpgid(0, 0)) _exit(126);
        if (pipeline) {
            close(pipefd[1]);
            if (dup2(pipefd[0], STDIN_FILENO) < 0) _exit(126);
            if (pipefd[0] != STDIN_FILENO) close(pipefd[0]);
        }
        char *args[] = {argv[2], pipeline ? "pipeline-helper" : "helper", argv[3], argv[4], "literal argument", "*;$()", NULL};
        execvp(argv[2], args);
        _exit(127);
    }
    close(capture[1]);
    /* Either this call or the child's establishes the group before exec. */
    int setup_failed = setpgid(child, child) && errno != EACCES;
    if (pipeline) {
        close(pipefd[0]);
        ssize_t count;
        do { count = write(pipefd[1], input, sizeof input - 1); } while (count < 0 && errno == EINTR && !interrupted);
        if (count != (ssize_t)(sizeof input - 1)) setup_failed = 1;
        close(pipefd[1]);
    }
    siginfo_t observed;
    memset(&observed, 0, sizeof observed);
    int waited = -1, eof = 0;
    char witness[256];
    size_t captured = 0;
    if (!setup_failed && !interrupted) {
        while (!interrupted) {
            waited = waitid(P_PID, (id_t)child, &observed, WEXITED | WNOWAIT | WNOHANG);
            int wait_error = errno;
            ssize_t count = read(capture[0], witness + captured, sizeof witness - captured);
            if (count > 0) {
                captured += (size_t)count;
                if (captured == sizeof witness) { setup_failed = 1; break; }
            } else if (!count) eof = 1;
            else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) { setup_failed = 1; break; }
            if (!waited && observed.si_pid == child && eof) break;
            if (waited && wait_error != EINTR) break;
            struct timespec pause = {0, 10000000};
            nanosleep(&pause, NULL);
        }
    }
    close(capture[0]);
    /* PID remains reserved: never signal numeric PID/PGID after waitpid. */
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    int status;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    if (setup_failed || interrupted || !eof || waited || result != child || !WIFEXITED(status) || WEXITSTATUS(status) != status_value(argv[4])) return fail();
    char expected[256];
    int length = snprintf(expected, sizeof expected, "SYROX_PATH_V1 HELPER %s ARGV OK%s\n", argv[3], pipeline ? " PIPE OK" : "");
    if (length < 0 || (size_t)length >= sizeof expected || captured != (size_t)length || memcmp(witness, expected, captured)) return fail();
    if (fwrite(witness, 1, captured, stdout) != captured || fflush(stdout)) return fail();
    return puts("SYROX_PATH_V1 DRIVER STATUS OK") < 0 ? fail() : 0;
}
/* These are public test sentinels, never user secret bytes. */
static int exact_file(const char *path, const char *expected) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    char bytes[128];
    ssize_t count = read(fd, bytes, sizeof bytes);
    int ok = !fstat(fd, &st) && S_ISREG(st.st_mode) && count >= 0 &&
        (size_t)count == strlen(expected) && !memcmp(bytes, expected, (size_t)count);
    close(fd);
    return ok;
}
static int inaccessible(const char *path) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) { close(fd); return 0; }
    return errno == EACCES || errno == ENOENT;
}
static int private_context(int argc, char **argv) {
    if (argc != 11 || (strcmp(argv[2], "alpha") && strcmp(argv[2], "beta"))) return fail();
    const int alpha = !strcmp(argv[2], "alpha");
    const char *own = alpha ? "alpha" : "beta", *other = alpha ? "beta" : "alpha";
    char config[128], secret[128], foreign_config[128], foreign_secret[128];
    snprintf(config, sizeof config, "/syrox/config/%s/settings", own);
    snprintf(secret, sizeof secret, "/syrox/secrets/%s/token", own);
    snprintf(foreign_config, sizeof foreign_config, "/syrox/config/%s/settings", other);
    snprintf(foreign_secret, sizeof foreign_secret, "/syrox/secrets/%s/token", other);
    if (strcmp(argv[3], config) || strcmp(argv[4], secret) || strcmp(argv[5], other) ||
        !exact_file(config, alpha ? "alpha-configuration" : "beta-configuration") ||
        !exact_file(secret, alpha ? "alpha-private-fixture" : "beta-private-fixture") ||
        !inaccessible(foreign_config) || !inaccessible(foreign_secret)) return fail();
    char through_proc[256];
    snprintf(through_proc, sizeof through_proc, "/proc/1/root%s", foreign_secret);
    if (!inaccessible(through_proc) || strcmp(argv[7], own)) return fail();
    if (strcmp(argv[6], "helper") && strcmp(argv[6], "pipeline-helper")) return fail();
    return helper(argc - 5, argv + 5, !strcmp(argv[6], "pipeline-helper"));
}
static int suite(void) {
    if (!getenv("PATH") || strcmp(getenv("PATH"), "/syrox/commands/bin")) return fail();
    if (!inaccessible("/syrox/config/alpha/settings") || !inaccessible("/syrox/secrets/alpha/token") ||
        !inaccessible("/syrox/config/beta/settings") || !inaccessible("/syrox/secrets/beta/token")) return fail();
    const char *commands[] = {"run", "alpha", "beta"};
    const char *identities[] = {"root", "alpha", "beta"};
    for (size_t i = 0; i < 3; ++i) {
        for (int pipe_mode = 0; pipe_mode < 2; ++pipe_mode) {
            char *args[] = {"path-payload", "driver", (char *)commands[i], (char *)identities[i], pipe_mode ? "37" : "0", NULL};
            alarm(5);
            if (driver(args, pipe_mode)) return fail();
        }
    }
    int saved = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
    int output = open("redirect-witness", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (saved < 0 || output < 0) { if (saved >= 0) close(saved); if (output >= 0) close(output); return fail(); }
    if (fflush(stdout) || dup2(output, STDOUT_FILENO) < 0) { close(saved); close(output); return fail(); }
    close(output);
    char *args[] = {"path-payload", "driver", "alpha", "alpha", "0", NULL};
    alarm(5);
    int result = driver(args, 0);
    int restore = dup2(saved, STDOUT_FILENO);
    close(saved);
    if (result || restore < 0 || !exact_file("redirect-witness", "SYROX_PATH_V1 HELPER alpha ARGV OK\nSYROX_PATH_V1 DRIVER STATUS OK\n")) return fail();
    int marker = open("path-success", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    static const char witness[] = "SYROX_PATH_V1 SUITE ROOT SERVICES PIPE REDIRECT STATUS ISOLATION OK\n";
    if (marker < 0) return fail();
    int ok = write(marker, witness, sizeof witness - 1) == (ssize_t)(sizeof witness - 1) && !fsync(marker);
    close(marker);
    if (!ok || !exact_file("path-success", witness)) return fail();
    return puts(witness) < 0 ? fail() : 0;
}
int main(int argc, char **argv) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = interrupt;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
        sigaction(SIGINT, &action, NULL) || signal(SIGPIPE, SIG_IGN) == SIG_ERR) return fail();
    alarm(5);
    if (argc == 2 && !strcmp(argv[1], "suite")) return suite();
    if (argc > 1 && !strcmp(argv[1], "context")) return private_context(argc, argv);
    if (argc == 5 && (!strcmp(argv[1], "driver") || !strcmp(argv[1], "pipeline"))) return driver(argv, !strcmp(argv[1], "pipeline"));
    if (argc > 1 && (!strcmp(argv[1], "helper") || !strcmp(argv[1], "pipeline-helper"))) return helper(argc, argv, !strcmp(argv[1], "pipeline-helper"));
    if (argc == 3 && !strcmp(argv[1], "denied")) {
        if (argv[2][0] != '/' || strlen(argv[2]) > 4096) return fail();
        int fd = open(argv[2], O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd >= 0) { close(fd); return fail(); }
        if (errno != EACCES && errno != ENOENT) return fail();
        return puts("SYROX_PATH_V1 ACCESS DENIED") < 0 ? fail() : 0;
    }
    return fail();
}
