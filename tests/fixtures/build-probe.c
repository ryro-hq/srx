#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    if (strcmp(argv[1], "network") == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) { close(fd); return 72; }
        return errno == EPERM ? 0 : 73;
    }
    if (strcmp(argv[1], "log") == 0) {
        char bytes[8192];
        memset(bytes, 'x', sizeof(bytes));
        for (int i = 0; i < 128; ++i)
            if (fwrite(bytes, 1, sizeof(bytes), stderr) != sizeof(bytes)) return 74;
        if (fputs("FINAL_FAILURE_MARKER\n", stderr) == EOF) return 74;
        return 19;
    }
    int failure = strcmp(argv[1], "failure") == 0;
    int unsafe = strcmp(argv[1], "symlink") == 0;
    if (!failure && !unsafe && strcmp(argv[1], "stable") != 0) return 64;
    pid_t child = fork();
    if (child < 0) return 75;
    if (child > 0) return 0;
    if (setsid() < 0) _exit(76);
    child = fork();
    if (child < 0) _exit(75);
    if (child > 0) _exit(0);
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 300000000 };
    while (nanosleep(&delay, &delay) < 0) if (errno != EINTR) _exit(77);
    if (failure) _exit(42);
    const char *prefix = getenv("SYROX_OUTPUT_PREFIX");
    char path[4096];
    if (!prefix) _exit(78);
    int size = snprintf(path, sizeof(path), "/out%s/bin/hello", prefix);
    if (size < 0 || (size_t)size >= sizeof(path)) _exit(78);
    if (unsafe) {
        if (unlink(path) < 0 || symlink("/etc/passwd", path) < 0) _exit(79);
    } else {
        FILE *output = fopen(path, "w");
        if (!output) _exit(80);
        if (fputs("stable after orphan", output) == EOF || fclose(output) != 0) _exit(81);
    }
    _exit(0);
}
