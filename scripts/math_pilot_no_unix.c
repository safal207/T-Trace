#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/io_uring.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Additional syscall guard, not a replacement for Landrun.  Proof checking
 * needs no sockets after dependencies have been prepared.  Denying all socket
 * creation also closes the UDP gap in Landlock's TCP-only restrictions.
 */
static int zero_effective_caps(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    int valid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "CapEff:", 7)) {
            unsigned long long cap = 1;
            if (sscanf(line + 7, "%llx", &cap) == 1 && cap == 0) valid = 1;
        }
    }
    fclose(f);
    return valid;
}

static int probe(void) {
    const int families[] = {AF_UNIX, AF_INET, AF_INET6};
    const int types[] = {SOCK_STREAM, SOCK_DGRAM};
    for (unsigned int f = 0; f < sizeof(families) / sizeof(families[0]); f++) {
        for (unsigned int t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
            errno = 0;
            if (socket(families[f], types[t], 0) != -1 || errno != EAFNOSUPPORT) {
                fputs("socket denial probe failed\n", stderr);
                return 125;
            }
        }
    }
    int pair[2];
    errno = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != -1 || errno != EAFNOSUPPORT) {
        fputs("socketpair denial probe failed\n", stderr);
        return 125;
    }
    struct io_uring_params params = {0};
    errno = 0;
    if (syscall(SYS_io_uring_setup, 1, &params) != -1 || errno != EPERM) {
        fputs("io_uring denial probe failed\n", stderr);
        return 125;
    }
    printf("{\"socket_creation\":\"DENIED\",\"socketpair\":\"DENIED\","
           "\"io_uring_setup\":\"DENIED\",\"uid\":%ld,\"effective_caps\":0}\n",
           (long)geteuid());
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || geteuid() == 0 || getegid() == 0 || !zero_effective_caps()) {
        fputs("launcher refuses root, effective capabilities, or no command\n", stderr);
        return 125;
    }
    for (int fd = 0; fd < 3; fd++) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode)) {
            fputs("launcher refuses inherited standard socket descriptor\n", stderr);
            return 125;
        }
    }
    if (syscall(SYS_close_range, 3, ~0U, 0) < 0) {
        perror("close_range");
        return 125;
    }
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_setup, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socketpair, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EAFNOSUPPORT),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = sizeof(code) / sizeof(code[0]), .filter = code};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0) {
        perror("seccomp");
        return 125;
    }
    if (argc == 2 && !strcmp(argv[1], "--probe")) return probe();
    execvp(argv[1], argv + 1);
    perror("execvp");
    return 127;
}
