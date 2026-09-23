#include <errno.h>
#include <stdio.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: chroot_exec ROOT PROGRAM [ARG ...]\n");
        return 64;
    }
    if (chroot(argv[1])) {
        perror("chroot");
        return 65;
    }
    if (chdir("/")) {
        perror("chdir");
        return 66;
    }
    execve(argv[2], &argv[2], environ);
    perror("execve");
    return errno ? errno : 67;
}
