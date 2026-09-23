#include "olsn0w_config.h"
typedef unsigned int size_t;
extern int strcmp(const char *, const char *);
extern int sysctlbyname(const char *, void *, size_t *, void *, size_t);
extern int geteuid(void), getppid(void), open(const char *, int, ...), close(int);
extern long read(int, void *, unsigned long);
extern int usleep(unsigned int), execve(const char *, char *const *, char *const *);

#define SERVICES_READY "/var/run/olsn0w-services-ready"
struct boot_identity { long seconds; int microseconds; };

static int identity(void) {
    char model[64] = {0}, release[64] = {0};
    size_t size = sizeof(model) - 1;
    if (sysctlbyname("hw.model", model, &size, 0, 0) || strcmp(model, OLSN0W_BOARD)) return 0;
    size = sizeof(release) - 1;
    return !sysctlbyname("kern.osrelease", release, &size, 0, 0) && !strcmp(release, "14.0.0");
}

static int same_boot(const struct boot_identity *expected) {
    struct boot_identity found = {0, 0};
    int fd = open(SERVICES_READY, 0);
    if (fd < 0) return 0;
    long count = read(fd, &found, sizeof(found));
    close(fd);
    return count == sizeof(found) && found.seconds == expected->seconds &&
           found.microseconds == expected->microseconds;
}

int main(int argc, char **argv, char **environment) {
    if (geteuid() || getppid() != 1 || argc < 2 || !identity()) return 120;
    if (strcmp(argv[1], "/usr/sbin/notifyd") &&
        strcmp(argv[1], "/System/Library/CoreServices/powerd.bundle/powerd")) return 121;
    struct boot_identity boot = {0, 0};
    size_t size = sizeof(boot);
    if (sysctlbyname("kern.boottime", &boot, &size, 0, 0) || size != sizeof(boot)) return 122;
    for (int i = 0; i < 2400; i++) {
        if (same_boot(&boot)) {
            execve(argv[1], argv + 1, environment);
            return 124;
        }
        usleep(100000);
    }
    return 123;
}
