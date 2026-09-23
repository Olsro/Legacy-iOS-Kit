#include "olsn0w_config.h"
typedef unsigned int size_t;
extern int printf(const char *, ...), fflush(void *), strcmp(const char *, const char *);
extern char *strstr(const char *, const char *);
extern int sysctlbyname(const char *, void *, size_t *, void *, size_t);
extern int geteuid(void), getppid(void), open(const char *, int, ...), close(int);
extern long read(int, void *, unsigned long), write(int, const void *, unsigned long);
extern int unlink(const char *);
extern void sync(void);
extern int posix_spawn(int *, const char *, const void *, const void *, char *const *, char *const *);
extern int waitpid(int, int *, int), kill(int, int), execve(const char *, char *const *, char *const *);
extern int usleep(unsigned int);
extern int pipe(int *), fcntl(int, int, ...);
extern int posix_spawn_file_actions_init(void **), posix_spawn_file_actions_destroy(void **);
extern int posix_spawn_file_actions_addclose(void **, int), posix_spawn_file_actions_adddup2(void **, int, int);
extern unsigned int mach_task_self_;
extern int task_for_pid(unsigned int, int, unsigned int *), mach_port_deallocate(unsigned int, unsigned int);

#define MARKER "/olsn0w/bootstrap.marker"
#define ENABLED "/olsn0w/autoboot.enabled"
#define FAILURE "/var/log/autoboot.failure"
#define STAGE "/var/log/autoboot.stage"
#define SERVICES_READY "/var/run/olsn0w-services-ready"

struct boot_identity { long seconds; int microseconds; };

static char *const environment[] = {"PATH=/bin:/sbin:/usr/bin:/usr/sbin", "HOME=/var/root", 0};

static int exact_file(const char *path, const char *expected) {
    char data[64] = {0};
    int fd = open(path, 0);
    if (fd < 0) return 0;
    long count = read(fd, data, sizeof(data) - 1);
    close(fd);
    size_t length = 0;
    while (expected[length]) length++;
    return count == (long)length && !strcmp(data, expected);
}

static int identity(void) {
    char model[64] = {0}, release[64] = {0}, args[2048] = {0};
    size_t size = sizeof(model) - 1;
    if (sysctlbyname("hw.model", model, &size, 0, 0) || strcmp(model, OLSN0W_BOARD)) return 0;
    size = sizeof(release) - 1;
    if (sysctlbyname("kern.osrelease", release, &size, 0, 0) || strcmp(release, "14.0.0")) return 0;
    size = sizeof(args) - 1;
    if (sysctlbyname("kern.bootargs", args, &size, 0, 0)) return 0;
    /* Stock iBoot supplies an empty command line and root-matching ID 1.
     * The bootstrap marker below binds this controller to our filesystem. */
    printf("OLSN0W-AUTONOMOUS bootargs=%s\n", args); fflush(0);
    return 1;
}

static int run(char *const arguments[]) {
    int pid = 0, status = 0;
    int result = posix_spawn(&pid, arguments[0], 0, 0, arguments, environment);
    if (result || waitpid(pid, &status, 0) != pid) return -1;
    return status;
}

static void stage(const char *value) {
    int fd = open(STAGE, 0x601, 0600);
    if (fd < 0) return;
    unsigned long length = 0;
    while (value[length]) length++;
    write(fd, value, length);
    write(fd, "\n", 1);
    close(fd);
    sync();
}

static int release_services(void) {
    struct boot_identity boot = {0, 0};
    size_t size = sizeof(boot);
    if (sysctlbyname("kern.boottime", &boot, &size, 0, 0)) return 1;
    if (size != sizeof(boot)) return 2;
    int fd = open(SERVICES_READY, 0x601, 0600);
    if (fd < 0) return 3;
    long count = write(fd, &boot, sizeof(boot));
    close(fd);
    sync();
    return count == sizeof(boot) ? 0 : 4;
}

static int fail(int code) {
    char text[16];
    int count = 0, value = code;
    text[count++] = '0' + (value / 100) % 10;
    text[count++] = '0' + (value / 10) % 10;
    text[count++] = '0' + value % 10;
    text[count++] = '\n';
    int fd = open(FAILURE, 0x601, 0600);
    if (fd >= 0) { write(fd, text, count); close(fd); sync(); }
    printf("OLSN0W-AUTONOMOUS failure=%d\n", code); fflush(0);
    return code;
}

int main(void) {
    if (geteuid() || getppid() != 1 || !identity() ||
        !exact_file(MARKER, OLSN0W_ROOT_MARKER)) return fail(101);
    if (!exact_file(ENABLED, OLSN0W_TARGET_MARKER)) {
        printf("OLSN0W-AUTONOMOUS disarmed\n"); fflush(0); return 0;
    }
    unlink(SERVICES_READY);
    /* Enablement is persistent and read-only. A power cut must not consume
     * the next boot; writable stage/failure records are diagnostic only. */
    stage("controller-starting-held");
    unsigned int port = 0;
    int ready = 0, held_pid = 0, held_status = 0, channel[2] = {-1, -1};
    if (!task_for_pid(mach_task_self_, 0, &port) && port) {
        mach_port_deallocate(mach_task_self_, port); ready = 1;
    } else {
        /* A fresh pipe cannot contain a readiness marker left by a prior boot.
         * Do not probe task ports while the untether is modifying them. */
        if (pipe(channel)) return fail(111);
        if (fcntl(channel[0], 4, 4) < 0 || fcntl(channel[0], 2, 1) < 0) {
            close(channel[0]); close(channel[1]); return fail(111);
        }
        void *actions = 0;
        int rc = posix_spawn_file_actions_init(&actions);
        if (!rc) {
            rc = posix_spawn_file_actions_addclose(&actions, channel[0]);
            if (!rc) rc = posix_spawn_file_actions_adddup2(&actions, channel[1], 3);
            if (!rc && channel[1] != 3) rc = posix_spawn_file_actions_addclose(&actions, channel[1]);
            char *held[] = {"/olsn0w/held-control", "--ready-fd=3", 0};
            if (!rc) rc = posix_spawn(&held_pid, held[0], &actions, 0, held, environment);
            posix_spawn_file_actions_destroy(&actions);
        }
        close(channel[1]);
        printf("OLSN0W-AUTONOMOUS held-spawn=%d pid=%d\n", rc, held_pid); fflush(0);
        if (rc || held_pid <= 0) { close(channel[0]); return fail(111); }
    }
    for (int i = 0; !ready && i < 1200; i++) {
        char signal = 0;
        long count = read(channel[0], &signal, 1);
        if (count == 1 && signal == 'R') {
            close(channel[0]); channel[0] = -1;
            if (task_for_pid(mach_task_self_, 0, &port) || !port) return fail(113);
            mach_port_deallocate(mach_task_self_, port); ready = 1; break;
        }
        if (count >= 0 || waitpid(held_pid, &held_status, 1) == held_pid) {
            close(channel[0]); return fail(112);
        }
        usleep(100000);
    }
    if (channel[0] >= 0) close(channel[0]);
    if (!ready) return fail(102);
    /* Allow the kernel changes to settle before starting power services. */
    usleep(2000000);
    stage("controller-untether-ready");
    /* launchd registered powerd's Mach services from its embedded registry
     * before clients could request them.  Release its already-running gate only
     * after the held untether reports a patched kernel.  The boot-time token
     * prevents a persistent /var marker from releasing a later boot early. */
    int release_status = 0;
    for (int i = 0; i < 100; i++) {
        release_status = release_services();
        if (!release_status) break;
        if (!(i % 10)) {
            printf("OLSN0W-AUTONOMOUS services-release=%d attempt=%d\n",
                   release_status, i + 1);
            fflush(0);
        }
        usleep(100000);
    }
    if (release_status) return fail(104);
    stage("controller-power-services");
    char *pm[] = {"/olsn0w/bootstrap_pm_ready", "--complete", 0};
    if (run(pm)) return fail(105);
    stage("controller-power-complete");
    unlink("/var/run/olsn0w-wake.ready");
    int wake_pid = 0;
    char *wake[] = {"/olsn0w/bootstrap_wake", 0};
    if (posix_spawn(&wake_pid, wake[0], 0, 0, wake, environment)) return fail(106);
    for (int i = 0; i < 40; i++) {
        if (exact_file("/var/run/olsn0w-wake.ready", "ready\n")) { ready = 2; break; }
        if (kill(wake_pid, 0)) return fail(107);
        usleep(250000);
    }
    if (ready != 2) return fail(108);
    stage("controller-wake-ready");
    unlink(FAILURE);
    sync();
    stage("controller-relay-exec");
    printf("OLSN0W-AUTONOMOUS launching selected target root3\n"); fflush(0);
    char *loader[] = {"/usr/local/bin/kloader", "/olsn0w/relay.bin", 0};
    execve(loader[0], loader, environment);
    return fail(110);
}
