#include "olsn0w_config.h"
#define main native_check
#include "cache_check.c"
#undef main
extern int getppid(void), geteuid(void), open(const char *, int, ...), close(int);
extern long read(int, void *, unsigned long);
extern unsigned int sleep(unsigned int);
extern int execve(const char *, char *const *, char *const *);
extern int posix_spawn(int *, const char *, const void *, const void *, char *const *, char *const *);
extern int waitpid(int, int *, int), write(int, const void *, unsigned long);
extern void sync(void);
extern void *CFStringCreateWithCString(void *, const char *, unsigned int);
extern void CFRelease(void *);
extern int IOUSBDeviceControllerCreate(void *, void **);
extern void *IOUSBDeviceControllerCreateDefaultDescription(void *, void *);
extern void IOUSBDeviceDescriptionRemoveAllConfigurations(void *);
extern int IOUSBDeviceDescriptionAppendConfigurationWithInterface(void *, void *);
extern void IOUSBDeviceDescriptionSetSerialString(void *, void *);
extern int IOUSBDeviceControllerSetDescription(void *, void *);
extern int IOUSBDeviceControllerSetPreferredConfiguration(void *, int);

#ifndef OLSN0W_ROOT_MARKER_PATH
#define OLSN0W_ROOT_MARKER_PATH "/olsn0w/bootstrap.marker"
#endif
#ifndef OLSN0W_ROOT_MARKER
#define OLSN0W_ROOT_MARKER "olsn0w-bootstrap-v1"
#endif

#ifdef OLSN0W_RW_DEVICE
static char *const root_environment[] = {"PATH=/bin:/sbin:/usr/bin:/usr/sbin", "HOME=/var/root", 0};

static int prepare_disk_root(void) {
    int pid = 0, status = 0;
    char *mount[] = {"/sbin/mount", "-u", "-w", "-t", "hfs", OLSN0W_RW_DEVICE, "/", 0};
    int rc = posix_spawn(&pid, mount[0], 0, 0, mount, root_environment);
    if (rc || waitpid(pid, &status, 0) != pid || status) return 89;
    int fd = open("/var/log/root-start.stage", 0x601, 0600);
    if (fd < 0) return 89;
    const char value[] = "root-mounted-rw\n";
    write(fd, value, sizeof(value) - 1); close(fd); sync();
    return 0;
}
#endif

static int root_guard(void) {
    char marker[64] = {0};
    int fd = open(OLSN0W_ROOT_MARKER_PATH, 0);
    if (fd < 0) return 90;
    long n = read(fd, marker, sizeof(marker)-1); close(fd);
    const char expected[] = OLSN0W_ROOT_MARKER;
    if (n != sizeof(expected)-1 || strcmp(marker, expected)) return 91;
    char *args[] = {"root-check", "cache", 0};
    return native_check(2, args);
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "start") && strcmp(argv[1], "report"))) return 64;
#ifdef OLSN0W_RW_DEVICE
    int rc = prepare_disk_root();
    if (rc) return rc;
#else
    int rc = root_guard();
#endif
#ifdef OLSN0W_RW_DEVICE
    rc = root_guard();
#endif
    if (rc) return rc;
    printf("OLSN0W-ROOT32 mode=%s pid=%d parent=%d\n", argv[1], getpid(), getppid()); fflush(0);
    if (!strcmp(argv[1], "report")) return 0;
    /* Success of SSH startup implies launchd started this guarded child. */
    if (geteuid() != 0 || getppid() != 1) return 92;
    void *controller = 0;
    for (int i = 0; i < 30; i++) {
        rc = IOUSBDeviceControllerCreate(0, &controller);
        if (!rc && controller) break;
        sleep(1);
    }
    printf("OLSN0W-ROOT32 usb-controller=0x%x\n", rc); fflush(0);
    if (rc || !controller) return 93;
    void *description = IOUSBDeviceControllerCreateDefaultDescription(controller, 0);
    if (!description) return 94;
    void *mux = CFStringCreateWithCString(0, "AppleUSBMux", 0x08000100U);
    void *serial = CFStringCreateWithCString(0, OLSN0W_USB_SERIAL, 0x08000100U);
    if (!mux || !serial) return 95;
    IOUSBDeviceDescriptionRemoveAllConfigurations(description);
    int config = IOUSBDeviceDescriptionAppendConfigurationWithInterface(description, mux);
    if (config != 0) return 96;
    IOUSBDeviceDescriptionSetSerialString(description, serial);
    rc = IOUSBDeviceControllerSetDescription(controller, description);
    printf("OLSN0W-ROOT32 usb-description=0x%x\n", rc); fflush(0);
    if (rc) return 97;
    rc = IOUSBDeviceControllerSetPreferredConfiguration(controller, config+1);
    printf("OLSN0W-ROOT32 usb-preferred=0x%x\n", rc); fflush(0);
    if (rc) return 98;
    CFRelease(serial); CFRelease(mux); CFRelease(description); CFRelease(controller);
    int stage_fd = open("/var/log/root-start.stage", 0x601, 0600);
    if (stage_fd >= 0) {
        const char value[] = "root-usb-ready\n";
        write(stage_fd, value, sizeof(value) - 1); close(stage_fd); sync();
    }
    printf("OLSN0W-ROOT32 launchd-child-and-usb=PASS; starting SSH\n"); fflush(0);
    char *ssh[] = {"/sbin/sshd", "-D", "-e", "-f", "/olsn0w/sshd_config", 0};
    char *env[] = {"PATH=/bin:/sbin:/usr/bin:/usr/sbin", "HOME=/var/root", 0};
    execve(ssh[0], ssh, env);
    return 99;
}
