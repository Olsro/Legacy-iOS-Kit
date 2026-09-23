/* Wired A5 wake: kernel power notifications, not Darwin notify dispatch.
 * Register and arm BEFORE publishing readiness to the relay controller. */
#include "olsn0w_config.h"
typedef unsigned int io_object_t;
extern int strcmp(const char *, const char *);
extern int sysctlbyname(const char *, void *, unsigned int *, void *, unsigned int);
extern int printf(const char *, ...), fflush(void *);
extern int open(const char *, int, ...), close(int), unlink(const char *);
extern long write(int, const void *, unsigned long);
extern void sync(void);
extern void *CFNumberCreate(const void *, int, const void *);
extern void *CFStringCreateWithCString(const void *, const char *, unsigned int);
extern void CFRelease(const void *);
extern const void *kCFRunLoopDefaultMode;
extern void *CFRunLoopGetCurrent(void);
extern void CFRunLoopAddSource(void *, void *, const void *);
extern void CFRunLoopRemoveSource(void *, void *, const void *);
extern int CFRunLoopRunInMode(const void *, double, unsigned char);
extern void *IOServiceMatching(const char *);
extern io_object_t IOServiceGetMatchingService(unsigned int, void *);
extern int IORegistryEntrySetCFProperty(io_object_t, const void *, const void *);
extern int IOObjectRelease(io_object_t);
extern unsigned int IORegisterForSystemPower(void *, void **,
    void (*)(void *, io_object_t, unsigned int, void *), io_object_t *);
extern void *IONotificationPortGetRunLoopSource(void *);
extern int IOAllowPowerChange(unsigned int, long);
extern int IOCancelPowerChange(unsigned int, long);
extern int IODeregisterForSystemPower(io_object_t *);
extern void IONotificationPortDestroy(void *);
extern int IOServiceClose(unsigned int);

static unsigned int connection;
static const char *ready = "/var/run/olsn0w-wake.ready";

static int arm_wake(void) {
    io_object_t root = IOServiceGetMatchingService(0, IOServiceMatching("IOPMrootDomain"));
    int seconds = 8;
    void *value = CFNumberCreate(0, 9 /* kCFNumberIntType */, &seconds);
    void *key = CFStringCreateWithCString(0, "WakeRelativeToSleep", 0x08000100);
    int result = root && value && key ? IORegistryEntrySetCFProperty(root, key, value) : -1;
    printf("A5 relative wake: delay=%ds result=0x%x\n", seconds, result); fflush(0);
    if (key) CFRelease(key);
    if (value) CFRelease(value);
    if (root) IOObjectRelease(root);
    return result;
}

static void power_event(void *context, io_object_t service, unsigned int message, void *argument) {
    (void)context; (void)service;
    if (message == 0xe0000270 || message == 0xe0000280) {
        if (message == 0xe0000280 && arm_wake()) {
            unlink(ready);
            IOCancelPowerChange(connection, (long)argument);
            return;
        }
        sync();
        printf("A5 power event=0x%x acknowledge=0x%x\n", message,
               IOAllowPowerChange(connection, (long)argument)); fflush(0);
    }
}

int main(void) {
    char board[64] = {0}, release[64] = {0};
    unsigned int bn = sizeof(board)-1, rn = sizeof(release)-1;
    if (sysctlbyname("hw.model", board, &bn, 0, 0) ||
        sysctlbyname("kern.osrelease", release, &rn, 0, 0) ||
        strcmp(board, OLSN0W_BOARD) || strcmp(release, "14.0.0")) return 2;
    unlink(ready);
    void *port = 0, *source = 0;
    io_object_t notifier = 0;
    int result = 3;
    connection = IORegisterForSystemPower(0, &port, power_event, &notifier);
    if (!connection || !port) goto finish;
    source = IONotificationPortGetRunLoopSource(port);
    if (!source) goto finish;
    CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
    result = 4;
    if (arm_wake()) goto finish;
    result = 5;
    int fd = open(ready, 0x601, 0600);
    if (fd < 0) goto finish;
    long count = write(fd, "ready\n", 6);
    close(fd);
    if (count != 6) goto finish;
    sync();
    /* An initial awake notification must not consume the observer. */
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 720.0, 0);
    result = 6; /* Returning here means the relay never took over. */
finish:
    unlink(ready);
    if (notifier) IODeregisterForSystemPower(&notifier);
    if (source) CFRunLoopRemoveSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
    if (port) IONotificationPortDestroy(port);
    if (connection) IOServiceClose(connection);
    return result;
}
