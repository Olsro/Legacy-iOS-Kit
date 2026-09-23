/* A5 bootstrap diagnostic. --inspect is read-only; --observe arms a wake
 * and records kernel power notifications without requesting sleep itself. */
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/sysctl.h>

typedef mach_port_t io_object_t;
typedef void *IONotificationPortRef;
extern CFMutableDictionaryRef IOServiceMatching(const char *);
extern io_object_t IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);
extern kern_return_t IORegistryEntryCreateCFProperties(io_object_t, CFMutableDictionaryRef *, CFAllocatorRef, uint32_t);
extern kern_return_t IORegistryEntrySetCFProperty(io_object_t, CFStringRef, CFTypeRef);
extern kern_return_t IOObjectRelease(io_object_t);
extern mach_port_t IORegisterForSystemPower(void *, IONotificationPortRef *, void (*)(void *, io_object_t, uint32_t, void *), io_object_t *);
extern CFRunLoopSourceRef IONotificationPortGetRunLoopSource(IONotificationPortRef);
extern kern_return_t IOAllowPowerChange(mach_port_t, long);
extern kern_return_t IODeregisterForSystemPower(io_object_t *);
extern void IONotificationPortDestroy(IONotificationPortRef);
extern kern_return_t IOServiceClose(mach_port_t);
extern mach_port_t IOPMFindPowerManagement(mach_port_t);
extern kern_return_t IOPMSleepSystem(mach_port_t);

static mach_port_t connection;
static const char *ready = "/var/run/olsn0w-wake.ready";
static unsigned int messages;

static int exact_ready(void) {
    char data[7] = {0};
    int fd = open(ready, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, data, sizeof(data));
    close(fd);
    return n == 6 && !memcmp(data, "ready\n", 6);
}

static int relay_gate(void) {
    const char *trigger = "/var/run/olsn0w-relay-go";
    if (unlink(trigger) && errno != ENOENT) return 10;
    printf("POWER-PROBE native gate waiting 600 seconds for host trigger\n");
    for (int i = 0; i < 600; ++i) {
        if (!access(trigger, F_OK) && exact_ready()) {
            printf("POWER-PROBE armed host trigger accepted\n");
            fflush(stdout); sync();
            execl("/usr/local/bin/4smulti_kloader", "4smulti_kloader",
                  "/olsn0w/iBSS.raw", "/olsn0w/iBEC.probe.img3", (char *)NULL);
            printf("POWER-PROBE loader exec failed errno=%d\n", errno);
            return 11;
        }
        sleep(1);
    }
    printf("POWER-PROBE gate timed out; loader not executed\n");
    return 12;
}

static void snapshot(const char *name) {
    io_object_t service = IOServiceGetMatchingService(0, IOServiceMatching(name));
    CFMutableDictionaryRef properties = NULL;
    kern_return_t kr = service ? IORegistryEntryCreateCFProperties(service, &properties, NULL, 0) : -1;
    printf("POWER-PROBE snapshot=%s result=0x%x time=%.3f\n", name, kr, CFAbsoluteTimeGetCurrent());
    if (properties) {
        CFDataRef xml = CFPropertyListCreateXMLData(NULL, properties);
        if (xml) { fwrite(CFDataGetBytePtr(xml), 1, CFDataGetLength(xml), stdout); CFRelease(xml); }
        CFRelease(properties);
    }
    if (service) IOObjectRelease(service);
    fflush(stdout);
}

static int arm_wake(void) {
    /* Set the relative-seconds root-domain property directly: the historical
     * IOPMSchedulePowerEvent wrapper discards this operation's return code. */
    io_object_t root = IOServiceGetMatchingService(0, IOServiceMatching("IOPMrootDomain"));
    int seconds = 8;
    CFNumberRef value = CFNumberCreate(NULL, kCFNumberIntType, &seconds);
    kern_return_t kr = (root && value) ? IORegistryEntrySetCFProperty(root, CFSTR("WakeRelativeToSleep"), value) : -1;
    printf("POWER-PROBE arm-relative-wake seconds=%d result=0x%x time=%.3f\n", seconds, kr, CFAbsoluteTimeGetCurrent());
    if (value) CFRelease(value);
    if (root) IOObjectRelease(root);
    fflush(stdout);
    return kr;
}

/* Negative control: same power transition, no kernel mapping or wake-vector
 * writes. Invoke only from the host while the separate observer is ready. */
static int sleep_control(void) {
    if (!exact_ready()) return 20;
    mach_port_t root = IOPMFindPowerManagement(0);
    if (!root) return 21;
    if (arm_wake()) { IOServiceClose(root); return 22; }
    printf("POWER-PROBE CONTROL requesting sleep; this command leaves existing relay state unchanged time=%.3f\n",
           CFAbsoluteTimeGetCurrent());
    fflush(stdout); sync();
    kern_return_t kr = IOPMSleepSystem(root);
    printf("POWER-PROBE CONTROL sleep-request result=0x%x time=%.3f\n",
           kr, CFAbsoluteTimeGetCurrent());
    fflush(stdout); sync();
    IOServiceClose(root);
    return kr ? 23 : 0;
}

static void power_event(void *context, io_object_t service, uint32_t message, void *argument) {
    (void)context; (void)service;
    ++messages;
    printf("POWER-PROBE notification=0x%x token=%ld time=%.3f\n", message, (long)argument, CFAbsoluteTimeGetCurrent());
    fflush(stdout);
    if (message == 0xe0000270 || message == 0xe0000280) {
        /* CanSystemSleep / SystemWillSleep both require acknowledgement. */
        if (message == 0xe0000280) arm_wake();
        sync();
        kern_return_t kr = IOAllowPowerChange(connection, (long)argument);
        printf("POWER-PROBE acknowledge=0x%x\n", kr);
        fflush(stdout);
    }
}

int main(int argc, char **argv) {
    char board[64] = {0}, release[64] = {0};
    size_t bn = sizeof(board), rn = sizeof(release);
    if (sysctlbyname("hw.model", board, &bn, NULL, 0) ||
        sysctlbyname("kern.osrelease", release, &rn, NULL, 0) ||
        strcmp(board, "N78AP") || strcmp(release, "14.0.0")) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--gate")) return relay_gate();
    if (argc == 2 && !strcmp(argv[1], "--sleep-control")) return sleep_control();
    int observe = argc == 2 && !strcmp(argv[1], "--observe");
    if (argc != 2 || (!observe && strcmp(argv[1], "--inspect"))) return 2;
    snapshot("IOPMrootDomain");
    snapshot("AppleARMPMUCharger");
    snapshot("AppleARMPMUPowerSource");
    if (!observe) return 0;
    unlink(ready);
    IONotificationPortRef port = NULL;
    io_object_t notifier = 0;
    connection = IORegisterForSystemPower(NULL, &port, power_event, &notifier);
    printf("POWER-PROBE register connection=0x%x notifier=0x%x\n", connection, notifier);
    if (!connection || !port) return 3;
    CFRunLoopSourceRef source = IONotificationPortGetRunLoopSource(port);
    if (!source) return 4;
    CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
    if (arm_wake()) return 5;
    int fd = open(ready, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 6;
    ssize_t count = write(fd, "ready\n", 6);
    close(fd);
    if (count != 6) return 7;
    sync();
    for (int i = 0; i < 144; ++i) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 5.0, false);
        printf("POWER-PROBE heartbeat=%d notifications=%u time=%.3f\n", i, messages, CFAbsoluteTimeGetCurrent());
        fflush(stdout);
        if (i == 2 || i == 5 || i == 143) snapshot("IOPMrootDomain");
        sync();
    }
    unlink(ready);
    IODeregisterForSystemPower(&notifier);
    CFRunLoopRemoveSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
    IONotificationPortDestroy(port);
    IOServiceClose(connection);
    return messages ? 0 : 8;
}
