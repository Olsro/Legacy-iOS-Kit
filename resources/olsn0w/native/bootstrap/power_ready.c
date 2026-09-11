#include "olsn0w_config.h"
#ifndef OLSN0W_BOARD
#error Compile for an explicitly validated board
#endif
typedef unsigned int size_t;
typedef unsigned int io_object_t;
typedef struct { unsigned int tv_sec; int tv_nsec; } mach_timespec_t;
extern int printf(const char *, ...);
extern int strcmp(const char *, const char *);
extern int sysctlbyname(const char *, void *, size_t *, void *, size_t);
extern int IOKitWaitQuiet(unsigned int, mach_timespec_t *);
extern void *IOServiceMatching(const char *);
extern io_object_t IOServiceGetMatchingService(unsigned int, void *);
extern int IORegistryEntrySetCFProperty(io_object_t, const void *, const void *);
extern int IOObjectRelease(io_object_t);
extern void *CFStringCreateWithCString(const void *, const char *, unsigned int);
extern const void *kCFBooleanTrue;
extern void CFRelease(const void *);

static int matches(const char *name, const char *expected) {
    char text[64] = {0}; size_t n = sizeof(text) - 1;
    return !sysctlbyname(name, text, &n, 0, 0) && !strcmp(text, expected);
}

int main(int argc, char **argv) {
    int complete = argc == 2 && !strcmp(argv[1], "--complete");
    if (argc != 2 || (!complete && strcmp(argv[1], "--check"))) return 2;
    if (!matches("hw.model", OLSN0W_BOARD) || !matches("kern.osrelease", "14.0.0")) return 3;
    mach_timespec_t timeout = {10, 0};
    int result = IOKitWaitQuiet(0, &timeout);
    printf("IOKitWaitQuiet: 0x%x\n", result);
    if (result) return 4;
    io_object_t root = IOServiceGetMatchingService(0, IOServiceMatching("IOPMrootDomain"));
    if (!root) return 5;
    if (complete) {
        void *key = CFStringCreateWithCString(0, "System Boot Complete", 0x08000100);
        if (!key) { IOObjectRelease(root); return 6; }
        result = IORegistryEntrySetCFProperty(root, key, kCFBooleanTrue);
        CFRelease(key);
        printf("Headless bootstrap: System Boot Complete = 0x%x\n", result);
    }
    IOObjectRelease(root);
    return result ? 7 : 0;
}
