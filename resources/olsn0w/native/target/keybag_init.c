/* Initialize a fresh target keybag after guard-target.sh has checked its mounts.
 * Existing keybags are retained. This is never an erase or reset operation. */
extern int open(const char *, int, ...), close(int), getuid(void), printf(const char *, ...);
extern void *dlopen(const char *, int), *dlsym(void *, const char *);
extern int dlclose(void *);
extern unsigned int IORegistryEntryFromPath(unsigned int, const char *);
extern void *IORegistryEntryCreateCFProperty(unsigned int, const void *, const void *, unsigned int);
extern int IOObjectRelease(unsigned int);
extern void *CFStringCreateWithCString(const void *, const char *, unsigned int);
extern unsigned long CFGetTypeID(const void *), CFDataGetTypeID(void);
extern long CFDataGetLength(const void *);
extern const unsigned char *CFDataGetBytePtr(const void *);
extern void CFRelease(const void *);
static int exists(void) {
    int fd = open("/private/var/keybags/systembag.kb", 0);
    if (fd < 0) return 0;
    close(fd); return 1;
}
int main(void) {
    if (getuid()) return 1;
    if (exists()) return 0;
    unsigned int entry = IORegistryEntryFromPath(0, "IODeviceTree:/defaults");
    if (!entry) return 5;
    void *key = CFStringCreateWithCString(0, "no-effaceable-storage", 0x08000100);
    void *value = key ? IORegistryEntryCreateCFProperty(entry, key, 0, 0) : 0;
    int protected = 0;
    if (value && CFGetTypeID(value) == CFDataGetTypeID() && CFDataGetLength(value) == 4) {
        const unsigned char *p = CFDataGetBytePtr(value);
        protected = (p[0] | p[1] | p[2] | p[3]) != 0;
    }
    if (value) CFRelease(value);
    if (key) CFRelease(key);
    IOObjectRelease(entry);
    if (!protected) return 6;
    void *framework = dlopen("/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag", 1);
    if (!framework) return 2;
    int (*create)(int, char *) = dlsym(framework, "MKBKeyBagCreateSystem");
    if (!create) { dlclose(framework); return 3; }
    int result = create(0, "/private/var");
    int ready = exists();
    printf("olsn0w: keybag initialization result=%d present=%d\n", result, ready);
    dlclose(framework);
    return ready ? 0 : 4;
}
