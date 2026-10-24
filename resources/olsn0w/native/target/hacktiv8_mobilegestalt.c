typedef unsigned long usize;
typedef long index_t;

extern void *fopen(const char *, const char *);
extern int fclose(void *), fseek(void *, long, int), fflush(void *);
extern long ftell(void *);
extern usize fread(void *, usize, usize, void *);
extern usize fwrite(const void *, usize, usize, void *);
extern void *malloc(usize);
extern void free(void *);
extern int snprintf(char *, usize, const char *, ...);
extern int chmod(const char *, unsigned short);
extern int chown(const char *, unsigned int, unsigned int);
extern unsigned int geteuid(void);
extern int rename(const char *, const char *);
extern int remove(const char *);
extern int strcmp(const char *, const char *);

extern void *CFDataCreate(const void *, const unsigned char *, index_t);
extern index_t CFDataGetLength(const void *);
extern const unsigned char *CFDataGetBytePtr(const void *);
extern void *CFPropertyListCreateWithData(const void *, const void *, usize,
                                          void *, void *);
extern void *CFPropertyListCreateData(const void *, const void *, long,
                                      usize, void *);
extern usize CFGetTypeID(const void *);
extern usize CFDictionaryGetTypeID(void);
extern const void *CFDictionaryGetValue(const void *, const void *);
extern void CFDictionarySetValue(void *, const void *, const void *);
extern void *CFStringCreateWithCString(const void *, const char *,
                                       unsigned int);
extern void CFRelease(const void *);
extern const void *kCFBooleanTrue;

static int read_file(const char *path, unsigned char **bytes, long *size) {
    void *file = fopen(path, "rb");
    if (!file) return -1;
    if (fseek(file, 0, 2)) { fclose(file); return -1; }
    *size = ftell(file);
    if (*size <= 0 || *size > 8 * 1024 * 1024 || fseek(file, 0, 0)) {
        fclose(file); return -1;
    }
    *bytes = malloc((usize)*size);
    if (!*bytes || fread(*bytes, 1, (usize)*size, file) != (usize)*size) {
        free(*bytes); *bytes = 0; fclose(file); return -1;
    }
    fclose(file);
    return 0;
}

static int write_file(const char *path, const void *data) {
    char temporary[4096];
    int name_size = snprintf(temporary, sizeof(temporary),
                             "%s.hacktiv8-new", path);
    if (name_size < 0 || (usize)name_size >= sizeof(temporary))
        return -1;
    void *file = fopen(temporary, "wb");
    if (!file) return -1;
    index_t size = CFDataGetLength(data);
    int result = (size <= 0 ||
                  fwrite(CFDataGetBytePtr(data), 1, (usize)size, file) != (usize)size);
    if (fflush(file)) result = 1;
    if (fclose(file)) result = 1;
    if (result) { remove(temporary); return -1; }
    if (chmod(temporary, 0644) || (geteuid() == 0 && chown(temporary, 501, 501)) ||
            rename(temporary, path)) {
        remove(temporary); return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 2;
    int check_only = argc == 3 && !strcmp(argv[1], "--check");
    unsigned char *bytes = 0;
    long size = 0;
    void *data = 0, *plist = 0, *cache_key = 0, *flag_key = 0, *serialized = 0;
    int result = 10;
    if (read_file(argc == 3 ? argv[2] : argv[1], &bytes, &size)) goto done;
    result = 11;
    data = CFDataCreate(0, bytes, size);
    if (!data) goto done;
    result = 12;
    plist = CFPropertyListCreateWithData(0, data, 2, 0, 0);
    if (!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) goto done;
    result = 13;
    cache_key = CFStringCreateWithCString(0, "CacheExtra", 0x08000100);
    flag_key = CFStringCreateWithCString(0, "a6vjPkzcRjrsXmniFsm0dg", 0x08000100);
    if (!cache_key || !flag_key) goto done;
    result = 14;
    void *cache = (void *)CFDictionaryGetValue(plist, cache_key);
    if (!cache || CFGetTypeID(cache) != CFDictionaryGetTypeID()) goto done;
    if (check_only) {
        result = CFDictionaryGetValue(cache, flag_key) == kCFBooleanTrue ? 0 : 17;
        goto done;
    }
    CFDictionarySetValue(cache, flag_key, kCFBooleanTrue);
    result = 15;
    serialized = CFPropertyListCreateData(0, plist, 200, 0, 0);
    if (!serialized) goto done;
    result = 16;
    if (write_file(argv[1], serialized)) goto done;
    result = 0;
done:
    if (serialized) CFRelease(serialized);
    if (flag_key) CFRelease(flag_key);
    if (cache_key) CFRelease(cache_key);
    if (plist) CFRelease(plist);
    if (data) CFRelease(data);
    free(bytes);
    return result;
}
