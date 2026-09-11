/* Load only jobs that launchd has not registered. Re-loading an existing job
 * can unlink its live Unix socket before launchd rejects the duplicate. */
typedef unsigned long usize;
typedef long index_t;
extern void *fopen(const char *, const char *);
extern int fclose(void *), fseek(void *, long, int);
extern long ftell(void *);
extern usize fread(void *, usize, usize, void *);
extern void *malloc(usize);
extern void free(void *);
extern int fprintf(void *, const char *, ...);
extern void *__stderrp;
extern int fork(void), execv(const char *, char *const *), waitpid(int, int *, int);
extern void _exit(int);
extern int *__error(void);
extern void *CFDataCreate(const void *, const unsigned char *, index_t);
extern void *CFPropertyListCreateWithData(const void *, const void *, usize, void *, void *);
extern usize CFGetTypeID(const void *), CFDictionaryGetTypeID(void), CFStringGetTypeID(void);
extern const void *CFDictionaryGetValue(const void *, const void *);
extern void *CFStringCreateWithCString(const void *, const char *, unsigned int);
extern unsigned char CFStringGetCString(const void *, char *, index_t, unsigned int);
extern void CFRelease(const void *);
extern void *launch_data_alloc(int), *launch_data_new_string(const char *), *launch_msg(const void *);
extern unsigned char launch_data_dict_insert(void *, const void *, const char *);
extern void launch_data_free(void *);
extern int launch_data_get_type(const void *), launch_data_get_errno(const void *);

static int label_for(const char *path, char *label, usize capacity) {
    void *file = fopen(path, "rb"), *data = 0, *plist = 0, *key = 0;
    unsigned char *bytes = 0;
    int result = -1;
    if (!file) return -1;
    if (fseek(file, 0, 2)) goto done;
    long size = ftell(file);
    if (size <= 0 || size > 4 * 1024 * 1024 || fseek(file, 0, 0)) goto done;
    bytes = malloc((usize)size);
    if (!bytes || fread(bytes, 1, (usize)size, file) != (usize)size) goto done;
    data = CFDataCreate(0, bytes, size);
    if (!data) goto done;
    plist = CFPropertyListCreateWithData(0, data, 0, 0, 0);
    if (!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) goto done;
    key = CFStringCreateWithCString(0, "Label", 0x08000100);
    if (!key) goto done;
    const void *value = CFDictionaryGetValue(plist, key);
    if (value && CFGetTypeID(value) == CFStringGetTypeID() &&
        CFStringGetCString(value, label, (index_t)capacity, 0x08000100) && label[0]) result = 0;
done:
    if (key) CFRelease(key);
    if (plist) CFRelease(plist);
    if (data) CFRelease(data);
    free(bytes);
    fclose(file);
    return result;
}

/* 1 includes registered jobs without a running PID; 0 means absent.
 * Transport and malformed responses must never trigger a speculative load. */
static int registered(const char *label) {
    void *request = launch_data_alloc(1), *name = launch_data_new_string(label);
    if (!request || !name) {
        if (request) launch_data_free(request);
        if (name) launch_data_free(name);
        return -1;
    }
    if (!launch_data_dict_insert(request, name, "GetJob")) {
        launch_data_free(name); launch_data_free(request); return -1;
    }
    void *response = launch_msg(request);
    launch_data_free(request);
    if (!response) return -1;
    int type = launch_data_get_type(response);
    int result = type == 1 ? 1 : (type == 9 && launch_data_get_errno(response) == 3 ? 0 : -1);
    launch_data_free(response);
    return result;
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    char **args = malloc(((usize)argc + 2) * sizeof(*args));
    if (!args) return 1;
    int count = 2;
    args[0] = "/bin/launchctl";
    args[1] = "load";
    for (int i = 1; i < argc; ++i) {
        char label[1024];
        if (label_for(argv[i], label, sizeof(label))) {
            fprintf(__stderrp, "olsn0w: invalid job plist: %s\n", argv[i]);
            free(args); return 1;
        }
        int state = registered(label);
        if (state < 0) {
            fprintf(__stderrp, "olsn0w: cannot query job: %s\n", label);
            free(args); return 1;
        }
        if (!state) args[count++] = argv[i];
    }
    args[count] = 0;
    if (count == 2) { free(args); return 0; }
    fprintf(__stderrp, "OLSN-BATCH submitting %d missing jobs\n", count - 2);
    execv(args[0], args);
    fprintf(__stderrp, "olsn0w: cannot execute launchctl\n");
    free(args); return 1;
}
