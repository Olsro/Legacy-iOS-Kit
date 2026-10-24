#define main loader_program_main
#include "../native/target/load_jobs.c"
#undef main
/* A job dictionary can describe a running, stopped or demand-start job.
 * No PID-dependent assumption is allowed; transport failure is not absence. */
static int response_type, response_error, unavailable;
void *launch_data_alloc(int t) { (void)t; return (void *)1; }
void *launch_data_new_string(const char *s) { (void)s; return (void *)2; }
unsigned char launch_data_dict_insert(void *a, const void *b, const char *k) {
    (void)a; (void)b; (void)k; return 1;
}
void launch_data_free(void *p) { (void)p; }
void *launch_msg(const void *p) { (void)p; return unavailable ? 0 : (void *)3; }
int launch_data_get_type(const void *p) { (void)p; return response_type; }
int launch_data_get_errno(const void *p) { (void)p; return response_error; }

/* Exercise actual plist/override precedence without needing CoreFoundation
 * on the host. The objects below model just dictionaries, strings and bools. */
extern int strcmp(const char *, const char *);
struct object {
    usize type;
    const char *text;
    int boolean;
    struct object *disabled, *entry;
};
usize CFDictionaryGetTypeID(void) { return 1; }
usize CFStringGetTypeID(void) { return 2; }
usize CFBooleanGetTypeID(void) { return 3; }
usize CFGetTypeID(const void *p) { return ((const struct object *)p)->type; }
unsigned char CFBooleanGetValue(const void *p) { return ((const struct object *)p)->boolean; }
void *CFStringCreateWithCString(const void *a, const char *text, unsigned int encoding) {
    static struct object keys[4];
    static unsigned int next;
    (void)a; (void)encoding;
    struct object *key = &keys[(next++) % 4];
    key->type=2; key->text=text;
    return key;
}
const void *CFDictionaryGetValue(const void *p, const void *k) {
    const struct object *dictionary=p, *key=k;
    return !strcmp(key->text, "Disabled") ? dictionary->disabled : dictionary->entry;
}
void CFRelease(const void *p) { (void)p; }

/* Exercise real file opening/length checks; the parser stub distinguishes
 * valid dictionaries, other plist types and malformed nonempty data. */
#ifdef __linux__
extern int *__errno_location(void);
int *__error(void) { return __errno_location(); }
#endif
static struct object parsed_dictionary={1,0,0,0,0}, parsed_array={4,0,0,0,0};
static int parser_called;
void *CFDataCreate(const void *allocator, const unsigned char *bytes, index_t size) {
    (void)allocator; (void)size;
    return (void *)bytes;
}
void *CFPropertyListCreateWithData(const void *allocator, const void *data,
                                 usize options, void *format, void *error) {
    (void)allocator; (void)options; (void)format; (void)error;
    parser_called=1;
    return *(const char *)data=='D' ? &parsed_dictionary :
           *(const char *)data=='A' ? &parsed_array : 0;
}

int main(int argc, char **argv) {
    if (argc==4) {
        void *result=(void *)1;
        int status=read_dictionary(argv[1],&result,argv[2][0]=='1');
        if (!strcmp(argv[3],"empty"))
            return status==0 && !result && !parser_called ? 0 : 20;
        if (!strcmp(argv[3],"dictionary"))
            return status==0 && result==&parsed_dictionary && parser_called ? 0 : 21;
        return status==-1 && !result ? 0 : 22;
    }
    response_type=1;
    if (registered("registered-without-pid") != 1) return 1;
    response_type=9; response_error=3;
    if (registered("missing") != 0) return 2;
    response_error=1;
    if (registered("permission-denied") != -1) return 3;
    response_error=0;
    if (registered("unexpected-success-response") != -1) return 4;
    response_type=7;
    if (registered("malformed-response") != -1) return 5;
    unavailable=1;
    if (registered("disconnected-launchd") != -1) return 6;
    struct object yes={3,0,1,0,0}, no={3,0,0,0,0}, invalid={2,"true",0,0,0};
    struct object job={1,0,0,0,0}, override={1,0,0,0,0}, overrides={1,0,0,0,&override};
    if (disabled_for(&job, 0, "default-enabled") != 0) return 7;
    job.disabled=&yes;
    if (disabled_for(&job, 0, "plist-disabled") != 1) return 8;
    override.disabled=&no;
    if (disabled_for(&job, &overrides, "explicitly-enabled") != 0) return 9;
    job.disabled=&no; override.disabled=&yes;
    if (disabled_for(&job, &overrides, "persistently-disabled") != 1) return 10;
    override.disabled=0; job.disabled=&yes;
    if (disabled_for(&job, &overrides, "override-without-setting") != 1) return 11;
    overrides.entry=&invalid;
    if (disabled_for(&job, &overrides, "malformed-override") != -1) return 12;
    overrides.entry=&override; override.disabled=&invalid;
    if (disabled_for(&job, &overrides, "malformed-disabled") != -1) return 13;
    job.disabled=&invalid;
    if (disabled_for(&job, 0, "malformed-plist-disabled") != -1) return 14;
    return 0;
}
