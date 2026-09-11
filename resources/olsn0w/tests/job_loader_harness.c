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
int main(void) {
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
    return 0;
}
