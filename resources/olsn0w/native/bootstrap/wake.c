#include "olsn0w_config.h"
#ifndef OLSN0W_BOARD
#error Compile for an explicitly validated board
#endif
extern int strcmp(const char *, const char *);
extern int sysctlbyname(const char *, void *, unsigned int *, void *, unsigned int);
extern int printf(const char *, ...);
extern int fflush(void *);
extern int open(const char *, int, ...);
extern long write(int, const void *, unsigned long);
extern int close(int);
extern int unlink(const char *);
extern double CFAbsoluteTimeGetCurrent(void);
extern void *CFDateCreate(const void *, double);
extern void *CFStringCreateWithCString(const void *, const char *, unsigned int);
extern void CFRelease(const void *);
extern const void *kCFRunLoopDefaultMode;
extern void *CFRunLoopGetCurrent(void);
extern void CFRunLoopStop(void *);
extern int CFRunLoopRunInMode(const void *, double, unsigned char);
extern int IOPMSchedulePowerEvent(const void *, const void *, const void *);
extern char _dispatch_main_q;
extern unsigned int notify_register_dispatch(const char *, int *, void *, void (^)(int));
extern unsigned int notify_cancel(int);

static int result = 5;
static const char *ready = "/var/run/olsn0w-wake.ready";

int main(void) {
    char board[64] = {0}, release[64] = {0};
    unsigned int bn = sizeof(board) - 1, rn = sizeof(release) - 1;
    if (sysctlbyname("hw.model", board, &bn, 0, 0) ||
        sysctlbyname("kern.osrelease", release, &rn, 0, 0) ||
        strcmp(board, OLSN0W_BOARD) || strcmp(release, "14.0.0")) return 6;
    int token = 0;
    unlink(ready);
    unsigned int status = notify_register_dispatch(
        "com.apple.powermanagement.systempowerstate", &token, &_dispatch_main_q, ^(int delivered) {
            (void)delivered;
            void *date = CFDateCreate(0, CFAbsoluteTimeGetCurrent() + 5.0);
            void *type = CFStringCreateWithCString(0, "WakeRelativeToSleep", 0x08000100);
            int kr = (date && type) ? IOPMSchedulePowerEvent(date, 0, type) : -1;
            printf("Sleep notification: IOPMSchedulePowerEvent=0x%x, delay=5s\n", kr);
            fflush(0);
            if (type) CFRelease(type);
            if (date) CFRelease(date);
            result = kr ? 4 : 0;
            /* Stay registered for 30s: an initial awake-state notification
             * must not consume the observer before the sleep transition. */
        });
    if (status) {
        printf("notify_register_dispatch failed: 0x%x\n", status);
        return 2;
    }
    int fd = open(ready, 0x601 /* O_WRONLY | O_CREAT | O_TRUNC */, 0600);
    if (fd < 0) { notify_cancel(token); return 3; }
    long written = write(fd, "ready\n", 6);
    close(fd);
    if (written != 6) { unlink(ready); notify_cancel(token); return 3; }
    printf("Registered sleep observer; timeout=30s\n");
    fflush(0);
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 30.0, 0);
    notify_cancel(token);
    unlink(ready);
    if (result == 5) printf("No sleep notification before timeout\n");
    return result;
}
