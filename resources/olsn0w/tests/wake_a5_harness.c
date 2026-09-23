#define main wake_program
#include "../native/bootstrap/wake_a5.c"
#undef main
#include <assert.h>
#include <string.h>

const void *kCFRunLoopDefaultMode=(void *)1;
static void (*callback)(void *, io_object_t, unsigned int, void *);
static int scenario, arms, registered, published, acknowledgements, cancellations;
static int seconds;
int sysctlbyname(const char *name, void *out, unsigned int *size, void *in, unsigned int n) {
    (void)size; (void)in; (void)n;
    strcpy(out, !strcmp(name,"hw.model") ? (scenario==1?"WRONG":"TESTAP") : "14.0.0"); return 0;
}
int unlink(const char *p) { (void)p; published=0; return 0; }
int open(const char *p,int flags,...) { (void)p;(void)flags; assert(registered && arms==1);return 10; }
int close(int fd) { (void)fd;return 0; }
long write(int fd,const void *data,unsigned long n) {
    (void)fd;assert(n==6 && !memcmp(data,"ready\n",6));
    if(scenario==4)return 5;
    published=1;return n;
}
void sync(void) {}
void *CFNumberCreate(const void *a,int type,const void *value) {
    (void)a;assert(type==9);seconds=*(const int *)value;return &seconds;
}
void *CFStringCreateWithCString(const void *a,const char *s,unsigned int encoding) {
    (void)a;(void)encoding;assert(!strcmp(s,"WakeRelativeToSleep"));return (void *)s;
}
void CFRelease(const void *p) {(void)p;}
void *IOServiceMatching(const char *s) {assert(!strcmp(s,"IOPMrootDomain"));return (void *)1;}
io_object_t IOServiceGetMatchingService(unsigned int p,void *d) {(void)p;(void)d;return 4;}
int IORegistryEntrySetCFProperty(io_object_t root,const void *key,const void *value) {
    (void)root;(void)key;assert(*(int *)value==8);arms++;
    return scenario==3 || (scenario==5 && arms==2) ? -1:0;
}
int IOObjectRelease(io_object_t o) {(void)o;return 0;}
unsigned int IORegisterForSystemPower(void *c,void **port,
    void (*cb)(void *,io_object_t,unsigned int,void *),io_object_t *notifier) {
    (void)c;if(scenario==2)return 0;
    callback=cb;*port=(void *)1;*notifier=2;registered=1;return 3;
}
void *IONotificationPortGetRunLoopSource(void *p) {(void)p;return (void *)2;}
void *CFRunLoopGetCurrent(void) {return (void *)3;}
void CFRunLoopAddSource(void *l,void *s,const void *m) {(void)l;(void)s;(void)m;}
void CFRunLoopRemoveSource(void *l,void *s,const void *m) {(void)l;(void)s;(void)m;}
int CFRunLoopRunInMode(const void *m,double timeout,unsigned char once) {
    (void)m;assert(timeout==720.0 && !once && published);
    callback(0,0,0xe0000300,0);assert(arms==1); /* awake is not sleep */
    callback(0,0,0xe0000270,(void *)17);assert(arms==1);
    callback(0,0,0xe0000280,(void *)18);assert(arms==2);
    return 0;
}
int IOAllowPowerChange(unsigned int c,long token) {assert(c==3 && (token==17 || token==18));acknowledgements++;return 0;}
int IOCancelPowerChange(unsigned int c,long token) {assert(c==3 && token==18);cancellations++;return 0;}
int IODeregisterForSystemPower(io_object_t *p) {(void)p;registered=0;return 0;}
void IONotificationPortDestroy(void *p) {(void)p;}
int IOServiceClose(unsigned int p) {(void)p;return 0;}
int main(void) {
    for(scenario=0;scenario<=5;scenario++) {
        arms=registered=published=acknowledgements=cancellations=0;connection=0;
        int rc=wake_program();assert(rc && !registered && !published);
        if(scenario==0)assert(arms==2 && acknowledgements==2 && !cancellations);
        if(scenario==1 || scenario==2)assert(!arms);
        if(scenario==3 || scenario==4)assert(arms==1 && !acknowledgements);
        if(scenario==5)assert(arms==2 && acknowledgements==1 && cancellations==1);
    }
    printf("A5 wake readiness, callbacks and failure guards passed\n");return 0;
}
