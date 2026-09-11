#include "olsn0w_config.h"
#define main native_check
#include "cache_check.c"
#undef main
extern int open(const char *,int,...),close(int),geteuid(void),getgid(void);
extern long read(int,void *,unsigned long);
extern unsigned int mach_task_self_;
extern int task_for_pid(unsigned int,int,unsigned int *),mach_port_deallocate(unsigned int,unsigned int);
extern int posix_spawn(int *,const char *,const void *,const void *,char *const *,char *const *);
extern int waitpid(int,int *,int),usleep(unsigned int),kill(int,int),write(int,const void *,unsigned long);
extern void sync(void);
extern int pipe(int *), fcntl(int, int, ...);
extern int posix_spawn_file_actions_init(void **), posix_spawn_file_actions_destroy(void **);
extern int posix_spawn_file_actions_addclose(void **, int), posix_spawn_file_actions_adddup2(void **, int, int);
#include "patch_completion.h"
static int signal_ready(int fd) {
    if (fd < 0) return 0;
    int ok = write(fd, "R", 1) == 1;
    close(fd);
    return ok ? 0 : 70;
}
#ifndef OLSN0W_UNTETHER_MARKER_PATH
#define OLSN0W_UNTETHER_MARKER_PATH "/olsn0w/UNTETHER-RAM-ONLY"
#endif
#ifndef OLSN0W_UNTETHER_MARKER
#define OLSN0W_UNTETHER_MARKER "kernel-only50"
#endif
static void held_stage(const char *value) {
    int fd=open("/var/log/held.stage",0x601,0600);if(fd<0)return;
    unsigned long n=0;while(value[n])n++;write(fd,value,n);write(fd,"\n",1);close(fd);sync();
}
int main(int argc, char **argv) {
    int ready_fd = -1;
    if (argc == 2 && !strcmp(argv[1], "--ready-fd=3")) ready_fd = 3;
    else if (argc != 1) return 64;
    char marker[32]={0};int fd=open(OLSN0W_UNTETHER_MARKER_PATH,0);
    if(fd<0 || geteuid()!=0 || getgid()!=0)return 65;
    long n=read(fd,marker,31);close(fd);
    const char expected[]=OLSN0W_UNTETHER_MARKER;
    if(n!=(long)(sizeof(expected)-1) || strcmp(marker,expected))return 65;
    char *check[]={"held-control","cache",0};if(native_check(2,check))return 66;
    held_stage("held-guard-pass");
    unsigned int port=0;if(!task_for_pid(mach_task_self_,0,&port) && port){mach_port_deallocate(mach_task_self_,port);printf("OLSN0W-HELD ALREADY_READY\n");return signal_ready(ready_fd);}
    int pid=0,status=0;char *child[]={"/olsn0w/untether-held",0};char *env[]={"PATH=/bin:/sbin:/usr/bin:/usr/sbin",0};
    int output[2];
    if (pipe(output)) return 70;
    if (fcntl(output[0], 4, 4) < 0 || fcntl(output[0], 2, 1) < 0) {
        close(output[0]); close(output[1]); return 70;
    }
    void *actions = 0;
    int rc = posix_spawn_file_actions_init(&actions);
    if (!rc) {
        rc = posix_spawn_file_actions_addclose(&actions, output[0]);
        if (!rc) rc = posix_spawn_file_actions_adddup2(&actions, output[1], 1);
        if (!rc) rc = posix_spawn_file_actions_adddup2(&actions, output[1], 2);
        if (!rc && output[1] > 2) rc = posix_spawn_file_actions_addclose(&actions, output[1]);
        if (!rc && ready_fd >= 0 && ready_fd != output[0] && ready_fd != output[1])
            rc = posix_spawn_file_actions_addclose(&actions, ready_fd);
        if (!rc) rc = posix_spawn(&pid, child[0], &actions, 0, child, env);
        posix_spawn_file_actions_destroy(&actions);
    }
    close(output[1]);
    if (rc) { close(output[0]); return 67; }
    struct patch_completion completion = {0};
printf("OLSN0W-HELD spawn=%d pid=%d\n",rc,pid);fflush(0);if(rc)return 67;
    held_stage("held-child-spawned");
    for(int i=0;i<200;i++) {
        usleep(100000);
        int done=waitpid(pid,&status,1);
        if(done==pid){printf("OLSN0W-HELD exited status=%x\n",status);return 68;}
        char output_bytes[1024];
        long count;
        while ((count = read(output[0], output_bytes, sizeof(output_bytes))) > 0) {
            patch_completion_feed(&completion, output_bytes, (unsigned long)count);
            /* Logging is optional; readiness never depends on a writable file. */
            write(2, output_bytes, (unsigned long)count);
        }
        if (!completion.ready) continue;
        port=0;rc=task_for_pid(mach_task_self_,0,&port);
        if(!rc && port){
            mach_port_deallocate(mach_task_self_,port);
            if(kill(pid,0))return 69;
            printf("OLSN0W-HELD KERNEL_READY child=%d\n",pid);fflush(0);
            held_stage("held-kernel-ready");
            if (signal_ready(ready_fd)) return 70;
            /* Retain supervisor and inherited SSH output during the relay.
             * Neither process runs cleanup before the target takes over. */
            for(;;)usleep(1000000);
        }
    }
    printf("OLSN0W-HELD TIMEOUT\n");fflush(0);for(;;)usleep(1000000);
}
