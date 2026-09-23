/* Exercise the production controller with a read-only root and lost log writes. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define size_t ios_size_t
#define printf mock_printf
#define fflush mock_fflush
#define open mock_open
#define close mock_close
#define read mock_read
#define write mock_write
#define unlink mock_unlink
#define sync mock_sync
#define main controller_main
#include "controller.c"
#undef main
#undef size_t
#undef printf
#undef fflush
#undef open
#undef close
#undef read
#undef write
#undef unlink
#undef sync
static int enabled=1, log_failure=0, wrong_board=0, jumps=0, root_writes=0;
static int needs_patch=0, signalled=0, polling=0, unsafe_probes=0, held_died=0, spawn_error=0;
unsigned int mach_task_self_=1;
int mock_printf(const char *s,...){return 0;}
int mock_fflush(void *p){return 0;}
int geteuid(void){return 0;}
int getppid(void){return 1;}
int sysctlbyname(const char *n,void *p,ios_size_t *z,void *v,ios_size_t l){
 if(!strcmp(n,"kern.boottime")){
  struct boot_identity value={1234,5678};memcpy(p,&value,sizeof(value));*z=sizeof(value);return 0;
 }
 const char *value=!strcmp(n,"hw.model")?(wrong_board?"OTHER":OLSN0W_BOARD):!strcmp(n,"kern.osrelease")?"14.0.0":"";
 strcpy(p,value);*z=strlen(value)+1;return 0;
}
int mock_open(const char *p,int flags,...){
 if(!strncmp(p,"/olsn0w/",8) && flags){root_writes++;return -1;}
 if(!strcmp(p,MARKER))return 1;
 if(!strcmp(p,ENABLED))return enabled?2:-1;
 if(!strcmp(p,"/var/run/olsn0w-wake.ready"))return 3;
 if(!strcmp(p,SERVICES_READY))return 5;
 return log_failure?-1:4;
}
int mock_close(int fd){return 0;}
long mock_read(int fd,void *p,unsigned long n){
 if(fd==10){
  if(held_died)return 0;
  if(++polling<4)return -1;
  signalled=1;*(char *)p='R';return 1;
 }
 const char *s=fd==1?OLSN0W_ROOT_MARKER:fd==2?OLSN0W_TARGET_MARKER:"ready\n";
 memcpy(p,s,strlen(s));return strlen(s);
}
long mock_write(int fd,const void *p,unsigned long n){return log_failure && fd!=5?-1:n;}
int mock_unlink(const char *p){return log_failure?-1:0;}
void mock_sync(void){}
int posix_spawn(int *pid,const char *p,const void *a,const void *b,char *const *v,char *const *e){
 if(!strcmp(p,"/olsn0w/held-control")){
  if(!a || !v[1] || strcmp(v[1],"--ready-fd=3"))abort();
  *pid=21;return spawn_error;
 }
 *pid=20;return 0;
}
int pipe(int *fds){fds[0]=10;fds[1]=11;return 0;}
int fcntl(int fd,int cmd,...){return 0;}
int posix_spawn_file_actions_init(void **a){*a=(void *)1;return 0;}
int posix_spawn_file_actions_destroy(void **a){return 0;}
int posix_spawn_file_actions_addclose(void **a,int fd){return 0;}
int posix_spawn_file_actions_adddup2(void **a,int from,int to){return 0;}
int waitpid(int pid,int *status,int flags){*status=0;return pid==21 && !held_died?0:pid;}
int kill(int pid,int sig){return 0;}
int usleep(unsigned int n){return 0;}
int task_for_pid(unsigned int self,int pid,unsigned int *port){
 if(needs_patch && !signalled){if(polling)unsafe_probes++;*port=0;return 1;}
 *port=2;return 0;
}
int mach_port_deallocate(unsigned int self,unsigned int port){return 0;}
int execve(const char *p,char *const *a,char *const *e){
 if(strcmp(p,"/usr/local/bin/kloader") || strcmp(a[1],"/olsn0w/relay.bin"))abort();
 jumps++;return -1;
}
int main(void){
 /* A failed relay and stale/unwritable diagnostic state cannot consume enablement. */
 for(int i=0;i<4;i++){log_failure=i%2;if(controller_main()!=110 || jumps!=i+1 || root_writes)return 1;}
 enabled=0;if(controller_main()!=0 || jumps!=4)return 2;
 enabled=1;wrong_board=1;if(controller_main()!=101 || jumps!=4)return 3;
 wrong_board=0;needs_patch=1;log_failure=1;
 if(controller_main()!=110 || jumps!=5 || unsafe_probes || polling!=4)return 4;
 signalled=0;polling=0;held_died=1;
 if(controller_main()!=112 || jumps!=5 || unsafe_probes)return 5;
 held_died=0;spawn_error=1;polling=0;
 if(controller_main()!=111 || jumps!=5 || unsafe_probes)return 6;
 puts("persistent enablement and identity guards passed; readiness race guards passed");return 0;
}
