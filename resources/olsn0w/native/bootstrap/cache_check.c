#include "olsn0w_config.h"
typedef __SIZE_TYPE__ size_t;
typedef struct { const char *name; void *base; const char *symbol; void *address; } DlInfo;
extern int dladdr(const void *, DlInfo *);
extern int printf(const char *, ...), fflush(void *), getpid(void), strcmp(const char *, const char *);
extern void *malloc(size_t);
extern void free(void *);
extern int sysctlbyname(const char *, void *, size_t *, void *, size_t);
extern char *strstr(const char *, const char *);
extern unsigned int _dyld_image_count(void);
extern int csops(int, unsigned int, void *, size_t);
extern const char *_dyld_get_image_name(unsigned int);
extern const void *_dyld_get_image_header(unsigned int);

#ifndef OLSN0W_ROOT_TOKEN
#define OLSN0W_ROOT_TOKEN "rd=md0"
#endif

int main(int argc, char **argv) {
    char release[64]={0}, model[64]={0}, args[2048]={0};
    size_t size=sizeof(release)-1;
    if (argc!=2 || (strcmp(argv[1],"loose") && strcmp(argv[1],"cache"))) return 64;
    if (sysctlbyname("kern.osrelease",release,&size,0,0) || strcmp(release,"14.0.0")) return 65;
    size=sizeof(model)-1;
    if (sysctlbyname("hw.model",model,&size,0,0) || strcmp(model,OLSN0W_BOARD)) return 65;
    size=sizeof(args)-1;
    if (sysctlbyname("kern.bootargs",args,&size,0,0)) return 65;
#ifndef OLSN0W_DISK_DEFAULT_ROOT
    const char *root_token=OLSN0W_ROOT_TOKEN;
    char *p=strstr(args,root_token);
    size_t root_length=0;
    while (root_token[root_length]) root_length++;
    if (!p || (p!=args && p[-1]!=' ') || (p[root_length] && p[root_length]!=' ')) return 65;
#endif
    printf("OLSN0W-NATIVE bootargs=%s\n",args);
    printf("OLSN0W-NATIVE MAIN_REACHED pid=%d release=%s model=%s expected=%s\n",getpid(),release,model,argv[1]);
    unsigned int cs=0;
    if (csops(0,0,&cs,sizeof(cs))) return 70;
    printf("OLSN0W-NATIVE csflags=0x%x dyld_environment_ignored=%u\n",cs,(cs&0x1004U)==0x1000U);
    fflush(0);
    const void *functions[]={(const void *)&printf,(const void *)&getpid,(const void *)&malloc};
    int expected=!strcmp(argv[1],"cache"), errors=0;
    for (unsigned int i=0;i<3;i++) {
        DlInfo info={0};
        if (!dladdr(functions[i],&info) || !info.base) return 66;
        const unsigned int *h=info.base;
        if (h[0]!=0xfeedface) return 67;
        int cached=!!(h[6]&0x80000000U);
        printf("OLSN0W-NATIVE function=%u pointer=%p image=%s base=%p in_cache=%d\n",i,functions[i],info.name,info.base,cached);
        if (cached!=expected) errors++;
    }
    unsigned int cached_images=0, count=_dyld_image_count();
    for (unsigned int i=0;i<count;i++) {
        const unsigned int *h=_dyld_get_image_header(i);
        int cached=h && h[0]==0xfeedface && (h[6]&0x80000000U);
        cached_images+=cached;
        printf("OLSN0W-NATIVE image=%s in_cache=%d\n",_dyld_get_image_name(i),cached);
    }
    unsigned char *mem=malloc(4096);
    if (!mem) return 68;
    for (unsigned int i=0;i<4096;i++) mem[i]=(unsigned char)i;
    unsigned int sum=0;
    for (unsigned int i=0;i<4096;i++) sum+=mem[i];
    free(mem);
    if (sum!=522240) return 68;
    printf("OLSN0W-NATIVE RESULT=%s images=%u cached=%u allocator_sum=%u\n",errors?"FAIL":"PASS",count,cached_images,sum);
    fflush(0);
    return errors?69:0;
}
