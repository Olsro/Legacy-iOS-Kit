#include <string.h>
#include <stdio.h>
#include <assert.h>
static const char *build="12H321", *args="rd=md0 -v";
static int calls, fail, flags_seen;
int sysctlbyname(const char *name, void *value, unsigned int *size, void *newval, unsigned int n) {
    const char *v=!strcmp(name,"kern.osversion")?build:args;
    if(fail)return -1;
    assert(*size>strlen(v));strcpy(value,v);return 0;
}
int unmount(const char *path,int flags){calls++;flags_seen=flags;return 0;}
#define main rescue_main
#include "../native/target/rescue_unmount.c"
#undef main
int main(void){
    char *ok[]={"unmount","/mnt1"},*bad[]={"unmount","/"};
    assert(rescue_main(2,ok)==0 && calls==1 && flags_seen==0);
    assert(rescue_main(2,bad)==91 && calls==1);
    args="rd=md00 -v";assert(rescue_main(2,ok)==90 && calls==1);
    args="xrd=md0";assert(rescue_main(2,ok)==90 && calls==1);
    args="rd=disk0s1s1";assert(rescue_main(2,ok)==90 && calls==1);
    args="rd=md0";build="10B329";assert(rescue_main(2,ok)==0 && calls==2);
    build="11D257";assert(rescue_main(2,ok)==90 && calls==2);
    build="12H321";fail=1;assert(rescue_main(2,ok)==90 && calls==2);
    return 0;
}
