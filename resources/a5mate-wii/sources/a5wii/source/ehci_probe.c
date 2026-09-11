// Experimental Wii EHCI descriptor read, with a bounded temporary schedule.
// Layouts follow EHCI 1.0 sections 3.5/3.6; see linux-ehci.h for reference.
// This implements no reset, firmware download, or exploit payload.
#include "ehci_probe.h"
#include <ogc/ipc.h>
#include <ogc/lwp_watchdog.h>
#include <string.h>

#define COMMAND 0xcd040010U
#define STATUS 0xcd040014U
#define INTR 0xcd040018U
#define ASYNC 0xcd040028U
#define ASE (1U<<5)
#define ASS (1U<<15)
#define ACTIVE 0x80U
#define HALTED 0x40U
static s32 probe_heap=-1;

typedef struct {
    u32 qh[32];
    u32 setup_td[16], data_td[16], status_td[16];
    u8 setup[32], data[256];
} dma_work;

static u32 rd(u32 address) {
    u32 v=*(volatile u32*)address;
    __asm__ volatile("eieio" ::: "memory");return v;
}
static void wr(u32 address,u32 v) {
    *(volatile u32*)address=v;
    __asm__ volatile("eieio; sync" ::: "memory");
}
static u32 phys(const void *p){return (u32)p&0x3fffffff;}
static u32 le(u32 v){return __builtin_bswap32(v);}
static int wait_async(int enabled,u32 timeout_us) {
    u64 start=gettime();
    do {
        if(!!(rd(STATUS)&ASS)==enabled)return 1;
    }while(ticks_to_microsecs(gettime()-start)<timeout_us);
    return 0;
}
static int wait_halted(u32 timeout_us) {
    u64 start=gettime();
    do {if(rd(STATUS)&(1U<<12))return 1;}
    while(ticks_to_microsecs(gettime()-start)<timeout_us);
    return 0;
}
static void td(u32 *q,u32 next,u32 alternate,u32 token,void *buffer) {
    q[0]=le(next);q[1]=le(alternate);q[2]=le(token);
    if(buffer) {
        u32 p=phys(buffer);q[3]=le(p);
        for(unsigned i=1;i<5;i++)q[3+i]=le((p&~4095U)+4096*i);
    }
}

void ehci_read_probe(u8 address,const u8 setup[8],u16 read_length,int finish_status,ehci_probe_result *out) {
    memset(out,0,sizeof(*out));out->result=-1;
    if(address>127)return;
    int status_only=setup==NULL && read_length==0 && finish_status==1;
    if(!status_only) {
        if(!setup || !(setup[0]&0x80) || read_length==0 || read_length>256)return;
        if(read_length>(setup[6]|((u16)setup[7]<<8)))return;
    }
    if(rd(0xcd800064)!=0xffffffff || rd(0xcd040000)!=0x01000010)return;
    if(probe_heap<0)probe_heap=iosCreateHeap(4096);
    s32 heap=probe_heap;
    if(heap<0){out->result=-2;return;}
    dma_work *w=iosAlloc(heap,sizeof(*w));
    if(!w){out->result=-2;return;}
    memset(w,0,sizeof(*w));
    if(setup)memcpy(w->setup,setup,8);
    memset(w->data,0xff,sizeof(w->data));
    w->qh[0]=le(phys(w->qh)|2);
    w->qh[1]=le(address|(2U<<12)|(1U<<14)|(1U<<15)|(64U<<16)|(15U<<28));
    w->qh[2]=le(1U<<30);
    w->qh[4]=le(phys(status_only?w->status_td:w->setup_td));w->qh[5]=le(1);
    td(w->setup_td,phys(w->data_td),1,(8U<<16)|(3U<<10)|(2U<<8)|ACTIVE,w->setup);
    u32 data_next=finish_status?phys(w->status_td):1;
    td(w->data_td,data_next,data_next,
       (1U<<31)|((u32)read_length<<16)|(3U<<10)|(1U<<8)|ACTIVE,w->data);
    td(w->status_td,1,1,(1U<<31)|(3U<<10)|ACTIVE,NULL);
    DCFlushRange(w,sizeof(*w));
    volatile dma_work *uncached=(volatile dma_work*)((u32)w|0x40000000);

    u32 cmd=rd(COMMAND), irq=rd(INTR), old_async=rd(ASYNC), old_status=rd(STATUS);
    out->saved_command=cmd;out->saved_async=old_async;
    if(!(cmd&1) || !(cmd&ASE) || !(old_status&ASS)) {
        out->result=-3;iosFree(heap,w);return;
    }
    // Never call an IOS or network API while its async schedule is suspended.
    wr(INTR,0);wr(COMMAND,cmd&~(ASE|1U));
    if(!wait_halted(10000)) {
        wr(COMMAND,cmd);wr(INTR,irq);out->result=-4;iosFree(heap,w);return;
    }
    wr(ASYNC,phys(w->qh));out->programmed_async=rd(ASYNC);
    wr(COMMAND,cmd|ASE);
    out->result=-5;
    u64 start=gettime();
    do {
        u32 a=le(uncached->setup_td[2]),b=le(uncached->data_td[2]);
        u32 c=le(uncached->status_td[2]);
        if((a|b|(finish_status?c:0))&HALTED){out->result=-6;break;}
        if(!((finish_status?c:b)&ACTIVE)){out->result=0;break;}
    }while(ticks_to_microsecs(gettime()-start)<20000);
    out->active_command=rd(COMMAND);out->active_status=rd(STATUS);
    out->active_async=rd(ASYNC);out->dma_address=phys(w);
    out->qh_next=le(uncached->qh[4]);out->qh_token=le(uncached->qh[6]);
    wr(COMMAND,cmd&~(ASE|1U));
    if(!wait_halted(10000)) {
        // Fallback: halt the host without resetting ports, then restore IOS.
        wr(COMMAND,cmd&~(ASE|1U));
        u64 halt_start=gettime();
        while(!(rd(STATUS)&(1U<<12)) && ticks_to_microsecs(gettime()-halt_start)<10000){}
        out->result=-7;
        if(!(rd(STATUS)&(1U<<12))) {
            // Keep DMA storage alive if the controller cannot be stopped.
            wr(INTR,irq);return;
        }
    }
    out->setup_token=le(uncached->setup_td[2]);
    out->data_token=le(uncached->data_td[2]);
    out->status_token=le(uncached->status_td[2]);
    for(unsigned i=0;i<256;i++)out->data[i]=uncached->data[i];
    // Clear only newly raised completion/error bits before restoring IOS.
    wr(STATUS,(rd(STATUS)&3)&~old_status);
    wr(ASYNC,old_async);wr(COMMAND,cmd);wr(INTR,irq);
    if(!wait_async(1,10000))out->result=-8;
    out->restored_command=rd(COMMAND);out->restored_async=rd(ASYNC);
    if(out->restored_async!=old_async || out->restored_command!=cmd)out->result=-9;
    iosFree(heap,w);
}

void ehci_descriptor_probe(u8 address,ehci_probe_result *out) {
    const u8 setup[8]={0x80,6,0,1,0,0,18,0};
    ehci_read_probe(address,setup,18,1,out);
}

void ehci_finish_read(u8 address,ehci_probe_result *out) {
    ehci_read_probe(address,NULL,0,1,out);
}
