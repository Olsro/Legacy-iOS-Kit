#include <gccore.h>
#include <ogc/usb.h>
#include <ogc/ios.h>
#include <ogc/ipc.h>
#include <ogc/pad.h>
#include <wiiuse/wpad.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <malloc.h>
#include "ehci_probe.h"
#include "packet_probe.h"

#ifndef A5WII_ENABLE_PWNDFU
#define A5WII_ENABLE_PWNDFU 0
#endif
#ifndef A5WII_ENABLE_NETWORK
#define A5WII_ENABLE_NETWORK 0
#endif
#if A5WII_ENABLE_NETWORK
#include <network.h>
#endif
#ifndef A5WII_PROFILE_CPID
#error "A5WII_PROFILE_CPID must be selected by the Makefile"
#endif
#ifndef A5WII_PROFILE_LABEL
#error "A5WII_PROFILE_LABEL must be selected by the Makefile"
#endif
#ifndef A5WII_BUILD_LABEL
#define A5WII_BUILD_LABEL "local"
#endif

#if A5WII_ENABLE_NETWORK
static int logfd=-1;
static struct sockaddr_in receiver;
static unsigned seq;
#endif
static u8 control_addresses[16];
static unsigned control_address_count;
static void report(const char *fmt,...);
static int serial_matches_profile(const char *serial) {
    return strstr(serial,"CPID:" A5WII_PROFILE_CPID " ")!=NULL;
}
static u32 mmio_read(u32 address) {
    u32 value=*(volatile u32*)address;
    __asm__ volatile("eieio" ::: "memory");
    return value;
}

/* This is intentionally read-only.  Hollywood exposes one EHCI root hub and
 * two OHCI companions; the values let us identify the companion that owns the
 * externally connected port before attempting a full-speed transaction. */
static void report_usb_topology(void) {
    const u32 ehci=0xcd040000U;
    report("EHCI cap=%08lx params=%08lx hcc=%08lx route=%08lx config=%08lx cmd=%08lx sts=%08lx segment=%08lx",
           (unsigned long)mmio_read(ehci+0x00),(unsigned long)mmio_read(ehci+0x04),
           (unsigned long)mmio_read(ehci+0x08),(unsigned long)mmio_read(ehci+0x0c),
           (unsigned long)mmio_read(ehci+0x50),(unsigned long)mmio_read(ehci+0x10),
           (unsigned long)mmio_read(ehci+0x14),(unsigned long)mmio_read(ehci+0x20));
    unsigned ports=mmio_read(ehci+0x04)&15U;
    report("EHCI frame=%08lx async=%08lx port_count=%u",
           (unsigned long)mmio_read(ehci+0x1c),(unsigned long)mmio_read(ehci+0x28),ports);
    for(unsigned p=0;p<ports;p++)
        report("EHCI port[%u]=%08lx",p,(unsigned long)mmio_read(ehci+0x54+4*p));
    for(unsigned controller=0;controller<2;controller++) {
        u32 ohci=0xcd050000U+controller*0x10000U;
        report("OHCI%u rev=%08lx ctrl=%08lx cmd=%08lx int=%08lx/%08lx hcca=%08lx chead=%08lx ccur=%08lx",
               controller,(unsigned long)mmio_read(ohci+0x00),(unsigned long)mmio_read(ohci+0x04),
               (unsigned long)mmio_read(ohci+0x08),(unsigned long)mmio_read(ohci+0x0c),
               (unsigned long)mmio_read(ohci+0x10),(unsigned long)mmio_read(ohci+0x18),
               (unsigned long)mmio_read(ohci+0x20),(unsigned long)mmio_read(ohci+0x24));
        report("OHCI%u root a=%08lx b=%08lx status=%08lx ports=%08lx/%08lx",
               controller,(unsigned long)mmio_read(ohci+0x48),(unsigned long)mmio_read(ohci+0x4c),
               (unsigned long)mmio_read(ohci+0x50),(unsigned long)mmio_read(ohci+0x54),
               (unsigned long)mmio_read(ohci+0x58));
    }
}
static s32 read_control(s32 fd,u8 type,u8 request,u16 value,u16 index,u16 length,u8 *buffer) {
    // This IOS58 USBV5 backend reports setup bytes plus actual data bytes.
    // The buffer MUST come from iosAlloc (MEM2): MEM1 lost trailing bytes
    // on this Wii, even with explicit full-cache-line synchronization.
    DCFlushRange(buffer,256);
    s32 result=USB_ReadCtrlMsg(fd,type,request,value,index,length,buffer);
    DCInvalidateRange(buffer,256);
    return result;
}
static void report(const char *fmt,...) {
    char text[1024];
    va_list ap;va_start(ap,fmt);vsnprintf(text,sizeof(text),fmt,ap);va_end(ap);
    printf("%s\n",text);fflush(stdout);
#if A5WII_ENABLE_NETWORK
    char packet[1100];
    snprintf(packet,sizeof(packet),"A5WII-v1 %u %s",seq++,text);
    if(logfd>=0) {
        size_t n=strlen(packet);packet[n++]='\n';
        s32 sent=net_send(logfd,packet,n,0);
        if(sent<0)printf("Network send error: %ld\n",(long)sent);
    }
#endif
}

static void report_a5mate_topology(const a5mate_result *r) {
    const a5mate_topology *t=&r->topology;
    report("A5MATE topology params=%08lx ports=%u connected=%u ehci=%u selected=%d",
           (unsigned long)t->hcsparams,t->ports,t->connected,t->ehci_connected,t->selected_port);
    for(unsigned p=0;p<t->ports;p++)
        report("A5MATE port[%u]=%08lx",p,(unsigned long)t->portsc[p]);
    if(r->result==-20)report("A5MATE blocked: controller reports zero root ports");
    if(r->result==-27)report("A5MATE blocked: need exactly one EHCI-owned connection; use a direct cable, unplug other USB devices");
    if(r->result==-28)report("A5MATE blocked: selected port is not powered/enabled or is resetting");
}

static void inspect_async_ring_core(void) {
    u32 head=mmio_read(0xcd040028)&~31U, next=head;
    for(unsigned n=0;n<16;n++) {
        if(next<0x10000000 || next>0x13ffffc0 || (next&31)) {
            report("EHCI ring stop: invalid MEM2 pointer %08lx",(unsigned long)next);
            return;
        }
        volatile u32 *qh=(volatile u32*)(next|0xc0000000);
        u32 link=__builtin_bswap32(qh[0]), ep=__builtin_bswap32(qh[1]);
        u32 cap=__builtin_bswap32(qh[2]), token=__builtin_bswap32(qh[6]);
        report("EHCI QH %08lx link=%08lx ep=%08lx cap=%08lx token=%08lx",
               (unsigned long)next,(unsigned long)link,(unsigned long)ep,
               (unsigned long)cap,(unsigned long)token);
        report("EHCI endpoint address=%u endpoint=%u speed=%u maxpacket=%u",
               ep&127,(ep>>8)&15,(ep>>12)&3,(ep>>16)&0x7ff);
        if((ep&127) && ((ep>>8)&15)==0 && ((ep>>12)&3)==2 &&
           ((ep>>16)&0x7ff)==64 && control_address_count<16) {
            int seen=0;
            for(unsigned j=0;j<control_address_count;j++)if(control_addresses[j]==(ep&127))seen=1;
            if(!seen)control_addresses[control_address_count++]=ep&127;
        }
        if((link&7)!=2) {
            report("EHCI ring stop: unrecognized link format");return;
        }
        next=link&~31U;
        if(next==head){report("EHCI ring loop closed");return;}
    }
    report("EHCI ring inspection bounded at 16 nodes");
}

static void inspect_async_ring(void) {
    volatile u16 *protection=(volatile u16*)0xcd8b420a;
    u16 saved=*protection;
    report("MEM_PROT_DDR saved=%04x; temporary access for ring inspection",saved);
    *protection=0;
    __asm__ volatile("eieio; sync" ::: "memory");
    inspect_async_ring_core();
    *protection=saved;
    __asm__ volatile("eieio; sync" ::: "memory");
    report("MEM_PROT_DDR restored=%04x",*protection);
    // Address zero can be probed only with one connected, enabled EHCI port.
    unsigned enabled_ports=0;
    unsigned ports=mmio_read(0xcd040004)&15U;
    for(unsigned port=0;port<ports;port++)if((mmio_read(0xcd040054+4*port)&0x2005)==5)enabled_ports++;
    if(enabled_ports==1 && control_address_count<16)control_addresses[control_address_count++]=0;
}

static int descriptor_is_target(const ehci_probe_result *r) {
    return r->result==0 && ((r->data_token>>16)&0x7fff)==0 &&
           r->data[0]==18 && r->data[1]==1 && r->data[8]==0xac &&
           r->data[9]==5 && r->data[10]==0x27 && r->data[11]==0x12;
}

static int finish_reset_and_identify(u8 address,packet_reset r) {
    report("RESET port=%d result=%d before=%08lx asserted=%08lx after=%08lx hold_us=%lu",
           r.port,r.result,(unsigned long)r.before,(unsigned long)r.asserted,
           (unsigned long)r.after,(unsigned long)r.hold_us);
    for(unsigned n=0;n<r.count;n++) {
        if(r.cleanup_attempted && n==r.cleanup_before_stage)
            report("RESET cleanup before_stage=%u result=%d before=%08lx at_1ms=%08lx at_50ms=%08lx after=%08lx hold_us=%lu",
                   n,r.cleanup_result,(unsigned long)r.cleanup_before,
                   (unsigned long)r.cleanup_1ms,(unsigned long)r.cleanup_50ms,
                   (unsigned long)r.cleanup_after,(unsigned long)r.cleanup_hold_us);
        packet_stage *s=&r.stage[n];char bytes[257]={0};
        for(unsigned j=0;j<s->requested;j++)snprintf(bytes+2*j,3,"%02x",s->bytes[j]);
        report("RESET PACKET index=%u pid=%u toggle=%u requested=%u result=%d before=%08lx after=%08lx bytes=%s",
               n,s->pid,s->toggle,s->requested,s->result,(unsigned long)s->before,(unsigned long)s->after,bytes);
    }
    if(r.cleanup_attempted && r.cleanup_before_stage==r.count)
        report("RESET cleanup before_stage=%u result=%d before=%08lx at_1ms=%08lx at_50ms=%08lx after=%08lx hold_us=%lu",
               r.count,r.cleanup_result,(unsigned long)r.cleanup_before,
               (unsigned long)r.cleanup_1ms,(unsigned long)r.cleanup_50ms,
               (unsigned long)r.cleanup_after,(unsigned long)r.cleanup_hold_us);
    report("RESET end result=%d count=%u restored=%d cmd=%08lx/%08lx async=%08lx/%08lx",
           r.result,r.count,r.restored,(unsigned long)r.saved_command,(unsigned long)r.restored_command,
           (unsigned long)r.saved_async,(unsigned long)r.restored_async);
    if(r.address_verified)report("RESET address_verified_before_ios=1 address=%u",address);
    if(r.result || !r.restored) {
        report("RESET diagnostic qh_token=%08lx async=%08lx/%08lx",
               (unsigned long)r.last_qh_token,(unsigned long)r.last_async,(unsigned long)r.expected_async);
        return 0;
    }
    ehci_probe_result d,s,t;
    ehci_descriptor_probe(address,&d);
    char hex[37];for(unsigned i=0;i<18;i++)snprintf(hex+2*i,3,"%02x",d.data[i]);
    report("REENUM descriptor address=%u result=%d bytes=%s",address,d.result,hex);
    if(d.result)report("REENUM failed setup=%08lx data=%08lx status=%08lx",(unsigned long)d.setup_token,(unsigned long)d.data_token,(unsigned long)d.status_token);
    if(!descriptor_is_target(&d))return 0;
    const u8 serial_setup[8]={0x80,6,d.data[16],3,9,4,254,0};
    ehci_read_probe(address,serial_setup,254,1,&s);
    unsigned remaining=(s.data_token>>16)&0x7fff;
    unsigned received=remaining<=254?254-remaining:0;
    char serial[128]={0};
    if(s.result==0 && received>=2 && s.data[1]==3 && s.data[0]>=2 &&
       s.data[0]<=received && !(s.data[0]&1)) {
        for(unsigned j=0;j<(s.data[0]-2)/2;j++)serial[j]=s.data[3+j*2]?'?':s.data[2+j*2];
    }
    int same=serial_matches_profile(serial);
    report("REENUM SERIAL result=%d received=%u same_target=%d value=%s",s.result,received,same,serial);
    if(!same)return 0;
    const u8 state_setup[8]={0xa1,5,0,0,0,0,1,0};
    ehci_read_probe(address,state_setup,1,1,&t);
    int idle=t.result==0 && t.data[0]==2 && ((t.data_token>>16)&0x7fff)==0;
    report("REENUM GETSTATE result=%d state=%u idle_validated=%d",t.result,t.data[0],idle);
    report("RESET verified same_target=%d dfu_idle=%d pwn_dfu_validated=false boot_validated=false",same,idle);
    return idle;
}

static int reset_and_identify(u8 address,int incomplete,int retry) {
    if(retry==2)report("RESET begin address=%u after_incomplete=%d drain=1",address,incomplete);
    else if(retry)report("RESET begin address=%u after_incomplete=%d retry=1",address,incomplete);
    else report("RESET begin address=%u after_incomplete=%d",address,incomplete);
    packet_reset r;
    if(retry==2)packet_reset_target_drain(address,&r);
    else if(retry)packet_reset_target_retry(address,&r);
    else packet_reset_target(address,&r);
    return finish_reset_and_identify(address,r);
}

static int transfer_reset_and_identify(u8 address,u8 serial_index) {
    report("TRANSFER begin address=%u serial_index=%u requested=128 complete_before_reset=1 held=1",address,serial_index);
    packet_transaction tx;packet_reset r;
    packet_reset_after_transfer(address,serial_index,&tx,&r);
    for(unsigned n=0;n<tx.count;n++) {
        packet_stage *s=&tx.stage[n];char bytes[129]={0};
        for(unsigned j=0;j<s->requested;j++)snprintf(bytes+2*j,3,"%02x",s->bytes[j]);
        report("TRANSFER PACKET index=%u pid=%u toggle=%u requested=%u result=%d before=%08lx after=%08lx bytes=%s",
               n,s->pid,s->toggle,s->requested,s->result,(unsigned long)s->before,(unsigned long)s->after,bytes);
    }
    report("TRANSFER end result=%d count=%u sts=%08lx irq=%08lx",
           tx.result,tx.count,(unsigned long)r.interrupted_status,(unsigned long)r.interrupted_irq);
    report("RESET samples at_1ms=%08lx at_50ms=%08lx cmd=%08lx sts=%08lx",
           (unsigned long)r.during_1ms,(unsigned long)r.during_50ms,
           (unsigned long)r.during_command,(unsigned long)r.during_status);
    report("RESET begin address=%u after_transfer=1 transfer_complete=1 held=1",address);
    return finish_reset_and_identify(address,r);
}


// Keep the program alive after an incomplete transfer instead of asking HBC
// to reinitialize a device whose control endpoint may still be blocked.
#if A5WII_ENABLE_NETWORK
static int recovery_identify(u8 address,ehci_probe_result *descriptor) {
    ehci_descriptor_probe(address,descriptor);
    if(!descriptor_is_target(descriptor))return 0;
    const u8 setup[8]={0x80,6,descriptor->data[16],3,9,4,254,0};
    ehci_probe_result serial,state;
    ehci_read_probe(address,setup,254,1,&serial);
    unsigned left=(serial.data_token>>16)&0x7fff;
    unsigned received=left<=254?254-left:0;
    char text[128]={0};
    if(serial.result==0 && received>=2 && serial.data[1]==3 &&
       serial.data[0]>=2 && serial.data[0]<=received && !(serial.data[0]&1)) {
        for(unsigned i=0;i<(serial.data[0]-2)/2;i++)
            text[i]=serial.data[3+2*i]?'?':serial.data[2+2*i];
    }
    int same=serial_matches_profile(text);
    if(!same)return 0;
    const u8 getstate[8]={0xa1,5,0,0,0,0,1,0};
    ehci_read_probe(address,getstate,1,1,&state);
    return state.result==0 && state.data[0]==2 && ((state.data_token>>16)&0x7fff)==0;
}
#endif

/* The pwnDFU marker has already been verified before this listener starts.
 * Unlike recovery_console, this path never sends an iPhone control transfer.
 */
#if A5WII_ENABLE_NETWORK
static int pwn_hold_console(void) {
    s32 server=net_socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in local={0};local.sin_family=AF_INET;local.sin_port=htons(44006);
    if(server<0 || net_bind(server,(struct sockaddr*)&local,sizeof(local))<0 || net_listen(server,1)<0) {
        report("PWND hold console unavailable; direct EHCI ownership retained");
        for(;;)VIDEO_WaitVSync();
    }
    report("PWND hold console TCP 44006: status / eject / release");
    int ejected=0;
    for(;;) {
        struct sockaddr_in peer={0};socklen_t peer_size=sizeof(peer);
        s32 client=net_accept(server,(struct sockaddr*)&peer,&peer_size);
        if(client<0)continue;
        if(peer.sin_addr.s_addr!=inet_addr("192.168.1.10")){net_close(client);continue;}
        char command[32]={0},reply[256];
        s32 n=net_recv(client,command,sizeof(command)-1,0);
        if(n<=0){net_close(client);continue;}
        command[strcspn(command,"\r\n")]=0;
        if(strcmp(command,"status")==0) {
            snprintf(reply,sizeof(reply),"pwn_ready=1 held=1 ejected=%d; use eject before moving the cable\n",ejected);
        } else if(strcmp(command,"eject")==0) {
            a5mate_result r;int result=packet_a5mate_eject(&r);
            if(!result)ejected=1;
            snprintf(reply,sizeof(reply),"eject result=%d ejected=%d; cable may now be disconnected\n",result,r.ejected);
        } else if(strcmp(command,"release")==0) {
            a5mate_result r;int result=packet_a5mate_release(&r);
            snprintf(reply,sizeof(reply),"release result=%d restored=%d\n",result,r.restored);
            net_send(client,reply,strlen(reply),0);net_close(client);
            if(!result){net_close(server);return 1;}
            continue;
        } else {
            snprintf(reply,sizeof(reply),"Available commands: status, eject, release (after physical disconnect)\n");
        }
        net_send(client,reply,strlen(reply),0);net_close(client);
    }
}
#else
/* Distribution builds do not initialize the Wii network stack.  The same
 * two-step physical handoff remains available locally: A quiesces the USB
 * port, then B restores IOS58 only after the cable has been unplugged. */
static int pwn_hold_console(void) {
    WPAD_Init();PAD_Init();
    int ejected=0;
    report("PWND local hold: press A to eject, unplug cable, then press B to release");
    for(;;) {
        WPAD_ScanPads();
        u32 keys=WPAD_ButtonsDown(0)|PAD_ButtonsDown(0);
        if(!ejected && (keys&(WPAD_BUTTON_A|PAD_BUTTON_A))) {
            a5mate_result r;int result=packet_a5mate_eject(&r);
            if(!result)ejected=1;
            report("PWND local eject result=%d ejected=%d",result,r.ejected);
        } else if(ejected && (keys&(WPAD_BUTTON_B|PAD_BUTTON_B))) {
            a5mate_result r;int result=packet_a5mate_release(&r);
            report("PWND local release result=%d restored=%d",result,r.restored);
            if(!result)return 1;
        }
        VIDEO_WaitVSync();
    }
}
#endif

#if A5WII_ENABLE_NETWORK
static void recovery_console(u8 address) {
    s32 server=net_socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in local={0};local.sin_family=AF_INET;local.sin_port=htons(44005);
    if(server<0 || net_bind(server,(struct sockaddr*)&local,sizeof(local))<0 || net_listen(server,1)<0) {
        report("RECOVERY console unavailable; holding screen to preserve the failed state");
        for(;;)VIDEO_WaitVSync();
    }
    report("RECOVERY console TCP 44005: identify / rescan / finish / reset / quit; target address=%u",address);
    for(;;) {
        struct sockaddr_in peer={0};socklen_t peer_size=sizeof(peer);
        s32 client=net_accept(server,(struct sockaddr*)&peer,&peer_size);
        if(client<0)continue;
        if(peer.sin_addr.s_addr!=inet_addr("192.168.1.10")){net_close(client);continue;}
        char command[32]={0},reply[256];
        s32 n=net_recv(client,command,sizeof(command)-1,0);
        if(n<=0){net_close(client);continue;}
        command[strcspn(command,"\r\n")]=0;
        ehci_probe_result state;
        if(strcmp(command,"finish")==0) {
            ehci_finish_read(address,&state);
            snprintf(reply,sizeof(reply),"finish result=%d status_token=%08lx\n",state.result,(unsigned long)state.status_token);
        } else if(strcmp(command,"reset")==0) {
            /* A bounded reset plus full re-identification is safer than
             * asking the operator to reboot after a deliberately incomplete
             * packet sequence.  The retry path tolerates one stale EP0 IN
             * packet before accepting the exact CPID/BDID/ECID target. */
            int target=reset_and_identify(address,0,2);
            if(!target)target=reset_and_identify(address,0,1);
            snprintf(reply,sizeof(reply),"reset result=%d address=%u same_target_dfu_idle=%d\n",
                     target?0:-1,address,target);
        } else if(strcmp(command,"identify")==0 || strcmp(command,"rescan")==0 || strcmp(command,"quit")==0) {
            int force_rescan=strcmp(command,"rescan")==0;
            memset(&state,0,sizeof(state));state.result=-1;
            int target=force_rescan?0:recovery_identify(address,&state);
            if(!target) {
                // Hotplug can make IOS assign a different address. Refresh
                // only the controller's observed EP0 candidates, then require
                // the original CPID/BDID/ECID and DFU idle before adopting one.
                usb_device_entry entries[32] ATTRIBUTE_ALIGN(32);u8 count=0;
                s32 list=USB_GetDeviceList(entries,32,0,&count);
                report("RECOVERY device list result=%ld count=%u",(long)list,count);
                if(list>=0)for(unsigned i=0;i<count && i<32;i++) {
                    if(entries[i].vid!=0x05ac || entries[i].pid!=0x1227)continue;
                    // Match libogc's vendor-device open path, but retain the
                    // resume result that USB_OpenDevice itself discards.
                    s32 resumed=USB_ResumeDevice(entries[i].device_id);
                    report("RECOVERY resume result=%ld device=%ld",(long)resumed,(long)entries[i].device_id);
                }
                control_address_count=0;
                inspect_async_ring();
                for(unsigned i=0;i<control_address_count && !target;i++) {
                    u8 candidate=control_addresses[i];
                    target=recovery_identify(candidate,&state);
                    if(target)address=candidate;
                }
            }
            snprintf(reply,sizeof(reply),"identify result=%d target=%d address=%u same_target_dfu_idle=%d setup=%08lx data=%08lx\n",
                     state.result,target,address,target,(unsigned long)state.setup_token,(unsigned long)state.data_token);
            if(strcmp(command,"quit")==0 && target) {
                net_send(client,reply,strlen(reply),0);net_close(client);net_close(server);
                report("RECOVERY exact target DFU idle; returning from console");return;
            }
        } else snprintf(reply,sizeof(reply),"Available commands: identify, rescan, finish, reset, quit (quit requires exact target in DFU idle)\n");
        printf("%s",reply);fflush(stdout);
        net_send(client,reply,strlen(reply),0);net_close(client);
    }
}
#else
static void recovery_console(u8 address) {
    report("RECOVERY console disabled in distribution build; address=%u",address);
    for(;;)VIDEO_WaitVSync();
}
#endif

int main(int argc,char **argv) {
    int topology_only=argc>1 && !strcmp(argv[1],"--topology");
    int fullspeed_probe=argc>1 && !strcmp(argv[1],"--fullspeed-probe");
    int fullspeed_replug=argc>1 && !strcmp(argv[1],"--fullspeed-replug");
    int transfer_reset=argc>1 && !strcmp(argv[1],"--transfer-reset");
    int pwndfu_requested=argc>1 && !strcmp(argv[1],"--pwndfu");
    int console_enabled=argc>1 && !strcmp(argv[1],"--console");
    int retry_reset=argc>1 && !strcmp(argv[1],"--packets-reset-retry");
    if(argc>1 && !strcmp(argv[1],"--packets-reset-drain"))retry_reset=2;
    int reset_enabled=retry_reset || (argc>1 && (!strcmp(argv[1],"--reset") || !strcmp(argv[1],"--packets-reset")));
    int partial_enabled=argc>1 && strcmp(argv[1],"--partial")==0;
    int drain_enabled=argc>1 && !strcmp(argv[1],"--packets-drain");
    int packet_enabled=retry_reset || drain_enabled || (argc>1 && (!strcmp(argv[1],"--packets") || !strcmp(argv[1],"--packets-early") || !strcmp(argv[1],"--packets-reset")));
    int early_status=argc>1 && (!strcmp(argv[1],"--packets-early") || !strcmp(argv[1],"--packets-reset"));
    if(retry_reset)early_status=1;
    if(drain_enabled)early_status=2;
    int direct_enabled=fullspeed_probe || fullspeed_replug || pwndfu_requested || transfer_reset || console_enabled || reset_enabled || packet_enabled || partial_enabled || (argc>1 && strcmp(argv[1],"--direct")==0);
    VIDEO_Init();
    GXRModeObj *mode=VIDEO_GetPreferredMode(NULL);
    void *xfb=MEM_K0_TO_K1(SYS_AllocateFramebuffer(mode));
    console_init(xfb,20,20,mode->fbWidth,mode->xfbHeight,mode->fbWidth*2);
    VIDEO_Configure(mode);VIDEO_SetNextFramebuffer(xfb);VIDEO_SetBlack(FALSE);VIDEO_Flush();VIDEO_WaitVSync();
    printf("A5Mate Wii USB diagnostic (%s) by Olsro\n",A5WII_PROFILE_LABEL);
    printf("Build: %s\n",A5WII_BUILD_LABEL);
#if A5WII_ENABLE_NETWORK
    printf("Development network initialization...\n");
    char ip[16]={0},mask[16]={0};
    s32 nr=if_config(ip,mask,NULL,TRUE,5);
    if(nr>=0) {
        logfd=net_socket(AF_INET,SOCK_STREAM,0);
        memset(&receiver,0,sizeof(receiver));receiver.sin_family=AF_INET;
        receiver.sin_port=htons(44004);receiver.sin_addr.s_addr=inet_addr("192.168.1.10");
        if(logfd>=0) {
            s32 connected=net_connect(logfd,(struct sockaddr*)&receiver,sizeof(receiver));
            printf("TCP connect=%ld\n",(long)connected);
            if(connected<0){net_close(logfd);logfd=-1;}
        }
    }
    report("network=%ld ip=%s tcp=%d IOS=%u revision=%u",(long)nr,ip,logfd,IOS_GetVersion(),IOS_GetRevision());
#else
    report("network=disabled IOS=%u revision=%u",IOS_GetVersion(),IOS_GetRevision());
#endif
    report("AHBPROT=%08lx",(unsigned long)*(volatile u32*)0xcd800064);
    report("USB controller topology probe starting (read-only)");
    report_usb_topology();
    if(topology_only)goto done;
    if(argc==3 && strcmp(argv[1],"--finish-read")==0) {
        int address=atoi(argv[2]);
        if(address>=0 && address<128) {
            ehci_probe_result finish,check;
            report("RECOVERY standalone OUT status stage, previously identified address=%d",address);
            ehci_finish_read(address,&finish);
            report("RECOVERY status result=%d token=%08lx restore=%08lx/%08lx",
                   finish.result,(unsigned long)finish.status_token,
                   (unsigned long)finish.saved_async,(unsigned long)finish.restored_async);
            ehci_descriptor_probe(address,&check);
            char hex[37];for(int j=0;j<18;j++)snprintf(hex+j*2,3,"%02x",check.data[j]);
            report("RECOVERY descriptor result=%d setup=%08lx data=%08lx bytes=%s",
                   check.result,(unsigned long)check.setup_token,(unsigned long)check.data_token,hex);
        }
        goto done;
    }
    s32 result=USB_Initialize();report("USB_Initialize=%ld",(long)result);
    if(result<0)goto done;
    usb_device_entry entries[32] ATTRIBUTE_ALIGN(32);
    u8 count=0;
    for(int attempt=0;attempt<10;attempt++) {
        memset(entries,0,sizeof(entries));
        result=USB_GetDeviceList(entries,32,0,&count);
        if(result>=0 && count)break;
        usleep(200000);
    }
    report("USB_GetDeviceList=%ld count=%u",(long)result,count);
    unsigned matches=0, dfu_validated=0;
    int existing_pwndfu=0;
    s32 dma_heap=iosCreateHeap(2048);
    report("IPC DMA heap=%ld",(long)dma_heap);
    for(unsigned i=0;i<count && i<32;i++) {
        report("device id=%ld vid=%04x pid=%04x",(long)entries[i].device_id,entries[i].vid,entries[i].pid);
        if(entries[i].vid!=0x05ac || entries[i].pid!=0x1227)continue;
        s32 fd=-1;
        result=USB_OpenDevice(entries[i].device_id,0x05ac,0x1227,&fd);
        report("open=%ld fd=%ld",(long)result,(long)fd);
        if(result<0)continue;
        u8 *buffer=dma_heap>=0?iosAlloc(dma_heap,256):NULL;
        report("IPC DMA buffer=%p",buffer);
        if(!buffer){USB_CloseDevice(&fd);continue;}
        memset(buffer,0,256);
        result=read_control(fd,0x80,6,0x0100,0,18,buffer);
        report("descriptor result=%ld len=%u type=%u serialIndex=%u",(long)result,buffer[0],buffer[1],buffer[16]);
        char hex[65];
        for(int j=0;j<32;j++)snprintf(hex+j*2,3,"%02x",buffer[j]);
        report("descriptor_raw=%s",hex);
        if(result==26 && buffer[0]==18 && buffer[1]==1 && buffer[8]==0xac && buffer[9]==5 &&
           buffer[10]==0x27 && buffer[11]==0x12) {
            u8 index=buffer[16];
            if(!index){report("No serial index in raw descriptor; trying standard A5 string index 3 for identification only");index=3;}
            memset(buffer,0,256);
            result=read_control(fd,0x80,6,0x0300|index,0x0409,254,buffer);
            char serial[128]={0};
            if(result==8+buffer[0] && buffer[1]==3 && buffer[0]>=2 && buffer[0]<=254 && !(buffer[0]&1)) {
                unsigned chars=(buffer[0]-2)/2;
                for(unsigned j=0;j<chars;j++)serial[j]=buffer[3+j*2]?'?':buffer[2+j*2];
            }
            report("serial result=%ld bytes=%u type=%u value=%s",(long)result,buffer[0],buffer[1],serial);
            if(result>=0 && serial_matches_profile(serial)) {
                matches++;
                if(strstr(serial,"PWND:[checkm8]")) {
                    /* This marker is the pwnDFU milestone.  Once seen, do
                     * not ask IOS58 to issue GETSTATE/GETSTATUS before the
                     * direct holder takes over. */
                    existing_pwndfu=1;dfu_validated++;
                    report("TARGET existing pwnDFU marker detected; suppressing further IOS control requests");
                    iosFree(dma_heap,buffer);USB_CloseDevice(&fd);continue;
                }
                memset(buffer,0xff,256);
                result=read_control(fd,0xa1,5,0,0,1,buffer);
                report("TARGET DFU_GETSTATE result=%ld state=%u",(long)result,buffer[0]);
                int idle=(result==9 && buffer[0]==2);
                if(idle) {
                    memset(buffer,0xff,256);
                    result=read_control(fd,0xa1,3,0,0,6,buffer);
                    report("TARGET DFU_GETSTATUS result=%ld status=%u state=%u string=%u",
                           (long)result,buffer[0],buffer[4],buffer[5]);
                    if(result==14 && buffer[0]==0 && buffer[4]==2)dfu_validated++;
                }
            } else report("Target ECID mismatch or unreadable; no DFU requests sent");
        }
        iosFree(dma_heap,buffer);USB_CloseDevice(&fd);
    }
    report("matching_targets=%u dfu_idle_validated=%u existing_pwndfu=%d boot_validated=false",matches,dfu_validated,existing_pwndfu);
    if(dfu_validated!=1 || !direct_enabled) { USB_Deinitialize(); goto done; }
    report("NATIVE discovery: after exact-target IOS58 identification");
    {
        inspect_async_ring();
        int recovered_target=0;
        if(pwndfu_requested && existing_pwndfu) {
#if A5WII_ENABLE_PWNDFU
            a5mate_result transition;
            /* a5mate_begin only seizes the controller; it emits no USB
             * transfer, so the marker-bearing pwnDFU device is untouched. */
            int hold_result=packet_a5mate_hold_existing(1,&transition);
            report_a5mate_topology(&transition);
            report("A5MATE existing-pwn hold result=%d restored=%d marker=%d pwn_ready=%d held=%d",
                   hold_result,transition.restored,transition.pwn_marker_seen,
                   transition.pwn_ready,transition.held);
            if(!hold_result && transition.pwn_ready && transition.held) {
                report("A5MATE existing pwnDFU verified; holding direct EHCI ownership until clean ejection");
                if(pwn_hold_console())
                    report("A5MATE clean ejection released; returning to Homebrew Channel");
            }
#else
            report("A5MATE disabled at build time; cannot hold existing pwnDFU");
#endif
            recovered_target=1;
        } else for(unsigned candidate=0;candidate<control_address_count;candidate++) {
        u8 target_address=control_addresses[candidate];
        report("DIRECT EHCI descriptor probe: discovered address %u, bounded temporary schedule",target_address);
        ehci_probe_result direct;
        ehci_descriptor_probe(target_address,&direct);
        report("DIRECT result=%d setup=%08lx data=%08lx status=%08lx",
               direct.result,(unsigned long)direct.setup_token,
               (unsigned long)direct.data_token,(unsigned long)direct.status_token);
        report("DIRECT restore cmd=%08lx/%08lx async=%08lx/%08lx",
               (unsigned long)direct.saved_command,(unsigned long)direct.restored_command,
               (unsigned long)direct.saved_async,(unsigned long)direct.restored_async);
        report("DIRECT active cmd=%08lx sts=%08lx async=%08lx dma=%08lx qh_next=%08lx qh_token=%08lx",
               (unsigned long)direct.active_command,(unsigned long)direct.active_status,
               (unsigned long)direct.active_async,(unsigned long)direct.dma_address,
               (unsigned long)direct.qh_next,(unsigned long)direct.qh_token);
        report("DIRECT programmed_async=%08lx",(unsigned long)direct.programmed_async);
        char raw[37];for(int i=0;i<18;i++)snprintf(raw+i*2,3,"%02x",direct.data[i]);
        report("DIRECT descriptor=%s",raw);
        report("DIRECT target_descriptor_valid=%d boot_validated=false",
               direct.result==0 && ((direct.data_token>>16)&0x7fff)==0 &&
               direct.data[0]==18 && direct.data[1]==1 && direct.data[8]==0xac &&
               direct.data[9]==5 && direct.data[10]==0x27 && direct.data[11]==0x12);
        int target_descriptor=(direct.result==0 && ((direct.data_token>>16)&0x7fff)==0 &&
           direct.data[0]==18 && direct.data[1]==1 && direct.data[8]==0xac && direct.data[9]==5 &&
           direct.data[10]==0x27 && direct.data[11]==0x12);
        if(!target_descriptor)continue;
        ehci_probe_result direct_serial,direct_state;
        const u8 serial_setup[8]={0x80,6,direct.data[16],3,9,4,254,0};
        ehci_read_probe(target_address,serial_setup,254,1,&direct_serial);
        char native_serial[128]={0};
        unsigned serial_received=254-((direct_serial.data_token>>16)&0x7fff);
        if(direct_serial.result==0 && serial_received>=2 && direct_serial.data[1]==3 &&
           direct_serial.data[0]>=2 && direct_serial.data[0]<=254 &&
           !(direct_serial.data[0]&1) && direct_serial.data[0]<=serial_received) {
            unsigned chars=(direct_serial.data[0]-2)/2;
            for(unsigned j=0;j<chars;j++)native_serial[j]=direct_serial.data[3+j*2]?'?':direct_serial.data[2+j*2];
        }
        int native_target=serial_matches_profile(native_serial);
        report("DIRECT SERIAL result=%d received=%u target=%d value=%s",
               direct_serial.result,serial_received,native_target,native_serial);
        int native_idle=0;
        if(native_target) {
            const u8 state_setup[8]={0xa1,5,0,0,0,0,1,0};
            ehci_read_probe(target_address,state_setup,1,1,&direct_state);
            native_idle=direct_state.result==0 && direct_state.data[0]==2 &&
                        ((direct_state.data_token>>16)&0x7fff)==0;
            report("DIRECT GETSTATE result=%d state=%u idle_validated=%d",
                   direct_state.result,direct_state.data[0],native_idle);
        }
        recovered_target=native_idle;
        if((fullspeed_probe || fullspeed_replug) && native_idle) {
            fullspeed_probe_result fullspeed;
            if(fullspeed_replug)
                report("FULLSPEED replug armed: OHCI0 will wait up to 180 seconds for cable unplug then reconnect before one address-zero descriptor");
            report("FULLSPEED begin address=%u; routing external port to OHCI0 for one address-zero descriptor",target_address);
            /* Close IOS58's vendor USB service before seizing its companion.
             * Identity was already established above; this prevents its
             * background controller task from observing the new attach. */
            USB_Deinitialize();
            report("FULLSPEED IOS58 USB service released before OHCI0 ownership");
            int probe_result=packet_fullspeed_probe(target_address,fullspeed_replug,&fullspeed);
            char descriptor[37];
            for(unsigned j=0;j<18;j++)snprintf(descriptor+j*2,3,"%02x",fullspeed.descriptor[j]);
            int descriptor_valid=fullspeed.descriptor[0]==18 && fullspeed.descriptor[1]==1 &&
                fullspeed.descriptor[8]==0xac && fullspeed.descriptor[9]==5 &&
                fullspeed.descriptor[10]==0x27 && fullspeed.descriptor[11]==0x12;
            report("FULLSPEED end result=%d restored=%d port=%d replug=%d dma=%08lx ehci_port=%08lx/%08lx config=%08lx/%08lx gate=%08lx/%08lx ohci_port=%08lx/%08lx",
                   probe_result,fullspeed.restored,fullspeed.port,fullspeed.replug_seen,
                   (unsigned long)fullspeed.dma_physical,
                   (unsigned long)fullspeed.ehci_port_before,
                   (unsigned long)fullspeed.ehci_port_during,
                   (unsigned long)fullspeed.ehci_config_before,
                   (unsigned long)fullspeed.ehci_config_during,
                   (unsigned long)fullspeed.ohci_gate_before,
                   (unsigned long)fullspeed.ohci_gate_during,
                   (unsigned long)fullspeed.ohci_port_before,
                   (unsigned long)fullspeed.ohci_port_after);
            report("FULLSPEED td setup=%08lx data=%08lx status=%08lx descriptor=%s valid=%d",
                   (unsigned long)fullspeed.setup_info,(unsigned long)fullspeed.data_info,
                   (unsigned long)fullspeed.status_info,descriptor,descriptor_valid);
            /* A full-speed probe ends here.  It has reset the target at
             * address zero, so no normal-DFU postcondition is inferred. */
            recovered_target=1;
            break;
        }
        if(pwndfu_requested && native_idle) {
#if A5WII_ENABLE_PWNDFU
            a5mate_result transition;
            report("A5MATE begin address=%u serial_index=%u profile=%s padding=0x%x",target_address,direct.data[16],A5WII_PROFILE_LABEL,packet_a5mate_profile_padding());
            int transition_result=packet_a5mate_profile(target_address,direct.data[16],&transition);
            report("A5MATE end result=%d phase=%u packet_step=%u token=%08lx restored=%d marker=%d pwn_ready=%d held=%d",
                   transition_result,transition.phase,transition.packet_step,
                   (unsigned long)transition.last_token,transition.restored,
                   transition.pwn_marker_seen,transition.pwn_ready,transition.held);
            report("A5MATE packets ok=%u timeout=%u error=%u global_out=%u/%u heap_out=%u/%u async_advance=%u fallback=%u",
                   transition.packets_ok,transition.packets_timeout,transition.packets_error,
                   transition.global_out_ok,transition.global_out_attempted,
                   transition.heap_out_ok,transition.heap_out_attempted,
                   transition.async_advances,transition.async_fallbacks);
            report("A5MATE EHCI qTD service total_us=%lu min_us=%lu max_us=%lu",
                   (unsigned long)transition.packet_elapsed_total_us,
                   (unsigned long)transition.packet_elapsed_min_us,
                   (unsigned long)transition.packet_elapsed_max_us);
            report("A5MATE packet-failure first=step%u/phase%u/pid%u/toggle%u/code%d/token%08lx last=step%u/phase%u/pid%u/toggle%u/code%d/token%08lx",
                   transition.first_error_step,transition.first_error_phase,
                   transition.first_error_pid,transition.first_error_toggle,
                   transition.first_error_result,(unsigned long)transition.first_error_token,
                   transition.last_error_step,transition.last_error_phase,
                   transition.last_error_pid,transition.last_error_toggle,
                   transition.last_error_result,(unsigned long)transition.last_error_token);
            report("A5MATE out-failure global=%d index=%u token=%08lx heap=%d index=%u token=%08lx",
                   transition.global_out_failure_result,transition.global_out_failure_index,
                   (unsigned long)transition.global_out_failure_token,
                   transition.heap_out_failure_result,transition.heap_out_failure_index,
                   (unsigned long)transition.heap_out_failure_token);
            report("A5MATE reset code=%d stage=%u port=%08lx/%08lx cmd=%08lx sts=%08lx frame=%08lx/%08lx",
                   transition.reset_result,transition.reset_stage,
                   (unsigned long)transition.reset_before,(unsigned long)transition.reset_after,
                   (unsigned long)transition.reset_command,(unsigned long)transition.reset_status,
                   (unsigned long)transition.reset_frame_before,(unsigned long)transition.reset_frame_after);
            report("A5MATE reset packets setup=%08lx status=%08lx",
                   (unsigned long)transition.reset_setup_token,
                   (unsigned long)transition.reset_status_token);
            report_a5mate_topology(&transition);
            if(!transition_result && transition.pwn_ready && transition.held) {
                report("A5MATE pwnDFU verified; holding direct EHCI ownership until clean ejection");
                if(pwn_hold_console()) {
                    report("A5MATE clean ejection released; returning to Homebrew Channel");
                    recovered_target=1;break;
                }
            }
            /* A failed transition has already restored IOS58's original
             * controller state in packet_a5mate_profile().  Do not leave the
             * Wii in a recovery listener merely because a deliberately
             * incomplete transfer cannot be re-identified immediately. */
            recovered_target=1;
            break;
#else
            report("A5MATE disabled at build time; rebuild with A5WII_ENABLE_PWNDFU=1 after reviewing the offline contract");
            recovered_target=1;
            break;
#endif
        }
        if(transfer_reset && native_idle) {
            recovered_target=transfer_reset_and_identify(target_address,direct.data[16]);
            if(!recovered_target){recovery_console(target_address);recovered_target=1;}
            break;
        }
        if(console_enabled && native_idle) {
            recovery_console(target_address);
            recovered_target=1;
            break;
        }
        if(packet_enabled && native_idle) {
            packet_transaction tx;
            if(drain_enabled)
                report("PACKETS begin address=%u serial_index=%u early_status=1 drain=1",target_address,direct.data[16]);
            else
                report("PACKETS begin address=%u serial_index=%u early_status=%d",target_address,direct.data[16],early_status);
            packet_read_transaction(target_address,direct.data[16],early_status,&tx);
            for(unsigned n=0;n<tx.count;n++) {
                packet_stage *stage=&tx.stage[n];
                char bytes[129];for(unsigned j=0;j<stage->requested;j++)snprintf(bytes+2*j,3,"%02x",stage->bytes[j]);
                bytes[2*stage->requested]=0;
                report("PACKET index=%u pid=%u toggle=%u requested=%u result=%d before=%08lx after=%08lx bytes=%s",
                       n,stage->pid,stage->toggle,stage->requested,stage->result,
                       (unsigned long)stage->before,(unsigned long)stage->after,bytes);
            }
            report("PACKETS end result=%d count=%u restored=%d cmd=%08lx/%08lx async=%08lx/%08lx",
                   tx.result,tx.count,tx.restored,(unsigned long)tx.saved_command,(unsigned long)tx.restored_command,
                   (unsigned long)tx.saved_async,(unsigned long)tx.restored_async);
            if(reset_enabled) {
                recovered_target=reset_and_identify(target_address,1,retry_reset);
                if(!recovered_target)recovery_console(target_address);
                break;
            }
            ehci_probe_result after;
            ehci_descriptor_probe(target_address,&after);
            char hex[37];for(unsigned j=0;j<18;j++)snprintf(hex+2*j,3,"%02x",after.data[j]);
            report("PACKETS recovery result=%d setup=%08lx data=%08lx status=%08lx descriptor=%s",
                   after.result,(unsigned long)after.setup_token,(unsigned long)after.data_token,
                   (unsigned long)after.status_token,hex);
            recovered_target=descriptor_is_target(&after);
            if(recovered_target) {
                const char *recovery_label=drain_enabled?"DRAIN":"PACKETS";
                ehci_probe_result serial_read,state_read;
                const u8 read_serial[8]={0x80,6,after.data[16],3,9,4,254,0};
                ehci_read_probe(target_address,read_serial,254,1,&serial_read);
                unsigned remaining=(serial_read.data_token>>16)&0x7fff;
                unsigned received=remaining<=254?254-remaining:0;
                unsigned expected=2+2*strlen(native_serial);
                int same=serial_read.result==0 && received==expected &&
                    serial_read.data[0]==expected && serial_read.data[1]==3;
                for(unsigned j=0;same && native_serial[j];j++)
                    same=serial_read.data[2+2*j]==(u8)native_serial[j] && serial_read.data[3+2*j]==0;
                report("%s SERIAL result=%d received=%u same_target=%d",recovery_label,serial_read.result,received,same);
                recovered_target=0;
                if(same) {
                    const u8 getstate[8]={0xa1,5,0,0,0,0,1,0};
                    ehci_read_probe(target_address,getstate,1,1,&state_read);
                    recovered_target=state_read.result==0 && state_read.data[0]==2 &&
                        ((state_read.data_token>>16)&0x7fff)==0;
                    report("%s GETSTATE result=%d state=%u idle_validated=%d",
                           recovery_label,state_read.result,state_read.data[0],recovered_target);
                }
            }
            if(!recovered_target)recovery_console(target_address);
        }
        if(reset_enabled && !packet_enabled && native_idle) {
            recovered_target=reset_and_identify(target_address,0,0);
            if(!recovered_target)recovery_console(target_address);
        }
        if(partial_enabled && native_idle) {
            const u8 partial_setup[8]={0x80,6,3,3,9,4,128,0};
            ehci_probe_result partial, finished, recovered;
            report("PARTIAL reading 64 of 128 requested bytes, omitting status stage");
            ehci_read_probe(target_address,partial_setup,64,0,&partial);
            // Terminate the pending read before submitting a fresh SETUP.
            ehci_finish_read(target_address,&finished);
            ehci_descriptor_probe(target_address,&recovered);
            report("PARTIAL result=%d setup=%08lx data=%08lx status=%08lx prefix=%02x%02x%02x%02x",
                   partial.result,(unsigned long)partial.setup_token,(unsigned long)partial.data_token,
                   (unsigned long)partial.status_token,partial.data[0],partial.data[1],partial.data[2],partial.data[3]);
            report("PARTIAL finish result=%d status=%08lx",finished.result,(unsigned long)finished.status_token);
            report("PARTIAL recovery result=%d descriptor=%02x%02x vid=%02x%02x pid=%02x%02x",
                   recovered.result,recovered.data[0],recovered.data[1],recovered.data[9],
                   recovered.data[8],recovered.data[11],recovered.data[10]);
            report("PARTIAL recovery setup=%08lx data=%08lx status=%08lx active_async=%08lx restored_async=%08lx",
                   (unsigned long)recovered.setup_token,(unsigned long)recovered.data_token,
                   (unsigned long)recovered.status_token,(unsigned long)recovered.active_async,
                   (unsigned long)recovered.restored_async);
            recovered_target=descriptor_is_target(&recovered);
            if(!recovered_target){recovery_console(target_address);recovered_target=1;}
        }
        break;
        }
        if(!recovered_target)report("DIRECT baseline failed; contract not validated");
    }
    USB_Deinitialize();
done:
    report("DONE returning to Homebrew Channel");
    report("Visit https://olsro.fr for cool stuff and to support Olsro with a donation.");
    usleep(12000000);
#if A5WII_ENABLE_NETWORK
    if(logfd>=0)net_close(logfd);
#endif
    return 0;
}
