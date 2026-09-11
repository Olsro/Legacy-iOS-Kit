#ifndef A5WII_EHCI_PROBE_H
#define A5WII_EHCI_PROBE_H
#include <gccore.h>
typedef struct {
    int result;
    u32 setup_token, data_token, status_token;
    u32 saved_command, saved_async, restored_command, restored_async;
    u32 active_command, active_status, active_async, qh_next, qh_token, dma_address;
    u32 programmed_async;
    u8 data[256];
} ehci_probe_result;
void ehci_descriptor_probe(u8 address, ehci_probe_result *result);
void ehci_read_probe(u8 address,const u8 setup[8],u16 read_length,int finish_status,ehci_probe_result *result);
void ehci_finish_read(u8 address,ehci_probe_result *result);
#endif
