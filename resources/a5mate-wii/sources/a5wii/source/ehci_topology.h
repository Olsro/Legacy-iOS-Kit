#ifndef A5WII_EHCI_TOPOLOGY_H
#define A5WII_EHCI_TOPOLOGY_H
#include <stdint.h>

/* EHCI HCSPARAMS.N_PORTS is four bits; never read beyond that count. */
#define A5WII_EHCI_MAX_PORTS 15U
typedef struct {
    uint32_t hcsparams, portsc[A5WII_EHCI_MAX_PORTS];
    unsigned ports, connected, ehci_connected;
    int selected_port;
} a5mate_topology;

/* Read-only selection from a snapshot, shared with the host-side tests.
 * PORT_OWNER means a companion owns the port; it cannot be our directly
 * addressed high-speed DFU target. Do not guess between EHCI connections,
 * even if one of them is disabled. The caller requires a direct cable (no
 * hub) and has already verified the device through this EHCI controller.
 */
static inline int a5mate_select_port(a5mate_topology *t) {
    t->ports=t->hcsparams&15U;
    t->connected=0;t->ehci_connected=0;t->selected_port=-1;
    if(!t->ports)return -20;
    for(unsigned p=0;p<t->ports;p++) {
        uint32_t value=t->portsc[p];
        if(!(value&1U))continue;
        t->connected++;
        if(value&0x2000U)continue;
        t->ehci_connected++;
        t->selected_port=(int)p;
    }
    if(t->ehci_connected!=1){t->selected_port=-1;return -27;}
    /* Same powered/enabled/not-reset prerequisite as a5mate_reset_default.
     * A suspended port is allowed: the existing reset path resumes it. */
    if((t->portsc[t->selected_port]&0x3105U)!=0x1005U)return -28;
    return 0;
}
#endif
