#include <assert.h>
#include <stdio.h>
#include "../sources/a5wii/source/ehci_topology.h"

int main(void) {
    /* Every advertised port is selectable, including those beyond the
     * original four-port assumption. Unadvertised registers are ignored. */
    for(unsigned count=1;count<=15;count++) {
        for(unsigned target=0;target<count;target++) {
            a5mate_topology t={0};
            t.hcsparams=0x1200U|count;
            t.portsc[target]=0x1005;
            if(count<15)t.portsc[count]=0x1005;
            assert(a5mate_select_port(&t)==0);
            assert(t.ports==count && t.connected==1 && t.ehci_connected==1);
            assert(t.selected_port==(int)target);
        }
    }
    a5mate_topology t={0};
    assert(a5mate_select_port(&t)==-20 && t.selected_port==-1);
    t.hcsparams=4;
    assert(a5mate_select_port(&t)==-27 && t.selected_port==-1);
    t.portsc[0]=0x3001; /* Only a companion-owned device: never select it. */
    assert(a5mate_select_port(&t)==-27 && t.connected==1 && t.ehci_connected==0);
    t.portsc[2]=0x1085; /* The DFU port may be suspended before takeover. */
    assert(a5mate_select_port(&t)==0 && t.selected_port==2);
    assert(t.connected==2 && t.ehci_connected==1);
    t.portsc[1]=0x1005; /* Two high-speed connections: ambiguous. */
    assert(a5mate_select_port(&t)==-27 && t.selected_port==-1);
    t.portsc[1]=0x1001; /* Disabled, but still connected: also ambiguous. */
    assert(a5mate_select_port(&t)==-27 && t.selected_port==-1);
    t.portsc[1]=0;
    t.portsc[2]=0x1001; /* A single disabled port is not reset-ready. */
    assert(a5mate_select_port(&t)==-28);
    t.portsc[2]=0x0005; /* No power. */
    assert(a5mate_select_port(&t)==-28);
    t.portsc[2]=0x1105; /* Reset already in progress. */
    assert(a5mate_select_port(&t)==-28);
    t.portsc[2]=0x1005;
    assert(a5mate_select_port(&t)==0 && t.selected_port==2);
    puts("EHCI topology selection: all tests passed");
    return 0;
}
