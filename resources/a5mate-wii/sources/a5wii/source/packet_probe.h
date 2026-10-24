#ifndef A5WII_PACKET_PROBE_H
#define A5WII_PACKET_PROBE_H
#include <gccore.h>
#include "ehci_topology.h"
#define PACKET_MAX_STAGES 8
typedef struct {
    u8 pid, toggle;
    u16 requested;
    u32 before, after;
    int result;
    u8 bytes[128];
} packet_stage;
typedef struct {
    int result, restored;
    unsigned count;
    u32 saved_command, restored_command, saved_async, restored_async;
    packet_stage stage[PACKET_MAX_STAGES];
} packet_transaction;
typedef struct {
    int result, restored, port;
    u32 before, asserted, after, hold_us;
    u32 interrupted_status, interrupted_irq;
    u32 during_1ms, during_50ms, during_command, during_status;
    u32 saved_command, restored_command, saved_async, restored_async;
    unsigned count;
    packet_stage stage[28];
    int address_verified;
    u32 last_qh_token, last_async, expected_async;
    int cleanup_attempted, cleanup_result;
    unsigned cleanup_before_stage;
    u32 cleanup_before, cleanup_1ms, cleanup_50ms, cleanup_after, cleanup_hold_us;
} packet_reset;

/*
 * A controller-owned transcription of the a5mate state machine selected at
 * build time (A5_8940, A5_8942, or A5_8945).
 * The caller must identify the exact target before invoking it.  The
 * transaction never calls IOS or networking code during the raw packet
 * sequence.  On the pwnDFU milestone it deliberately retains controller
 * ownership, so IOS58 cannot submit a follow-up control request.
 */
typedef struct {
    int result, restored;
    unsigned phase, packet_step;
    u32 last_token;
    int pwn_marker_seen, normal_dfu_restored;
    int pwn_ready, held, ejected;
    a5mate_topology topology;
    unsigned packets_ok, packets_timeout, packets_error;
    /* Completed qTD service time.  This characterizes the EHCI cadence on
     * the Wii before deliberately applying any full-speed-frame shaping. */
    u32 packet_elapsed_total_us, packet_elapsed_min_us, packet_elapsed_max_us;
    /* EHCI high-speed path: successful asynchronous-advance fences and
     * conservative stop/restart fallbacks while reusing the one-QH ring. */
    unsigned async_advances, async_fallbacks;
    /* First/last non-successful primitive: enough to separate intentional
     * a5mate stalls from a sequence break without retaining a full trace. */
    unsigned first_error_step, last_error_step;
    u8 first_error_phase, first_error_pid, first_error_toggle;
    u8 last_error_phase, last_error_pid, last_error_toggle;
    int first_error_result, last_error_result;
    u32 first_error_token, last_error_token;
    unsigned global_out_attempted, global_out_ok;
    unsigned heap_out_attempted, heap_out_ok;
    int global_out_failure_result, heap_out_failure_result;
    unsigned global_out_failure_index, heap_out_failure_index;
    u32 global_out_failure_token, heap_out_failure_token;
    /* Most recent reset/re-address boundary, retained for recovery telemetry. */
    int reset_result;
    unsigned reset_stage;
    u32 reset_before, reset_after, reset_command, reset_status;
    u32 reset_frame_before, reset_frame_after;
    u32 reset_setup_token, reset_status_token;
} a5mate_result;
int packet_a5mate_profile(u8 address,u8 serial_index,a5mate_result *out);
unsigned packet_a5mate_profile_padding(void);
/* Seize EHCI without emitting any iPhone transaction when IOS58 has already
 * observed the immutable pwnDFU serial marker. */
int packet_a5mate_hold_existing(u8 address,a5mate_result *out);

/* Bounded prerequisite for the full-speed path.  It temporarily gives the
 * two external ports to OHCI0, reads the target's device descriptor at
 * address zero through OHCI, then restores IOS58's exact controller state.
 * It does not run any checkm8/a5mate packet sequence. */
typedef struct {
    int result, restored, port, replug_seen;
    u32 ehci_port_before, ehci_port_during, ehci_config_before, ehci_config_during;
    u32 ohci_gate_before, ohci_gate_during;
    u32 ohci_port_before, ohci_port_after;
    /* The OHCI descriptor/data workspace must reside in MEM1.  Retain its
     * bus address in the report so a probe can prove that invariant. */
    u32 dma_physical;
    u32 setup_info, data_info, status_info;
    u8 descriptor[18];
} fullspeed_probe_result;
int packet_fullspeed_probe(u8 address,int require_replug,fullspeed_probe_result *out);
/* Available only after a verified pwnDFU hold.  Eject quiesces the Wii port
 * so the cable can be moved; release requires the physical disconnect before
 * restoring IOS58's original EHCI state. */
int packet_a5mate_eject(a5mate_result *out);
int packet_a5mate_release(a5mate_result *out);
// Read the already identified target's string in individually submitted packets.
// early_status: 0 = complete read, 1 = early status, 2 = early status then
// attempt to drain the remaining DATA0 packet (status was already accepted).
void packet_read_transaction(u8 address,u8 serial_index,int early_status,packet_transaction *out);
// Reset the sole connected EHCI port, read address zero, then restore the
// previously identified target's address before returning the schedule to IOS.
void packet_reset_target(u8 address,packet_reset *out);
// Diagnostic only: retry descriptor once after a babble on its data stage.
// Both attempts remain in the result; a successful retry does not erase it.
void packet_reset_target_retry(u8 address,packet_reset *out);
void packet_reset_target_drain(u8 address,packet_reset *out);
// One controller ownership interval: partial string read, no STATUS, reset,
// address-zero enumeration, original address restored, then return to IOS.
void packet_reset_interrupted(u8 address,u8 serial_index,int early_status,
                              packet_transaction *prefix,packet_reset *out);
// Complete a normal 128-byte DFU control read, including its status stage,
// before resetting and re-enumerating the same device.
void packet_reset_after_transfer(u8 address,u8 serial_index,
                                 packet_transaction *transfer,packet_reset *out);
#endif
