# A5 two-image loader

`multi_kloader.c` is derived from winocm's GPL-2.0-or-later multi_kloader.
It retains separate raw iBSS / plaintext IMG3 iBEC destinations and requests
sleep immediately after installing the trampoline. The independent `wake_a5`
observer arms the eight-second relative wake before the controller starts it.
There is no cable-unplug countdown or host-trigger gate.

The bundled binary in `target/a5-loader` is the exact hardware-qualified
53920-byte build, SHA-256 recorded in its manifest. Normal preparation verifies
and copies it; no compiler or SDK is needed. Qualification is currently the
iPod5,1 8.4.1 bootstrap and 6.1.3 target, not every A5 model/release.

To rebuild a candidate, compile for `armv7-apple-ios8.0`, Thumb, `-Os`,
`-DINLINE_IT_ALL=1` with Clang and Darwin headers. Link with an ARMv7-capable
Mach-O linker (`ld-classic`, not current LLVM ld64.lld), libSystem and IOKit,
then sign with platform-application, get-task-allow, task_for_pid-allow and
run-unsigned-code entitlements. The original source's iPhoneOS SDK invocation
is also included in its header. A rebuilt candidate requires new qualification;
do not silently update the pinned binary hash on a preparation machine.
