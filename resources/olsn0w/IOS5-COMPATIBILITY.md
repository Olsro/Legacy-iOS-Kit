# iOS 5 compatibility and validation

iOS 5 is selectable in the normal olsn0w menu for every compatible A5/A5X
model, including models not yet tested on hardware. No experimental flag or
per-model validation opt-in is required. iPad3,1 and iPhone4,1 / iOS 5.1.1
(9B206) are validated with official activation, a working interface, Cydia
and AppSync installation after the corrections described below. The iPad also
passed AppSync reinstallation and respring checks. Other models
and builds remain untested, not blocked. Firmware identity, patch-pattern,
signature, storage, activation and first-boot checks remain mandatory.

## Scope

The catalog accepts the actual iOS 5 releases published for iPhone4,1,
iPad2,1–iPad2,4 and iPad3,1–iPad3,3. iPad2,4 and iPad3 models start at 5.1;
the others start at 5.0. Every IPSW must still match the product and board.
iPad mini, iPod touch 5G and A6 devices did not ship iOS 5 and are excluded.
The signed 8.4.1 base remains mandatory; iPhone4,1 retains multipatch.

## Separate legacy contracts

- The iOS 5 iBSS receive-length and iBEC RAM autoboot instruction layouts are
  recognized explicitly. Unknown or ambiguous patterns fail preparation. The
  existing iOS 6–8 recipes are not replaced with these patterns.
- The graphical logo loader accepts the checked iOS 5 instruction ordering;
  the generated trampoline still passes the execution checks.
- Aquila's shipped `aquila_5.tar` executable matches the already checked legacy
  binary. Native launchd runs the guarded first-boot handoff before Aquila.
- The helper binaries in `target/ios5/` use an iOS 5 deployment target and
  `LC_UNIXTHREAD`/crt1, not the iOS 6 `LC_MAIN` convention. The provenance manifest
  checks their signatures, source and build-script hashes. The existing iOS 6
  helper artifacts remain unchanged.
- A5 iOS 5 uses the 10B329 RAM formatter/crypto environment, never the iOS 8
  environment. The fresh, metadata-only Data image receives cprotect v2 before
  target boot. The target creates its system keybag before extracting regular
  files or personalization. A class-D **file** probe must succeed before the
  generation marker is published; the iOS 6 directory-class probe is not reused.

The DeviceTree retains olsn0w's nonstandard `no-effaceable-storage` policy. Older
iOS 5 trees lack the capacity property used by the existing recipes, so this
route supplies an explicit nonzero 32-bit value. A successful class-D probe is
not proof of stock-equivalent key storage, all protection classes, or passcode
security. Those claims require separate validation.

The v2 format and regular-file boundary follow Apple's
[XNU 1699 cprotect definitions](https://github.com/apple-oss-distributions/xnu/blob/xnu-1699.26.8/bsd/sys/cprotect.h)
and [HFS implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-1699.26.8/bsd/hfs/hfs_cprotect.c).
They are a preparation basis, not evidence of successful protection on hardware.

## Building the separate helpers

`native/target/build-ios5-helpers.sh CLANG MACH_O_LD IOS5_SDK OUTPUT_DIRECTORY`
requires a Mach-O linker with ARMv7 support and an iPhoneOS 5 SDK containing
`usr/lib/crt1.o`. Sign each resulting helper with the corresponding existing
helper entitlements, then regenerate its checked provenance manifest. Normal
users consume the checked artifacts and do not need this SDK.

## Qualification checklist

### iPad2,2 with 8 KiB sectors: user report

On 2026-10-25, the reporter in
[issue #11](https://github.com/Olsro/Legacy-iOS-Kit/issues/11#issuecomment-6401931903)
confirmed that restoration to iOS 5.1.1 worked after the disk-sector fix.
The preceding RAM diagnostics identified a 64 GB iPad2,2 with 8,192-byte
logical sectors and a valid stock GPT. The earlier 4,096-byte raw read failed
with `Invalid argument`; a 16 KiB read succeeded.

### iPhone 4S first restoration and modem path

On 2026-09-28, iPhone4,1 / 5.1.1 (9B206) with multipatch passed the signed
8.4.1 restore, volume readbacks and filesystem checks. The first boot returned
to stock iBoot Recovery with `Kernelcache image not valid`. The RAM rescue
confirmed a persistent `boot-partition=2` left after the user's DRA installation.
After backing up and clearing NVRAM, then setting `auto-boot=true`, the same
installation reached Setup without rewriting any volume. Recovery `getenv`
output alone was not reliable for absent variables; the rescue plist was used
to confirm the state. This recovery step is not an automatic NVRAM wipe.

An independent iOS 5 personalization omission prevented modem startup: the
selected-device Trek archive was present at the iOS 6+ path, but iOS 5 expects
`/usr/standalone/firmware/Trek-personalized.zip`. This legacy location is also
documented in the [iOS 5 dualboot guide](https://nyansatan.github.io/dualboot/ios5dualboot.html).
Copying the existing archive there allowed CommCenter to recover without a
restart. Baseband 6.7.00 and official `Activated` status were then verified.
Personalization now selects that archive directory for iOS 5 only; host tests
cover all iOS 5 releases and retain the iOS 6–8 paths and archive contents.
No modem ticket is fabricated and no extra firmware flashing is required.

The same 4S passed generation-bound Cydia startup, SpringBoard and boot-success
checks. System was read-write, Data was mounted with `protect`, the native
class-D file probe returned `before=4 set=0 after=4`, and named `installd`
queries worked. The user then confirmed completing the functional checks,
updating the Cydia packages and installing AppSync without disappearing
SpringBoard applications: everything worked. This validates the tested
iPhone4,1 / 5.1.1 combination end to end with multipatch and official activation,
after the two corrections above. A subsequent post-installation reboot was
not reported in this run; this result does not qualify every 4S hardware
revision or other iOS 5 builds.

### iPad 3 restoration

Host tests cover model boundaries, normal menu selection for all compatible models, legacy instruction
patterns, helper entry format and provenance, and metadata-only v2/v4 HFS
initialization with readback and no-mutation rejection of existing payloads.
On 2026-09-28, the first iPad3,1 / 5.1.1 (9B206) restoration passed from one
initial pwnDFU entry: signed-base handoff, all volume readbacks and filesystem
checks, graphical target boot, official activation, SpringBoard and Cydia's
generation-bound startup job. The target mounted System read-write and Data
with `protect`; its native file probe returned `before=4 set=0 after=4` and the
new system keybag was present. Before Setup, the language array was nonempty;
selecting French changed its first entry to `fr`.

Interactive package installation was subsequently validated after the socket
correction below. This does not validate all protection classes across
lock/unlock, other builds or other models. The separate forced-reset/language
tests are recorded below.

### Forced reset immediately after Setup

The same iPad returned to Setup after the user forced a reset immediately upon
reaching SpringBoard, before opening Cydia or adding packages. Read-only host
observations showed `fr_FR`, a nonempty language array beginning with `fr`, and
both `SetupDone` and `SetupFinishedAllSteps` set before the reset. Afterward,
both completion keys were absent and the locale was `en_US`, but the language
array still began with `fr`. Activation remained `Activated`, the Data generation
was unchanged, and the existing keybag and generation-file modification times
still belonged to the first boot. The system booted normally; this was a partial
configuration-state loss, not a boot failure.

Loss of recent unflushed writes is a hypothesis, not a proven root cause. This
does not reproduce the exact empty-language-array application exception seen
on iOS 6, and no stock iOS 5 control test has been performed. Do not add a fix
that silently chooses the user's language or forges Setup completion flags.
The iOS 6 missing-language incident was not reproduced and must not be treated
as a confirmed stock iOS defect or as proof of an iOS 5 defect.

After the user completed Setup a second time, the host checked the real French
preferences and completion keys, ran `/bin/sync` without changing their values,
then re-read them. A second user-initiated forced reset reached SpringBoard in
French. Both completion keys and `fr_FR` survived, and the native class-D file
probe still returned `before=4 set=0 after=4`. This control combines elapsed
time and explicit synchronization: it strengthens the persistence hypothesis
but does not isolate either factor or demonstrate a stock-system defect.

### Package installation and launchd socket lifetime

The first interactive package test exposed a separate iOS 5 integration bug:
after installing AppSync and updating `apt7-lib` and `debianutils`, SpringBoard
lost all application icons. The application bundles and populated installation
cache remained present, with free space on both volumes. Cydia logged
`launch_msg(): Socket is not connected`; AppSync had unloaded `installd`, whose
reload failed. The all-jobs `launchctl list` query still worked, but named-job
queries and loading jobs failed, and `/var/tmp/launchd/sock` was absent.

Apple's [launchctl boot sequence](https://github.com/apple-oss-distributions/launchd/blob/launchd-392.38/launchd/src/launchctl.c)
reads `launchd.conf`, then empties `/var/run` and `/var/tmp`, then invokes
`dirhelper -machineBoot`. The Kit's existing g1lbertJB iOS 5 route already
preserves a hard link to the live launchd socket outside those directories and
restores it from dirhelper. The experimental Aquila preparation omitted that
handoff. Recipe 46 applies this preservation **only to iOS 5**, using a private
olsn0w directory; it preserves any stock dirhelper at a separate path and calls
it before restoring the socket. The tested 9B206 image has no stock dirhelper.
This does not replace launchctl or modify application registration caches.

On the same iPad3,1 / 9B206, the correction was installed without restoring or
erasing Data. After a controlled reboot, the socket existed, named-job queries
worked, and `installd` was running. A disposable on-demand job could be loaded,
queried and unloaded. The user confirmed that the icons returned and Settings
and Cydia opened, then reinstalled AppSync and completed the respring: all icons
remained and Settings still opened. French preferences and Setup completion
also survived. This validates that package workflow on this device/build, not
every tweak or all iOS 5 models/releases.

Cydia preflight now requires the named `installd` query on the iOS 5 route;
an all-jobs query alone cannot qualify this transport. Host regression tests
exercise real Unix socket hard links across temporary-directory cleanup,
repeated boots, optional native dirhelper delegation, and failure of the new
preflight on missing or malformed service responses. iOS 6–8 boot configuration
does not acquire this socket workaround.
