# olsn0w

Part of **Olsro's Legacy iOS Kit**. See the [current hardware validation table](../../README.md#hardware-validation)
for successful device/version tests; the recipe history below also records earlier limitations.

Start `./restore.sh`, connect a supported A5/A5X/A6/A6X device, and open **Restore →
olsn0w (choose iOS version)**. Select the desired release by its menu number or version; olsn0w prepares and
checks its firmware, Apple signing ticket, modem, restore environment and compact
bootstrap automatically. No developer paths or build tools for the ARM helpers
are requested. The Python runtime is installed on first use.

After selecting the release, the guided menu requires an explicit activation
choice (`y` or `n`; empty input repeats the question). On a supported build,
the optional Hacktiv8 policy preserves `/Applications/Setup.app` and skips
official activation. If no Hacktiv8 recipe exists, the offered alternative
removes Setup.app and skips activation. The choice uses a separate checked
system cache. Neither bypass policy performs official activation or an
activation acknowledgement; the ordinary choice retains the official
activation and Setup Assistant flow. See the [Hacktiv8 guide](../hacktiv8/README.md).

Preparation calculates the remaining disk requirement from firmware and system
images that are not already cached, and reports it before creating large files.
An Internet connection is needed for firmware that is not already available.
After preparation, confirm the erase and follow the instructions for the initial
manual DFU entry. Existing verified IPSW archives are reused to avoid duplicate downloads.
The signed 8.4.1 restore, RAM handoff, compact installation,
target boot and, in normal mode, official activation verification then run automatically. Only
one manual DFU entry is used by the integrated A5 and A6 workflow; recovery after a failure
can require another. A5 devices require external pwnDFU, such as A5Mate's
model-appropriate `PWND:[checkm8]` state. Every failed DFU attempt can be retried without repeating
the completed firmware preparation. The current pipeline still restores the full signed base
before reducing it to the 30 MiB + 2 MiB bootstrap.

The menu follows releases published for the connected product across the
32-bit 8.4.1 OTA family. iOS 5, 6, 7 and 8 have installation recipes; iOS 9/10
remain outside the implemented target path. Preparation rejects firmware that
does not match checked patch patterns. Catalog availability is not physical
qualification of every listed build or hardware revision.

[iOS 5 preparation](IOS5-COMPATIBILITY.md) is available in the normal menu for
all compatible A5/A5X models, including models not yet physically tested.
iPad3,1 and iPhone4,1 / 5.1.1 are validated; no experimental flag is required for other
compatible models. The firmware catalog retains each model's real minimum OS.

Preparation displays a live, single-line percentage for downloads, archive
extraction, decryption, checksums and firmware assembly. Percentages refer to the
named operation's measured bytes, not estimated overall time. Opaque filesystem
operations show activity and elapsed time instead. Redirected output uses periodic
plain-text updates; the display never reports 100% before the operation succeeds.

Follow the computer's phase messages: the device can display stationary progress
bars, black screens and successive Apple logos during transitions. Success is
reported only after target verification and the activation policy selected in
the menu. Failures retain logs and
stop without silently repeating an erase. The guided frontend has host tests
and physical restore validation on the device/version combinations listed in
the main README; this does not qualify every profile.

After final target boot and its selected activation qualification, olsn0w retains manifests,
logs and the small device-bound technical collection while pruning reconstructible
restore archives and working images. A failure at any earlier stage preserves its
complete session for diagnosis. Mutable HFS working images use filesystem
copy-on-write clones where the host supports them, with an ordinary copy fallback.

## Enable network SSH after restoration

With the restored device booted normally and connected by USB, select **Misc
Utilities → Configure olsn0w restored device for SSH external access**. This
enables OpenSSH on all network interfaces (IPv4/IPv6), port 22, with username `root` and password
`alpine`. The existing olsn0w USB key remains accepted. Only the root password is
reset; the mobile account is unchanged.

Use the same Kit folder that performed the restoration: the option finds the
device-bound target keys under `saved/olsn0w/sessions/`, verifies the selected
device and installed generation, backs up both SSH configurations and the root
password file on the device, validates the new configuration, and restarts the
SSH service. If Cydia's standard OpenSSH service is already loaded, the option
uses it and disables the duplicate olsn0w listener; both configuration files
retain the olsn0w key. Otherwise it restarts the olsn0w service. Success requires
fresh root logins with the password and with the existing key.
The device's Wi-Fi address is displayed when available. No reboot is required.

The equivalent command is:

```sh
./restore.sh --olsn0w configure-ssh --product iPad2,5 --udid "$UDID"
```

For a target bundle saved elsewhere, append `--bundle "$BUNDLE"`. The backups
remain in `/var/lib/olsn0w/ssh-external-*` on the device. A normal restoration
continues to use USB-only, key-authenticated SSH until this option is selected.

## Reinstall a provisioned device

After preparing the firmware/system, supply the selected device's session and
attested compact base (activation, signed kernel/modem, mirrored partition table,
and qualified 30 MiB + 2 MiB bootstrap). These private artifacts belong under
`saved/olsn0w/`. A base from another ECID is rejected.

```sh
./restore.sh --olsn0w prepare-restore --product iPhone5,2 --version 7.1.2 \
  --session "$SESSION" --base "$BASE" --bundle "$BUNDLE"
# Enter DFU once, then run the complete erase/install/normal-boot check:
./restore.sh --olsn0w restore --product iPhone5,2 \
  --session "$SESSION" --bundle "$BUNDLE" --erase
```

Before personalization, the target image is sized for the actual modem and
activation files, the restore formatter, filesystem metadata and a free-space
reserve. The budget uses uncompressed file sizes and never relies on compression
or replacement of stock files to make the payload fit. Each personalized file
is read back before the partition layout is calculated.

The installer verifies the prepared inputs and current partition table before
committing the native LwVM layout. It writes and reads back the system and compact
bootstrap, formats fresh target Data with the selected iOS formatter, seeds it,
and checks every filesystem before requesting normal boot. iOS 5, 6, 7 and 8
format a fresh protected Data volume and write only its directory metadata
offline. On iOS 5 and 6, a guarded launchd.conf handoff creates a missing Apple
system keybag, then extracts the Data seed and personalization before Aquila;
an existing keybag is never replaced. A failed handoff blocks Aquila rather
than starting it against incomplete Data. iOS 7 and 8 use their protected
keybag first-boot path. No host disk
mounts or Docker are needed for this installation path. The same RAM connection
covers all installation stages.

`installation.json` records completed writes and failures; `qualification.json`
is published only after the target's version, Data generation, and SpringBoard
are observed. In the normal mode, activation must report `Activated` for the
command to succeed. Only then does the USB handshake acknowledge that existing
activation; it does not fabricate records or skip Setup Assistant. When the
explicit Setup.app-removal option is selected, activation is intentionally
omitted and is not part of the completion gate.
A failed installation stops in rescue and preserves its logs; it does not silently
repeat an erase. `--ram-ready` skips the DFU loader only when an already running,
authenticated rescue passes the same identity/mount checks.

Linux uses the Kit's existing pwn-tool selection; Apple Silicon uses its bundled
`ipwnder`. PyUSB/libusb checks that the selected DFU device is the only connected
iOS device before unscoped exploit tools run. Physical qualification of the Linux
USB path remains separate from host tests.

## Prepare a RAM rescue

`select --product TYPE --ecid ECID` creates a private session for the connected
recovery/DFU device. `prepare-rescue --product TYPE --session "$SESSION"` builds
its rescue from the selected stock 8.4.1 firmware and the Kit's SSH tools;
`--ipsw` can supply an existing firmware archive. Preparation writes host files
only and does not start a restoration.

Once the selected device is in the required pwned DFU state, start the prepared
rescue without erasing or restoring anything and open its authenticated root
shell with:

```sh
./restore.sh --olsn0w rescue --product TYPE --session "$SESSION"
```

The command owns the selected USB tunnel, verifies that `/` is the RAM disk and
that no internal volume is mounted, then opens a root shell. Type `exit` to close
the shell and USB tunnel; the device remains in the RAM rescue until rebooted.
When the rescue is already running, append `--ram-ready` to reconnect without
putting the device back in DFU or sending the boot chain again.

The rescue uses a 64,000,000-byte HFS volume, preserving the allocation size
qualified with the stock boot chain. A 64 MiB volume caused an early kernel
failure during qualification. Its startup does not automatically mount internal
partitions or run the Kit's general maintenance script. SSH uses generated keys
and a pinned host key. Maintenance commands verify the RAM root and hardware
before any disk access; the unmount helper only permits explicit rescue mount
points and never forces an unmount. Build provenance and hardware qualification
are recorded separately in the private session.
The startup stub returns immediately so launchd can register Apple's restore
services; the stock iOS 8 restore job starts the SSH/restore wrapper. The iPhone
4S multipatch rescue instead preserves the iOS 6 contract in which `rc.boot`
directly enters `restored_external`.

## Initial provisioning status

`prepare-provision` prepares an experimental signed-base IPSW with a held RAM
handoff. The host requires both a successful restore-tool exit with `DONE` and
the matching per-run NVRAM token before accepting that handoff. The reboot hook
does not try to remount the restore RAM for writing. A failed restore preserves
its journal and any available RAM diagnostics; it does not automatically retry
the erase or reboot. In particular, failure may leave `auto-boot` disabled and
the internal filesystems empty. An accessible rescue is not proof of a completed
restoration.

The signed-base restore followed by iOS 7.1.2 installation has been exercised
on iPhone5,2 from one initial DFU entry, without an intermediate base UI boot.
This does not qualify every listed model or target version. The current path
still restores the full 8.4.1 filesystem temporarily before replacing it with
the compact bootstrap. The original inner UDIF is retained after removal of its FileVault envelope and is checked
against the exact stock HFS bytes. A full transfer exposed a further ASR image
signature rejection. Preparation applies the Kit's failure-to-success branch
inside the RAM's ASR, located by its diagnostic-string references. The patched
executable retains its disk-access entitlement and its code hashes are checked;
the installed stock system is unchanged. Unknown or ambiguous instruction
patterns stop preparation. A successful metadata check or transfer alone does
not qualify the entire restoration.

The iPhone4,1 path follows upstream Legacy iOS Kit's battery-safe
`multipatch` policy. It keeps the signed 8.4.1 base and ticket, but restores it
through the checked 6.1.3 iBSS, iBEC, DeviceTree, kernel and restore ramdisk;
the target 8.4.1 restore options and library are copied into that environment.
The Kit's checked multipatch ASR and `restored_external` replacements are used,
and only the erase BuildIdentity is routed to the added `Downgrade` components.
The Trek modem donor is 9.3.6 (Trek 6.7.00). A complete 4S provisioning IPSW
and 32 MiB ARMv7 bootstrap reproduce successfully on the host. Subsequent 4S
restores to 6.1.3, 7.1.2 and 8.3 were confirmed functional, including Cydia;
this does not establish compatibility for all manufacturing revisions.

After a successful signed restore, the held RAM can collect its personalized
kernel, modem and partition table, then install the selected target. Official
activation is performed on the target through the Kit's activation utility;
no fabricated records or prior activation from another device are used.
Recovery using an already attested base remains a separate path.

For the native iOS 6 restore environment, Mav5 collection accepts the additional
restore-only `restoresbl1.mbn` member in the personalized ZIP, including on the
cellular iPad mini (`iPad2,6` and `iPad2,7`). Only the required runtime modem
files are transferred to the target. Missing required files, unknown members
and duplicate ZIP entries still stop collection, with their names in the error.
An earlier `Personalized modem archive has an unexpected component set` failure
can therefore be caused by the old collector rejecting this restore-only member;
the original error alone does not identify the archive's actual contents.

For a prepared rescue, provisioning bundle and compact bootstrap,
`provision-restore` runs the entire sequence. The device must initially be in
DFU. Use `--base-keys` for 8.4.1; optional `--keys` and `--ipsw` refer to the
selected target. Cellular devices also require the selected baseband and its
manifest. This developer interface still requires separately prepared inputs.

```sh
./restore.sh --olsn0w provision-restore --product iPhone5,2 --version 7.1.2 \
  --session saved/olsn0w/session --bundle saved/olsn0w/provision \
  --bootstrap saved/olsn0w/bootstrap --ticket saved/olsn0w/base.shsh2 \
  --base-keys saved/olsn0w/base-keys.json \
  --baseband saved/baseband/Mav5-11.80.00.Release.bbfw \
  --baseband-manifest saved/iPhone5,2/14G61.plist --erase
```

During restoration, the host names the component being sent, reports each
step's percentage, and distinguishes transfer from verification and boot wait.
The phone's base-restore bar may stay unchanged while the target is installed.
Sparse Data progress counts bytes actually transferred, not the last disk
position. Waiting messages do not claim progress or a successful boot; target
services and, in normal mode, official activation must still be observed within
the timeout.
Startup observation normally never reboots a device whose initialization did
not finish. The Setup.app-removal mode has one bounded exception on the iOS 7.1 Pangu path:
after the selected Data generation, SpringBoard and Pangu completion marker are
all observed repeatedly, a root volume that remains read-only receives one
controlled reboot so Pangu can retry. A second failure is reported without
another reboot. The iPod touch 5G / iPhone 4S Aquila paths do not use this retry.
On the iOS 7.1 Pangu path, its launchctl call is only an intermediate signal:
Pangu still has to finish its kernel work and remount the selected System
partition. The host therefore never treats that marker alone as completion and
requires the real root mount to be read-write before Cydia initialization or
successful qualification. This is necessary for `dpkg` and Cydia package
upgrades. Failures preserve the logs and report the observed stage without
reinstalling the device.

## Hosts and dependencies

Linux and macOS use the same Python implementation. Supported host architectures
follow the kit: x86_64 and arm64. Preparation requires Python 3.8 or later, curl,
and the kit's `iBoot32Patcher`, `xpwntool`, `dmg`, and `hfsplus` binaries. System
image preparation also uses `ssh-keygen` and the same pinned ldid release used
by the kit (downloaded into the private working directory). Capstone
and Unicorn provide binary inspection and instruction emulation. PyCryptodome
decrypts the firmware envelope identically on either host. PyUSB explicitly loads
the native library supplied by the pinned `libusb-package==1.0.26.4` dependency
in the private Python environment. This includes a macOS 10.9+ Intel wheel and
does not require Homebrew. Runtime preflight checks the actual libusb backend,
not just the Python import, before any firmware preparation. Post-boot activation
acknowledgement uses libimobiledevice and libplist on either host.

Linux tools receive an absolute path to the Kit's bundled shared libraries,
including LibreSSL, even when launched from a session working directory. Before
DFU preparation, the restore tool is started without restore arguments to check
its loader; diagnostics are saved in `provision/restore-loader.log`.
The signed-base restore saves its full stdout and stderr in
`saved/olsn0w/sessions/<session>/provision/restore.log` for menu sessions
(or `<bundle>/restore.log` when using an explicit `--bundle`). The terminal
prints the absolute log path when the file is created and repeats it with the
exit code if the restore tool fails or exits without reporting `DONE`.
Failed restores retain the session directory, including `provision/run.json`
and any available RAM diagnostics.
Before firmware preparation, `ssh -G` checks that the host SSH client accepts
the required options without connecting. RSA compatibility uses
`PubkeyAcceptedKeyTypes`, accepted by both older High Sierra clients and newer
OpenSSH versions. Saved RAM SSH argument vectors using the newer
`PubkeyAcceptedAlgorithms` spelling are normalized when loaded; existing keys
and strict host-key pinning are preserved. Failed RAM handoff connections retain
the underlying SSH diagnostic in `handoff-ssh.log` in the session directory and
include it in the terminal error. An invalid client option fails immediately;
temporary connection failures are still retried while the RAM service starts.
Known-hosts paths are quoted for OpenSSH itself, so Kit folders containing spaces
(such as `Legacy-iOS-Kit-main 2`) retain strict host-key verification. Saved RAM
SSH arguments receive the same quoting correction when loaded.
RAM, bootstrap and target identity checks retain Apple's mixed-case board names
(`K93aAP` on iPad2,4 and `J2aAP` on iPad3,3). Older system preparations are rebuilt
to update the on-device guards and bootstrap helpers. A RAM identity rejection
reports the expected model/build and the received `sysctl` output, and retains
that diagnostic in `handoff-ssh.log` without retrying validation.

On Linux and Intel Macs, the DFU step delegates to the Kit through an internal
mode that preserves the owning menu's temporary files and usbmuxd instance.
It discovers and checks the selected product/ECID without opening another menu.
The `kit-pwn` diagnostics are displayed live and saved in the session log;
timeouts stop the helper's process group, including descendants holding pipes.

The menu and standalone entry point automatically create or repair the private
Python environment before device operations. They check the pinned package
versions and load the native libraries, so an interrupted installation is retried
on the next launch. Missing Python/venv prerequisites are installed using the host
package manager (APT, DNF, Pacman, Zypper or XBPS; Homebrew on macOS when available).
System package installation may request your sudo password. On macOS without
Homebrew, install Python 3.8+ from python.org if it is missing. Help, catalog
listing and model support checks do not require the private environment.
The Kit shows the olsn0w restore and SSH options for supported models even if
Python is missing or too old. Selecting an option runs the prerequisite check
and reports any installation problem in the terminal. This also applies to
Intel Macs running older macOS versions such as High Sierra.

After a cancelled preparation or a failure before any erase, selecting the same
device, exact iOS build and activation policy reuses a completed compatible
`guided-plan.json` from `saved/olsn0w/sessions/`. This skips rebuilding the five
preparation steps. Saved component checksums, recipe versions, device identity,
restore environment and ticket are checked first; sessions that may already
have started restoring are excluded. Keep the original `saved/olsn0w/` directory.
An early pipeline failure marker is archived as `pipeline-before-retry.json`;
prepared images and diagnostic logs are retained. Incomplete or obsolete plans
fall back to preparation, using the existing firmware/system caches.

During one process, an unchanged file is hashed once per algorithm. IPSW SHA-1
and SHA-256 are computed together in one read. Repeated checks reuse the result
only while the device/inode, size, modification time and change time match;
changed or replaced files are hashed again, and files changing during a read
are rejected. Hash results are not persisted: a new launch verifies saved files
again rather than trusting a previous run's filesystem metadata.

Run from the kit directory:

```sh
./restore.sh --olsn0w list --product iPhone5,2
./restore.sh --olsn0w prepare --product iPhone5,2 --version 7.1.2
./restore.sh --olsn0w prepare-system --product iPhone5,2 --version 7.1.2
```

The isolated Python runtime, downloaded firmware, generated images, keys, and
local validation reports live under the ignored `saved/olsn0w/` directory.
The firmware relay uses direct Thumb encoding and emulator checks. System and
compact-bootstrap image preparation compile an HFS helper with a C compiler,
CMake and zlib development files. Before building the helper, olsn0w checks a
small CMake project that compiles and links against zlib. Missing prerequisites
on Linux are installed automatically through the host package manager, then
checked again. On Ubuntu/Debian these are `build-essential`, `cmake` and `zlib1g-dev`.
On macOS, an installed `CMake.app` in `/Applications` or `~/Applications` is
detected automatically. If no working CMake is found, olsn0w downloads the
official CMake 3.31.12 macOS 10.10+ universal archive, verifies its pinned SHA-256,
and installs it under `saved/olsn0w/tools/` without Homebrew or sudo. This build
supports Intel Macs running High Sierra. The C compiler, Make and SDK/zlib still
require Apple's Xcode Command Line Tools: run `xcode-select --install`, complete
the installation, then relaunch olsn0w. If those tools are already installed,
inspect `xcode-select -p` and the displayed compile/link diagnostics.
This repair preserves the Python runtime and prepared firmware. Its tar importer
preserves symlink metadata without changing the target's permissions or ownership.
Bootstrap programs use Clang and an ARM-capable Mach-O
linker, with libraries extracted from the selected stock restore ramdisk. No Apple
SDK, Xcode project, or macOS image mount is needed. Linux compilation and image
checks are exercised during development. Cross-compilation toolchain setup for
bootstrap programs remains separate from the host HFS helper dependencies.
Docker is used for development checks.

Normal relays on A5/A5X and A6/A6X use graphical target boot arguments and the
same checked Apple-logo display hook. Relay recipe 24 invalidates the older A5
caches that forced `-v debug=0x14e` even in normal mode. The guided flow rebuilds
the relay and its dependent System/bootstrap images; already restored devices
are not modified. Explicit verbose relays omit the logo display hook so it does not replace diagnostic
output. The image-address patch preserves the register used by the selected
iBSS instead of assuming the same register across firmware versions. Prepared
relay manifests record the recipe version; older cached relays
must be rebuilt when the recipe changes.
Recipe 24 was prepared offline for iPod5,1 and iPhone4,1 on 6.1.3, 7.1.2 and
8.4.1, and iPad3,4 on 6.1.3 and 7.1.2. Each generated logo trampoline passed
the emulator's success and two failure paths with preserved registers/stack.
The explicit iPod 7.1.2 verbose relay was also checked. These checks do not
replace visual hardware confirmation of the new graphical A5 boot.

The bootstrap keeps a persistent enable marker on its read-only root. Diagnostic
attempt/failure records do not consume that marker, so interrupted attempts do
not require a target-side rearm. This policy has a controller test with failed
log writes and repeated attempts; it is not a hardware power-loss qualification.
The controller waits on a fresh pipe for untether completion before querying
the kernel port. The supervisor detects completion in the pinned child's output
stream; writable logs and markers from previous attempts are not readiness
signals. This synchronization has host regression tests; each assembled bootstrap
still needs hardware qualification.

Target preparation preserves the selected firmware's `fstab` mount options and
changes only the root and Data device paths. In particular, the iOS 7 root must
start read-only until the untether applies the kernel changes and remounts it.
The target Data volume must use HFS journaling. An unjournaled writable volume
can retain overlapping allocations after an interrupted boot; the limited
repair mode used during early iOS startup may then refuse to continue. Native
offline repair and journaling checks must precede a retry when corruption is
detected. Journaling does not replace hardware testing of abrupt shutdowns.

Package Data overlays preserve existing firmware directory modes and ownership.
Replacing these with package defaults can prevent system services from traversing
the mobile user's Library, even when their resource files are present. New
package directories and file replacements retain their package metadata.

On iOS 7 and 8, the untether's post-patch service load goes through an idempotent job loader. It reads
each XML or binary plist's actual `Label` and queries launchd before loading it;
registered jobs are left intact even when they have no running PID. Other
jobs disabled in their plist or launchd's persistent overrides are skipped;
an explicit persistent enable overrides the plist default. A disabled, absent
job must not be submitted and turn `nothing found to load` into a failed
untether handoff. This also preserves the deliberate disabling of the bundled
SSH service when the separately installed OpenSSH service owns port 22.
System recipe 47 rebuilds prepared images with this loader correction. Legacy
`launchctl load` can unlink a live Unix socket before rejecting a duplicate job,
breaking local activation queries and DNS while USB access still works. Query
failures are reported without attempting another load. The firmware's
`/bin/launchctl` remains unchanged. Pangu's `launchctl load -D all` is narrowed
to newly installed `/Library/LaunchDaemons` jobs, because PID 1 has already
registered the stock system jobs. Activation records and Setup Assistant
completion flags are not modified by this correction.

Every iOS 8 release keeps the stock early `/usr/libexec/keybagd`, matching the
validated iOS 8.3 boot path.

On iOS 8, an active `datamigrator` does not postpone official activation once
SpringBoard, Cydia, the selected identity and the personalized baseband are
verified. The service can remain active while Setup Assistant itself waits for
activation, so using its exit as the activation gate would deadlock first boot.
Official activation is also attempted through the selected lockdownd USB identity
independently of diagnostic SSH. A missing or rejected per-image SSH key still
fails final boot qualification, but can no longer leave Setup Assistant waiting
for an activation that the connected computer was already able to perform.
Early lockdownd availability can precede Apple's ability to create the activation
request. That response is now treated as transient and retried within the normal
startup deadline; every attempt is appended to `activation.log` for diagnosis.
Likewise, iOS 7 may expose SSH before protected Data has atomically published its
generation marker. That transient state is polled rather than treated as a wrong
installation; lockdownd still strictly verifies product, version and build before
activation, and final success still requires the selected Data generation.
The Cydia preparation diversion also restores the generated `sshd_config` at its
canonical path. Legacy `dpkg-divert` can move that file even without `--rename`;
without the restoration, a restarted sshd ignores the per-image authorized key.
The diagnostic job explicitly reads an undiverted reference configuration and
disables `StrictModes`, avoiding first-boot HFS ancestor-mode rejection. It stays
bound to loopback, disables password authentication and accepts only the
per-image key.

For iOS 7 releases using Aquila, the Apple `profiled` and `accountsd` jobs are
kept in `/olsn0w/late-jobs` and registered by Aquila's post-patch loader. Their
executables, Mach services, users and job options are preserved. This avoids
starting them against Aquila's early admission environment. Cydia preparation retries unsuccessful runs
with a 30-second launchd throttle, then stops retrying after successful completion;
its output is retained under `/var/logs/AppleSupport/olsn0w-cydia.log`. A
launchd `- 0` status alone is not accepted as completion because it also
describes a registered job that has never run. The final startup command
atomically publishes a marker containing the selected Data generation, and
qualification starts an idle uninitialized job and waits for that exact marker.
An intermediate nonzero launchd status is diagnostic rather than terminal:
launchd's configured retry can still complete successfully after protected Data
and the root remount settle, as observed on the iPad3,4. The timeout retains the
last failure and its log path if no generation marker is ever published.
This prevents the first Cydia launch from preceding its firmware and default
source initialization. The image also contains Cydia's `/User` compatibility
link and its Data-backed default-source link at the real `/private/etc` HFS
catalog path before first boot. The link's mobile-owned cache target is seeded
with the five default Cydia repositories as well; Cydia returning status 0
without creating that cache can therefore no longer yield an empty source list.
All iOS 5/6/7/8 target images also include the nine repositories listed at
http://cydia.olsro.fr/ (checked 2026-09-24): BigBoss, Cydia.vn, Eat My Phone,
Hack Your iPhone, ModMyi, Personal (Olsro), Ryan Petrich, Saurik and ZodTTD.
They use a separate root-owned `/private/etc/apt/sources.list.d/Olsro.list`,
like the existing LukeZGD source, without replacing the default repositories
or weakening APT signature checks. The list is prepared offline and checked
after insertion into the System image; no repository refresh is added to the
boot/activation sequence. System recipe 38 invalidates older prepared images
in the guided restore flow. Already restored devices are not modified.
The list is shared with the other jailbreak restoration paths in `restore.sh`;
see `resources/jailbreak/olsro/README.md` for the common payload and cache policy.
This is prepared offline because the Pangu
path can still have a read-only System volume when `firmware.sh` runs. A failed
`firmware.sh` no longer publishes a successful Cydia marker.
For iOS 7.1 profiles which do not select Aquila below, the restore recipe uses the Pangu untether already bundled and used
by Legacy iOS Kit, selecting its checked ARMv7 slice and retargeting it to the
chosen root volume. Its original launch service and the stock daemon layout are
retained, matching the Kit's A5X/A6X fallback instead of applying Aquila's daemon
relocation. Its bulk launchd request is routed through the same guarded loader so
it cannot invalidate lockdownd's live local socket. Earlier iOS 7 releases retain Aquila. The board-specific iOS 7 jetsam
policy gives the selected untether an explicit 128 MiB ceiling; the stock fallback
ceiling of 5 MiB can terminate the exploit before it remounts the selected root
read-write, leaving Cydia preparation unable to finish.

System recipe 39 selects the pinned Aquila 2.1.1 iOS 7 payload for the iPod touch
5G (`iPod5,1`) and iPhone 4S (`iPhone4,1`) on iOS 7.1.x. It preserves the same 7.1 bootstrap and stock daemon
layout (including native keybag ordering), not the relocated iOS 7.0 layout.
The Pangu binary and startup job are excluded. A single native
`org.olsn0w.aquila` job runs `/aquila` with `RunAtLoad`, `LaunchOnlyOnce` and a
128 MiB jetsam budget; there is no delayed retry or second exploit launch.
The selected root path and guarded job loader are retargeted and signed by the
existing checked Aquila preparation. Root read-write, generation, SpringBoard
and Cydia readiness remain mandatory for successful qualification.
Two normal boots and Cydia package installation were verified on the iPod under
7.1.2. The 4S was subsequently restored to 7.1.2 with user-confirmed working
interface and Cydia. Cold/forced-reset behavior and other 7.1 releases are not
qualified by those tests. The 4S multipatch/baseband path is unchanged.
Apart from the N42 qualification below, other devices and iOS 6/7.0/8 retain their existing recipes.
The guided flow rebuilds recipe-38 System caches automatically. This does not
modify already restored devices, the activation choice or Cydia sources.

System recipe 48 also selects Aquila for iPhone5,2 (N42) on iOS 7.1.2
(`11D257`). Pangu could reach its completion endpoint yet leave the selected
System volume read-only on a later normal reboot, blocking package installs.
That remount failure recurred after correcting disabled-job handling. The N42
profile uses the same native iOS 7.1 Aquila job and stock daemon/keybag layout,
with its own board's 128 MiB jetsam allowance. On the existing N42 installation,
three consecutive normal boots verified writable System, selected Data generation,
SpringBoard, Cydia initialization and boot-success; installing and purging a
temporary package through dpkg after the third boot also passed. The user then
confirmed successful package installation from Cydia. Pangu's startup job was
preserved outside LaunchDaemons for rollback. This profile
change is limited to iPhone5,2 on 7.1.2; iPhone5,1 and N42 7.1/7.1.1 keep their
existing untether selection.

System recipe 40 validates the pre-relocation LaunchDaemons against the exact
prepared overlay, including the boot-success job and optional Hacktiv8 job.
The former Cydia-only allowlist rejected these generated services on iOS 8
and the relocated iOS 7.0 path. Unexpected, missing, modified or non-regular
jobs and destination-name collisions still abort preparation before relocation.
This does not change the untether selection or the activation policy.

The guarded Pangu launch wrapper accepts `/private` only when its existing
read-only metadata is already exactly safe, then publishes a service-loading
gate after all payload jobs have been registered. Cydia waits for that gate on
iOS 7 and 8. The gate alone does not prove a successful kernel patch or remount:
the bundled Pangu can reach its launchctl endpoint after the remount failed.
Final restoration qualification therefore still requires the writable root
and Cydia completion, not just that marker.

Pangu's stock-jailbreak admission files are deliberately excluded:
olsn0w's boot relay already supplies `amfi=0xff cs_enforcement_disable=1`, so the
ordinary Pangu LaunchDaemon can start without its reduced loose libmis, global
dyld marker or system-only xpcd cache. Keeping those redundant overrides would
remove MIS APIs used by Apple applications and make the mobile-user xpcd crash,
which in turn blocks Messages and FaceTime. On devices selecting Pangu, its untether and
checked launch job remain installed; Apple services and Cydia use the firmware's
complete shared-cache implementations.

The small ARMv7 helper is shipped with source/build checksums in
`target/load-jobs.json`. An absent or zero-byte optional launchd overrides file
means no persistent Disabled settings, as seen on a fresh iOS 7.1.2 installation.
Nonempty malformed overrides and empty required job plists still fail closed.
System recipe 51 rebuilds cached images with this correction.

`native/target/build.sh` rebuilds it with Clang, an ARM
Mach-O linker and stock iOS libraries on Linux or macOS; sign the result with
the existing `signing.resign` function and update the checksums together. Its
minimum deployment target is iOS 6. Image integration covers iOS 6 and 7.
The iOS 6.1.3 recipe is physically qualified on iPad3,4: the stock unprotected
Data mount policy and package-provided Aquila launch route reach SpringBoard,
official activation, Wi-Fi and a working Cydia first start. This p101 build also
uses an exact, hash-pinned kernel fix after the TriStar System-ID retry. A
successful retry retains the real identifier; only a repeated
`kIOReturnBadMessageID` enters Apple's existing `0xffff` fallback. The fix is
also hash-pinned for every released iPad3,4 iOS 6 kernel: 6.0, 6.0.1, 6.1,
6.1.2 and 6.1.3. All five contain the same complete retry/fallback function;
6.0 and 6.0.1 place it at the earlier prelink address, while every 6.1 build
has byte-identical code at the 6.1.3 address. iOS 6.1.2 is physically qualified
through normal boot, official activation, SSH and a successful Cydia
first-start job. Unknown products, releases, builds or kernel hashes retain
their stock kernel instead of inheriting the workaround. Every patched
container is read back before being embedded. Every iOS 6 release on the
explicit Lightning profiles N41, N42, N78, P101, P102 and P103 receives the TriStar
DeviceTree reset; this major-version rule includes the phone-only 6.0.2 and
6.1.4 releases without maintaining an incomplete point-release list. The N78
rule covers every iOS 6 release available for iPod5,1; its 6.1.3 kernel contains
the same `AppleTriStarBuiltIn` reset-and-retry path and its parsed DeviceTree
has the same THS7383 TriStar node. A physical N78 restore without the property
reached the selected kernel but remained at the Apple logo before USB came up.
Relay recipe 25 extends this iOS 6 reset policy to the iPad mini Wi-Fi P105
(`iPad2,5`). Its 6.1.3 DeviceTree exposes the same THS7383-compatible TriStar
node and its kernel recognizes `soft-reset`. A fresh restoration without the
property stalled at the iOS 6 Apple logo without target USB. Adding only this
property to the installed target DeviceTree allowed normal boot, official
activation, the selected Data generation, SpringBoard and Cydia first-start
qualification. The user also confirmed completion of Setup Assistant and a
successful package installation through Cydia. The kernel, jailbreak, bootstrap
and activation policy were unchanged. Other iOS 6 releases use the same
major-version policy but have not been hardware-tested in this qualification.
Relay recipe 26 extends that iOS 6 policy to the cellular mini variants P106
and P107 (`iPad2,6` and `iPad2,7`) by family analogy, not by a separate hardware
qualification. All three mini variants retain their existing iOS 7/8 policy
(no forced reset). P105 (`iPad2,5`) was subsequently restored to 7.1.2 in one
DFU workflow without that reset: normal boot, official activation, writable
System, Data generation, boot-success and Cydia first-start checks passed.
The user confirmed end-to-end functionality. This run used the existing Pangu
profile, without an untether retry reboot. P105 was also restored to 8.3
(`12F69`) through one DFU workflow with EverUntether and official activation,
without Hacktiv8 or a forced TriStar reset. Normal boot, Data generation,
SpringBoard, boot-success and Cydia first-start checks passed; the user
confirmed full functionality. Neither run qualifies forced resets or the
cellular variants. All three iPad 4 variants already receive it on iOS 6/7/8;
the iPad 2/3 and iPhone 4S profiles remain excluded. Preparation still requires
exactly one TriStar node and verifies the packed DeviceTree by readback; a
missing or ambiguous node is an error, not a silently skipped patch. Stale
relay caches and dependent System images are rebuilt on next preparation.
For p101,
6.1.2 is physically qualified, the 6.0/6.0.1 and 6.1 DeviceTrees were
separately extracted, decrypted and parsed, and the 6.1, 6.1.2 and 6.1.3
DeviceTrees are byte-identical. The same reset is required by iPad3,4 on
iOS 7: without it, 7.1.2 panics before launchd and loops between the Apple logo
and a black screen. Adding only the TriStar `soft-reset` property was physically
qualified through two normal boots, official activation, the selected Data
generation and SpringBoard. The iPad3,5 and iPad3,6 profiles inherit this iOS 7
rule from the same A6X iPad 4 platform, but still need their own hardware
qualification. The iPhone 5 remains on the iOS 6-only rule because iPhone5,2
7.1.2 and its iOS 8 path were physically qualified without the property. The
iPad 4 A6X family keeps the reset through iOS 8: an iPad3,4 running 8.1.3 was
captured panicking in `AppleTriStarBuiltin` with `could not find system ID: bad
IPC message ID` before launchd when the property was absent. Reinstalling that
same target DeviceTree with `soft-reset` then completed the physical boot,
official activation and SpringBoard qualification on the same installation.
This reset policy remains explicit per qualified Lightning profile instead of
being inherited by unrelated products or SoCs. Existing prepared relay and
target-system images are rebuilt automatically by the guided flow to acquire
recipe changes.

Every selected target also installs a late boot-success job. It waits for
GraphicsServices and a stable SpringBoard, reruns Apple's `CrashHousekeeping`
executable (the preserved original where its launch path hosts the untether)
to acknowledge the PMU boot-failure and panic counters, and then restores
`auto-boot=true` before publishing a
generation-bound marker required by host qualification. Apple's stock job is
launch-once and runs before the olsn0w relay and untether handoff have finished;
the late invocation prevents failures during that handoff from remaining armed
after a successful target boot. This keeps the early-crash Recovery safeguard
intact while ensuring that a later interrupted startup does not consume stale
failure counts from an earlier, successful boot.

The relay also changes the stock `upgrade` command's pre-boot NVRAM write from
`auto-boot=false` to `auto-boot=true`. The original write otherwise turns one
transient selected-system failure into an immediate Recovery stop on the next
hardware boot. PMU boot and panic counts are not bypassed by this patch, so
repeated real failures still retain iBoot's Recovery safeguard; a stable target
boot clears them through the late Apple housekeeping step above.

When iBoot has already stopped in Recovery, the guided menu offers a selected-
device repair before any firmware is downloaded. It verifies the product,
board, chip and ECID, sets and saves `auto-boot=true`, then reboots without
mounting storage, preparing firmware or erasing data. Declining the repair
continues to the normal restore-version menu.

The compact bootstrap has separate, hash-pinned iOS 8.4.1 (12H321) recipes for
ARMv7 and ARMv7s. iPhone4,1 uses its own ARMv7 stock cache. The ARMv7s recipe is
reconstructed from the iPhone5,2 cache and its resulting shared cache was also
physically exercised on iPad3,4. Both variants retain the same 30 MiB system plus
2 MiB Data geometry. Guided preparation obtains a donor only where
the exact recipe requires one and never treats an unknown cache hash as equivalent
merely because its architecture and build match. The ARMv7 recipe retains the
missing Objective-C selectors, cached libutil and complete retained-image
LINKEDIT metadata. Its 2,946 retained executable pages are compared byte-for-byte
with stock; dispatch releases are no longer patched. ARMv7 uses stock signed
launchd. ARMv7s now also retains the exact stock signed launchd, including its
embedded XML bootstrap plist. Converting that plist and rehashing the executable
stalled a normal iPhone5,2 bootstrap before its writable logs or USB services
started. A diagnostic USB boot with AMFI disabled masked the problem and reached
iOS 7.1.2. Replacing only launchd with the stock executable, then restoring empty
boot arguments, allowed an ordinary reboot into iOS 7.1.2 on the same installation.
The ARMv7s shared-cache recipe is unchanged.

Automatic A5 preparation now packages the qualified two-image `multi_kloader`,
independently checked raw iBSS and plaintext IMG3 iBEC, and the native kernel
power observer. It arms an eight-second `WakeRelativeToSleep` before publishing
readiness, rearms on the sleep notification and acknowledges the transition.
No host trigger, cable removal or Home press is required. The iBSS receive stub
returns its buffer length, not its address; the selected RAM iBEC starts its
target without a persistent NVRAM change. Old relay recipes are rebuilt through
the normal recipe-version mechanism. No session/scratchpad files are inputs.

This boot sequence was physically exercised on iPod5,1 with target 6.1.3,
including normal autonomous boot with USB attached and user-confirmed Cydia/APT.
The integrated image is also rebuilt/read back offline within 30+2 MiB. Target
diagnostics are now opt-in on A5, as on A6; the signed bootstrap's normal entry
uses stock boot arguments. The newly packaged
preparation was subsequently exercised in the restore runs summarized in the
main README. Other A5 models and releases are not hardware-qualified by this
individual result. The single-DFU native
iOS 6 installation test and its remaining qualification limits are recorded below.

The restore completion check waits for Cydia preparation to exit successfully,
for deferred iOS 7 services to be registered, and for the modem on cellular
models. It verifies Apple activation and acknowledges it over the selected USB
connection before reporting success. SpringBoard alone is not sufficient.

For official activation, olsn0w first looks for the Kit backup at
`saved/<ProductType>/activation-<ECID>.tar`. After the target boots, it checks
the saved AccountToken against the real device UDID and, when present, product, and checks
the connected device's ECID. This also works when the DFU rescue used a
synthetic USB serial. The original signed record is restored over authenticated
target SSH and lockdownd is restarted (the device is not rebooted);
old `data_ark`, pairing and radio preferences are not copied over the new Data
volume. Only an `Activated` readback counts as success. Missing or rejected
records fall back to official online activation; malformed or mismatched
backups stop with an error. Setup-removal/Hacktiv8 modes skip official activation.
With Setup.app preserved, Hacktiv8 must still reach `ActivationState=Activated`
over the selected USB connection before restoration is reported as complete.
Its activation handshake is acknowledged after that state is observed.

On cellular iOS 8 devices, the upstream jailbroken Hacktiv8 recipe also disables
CommCenter. The menu warns before selection that calls, SMS and cellular data
will be unavailable; Wi-Fi remains available. The first-boot job applies this
policy before editing MobileGestalt. An old completion marker cannot hide a
regenerated cache: the bundled helper checks the actual boolean on every boot.
Cache repair can request at most two restarts. System recipe 52 rebuilds older
prepared images with this policy and verification. Cellular versions may be
absent after CommCenter is disabled; the signed-base stage still validates the
selected modem before installation.
An Apple account challenge stops automatic retries and requires owner input;
a saved certificate does not guarantee acceptance or remove Activation Lock.
This saved-record path was verified on iPod touch 5G with target 6.1.3: the
unchanged certificate was accepted after daemon reload, without online
activation or a device reboot. Other models/releases still require validation.
Older Apple tokens without `ProductType` are accepted only when their required
UDID matches the observed target. An explicitly different product is rejected;
the connected device's product and ECID checks remain mandatory.

## Firmware selection and qualification

The catalog follows releases available for the complete 32-bit iOS 8.4.1 OTA
signing set: iPhone 4S and 5, every iPad 2/3/4 variant, iPad mini 1, and iPod
touch 5. The Restore menu asks the Python catalog directly whether olsn0w
supports a product, so its entry cannot silently omit one of these profiles.
The catalog has no upper iOS version cutoff. A catalog entry does not by itself
establish that its complete restore/boot path has been physically validated.

Cellular iPad2,2, iPad2,3, iPad3,2 and iPad3,3 profiles preserve the installed
baseband, matching the Kit's established OTA policy. Their provisioning RAM
sets `UpdateBaseband=false` in the selected board's restore options (falling
back to `options.plist` only when board-specific options are absent), in addition
to the host's `--no-baseband`. An iPad3,3 failure showed that the legacy host
flag alone still allowed a `BasebandData` request, followed by a baseband TSS
rejection (`STATUS=94`) and restore error `-11`. Preparation retains all other
restore options and verifies the modified file before packing the RAM. Older
bundles without this recorded policy are rejected before DFU or erase; prepare
a new session and preserve the failed session's diagnostics. The RAM change
has host-side readback coverage; a physical restore still needs validation.
Other cellular profiles
use their explicitly qualified Trek or Mav5 donor; no model silently inherits a
different modem recipe.

Select `--build` when a version has multiple releases. The interactive menu shows
both version and build. A local `--ipsw` also identifies the build through its
manifest. Product type, chip, board, version, build, and archive digest are checked
before extracting components. Unknown binary patterns are rejected instead of
applying offsets from a different firmware.

Existing kit code is reused where applicable:

| Component | Existing implementation | Integration limit |
| --- | --- | --- |
| Bootloader patches | Bundled `iBoot32Patcher` | Each selected binary must match the relay's checked instruction patterns. |
| iOS 5/6/7 jailbreak payloads | Kit package layout, with the pinned upstream Aquila 2.1.1 device binary | The iOS 5, 6 and 7 image recipes integrate root selection and first-boot services. Hardware qualification remains specific to each build and product. |
| iOS 7/8 daemon placement | `jailbreak/daibutsu/move.sh` | Must be adapted to the selected image/layout rather than run blindly on a device. |
| iOS 8 | Kit EverUntether and daibutsu cache admission | Preparation and restores validated on the builds/devices in the main README, not every catalog entry. |
| iOS 9 | The Kit selects EverUntether for releases before 9.3.5 | Target service and boot integration remains to be implemented and validated. |
| iOS 10 | The kit documents socket and has newer restore tooling | There is no integrated olsn0w iOS 10 restore path yet. Its boot and filesystem handling must be validated separately. |

Prepared manifests distinguish host preparation from physical boot validation.
They must not be used to claim that all catalog versions have been restored or
that every supported product type has been tested on hardware.

`prepare-system` implements iOS 5/6/7 Aquila recipes and an iOS 8 EverUntether
recipe using the Kit's daibutsu layout. It separates the
stock Data contents from the system image, preserves bundled dictionary and font
assets, relocates launch services for iOS 7, disables OTA services, and installs guarded
keybag initialization. SSH keys are generated per prepared image. Modified
executable pages and installed payload bytes are checked after writing. Image
generation does not copy activation or modem personalization from another device.
The result still requires a filesystem check, device-specific personalization,
and the compact bootstrap installation before restoration. Existing output is
preserved rather than overwritten.

The iOS 6 recipe follows the firmware's stock unprotected HFS Data contract and
uses its native Aquila payload. Its complete Data seed and personalization are
written and checked before the first boot. Wi-Fi products explicitly select
activation personalization without modem artifacts; cellular products still
require their qualified modem component set.

For A5-family iOS 6 targets, the installer now rejects a Data-writing operation
through the iOS 8 RAM environment, including resumed installations. N78AP
hardware testing found that a Data image written through 12H321 passes that
kernel's checks but has different first 16-byte reads per 4096-byte block under
10B329; the iOS 6 HFS mount then fails. Rewriting the verified Data image through
the native 10B329 rescue allowed normal journaled mounts, SpringBoard, Cydia and
an APT update on iPod5,1/6.1.3. The exact crypto implementation difference is not
yet established. Do not repair that Data volume through the newer rescue.
Guided preparation now selects the 10B329 RAM environment **from the initial
DFU** for A5-family iOS 6 targets. It reuses the native restore-component,
ASR and plaintext-UDIF recipe from the 4S path, while retaining the actual
signed 8.4.1 filesystem, ticket and persistent boot firmware. The restore's
authenticated reboot hook holds that same RAM environment for collection and
target installation: no second DFU or inter-kernel RAM handoff is introduced.
Gas-gauge `multipatch` remains a separate, 4S-only model property. A stale
iOS 8 writer is rejected before the signed-base erase, not just before Data.
The developer `prepare-rescue` command also selects this writer when given
`--version 6.1.3` (or another iOS 6 target version); its optional IPSW/key inputs
still refer to the signed 8.4.1 base. Without a target version, its existing
model-specific rescue default is preserved.
The iPod5,1/6.1.3 hardware run on 2026-09-24 completed the signed-base restore,
target/Data installation and first-boot qualification from one initial DFU,
with the cable connected and lockdownd activation bypass. SpringBoard, the
generation-bound Cydia-ready marker and an actual `/usr/lib` write/remove probe
passed. Official activation was skipped. Two host-side binding errors were
fixed during that run, then preparation resumed in the still-running rescue;
the signed-base erase was not repeated. This is not yet an unattended fresh
run of the final corrected code, nor qualification of every A5 model/release.
Device-bound preparation must retain both A5 relay images instead of writing
the A6-only `relay.bin`. Native6 technical collection supplies a decrypted host
kernel: binding must retain the checked encrypted stock 8.4.1 bootstrap kernel
so that ordinary A5 iBoot can admit it. Both contracts have regression tests.
The validated A6/A6X iOS 6 and existing iOS 7/8 policies are unchanged.

Fresh iOS 7 and iOS 8 Data volumes require the native `newfs_hfs -P` format,
`HFS.initialize_protection_v4()`, and a protected mount from the target kernel.
The initializer writes Apple's version-4 root protection attribute at CNID 1
and rejects existing attributes or regular payload files. The version must be
present before the kernel first opens the protected root directory.
Their offline seed contains only directories and
symlinks. File contents and the selected device's activation archive are staged
on the system volume, written after keybag initialization, and committed with
the generation marker. Do not unpack `data-personalization.tar` onto an
unprotected iOS 7 or iOS 8 Data image or mount the fresh Data volume with
protection under a newer kernel.
This initialization path is not a conversion procedure for existing user data.

The iOS 8 cache preparer preserves executable bytes and changes only the
virtual export entry for early signature admission, retaining its Thumb bit.
The HFS writer preserves the cache catalog entry and emits overflow extents
with logical block keys, big-endian descriptors and zero-filled unused slots.
Full content readback and filesystem verification remain required.

The iOS 6 recipe uses the native Aquila binary already bundled by Legacy iOS Kit
and retains its stock `/bin/launchctl` contract. The iOS 7 Aquila recipe reads its
device binary from the
[upstream 2.1.1 release](https://github.com/staturnzz/aquila/releases/tag/2.1.1)
and routes its bulk load through the guarded `/olsn0w/lctl` endpoint.
The downloaded release executable is only a data container and is never run.
Python verifies both its checksum and the embedded ARM component's checksum and
code signature. Extraction is identical on Linux and macOS and does not require
Wine or an Apple SDK. Aquila is distributed under its
[MIT license](https://github.com/staturnzz/aquila/blob/031ddb3aa9d50200bcd953d6c371cc5a79e5049d/LICENSE).

## Checks

```sh
saved/olsn0w/runtime/bin/python -m unittest discover -s resources/olsn0w/tests -v
```

CI runs the host tests on Linux and macOS. Tests cover build selection, rejection
of mismatched hardware identities, host tool selection, Thumb encoding, and the
display trampoline's success and failure paths. Firmware-specific comparisons
belong in `scratchpad/`; device identifiers and activation records must never be
added to source, fixtures, comments, or committed reports.

The optional real HFS image test also parses compressed resource references
directly from the catalog and resource fork. Decompression readback alone cannot
validate this structure: xpwn ignores a resource map that Apple's kernel rejects.
Set `OLSN0W_TEST_HFS_TEMPLATE` to an empty HFSX image to run this check.
