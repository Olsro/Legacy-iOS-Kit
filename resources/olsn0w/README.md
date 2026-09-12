# olsn0w

Start `./restore.sh`, connect an iPhone 4S, iPhone 5 or iPad 4, and open **Restore →
olsn0w (choose iOS version)**. Select the desired release by its menu number or version; olsn0w prepares and
checks its firmware, Apple signing ticket, modem, restore environment and compact
bootstrap automatically. No developer paths or build tools for the ARM helpers
are requested. The Python runtime is installed on first use.

Preparation calculates the remaining disk requirement from firmware and system
images that are not already cached, and reports it before creating large files.
An Internet connection is needed for firmware that is not already available.
After preparation, confirm the erase and follow the instructions for the initial
manual DFU entry. Existing verified IPSW archives are reused to avoid duplicate downloads.
The signed 8.4.1 restore, RAM handoff, compact installation,
target boot and official activation verification then run automatically. Only
one manual DFU entry is intended for a successful A6 run; recovery after a failure
can require another. The iPhone 4S additionally requires A5Mate's A5_8940
`PWND:[checkm8]` state. Every failed DFU attempt can be retried without repeating
the completed firmware preparation. The current pipeline still restores the full signed base
before reducing it to the 30 MiB + 2 MiB bootstrap.

The intended target range is every iOS 6, 7, 8, 9 and 10 release published for
the connected iPhone 5 or iPad 4 model. This is a development objective, not a
claim that every release already boots with olsn0w.

The menu shows releases for the connected product. iOS 6 and 7 have installation
recipes; later releases are marked unavailable until their first-boot integration
exists. Preparation rejects firmware that does not match the checked patch
patterns. This does not claim physical qualification of every listed build.

Preparation displays a live, single-line percentage for downloads, archive
extraction, decryption, checksums and firmware assembly. Percentages refer to the
named operation's measured bytes, not estimated overall time. Opaque filesystem
operations show activity and elapsed time instead. Redirected output uses periodic
plain-text updates; the display never reports 100% before the operation succeeds.

Follow the computer's phase messages: the device can display stationary progress
bars, black screens and successive Apple logos during transitions. Success is
reported only after target and activation verification. Failures retain logs and
stop without silently repeating an erase. The guided frontend and renamed assets
have host tests; a complete physical restore through this new menu remains to be
qualified.

After final target boot and activation qualification, olsn0w retains manifests,
logs and the small device-bound technical collection while pruning reconstructible
restore archives and working images. A failure at any earlier stage preserves its
complete session for diagnosis. Mutable HFS working images use filesystem
copy-on-write clones where the host supports them, with an ordinary copy fallback.

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
and checks every filesystem before requesting normal boot. iOS 6 keeps its stock
unprotected Data mount and is populated completely before boot. iOS 7 and 8 use
the protected first-boot path. No host disk mounts or Docker are needed for this
installation path. The same RAM connection covers all installation stages.

`installation.json` records completed writes and failures; `qualification.json`
is published only after the target's version, Data generation, and SpringBoard
are observed. Activation must report `Activated` for the command to succeed. Only then does
the USB handshake acknowledge that existing activation; it does not fabricate
records or skip Setup Assistant.
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

The experimental iPhone4,1 path always follows Legacy iOS Kit's battery-safe
`multipatch` policy. It keeps the signed 8.4.1 base and ticket, but restores it
through the checked 6.1.3 iBSS, iBEC, DeviceTree, kernel and restore ramdisk;
the target 8.4.1 restore options and library are copied into that environment.
The Kit's checked multipatch ASR and `restored_external` replacements are used,
and only the erase BuildIdentity is routed to the added `Downgrade` components.
The Trek modem donor is 9.3.6 (Trek 6.7.00). A complete 4S provisioning IPSW
and 32 MiB ARMv7 bootstrap reproduce successfully on the host; physical restore
qualification is deliberately deferred to the connected-device test.

After a successful signed restore, the held RAM can collect its personalized
kernel, modem and partition table, then install the selected target. Official
activation is performed on the target through the Kit's activation utility;
no fabricated records or prior activation from another device are used.
Recovery using an already attested base remains a separate path.

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
services and official activation must still be observed within the timeout.
Startup observation never reboots the device automatically. If initialization
does not finish, the script preserves the logs and reports the observed stage
for diagnosis before another attempt.

## Hosts and dependencies

Linux and macOS use the same Python implementation. Supported host architectures
follow the kit: x86_64 and arm64. Preparation requires Python 3.8 or later, curl,
and the kit's `iBoot32Patcher`, `xpwntool`, `dmg`, and `hfsplus` binaries. System
image preparation also uses `ssh-keygen` and the same pinned ldid release used
by the kit (downloaded into the private working directory). Capstone
and Unicorn provide binary inspection and instruction emulation. PyCryptodome
decrypts the firmware envelope identically on either host. PyUSB uses the
Kit's libusb dependency for portable USB identity checks. Post-boot activation
acknowledgement uses libimobiledevice and libplist on either host.

Run from the kit directory after its normal dependency installation:

```sh
sh resources/olsn0w/setup.sh
./restore.sh --olsn0w list --product iPhone5,2
./restore.sh --olsn0w prepare --product iPhone5,2 --version 7.1.2
./restore.sh --olsn0w prepare-system --product iPhone5,2 --version 7.1.2
```

The isolated Python runtime, downloaded firmware, generated images, keys, and
local validation reports live under the ignored `saved/olsn0w/` directory.
The firmware relay uses direct Thumb encoding and emulator checks. System and
compact-bootstrap image preparation compile an HFS helper with a C compiler,
CMake and zlib. Its tar importer preserves symlink metadata without changing the
target's permissions or ownership. Bootstrap programs use Clang and an ARM-capable Mach-O
linker, with libraries extracted from the selected stock restore ramdisk. No Apple
SDK, Xcode project, or macOS image mount is needed. Linux compilation and image
checks are exercised during development; native-tool setup is not yet integrated
into the public restoration entry point. Docker is used for development checks.

Verbose relays omit the logo display hook so it does not replace diagnostic
output. The image-address patch preserves the register used by the selected
iBSS instead of assuming the same register across firmware versions. Prepared
relay manifests record the recipe version; older cached relays
must be rebuilt when the recipe changes.

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
registered jobs are left intact even when they have no running PID. Legacy
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

For iOS 7, the Apple `profiled` and `accountsd` jobs are kept in `/olsn0w/late-jobs` and registered
by Aquila's post-patch loader. Early amfid admission still uses the Kit's limited
MIS library; after Aquila restores shared-cache selection, these services use
the complete Apple implementation. Their executables, Mach services, users and
job options are preserved. This avoids starting them against the incomplete
implementation during early boot. Cydia preparation retries unsuccessful runs
with a 30-second launchd throttle, then stops retrying after successful completion;
its output is retained under `/var/logs/AppleSupport/olsn0w-cydia.log`.
For iOS 7.1.x, the restore recipe uses the Pangu untether already bundled and used
by Legacy iOS Kit, selecting its checked ARMv7 slice and retargeting it to the
chosen root volume. Its original launch service and the stock daemon layout are
retained, matching the Kit's A5X/A6X fallback instead of applying Aquila's daemon
relocation. Its bulk launchd request is routed through the same guarded loader so
it cannot invalidate lockdownd's live local socket. Earlier iOS 7 releases retain Aquila. The board-specific iOS 7 jetsam
policy gives the selected untether an explicit 128 MiB ceiling; the stock fallback
ceiling of 5 MiB can terminate the exploit before it remounts the selected root
read-write, leaving Cydia preparation unable to finish.

The small ARMv7 helper is shipped with source/build checksums in
`target/load-jobs.json`. `native/target/build.sh` rebuilds it with Clang, an ARM
Mach-O linker and stock iOS libraries on Linux or macOS; sign the result with
the existing `signing.resign` function and update the checksums together. Its
minimum deployment target is iOS 6. Image integration covers iOS 6 and 7.
The iOS 6.1.3 recipe is physically qualified on iPad3,4: the stock unprotected
Data mount policy and package-provided Aquila launch route reach SpringBoard,
official activation, Wi-Fi and a working Cydia first start. This p101 build also
uses one exact, hash-pinned kernel fix after the TriStar System-ID retry. A
successful retry retains the real identifier; only a repeated
`kIOReturnBadMessageID` enters Apple's existing `0xffff` fallback. The fix is
restricted to iPad3,4 / 6.1.3 / 10B329 and its packed kernel is read back before
being embedded. Existing prepared system images must be rebuilt to acquire
this change.

The compact bootstrap has separate, hash-pinned iOS 8.4.1 (12H321) recipes for
ARMv7 and ARMv7s. iPhone4,1 uses its own ARMv7 stock cache. The ARMv7s recipe is
reconstructed from the iPhone5,2 cache and its resulting shared cache was also
physically exercised on iPad3,4. Both variants retain the same 30 MiB system plus
2 MiB Data geometry; the verified host-built iPhone4,1 image leaves more than
1 MiB free on its system volume. Guided preparation obtains a donor only where
the exact recipe requires one and never treats an unknown cache hash as equivalent
merely because its architecture and build match. ARMv7 device qualification is
still pending; the model catalog is not a claim that this bootstrap covers every
device.

The restore completion check waits for Cydia preparation to exit successfully,
for deferred iOS 7 services to be registered, and for the modem on cellular
models. It verifies Apple activation and acknowledges it over the selected USB
connection before reporting success. SpringBoard alone is not sufficient.

## Firmware selection and qualification

The catalog follows releases available for each supported product type:
`iPhone4,1`, `iPhone5,1`, `iPhone5,2`, `iPad3,4`, `iPad3,5`, and `iPad3,6`. It has no upper iOS
version cutoff. A catalog entry does not by itself establish that its complete
restore/boot path is supported.

Select `--build` when a version has multiple releases. The interactive menu shows
both version and build. A local `--ipsw` also identifies the build through its
manifest. Product type, chip, board, version, build, and archive digest are checked
before extracting components. Unknown binary patterns are rejected instead of
applying offsets from a different firmware.

Existing kit code is reused where applicable:

| Component | Existing implementation | Integration limit |
| --- | --- | --- |
| Bootloader patches | Bundled `iBoot32Patcher` | Each selected binary must match the relay's checked instruction patterns. |
| iOS 6/7 jailbreak payloads | Kit package layout, with the pinned upstream Aquila 2.1.1 device binary | The iOS 6 and 7 image recipes integrate root selection and first-boot services. Hardware qualification remains specific to each build and product. |
| iOS 7/8 daemon placement | `jailbreak/daibutsu/move.sh` | Must be adapted to the selected image/layout rather than run blindly on a device. |
| iOS 8 | Kit EverUntether and daibutsu cache admission | Portable preparation is implemented; complete device qualification is pending. |
| iOS 9 | The Kit selects EverUntether for releases before 9.3.5 | Target service and boot integration remains to be implemented and validated. |
| iOS 10 | The kit documents socket and has newer restore tooling | There is no integrated olsn0w iOS 10 restore path yet. Its boot and filesystem handling must be validated separately. |

Prepared manifests distinguish host preparation from physical boot validation.
They must not be used to claim that all catalog versions have been restored or
that every supported product type has been tested on hardware.

`prepare-system` implements iOS 6/7 Aquila recipes and an iOS 8 EverUntether
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
