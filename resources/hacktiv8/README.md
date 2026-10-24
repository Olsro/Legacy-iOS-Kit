# Hacktiv8 on a connected jailbroken device

Open **Misc Utilities → hactiv8**, next to **Attempt Activation**, with the
device connected in normal mode. This utility is independent of olsn0w restores.
It leaves Setup.app unchanged and applies the existing Hacktiv8 recipe to the installed OS;
it does not restore or erase the device. Hacktiv8 is not official activation,
a carrier unlock or an Apple account unlock.

The utility checks product, version, build and UDID over USB, then verifies the
model, OS build and root privileges over a UDID-bound SSH tunnel. OpenSSH and
the root password are required (default: `alpine`). SSH host keys are retained
per device; a changed key is not silently accepted. Passwords are passed to
sshpass through its environment, not its command line or the saved reports.

If root SSH cannot be reached, the menu offers **Retry SSH**, **Jailbreak Device**
or **Go Back**. SSH failure alone does not establish that a device is unjailbroken.
Install OpenSSH if already jailbroken; otherwise the jailbreak option delegates
to the Kit's existing confirmation and supported jailbreak workflow. No jailbreak
is started without that confirmation. Afterwards, install OpenSSH and select
**hactiv8** again. Unsupported device/build combinations are rejected before
offering a jailbreak or changing any device file.

Before committing a change, the utility saves the original under
`saved/hacktiv8/<UDID>/<run>/original` and alongside the device file with the
`.hacktiv8-original` suffix. It checks an existing backup for conflicts, preserves
file permissions/ownership, reads back the staged replacement, installs it with
a same-directory rename and reads it back again. Conflicting backups or unknown
binary signatures stop the operation. A verified change requests one restart;
an already-applied patch does not request another. Backups contain device data:
keep them private and retain them for recovery.

iOS 4–6 uses the existing lockdownd signature recipe, with code-page hashes
updated while preserving the original Apple ad-hoc signature metadata and
entitlements. Both ARMv7 and ARMv7s instruction orders are recognized, without
requiring a new firmware-specific offset for each matching build. Multiple
matches, including mixtures of original and already-patched sites, are rejected.
Reapplication reports the same patch offset and leaves the binary unchanged.
olsn0w validates the selected stock binary or MobileGestalt assets before
building the target filesystem. This detects an unsupported binary or missing
asset before the expensive preparation steps.
System recipe 49 rebuilds older prepared images so the shared image and live
patch paths both preserve valid code-page hashes.
Stock iOS 4 has no Setup.app; image preparation and the live
utility allow its absence there, but still require its preservation on iOS 5+.
The 3GS 4.3.5/8L1 executable uses a SHA-256-pinned reproduction of
`Down_iPhone2,1_4.3.5_8L1.bundle/lockdownd.patch`, including its UUID and
CoreLocation linked-version changes. The full original and patched executable
hashes and signed pages are checked; no unknown binary can borrow its offsets.
On 2026-09-29, both the stock and custom 3GS 8L1 filesystems were checked:
neither contains Setup.app and both contain the same original lockdownd.
A disposable custom IPSW passed full patching, DMG/ZIP reconstruction and
readback, with the exact historical result, original backup, correct metadata,
idempotent reapplication and all 27 non-root archive entries unchanged. This
validates preparation only, not restoration or activation on hardware.
The iPhone 3GS and 4S 5.1.1/9B206 share an exact SHA-256-pinned
case, reproduced byte-for-byte from the Kit's historic
`Down_iPhone2,1_5.1.1_9B206.bundle/lockdownd.patch`; it is never applied by offset
to an unknown binary. iOS 7/8 uses the MobileGestalt flag or a bundled exact
profile; later supported builds require their bundled profile. A missing live
cache is an error, not grounds for removing Setup.app or guessing its contents.

The pinned 3GS/4S 5.1.1 recipe is shared with custom IPSW preparation (including
DRA) and olsn0w. Installation and filesystem readback use the same recipe;
it is not limited to the live-device menu.
The iPhone 5 6.1.4/10B350 ARMv7s executable has a different instruction order
from the generic signature. Its recipe pins the entire original and patched
SHA-256, forces the same `ShouldHactivate` result, and rehashes the original
ad-hoc signature while retaining its metadata and entitlements. This recipe is
shared by image preparation and the live utility on Linux and macOS. Unknown
binaries cannot borrow its fixed offset. Preparation checks do not establish
successful activation or restoration on hardware.
The 5.1.1 DRA custom IPSW was checked through extraction, patching, DMG/ZIP
reconstruction and filesystem readback on a disposable copy. Its other 37
archive entries were unchanged. This validates preparation, not a new hardware
restore.

The 3GS (`iPhone2,1`) 9B206 custom IPSW contains the identical stock lockdownd
SHA-256 as the qualified 4S binary. Its former rejection was a product allowlist
omission, not a different instruction layout. Both products now use the same
hash-checked recipe; unknown hashes, other builds and other products cannot
borrow the fixed offset. This preparation correction does not itself establish
successful activation or restoration on 3GS hardware.
On 2026-09-29, a disposable copy of the 3GS 9B206 custom IPSW passed the full
Hacktiv8 preparation and DMG/ZIP reconstruction. Readback verified the exact
historic patched binary, original backup, file metadata and preserved Setup.app;
all 30 other archive entries were unchanged. Host regression tests cover both
products, reapplication, shared image/live paths and rejection of unknown inputs.

The host reports file-patch verification, not successful official activation.
After restart, verify Setup Assistant, device connectivity and normal use.

For olsn0w restores on cellular iOS 8 devices, the
[upstream jailbroken recipe](https://github.com/overcast302/hacktiv8/blob/main/exploits/sftp/sftp.py)
requires disabling CommCenter in addition to editing MobileGestalt. This disables
calls, SMS and cellular data. The restore menu explains this before selection.
The generated first-boot job checks the actual cache flag instead of trusting
an old marker and limits cache-repair restarts to two. A preserved Setup.app
requires USB `ActivationState=Activated` before restoration can be qualified;
skipping Apple's activation request alone is no longer treated as success.

Hardware validation: iPhone 4S on iOS 5.1.1 (9B206), 2026-09-25. The patched
device returned after restart with `ActivationState=Activated`; the user
completed Setup Assistant and reached SpringBoard. A second application was
verified as unchanged and did not request another restart. Other device/build
combinations are not implied to be hardware-tested by this result.
