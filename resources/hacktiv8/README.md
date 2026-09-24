# Hacktiv8 on a connected jailbroken device

Open **Misc Utilities → hactiv8**, next to **Attempt Activation**, with the
device connected in normal mode. This utility is independent of olsn0w restores.
It keeps Setup.app and applies the existing Hacktiv8 recipe to the installed OS;
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
entitlements. The iPhone 4S 5.1.1/9B206 additionally has an exact SHA-256-pinned
case, reproduced byte-for-byte from the Kit's historic
`Down_iPhone2,1_5.1.1_9B206.bundle/lockdownd.patch`; it is never applied by offset
to an unknown binary. iOS 7/8 uses the MobileGestalt flag or a bundled exact
profile; later supported builds require their bundled profile. A missing live
cache is an error, not grounds for removing Setup.app or guessing its contents.

The pinned 4S 5.1.1 recipe is shared with custom IPSW preparation (including
DRA) and olsn0w. Installation and filesystem readback use the same recipe;
it is not limited to the live-device menu.
The 5.1.1 DRA custom IPSW was checked through extraction, patching, DMG/ZIP
reconstruction and filesystem readback on a disposable copy. Its other 37
archive entries were unchanged. This validates preparation, not a new hardware
restore.

The host reports file-patch verification, not successful official activation.
After restart, verify Setup Assistant, device connectivity and normal use.

Hardware validation: iPhone 4S on iOS 5.1.1 (9B206), 2026-09-25. The patched
device returned after restart with `ActivationState=Activated`; the user
completed Setup Assistant and reached SpringBoard. A second application was
verified as unchanged and did not request another restart. Other device/build
combinations are not implied to be hardware-tested by this result.
