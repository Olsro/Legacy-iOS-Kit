# iOS 6 application compatibility audit

Initial audit: 2026-09-26. Hardware checked: iPod5,1, iOS 6.1.3 (10B329).
The replacement recipe 45 was restored on this device on 2026-09-27.
This is not qualification of every iOS 6 release or device.

## Historical defect on the earlier recipe

On the earlier running test device, setting directory protection class D
(class 4) failed with EPERM, including as root. Apple's installation logs
showed that this stopped container population before the normal
global-preferences links were created, even though installation subsequently
reported success.
Repairing Tiny Wings' preferences link restored French localization.

The stock firmware's fstab also omits the `protect` option. That omission
alone is not evidence that a normal Apple installation lacks protection.
The restored volume's formatting, metadata and native keybag initialization
must be considered together.

The experimental installd interposer was withdrawn from automatic preparation:
treating the failed protection operation as success does not restore its
semantics. No such interposer was installed into the running installd service.

Do not enable protection in place over an existing plaintext Data volume.
The audit therefore required independent validation of a replacement
initialization on a fresh volume, including actual protection operations and
subsequent reboots. Changing `uses_protected_data()` alone was not a fix.

## Readback checks added to preparation

`filesystem_contract.py` compares these selected properties to the firmware
being prepared, rather than hardcoding one device's permission values:

- System directory type, mode and ownership for Applications, Library,
  Library/Caches, Library/Ringtones, Library/Wallpaper and System.
- Data seed directory type, mode and ownership for mobile, its Applications,
  Library, Caches and Preferences directories, and tmp (including its sticky bit).
- Contents and POSIX metadata of installd, mobile_installation_proxy,
  launchd, dyld, the installd launch job and the architecture-specific dyld cache.

All these checks passed against the retained iPod5,1/10B329 prepared image
and its Data seed. The sampled live Data directory permissions also matched
the stock image. These checks do not cover every file, ACL, extended attribute,
keybag, protection class, runtime service or third-party tweak.

The directory checks also run for iOS 7/8. Application directory candidates
(`mobile/Applications` and `mobile/Containers`) are checked when present in
that firmware, rather than requiring an iOS 6 layout on iOS 8. Unchanged Apple
binary checks remain iOS 6-only: intentional iOS 7/8 modifications need their
own qualification and are not rejected by this common metadata check.

Recipe 43 includes these checks and no installd injection. It did **not** repair
the then-open Data protection defect. The manifest explicitly records that runtime
application behavior and content protection have not been verified by this
static check.

## Personalization directory metadata fix (iOS 6/7/8)

The personalization archive used to include generic ancestor directories. For
example, it could include mobile and mobile/Library with mode 0755 when the
selected firmware used 0711. Native tar extraction at protected first boot can
apply those directory modes, undoing the seed's original access policy.

The restore preparation now supplies its verified Data seed to personalization.
Directories already present in that seed retain its modes and ownership;
new directories keep their explicit personalization metadata. Conflicting
non-directory ancestors are rejected. The manifest records the seed hash and
preparation verifies that it matches the system image's seed. Activation file
contents and the activation policy are unchanged.

Tests cover iOS 6.1.3, 7.1.2 and 8.3 archive construction, embedded protected
first-boot archives, and a host tar extraction preserving 0711. This fixes a
metadata discrepancy; it is not evidence of a game-crash fix.

## Native protection evidence

Apple's published [HFS protection implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-2050.48.11/bsd/hfs/hfs_cprotect.c)
returns EPERM from class operations when the mount lacks MNT_CPROTECT. This is
consistent with the observed device behavior. This published XNU version is
not the exact iOS 6.1.3 device build; it is supporting evidence, not binary
qualification of that build or a complete first-boot recipe.

The current prepared boot environment also sets a non-stock effaceable-storage
policy, and the iOS 6 keybag helper explicitly requires that policy. Therefore
the existing key initialization is not evidence of equivalence to Apple's
normal hardware-backed storage configuration. No boot-chain or keybag changes
were made in this audit. Changing mount flags alone must not be advertised as
restoring normal data-protection guarantees.

## Application crash evidence

The reproduced Cut the Rope launch did not produce a new named crash report
in the inspected CrashReporter directory. The available ASL output showed
tweak loading but did not establish a crash cause. Do not attribute that
failure to protection, Sideloadly or a particular tweak without more evidence.

## Functional checks for broader qualification

- Stock installd completes container population without protection errors.
- A newly installed app receives its normal preferences links without repair.
- A test file's protection class can be set and read back, and file access
  follows that class across lock/unlock and reboot.
- French localization works on a fresh installation, not only on repaired apps.
- Saving app data, relaunching, updating and uninstalling work normally.
- Investigate any remaining crashes separately using a fresh crash log and
  distinguish third-party app/tweak compatibility from preparation defects.

No restoration or on-device filesystem change was performed during the initial
2026-09-26 audit. The subsequent replacement-recipe restorations are recorded below.

## Replacement recipe 44 and first-boot gate in recipe 45

Recipe 44 changes iOS 6 to format Data with native HFS content
protection, writes only unprotected directory metadata offline, and performs
keybag creation followed by Data/personalization extraction on the target at
first boot. Aquila is gated on the completed Data generation. A failed archive
extraction is retryable without marking Data complete. On the iPod5,1/10B329,
recipe 44 was restored with the activation bypass. Data mounted with `protect`;
setting and reading class D succeeded on both a fresh directory and file,
while locked and again after a normal reboot. A second reboot preserved a
class-D test file. The user also confirmed the interface and a Cydia package
operation. Recipe 45 adds the same directory/file class-D test to iOS 6 first
boot before marking Data complete, so a future failure blocks Aquila. On
2026-09-27, recipe 45 completed a fresh iPod5,1/6.1.3 restoration with
Hacktiv8/lockdownd; the script verified the target boot and the user confirmed
the SpringBoard and Cydia opened. On the running device, Data was mounted with
`protect`, the system keybag existed, and both the gate's diagnostic directory
and file reported class D (`before=4 set=0 after=4`). This qualifies the
first-boot gate for this device/build, but not other iOS 6 combinations.
The user also reported that Cut the Rope no longer crashed and Tiny Wings
found its language after the recipe 44 restore; these are functional results,
not proof of which individual change caused them.
Neither recipe converts an existing Data volume in place. The non-stock
effaceable-storage policy remains; these tests do not establish equivalence
to Apple's usual hardware-backed storage guarantees or class-A lock behavior.

## iPad 3 / Peggle HD language regression (2026-09-28)

On a freshly restored iPad3,1 running 6.1.3/10B329, Data was mounted with
`protect`, the system keybag existed, and fresh diagnostic directory/file
class-D operations both returned `before=4 set=0 after=4`. This checks those
operations only, not all protection classes or lock/reboot behavior.

Peggle Classic HD 2.0.9 crashed with `NSRangeException` during
`-[NimbleApplicationEnvironmentImpl initWithCore:]`: the binary calls
`[NSLocale preferredLanguages]` and indexes element zero without checking
for an empty array. Setup Assistant preferences recorded `fr` / `fr_FR`,
but `/var/mobile/Library/Preferences/.GlobalPreferences.plist` was absent.
The app's preferences symlink existed, but pointed to that missing file.

Reselecting French through Settings recreated the global preferences with
`AppleLanguages[0] = fr`, and the user confirmed that Peggle launched normally.
No game binary, save data or protection setting was modified. The cause of
the missing global preferences remains unknown; this is not yet an automatic
preparation fix, nor evidence that content protection caused the crash.

The user subsequently confirmed that French survived a forced reboot.
A second standard restore on the same iPad3,1 (6.1.3, official activation,
Setup Assistant retained) was observed in session
`455657d1-ada7-41b0-88a6-74e0395c0fc7`. No language repair was added to the
preparation. The deferred `data-firstboot.tar.gz`, unlike the metadata-only
`data-seed.tar`, contains the stock mobile global preferences with
`AppleLocale = en_US` and a nonempty `AppleLanguages` array. Read-only SSH
snapshots confirmed these preferences existed before Setup Assistant.
Cydia initialization and official activation completed successfully.
Selecting French in Setup then persisted `AppleLanguages[0] = fr` on disk.
Choosing France persisted `AppleLocale = fr_FR`; both values survived
completion of Setup Assistant (`SetupDone` / `SetupFinishedAllSteps` true),
and the user confirmed the interface was French. These stages did not
reproduce the earlier missing-file failure. The user then opened Cydia,
allowed its first load to finish and confirmed the interface remained French.
The preferences also survived a normal reboot initiated over SSH: a new
`kern.boottime` and running SpringBoard were observed, and a fresh plist read
still returned `AppleLanguages[0] = fr` and `AppleLocale = fr_FR`.
Timestamped selected-key snapshots are retained in the session's
`language-observation.jsonl`; the temporary watcher was stopped afterwards.
The user subsequently installed the same Cydia tweaks (including AppSync),
forced a reboot with the two hardware buttons, and installed Peggle HD.
The user confirmed everything worked. This completes the functional retest
after package installation and a forced reboot; the original disappearance
was not reproduced.

The user suspects a forced reboot immediately after Setup Assistant may
interrupt persistence of the language preferences. This timing-dependent
explanation remains a hypothesis: that exact early interruption has not
been reproduced under observation, and no stock iOS 6 control has been
tested. Do not label this a confirmed stock-iOS bug, restrict it to that
single trigger, or infer a content-protection failure from the first incident.
No speculative language workaround was added to the restoration code.

## Launchd socket lifetime (recipe 55, 2026-10-30)

A user reported that f.lux (`org.herf.flux` 0.9988) never worked on iPhone 5
and iPad 4 restored to 6.1.3. The Olsro mirror serves the same bytes as the
official `justgetflux.com/cydia` package (SHA256 `e8a73c0e…`), so the
repository was not the cause. On the test iPhone5,2 / 6.1.4 (10B350), its
installation script logged `launch_msg(): Socket is not connected`: the daemon
only started after a reboot, and Cydia requests only a respring.
`/var/tmp/launchd/sock` was absent and the named `com.apple.mobile.installd`
query failed while the all-jobs `launchctl list` still worked. This is the
iOS 5 defect described in IOS5-COMPATIBILITY.md: launchctl empties `/var/tmp`
after `launchd.conf`. It affects any package that loads or reloads a daemon,
including AppSync's `installd` reload. 10B350 has no stock `dirhelper`.

The iOS 5 save/restore handoff was installed on that device without restoring
or erasing Data: the `save` line was appended to `launchd.conf`, and the
wrapper was installed as `/usr/libexec/dirhelper`. After a reboot the socket
existed, the named `installd` query worked, and f.lux could be unloaded and
loaded again. After `dpkg -r` and a reinstall, its daemon was running
immediately without a reboot. With 3400 K forced, the user confirmed a warm
screen tint. Recipe 55 applies this handoff to iOS 6 images and extends the
Cydia `installd` preflight to them. Only iPhone5,2 / 10B350 was tested;
other iOS 6 products and builds inherit the change without separate physical
validation.

## Package daemon start order (recipe 56, 2026-10-30)

After the same iPhone5,2 / 10B350 was restored with recipe 55, f.lux still did
not tint the screen after a reboot. The launchd socket was intact. The boot
instance of `/usr/libexec/flux` (PID 39) never wrote `/tmp/.iomfgamma.dat`,
whereas notifyd (90), locationd (116), backboardd (126) and SpringBoard (195)
started after it. After `killall flux`, launchd restarted the daemon, which wrote
the gamma table at once. Aquila runs from `launchd.conf` and loads every
`/Library/LaunchDaemons` job itself, before launchd starts the system daemons;
f.lux therefore registered for notifications before notifyd existed and
kept waiting for the display. The recipe 54 image behaved the same way: the
earlier warm tint appeared only after a manual daemon restart.

Recipe 56 retargets the two job-directory strings in the iOS 6 Aquila binary
(`/Library/LaunchDaemons` and `/Library/LaunchDaemons/%s`) to
`/olsn0w/early-jobs`, which only holds the Kit's recovery SSH job, and re-signs
it. The `wifid` paths and the stock `/bin/launchctl` stay unchanged.
`/System/Library/LaunchDaemons/org.olsn0w.late-jobs.plist` runs once at boot,
waits for GraphicsServices and loads `/Library/LaunchDaemons`.

On the device, the patched binary was installed without restoring Data. Its
code matches the recipe output byte for byte; only the signature blob differs.
After a reboot, Aquila reported `kernel patched`. The socket existed.
Cydia.Startup, boot-success, `com.openssh.sshd` and `ai.akemi.asu_inject` were
loaded. f.lux (PID 101) started after locationd and backboardd and wrote its
gamma table right after boot. `org.olsn0w.sshd` was not loaded, as before the
change: network SSH configuration disables it with `launchctl unload -w`.
Without Location Services (`LocationServicesEnabled = 0`), f.lux keeps its
daytime temperature. Once the user enabled them and authorised f.lux, the
user confirmed the night tint after this boot. iOS 5
shares the binary but keeps the early loading; it was not tested with this
change. Other iOS 6 products and builds inherit it without separate physical
validation.

