# Olsro's Legacy iOS Kit

Olsro's fork of [Legacy iOS Kit](https://github.com/LukeZGD/Legacy-iOS-Kit),
originally developed by LukeZGD and contributors. The original tools, credits
and license are retained. This fork adds olsn0w restoration, integrated
Hacktiv8, Olsro Cydia repositories and the hardware-tested improvements below.
Upstream wiki links describe the original project; fork-specific instructions
and validation results are documented here and in the linked local guides.

The fork's version is **1.0.0**, maintained in [`VERSION`](VERSION).
The toolkit checks for updates from [Olsro/Legacy-iOS-Kit](https://github.com/Olsro/Legacy-iOS-Kit)
at startup and asks before installing them. Updating is optional: declining
continues with the installed version.
Both Git clones and release ZIP installations can update in place; saved data
and firmware files outside the program folders are retained. Run the script
again after updating. Git updates require a clean checkout and fast-forward
history; commit or stash local changes first. Existing Git remotes are left
unchanged, and toolkit updates always come from this fork. Release ZIPs include
the complete toolkit and do not require an initial Git clone. Use
`--no-version-check` to skip the check. If no release is published yet, the check
uses the fork's `main` branch.

- (formerly iOS-OTA-Downgrader)
- **An all-in-one tool to [restore/downgrade](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Restore-Downgrade), [save SHSH blobs](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Saving-SHSH-blobs), [jailbreak](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Jailbreaking) legacy iOS devices, and more**
- Supported on **Linux and macOS**
- **Read the ["How to Use" wiki page](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/How-to-Use) for instructions**
- **Read the ["Troubleshooting" wiki page](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Troubleshooting) for tips, frequent questions, and troubleshooting**

## Features

- Olsro's Legacy iOS Kit supports all 32-bit iOS devices, and some 64-bit (A7/A8/A9/A10/A11) devices
    - Devices that received iOS 16 and newer will only have limited functionality (e.g. sideloading) and some features like SSH ramdisk are not supported
- Restore to signed OTA versions (iOS 8.4.1 and/or 6.1.3) on A5/A6 devices
- Restore to iOS 10.3.3 (signed OTA version) on supported A7 devices
- Restore supported devices to unsigned versions with SHSH blobs
- Restore to unsigned iOS versions with iOS 7 blobs (powdersn0w)
- Restore supported 32-bit devices to unsigned iOS versions "without" blobs
    - Includes downgrading iPhone 2G, 3G, 3GS, iPhone 4 GSM and CDMA, iPod touch 1, 2, 3, iPad 1
    - "without" is in quotes because powdersn0w uses iOS 5/7 blobs for touch 3 and A4 devices, but it is signed for everyone to use
    - Other devices however are true blobless
- Tethered downgrades/restores to supported iOS versions for A5(X)/A6(X) and some other 32-bit devices
- Jailbreak all 32-bit iOS devices on nearly any iOS version
    - Available on iOS versions 3.0 to 9.3.4 with some small exceptions
- Hacktivation for iPhone 2G, 3G, 3GS, 4 GSM (activate without valid SIM card)
- Boot SSH Ramdisk for supported 32-bit and 64-bit devices
- Save Onboard SHSH blobs for supported 32-bit and 64-bit devices
- Sideload IPA files for supported devices on Linux (and macOS)
- Save SHSH blobs from Cydia servers for 32-bit devices
- Enter pwned iBSS/kDFU mode for supported 32-bit devices
- Save onboard SHSH blobs for jailbroken 64-bit devices (deverser)
    - This also saves onboard Cryptex APTicket and seed for iOS 16+ (x8A4)
- Install [TrollStore](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/TrollStore) using SSH Ramdisk for supported 64-bit devices on iOS 14/15
- Clear NVRAM for 32-bit devices
- Device activation using ideviceactivation (especially useful for iOS 4 and lower)
- The latest baseband will be flashed for certain A5/A6 devices (for iPhone 4S, 5, 5C, iPad 4, mini 1)
    - For more info on baseband, go to [Baseband Update](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Baseband-Update) wiki page
- Dumping and stitching baseband to IPSW (requires `--disable-bbupdate`)
- Dumping and stitching activation records to IPSW (requires `--activation-records`)
- [App Management](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/App-Management) - Install IPA (AppSync), dump apps as IPA, list installed apps
- [Data Management](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Data-Management) - Backup and restore, mount device, erase all content and settings
- [Misc Utilities](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Misc-Utilities) - Pair device, export data and battery info, shutdown/restart device, and more

## Ethics / Legal
- If you resell a modified or hacktivated device, your buyer should always know it. For example osn0w has little compromises a native restored OS won't have (slower restores/boot times, etc)
- This program is free of charge & open source. If you paid for it anywhere, ask for a refund, you got scammed.
- This fork was not free to build & to maintain, see in https://olsro.fr how you can support me
- There's no guarantees this program will work right for you, though it should not harm your device in a unrecoverable way (you can always enter DFU to factory restore)
- This program was created to fight ewaste and to allow anyone to use their legacy iOS device how they like to enjoy the super speed & the vibes (skeuomorphic, cover flow, etc) of older iOS versions. You regain even a few GB of storage by using very old iOS versions compared to the latest ones so you can just store more content. Easy Hacktivation is provided in the only intent to fight ewaste. Apple remote locking a device so much you can't even use YOUR device as an mp3 player is super anti-consumer to me and many legitimate users just forget their Apple ID over time.
- Hacktivated devices can be used as an iPod Touch basically and even synced through iTunes, but the baseband remains unactivated (no mobile networks like 2G/3G/4G but wifi/bluetooth works). This is not a bug and won't be addressed

## Additions and verified results in this fork

### olsn0w: iOS 5, 6, 7 and 8 restoration

Start `./restore.sh`, connect the device, then choose **Restore → olsn0w
(choose iOS version)**. Firmware, signing ticket, restore environment,
device-specific boot relay and jailbreak preparation are automated. The target
must be a release actually published for the selected product; unknown or
ambiguous patch patterns stop preparation instead of reusing another build's
offsets. iOS 9/10 catalog entries are not an implemented olsn0w restore path.

iOS 5 is available without an experimental opt-in on all compatible iPhone 4S,
iPad 2 and iPad 3 variants, including those not yet physically tested. Only
firmwares actually published for each model are offered.

The menu covers the 32-bit iOS 8.4.1 OTA device family: iPhone 4S and 5,
iPad 2/3/4 (including cellular variants), iPad mini 1 and iPod touch 5G.
**Menu availability and host-side preparation are not proof that every
device/build combination works on hardware.** This does not include iPhone 5C
or 64-bit devices merely because their last OS is iOS 9 or 10.

- Every installation still restores the signed **8.4.1 base** before installing
  the selected target. The retained bootstrap occupies **30 MiB + 2 MiB**;
  that is not the host disk-space requirement. Preparation calculates remaining
  space from the needed firmware and cached images rather than imposing a fixed
  20 GB requirement.
- The successful workflow uses one initial DFU entry, including the integrated
  A5 path. A5 devices require an external pwnDFU step; A5Mate supports the
  tested 8940/8942 paths. Failed DFU attempts can be retried without repeating
  completed preparation. Recovery from a failed restore may need another DFU.
- A5 targets use the integrated two-image boot relay and automatic wake/handoff
  with USB left connected. Normal boots use the graphical Apple logo;
  diagnostic output is opt-in. The two boot stages remain intentional.
- iPhone 4S retains its battery-compatible **multipatch** restore environment.
  For A5-family iOS 6 targets, the native iOS 6 environment also writes target
  Data; an incompatible iOS 8 writer is rejected. Other products do not inherit
  the 4S gas-gauge policy.
- iPod touch 5G and iPhone 4S use the integrated **Aquila** recipe for iOS 7.1.x.
  Other models use their selected recipe, not a blanket jailbreak substitution.
  iOS 6 and iOS 7/8 retain distinct Data/keybag initialization policies.
- First-boot checks cover the selected system, Data generation, writable root,
  SpringBoard and Cydia preparation, plus the selected activation policy.
  Corrections address Apple-app launch failures, Cydia source initialization
  and APT/package installation permissions.
- Boot housekeeping and the relay's `auto-boot` handling address the observed
  iPhone 5/iOS 8.1.3 forced-reboot Recovery regression. Recovery safeguards for
  real repeated boot failures are retained; not every interruption scenario is
  qualified on every model.
- Successful sessions remove reconstructible working files while retaining
  diagnostic reports and device-bound artifacts. Failed sessions retain their
  evidence. Verified downloads are reused, and supported hosts use copy-on-write
  image clones.

See the [olsn0w guide](resources/olsn0w/README.md) for rescue commands,
implementation details and remaining qualification limits. Back up important
data before any restore; the installation erases the device.

The bundled [A5Mate Wii homebrew](resources/a5mate-wii/README.md) includes
separate 8940, 8942 and 8945 builds for the Homebrew Channel SD card. PwnDFU
was observed on the 4S (8940) and iPod touch 5G (8942); PwnDFU and ramdisk
boot were also confirmed on the test iPad 3 (8945), as recorded in the homebrew guide.
The 8942 payload preserves production keys for the subsequent signed iBSS.
The 0.1.2 EHCI topology fix also has user-confirmed success on Wii U/vWii
with a CPID 8942 iPad (25 October 2026). This vWii validation covers profile
8942; the other profiles have not yet been validated on Wii U.

### Hardware validation

These are the successful physical tests reported for this fork, not a promise
for all storage capacities, manufacturing revisions or cellular variants.
Unless a row specifies otherwise, tests included reaching the interface,
opening applications and Cydia, and package installation or APT updates.
Activation was checked according to the
policy chosen for each run; a bypass run does not validate official activation.

| Device tested with olsn0w | Target versions validated | Notes |
| --- | --- | --- |
| iPhone 5 | 6.1.4, 7.1.2, 8.1.3, 8.3 | Apple apps, Cydia and activation; subsequent 8.1.3 reboot correction |
| iPad 4 | 6.1.3, 7.1.2, 8.1.3, 8.3 | Working interface, jailbreak and Cydia; not every cellular variant tested |
| iPad 3 | 6.1.3 | Successful olsn0w restoration confirmed by the user on 2026-09-28; exact variant, activation policy and individual functional checks not specified |
| iPad 3 Wi-Fi (`iPad3,1`) | 5.1.1 (9B206) | Official activation, French interface, Cydia, AppSync installation/reinstallation and respring validated on 2026-09-28 after the iOS 5 launchd socket correction; see [details](resources/olsn0w/IOS5-COMPATIBILITY.md) |
| iPhone 4S | 5.1.1 (9B206), 6.1.3, 7.1.2, 8.3 | Multipatch; official activation on 5.1.1/8.3, bypass on 6.1.3/7.1.2. 5.1.1 validated on 2026-09-28 after DRA NVRAM cleanup and modem-path correction: Cydia updates and AppSync installation, with SpringBoard icons intact; see [details](resources/olsn0w/IOS5-COMPATIBILITY.md) |
| iPod touch 5G | 6.1.3, 7.1.2, 8.3 | Bypass runs; working Cydia/package installation |
| iPad mini 1 Wi-Fi (`iPad2,5`) | 6.1.3, 7.1.2, 8.3 | Official activation and end-to-end user confirmation |

The mini Wi-Fi iOS 6 path required the TriStar reset fix; its 7.1.2 and 8.3
tests succeeded without forcing that reset. Related cellular mini profiles are
covered by preparation policy, not by those physical tests. iPad 2 models,
other iPad 3 variants and unlisted builds still require their own hardware
validation; the iPad 3 report does not qualify every Wi-Fi/cellular variant.

### Hacktiv8 and activation choices

- Restoration can apply **Hacktiv8 while preserving Setup.app**, including
  custom IPSW methods outside olsn0w such as DRA. The olsn0w guided activation
  prompt requires an explicit `y` or `n`; an empty answer repeats the question.
- Declining keeps the official activation workflow. Selecting Hacktiv8 skips
  official activation. Where Hacktiv8 has no supported recipe, the offered
  alternative removes Setup.app and skips activation; removing Setup.app is
  not itself activation.
- **Misc Utilities → hactiv8**, next to **Attempt Activation**, applies the
  patch to an already jailbroken device without restoring it. It requires root
  OpenSSH, verifies device identity, preserves the original and checks the
  replacement before requesting a restart. Reapplying an unchanged patch does
  not restart the phone.
- If SSH is unavailable, the menu offers retrying or the existing jailbreak
  workflow with confirmation. A missing SSH connection alone is not treated
  as proof that the device is unjailbroken.
- The iPhone 3GS/4S **5.1.1/9B206** patch is shared between live application and
  IPSW preparation, with exact binary hashes and signature verification.
  Live activation and Setup Assistant completion were validated on one 4S;
  DRA IPSW reconstruction/readback was tested separately.

Hacktiv8 is **not official activation, a carrier unlock or an Apple account
unlock**. See the [Hacktiv8 guide](resources/hacktiv8/README.md) for supported
recipes, backups and safeguards.

### Cydia repositories

The bundled [Olsro repositories](http://cydia.olsro.fr/) are automatically added
to jailbreak restorations, **including methods outside olsn0w**, alongside
the existing source configuration. Repository package versions, dependencies
and upgrade offers remain server-side behavior; adding sources does not mean
every package they publish has been tested by this fork.
The [shared source-list guide](resources/jailbreak/olsro/README.md) describes
integration and cache invalidation. Stock non-jailbreak restores are unchanged;
existing devices are not retroactively modified merely by updating the script.

### Returning from DRA and late iPhone 4S revisions

After DRA, a conventional restore to an older OS may still return to Recovery
because DRA's NVRAM state remains. Use **Useful Utilities → Clear NVRAM** and
follow the ramdisk/DFU instructions before assuming a hardware incompatibility
or repeating the restore. The [upstream DRA guide](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/DRA-v6)
documents this requirement when returning to iOS versions below 9.

A specific **8 GB iPhone 4S** was restored conventionally to **6.1.3** (without
DRA or olsn0w), initially returned to Recovery, then reached SpringBoard with
working Cydia after clearing NVRAM. That validates iOS 6 on that phone, not
every 8 GB 4S. Its iOS 5.1.1 DRA attempt ended on a white screen and remains
unqualified. Upstream documents iOS 5 white-screen failures on some later
hardware revisions; iOS 6 incompatibility has a different documented symptom,
such as a restore stuck at `Waiting for NAND`. Storage capacity or Recovery
mode alone is not sufficient to diagnose either case.

## Supported devices

- [Identify your device here](https://ipsw.me/device-finder)
- **iPhone 5C and iPad mini 3 devices are NOT supported by OTA downgrades**
    - These devices still support restoring to other iOS versions with SHSH blobs, see below
- See the table below for OTA downgrading support:

<table>
    <thead>
        <tr>
            <th>Target Version</th>
            <th>Supported Devices</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td rowspan=4>iOS 10.3.3</td>
            <td><b>A7 devices:</b></td>
        </tr>
        <tr><td>iPhone 5S</td></tr>
        <tr><td>iPad Air 1</td></tr>
        <tr><td>iPad mini 2 (except iPad4,6)</td></tr>
        <tr>
            <td rowspan=6>iOS 8.4.1</td>
            <td><b>32-bit devices:</b></td>
        </tr>
        <tr><td>iPhone 4S</td></tr>
        <tr><td>iPhone 5</td></tr>
        <tr><td>iPad 2, iPad 3, iPad 4</td></tr>
        <tr><td>iPad mini 1</td></tr>
        <tr><td>iPod touch 5</td></tr>
        <tr>
            <td rowspan=2>iOS 6.1.3</td>
            <td>iPhone 4S</td>
        </tr>
        <tr><td>iPad 2 (except iPad2,4)</td></tr>
    </tbody>
</table>

- Restoring with SHSH blobs, jailbreaking, and using SSH ramdisks are supported on the following devices:
    - iPhone 2G, 3G, iPod touch 1
    - iPhone 3GS, 4, 4S, 5, 5C
    - iPad 1, 2, 3, 4, mini 1
    - iPod touch 2, 3, 4, 5
- Restoring with SHSH blobs and using SSH Ramdisks are also supported on some 64-bit devices:
    - iPhone 5S, 6, 6S, SE 2016, 7 (including Plus variants)
    - iPad Air 1, 2
    - iPad mini 2, 3, 4
    - iPod touch 6, 7
    - Versions that can be restored to depend on SEP/BB compatibility
    - Although SEP/BB compatibility does not matter anymore for A9(X)/A10(X) devices thanks to [turdus merula](https://sep.lol)
- Restoring with iOS 14.3-15.x and 16.6+ SHSH blobs using futurerestore is also supported on these devices (SSH ramdisks not supported):
    - iPhone 8, X
    - iPad 5
    - iPad Pro 9.7/12.9 1st gen
- Restoring with **powdersn0w** is supported on the following devices and target version range:
    - See the ["powdersn0w" wiki page](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/powdersn0w)
- Restoring with **DRA v6** is supported on the following devices and target version range:
    - See the ["DRA v6" wiki page](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/DRA-v6)
- Restoring **tethered** to any version is supported on the following devices:
    - iPhone 4 (3,2 and 3,3), 4S, 5, 5C
    - iPad 2, 3, 4, mini 1
    - iPod touch 3, 4, 5
- Restoring to other unsigned versions without blobs is supported on the following devices and target version range:
    - iPhone 2G, 3G, 3GS, iPod touch 1, touch 2 - All versions are supported
    - Lowest downgradable version is 2.0. Going to 1.x does not work
    - For jailbreaking support, see below
- [Restoring the iPod touch 3rd gen and iPad 1 to iOS 6 (and also iOS 7 for iPad 1) untethered](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/touch3-ios6)
- [Restoring the iPod touch 4th gen to iOS 7 tethered](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/touch4-ios7)
- Jailbreaking for 32-bit devices and versions support:
    - iPhone 2G and touch 1 - 3.1.3 only
    - iPhone 3G and touch 2 - 3.1.3 to 4.2.1
    - iPod touch 2 - 3.1.1 to 4.2.1
    - iPhone 3GS - All release versions from 3.0 to 6.1.6 are supported
    - Other devices - All release versions from 3.1.3 to 9.3.4 are supported, with some exceptions
    - For more details, go to the ["Jailbreaking" wiki page](https://github.com/LukeZGD/Legacy-iOS-Kit/wiki/Jailbreaking)


## Supported OS versions/distros

#### Supported architectures: x86_64, arm64

- **macOS** 10.11 and newer
    - macOS 12.6 and newer recommended
- [**Ubuntu**](https://ubuntu.com/) 22.04 and newer, and Ubuntu-based distros like [Linux Mint](https://www.linuxmint.com/)
- [**Fedora**](https://fedoraproject.org/) 36 and newer, [Atomic Desktop](https://fedoraproject.org/atomic-desktops/) (Silverblue, Kinoite, [Bazzite](https://bazzite.gg/), etc.) also supported
- [**Debian**](https://www.debian.org/) 12 Bookworm and newer, Sid, and Debian-based distros
- [**Arch Linux**](https://www.archlinux.org/) and Arch-based distros like [CachyOS](https://cachyos.org) and [SteamOS](https://store.steampowered.com/steamos/)
- Less tested distros: [**openSUSE Tumbleweed**](https://get.opensuse.org/tumbleweed/), [**Gentoo**](https://www.gentoo.org/), [**Void Linux**](https://voidlinux.org/)

## Tools and other stuff used

- curl
- [bspatch](https://github.com/LukeZGD/bsdiff)
- [powdersn0w_pub](https://github.com/dora2-iOS/powdersn0w_pub) - dora2ios; [LukeZGD fork](https://github.com/LukeZGD/powdersn0w_pub)
    - [Most of the exploit ramdisks used are from kok3shidoll's repo](https://github.com/kok3shidoll/untitled)
    - [iPhone 5C 7.0.x exploit ramdisk is from m1zole](https://github.com/m1zole/untitled_pub)
    - [Other iPhone 5/5C ramdisks are from Ralph0045's iloader repo](https://github.com/Ralph0045/iloader)
    - [iPad 1 exploit ramdisk is from Ralph0045](https://github.com/Ralph0045/iBoot-5-Stuff)
    - [The following exploit ramdisks are from Pingzi610](https://github.com/Pingzi610/iloader)
        - iPhone3,2 7.1.2
        - iPad mini 1 7.0.x and 7.1.x
        - iPad 2 7.0.x and 7.1.x
        - iPad 3 7.1.x
        - iPad 4 7.0.x and 7.1.x
        - iPod touch 5 7.0.x
- [De-Rebus-Antiquis-v6](https://github.com/synackuk/De-Rebus-Antiquis-v6) - [synackuk](https://github.com/synackuk) and [Pingzi610](https://github.com/Pingzi610/De-Rebus-Antiquis-v6)
- [ipwndfu](https://github.com/LukeZGD/ipwndfu) - axi0mX; LukeZGD fork
- [iPwnder32](https://github.com/dora2ios/iPwnder32) - dora2ios
- [ipwnder_lite](https://github.com/LukeZGD/ipwnder_lite/tree/old) - dora2ios; LukeZGD fork
- [gaster](https://github.com/LukeZGD/gaster) - 0x7ff; LukeZGD fork
- [primepwn](https://github.com/LukeZGD/primepwn)
- [a6meowing](https://github.com/kok3shidoll/a6meowing) - dora/kok3shidoll; [LukeZGD fork](https://github.com/LukeZGD/a6meowing) with changes from [retr0id](https://github.com/DavidBuchanan314/a6meowing) for Linux support
- [daibutsuCFW](https://github.com/LukeZGD/daibutsuCFW) - dora2ios; LukeZGD fork
- [libimobiledevice](https://github.com/LukeZGD/libimobiledevice) - libimobiledevice
- [libirecovery](https://github.com/LukeZGD/libirecovery) - libimobiledevice
- [libideviceactivation](https://github.com/libimobiledevice/libideviceactivation) - libimobiledevice
- [ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller) - libimobiledevice
- [static-cross-openssh](https://codeberg.org/binary-manu/static-cross-openssh) - scp and ssh binaries (used on Linux only)
- [Motrix](https://github.com/agalwood/Motrix) - aria2c binaries
- [Plumesign](https://github.com/claration/Impactor) - claration (used for sideloading)
- [tsschecker](https://github.com/1Conan/tsschecker) - tihmstar; 1Conan fork (v413)
- [darkhttpd](https://github.com/LukeZGD/darkhttpd)
- [x8A4](https://github.com/Cryptiiiic/x8A4) - Cryptiiiic (for getting Cryptex seed)
- [futurerestore](https://github.com/LukeZGD/futurerestore) - LukeZGD fork (multiple branches, based on [futurerestore nightly](https://github.com/futurerestore/futurerestore/))
- [iBoot32Patcher](https://github.com/LukeZGD/iBoot32Patcher/) - Merculous fork with fixes from Pingzi610
- [idevicerestore](https://github.com/LukeZGD/idevicerestore) - libimobiledevice; LukeZGD fork
- [kloader from Odysseus](https://www.youtube.com/watch?v=fh0tB6fp0Sc)
- [kloader from axi0mX](https://github.com/axi0mX/ios-kexec-utils/blob/master/kloader) (used on iOS 4/5 only)
- [kloader for iOS 5](https://www.pmbonneau.com/cydia/com.pmbonneau.kloader5_1.2_iphoneos-arm.deb) (used on A5X iOS 5 only)
- [jq](https://github.com/jqlang/jq)
- [partialZipBrowser](https://github.com/tihmstar/partialZipBrowser)
- [zenity](https://github.com/GNOME/zenity); [macOS build](https://github.com/ncruces/zenity)
- A7 10.3.3 patches from [MatthewPierson](https://github.com/MatthewPierson/iPhone-5s-OTA-Downgrade-Patches)
- [datautils0](https://github.com/comex/datautils0) - comex (used for iPad 2 4.3.x kernel diffs)
- [sshpass](https://github.com/LukeZGD/sshpass)
- Bootstrap tar from [SpiritNET](https://invoxiplaygames.uk/projects/spiritnet/)
- [Cydia HTTPatch](https://cydia.invoxiplaygames.uk/package/cydiahttpatch) for 3.1.3 downgrades/jailbreaks
- [Aquila](https://github.com/staturnzz/aquila)
- [aquila_cdma](https://github.com/tuanemss/aquila_cdma)
- [BSPQMIShim](https://github.com/tuanemss/BSPQMIShim)
- [EverPwnage](https://github.com/LukeZGD/EverPwnage) (based on [daibutsu](https://github.com/kok3shidoll/daibutsu) - dora/kok3shidoll, Clarity)
- [Pangu](https://www.theapplewiki.com/wiki/Pangu)
- [p0sixspwn](https://www.theapplewiki.com/wiki/p0sixspwn)
- [evasi0n7](https://www.theapplewiki.com/wiki/Evasi0n7)
- [evasi0n](https://www.theapplewiki.com/wiki/Evasi0n)
- [g1lbertJB](https://github.com/g1lbertJB/g1lbertJB)
- [UntetherHomeDepot](https://www.theapplewiki.com/wiki/UntetherHomeDepot)
- [greenpois0n](https://github.com/OpenJailbreak/greenpois0n/tree/0f1eac8e748abb200fc36969e616aaad009f7ebf)
- Some patches from [PwnageTool](https://www.theapplewiki.com/wiki/PwnageTool), [sn0wbreeze](https://www.theapplewiki.com/wiki/sn0wbreeze), [redsn0w](https://www.theapplewiki.com/wiki/redsn0w)
- Many patches for the 3GS are made using patchers by Merculous (including [Bundle-Creation](https://github.com/Merculous/Bundle-Creation))
- SSH Ramdisk tars from Ralph0045's [SSH-Ramdisk-Maker-and-Loader](https://github.com/Ralph0045/SSH-Ramdisk-Maker-and-Loader) and msftguy's [ssh-rd](https://github.com/msftguy/ssh-rd)
- 64-bit SSH Ramdisk stuff is based on Nathan's [SSHRD_Script](https://github.com/verygenericname/SSHRD_Script) (iOS 12+), and exploit3dguy's iram tar from [iarchive.app](https://web.archive.org/web/20240324134204/https://ios7.iarchive.app/downgrade/making-ramdisk.html) (iOS 8)
    - [img4lib](https://github.com/xerub/img4lib) - xerub
    - [img4tool](https://github.com/tihmstar/img4tool) - tihmstar
- Tools used for dumping IPA - forks by rcky844
    - [ipainstaller](https://github.com/rcky844/ipainstaller)
    - [Clutch](https://github.com/rcky844/Clutch)
- For iPhone X restore patches:
    - Method by Mineek and Nathan
    - Mineek's [restored_external patcher](https://gist.github.com/mineek/16c2607c928477dcd273e680e40a1c90) for iPhone X downgrades to 14.3-15.x
    - [KPlooshFinder](https://github.com/plooshi/KPlooshFinder/tree/amfi-only)
    - [kerneldiff](https://gist.github.com/LukeZGD/8c719b613ca28d6883552437bdd500de)
- iPad 1 and iPod touch 3 unofficial upgrades:
    - [SundanceInH2A](https://github.com/NyanSatan/SundanceInH2A) - NyanSatan
    - [ipad-1-ios-7](https://github.com/amy-and-nicole/ipad-1-ios-7) - amy-and-nicole and pwnerblu, also uses stuff from SundanceInH2A
- [kurouta dori](https://sep.lol/legacy/index.html) (turdus merula A6(X)) - dora/kok3shidoll (used for A6X pwning on Linux, and iOS 10 tethered restores)
