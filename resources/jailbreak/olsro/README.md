# Olsro sources

`private/etc/apt/sources.list.d/Olsro.list` is the single source list shared by
olsn0w and the other jailbreak restoration paths in `restore.sh`. The nine flat
repositories were checked against http://cydia.olsro.fr/ on 2026-09-24.

The shell prepares a small root-owned ustar overlay for custom IPSW builders,
direct HFS injection and SSH ramdisk installs. Sundance and g1lbert receive the
same overlay appended to their Cydia bootstrap. Prebuilt legacy filesystems
receive it after extraction, including filesystem replacements by multipatch.
No installed packages, other repositories or APT trust policies are changed.
Stock (non-jailbreak) restores are unaffected.

New generated jailbreak IPSW names carry `Olsro1`, avoiding reuse of images made
without the sources; old IPSWs are not deleted. olsn0w uses system recipe 38.
Existing devices and externally supplied custom IPSWs are not retroactively
modified. Adding a repository does not guarantee compatibility of its packages
with every target iOS release.

When changing the list, also update the shell cache suffix and the olsn0w system
recipe version so previously prepared images are not silently reused.
