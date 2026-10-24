#!/bin/sh
# Rebuild the distribution DOL in a pinned devkitPPC container.
set -eu

package_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
network_mode=${A5WII_ENABLE_NETWORK:-0}

for profile in 8940 8942 8945; do
  docker run --rm \
    -v "$package_root:/project" \
    -w /project/sources/a5wii \
    devkitpro/devkitppc:20260215 \
    /bin/sh -lc ". /opt/devkitpro/wiivars.sh && make clean && make A5WII_ENABLE_PWNDFU=1 A5WII_ENABLE_NETWORK=$network_mode A5WII_A5_PROFILE=$profile A5WII_BUILD_LABEL=0.1.2-ehci-topology && cp a5wii.dol /project/apps/a5mate-wii-$profile/boot.dol && make clean"
done

(cd "$package_root" && shasum -a 256 apps/a5mate-wii-8940/boot.dol apps/a5mate-wii-8942/boot.dol apps/a5mate-wii-8945/boot.dol > SHA256SUMS)
