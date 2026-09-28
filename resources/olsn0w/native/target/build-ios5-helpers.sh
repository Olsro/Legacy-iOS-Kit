#!/bin/sh
# Usage: build-ios5-helpers.sh CLANG MACH_O_LD IOS5_SDK OUTPUT_DIRECTORY
# Separate artifacts: never replace the physically qualified iOS 6 helpers.
set -eu
compiler=$1
linker=$2
sdk=$3
output=$4
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$output"
for name in keybag_init protection_probe; do
    "$compiler" -target armv7-apple-ios5.0 -mthumb -Os -nostdinc -ffreestanding \
        -c "$source_dir/$name.c" -o "$output/$name.o"
    # crt1 supplies the pre-iOS 6 LC_UNIXTHREAD entry convention.
    if [ "$name" = keybag_init ]; then
        "$linker" -arch armv7 -iphoneos_version_min 5.0 -syslibroot "$sdk" \
            "$sdk/usr/lib/crt1.o" "$output/$name.o" -lSystem \
            -framework CoreFoundation -framework IOKit -o "$output/keybag-init"
    else
        "$linker" -arch armv7 -iphoneos_version_min 5.0 -syslibroot "$sdk" \
            "$sdk/usr/lib/crt1.o" "$output/$name.o" -lSystem \
            -o "$output/protection-probe"
    fi
done
