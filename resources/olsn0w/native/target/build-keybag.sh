#!/bin/sh
# Usage: build-keybag.sh CLANG MACH_O_LD STOCK_LIBRARY_ROOT OUTPUT
# Cross-build with stock libraries on Linux or macOS, without an Apple SDK.
set -eu
compiler=$1
linker=$2
libraries=$3
output=$4
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$compiler" -target armv7-apple-ios6.0 -mthumb -Os -nostdinc -ffreestanding \
    -c "$source_dir/keybag_init.c" -o "$output.o"
"$linker" -arch armv7 -iphoneos_version_min 6.0 -syslibroot "$libraries" \
    "$libraries/usr/lib/libSystem.B.dylib" \
    "$libraries/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation" \
    "$libraries/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit" \
    -o "$output" "$output.o"
rm "$output.o"
