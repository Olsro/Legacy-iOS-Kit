#!/bin/sh
# Usage: build-protection-probe.sh CLANG MACH_O_LD STOCK_LIBRARY_ROOT OUTPUT
# Compile the diagnostic for iOS 6 with stock libraries; sign the result
# with the checked signing helper before placing it in target/.
set -eu
compiler=$1
linker=$2
libraries=$3
output=$4
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$compiler" -target armv7-apple-ios6.0 -mthumb -Os -nostdinc -ffreestanding \
    -c "$source_dir/protection_probe.c" -o "$output.o"
"$linker" -arch armv7 -ios_version_min 6.0 -syslibroot "$libraries" \
    "$libraries/usr/lib/libSystem.B.dylib" -o "$output" "$output.o"
rm "$output.o"
