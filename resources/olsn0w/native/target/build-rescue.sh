#!/bin/sh
# Usage: build-rescue.sh CLANG MACH_O_LD STOCK_LIBRARY_ROOT OUTPUT
set -eu
compiler=$1
linker=$2
libraries=$3
output=$4
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$compiler" -target armv7-apple-ios8.0 -mthumb -Os -nostdinc -ffreestanding \
    -c "$source_dir/rescue_unmount.c" -o "$output.o"
"$linker" -arch armv7 -iphoneos_version_min 8.0 -syslibroot "$libraries" \
    "$libraries/usr/lib/libSystem.B.dylib" -o "$output" "$output.o"
rm "$output.o"
