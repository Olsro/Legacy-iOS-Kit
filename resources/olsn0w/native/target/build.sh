#!/bin/sh
# Usage: build.sh CLANG MACH_O_LD STOCK_LIBRARY_ROOT OUTPUT
# Uses stock iOS libraries, on either Linux or macOS; no Apple SDK is required.
set -eu
compiler=$1
linker=$2
libraries=$3
output=$4
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$compiler" -target armv7-apple-ios6.0 -mthumb -Os -nostdinc -c "$source_dir/load_jobs.c" -o "$output.o"
"$linker" -arch armv7 -iphoneos_version_min 6.0 -syslibroot "$libraries" \
    "$libraries/usr/lib/libSystem.B.dylib" \
    "$libraries/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation" \
    -o "$output" "$output.o"
rm "$output.o"
