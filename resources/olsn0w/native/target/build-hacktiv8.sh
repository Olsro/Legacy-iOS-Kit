#!/bin/sh
set -eu
compiler=$1
linker=$2
libraries=$3
output=$4
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$compiler" -target armv7-apple-ios7.0 -mthumb -Os -nostdinc \
    -fno-stack-protector -c \
    "$source_dir/hacktiv8_mobilegestalt.c" -o "$output.o"
"$linker" -arch armv7 -iphoneos_version_min 7.0 -syslibroot "$libraries" \
    "$libraries/usr/lib/libSystem.B.dylib" \
    "$libraries/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation" \
    -o "$output" "$output.o"
rm "$output.o"
