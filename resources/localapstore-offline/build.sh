#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /path/to/CydiaSubstrate out-directory" >&2
    exit 2
fi
substrate=$1
output=$2
mkdir -p "$output"
cp "$substrate" "$output/libCydiaSubstrate.dylib"
cp "$(dirname "$0")/libSystem.tbd" "$output/libSystem.tbd"
cp "$(dirname "$0")/libobjc.tbd" "$output/libobjc.tbd"
xcrun --sdk iphoneos clang -target armv7-apple-ios5.1.1 -mthumb -Os -fPIC \
    -dynamiclib -nostdlib \
    -Wl,-install_name,/Library/MobileSubstrate/DynamicLibraries/LocalAPStoreOffline.dylib \
    -L"$output" -lSystem -lobjc -lCydiaSubstrate \
    "$(dirname "$0")/OfflineCatalog.c" -o "$output/LocalAPStoreOffline.armv7.dylib"
xcrun --sdk iphoneos clang -target arm64-apple-ios7.0 -Os -fPIC \
    -dynamiclib -nostdlib \
    -Wl,-install_name,/Library/MobileSubstrate/DynamicLibraries/LocalAPStoreOffline.dylib \
    -L"$output" -lSystem -lobjc -lCydiaSubstrate \
    "$(dirname "$0")/OfflineCatalog.c" -o "$output/LocalAPStoreOffline.arm64.dylib"
lipo -create "$output/LocalAPStoreOffline.armv7.dylib" \
    "$output/LocalAPStoreOffline.arm64.dylib" -output "$output/LocalAPStoreOffline.dylib"
