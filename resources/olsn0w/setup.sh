#!/bin/sh
set -eu
kit=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

as_root() {
    if [ "$(id -u)" = 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo 'olsn0w: installing system prerequisites requires root or sudo.' >&2
        exit 1
    fi
}

install_host_python() {
    echo 'olsn0w: installing Python 3 and virtual environment support.' >&2
    echo 'Your system may request your password to install these packages.' >&2
    if [ "$(uname -s)" = Darwin ]; then
        if ! command -v brew >/dev/null 2>&1; then
            echo 'olsn0w: Python 3.8+ with venv is required. Install Python from https://www.python.org/downloads/macos/ or install Homebrew, then retry.' >&2
            exit 1
        fi
        brew install python
    elif command -v apt-get >/dev/null 2>&1; then
        # One broken source (such as a Live USB cdrom entry) fails the whole
        # update although the other package lists were refreshed.
        as_root apt-get update || echo 'olsn0w: apt-get update reported errors; continuing with the available package lists.' >&2
        as_root apt-get install -y python3 python3-venv
    elif command -v dnf >/dev/null 2>&1; then
        as_root dnf install -y python3 python3-pip
    elif command -v pacman >/dev/null 2>&1; then
        as_root pacman -S --needed --noconfirm python python-pip
    elif command -v zypper >/dev/null 2>&1; then
        as_root zypper -n install python3 python3-pip
    elif command -v xbps-install >/dev/null 2>&1; then
        as_root xbps-install -Sy python3 python3-pip
    else
        echo 'olsn0w: no supported package manager found. Install Python 3.8+ with venv and ensurepip, then retry.' >&2
        exit 1
    fi
}

install_native_dependencies() {
    echo 'olsn0w: installing CMake, a C compiler, Make and zlib development files.' >&2
    echo 'Your system may request your password to install these packages.' >&2
    if [ "$(uname -s)" = Darwin ]; then
        if ! command -v brew >/dev/null 2>&1; then
            echo 'olsn0w: install CMake and the Xcode Command Line Tools, or install Homebrew, then retry.' >&2
            exit 1
        fi
        brew install cmake
    elif command -v apt-get >/dev/null 2>&1; then
        # One broken source (such as a Live USB cdrom entry) fails the whole
        # update although the other package lists were refreshed.
        as_root apt-get update || echo 'olsn0w: apt-get update reported errors; continuing with the available package lists.' >&2
        as_root apt-get install -y build-essential cmake zlib1g-dev
    elif command -v dnf >/dev/null 2>&1; then
        as_root dnf install -y cmake gcc make zlib-devel
    elif command -v pacman >/dev/null 2>&1; then
        as_root pacman -S --needed --noconfirm base-devel cmake zlib
    elif command -v zypper >/dev/null 2>&1; then
        as_root zypper -n install cmake gcc make zlib-devel
    elif command -v xbps-install >/dev/null 2>&1; then
        as_root xbps-install -Sy base-devel cmake zlib-devel
    else
        echo 'olsn0w: install CMake, a C compiler, Make and zlib development files, then retry.' >&2
        exit 1
    fi
}

# Native prerequisites can be repaired without rebuilding the Python runtime.
if [ "${1:-}" = --native-only ]; then
    install_native_dependencies >&2
    exit 0
fi

host_ready() {
    python3 -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3, 8))' 2>/dev/null
}

if ! host_ready; then
    install_host_python >&2
fi
if ! host_ready; then
    echo 'olsn0w: python3 still lacks Python 3.8+, venv or ensurepip. Check which python3 is selected in PATH.' >&2
    exit 1
fi
[ "${1:-}" != --host-only ] || exit 0

runtime="$kit/saved/olsn0w/runtime"
# Rebuild only the disposable environment, preserving firmware and device data.
python3 -m venv --clear "$runtime"
"$runtime/bin/python" -m pip install -r "$kit/resources/olsn0w/requirements.txt" >&2
"$runtime/bin/python" "$kit/resources/olsn0w/runtime.py"
