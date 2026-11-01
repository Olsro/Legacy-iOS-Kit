"""Build the host HFS helper from the kit's pinned xpwn implementation."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

from archives import members
from common import KIT, STATE, digest, run, save
from firmware import fetch

XPWN_COMMIT = '300c54a161925afdb77723616025bd60047db7fd'
XPWN_ARCHIVE_SHA256 = '5cfed5242db6fccfae76a7677cb28c41c301669a3aa54aeed5fd4fab0901b43c'
CMAKE_MACOS_PACKAGE = 'cmake-3.31.12-macos10.10-universal'
CMAKE_MACOS_SHA256 = 'cf096d869d45b79f5ce82f3d6abffa44f983fc146fee13cfe59024911e6975af'


# The first launch of a freshly extracted CMake.app can be held for a long time
# by Gatekeeper/XProtect on recent macOS releases, especially on slow disks.
CMAKE_FIRST_LAUNCH_TIMEOUT = 300


def cmake_problem(executable, timeout=15):
    """Return None if CMake runs, otherwise a short description of the failure."""
    try:
        result = subprocess.run([str(executable), '--version'], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 'cmake --version did not finish within %d seconds' % timeout
    except OSError as error:
        return str(error)
    if result.returncode:
        output = (result.stdout + result.stderr).decode(errors='replace').strip()[-1000:]
        return 'cmake --version exited with status %d%s' % (result.returncode,
                                                            ': ' + output if output else '')
    return None


def usable_cmake(executable):
    return cmake_problem(executable) is None


def prepare_macos_cmake():
    """Use CMake.app or a private, checksum-pinned build for macOS 10.10+."""
    if platform.system() != 'Darwin':
        return
    installed = shutil.which('cmake')
    if installed and usable_cmake(installed):
        return
    destination = STATE / 'tools' / CMAKE_MACOS_PACKAGE
    relative = Path('CMake.app/Contents/bin/cmake')
    candidates = [Path('/Applications') / relative,
                  Path.home() / 'Applications' / relative, destination / relative]
    for executable in candidates:
        if executable.is_file() and usable_cmake(executable):
            os.environ['PATH'] = str(executable.parent) + os.pathsep + os.environ.get('PATH', '')
            return
    archive = STATE / 'sources' / (CMAKE_MACOS_PACKAGE + '.tar.gz')
    if not archive.exists():
        print('olsn0w: downloading private CMake 3.31.12 (compatible with High Sierra); '
              'Homebrew is not required.', file=sys.stderr, flush=True)
        fetch('https://cmake.org/files/v3.31/' + archive.name, archive)
    if digest(archive) != CMAKE_MACOS_SHA256:
        raise ValueError('CMake archive checksum mismatch: ' + str(archive))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cmake-install-', dir=destination.parent) as temporary:
        # Only extract the official archive after checking the pinned SHA-256.
        result = subprocess.run(['tar', '-xzf', str(archive), '-C', temporary],
                                capture_output=True, timeout=120)
        if result.returncode:
            raise RuntimeError('Could not extract private CMake: ' + result.stderr.decode(errors='replace'))
        extracted = Path(temporary) / CMAKE_MACOS_PACKAGE
        problem = cmake_problem(extracted / relative, CMAKE_FIRST_LAUNCH_TIMEOUT)
        if problem is not None:
            raise RuntimeError('Private CMake cannot run on this Mac (' + problem + '). '
                               'Install CMake.app from https://cmake.org/download/ into /Applications, '
                               'or run: brew install cmake, then run olsn0w again.')
        if destination.exists():
            shutil.rmtree(destination)
        extracted.rename(destination)
    os.environ['PATH'] = str((destination / relative).parent) + os.pathsep + os.environ.get('PATH', '')


# Configuring and compiling can be very slow on Live USB systems.
BUILD_TIMEOUT = 1800


def build_dependencies_problem():
    if not shutil.which('cmake'):
        return 'CMake is not installed.'
    # Check the same CMake generator, compiler and zlib headers/library that
    # the real build will use. Finding an executable alone is insufficient.
    with tempfile.TemporaryDirectory(prefix='olsn0w-build-check-') as temporary:
        source = Path(temporary)
        (source / 'CMakeLists.txt').write_text(
            'cmake_minimum_required(VERSION 3.10)\n'
            'project(olsn0w_build_check C)\n'
            'find_package(ZLIB REQUIRED)\n'
            'add_executable(check_zlib main.c)\n'
            'target_link_libraries(check_zlib PRIVATE ZLIB::ZLIB)\n')
        (source / 'main.c').write_text('#include <zlib.h>\nint main(void) { return zlibVersion() == 0; }\n')
        try:
            for argv in (['cmake', '-S', str(source), '-B', str(source / 'build')],
                         ['cmake', '--build', str(source / 'build')]):
                result = subprocess.run(argv, capture_output=True, timeout=BUILD_TIMEOUT)
                if result.returncode:
                    return (result.stdout + result.stderr).decode(errors='replace')[-2000:]
        except (OSError, subprocess.TimeoutExpired) as error:
            return str(error)
    return None


def ensure_build_dependencies():
    prepare_macos_cmake()
    problem = build_dependencies_problem()
    if problem is None:
        return
    print('olsn0w: native build prerequisites are missing or unusable:\n' + problem,
          file=sys.stderr, flush=True)
    if platform.system() == 'Darwin':
        raise RuntimeError('CMake is available, but the C compiler, Make or macOS SDK/zlib check failed. '
                           'Install the Xcode Command Line Tools with: xcode-select --install. '
                           'Finish installation, then run olsn0w again. If they are already installed, '
                           'check xcode-select -p and the build diagnostics above.')
    result = subprocess.run(['sh', str(KIT / 'resources/olsn0w/setup.sh'), '--native-only'])
    if result.returncode:
        raise RuntimeError('Could not install the native build prerequisites; see the package manager error above. '
                           'Run olsn0w again to retry.')
    problem = build_dependencies_problem()
    if problem is not None:
        raise RuntimeError('Native build prerequisites are still unusable after installation:\n' + problem)


def hfscompress():
    source = KIT / 'resources/olsn0w/native/hfscompress'
    fingerprint = hashlib.sha256()
    for name in ('CMakeLists.txt', 'compress.c', 'extents_write.c'):
        fingerprint.update((source / name).read_bytes())
    fingerprint.update(XPWN_ARCHIVE_SHA256.encode())
    host = platform.system() + '-' + platform.machine()
    destination = STATE / 'tools' / ('hfscompress-' + host + '-' + fingerprint.hexdigest()[:16])
    executable = destination / 'olsn0w-hfscompress'
    if executable.is_file():
        report = json.loads((destination / 'build.json').read_text())
        if digest(executable) != report['sha256']:
            raise ValueError('HFS helper checksum differs from its completed build')
        return executable
    ensure_build_dependencies()
    archive = STATE / 'sources' / ('powdersn0w-' + XPWN_COMMIT + '.tar.gz')
    if not archive.exists():
        fetch('https://codeload.github.com/LukeZGD/powdersn0w_pub/tar.gz/' + XPWN_COMMIT, archive)
    if digest(archive) != XPWN_ARCHIVE_SHA256:
        raise ValueError('xpwn source archive checksum mismatch')
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Make interprets colons in source/dependency paths as rule separators.
    # Keep every build input outside the Kit path, which may contain a colon.
    # Stage installation beside the cache so the final rename stays atomic
    # even when the system temporary directory is on another filesystem.
    with tempfile.TemporaryDirectory(prefix='hfscompress-build-') as temporary, \
         tempfile.TemporaryDirectory(prefix='hfscompress-install-', dir=destination.parent) as staging:
        temporary = Path(temporary)
        build_source = temporary / 'source'
        shutil.copytree(source, build_source)
        xpwn = temporary / 'xpwn'
        prefix = 'powdersn0w_pub-' + XPWN_COMMIT + '/xpwn/'
        for item, data in members(archive):
            if not item.name.startswith(prefix):
                continue
            relative = item.name[len(prefix):]
            if relative != 'LICENSE' and not relative.startswith(('include/', 'hfs/', 'common/')):
                continue
            if not item.isfile():
                if item.isdir():
                    continue
                raise ValueError('Unexpected link in xpwn sources')
            path = xpwn / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        build = temporary / 'build'
        run(['cmake', '-S', build_source, '-B', build, '-DXPWN_SOURCE=' + str(xpwn),
             '-DCMAKE_BUILD_TYPE=Release'], log=temporary / 'configure.log', timeout=BUILD_TIMEOUT)
        run(['cmake', '--build', build, '--parallel', '2'], log=temporary / 'compile.log', timeout=BUILD_TIMEOUT)
        result = Path(staging) / 'result'
        result.mkdir()
        shutil.copy2(build / 'olsn0w-hfscompress', result / executable.name)
        shutil.copy2(xpwn / 'LICENSE', result / 'XPWN-LICENSE')
        for name in ('configure.log', 'compile.log'):
            shutil.copy2(temporary / name, result / name)
        save(result / 'build.json', dict(source_commit=XPWN_COMMIT,
             source_sha256=XPWN_ARCHIVE_SHA256, sha256=digest(result / executable.name), host=host))
        result.rename(destination)
    return executable
