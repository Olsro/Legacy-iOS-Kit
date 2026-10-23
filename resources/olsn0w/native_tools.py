"""Build the host HFS helper from the kit's pinned xpwn implementation."""
import hashlib
import json
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
                result = subprocess.run(argv, capture_output=True, timeout=120)
                if result.returncode:
                    return (result.stdout + result.stderr).decode(errors='replace')[-2000:]
        except (OSError, subprocess.TimeoutExpired) as error:
            return str(error)
    return None


def ensure_build_dependencies():
    problem = build_dependencies_problem()
    if problem is None:
        return
    print('olsn0w: native build prerequisites are missing or unusable:\n' + problem,
          file=sys.stderr, flush=True)
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
    with tempfile.TemporaryDirectory(prefix='hfscompress-build-', dir=destination.parent) as temporary:
        temporary = Path(temporary)
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
        run(['cmake', '-S', source, '-B', build, '-DXPWN_SOURCE=' + str(xpwn),
             '-DCMAKE_BUILD_TYPE=Release'], log=temporary / 'configure.log')
        run(['cmake', '--build', build, '--parallel', '2'], log=temporary / 'compile.log', timeout=600)
        result = temporary / 'result'
        result.mkdir()
        shutil.copy2(build / 'olsn0w-hfscompress', result / executable.name)
        shutil.copy2(xpwn / 'LICENSE', result / 'XPWN-LICENSE')
        for name in ('configure.log', 'compile.log'):
            shutil.copy2(temporary / name, result / name)
        save(result / 'build.json', dict(source_commit=XPWN_COMMIT,
             source_sha256=XPWN_ARCHIVE_SHA256, sha256=digest(result / executable.name), host=host))
        result.rename(destination)
    return executable
