"""Shared paths, model identities and checked host operations."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
from progress import activity

KIT = Path(__file__).resolve().parents[2]
STATE = KIT / 'saved' / 'olsn0w'
MODELS = {
    'iPhone4,1': ('n94ap', 0x8940, 8),
    'iPhone5,1': ('n41ap', 0x8950, 0),
    'iPhone5,2': ('n42ap', 0x8950, 2),
    'iPad3,4': ('p101ap', 0x8955, 0),
    'iPad3,5': ('p102ap', 0x8955, 2),
    'iPad3,6': ('p103ap', 0x8955, 4),
}

# Keep the historic tuple table above for the binary-identity call sites, but
# put every behavioural difference in one checked profile.  Adding a product
# to MODELS must never silently make it inherit A6 boot, cache or modem rules.
MODEL_PROFILES = {
    'iPhone4,1': dict(soc='a5', cache_arch='armv7', has_baseband=True,
                     baseband_family='Trek',
                     external_pwndfu=True, multipatch=True,
                     baseband=dict(version='9.3.6', build='13G37',
                                   name='Trek-6.7.00.Release.bbfw',
                                   sha1='22a35425a3cdf8fa1458b5116cfb199448eecf49')),
    'iPhone5,1': dict(soc='a6', cache_arch='armv7s', has_baseband=True,
                     baseband_family='Mav5'),
    'iPhone5,2': dict(soc='a6', cache_arch='armv7s', has_baseband=True,
                     baseband_family='Mav5',
                     # This DeviceTree workaround was qualified only on the
                     # N42 6.1.3 Lightning handoff.  In particular, applying
                     # it to p101/A6X changes a kernel hang into a reboot.
                     tristar_soft_reset_versions=('6.1.3',)),
    'iPad3,4': dict(soc='a6x', cache_arch='armv7s', has_baseband=False),
    'iPad3,5': dict(soc='a6x', cache_arch='armv7s', has_baseband=True,
                   baseband_family='Mav5'),
    'iPad3,6': dict(soc='a6x', cache_arch='armv7s', has_baseband=True,
                   baseband_family='Mav5'),
}

BASEBAND_FILES = {
    'Mav5': ('apps.mbn','bbticket.der','dsp1.mbn','dsp2.mbn','dsp3.mbn',
             'rpm.mbn','sbl1.mbn','sbl2.mbn'),
    'Trek': ('amss.mbn','bbticket.der','dbl.mbn','osbl.mbn','restoredbl.mbn'),
}


def baseband_files(family):
    try:return BASEBAND_FILES[family]
    except KeyError as error:raise ValueError('Unsupported modem family') from error


def profile(product):
    if product not in MODELS or product not in MODEL_PROFILES:
        raise ValueError('Unsupported product')
    value = dict(MODEL_PROFILES[product])
    if 'baseband' in value:
        value['baseband'] = dict(value['baseband'])
    return value


def version(value):
    if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', value):
        raise ValueError('Expected a release version')
    return tuple(map(int, value.split('.'))) + (0,) * (3 - len(value.split('.')))


def target(product, release):
    if product not in MODELS or version(release) < version('6.0'):
        raise ValueError('Expected a supported 32-bit release from iOS 6.0 onward')
    return MODELS[product]


def tools():
    system = {'Darwin': 'macos', 'Linux': 'linux'}.get(platform.system())
    machine = {'aarch64': 'arm64', 'AMD64': 'x86_64'}.get(platform.machine(), platform.machine())
    if system is None:
        raise ValueError('Unsupported host platform')
    if machine not in ('arm64', 'x86_64'):
        raise ValueError('Unsupported host architecture: ' + machine)
    path = KIT / 'bin' / system / machine
    if not path.is_dir() and system == 'macos':
        path = KIT / 'bin' / system
    if not path.is_dir():
        raise ValueError('Legacy iOS Kit tools are missing: ' + str(path))
    return path


def digest(path, algorithm='sha256'):
    result = hashlib.new(algorithm)
    with activity('Verifying file integrity',Path(path).stat().st_size) as update, Path(path).open('rb') as stream:
        done=0
        for chunk in iter(lambda: stream.read(4 * 1048576), b''):
            result.update(chunk);done+=len(chunk);update(done)
    return result.hexdigest()


def clone_or_copy(source, destination):
    """Copy a mutable image, using copy-on-write when the host supports it."""
    source, destination = Path(source), Path(destination)
    if not source.is_file() or destination.exists():
        raise ValueError('Expected an existing source and a new image destination')
    try:
        if platform.system() == 'Darwin':
            result = subprocess.run(['/bin/cp', '-c', str(source), str(destination)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                return destination
        elif platform.system() == 'Linux':
            import fcntl
            with source.open('rb') as incoming, destination.open('xb') as outgoing:
                # Linux FICLONE. Unsupported filesystems return an error and
                # fall through to the ordinary portable copy below.
                fcntl.ioctl(outgoing.fileno(), 0x40049409, incoming.fileno())
            return destination
    except OSError:
        pass
    if destination.exists():
        destination.unlink()
    shutil.copyfile(source, destination)
    return destination


def run(argv, log=None, patcher=False, timeout=180):
    descriptions={'dmg':'Extracting system image','hfsplus':'Preparing filesystem contents',
                  'cmake':'Preparing filesystem tools','xpwntool':'Packing boot component',
                  'iBoot32Patcher':'Preparing boot component','curl':'Obtaining required files'}
    with activity(descriptions.get(Path(str(argv[0])).name,'Running preparation tool')):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=timeout)
    if log:
        Path(log).write_bytes(result.stdout + result.stderr)
    expected = 1 if patcher else 0
    if result.returncode != expected or (patcher and b'main: Quitting...' not in result.stdout + result.stderr):
        raise RuntimeError(Path(str(argv[0])).name + ': ' + (result.stdout + result.stderr).decode(errors='replace')[-2000:])
    return result.stdout


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)
