"""Shared paths, model identities and checked host operations."""
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
from progress import activity

KIT = Path(__file__).resolve().parents[2]
STATE = KIT / 'saved' / 'olsn0w'
MODELS = {
    'iPhone5,1': ('n41ap', 0x8950, 0),
    'iPhone5,2': ('n42ap', 0x8950, 2),
    'iPad3,4': ('p101ap', 0x8955, 0),
    'iPad3,5': ('p102ap', 0x8955, 2),
    'iPad3,6': ('p103ap', 0x8955, 4),
}


def version(value):
    if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', value):
        raise ValueError('Expected a release version')
    return tuple(map(int, value.split('.'))) + (0,) * (3 - len(value.split('.')))


def target(product, release):
    if product not in MODELS or version(release) < version('6.0'):
        raise ValueError('Expected an iPhone 5 / iPad 4 release from iOS 6.0 onward')
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
