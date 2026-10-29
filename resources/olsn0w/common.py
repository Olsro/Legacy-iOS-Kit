"""Shared paths, model identities and checked host operations."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
from progress import activity

KIT = Path(__file__).resolve().parents[2]
SUPPORT_MESSAGE = 'Visit https://olsro.fr for cool stuff and to support Olsro with a donation.'
STATE = KIT / 'saved' / 'olsn0w'
# Full system images on slow hosts (Live USB overlays, USB 2 disks) can take
# well over ten minutes to extract or rebuild.
IMAGE_TIMEOUT = 3600
MODELS = {
    'iPad2,1': ('k93ap', 0x8940, 4),
    'iPad2,2': ('k94ap', 0x8940, 6),
    'iPad2,3': ('k95ap', 0x8940, 2),
    'iPad2,4': ('k93aap', 0x8942, 6),
    'iPad2,5': ('p105ap', 0x8942, 10),
    'iPad2,6': ('p106ap', 0x8942, 12),
    'iPad2,7': ('p107ap', 0x8942, 14),
    'iPad3,1': ('j1ap', 0x8945, 0),
    'iPad3,2': ('j2ap', 0x8945, 2),
    'iPad3,3': ('j2aap', 0x8945, 4),
    'iPhone4,1': ('n94ap', 0x8940, 8),
    'iPhone5,1': ('n41ap', 0x8950, 0),
    'iPhone5,2': ('n42ap', 0x8950, 2),
    'iPad3,4': ('p101ap', 0x8955, 0),
    'iPad3,5': ('p102ap', 0x8955, 2),
    'iPad3,6': ('p103ap', 0x8955, 4),
    'iPod5,1': ('n78ap', 0x8942, 0),
}


def target_paths(target, *, verbose=False, remove_setup_app=False):
    """Keep graphical/verbose relays and their embedded system images separate."""
    target = Path(target)
    suffix = '-verbose' if verbose else ''
    return (target/('relay'+suffix),
            target/(('system-hacktiv8-v1' if remove_setup_app else 'system')+suffix))


def hardware_model(board):
    """Return Apple's case-sensitive hw.model for a firmware board identity."""
    if board not in {model[0] for model in MODELS.values()}:
        raise ValueError('Unsupported hardware board')
    return {'k93aap': 'K93aAP', 'j2aap': 'J2aAP'}.get(board, board.upper())


# This is the exact 32-bit OTA 8.4.1 signing set exposed by the Kit. Keep the
# restore menu and the checked model profiles equal to this set.
SIGNED_841_PRODUCTS = frozenset(MODELS)

# Keep the historic tuple table above for the binary-identity call sites, but
# put every behavioural difference in one checked profile.  Adding a product
# to MODELS must never silently make it inherit A6 boot, cache or modem rules.
MODEL_PROFILES = {
    'iPad2,1': dict(soc='a5', cache_arch='armv7', has_baseband=False,
                    external_pwndfu=True),
    'iPad2,2': dict(soc='a5', cache_arch='armv7', has_baseband=True,
                    baseband_strategy='preserve', external_pwndfu=True),
    'iPad2,3': dict(soc='a5', cache_arch='armv7', has_baseband=True,
                    baseband_strategy='preserve', external_pwndfu=True),
    'iPad2,4': dict(soc='a5r2', cache_arch='armv7', has_baseband=False,
                    external_pwndfu=True),
    'iPad2,5': dict(soc='a5r2', cache_arch='armv7', has_baseband=False,
                    external_pwndfu=True, tristar_soft_reset_majors=(6, 7, 8)),
    'iPad2,6': dict(soc='a5r2', cache_arch='armv7', has_baseband=True,
                    baseband_family='Mav5', external_pwndfu=True,
                    tristar_soft_reset_majors=(6,),
                    baseband=dict(version='9.3.6', build='13G37',
                                  name='Mav5-11.80.00.Release.bbfw',
                                  sha1='aa52cf75b82fc686f94772e216008345b6a2a750')),
    'iPad2,7': dict(soc='a5r2', cache_arch='armv7', has_baseband=True,
                    baseband_family='Mav5', external_pwndfu=True,
                    tristar_soft_reset_majors=(6,),
                    baseband=dict(version='9.3.6', build='13G37',
                                  name='Mav5-11.80.00.Release.bbfw',
                                  sha1='aa52cf75b82fc686f94772e216008345b6a2a750')),
    'iPad3,1': dict(soc='a5x', cache_arch='armv7', has_baseband=False,
                    external_pwndfu=True),
    'iPad3,2': dict(soc='a5x', cache_arch='armv7', has_baseband=True,
                    baseband_strategy='preserve', external_pwndfu=True),
    'iPad3,3': dict(soc='a5x', cache_arch='armv7', has_baseband=True,
                    baseband_strategy='preserve', external_pwndfu=True),
    'iPhone4,1': dict(soc='a5', cache_arch='armv7', has_baseband=True,
                     baseband_family='Trek',
                     external_pwndfu=True, multipatch=True,
                     baseband=dict(version='9.3.6', build='13G37',
                                   name='Trek-6.7.00.Release.bbfw',
                                   sha1='22a35425a3cdf8fa1458b5116cfb199448eecf49')),
    'iPhone5,1': dict(soc='a6', cache_arch='armv7s', has_baseband=True,
                     baseband_family='Mav5', tristar_soft_reset_majors=(6,)),
    'iPhone5,2': dict(soc='a6', cache_arch='armv7s', has_baseband=True,
                     baseband_family='Mav5',
                     tristar_soft_reset_majors=(6,)),
    'iPad3,4': dict(soc='a6x', cache_arch='armv7s', has_baseband=False,
                   tristar_soft_reset_majors=(6, 7, 8)),
    'iPad3,5': dict(soc='a6x', cache_arch='armv7s', has_baseband=True,
                   baseband_family='Mav5', tristar_soft_reset_majors=(6, 7, 8)),
    'iPad3,6': dict(soc='a6x', cache_arch='armv7s', has_baseband=True,
                   baseband_family='Mav5', tristar_soft_reset_majors=(6, 7, 8)),
    'iPod5,1': dict(soc='a5r2', cache_arch='armv7', has_baseband=False,
                    external_pwndfu=True, tristar_soft_reset_majors=(6,)),
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


def baseband_strategy(product):
    """Return whether the signed-base restore updates or preserves the modem."""
    selected=profile(product)
    if not selected['has_baseband']:
        return 'none'
    strategy=selected.get('baseband_strategy','update')
    if strategy not in ('update','preserve'):
        raise ValueError('Unsupported modem restore strategy')
    if strategy=='update' and 'baseband_family' not in selected:
        raise ValueError('Updated modem profile needs a firmware family')
    return strategy


def version(value):
    if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', value):
        raise ValueError('Expected a release version')
    return tuple(map(int, value.split('.'))) + (0,) * (3 - len(value.split('.')))


IOS5_MINIMUM = {
    'iPad2,1': '5.0', 'iPad2,2': '5.0', 'iPad2,3': '5.0',
    'iPad2,4': '5.1',
    'iPad3,1': '5.1', 'iPad3,2': '5.1', 'iPad3,3': '5.1',
    'iPhone4,1': '5.0',
}


def minimum_release(product):
    if product not in MODELS:
        raise ValueError('Unsupported product')
    return IOS5_MINIMUM.get(product, '6.0')


def target(product, release):
    if version(release) < version(minimum_release(product)):
        raise ValueError('Release predates the selected model support')
    return MODELS[product]


def tools():
    system = {'Darwin': 'macos', 'Linux': 'linux'}.get(platform.system())
    machine = {'aarch64': 'arm64', 'AMD64': 'x86_64'}.get(platform.machine(), platform.machine())
    if system is None:
        raise ValueError('Unsupported host platform')
    if machine not in ('arm64', 'x86_64'):
        raise ValueError('Unsupported host architecture: ' + machine)
    # macOS tools are universal binaries after the upstream layout change;
    # Linux keeps one directory per host architecture.
    path = KIT / 'bin' / system if system == 'macos' else KIT / 'bin' / system / machine
    if not path.is_dir():
        raise ValueError("Olsro's Legacy iOS Kit tools are missing: " + str(path))
    return path


_DIGEST_CACHE = {}


def _file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def digest(path, algorithm='sha256'):
    # Reuse only this process's verified reads. ctime catches same-size edits
    # even if a caller restores mtime. A new launch always hashes files again.
    path = Path(path)
    before = path.stat()
    key = (before.st_dev, before.st_ino, algorithm)
    stamp = _file_stamp(before)
    cached = _DIGEST_CACHE.get(key)
    if stat.S_ISREG(before.st_mode) and cached is not None and cached[0] == stamp:
        return cached[1]
    results = {algorithm: hashlib.new(algorithm)}
    # IPSWs need Apple's SHA-1 and our SHA-256 manifests. Compute both during
    # the first read instead of streaming the same multi-GiB archive twice.
    if algorithm == 'sha1':
        results['sha256'] = hashlib.sha256()
    with activity('Verifying file integrity',before.st_size) as update, path.open('rb') as stream:
        if _file_stamp(os.fstat(stream.fileno())) != stamp:
            raise ValueError('File changed before integrity verification: ' + str(path))
        done=0
        for chunk in iter(lambda: stream.read(4 * 1048576), b''):
            for result in results.values():
                result.update(chunk)
            done+=len(chunk);update(done)
        if (_file_stamp(os.fstat(stream.fileno())) != stamp or
                _file_stamp(path.stat()) != stamp):
            raise ValueError('File changed during integrity verification: ' + str(path))
    values = {name: result.hexdigest() for name, result in results.items()}
    if stat.S_ISREG(before.st_mode):
        for name, value in values.items():
            entry = (before.st_dev, before.st_ino, name)
            if entry not in _DIGEST_CACHE and len(_DIGEST_CACHE) >= 2048:
                _DIGEST_CACHE.pop(next(iter(_DIGEST_CACHE)))
            _DIGEST_CACHE[entry] = (stamp, value)
    return values[algorithm]


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


def tool_environment():
    """Resolve bundled Linux libraries before a subprocess changes directory."""
    env = os.environ.copy()
    if platform.system() == 'Linux':
        paths = [str((tools()/'lib').resolve())]
        existing = env.get('LD_LIBRARY_PATH')
        if existing:
            paths.extend(str(Path(path or '.').resolve()) for path in existing.split(':'))
        env['LD_LIBRARY_PATH'] = ':'.join(dict.fromkeys(paths))
    return env


def run(argv, log=None, patcher=False, timeout=180):
    descriptions={'dmg':'Extracting system image','hfsplus':'Preparing filesystem contents',
                  'cmake':'Preparing filesystem tools','xpwntool':'Packing boot component',
                  'iBoot32Patcher':'Preparing boot component','curl':'Obtaining required files'}
    with activity(descriptions.get(Path(str(argv[0])).name,'Running preparation tool')):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=timeout,
                                env=tool_environment())
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
