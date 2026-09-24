import argparse
import copy
import hashlib
from pathlib import Path
import plistlib
import shutil
import stat
import tempfile
import zipfile

from common import KIT, run, tools, version
from hfs import HFS
from signing import rehash_adhoc, verify


HACKTIV8 = KIT / 'resources/hacktiv8'
LOCKDOWN = '/usr/libexec/lockdownd'
LOCKDOWN_BACKUP = LOCKDOWN + '.hacktiv8-original'
SETUP = '/Applications/Setup.app'
GESTALT_KEY = 'a6vjPkzcRjrsXmniFsm0dg'
GESTALT_OLD = '/private/var/mobile/Library/Caches/com.apple.MobileGestalt.plist'
GESTALT_NEW = ('/private/var/containers/Shared/SystemGroup/'
               'systemgroup.com.apple.mobilegestaltcache/Library/Caches/'
               'com.apple.MobileGestalt.plist')
FIRSTBOOT_SCRIPT = '/usr/local/libexec/hacktiv8-mobilegestalt.sh'
FIRSTBOOT_JOB = '/Library/LaunchDaemons/org.legacyioskit.hacktiv8.plist'
FIRSTBOOT_HELPER = '/usr/local/libexec/hacktiv8-mobilegestalt'
FIRSTBOOT_PROFILE = '/usr/local/share/hacktiv8-mobilegestalt.plist'
HELPER_ASSET = Path(__file__).parent / 'target/hacktiv8-mobilegestalt'
HELPER_SHA256 = 'c4a693b6610c176319a1e1e126cad1df0806893cb628fc52adfd556c9150befe'

# Shared by IPSW preparation, olsn0w and the live-device utility. Only this
# exact 4S/9B206 executable may use the historic patch's fixed offset.
LOCKDOWN_511_ORIGINAL = 'bac1d37df1587685787aab68e97f561af711566fa950caa29d0e8eb529977710'
LOCKDOWN_511_PATCHED = 'd278d52d4f461d46a7e91d6fae4902a2db5fc184f57842e78446a94dba1d9e4f'

LOCKDOWN_PATCHES = (
    (
        [
            0x01, 0x46, None, None, None, None, None, None, None, None,
            None, 0x73, 0x78, 0x44, None, None, None, None, 0x02, 0x46,
            None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, 0x78, 0x44, 0x79, 0x44,
            None, 0x73,
        ],
        [(18, b'\x01\x22')],
    ),
)


def _find(data, signature):
    fixed = [(offset, value) for offset, value in enumerate(signature)
             if value is not None]
    anchor_offset, anchor = fixed[0]
    matches = []
    position = data.find(bytes([anchor]))
    while position != -1:
        start = position-anchor_offset
        if (start >= 0 and start+len(signature) <= len(data) and
                all(data[start+offset] == value for offset, value in fixed)):
            matches.append(start)
        position = data.find(bytes([anchor]), position+1)
    return matches


def _patched_signature(signature, replacements):
    result = list(signature)
    for offset, replacement in replacements:
        result[offset:offset+len(replacement)] = replacement
    return result


def patch_lockdownd(data, product=None, build=None, *, sign=False):
    if (product, build) == ('iPhone4,1', '9B206'):
        checksum = hashlib.sha256(data).hexdigest()
        if checksum == LOCKDOWN_511_PATCHED:
            verify(data)
            return bytes(data), 0xb932, False
        if checksum == LOCKDOWN_511_ORIGINAL:
            changed = bytearray(data)
            if changed[0xb932:0xb936] != bytes.fromhex('fff733fe'):
                raise ValueError('Unexpected 5.1.1 lockdownd instruction')
            changed[0xb932:0xb936] = bytes.fromhex('01200120')
            result = rehash_adhoc(data, changed)
            if hashlib.sha256(result).hexdigest() != LOCKDOWN_511_PATCHED:
                raise ValueError('Legacy 5.1.1 patch does not match the qualified result')
            return result, 0xb932, True
    original = bytes(data)
    data = bytearray(data)
    for signature, replacements in LOCKDOWN_PATCHES:
        matches = _find(data, _patched_signature(signature, replacements))
        if matches:
            if sign:
                verify(data)
            return bytes(data), matches[0], False
    for signature, replacements in LOCKDOWN_PATCHES:
        matches = _find(data, signature)
        if len(matches) > 1:
            raise ValueError('Ambiguous Hacktiv8 lockdownd signature')
        if matches:
            for offset, replacement in replacements:
                start = matches[0]+offset
                data[start:start+len(replacement)] = replacement
            result = rehash_adhoc(original, data) if sign else bytes(data)
            return result, matches[0]+replacements[0][0], True
    raise ValueError('Hacktiv8 does not recognize this lockdownd')


def profile_path(product, build):
    path = HACKTIV8 / 'plists' / product / build / 'patched.plist'
    return path if path.is_file() else None


def technique(release, product, build=None):
    selected = version(release)
    if (4,) <= selected < (7,):
        return 'lockdownd-patch'
    if build and (8,) <= selected <= (10, 3, 4) and profile_path(product, build):
        return 'mobilegestalt-profile'
    if (7,) <= selected <= (8, 4, 1):
        return 'mobilegestalt-flag'
    return None


def available(release, product, build=None):
    return technique(release, product, build) is not None


def remove_setup_application(image, required=True):
    matches = [item for item in image.ls('/Applications')
               if item['name'] == 'Setup.app']
    if ((required and not matches) or
            (matches and (len(matches) != 1 or
                          not stat.S_ISDIR(matches[0]['mode'])))):
        raise ValueError('Expected the stock Setup.app directory')
    if matches:
        image.command('rmall', SETUP)
    if any(item['name'] == 'Setup.app' for item in image.ls('/Applications')):
        raise ValueError('Setup.app removal readback failed')


def _profile(product, build):
    path = profile_path(product, build)
    if path is None:
        raise ValueError('Hacktiv8 has no profile for '+product+' / '+build)
    data = path.read_bytes()
    value = plistlib.loads(data)
    if (not isinstance(value, dict) or
            not isinstance(value.get('CacheExtra'), dict) or
            value['CacheExtra'].get(GESTALT_KEY) is not True):
        raise ValueError('Invalid Hacktiv8 MobileGestalt profile')
    return data


def _patch_gestalt(data):
    value = plistlib.loads(data)
    if not isinstance(value, dict) or not isinstance(value.get('CacheExtra'), dict):
        raise ValueError('Invalid stock MobileGestalt cache')
    value['CacheExtra'][GESTALT_KEY] = True
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)


def _gestalt_target(release):
    return GESTALT_NEW if version(release) >= (10, 3) else GESTALT_OLD


def _report(method, target, original, patched, *, offset=None, deferred=False,
            **details):
    result = dict(method=method, target=target,
                  original_sha256=hashlib.sha256(original).hexdigest(),
                  sha256=hashlib.sha256(patched).hexdigest())
    if offset is not None:
        result['patch_offset'] = offset
    if deferred:
        result['deferred'] = True
    result.update(details)
    return result


def firstboot_files(report):
    if not isinstance(report, dict) or report.get('deferred') is not True:
        return {}
    target = report['target']
    helper = HELPER_ASSET.read_bytes()
    if hashlib.sha256(helper).hexdigest() != HELPER_SHA256:
        raise ValueError('Hacktiv8 MobileGestalt helper checksum mismatch')
    method = report.get('method')
    if method == 'mobilegestalt-profile':
        profile = _profile(report.get('product'), report.get('build'))
        wait = f'[ -d "{Path(target).parent}" ]'
        command = f'"{FIRSTBOOT_HELPER}" "$target" "{FIRSTBOOT_PROFILE}"'
    elif method == 'mobilegestalt-flag':
        profile = None
        wait = '[ -s "$target" ]'
        command = f'"{FIRSTBOOT_HELPER}" "$target"'
    else:
        raise ValueError('Invalid deferred Hacktiv8 method')
    script = f'''#!/bin/sh
marker=/var/lib/hacktiv8/mobilegestalt-ready
target={target}
[ -e "$marker" ] && exit 0
i=0
while ! {wait} && [ "$i" -lt 180 ]; do
    /bin/sleep 2
    i=$((i+1))
done
{wait} || exit 1
{command} || exit 1
/bin/mkdir -p /var/lib/hacktiv8
: > "$marker"
/sbin/reboot
'''.encode()
    job = plistlib.dumps({
        'Label': 'org.legacyioskit.hacktiv8',
        'ProgramArguments': ['/bin/sh', FIRSTBOOT_SCRIPT],
        'KeepAlive': {'SuccessfulExit': False},
        'RunAtLoad': True,
    })
    files = {FIRSTBOOT_SCRIPT: (script, 0o755),
             FIRSTBOOT_JOB: (job, 0o644),
             FIRSTBOOT_HELPER: (helper, 0o755)}
    if profile is not None:
        files[FIRSTBOOT_PROFILE] = (profile, 0o644)
    return files


def _install_firstboot(image, report):
    for path, (data, mode) in firstboot_files(report).items():
        image.add(path, data, mode=mode)


def _identity(image, release, build):
    value = plistlib.loads(
        image.read('/System/Library/CoreServices/SystemVersion.plist'))
    if (version(value['ProductVersion']) != version(release) or
            (build is not None and value['ProductBuildVersion'] != build)):
        raise ValueError('Hacktiv8 target filesystem differs from the selected release')


def _require_setup(image):
    matches = [item for item in image.ls('/Applications')
               if item['name'] == 'Setup.app']
    if len(matches) != 1 or not stat.S_ISDIR(matches[0]['mode']):
        raise ValueError('Hacktiv8 requires Setup.app to be preserved')


def install(image, release, product, build=None):
    _identity(image, release, build)
    method = technique(release, product, build)
    if method is None:
        remove_setup_application(image, required=False)
        return None
    _require_setup(image)
    if method == 'lockdownd-patch':
        entries = {item['name']: item for item in image.ls('/usr/libexec')}
        if 'lockdownd' not in entries or not stat.S_ISREG(entries['lockdownd']['mode']):
            raise ValueError('Expected a regular stock lockdownd')
        current = image.read(LOCKDOWN)
        backup_name = Path(LOCKDOWN_BACKUP).name
        if backup_name in entries:
            original = image.read(LOCKDOWN_BACKUP)
            patched, offset, _ = patch_lockdownd(original, product, build)
            if current != patched:
                raise ValueError('Existing Hacktiv8 lockdownd backup conflicts with target')
        else:
            original = current
            patched, offset, changed = patch_lockdownd(original, product, build)
            if not changed:
                raise ValueError('Patched lockdownd has no original Hacktiv8 backup')
            image.add(LOCKDOWN_BACKUP, original, mode=0o755)
            image.add(LOCKDOWN, patched, mode=0o755)
        return _report(method, LOCKDOWN, original, patched, offset=offset)
    target = _gestalt_target(release)
    if method == 'mobilegestalt-profile':
        patched = _profile(product, build)
        report = _report(method, target, b'', patched, deferred=True,
                         product=product, build=build)
    else:
        report = _report(method, target, b'', b'', deferred=True)
    _install_firstboot(image, report)
    return report


def prepare_data(entries, release, product, build):
    method = technique(release, product, build)
    if method not in ('mobilegestalt-profile', 'mobilegestalt-flag'):
        return None
    target = _gestalt_target(release)[len('/private/var/'):]
    current = entries.get(target)
    original = current[1] if current and current[1] is not None else b''
    if method == 'mobilegestalt-profile':
        patched = _profile(product, build)
    else:
        if not original:
            return _report(method, '/private/var/'+target, b'', b'',
                           deferred=True)
        patched = _patch_gestalt(original)
    mobile = entries.get('mobile')
    if mobile is None or not mobile[0].isdir():
        raise ValueError('Hacktiv8 requires the stock mobile Data directory')
    item = copy.copy(current[0]) if current else copy.copy(mobile[0])
    item.name = target
    item.type = b'0'
    item.mode = 0o644
    item.size = len(patched)
    entries[target] = item, patched
    return _report(method, '/private/var/'+target, original, patched)


def verify_installed(image, report, release, product):
    setup_present = any(item['name'] == 'Setup.app' and
                        stat.S_ISDIR(item['mode'])
                        for item in image.ls('/Applications'))
    if report is None:
        if setup_present:
            raise ValueError('Setup.app is still present')
        return
    method = report.get('method') if isinstance(report, dict) else None
    if method not in ('lockdownd-patch', 'mobilegestalt-profile',
                      'mobilegestalt-flag'):
        raise ValueError('Invalid Hacktiv8 report')
    if not setup_present:
        raise ValueError('Hacktiv8 requires Setup.app to be preserved')
    if method == 'lockdownd-patch':
        current = image.read(LOCKDOWN)
        original = image.read(LOCKDOWN_BACKUP)
        build = plistlib.loads(image.read(
            '/System/Library/CoreServices/SystemVersion.plist'))['ProductBuildVersion']
        patched, offset, _ = patch_lockdownd(original, product, build)
        if (current != patched or
                hashlib.sha256(current).hexdigest() != report.get('sha256') or
                hashlib.sha256(original).hexdigest() != report.get('original_sha256') or
                offset != report.get('patch_offset')):
            raise ValueError('Hacktiv8 lockdownd readback mismatch')
        entries = {item['name']: item for item in image.ls('/usr/libexec')}
        for path in (LOCKDOWN, LOCKDOWN_BACKUP):
            item = entries[Path(path).name]
            if (item['mode'], item['uid'], item['gid']) != (stat.S_IFREG | 0o755, 0, 0):
                raise ValueError('Hacktiv8 lockdownd metadata mismatch')
    elif report.get('deferred') is True:
        for path, (data, mode) in firstboot_files(report).items():
            if image.read(path) != data:
                raise ValueError('Hacktiv8 first-boot payload readback mismatch')
            parent = str(Path(path).parent)
            item = next(item for item in image.ls(parent)
                        if item['name'] == Path(path).name)
            if stat.S_IMODE(item['mode']) != mode:
                raise ValueError('Hacktiv8 first-boot payload mode mismatch')


def activation_skipped(report):
    removed = report.get('setup_app_removed')
    applied = report.get('hacktiv8') is not None
    if type(removed) is not bool or (removed and applied):
        raise ValueError('Invalid Setup.app/Hacktiv8 policy')
    mode = report.get('activation_mode')
    if ((mode == 'skipped-setup-removed') != removed or
            (mode == 'skipped-hacktiv8') != applied):
        raise ValueError('Restore activation and Setup.app/Hacktiv8 policies differ')
    return removed or applied


def rootfs_path(archive):
    names = archive.namelist()
    if len(names) != len(set(names)):
        raise ValueError('Duplicate IPSW entries')
    if 'Restore.plist' in names:
        restore = plistlib.loads(archive.read('Restore.plist'))
        root = restore.get('SystemRestoreImages', {}).get('User')
        if isinstance(root, str) and root in names:
            return root
    if 'BuildManifest.plist' in names:
        manifest = plistlib.loads(archive.read('BuildManifest.plist'))
        paths = {item['Manifest']['OS']['Info']['Path']
                 for item in manifest['BuildIdentities'] if 'OS' in item['Manifest']}
        if len(paths) == 1 and next(iter(paths)) in names:
            return next(iter(paths))
    raise ValueError('Cannot identify the target root filesystem in the custom IPSW')


def patch_ipsw(path, release, product, build):
    path = Path(path).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='hacktiv8-', dir=path.parent) as folder:
        folder = Path(folder)
        raw, packed, output = folder/'root.hfs', folder/'root.dmg', folder/'custom.ipsw'
        with zipfile.ZipFile(path) as source:
            root = rootfs_path(source)
            with source.open(root) as source_stream, packed.open('wb') as output_stream:
                shutil.copyfileobj(source_stream, output_stream, 4*1024**2)
            run([tools()/'dmg', 'extract', packed, raw], timeout=1800)
            report = install(HFS(raw), release, product, build)
            packed.unlink()
            run([tools()/'dmg', 'build', raw, packed], timeout=1800)
            with zipfile.ZipFile(output, 'w', allowZip64=True) as target:
                target.comment = source.comment
                for item in source.infolist():
                    metadata = copy.copy(item)
                    if item.filename == root:
                        metadata.file_size = packed.stat().st_size
                        metadata.compress_type = zipfile.ZIP_STORED
                    with (packed.open('rb') if item.filename == root
                          else source.open(item)) as source_stream:
                        with target.open(metadata, 'w', force_zip64=True) as output_stream:
                            shutil.copyfileobj(source_stream, output_stream, 4*1024**2)
        run([tools()/'dmg', 'extract', packed, folder/'readback.hfs'], timeout=1800)
        verify_installed(HFS(folder/'readback.hfs'), report, release, product)
        with zipfile.ZipFile(output) as check:
            bad = check.testzip()
            if bad:
                raise ValueError('Custom IPSW verification failed: '+bad)
        output.replace(path)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--product', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--build')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--ipsw', type=Path)
    args = parser.parse_args()
    try:
        if args.check:
            selected = technique(args.version, args.product, args.build)
            if selected is None:
                raise ValueError('Hacktiv8 does not support this device/build')
            print(selected)
        elif args.ipsw and args.build:
            report = patch_ipsw(args.ipsw, args.version, args.product, args.build)
            print(('Hacktiv8 applied; Setup.app preserved.' if report else
                   'Setup.app removed; Hacktiv8 unavailable for this device/build.'))
        else:
            parser.error('Expected --check or --ipsw with --build')
    except (ValueError, OSError, RuntimeError) as error:
        parser.exit(1, str(error)+'\n')


if __name__ == '__main__':
    main()
