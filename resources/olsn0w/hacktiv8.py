import argparse
import copy
import hashlib
from pathlib import Path
import plistlib
import shutil
import stat
import tempfile
import zipfile

from common import KIT, profile, run, tools, version
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
HELPER_SHA256 = '7a428f02fe6ad4febbe7d28de559db38a91b0d42e34d240d943a53f05765087b'

# Shared by IPSW preparation, olsn0w and the live-device utility. Only this
# exact 3GS/4S 9B206 executable may use the historic patch's fixed offset.
LOCKDOWN_511_ORIGINAL = 'bac1d37df1587685787aab68e97f561af711566fa950caa29d0e8eb529977710'
LOCKDOWN_511_PATCHED = 'd278d52d4f461d46a7e91d6fae4902a2db5fc184f57842e78446a94dba1d9e4f'

# ARMv7s schedules the STRB before ADD R1, PC, unlike the generic pattern.
# The exact 10B350 image still reads ShouldHactivate immediately before
# MOV R2, R0 at 0x1aeae. Pin the complete input and ad-hoc rehashed output.
LOCKDOWN_614_ORIGINAL = '74a854a2195794093af4e95f1a89eea37b6ad8a9a6047db4cf75c9e9504610eb'
LOCKDOWN_614_PATCHED = '8f5e9bb90d6c670bf95b04665fe3dec89aaf695be607674c84eface4529b8434'

# Byte-for-byte reproduction of Down_iPhone2,1_4.3.5_8L1.bundle/lockdownd.patch.
# Match the entire executable, not a model name or an assumed instruction offset.
# The historical recipe also changes LC_UUID and CoreLocation's linked version.
LOCKDOWN_435_ORIGINAL = 'c4988d95fa560f2711fc553659d40254a2eb17b8694e9bc6f9f0a04706ec1635'
LOCKDOWN_435_PATCHED = '2ab13d63d380d5fdcc44f859318ce9a4bde163e03365c93f3ce1ab8fe3fa83ce'
LOCKDOWN_435_EDITS = (
    (0x570, bytes.fromhex('1c7f2b41744c35dc92f679e90a73e240'),
     bytes.fromhex('198056d75a8038c8ba5013c52760e06b')),
    (0x951, b'\x1d', b'\x1b'),
    (0xbb0e, bytes.fromhex('07f0d1fd'), bytes.fromhex('7de20000')),
)

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
    (
        # ARMv7s uses the same boolean result/store but schedules STRB before
        # ADD R1, PC. Keep both complete patterns instead of firmware offsets.
        [
            0x01, 0x46, None, None, None, None, None, None, None, None,
            None, 0x73, 0x78, 0x44, None, None, None, None, 0x02, 0x46,
            None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, 0x78, 0x44, None, 0x73,
            0x79, 0x44,
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
    checksum = hashlib.sha256(data).hexdigest()
    if checksum == LOCKDOWN_435_PATCHED:
        verify(data)
        return bytes(data), 0xbb0e, False
    if checksum == LOCKDOWN_435_ORIGINAL:
        changed = bytearray(data)
        for offset, original, replacement in LOCKDOWN_435_EDITS:
            if changed[offset:offset+len(original)] != original:
                raise ValueError('Unexpected 4.3.5 lockdownd bytes')
            changed[offset:offset+len(original)] = replacement
        result = rehash_adhoc(data, changed)
        if hashlib.sha256(result).hexdigest() != LOCKDOWN_435_PATCHED:
            raise ValueError('Legacy 4.3.5 patch does not match the qualified result')
        return result, 0xbb0e, True
    if product in ('iPhone2,1', 'iPhone4,1') and build == '9B206':
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
    if product in ('iPhone5,1', 'iPhone5,2') and build == '10B350':
        if checksum == LOCKDOWN_614_PATCHED:
            verify(data)
            return bytes(data), 0x1aeae, False
        if checksum == LOCKDOWN_614_ORIGINAL:
            changed = bytearray(data)
            if changed[0x1aeae:0x1aeb0] != bytes.fromhex('0246'):
                raise ValueError('Unexpected 6.1.4 lockdownd instruction')
            changed[0x1aeae:0x1aeb0] = bytes.fromhex('0122')
            result = rehash_adhoc(data, changed)
            if hashlib.sha256(result).hexdigest() != LOCKDOWN_614_PATCHED:
                raise ValueError('Legacy 6.1.4 patch does not match the qualified result')
            return result, 0x1aeae, True
    original = bytes(data)
    data = bytearray(data)
    candidates = []
    for signature, replacements in LOCKDOWN_PATCHES:
        for already, pattern in ((False, signature),
                                 (True, _patched_signature(signature, replacements))):
            candidates.extend((start, replacements, already) for start in _find(data, pattern))
    if len(candidates) > 1:
        raise ValueError('Ambiguous Hacktiv8 lockdownd signature')
    if candidates:
        start, replacements, already = candidates[0]
        offset = start+replacements[0][0]
        signed = sign or original[:4] == b'\xce\xfa\xed\xfe'
        if already:
            if signed:
                verify(original)
            return original, offset, False
        for relative, replacement in replacements:
            data[start+relative:start+relative+len(replacement)] = replacement
        # Image preparation and live patching must both retain valid signed
        # pages; this cannot depend on which entry point invokes the recipe.
        result = rehash_adhoc(original, data) if signed else bytes(data)
        return result, offset, True
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


def requires_cellular_disable(release, product):
    """The upstream jailbroken iOS 8 recipe also disables CommCenter."""
    if version(release)[0] != 8:
        return False
    if product.startswith('iPhone'):
        return True
    if product.startswith('iPod'):
        return False
    return profile(product)['has_baseband']


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
    cellular = ('/bin/launchctl disable system/com.apple.CommCenter || exit 1\n'
                if report.get('cellular_service_disabled') is True else '')
    ready_exit = '[ -e "$marker" ] && exit 0' if cellular else 'exit 0'
    script = f'''#!/bin/sh
marker=/var/lib/hacktiv8/mobilegestalt-ready
target={target}
{cellular}if "{FIRSTBOOT_HELPER}" --check "$target"; then
    {ready_exit}
fi
i=0
while ! {wait} && [ "$i" -lt 180 ]; do
    /bin/sleep 2
    i=$((i+1))
done
{wait} || exit 1
/bin/mkdir -p /var/lib/hacktiv8 || exit 1
attempts=$(/bin/cat "$marker.attempts" 2>/dev/null || true)
case "$attempts" in ''|0) attempts=0;; 1) attempts=1;; *)
    echo 'Hacktiv8 cache did not persist after two restart attempts' >&2
    exit 1;;
esac
{command} || exit 1
"{FIRSTBOOT_HELPER}" --check "$target" || exit 1
printf '%s\n' "$((attempts+1))" > "$marker.attempts" || exit 1
: > "$marker"
/bin/sync
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


def _require_setup(image, release):
    matches = [item for item in image.ls('/Applications')
               if item['name'] == 'Setup.app']
    # Stock iOS 4 has no on-device Setup Assistant. Do not require a directory
    # that never existed; still reject malformed entries and missing iOS 5+ Setup.
    if not matches and version(release) < (5,):
        return
    if len(matches) != 1 or not stat.S_ISDIR(matches[0]['mode']):
        raise ValueError('Hacktiv8 requires Setup.app to be preserved')


def preflight(image, release, product, build):
    """Check the selected recipe and assets without changing the stock image."""
    _identity(image, release, build)
    method = technique(release, product, build)
    if method is None:
        return
    _require_setup(image, release)
    if method == 'lockdownd-patch':
        patch_lockdownd(image.read(LOCKDOWN), product, build)
    else:
        firstboot_files(_report(method, _gestalt_target(release), b'', b'',
                                deferred=True, product=product, build=build,
                                cellular_service_disabled=requires_cellular_disable(release, product)))


def install(image, release, product, build=None):
    _identity(image, release, build)
    method = technique(release, product, build)
    if method is None:
        remove_setup_application(image, required=False)
        return None
    _require_setup(image, release)
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
                         product=product, build=build,
                         cellular_service_disabled=requires_cellular_disable(release, product))
    else:
        report = _report(method, target, b'', b'', deferred=True,
                         cellular_service_disabled=requires_cellular_disable(release, product))
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
                           deferred=True,
                           cellular_service_disabled=requires_cellular_disable(release, product))
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
    return _report(method, '/private/var/'+target, original, patched, deferred=True,
                   product=product, build=build,
                   cellular_service_disabled=requires_cellular_disable(release, product))


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
    _require_setup(image, release)
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
            print(('Hacktiv8 applied; Setup.app left unchanged.' if report else
                   'Setup.app removed; Hacktiv8 unavailable for this device/build.'))
        else:
            parser.error('Expected --check or --ipsw with --build')
    except (ValueError, OSError, RuntimeError) as error:
        parser.exit(1, str(error)+'\n')


if __name__ == '__main__':
    main()
