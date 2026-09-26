"""Readback checks for stock application services, not a boot qualification.

Matching these selected files and POSIX permissions does NOT establish that
HFS content protection, keybags, activation, or every application works.
"""
import hashlib
from pathlib import PurePosixPath
import stat


SYSTEM_DIRECTORIES = (
    '/Applications', '/Library', '/Library/Caches', '/Library/Ringtones',
    '/Library/Wallpaper', '/System',
)
DATA_DIRECTORIES = (
    'mobile', 'mobile/Library',
    'mobile/Library/Caches', 'mobile/Library/Preferences', 'tmp',
)
APP_DIRECTORIES = ('mobile/Applications', 'mobile/Containers')
STOCK_FILES = (
    '/usr/libexec/installd', '/usr/libexec/mobile_installation_proxy',
    '/sbin/launchd', '/usr/lib/dyld',
    '/System/Library/LaunchDaemons/com.apple.mobile.installd.plist',
)


def metadata(image, name, *, optional=False):
    path = PurePosixPath(name)
    records = [r for r in image.ls(str(path.parent)) if r['name'] == path.name]
    if not records and optional:
        return None
    if len(records) != 1:
        raise ValueError('Missing or ambiguous stock contract path: '+name)
    record = records[0]
    return record['mode'], record['uid'], record['gid']


def verify_directory_contract(stock, prepared, data_entries):
    """Common iOS 6/7/8 check, using each firmware's own app directory layout."""
    directories = {}
    for name in SYSTEM_DIRECTORIES:
        expected = metadata(stock, name)
        if not stat.S_ISDIR(expected[0]) or metadata(prepared, name) != expected:
            raise ValueError('Stock system directory metadata differs: '+name)
        directories[name] = list(expected)
    for name in (*DATA_DIRECTORIES, *APP_DIRECTORIES):
        path = '/private/var/'+name
        expected = metadata(stock, path, optional=name in APP_DIRECTORIES)
        if expected is None:
            continue
        item = data_entries.get(name)
        if (not stat.S_ISDIR(expected[0]) or item is None or not item[0].isdir()
                or (item[0].mode, item[0].uid, item[0].gid) !=
                   (stat.S_IMODE(expected[0]), expected[1], expected[2])):
            raise ValueError('Stock Data directory metadata differs: '+path)
        directories[path] = list(expected)
    return directories


def verify_ios6_contract(stock, prepared, data_entries, cache_arch):
    """Reject unintended changes to selected Apple files and directory access."""
    if cache_arch not in ('armv7', 'armv7s'):
        raise ValueError('Unexpected iOS 6 shared cache architecture')
    directories = verify_directory_contract(stock, prepared, data_entries)
    files = {}
    cache = '/System/Library/Caches/com.apple.dyld/dyld_shared_cache_'+cache_arch
    for name in (*STOCK_FILES, cache):
        expected = metadata(stock, name)
        if not stat.S_ISREG(expected[0]) or metadata(prepared, name) != expected:
            raise ValueError('Stock application service metadata differs: '+name)
        content = stock.read(name)
        if prepared.read(name) != content:
            raise ValueError('Stock application service content differs: '+name)
        files[name] = hashlib.sha256(content).hexdigest()
    return dict(directories=directories, files=files,
                content_protection_verified=False,
                application_runtime_verified=False)
