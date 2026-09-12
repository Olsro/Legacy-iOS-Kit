"""Apply narrowly qualified target-kernel fixes and verify their containers."""
import hashlib
from pathlib import Path

from common import digest, run, tools
from img3 import img3


# p101 iOS 6.1.3 retries the TriStar System-ID IPC after a controller reset,
# but this hardware can return kIOReturnBadMessageID a second time.  Apple's
# function already contains a failure fallback which publishes 0xffff and
# continues.  The stock instruction branches over that fallback regardless of
# the retry result; CBZ retains the stock success path and enters Apple's own
# fallback only when the retry still failed.
PATCHES = {
    ('iPad3,4', '6.1.3', '10B329'): dict(
        name='tristar-system-id-retry-fallback',
        raw_sha256='5471d5d55c582ecd8a3e14314cbb1744a416422ecfa1a736ac14d3dca7861dbe',
        patched_sha256='8e481c2e013f547110382cdaaf3e0cdb24fff9de5af8c64612741c816ad8bf4d',
        offset=0x9ec17e,
        virtual_address=0x80a2d17e,
        before='10e0',                 # b   0x80a2d1a2
        after='86b1',                  # cbz r6, 0x80a2d1a2
        validation='physical-boot-reboot-activation-wifi-cydia',
    ),
}


def qualified_patch(source):
    """Return a fix only for the exact firmware identity proven on hardware."""
    return PATCHES.get((source['product'], source['version'], source['build']))


def apply(data, patch):
    """Apply one exact byte change after checking the complete raw kernel."""
    original_hash = hashlib.sha256(data).hexdigest()
    if original_hash != patch['raw_sha256']:
        raise ValueError('Qualified target kernel differs')
    before, after = bytes.fromhex(patch['before']), bytes.fromhex(patch['after'])
    offset = patch['offset']
    if len(before) != len(after) or data[offset:offset+len(before)] != before:
        raise ValueError('Qualified target kernel patch site differs')
    result = data[:offset] + after + data[offset+len(before):]
    patched_hash = hashlib.sha256(result).hexdigest()
    if patched_hash != patch['patched_sha256']:
        raise ValueError('Patched target kernel digest differs')
    report = {key: patch[key] for key in (
        'name', 'offset', 'virtual_address', 'before', 'after', 'validation')}
    report.update(raw_sha256=original_hash, patched_sha256=patched_hash)
    return result, report


def prepare(source, firmware, destination):
    """Pack and read back the selected fix, or retain the stock container."""
    firmware, destination = Path(firmware), Path(destination)
    patch = qualified_patch(source)
    if patch is None:
        return firmware/'Kernelcache.img3', None
    raw, report = apply((firmware/'Kernelcache.raw').read_bytes(), patch)
    patched_raw = destination.with_suffix('.raw')
    readback = destination.with_suffix('.readback.raw')
    try:
        patched_raw.write_bytes(raw)
        run([tools()/'xpwntool', patched_raw, destination,
             '-t', firmware/'Kernelcache.img3'], destination.with_suffix('.pack.log'))
        kind, tags, _ = img3(destination.read_bytes())
        if kind != 'krnl' or 'KBAG' in tags:
            raise ValueError('Patched target kernel container is not bootable')
        run([tools()/'xpwntool', destination, readback],
            destination.with_suffix('.readback.log'))
        if readback.read_bytes() != raw:
            raise ValueError('Patched target kernel container readback differs')
        report['container_sha256'] = digest(destination)
        return destination, report
    finally:
        for path in (patched_raw, readback):
            if path.exists():
                path.unlink()
