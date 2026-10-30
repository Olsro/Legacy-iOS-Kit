"""Read the qualified iOS payload from a pinned upstream release as inert data."""
import hashlib
import json
from pathlib import Path
import struct

from common import STATE, digest
from firmware import fetch
from signing import verify, resign

RELEASE = '2.1.1'
URL = 'https://github.com/staturnzz/aquila/releases/download/' + RELEASE + '/aquila.exe'
ARCHIVE_SHA256 = '42a50f5e1ec40e547d2013ad9f7e7af9fe3381fce7ba8672e7360e59929a2290'
IOS7_SHA256 = 'a10c700b7f0ff38121326c65be4543162459dec8fb8e2f90a6602a0383e25f49'
IOS7_SIZE = 91056
IOS6_SHA256 = '5b358f7edc80a49fd9b13322a239e63af6c39d763e6e29670b063c1fa6193a86'
PANGU71_FAT_SHA256 = 'f010e13d4153dad7021ab106da055e54757ad704f3b1326e3a42cc58dbec8e64'
PANGU71_ARMV7_SHA256 = '69eddb2ba7dbd83aae4d41f3face8f526befddb1c29ce2eaede01dff86c007ea'


def armv7_slice(data):
    """Select one checked ARMv7 slice from a universal Mach-O payload."""
    if len(data) < 8 or data[:4] != bytes.fromhex('cafebabe'):
        raise ValueError('Expected a universal Mach-O payload')
    count = struct.unpack_from('>I', data, 4)[0]
    if not 0 < count <= 8 or 8 + count*20 > len(data):
        raise ValueError('Invalid universal Mach-O header')
    matches = []
    for index in range(count):
        cpu, subtype, offset, size, alignment = struct.unpack_from(
            '>IIIII', data, 8 + index*20)
        if offset + size > len(data) or alignment > 30 or offset % (1 << alignment):
            raise ValueError('Invalid universal Mach-O slice')
        if cpu == 12 and subtype & 0xffffff == 9:
            matches.append(data[offset:offset + size])
    if len(matches)!=1:
        raise ValueError('Missing or ambiguous ARMv7 payload slice')
    return matches[0]


def job_loader():
    """Check the shipped ARM helper against its source/build provenance."""
    root = Path(__file__).parent
    report = json.loads((root/'target/load-jobs.json').read_text())
    expected = {'native/target/load_jobs.c', 'native/target/build.sh',
                'target/load-jobs', 'target/launchctl.sh'}
    if set(report['files']) != expected:
        raise ValueError('Unexpected job-loader provenance')
    for name, checksum in report['files'].items():
        if digest(root/name) != checksum:
            raise ValueError('Job-loader source or executable checksum mismatch: '+name)
    helper = (root/'target/load-jobs').read_bytes()
    verify(helper)
    return helper, (root/'target/launchctl.sh').read_bytes()


def prepare_payload(original, root_device, output):
    """Retarget the pinned payload without replacing the stock launchctl."""
    if hashlib.sha256(original).hexdigest() != IOS7_SHA256:
        raise ValueError('Unqualified Aquila payload')
    signature = verify(original)
    edits = [(b'/dev/disk0s1s1\0', root_device.encode('ascii')+b'\0'),
             (b'/bin/launchctl\0', b'/olsn0w/lctl\0')]
    data = original
    for before, after in edits:
        if data.count(before) != 1 or len(after) > len(before):
            raise ValueError('Unrecognized Aquila path or oversized replacement')
        data = data.replace(before, after.ljust(len(before), b'\0'))
    output = Path(output)
    output.write_bytes(data)
    return resign(output, signature['entitlements'])


EARLY_JOBS = '/olsn0w/early-jobs'


def prepare_ios6_payload(original, root_device, output, defer_library_jobs=False):
    """Retarget the Kit's native iOS 6 Aquila payload to the new root.

    The iOS 6 package has its own kernel recipe and deliberately keeps the
    stock /bin/launchctl contract.  Replacing it with the iOS 7 component or
    routing it through the later guarded loader regresses A6/A6X boot.
    Aquila loads /Library/LaunchDaemons from launchd.conf, before notifyd and
    backboardd exist. When deferred, it loads only the Kit's early jobs and a
    late system job loads package daemons after GraphicsServices is ready.
    """
    if hashlib.sha256(original).hexdigest() != IOS6_SHA256:
        raise ValueError('Unqualified iOS 6 Aquila payload')
    signature = verify(original)
    before = b'/dev/disk0s1s1\0'
    after = root_device.encode('ascii') + b'\0'
    if original.count(before) != 1 or len(after) > len(before):
        raise ValueError('Unrecognized iOS 6 Aquila root or oversized replacement')
    if original.count(b'/bin/launchctl\0') != 1:
        raise ValueError('Unrecognized iOS 6 Aquila launchctl contract')
    data = original.replace(before, after.ljust(len(before), b'\0'))
    if defer_library_jobs:
        for before, after in [(b'/Library/LaunchDaemons\0', EARLY_JOBS.encode()+b'\0'),
                              (b'/Library/LaunchDaemons/%s\0', EARLY_JOBS.encode()+b'/%s\0')]:
            if data.count(before) != 1 or len(after) > len(before):
                raise ValueError('Unrecognized iOS 6 Aquila job directory')
            data = data.replace(before, after.ljust(len(before), b'\0'))
    output = Path(output)
    output.write_bytes(data)
    return resign(output, signature['entitlements'])


def prepare_ios8_payload(original, root_device, output):
    """Retarget EverUntether to the physically qualified iOS 8 loader path."""
    if hashlib.sha256(original).hexdigest() != '7f602f8e8e96fd6cbe2d313187ccade85de253ab1db21696ba7402c12ef8495c':
        raise ValueError('Unqualified EverUntether payload')
    signature=verify(original);data=original
    edits = [(b'/dev/disk0s1s1\0', root_device.encode('ascii')+b'\0'),
             (b'/bin/launchctl\0', b'/olsn0w/lctl\0')]
    for before, after in edits:
        if data.count(before)!=1 or len(after)>len(before):
            raise ValueError('Unrecognized EverUntether path or oversized replacement')
        data=data.replace(before,after.ljust(len(before),b'\0'))
    # These are the two instructions qualified on the iPhone5,2: sleep for
    # sixty seconds after spawning the loader, then repeat that sleep instead
    # of exiting and letting launchd tear down the loader process group.
    retained = [(0xae0c-0x4000, bytes.fromhex('42f2107003f000ee'),
                 bytes.fromhex('40f23c0003f0c8ed')),
                (0xae14-0x4000, bytes.fromhex('12b0'), bytes.fromhex('fae7'))]
    data=bytearray(data)
    for offset, before, after in retained:
        if data[offset:offset+len(before)] != before:
            raise ValueError('Unrecognized EverUntether parent-lifetime instruction')
        data[offset:offset+len(before)] = after
    Path(output).write_bytes(data)
    return resign(Path(output),signature['entitlements'])


def prepare_pangu71_payload(original, root_device, output):
    """Retarget the Kit's established iOS 7.1 untether to the selected root."""
    if hashlib.sha256(original).hexdigest()!=PANGU71_FAT_SHA256:
        raise ValueError('Unqualified Pangu 7.1 payload')
    data = armv7_slice(original)
    if hashlib.sha256(data).hexdigest()!=PANGU71_ARMV7_SHA256:
        raise ValueError('Unqualified Pangu ARMv7 payload')
    signature = verify(data)
    edits = [(b'/dev/disk0s1s1\0', root_device.encode('ascii')+b'\0'),
             # Pangu invokes `launchctl load -D all` after installing its
             # payload. Route that call through the guarded batch loader so
             # already registered jobs cannot lose their live Unix sockets.
             (b'/bin/launchctl\0', b'/olsn0w/lctl\0')]
    for before, after in edits:
        if data.count(before) != 1 or len(after) > len(before):
            raise ValueError('Unrecognized Pangu path or oversized replacement')
        data = data.replace(before, after.ljust(len(before), b'\0'))
    output = Path(output)
    output.write_bytes(data)
    return resign(output, signature['entitlements'])


def embedded_payload(container, size, expected):
    """Find an exact component by content, never by a host executable offset."""
    if size < 28 or size > len(container):
        raise ValueError('Invalid embedded payload size')
    matches, start = [], 0
    while True:
        start = container.find(b'\xce\xfa\xed\xfe', start)
        if start < 0:
            break
        candidate = container[start:start+size]
        if len(candidate) == size and hashlib.sha256(candidate).hexdigest() == expected:
            matches.append(candidate)
        start += 4
    if len(matches) != 1:
        raise ValueError('Missing or ambiguous qualified Aquila payload')
    return matches[0]


def ios7_payload():
    archive = STATE / 'downloads' / ('aquila-' + RELEASE + '.exe')
    if not archive.exists():
        fetch(URL, archive)
    if digest(archive) != ARCHIVE_SHA256:
        raise ValueError('Aquila release checksum mismatch')
    # This file is a carrier for the device binaries. It is never executed,
    # and extraction needs neither Wine nor any macOS/Windows APIs.
    payload = embedded_payload(archive.read_bytes(), IOS7_SIZE, IOS7_SHA256)
    verify(payload)
    return payload, dict(url=URL, release=RELEASE, sha256=ARCHIVE_SHA256,
                         component='aquila_5_7', component_sha256=IOS7_SHA256)
