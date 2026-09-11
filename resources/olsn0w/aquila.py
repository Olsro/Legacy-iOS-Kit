"""Read the qualified iOS payload from a pinned upstream release as inert data."""
import hashlib
import json
from pathlib import Path

from common import STATE, digest
from firmware import fetch
from signing import verify, resign

RELEASE = '2.1.1'
URL = 'https://github.com/staturnzz/aquila/releases/download/' + RELEASE + '/aquila.exe'
ARCHIVE_SHA256 = '42a50f5e1ec40e547d2013ad9f7e7af9fe3381fce7ba8672e7360e59929a2290'
IOS7_SHA256 = 'a10c700b7f0ff38121326c65be4543162459dec8fb8e2f90a6602a0383e25f49'
IOS7_SIZE = 91056


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
