"""Separate, checked pre-LC_MAIN helpers for the iOS 5 route."""
import json
from pathlib import Path
import struct

from common import digest
from signing import verify

ROOT = Path(__file__).parent


def payloads():
    report = json.loads((ROOT/'target/ios5/manifest.json').read_text())
    expected = {'native/target/build-ios5-helpers.sh', 'native/target/keybag_init.c',
                'native/target/protection_probe.c', 'target/ios5/keybag-init',
                'target/ios5/protection-probe'}
    if (report.get('minimum_ios') != '5.0' or set(report['files']) != expected
            or any(digest(ROOT/n) != h for n,h in report['files'].items())):
        raise ValueError('iOS 5 helper provenance differs')
    result = {}
    for name in ('keybag-init', 'protection-probe'):
        blob = (ROOT/'target/ios5'/name).read_bytes()
        verify(blob)
        count = struct.unpack_from('<I',blob,16)[0]
        offset=28
        commands=[]
        for _ in range(count):
            command,size=struct.unpack_from('<II',blob,offset)
            commands.append(command)
            if command==0x25 and struct.unpack_from('<I',blob,offset+8)[0] != 0x50000:
                raise ValueError('Unexpected iOS 5 helper deployment target')
            offset+=size
        if 0x80000028 in commands or commands.count(5)!=1 or commands.count(0x25)!=1:
            raise ValueError('iOS 5 helper needs LC_UNIXTHREAD, not LC_MAIN')
        result[name]=blob
    return result
