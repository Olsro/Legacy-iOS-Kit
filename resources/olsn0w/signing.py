"""Reuse the kit's ldid release and verify every signed page after modification."""
import hashlib
from pathlib import Path
import platform
import plistlib
import struct
import tempfile

from common import STATE, digest, run
from firmware import fetch

LDID_RELEASE = 'v2.1.5-procursus7'
LDID_HASHES = {
    'ldid_linux_aarch64': 'bddd525902f242d4cdf7aa40a7f0c2c85c42ab9440d58664251e8738ef0c565d',
    'ldid_linux_x86_64': '4b8862b2fefa2cd7fa8f88cb0310779619aeaa8c72d6aff22f019b470f2fa99a',
    'ldid_macosx_arm64': '5dff8e6b8d9dc3ff7226276c81e09930865f15381f54cb55b98b196a94c5ca50',
    'ldid_macosx_x86_64': '9d46e0feedf96e399edfca09872802ba21e729f79c01927ad25ea2b0a35bca23',
}


def ldid():
    system = {'Darwin': 'macosx', 'Linux': 'linux'}.get(platform.system())
    machine = platform.machine()
    if system == 'linux' and machine == 'arm64':
        machine = 'aarch64'
    name = 'ldid_' + str(system) + '_' + machine
    if name not in LDID_HASHES:
        raise ValueError('No kit ldid release for this host')
    path = STATE / 'tools' / name
    if not path.exists():
        fetch('https://github.com/ProcursusTeam/ldid/releases/download/' + LDID_RELEASE + '/' + name, path)
    if digest(path) != LDID_HASHES[name]:
        raise ValueError('ldid release checksum mismatch')
    path.chmod(0o755)
    return path


def verify(data):
    if len(data) < 28 or data[:4] != b'\xce\xfa\xed\xfe':
        raise ValueError('Expected a thin 32-bit Mach-O executable')
    count, command_bytes = struct.unpack_from('<II', data, 16)
    if command_bytes > len(data)-28 or count > command_bytes//8:
        raise ValueError('Invalid Mach-O load commands')
    at, signature, info_plist = 28, None, None
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, at)
        if length < 8 or at+length > 28+command_bytes:
            raise ValueError('Invalid Mach-O load command')
        if command == 1:
            if length < 56:
                raise ValueError('Truncated Mach-O segment')
            sections, = struct.unpack_from('<I', data, at+48)
            if length != 56+68*sections:
                raise ValueError('Invalid Mach-O section table')
            for section in range(sections):
                position = at+56+section*68
                if data[position:position+16].rstrip(b'\0') != b'__info_plist':
                    continue
                extent, start = struct.unpack_from('<II', data, position+36)
                if info_plist is not None or not extent or start+extent > len(data):
                    raise ValueError('Invalid embedded Info.plist')
                info_plist = data[start:start+extent]
        if command == 0x1d:
            if length != 16 or signature is not None:
                raise ValueError('Invalid code signature command')
            signature = struct.unpack_from('<II', data, at+8)
        at += length
    if signature is None:
        raise ValueError('Missing Mach-O code signature')
    offset, size = signature
    if size < 12 or offset+size > len(data):
        raise ValueError('Code signature outside file')
    blob = data[offset:offset+size]
    magic, length, count = struct.unpack_from('>III', blob)
    if magic != 0xfade0cc0 or not 12+8*count <= length <= size:
        raise ValueError('Invalid signature superblob')
    slots = {}
    for i in range(count):
        kind, position = struct.unpack_from('>II', blob, 12+8*i)
        if kind in slots or position < 12+8*count or position+8 > length:
            raise ValueError('Invalid signature slot')
        magic, extent = struct.unpack_from('>II', blob, position)
        if extent < 8 or position+extent > length:
            raise ValueError('Signature slot outside superblob')
        slots[kind] = blob[position:position+extent]
    pages, directories = 0, 0
    for kind, directory in slots.items():
        if kind != 0 and not 0x1000 <= kind <= 0x1005:
            continue
        if len(directory) < 44 or struct.unpack_from('>I', directory)[0] != 0xfade0c02:
            raise ValueError('Invalid CodeDirectory')
        hash_at, ident_at, special, codes, limit = struct.unpack_from('>5I', directory, 16)
        hash_size, hash_type, _, page_shift = struct.unpack_from('4B', directory, 36)
        algorithm = {1: 'sha1', 2: 'sha256'}.get(hash_type)
        if algorithm is None or hash_size != hashlib.new(algorithm).digest_size or not 9 <= page_shift <= 16:
            raise ValueError('Unsupported CodeDirectory hash/page format')
        page = 1 << page_shift
        if limit != offset or codes != (limit+page-1)//page:
            raise ValueError('Signature does not cover the complete executable')
        if hash_at-special*hash_size < 44 or hash_at+codes*hash_size > len(directory) or not 44 <= ident_at < len(directory):
            raise ValueError('Invalid CodeDirectory slot bounds')
        for i in range(codes):
            actual = hashlib.new(algorithm, data[i*page:min((i+1)*page, limit)]).digest()
            if actual != directory[hash_at+i*hash_size:hash_at+(i+1)*hash_size]:
                raise ValueError('Invalid signed page: '+str(i))
        for i in range(1, special+1):
            content = info_plist if i == 1 and info_plist is not None else slots.get(i)
            expected = hashlib.new(algorithm, content).digest() if content is not None else bytes(hash_size)
            if directory[hash_at-i*hash_size:hash_at-(i-1)*hash_size] != expected:
                raise ValueError('Invalid signature special slot: '+str(i))
        pages += codes
        directories += 1
    if not directories:
        raise ValueError('Missing CodeDirectory')
    entitlements = plistlib.loads(slots[5][8:]) if 5 in slots else {}
    return dict(directories=directories, verified_pages=pages, entitlements=entitlements)


def rehash_adhoc(original, modified):
    """Retain an Apple ad-hoc signature verbatim except for its code-page hashes."""
    original, data = bytes(original), bytearray(modified)
    if len(original) != len(data):
        raise ValueError('Ad-hoc rehash must preserve executable size')
    baseline = verify(original)

    def signature_location(executable):
        if len(executable) < 28 or executable[:4] != b'\xce\xfa\xed\xfe':
            raise ValueError('Expected a thin 32-bit Mach-O executable')
        count, command_bytes = struct.unpack_from('<II', executable, 16)
        if command_bytes > len(executable)-28 or count > command_bytes//8:
            raise ValueError('Invalid Mach-O load commands')
        found, at = [], 28
        for _ in range(count):
            command, length = struct.unpack_from('<II', executable, at)
            if length < 8 or at+length > 28+command_bytes:
                raise ValueError('Invalid Mach-O load command')
            if command == 0x1d:
                if length != 16:
                    raise ValueError('Invalid code signature command')
                found.append(struct.unpack_from('<II', executable, at+8))
            at += length
        if len(found) != 1:
            raise ValueError('Expected one Mach-O code signature command')
        return found[0]

    location = signature_location(original)
    if signature_location(data) != location:
        raise ValueError('Ad-hoc rehash changed the signature location')
    offset, size = location
    if offset+size > len(data) or data[offset:offset+size] != original[offset:offset+size]:
        raise ValueError('Ad-hoc rehash must preserve the original signature blob')
    blob = bytearray(data[offset:offset+size])
    magic, length, count = struct.unpack_from('>III', blob)
    if magic != 0xfade0cc0 or not 12+8*count <= length <= size:
        raise ValueError('Invalid signature superblob')
    directories = 0
    for i in range(count):
        kind, position = struct.unpack_from('>II', blob, 12+8*i)
        if kind != 0 and not 0x1000 <= kind <= 0x1005:
            continue
        if position+44 > length or struct.unpack_from('>I', blob, position)[0] != 0xfade0c02:
            raise ValueError('Invalid CodeDirectory')
        extent, _, flags, hash_at, _, special, codes, limit = struct.unpack_from(
            '>8I', blob, position+4)
        if extent < 44 or position+extent > length or not flags & 0x2:
            raise ValueError('Expected an Apple ad-hoc CodeDirectory')
        hash_size, hash_type, _, page_shift = struct.unpack_from('4B', blob, position+36)
        algorithm = {1: 'sha1', 2: 'sha256'}.get(hash_type)
        if algorithm is None or hash_size != hashlib.new(algorithm).digest_size or not 9 <= page_shift <= 16:
            raise ValueError('Unsupported CodeDirectory hash/page format')
        page = 1 << page_shift
        if limit != offset or codes != (limit+page-1)//page:
            raise ValueError('Signature does not cover the complete executable')
        if hash_at-special*hash_size < 44 or hash_at+codes*hash_size > extent:
            raise ValueError('Invalid CodeDirectory slot bounds')
        for page_index in range(codes):
            start = page_index*page
            value = hashlib.new(algorithm, data[start:min(start+page, limit)]).digest()
            slot = position+hash_at+page_index*hash_size
            blob[slot:slot+hash_size] = value
        directories += 1
    if not directories:
        raise ValueError('Missing CodeDirectory')
    data[offset:offset+size] = blob
    report = verify(data)
    if report['directories'] != baseline['directories'] or report['entitlements'] != baseline['entitlements']:
        raise ValueError('Ad-hoc signature metadata changed during rehash')
    return bytes(data)


def resign(path, entitlements):
    path = Path(path)
    with tempfile.TemporaryDirectory(prefix='olsn0w-sign-') as temporary:
        plist = Path(temporary) / 'entitlements.plist'
        plist.write_bytes(plistlib.dumps(entitlements))
        run([ldid(), '-S'+str(plist), path])
    report = verify(path.read_bytes())
    if report['entitlements'] != entitlements:
        raise ValueError('Entitlements changed during signing')
    return report
