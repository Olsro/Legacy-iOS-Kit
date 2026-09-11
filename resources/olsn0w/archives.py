"""Read the kit's tar and Debian payloads without extracting host filesystem paths."""
import copy
import io
from pathlib import PurePosixPath
import tarfile


def member_path(name):
    while name.startswith('./'):
        name = name[2:]
    name = name.rstrip('/')
    if name in ('', '.'):
        return None
    if name.startswith('/') or '..' in PurePosixPath(name).parts or '\0' in name:
        raise ValueError('Unsafe payload member path')
    return name


def members(source):
    options = dict(fileobj=io.BytesIO(source)) if isinstance(source, bytes) else dict(name=source)
    with tarfile.open(mode='r:*', **options) as archive:
        seen = set()
        for original in archive:
            name = member_path(original.name)
            if name is None:
                continue
            if name in seen:
                raise ValueError('Duplicate payload member: '+name)
            seen.add(name)
            if not (original.isfile() or original.isdir() or original.issym() or original.islnk()):
                raise ValueError('Unsupported payload member type: '+name)
            item = copy.copy(original)
            item.name = name
            data = None
            if item.isfile() or item.islnk():
                data = archive.extractfile(original).read()
                if item.islnk():
                    item.type, item.linkname, item.size = tarfile.REGTYPE, '', len(data)
            yield item, data


def deb_payload(data):
    if data[:8] != b'!<arch>\n':
        raise ValueError('Invalid Debian ar archive')
    offset, payload = 8, None
    while offset < len(data):
        header = data[offset:offset+60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('Invalid Debian ar member')
        length = int(header[48:58])
        name = header[:16].decode('ascii').strip().rstrip('/')
        if length < 0 or offset+60+length > len(data):
            raise ValueError('Truncated Debian ar member')
        if name.startswith('data.tar'):
            if payload is not None:
                raise ValueError('Multiple Debian data payloads')
            payload = data[offset+60:offset+60+length]
        offset += 60+length+(length % 2)
    if payload is None or offset != len(data):
        raise ValueError('Missing or invalid Debian payload')
    return payload


def write_tar(path, entries):
    # hfsplus expects parent directory members before the files within them.
    ordered = sorted(entries, key=lambda entry: (not entry[0].isdir(), entry[0].name.count('/'), entry[0].name))
    with tarfile.open(path, 'w', format=tarfile.GNU_FORMAT) as archive:
        for original, data in ordered:
            item = copy.copy(original)
            if member_path(item.name) != item.name:
                raise ValueError('Unnormalized payload path')
            item.mtime = 0
            item.uname = item.gname = ''
            archive.addfile(item, io.BytesIO(data) if data is not None else None)
