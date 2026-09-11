"""Bounded IMG3 container reader."""
import struct

def img3(data):
    magic, total, payload_total, shsh, kind = struct.unpack_from('<5I', data)
    if magic != int.from_bytes(b'Img3', 'big') or total != len(data) or payload_total != total - 20:
        raise ValueError('Invalid IMG3 root')
    offset, tags, payload = 20, [], None
    while offset < total:
        tag, size, length = struct.unpack_from('<III', data, offset)
        if size < 12 or length > size - 12 or offset + size > total:
            raise ValueError('Invalid IMG3 tag bounds')
        name = tag.to_bytes(4, 'big').decode('ascii')
        tags.append(name)
        if name == 'DATA':
            if payload is not None:
                raise ValueError('Duplicate DATA')
            payload = data[offset + 12:offset + 12 + length]
        offset += size
    if offset != total or payload is None:
        raise ValueError('Invalid IMG3 payload')
    return kind.to_bytes(4, 'big').decode('ascii'), tags, payload

