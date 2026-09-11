"""Parse and extend Apple DeviceTree blobs without changing existing properties."""
import struct

def parse(data):
    nodes = []

    def node(offset, parent='', depth=0):
        if depth > 64 or offset + 8 > len(data):
            raise ValueError('DeviceTree node out of bounds')
        start = offset
        count, children = struct.unpack_from('<II', data, offset)
        if count > 4096 or children > 4096:
            raise ValueError('DeviceTree node count out of bounds')
        offset += 8
        props = []
        for _ in range(count):
            if offset + 36 > len(data):
                raise ValueError('DeviceTree property header out of bounds')
            raw_name = data[offset:offset + 32]
            if b'\0' not in raw_name:
                raise ValueError('Unterminated property name')
            name = raw_name.split(b'\0')[0].decode('ascii')
            size = struct.unpack_from('<I', data, offset + 32)[0]
            end = offset + 36 + ((size + 3) & ~3)
            if end > len(data):
                raise ValueError('DeviceTree property out of bounds')
            props.append({'name': name, 'offset': offset, 'value': data[offset + 36:offset + 36 + size]})
            offset = end
        names = [p['name'] for p in props]
        if len(set(names)) != len(names) or 'name' not in names:
            raise ValueError('Duplicate or missing node property')
        name = next(p['value'] for p in props if p['name'] == 'name').split(b'\0')[0].decode('ascii')
        path = parent + '/' + name
        nodes.append({'path': path, 'offset': start, 'properties': props})
        for _ in range(children):
            offset = node(offset, path, depth + 1)
        return offset

    if node(0) != len(data):
        raise ValueError('Unexpected trailing bytes')
    return nodes


def add_property(raw, path, name, value):
    before=parse(raw)
    matches=[n for n in before if n['path']==path]
    if len(matches)!=1:raise ValueError('Expected exactly one selected node')
    node=matches[0]
    if any(p['name']==name for p in node['properties']):raise ValueError('Property already exists')
    at=node['offset']+8
    encoded=name.encode().ljust(32,b'\0')+struct.pack('<I',len(value))+value
    encoded+=b'\0'*(-len(value)%4)
    result=bytearray(raw[:at]+encoded+raw[at:])
    struct.pack_into('<I',result,node['offset'],len(node['properties'])+1)
    after=parse(result)
    flatten=lambda nodes:[(n['path'],p['name'],bytes(p['value'])) for n in nodes for p in n['properties']]
    old=flatten(before);new=flatten(after)
    assert [x for x in new if x[1]!=name]==old
    assert [x for x in new if x[1]==name]==[(path,name,value)]
    inverse=bytearray(result[:at]+result[at+len(encoded):])
    struct.pack_into('<I',inverse,node['offset'],len(node['properties']))
    assert inverse==raw
    return bytes(result),len(old)

