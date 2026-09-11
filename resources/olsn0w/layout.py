"""Validate mirrored GPT tables and plan an HFS target plus compact bootstrap.

This module only transforms bytes and computes ranges. It never opens a device.
"""
import struct
import uuid
import zlib

from common import version

HFS_TYPE = uuid.UUID('48465300-0000-11aa-aa11-00306543ecac').bytes_le


def header(block):
    if len(block) != 4096 or block[:8] != b'EFI PART':
        raise ValueError('Expected a 4096-byte GPT header block')
    revision, size, checksum, reserved = struct.unpack_from('<4I', block, 8)
    if revision not in (1, 0x10000) or size != 92 or reserved:
        raise ValueError('Unsupported GPT header revision or size')
    checked = bytearray(block[:size])
    checked[16:20] = bytes(4)
    if zlib.crc32(checked) != checksum:
        raise ValueError('GPT header checksum mismatch')
    here, other, first, last = struct.unpack_from('<4Q', block, 24)
    entries, count, entry_size, entries_crc = struct.unpack_from('<QIII', block, 72)
    if entry_size != 128 or not 1 <= count <= 128 or first > last:
        raise ValueError('Unsupported GPT entry geometry')
    return dict(revision=revision, here=here, other=other, first=first, last=last,
                guid=bytes(block[56:72]), entries=entries, count=count,
                entry_size=entry_size, entries_crc=entries_crc)


def inspect(primary, secondary):
    if len(primary) != 6*4096 or len(secondary) != 5*4096:
        raise ValueError('Expected complete primary and backup GPT regions')
    a, b = header(primary[4096:8192]), header(secondary[-4096:])
    if (a['here'] != 1 or a['entries'] != 2 or a['other'] != b['here'] or
            b['other'] != 1 or b['entries'] != b['here']-4 or
            a['first'] != 6 or a['last'] != b['here']-5):
        raise ValueError('Unexpected GPT placement')
    for key in ('revision', 'first', 'last', 'guid', 'count', 'entry_size', 'entries_crc'):
        if a[key] != b[key]:
            raise ValueError('GPT copies disagree: '+key)
    length = a['count']*128
    entries = primary[8192:8192+length]
    if entries != secondary[:length] or zlib.crc32(entries) != a['entries_crc']:
        raise ValueError('GPT entry arrays disagree or have invalid checksums')
    partitions, identifiers = [], set()
    for i in range(a['count']):
        entry = entries[i*128:(i+1)*128]
        if not any(entry[:16]):
            if any(entry):
                raise ValueError('Nonempty unused GPT record')
            continue
        first, last, attrs = struct.unpack_from('<QQQ', entry, 32)
        identifier = entry[16:32]
        if not any(identifier) or identifier in identifiers or not a['first'] <= first <= last <= a['last']:
            raise ValueError('Invalid partition identifier or range')
        identifiers.add(identifier)
        partitions.append(dict(index=i+1, first=first, last=last, attributes=attrs,
                               type=entry[:16], guid=identifier))
    ordered = sorted(partitions, key=lambda item: item['first'])
    if any(x['last'] >= y['first'] for x,y in zip(ordered,ordered[1:])):
        raise ValueError('Overlapping GPT partitions')
    return a, partitions


def plan(primary, secondary, target_bytes, release):
    source, previous = inspect(primary, secondary)
    if type(target_bytes) is not int or target_bytes <= 0 or target_bytes % 4096:
        raise ValueError('Target image must occupy whole allocation blocks')
    if version(release) < (6,0,0):
        raise ValueError('Expected an iOS release from 6.0 onward')
    if any(item['type'] != HFS_TYPE for item in previous):
        raise ValueError('This layout recipe requires HFS source partitions')
    block, root_blocks, var_blocks = 4096, 30*256, 2*256
    end = source['last']
    root_start = end+1-root_blocks-var_blocks
    target_start, target_end = source['first'], source['first']+target_bytes//block-1
    data_start, data_end = target_end+1, root_start-1
    if data_end-data_start+1 < 256*256:
        raise ValueError('Insufficient capacity for target Data and bootstrap')
    # iOS 7+ receives its own newly generated keybag, without the iOS 6
    # effaceable-storage flags that its kernel cannot use on a secondary root.
    data_attributes = 0x3000000000000 if version(release)[0] == 6 else 0
    partitions = [
        dict(index=1, role='bootstrap', first=root_start, last=root_start+root_blocks-1, attributes=0),
        dict(index=2, role='data', first=data_start, last=data_end, attributes=data_attributes),
        dict(index=3, role='system', first=target_start, last=target_end, attributes=0),
        dict(index=4, role='bootstrap-data', first=end-var_blocks+1, last=end, attributes=0),
    ]
    for item in partitions:
        item['bytes'] = (item['last']-item['first']+1)*block
        item['device'] = '/dev/disk0s1s'+str(item['index'])
    return dict(block_size=block, last_lba=source['other'], partitions=partitions,
                erase_required=True, target_version=release,
                source_disk_guid=str(uuid.UUID(bytes_le=source['guid'])))


def partition_names(release):
    """Use iBEC's proven OTA role for every iOS 8 target volume."""
    system = 'Update' if version(release)[0] == 8 else 'System'
    return {'bootstrap':'Olsn0w', 'data':'Data', 'system':system,
            'bootstrap-data':'Olsn0wData'}


def encode(primary, secondary, target_bytes, release):
    """Produce both GPT copies for the computed layout, preserving disk identity."""
    source, previous = inspect(primary, secondary)
    layout = plan(primary, secondary, target_bytes, release)
    entries = bytearray(4*4096)
    names = partition_names(release)
    for item in layout['partitions']:
        offset = (item['index']-1)*128
        entries[offset:offset+16] = HFS_TYPE
        # Preserve the signed base system's partition identity when relocating it.
        if item['index'] == 1:
            matches = [p for p in previous if p['index']==1]
            if len(matches)!=1:
                raise ValueError('Missing base system partition')
            identifier = matches[0]['guid']
        else:
            identifier = uuid.uuid5(uuid.UUID(bytes_le=source['guid']),
                'olsn0w:'+release+':'+item['role']).bytes_le
        entries[offset+16:offset+32] = identifier
        struct.pack_into('<QQQ', entries, offset+32, item['first'],item['last'],item['attributes'])
        name = names[item['role']].encode('utf-16-le')
        entries[offset+56:offset+56+len(name)] = name
        item['guid'] = str(uuid.UUID(bytes_le=identifier))
    def packed(here, other, entries_lba):
        block=bytearray(4096)
        struct.pack_into('<8sIIIIQQQQ16sQIII',block,0,b'EFI PART',source['revision'],92,0,0,
            here,other,source['first'],source['last'],source['guid'],entries_lba,4,128,
            zlib.crc32(entries[:512]))
        struct.pack_into('<I',block,16,zlib.crc32(block[:92]))
        return block
    first=primary[:4096]+packed(1,source['other'],2)+entries
    last=entries+packed(source['other'],1,source['other']-4)
    _,checked=inspect(first,last)
    for expected,actual in zip(layout['partitions'],checked):
        for key in ('index','first','last','attributes'):
            if expected[key]!=actual[key]:
                raise ValueError('Generated GPT layout failed readback')
    return bytes(first),bytes(last),layout


def editor_commands(source_primary, source_secondary, target_bytes, release, commit=False):
    """Use the Kit's native partition editor so Apple LwVM receives its commit.

    Raw writes to the synthetic GPT sectors may be silently discarded by LwVM.
    Newly created volumes must be populated through their post-commit mappings.
    """
    _,previous=inspect(source_primary,source_secondary)
    _,_,layout=encode(source_primary,source_secondary,target_bytes,release)
    indices = [p['index'] for p in previous]
    if indices not in ([1,2], [1,2,3,4]):
        raise ValueError('Expected a stock base or an existing four-partition olsn0w layout')
    if len(indices) == 4:
        # A reinstallation may change the target system size. Require the
        # existing compact bootstrap geometry before deleting any mappings.
        end = inspect(source_primary, source_secondary)[0]['last']
        if ((previous[0]['first'], previous[0]['last']) != (end+1-32*256, end-2*256) or
                (previous[3]['first'], previous[3]['last']) != (end+1-2*256, end) or
                previous[2]['first'] != 6 or previous[1]['first'] != previous[2]['last']+1 or
                previous[1]['last'] != previous[0]['first']-1):
            raise ValueError('Existing partitions do not match the olsn0w layout')
    names=partition_names(release)
    # HFS images may occupy an odd number of 4096-byte blocks. gdisk's
    # inherited alignment must not move Data backward into the system image.
    lines=[]
    for index in reversed(indices[1:]):
        lines += ['d', str(index)]
    lines += ['d','x','s','4','l','1','m']
    for p in layout['partitions']:
        lines+=['n',str(p['index']),str(p['first']),str(p['last']),'af00']
    # With a single partition gdisk selects it without a numeric prompt.
    # Rename only after every entry exists, so the input dialogue is stable.
    for p in layout['partitions']:
        lines+=['c',str(p['index']),names[p['role']]]
    lines+=['x']
    for p in layout['partitions']:
        lines+=['c',str(p['index']),p['guid'].upper()]
        if p['attributes']:
            if p['attributes']!=0x3000000000000:raise ValueError('Unsupported GPT attributes')
            lines+=['a',str(p['index']),'48','49','']
    lines+=['m','p']
    for i in range(1,5):lines+=['i',str(i)]
    lines+=['v']+(['w','Y'] if commit else ['q'])
    return ('\n'.join(lines)+'\n').encode()
