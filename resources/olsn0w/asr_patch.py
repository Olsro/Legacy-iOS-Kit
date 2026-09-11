"""Apply the Kit's ASR failure-to-success branch to the restore RAM only.

Locate diagnostic-string references rather than using device/firmware offsets.
The installed stock filesystem and its signed boot chain remain byte-identical.
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_REG_R0


def patch(data):
    if len(data) < 28 or data[:4] != b'\xce\xfa\xed\xfe':
        raise ValueError('Expected a thin ARM Mach-O ASR')
    cpu, = struct.unpack_from('<I', data, 4)
    count, size = struct.unpack_from('<II', data, 16)
    if cpu != 12 or count > size//8 or size > len(data)-28:
        raise ValueError('Invalid ASR Mach-O header')
    at, text = 28, []
    for _ in range(count):
        kind, length = struct.unpack_from('<II', data, at)
        if length < 8 or at+length > 28+size:
            raise ValueError('Invalid ASR load command')
        if kind == 1:
            if length < 56:
                raise ValueError('Truncated ASR segment')
            name = data[at+8:at+24].rstrip(b'\0')
            vm, _, offset, extent = struct.unpack_from('<4I', data, at+24)
            if offset+extent > len(data):
                raise ValueError('ASR segment outside file')
            if name == b'__TEXT':text.append((vm,offset,extent))
        at += length
    if at != 28+size or len(text) != 1:
        raise ValueError('Ambiguous ASR text segment')
    vm, offset, extent = text[0]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail = True
    targets = {}
    for label in ('passed','failed'):
        token = ('Image '+label+' signature verification').encode()+b'\0'
        if data.count(token) != 1:
            raise ValueError('Missing or ambiguous ASR '+label+' message')
        targets[label] = data.index(token)
    refs = {label:[] for label in targets}
    for start in range(offset,offset+extent-10,2):
        if struct.unpack_from('<H',data,start)[0] & 0xfbf0 != 0xf240:
            continue
        ins = list(md.disasm(data[start:start+10],vm+start-offset))
        if len(ins)!=3 or [i.mnemonic for i in ins]!=['movw','movt','add']:
            continue
        if ins[2].op_str != 'r0, pc':continue
        if any(len(i.operands)!=2 or i.operands[0].reg!=ARM_REG_R0 or
               i.operands[1].type!=ARM_OP_IMM for i in ins[:2]):continue
        address = (ins[0].operands[1].imm | ins[1].operands[1].imm<<16) + ins[2].address+4
        for label, pos in targets.items():
            if address == vm+pos-offset:refs[label].append(start)
    if any(len(value)!=1 for value in refs.values()):
        raise ValueError('Unrecognized or ambiguous ASR diagnostic references')
    source, target = refs['failed'][0], refs['passed'][0]
    delta = target-source-4
    if not -(1<<24) <= delta < 1<<24 or delta & 1:
        raise ValueError('ASR branch outside Thumb-2 range')
    bits = delta & 0x1ffffff
    s, i1, i2 = bits>>24, (bits>>23)&1, (bits>>22)&1
    first = 0xf000 | s<<10 | (bits>>12)&0x3ff
    second = 0x9000 | (1^(i1^s))<<13 | (1^(i2^s))<<11 | (bits>>1)&0x7ff
    branch = struct.pack('<HH',first,second)
    decoded = list(md.disasm(branch,source))
    if len(decoded)!=1 or decoded[0].mnemonic!='b.w' or decoded[0].operands[0].imm!=target:
        raise ValueError('ASR branch did not decode to the expected destination')
    result = bytearray(data); result[source:source+4] = branch
    return bytes(result), dict(method='kit-asr-failure-to-success',offset=source,
                               destination=target,before=data[source:source+4].hex(),after=branch.hex())
