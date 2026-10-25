"""Offline qualification of the iOS 6 TriStar retry/fallback function.

This tool emits a proposed hash-pinned patch; restoration never discovers or
applies patches with this scanner. Runtime selection stays in kernelcache.py.
The complete P107 / 10B329 function must match, excluding two relocated IOLog
calls. The iOS 6.0 variant differs only in an unchanged object-member load
(0xdc instead of 0xe8). Both exact templates retain identical retry, branch,
fallback and return instructions. Call destinations and all five diagnostic/
property references are resolved independently before accepting either form.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM


# P107 10B329, verified on hardware with Mac and wall-charger cold starts.
# Zeroes replace the two BL encodings, whose IOLog targets are checked below.
RETRY_CODE = bytes.fromhex(
    'f0b503af4df8048d81b02b4a05460c467a441068d0f8ac832846c04740f2c6210646'
    'cef200018e4241d1d5f8e800234902687944d2f88820904740f2c6260028cef20006'
    '33d028686946d0f88c2328469047d8b99df8000010f0010f16d028680021d0f8f020'
    '28469047164a014614487a447844000000002868d0f8a0132846884728462146c047'
    '064610e0286800210026d0f8f020284690470c4a01460a487a447844000000004ff6'
    'ff702080304601b05df8048bf0bd')
LOG_CALLS = (0x74, 0xa4)
PATCH_OFFSET = 0x8a
IOS60_RETRY_CODE = RETRY_CODE[:0x2c] + b'\xdc' + RETRY_CODE[0x2d:]
TEMPLATES = {RETRY_CODE: 'ios6.1-member-e8', IOS60_RETRY_CODE: 'ios6.0-member-dc'}
LITERALS = (
    (0xbc, 0x36, b'soft-reset'),
    (0xc0, 0x76, b'%s::%s: could not read system ID (retrying)\n'),
    (0xc4, 0x74, b'getSystemID'),
    (0xc8, 0xa6, b'%s::%s: could not read system ID (ignoring)\n'),
    (0xcc, 0xa4, b'getSystemID'),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def macho(data):
    if len(data) < 28 or data[:4] != b'\xce\xfa\xed\xfe':
        raise ValueError('Expected a thin ARM kernel')
    cpu = struct.unpack_from('<I', data, 4)[0]
    count, size = struct.unpack_from('<II', data, 16)
    if cpu != 12 or count > size//8 or size > len(data)-28:
        raise ValueError('Invalid kernel Mach-O header')
    at, segments, symtabs = 28, [], []
    for _ in range(count):
        kind, length = struct.unpack_from('<II', data, at)
        if length < 8 or at+length > 28+size:
            raise ValueError('Invalid kernel load command')
        if kind == 1:
            if length < 56:
                raise ValueError('Truncated kernel segment')
            name = data[at+8:at+24].rstrip(b'\0').decode('ascii')
            vm, vm_size, offset, extent = struct.unpack_from('<4I', data, at+24)
            if extent > vm_size or offset+extent > len(data):
                raise ValueError('Kernel segment outside file')
            segments.append((name, vm, offset, extent))
        elif kind == 2:
            if length != 24:
                raise ValueError('Invalid kernel symbol command')
            symtabs.append(struct.unpack_from('<4I', data, at+8))
        at += length
    if at != 28+size or len(symtabs) != 1:
        raise ValueError('Ambiguous kernel load commands/symbol table')
    return segments, symtabs[0]


def file_offset(segments, address, length=1):
    matches = [offset+address-vm for _, vm, offset, extent in segments
               if vm <= address and address+length <= vm+extent]
    if len(matches) != 1:
        raise ValueError('Address is not in one file-backed kernel segment')
    return matches[0]


def iolog_symbol(data, table):
    symbols, count, strings, length = table
    if symbols+12*count > len(data) or strings+length > len(data):
        raise ValueError('Kernel symbols outside file')
    matches = []
    for index in range(count):
        name, kind, _, _, value = struct.unpack_from('<IBBHI', data, symbols+12*index)
        if name >= length:
            raise ValueError('Invalid kernel symbol name')
        end = data.find(b'\0', strings+name, strings+length)
        if end < 0:
            raise ValueError('Unterminated kernel symbol name')
        if data[strings+name:end] == b'_IOLog' and kind & 0x0e == 0x0e:
            matches.append(value)
    if len(matches) != 1:
        raise ValueError('Missing or ambiguous IOLog symbol')
    return matches[0]


def log_target(data, segments, decoder, address):
    offset = file_offset(segments, address, 16)
    code = list(decoder.disasm(data[offset:offset+16], address))
    if ([(i.mnemonic, i.op_str) for i in code[2:]] !=
            [('add', 'ip, pc'), ('ldr.w', 'ip, [ip]'), ('bx', 'ip')]
            or len(code) != 5 or [i.mnemonic for i in code[:2]] != ['movw', 'movt']
            or any(i.op_str.split(',')[0] != 'ip' or i.operands[1].type != ARM_OP_IMM for i in code[:2])):
        raise ValueError('Logging call does not use the qualified import thunk')
    displacement = code[0].operands[1].imm | code[1].operands[1].imm << 16
    pointer = file_offset(segments, code[2].address+4+displacement, 4)
    return struct.unpack_from('<I', data, pointer)[0] & ~1


def audit(data):
    segments, table = macho(data)
    prelink = [s for s in segments if s[0] == '__PRELINK_TEXT']
    if len(prelink) != 1:
        raise ValueError('Missing or ambiguous prelinked kernel text')
    _, vm, start, extent = prelink[0]
    end = start+extent
    matches, position = [], start
    while True:
        position = data.find(RETRY_CODE[:0x2a], position, end)
        if position < 0:
            break
        if position % 2 == 0 and position+0xd0 <= end:
            code = bytearray(data[position:position+len(RETRY_CODE)])
            for call in LOG_CALLS:
                code[call:call+4] = b'\0'*4
            if bytes(code) in TEMPLATES:
                matches.append((position, bytes(code)))
        position += 2
    if len(matches) != 1:
        raise ValueError('Missing or ambiguous complete TriStar retry/fallback function')
    offset, template = matches[0]
    address = vm+offset-start
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB); decoder.detail = True
    iolog = iolog_symbol(data, table)
    calls = []
    for relative in LOG_CALLS:
        code = list(decoder.disasm(data[offset+relative:offset+relative+4], address+relative))
        if len(code) != 1 or code[0].mnemonic != 'bl' or code[0].operands[0].type != ARM_OP_IMM:
            raise ValueError('Relocated logging instruction is not a direct call')
        target = code[0].operands[0].imm & 0xffffffff
        if log_target(data, segments, decoder, target) != iolog:
            raise ValueError('Relocated call does not resolve to IOLog')
        calls.append(target)
    for pool, pc_relative, expected in LITERALS:
        displacement = struct.unpack_from('<i', data, offset+pool)[0]
        pointer = file_offset(segments, address+pc_relative+displacement, len(expected)+1)
        if data[pointer:pointer+len(expected)+1] != expected+b'\0':
            raise ValueError('TriStar property/diagnostic reference differs')
    # The Builtin override is also installed as a virtual method in prelink data.
    pointer = struct.pack('<I', address | 1)
    if data.count(pointer, start, end) != 1:
        raise ValueError('Missing or ambiguous TriStar virtual-method entry')
    patch_at, patch_va = offset+PATCH_OFFSET, address+PATCH_OFFSET
    changed = data[:patch_at]+bytes.fromhex('86b1')+data[patch_at+2:]
    original = next(decoder.disasm(data[patch_at:patch_at+2], patch_va))
    replacement = next(decoder.disasm(changed[patch_at:patch_at+2], patch_va))
    if ((original.mnemonic, original.op_str) != ('b', f'#{address+0xae:#x}')
            or (replacement.mnemonic, replacement.op_str) != ('cbz', f'r6, #{address+0xae:#x}')):
        raise ValueError('Retry branch does not retain the qualified return target')
    patch = dict(name='tristar-system-id-retry-fallback', offset=patch_at, virtual_address=patch_va,
                 before='10e0', after='86b1', raw_sha256=sha(data), patched_sha256=sha(changed),
                 validation='exact-structural-match')
    return dict(patch=patch, reference=dict(product='iPad2,7', build='10B329',
                raw_sha256='6642753b73af33e8490db4183612efc227f4c388fbeb46936355b58a8f369b30'),
                function_offset=offset, function_virtual_address=address,
                executable_bytes=len(RETRY_CODE), relocated_call_bytes=8,
                function_template=TEMPLATES[template], unchanged_member_load=template[0x2c],
                normalized_code_sha256=sha(template), literal_references_verified=len(LITERALS),
                iolog_symbol=iolog, iolog_call_targets=calls, virtual_method_entry_verified=True,
                changed_raw_bytes=2, physical_boot_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = json.dumps(audit(args.kernel.read_bytes()), indent=2)+'\n'
    if args.output:
        args.output.write_text(report)
    else:
        print(report, end='')


if __name__ == '__main__':
    main()
