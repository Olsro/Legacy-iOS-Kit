"""Select the target volume in iBECs that otherwise require an OTA volume flag.

The selected firmware supplies the storage device name and filesystem routines.
Only recognized function shapes are replaced; unrelated firmware is rejected.
"""
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from logo import bl


def _unique(values, label):
    values = list(values)
    if len(values) != 1:
        raise ValueError('Unrecognized or ambiguous ' + label)
    return values[0]


def discover(data):
    if len(data) < 64:
        raise ValueError('Truncated iBEC')
    base = struct.unpack_from('<I', data, 32)[0] - 64
    if not 0 <= base <= 0xffffffff - len(data):
        raise ValueError('Invalid iBEC base')
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True

    def string(token):
        if data.count(token) != 1:
            raise ValueError('Unrecognized or ambiguous upgrade string')
        return data.index(token)

    def literal(i):
        # This recognized form uses narrow PC-relative LDR instructions.
        if i.size != 2 or i.mnemonic != 'ldr':
            return None
        word = struct.unpack_from('<H', data, i.address)[0]
        if word & 0xf800 != 0x4800:
            return None
        at = ((i.address + 4) & ~3) + (word & 255) * 4
        if at > len(data) - 4:
            return None
        return at, struct.unpack_from('<I', data, at)[0]

    def references(pointer):
        for at in range(0, len(data) - 4, 2):
            word = struct.unpack_from('<H', data, at)[0]
            if word & 0xf800 != 0x4800:
                continue
            ins = next(md.disasm(data[at:at+2], at), None)
            value = literal(ins) if ins else None
            if value and value[1] == pointer:
                yield at

    missing = base + string(b'could not locate upgrade partition\n\0')
    failed = base + string(b'failed to mount upgrade partition\0')
    boot_device = base + string(b'boot-device\0')
    format_address = base + string(b'%s%c\0')
    candidates = []
    # Verify the complete flag-search function, both error messages and pool.
    for ref in references(missing):
        for start in range(max(0, ref - 96) & ~3, ref, 4):
            ins = list(md.disasm(data[start:ref+14], start))
            if len(ins) != 22:
                continue
            expected = ['push','mov','bl','b','bl','cbz','ldrb','tst.w',
                        'beq','adds','bl','cmp','itt','moveq','popeq',
                        'ldr','b','ldr','bl','mov.w','pop','nop']
            if [i.mnemonic for i in ins] != expected:
                continue
            checks = {0:'{r7, lr}',1:'r7, sp',6:'r1, [r0, #4]',7:'r1, #2',
                      9:'r0, #0x38',11:'r0, #0',12:'eq',13:'r0, #0',
                      14:'{r7, pc}',19:'r0, #-1',20:'{r7, pc}'}
            if any(ins[n].op_str != value for n,value in checks.items()):
                continue
            if (ins[3].operands[0].imm != ins[5].address or
                ins[5].operands[1].imm != ins[17].address or
                ins[8].operands[0].imm != ins[4].address or
                ins[16].operands[0].imm != ins[18].address):
                continue
            pool = ins[-1].address + ins[-1].size
            if literal(ins[15]) != (pool+4, failed) or literal(ins[17]) != (pool, missing):
                continue
            if pool+8-start != 64 or ins[17].address != ref:
                continue
            mount = ins[10].operands[0].imm
            if not 0 <= mount < len(data)-4:
                continue
            candidates.append((start, mount))
    start, mount = _unique(candidates, 'upgrade volume selector')

    # The string getter returns the first field of a found environment entry,
    # or NULL. Its unique complete function includes both return paths.
    getters = []
    for at in range(0, len(data)-20, 2):
        if data[at:at+4] != bytes.fromhex('80b56f46'):
            continue
        ins = list(md.disasm(data[at:at+20], at))
        if (len(ins) == 9 and ins[2].mnemonic == 'bl' and
            data[at+8:at+20] == bytes.fromhex('00281cbf006880bd002080bd')):
            getters.append(at)
    getter = _unique(getters, 'environment string getter')

    # Two independent device-name formatting sites must agree on snprintf.
    formatters = []
    for ref in references(format_address):
        ins = list(md.disasm(data[ref:ref+40], ref))
        first_call = next((i for i in ins if i.mnemonic == 'bl'), None)
        if first_call:
            formatters.append(first_call.operands[0].imm)
    if len(formatters) < 2 or len(set(formatters)) != 1:
        raise ValueError('Unrecognized bounded device-name formatter')
    formatter = formatters[0]
    if not 0 <= formatter < len(data)-4:
        raise ValueError('Invalid device-name formatter')
    return dict(base=base, offset=start, size=64, mount=mount, getter=getter,
                formatter=formatter, boot_device=boot_device, format=format_address)


def code(params, partition):
    """Encode the bounded ARM routine directly, without a host compiler/SDK."""
    if type(partition) is not int or not 1 <= partition <= 26:
        raise ValueError('Target partition must be between 1 and 26')
    body = bytearray.fromhex(
        '80b5a2b00b480000000070b103466320009001a88021084a00000000'
        '01387e2803d801a80000000001e04ff0ff3022b080bd00bf'
    )
    body[14] = ord('a') + partition - 1
    for site, name in [(6,'getter'),(24,'formatter'),(36,'mount')]:
        body[site:site+4] = bl(params['base']+params['offset']+site,
                             params['base']+params[name])
    body.extend(struct.pack('<II', params['boot_device'], params['format']))
    if len(body) > params['size']:
        raise ValueError('Upgrade selector does not fit')
    return bytes(body) + bytes(params['size']-len(body))


def apply(data, partition=3):
    params = discover(data)
    replacement = code(params, partition)
    at = params['offset']
    patched = data[:at] + replacement + data[at+params['size']:]
    return patched, dict(params, partition=partition,
                         before=data[at:at+params['size']].hex(), after=replacement.hex())
