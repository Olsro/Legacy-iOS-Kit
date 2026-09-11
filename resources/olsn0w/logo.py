"""Discover the iBEC upgrade-logo call and add display commands, with a pinned input.

Reusable across profiles with the same recognized instruction/command-table shapes.
Unknown shapes, ambiguous references or nonzero injection space are rejected.
"""
import hashlib, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM, ARM_REG_PC


def digest(b): return hashlib.sha256(b).hexdigest()

def bl(source,target):
    delta=target-(source+4)
    if delta&1 or not -(1<<24)<=delta<(1<<24): raise ValueError('BL target out of range')
    v=delta&0x1ffffff;s=(v>>24)&1;i1=(v>>23)&1;i2=(v>>22)&1
    return struct.pack('<HH',0xf000|(s<<10)|((v>>12)&1023),0xd000|((1^(i1^s))<<13)|((1^(i2^s))<<11)|((v>>1)&2047))

def discover(raw, expected_sha, cave):
    if digest(raw)!=expected_sha: raise ValueError('Unqualified iBEC build/input')
    base=struct.unpack_from('<I',raw,32)[0]-64
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    def command(name):
        token=b'\0'+name.encode()+b'\0'
        if raw.count(token)!=1:raise ValueError('Ambiguous command string')
        ptr=struct.pack('<I',base+raw.index(token)+1)
        refs=[i for i in range(0,len(raw)-12,4) if raw[i:i+4]==ptr]
        if len(refs)!=1:raise ValueError('Ambiguous command table')
        addr=struct.unpack_from('<I',raw,refs[0]+4)[0]
        if not addr&1 or not base<=addr<base+len(raw):raise ValueError('Invalid Thumb command')
        return addr
    logo=raw.index(b'/boot/applelogo\0')
    candidates=[]
    for offset in range(0,len(raw)-16,2):
        ins=list(md.disasm(raw[offset:offset+16],base+offset))
        if not ins or ins[0].mnemonic!='ldr' or not ins[0].op_str.startswith('r0, [pc,'):continue
        mem=ins[0].operands[1]
        if mem.type!=ARM_OP_MEM or mem.mem.base!=ARM_REG_PC:continue
        at=((ins[0].address+4)&~3)+mem.mem.disp-base
        if not 0<=at<len(raw)-4 or struct.unpack_from('<I',raw,at)[0]!=base+logo:continue
        if len(ins)>=3 and ins[1].mnemonic=='ldr' and ins[1].op_str.startswith('r1, [pc,') and ins[2].mnemonic=='bl':
            mem=ins[1].operands[1]
            if mem.type!=ARM_OP_MEM or mem.mem.base!=ARM_REG_PC:continue
            literal=((ins[1].address+4)&~3)+mem.mem.disp-base
            if 0<=literal<=len(raw)-4 and struct.unpack_from('<I',raw,literal)[0]==0x6c6f676f:
                candidates.append((ins[2].address-base,ins[2].operands[0].imm & 0xffffffff))
            continue
        if len(ins)<4 or [(i.mnemonic,i.op_str) for i in ins[1:3]] != [('movw','r1, #0x676f'),('movt','r1, #0x6c6f')]:continue
        if ins[3].mnemonic!='bl':continue
        candidates.append((ins[3].address-base,ins[3].operands[0].imm & 0xffffffff))
    if len(candidates)!=1:raise ValueError('Unrecognized upgrade logo call shape')
    site,loader=candidates[0]
    picture=command('setpicture');bgcolor=command('bgcolor')
    ins=list(md.disasm(raw[(bgcolor&~1)-base:(bgcolor&~1)-base+40],bgcolor&~1))
    calls=[i.operands[0].imm & 0xffffffff for i in ins if i.mnemonic=='bl']
    if len(calls)!=2 or sum(i.mnemonic.startswith('ldrb') for i in ins)!=3:raise ValueError('Unrecognized background command')
    if not 0x100<=cave<0x400 or cave%4 or any(raw[cave:cave+80]):raise ValueError('Injection space not empty')
    for p in range(base+cave,base+cave+80,2):
        if struct.pack('<I',p) in raw or struct.pack('<I',p|1) in raw:raise ValueError('Injection space has a data reference')
    return dict(base=base,hook_offset=site,original_hook_hex=raw[site:site+4].hex(),
                loader=loader|1,setpicture=picture,set_bgcolor=calls[0]|1,
                apply_bgcolor=calls[1]|1,cave_offset=cave,source_sha256=expected_sha)


def trampoline(p):
    """Fixed Thumb code with discovered literal addresses; host-independent.

    Preserve r4/lr, load the logo, stop on load/display failure, then paint the
    background. Return the original loader result. Literals start at byte 40.
    validation.display executes all three paths and checks the ABI.
    """
    body = bytes.fromhex(
        '10b5'      # push {r4, lr}
        '094b9847'  # ldr r3, [pc, #36]; blx r3: loader
        '0446'      # mov r4, r0
        '00280adb'  # cmp r0, #0; blt return
        '074b9847'  # ldr r3, [pc, #28]; blx r3: setpicture
        '002806db'  # cmp r0, #0; blt return
        '002000210022'  # movs r0/r1/r2, #0
        '054b9847'  # ldr r3, [pc, #20]; blx r3: set_bgcolor
        '054b9847'  # ldr r3, [pc, #20]; blx r3: apply_bgcolor
        '204610bd'  # return: mov r0, r4; pop {r4, pc}
        '00bf'      # align literal pool
    )
    pointers = [p[n] for n in ['loader', 'setpicture', 'set_bgcolor', 'apply_bgcolor']]
    if any(not 0 <= address <= 0xffffffff or not address & 1 for address in pointers):
        raise ValueError('Trampoline requires valid Thumb addresses')
    return body + struct.pack('<4I', *pointers)


def apply(raw,p,code):
    site=p['hook_offset'];cave=p['cave_offset']
    if digest(raw)!=p['source_sha256'] or len(code)>80 or any(raw[cave:cave+len(code)]):raise ValueError('Patch precondition changed')
    result=bytearray(raw);result[cave:cave+len(code)]=code
    result[site:site+4]=bl(p['base']+site,p['base']+cave)
    return bytes(result)
