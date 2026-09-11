"""Build the A6/A6X in-memory iBSS/iBEC relay from selected firmware inputs."""
import json
import re
import struct
import tempfile
from pathlib import Path

from common import tools, run, save, digest
from img3 import img3
import devicetree
import logo
from validation import display

FIRST = 0xbfe00000
SECOND = 0xbfe20000
WINDOW = 1048576
RECIPE_VERSION = 9


def movt(register, immediate):
    """Encode Thumb-2 MOVT without a host assembler or an Apple SDK."""
    if not 0 <= register <= 14 or not 0 <= immediate <= 0xffff:
        raise ValueError('Invalid MOVT register/immediate')
    first = 0xf2c0 | (immediate >> 12) | (((immediate >> 11) & 1) << 10)
    second = (((immediate >> 8) & 7) << 12) | (register << 8) | (immediate & 255)
    return struct.pack('<HH', first, second)


def relay_address_register(original, offset):
    """Retain the firmware's MOVT destination when replacing its address.

    The Kit patcher writes a fixed r4 instruction on A6/A6X, but some
    firmware builds keep the image pointer in a different register.
    """
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_REG, ARM_OP_IMM
    if offset < 0 or offset + 4 > len(original):
        raise ValueError('Relay address instruction is outside the image')
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    instruction = list(md.disasm(original[offset:offset + 4], offset))
    if (len(instruction) != 1 or instruction[0].mnemonic != 'movt'
            or instruction[0].size != 4 or len(instruction[0].operands) != 2
            or instruction[0].operands[0].type != ARM_OP_REG
            or instruction[0].operands[1].type != ARM_OP_IMM):
        raise ValueError('Original relay address instruction is not MOVT')
    register = (struct.unpack_from('<H', original, offset + 2)[0] >> 8) & 15
    if register > 14:
        raise ValueError('Invalid relay address register')
    return register


def skip_ramdisk(data):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    base=struct.unpack_from('<I',data,32)[0]-64
    token=b'/boot/ramdisk\0'
    if data.count(token)!=1:
        raise ValueError('Ambiguous ramdisk path')
    pointer=base+data.index(token)
    matches=[]
    for offset in range(0,len(data)-12,2):
        ins=list(md.disasm(data[offset:offset+16],offset))
        if len(ins)<3 or ins[0].mnemonic!='ldr' or not ins[0].op_str.startswith('r0, [pc,'):
            continue
        mem=ins[0].operands[1]
        if mem.type!=ARM_OP_MEM or mem.mem.base!=ARM_REG_PC:
            continue
        literal=((offset+4)&~3)+mem.mem.disp
        if not 0<=literal<=len(data)-4 or struct.unpack_from('<I',data,literal)[0]!=pointer:
            continue
        if ins[1].mnemonic!='bl':
            continue
        if len(ins)>=4 and ins[2].mnemonic=='cmp' and ins[2].op_str=='r0, #0' and ins[3].mnemonic=='bne':
            error=ins[3].operands[0].imm
            if error<=ins[3].address or error>=ins[3].address+128:continue
            load=list(md.disasm(data[error:error+2],error))
            if not load or load[0].mnemonic!='ldr':continue
            mem=load[0].operands[1]
            if mem.type!=ARM_OP_MEM or mem.mem.base!=ARM_REG_PC:continue
            lit=((error+4)&~3)+mem.mem.disp
            string=struct.unpack_from('<I',data,lit)[0]-base
            if not data[string:].startswith(b'failed to load ramdisk\n\0'):continue
            matches.append((ins[3].address,b'\x00\xbf'))
            continue
        if ins[2].mnemonic!='cbz' or ins[2].operands[0].reg!=ins[0].operands[0].reg:continue
        site=ins[2].address;destination=ins[2].operands[1].imm
        if destination!=site+6:
            continue
        matches.append((site,b'\x01\xe0'))
    if len(matches)!=1:
        raise ValueError('Unrecognized optional ramdisk result branch')
    at,replacement=matches[0];result=bytearray(data);result[at:at+2]=replacement
    return bytes(result),dict(offset=at,before=data[at:at+2].hex(),after=replacement.hex())


def literal_ibss(data):
    """Handle the literal-buffer form of the Kit's iBSS dualboot patch."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    base=struct.unpack_from('<I',data,32)[0]-64
    token=b'iBSS ready, asking for DFU...\n\0'
    if data.count(token)!=1:raise ValueError('Ambiguous iBSS ready message')
    pointer=base+data.index(token);matches=[]
    for at in range(0,len(data)-64,2):
        ins=list(md.disasm(data[at:at+64],at))
        if not ins or ins[0].mnemonic!='ldr' or ins[0].op_str.split(',')[0]!='r0':continue
        mem=ins[0].operands[1]
        if mem.type!=ARM_OP_MEM or mem.mem.base!=ARM_REG_PC:continue
        literal=((at+4)&~3)+mem.mem.disp
        if not 0<=literal<=len(data)-4 or struct.unpack_from('<I',data,literal)[0]!=pointer:continue
        for index,i in enumerate(ins):
            tail=ins[index:index+7]
            if len(tail)!=7:continue
            if [t.mnemonic for t in tail]!=['ldr','mov.w','str','str.w','bl','mov','cmp']:continue
            if [t.op_str for t in tail[1:4]]!=['r1, #0x200000','r0, [sp, #0x18]','r8, [sp, #0x14]']:continue
            if [t.op_str for t in tail[5:]]!=['r5, r0','r5, #0']:continue
            m=i.operands[1]
            if m.type!=ARM_OP_MEM or m.mem.base!=ARM_REG_PC:continue
            location=((i.address+4)&~3)+m.mem.disp
            branch=ins[index+7] if index+7<len(ins) else None
            if branch is None or branch.mnemonic!='blt':continue
            if struct.unpack_from('<I',data,location)[0]!=0x9fe00000:continue
            matches.append((location,tail[4].address,branch.address))
    if len(matches)!=1:raise ValueError('Unrecognized literal iBSS receive loop')
    location,call,branch=matches[0];out=bytearray(data)
    struct.pack_into('<I',out,location,SECOND)
    # The preloaded image occupies the receive buffer; keep the parser's bound.
    out[call:call+4]=bytes.fromhex('084600bf') # mov r0,r1; nop
    out[branch:branch+2]=bytes.fromhex('00bf')
    return bytes(out),dict(form='literal',literal=location,usb_call=call,branch=branch,
                           before=hex(0x9fe00000),physical=SECOND)


def prepare(firmware, *, verbose=False):
    firmware=Path(firmware)
    source=json.loads((firmware/'manifest.json').read_text())
    for name,value in source['files'].items():
        if digest(firmware/name)!=value:
            raise ValueError('Firmware input changed: '+name)
    destination=firmware.parent/('relay-verbose' if verbose else 'relay')
    if destination.exists():
        raise ValueError('Prepared relay already exists: '+str(destination))
    out=Path(tempfile.mkdtemp(prefix='relay-pending-',dir=firmware.parent))
    bootargs='rd=disk0s1s3 amfi=0xff cs_enforcement_disable=1'
    if verbose:
        bootargs+=' -v debug=0x14e'
    patches={}
    for name in ('iBSS','iBEC'):
        raw=(firmware/(name+'.raw')).read_bytes()
        patched=out/(name+'.patched.raw')
        use_literal=name=='iBSS' and source['version'].startswith('8.')
        argv=[tools()/'iBoot32Patcher',firmware/(name+'.raw'),patched,'--rsa']
        if not use_literal:argv+=['--dualboot']
        # Match the Kit's iBEC boot path: image RSA admission and the
        # separate boot ticket check both need the selected patcher recipe.
        if name=='iBEC':argv+=['--debug','--ticket','-b',bootargs]
        log=run(argv,out/(name+'.log'),patcher=True).decode()
        data=patched.read_bytes()
        if len(data)!=len(raw):raise ValueError('Bootloader length changed')
        if use_literal:
            data,patches['relay_address']=literal_ibss(data)
        elif name=='iBSS':
            matches=re.findall(r'patch_dualboot_ibss: Found kloader MOV at (0x[0-9a-f]+)',log)
            if len(matches)!=1:raise ValueError('Ambiguous relay address instruction')
            at=int(matches[0],16)
            if data[at:at+4]!=bytes.fromhex('c7f6d074'):
                raise ValueError('Unexpected A6/A6X relay address instruction')
            register=relay_address_register(raw,at)
            replacement=movt(register,SECOND >> 16)
            if len(replacement)!=4:raise ValueError('Invalid MOVT encoding')
            data=data[:at]+replacement+data[at+4:]
            patches['relay_address']=dict(offset=at,before='c7f6d074',after=replacement.hex(),physical=SECOND,register=register,original=raw[at:at+4].hex())
        else:
            data,patches['optional_ramdisk']=skip_ramdisk(data)
            if verbose:
                save(out/'display-validation.json',dict(mode='verbose',logo_hook=False))
            else:
                params=logo.discover(data,logo.digest(data),0x2a0)
                code=logo.trampoline(params)
                (out/'stub.bin').write_bytes(code)
                (out/'iBEC.before-logo.raw').write_bytes(data)
                data=logo.apply(data,params,code)
                patches['logo']=params
                save(out/'display-validation.json',display(data,params))
        patched.write_bytes(data)
    run([tools()/'xpwntool',out/'iBEC.patched.raw',out/'iBEC.img3','-t',firmware/'iBEC.orig'],out/'pack.log')
    container=(out/'iBEC.img3').read_bytes()
    kind,tags,payload=img3(container)
    if kind!='ibec' or 'KBAG' in tags or payload!=(out/'iBEC.patched.raw').read_bytes():
        raise ValueError('iBEC container readback mismatch')
    ibss=(out/'iBSS.patched.raw').read_bytes()
    if len(ibss)>SECOND-FIRST:raise ValueError('iBSS overlaps iBEC')
    relay=ibss+bytes(SECOND-FIRST-len(ibss))+container
    if len(relay)>WINDOW:raise ValueError('Relay exceeds loader memory window')
    (out/'relay.bin').write_bytes(relay)
    raw=(firmware/'DeviceTree.raw').read_bytes();nodes=devicetree.parse(raw)
    root=next(n for n in nodes if n['path']=='/device-tree')
    value=next(p['value'] for p in root['properties'] if p['name']=='firmware-min-capacity')
    raw,_=devicetree.add_property(raw,'/device-tree/defaults','no-effaceable-storage',value)
    paths=[n['path'] for n in nodes if n['path'].endswith('/tristar')]
    if len(paths)==1:
        raw,_=devicetree.add_property(raw,paths[0],'soft-reset',b'')
    (out/'DeviceTree.raw').write_bytes(raw)
    run([tools()/'xpwntool',out/'DeviceTree.raw',out/'devicetree','-t',firmware/'DeviceTree.orig'],out/'tree-pack.log')
    if img3((out/'devicetree').read_bytes())[2]!=raw:raise ValueError('DeviceTree readback mismatch')
    report=dict(recipe_version=RECIPE_VERSION,product=source['product'],version=source['version'],build=source['build'],
                bootargs=bootargs,patches=patches,physical_boot_validated=False,
                files={n:digest(out/n) for n in ['relay.bin','devicetree','iBSS.patched.raw','iBEC.patched.raw','display-validation.json']})
    save(out/'manifest.json',report)
    out.rename(destination)
    return destination,report
