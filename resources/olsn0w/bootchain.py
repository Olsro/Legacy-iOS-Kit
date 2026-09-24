"""Build a model-qualified 32-bit in-memory iBSS/iBEC relay."""
import json
import re
import struct
import tempfile
from pathlib import Path

from common import profile, tools, run, save, digest, version
from img3 import img3
import devicetree
import logo
from validation import display

WINDOW = 1048576
RECIPE_VERSION = 24


def memory_layout(product):
    """Return the actual loader destinations, not the patcher's defaults."""
    family = profile(product)['soc']
    if family.startswith('a5'):
        # multi_kloader loads independent images; iBEC precedes iBSS by 1 MiB.
        first = 0xbfe00000 if family == 'a5x' else 0x9fe00000
        return first, first - WINDOW
    if family in ('a6', 'a6x'):
        return 0xbfe00000, 0xbfe20000
    raise ValueError('No relay memory layout for selected product')


def uses_tristar_soft_reset(product, release):
    """Apply the reset only to release families selected by the model profile."""
    return version(release)[0] in profile(product).get('tristar_soft_reset_majors', ())


def movt(register, immediate):
    """Encode Thumb-2 MOVT without a host assembler or an Apple SDK."""
    if not 0 <= register <= 14 or not 0 <= immediate <= 0xffff:
        raise ValueError('Invalid MOVT register/immediate')
    first = 0xf2c0 | (immediate >> 12) | (((immediate >> 11) & 1) << 10)
    second = (((immediate >> 8) & 7) << 12) | (register << 8) | (immediate & 255)
    return struct.pack('<HH', first, second)


def dualboot_patcher_marker(product, register, first):
    """Return the exact address instruction emitted by iBoot32Patcher.

    iBoot32Patcher emits a fixed-r4 marker for both its A5-family recipe and
    its A6/A6X recipe.  olsn0w must validate that exact marker before restoring
    the firmware's real register and selected relay address.
    """
    family=profile(product)['soc']
    if family.startswith('a5'):return movt(4,0xbfd0)
    if family in ('a6','a6x'):return bytes.fromhex('c7f6d074')
    raise ValueError('No dualboot patcher contract for selected product')


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


def preserve_upgrade_autoboot(data):
    """Keep a transient target boot failure retryable by the signed base.

    The dualboot patch selects iBEC's stock ``upgrade`` command. That command
    persists ``auto-boot=false`` before loading the alternate system, so one
    failed target attempt makes the following hardware boot stop in Recovery.
    Retarget only the qualified false-string literal used by that write, or
    validate it byte-identically when the dualboot patcher already retargeted
    it. The PMU boot/panic counters remain untouched and are still
    acknowledged only after a stable SpringBoard by the target boot-success
    job.
    """
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from capstone.arm import (ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC,
                              ARM_REG_R0, ARM_REG_R1, ARM_REG_R2)
    data=bytes(data)
    if len(data)<64:
        raise ValueError('iBEC is too small for the upgrade auto-boot recipe')
    base=struct.unpack_from('<I',data,32)[0]-64
    tokens={}
    for name,token in [('auto_boot',b'auto-boot\0'),('false',b'false\0'),('true',b'true\0')]:
        locations=[at for at in range(len(data)) if data.startswith(token,at)]
        if len(locations)!=1:
            raise ValueError('Ambiguous iBEC '+name.replace('_',' ')+' string')
        tokens[name]=base+locations[0]

    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    matches=[]
    for at in range(0,len(data)-24,2):
        instructions=list(md.disasm(data[at:at+24],at))
        if not instructions:
            continue
        first=instructions[0]
        if (first.mnemonic!='ldr' or len(first.operands)!=2
                or first.operands[0].type!=ARM_OP_REG or first.operands[0].reg!=ARM_REG_R0
                or first.operands[1].type!=ARM_OP_MEM or first.operands[1].mem.base!=ARM_REG_PC):
            continue
        auto_literal=((first.address+4)&~3)+first.operands[1].mem.disp
        if (not 0<=auto_literal<=len(data)-4
                or struct.unpack_from('<I',data,auto_literal)[0]!=tokens['auto_boot']):
            continue
        persist=False;value_literal=None;value=None
        for instruction in instructions[1:6]:
            if instruction.mnemonic=='bl':
                break
            if (instruction.mnemonic.startswith('mov') and len(instruction.operands)==2
                    and instruction.operands[0].type==ARM_OP_REG
                    and instruction.operands[0].reg==ARM_REG_R2
                    and instruction.operands[1].type==ARM_OP_IMM
                    and instruction.operands[1].imm==1):
                persist=True
            if (instruction.mnemonic=='ldr' and len(instruction.operands)==2
                    and instruction.operands[0].type==ARM_OP_REG
                    and instruction.operands[0].reg==ARM_REG_R1
                    and instruction.operands[1].type==ARM_OP_MEM
                    and instruction.operands[1].mem.base==ARM_REG_PC):
                literal=((instruction.address+4)&~3)+instruction.operands[1].mem.disp
                if 0<=literal<=len(data)-4:
                    pointer=struct.unpack_from('<I',data,literal)[0]
                    if pointer==tokens['false']:
                        value_literal=literal;value='false'
                    elif pointer==tokens['true']:
                        value_literal=literal;value='true'
        if persist and value_literal is not None:
            matches.append((at,value_literal,value))
    if len(matches)!=1:
        if matches:
            raise ValueError('Ambiguous persistent upgrade auto-boot write')
        # Later iBECs remove the transient boot-command and save the
        # environment instead of persisting auto-boot=false. Validate that
        # known handler shape and leave it byte-identical.
        for name,token in [('upgrade',b'upgrade\0'),('boot_command',b'boot-command\0')]:
            locations=[at for at in range(len(data)) if data.startswith(token,at)]
            if len(locations)!=1:
                raise ValueError('Ambiguous iBEC '+name.replace('_',' ')+' string')
            tokens[name]=base+locations[0]
        command_entries=[]
        for at in range(len(data)-8):
            if not data.startswith(struct.pack('<I',tokens['upgrade']),at):
                continue
            candidate=struct.unpack_from('<I',data,at+4)[0]
            offset=(candidate&~1)-base
            # The dualboot patch adds another reference to the upgrade
            # string beside the fsboot literal.  It is not a command-table
            # entry: its following word is not a Thumb handler in this iBEC.
            if candidate&1 and 0<=offset<=len(data)-32:
                command_entries.append((at,offset))
        if len(command_entries)!=1:
            raise ValueError('Unrecognized iBEC upgrade command entry')
        _,handler=command_entries[0]
        instructions=list(md.disasm(data[handler:handler+32],handler))
        boot_load=None
        for index,instruction in enumerate(instructions[:4]):
            if (instruction.mnemonic=='ldr' and len(instruction.operands)==2
                    and instruction.operands[0].type==ARM_OP_REG
                    and instruction.operands[0].reg==ARM_REG_R0
                    and instruction.operands[1].type==ARM_OP_MEM
                    and instruction.operands[1].mem.base==ARM_REG_PC):
                literal=((instruction.address+4)&~3)+instruction.operands[1].mem.disp
                if (0<=literal<=len(data)-4
                        and struct.unpack_from('<I',data,literal)[0]==tokens['boot_command']):
                    boot_load=index
                    break
        calls=[index for index,instruction in enumerate(instructions[:7])
               if instruction.mnemonic=='bl']
        if (not instructions or instructions[0].mnemonic!='push' or boot_load is None
                or len(calls)<2 or calls[0]<=boot_load or calls[1]!=calls[0]+1):
            raise ValueError('Unrecognized non-disarming upgrade command')
        return data,dict(instruction=handler,form='transient-boot-command',persistent=False)
    instruction,literal,value=matches[0]
    before=data[literal:literal+4]
    after=struct.pack('<I',tokens['true'])
    if value=='true':
        return data,dict(instruction=instruction,literal=literal,
                         before=before.hex(),after=after.hex(),
                         form='persistent-auto-boot',persistent=True,
                         already_rearmed=True)
    result=data[:literal]+after+data[literal+4:]
    if (result[literal:literal+4]!=after or result[:literal]!=data[:literal]
            or result[literal+4:]!=data[literal+4:]):
        raise ValueError('Upgrade auto-boot patch changed unexpected bytes')
    return result,dict(instruction=instruction,literal=literal,
                       before=before.hex(),after=after.hex(),
                       form='persistent-auto-boot',persistent=True,
                       already_rearmed=False)


def literal_ibss(data, second, *, stock_buffer=0x9fe00000):
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
            if struct.unpack_from('<I',data,location)[0]!=stock_buffer:continue
            matches.append((location,tail[4].address,branch.address))
    if len(matches)!=1:raise ValueError('Unrecognized literal iBSS receive loop')
    location,call,branch=matches[0];out=bytearray(data)
    struct.pack_into('<I',out,location,second)
    # The preloaded image occupies the receive buffer; keep the parser's bound.
    out[call:call+4]=bytes.fromhex('084600bf') # mov r0,r1; nop
    out[branch:branch+2]=bytes.fromhex('00bf')
    return bytes(out),dict(form='literal',literal=location,usb_call=call,branch=branch,
                           before=hex(stock_buffer),physical=second)


def preloaded_ibss_length(original, data, log):
    """The receive-call replacement must return a length, not the buffer VA."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    matches=re.findall(r'patch_dualboot_ibss: Found usb_wait_for_image\(\) at (0x[0-9a-f]+)',log)
    if len(matches)!=1:raise ValueError('Ambiguous iBSS receive call')
    at=int(matches[0],16)
    ins=list(md.disasm(original[at:at+10],at))
    # The image-pointer store is 16-bit for r4 and 32-bit for r10 (iOS 7).
    prior=[]
    for distance in (10,12):
        if at<distance:continue
        candidate=list(md.disasm(original[at-distance:at],at-distance))
        if (candidate and candidate[0].mnemonic=='mov.w'
                and candidate[0].op_str=='r1, #0x200000'
                and candidate[-1].address+candidate[-1].size==at):prior.append(candidate)
    if (len(ins)!=4 or [i.mnemonic for i in ins]!=['bl','mov','cmp','blt']
            or ins[1].op_str.split(', ')[-1]!='r0'
            or ins[2].op_str!=ins[1].op_str.split(',')[0]+', #0'
            or len(prior)!=1
            or data[at:at+4]!=bytes.fromhex('00bf00bf')
            or data[at+8:at+10]!=bytes.fromhex('00bf')):
        raise ValueError('Unrecognized iBSS preloaded-image length contract')
    result=data[:at]+bytes.fromhex('084600bf')+data[at+4:]
    return result,dict(offset=at,before='00bf00bf',after='084600bf',length=2*WINDOW)


def ram_autoboot(data):
    """Force only this RAM iBEC's startup decision; never write NVRAM."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    token=b'auto-boot\0'
    if data.count(token)!=1:raise ValueError('Ambiguous RAM iBEC auto-boot string')
    base=struct.unpack_from('<I',data,32)[0]-64
    pointer=base+data.index(token);matches=[]
    for at in range(0,len(data)-48,2):
        # Narrow to Thumb literal LDR r0 before disassembling.
        if data[at+1]!=0x48:continue
        ins=list(md.disasm(data[at:at+48],at))
        if not ins or ins[0].mnemonic!='ldr':continue
        mem=ins[0].operands[1]
        if mem.type!=ARM_OP_MEM or mem.mem.base!=ARM_REG_PC:continue
        literal=((at+4)&~3)+mem.mem.disp
        if not 0<=literal<=len(data)-4 or struct.unpack_from('<I',data,literal)[0]!=pointer:continue
        if len(ins)<6 or ins[1].mnemonic!='movs' or ins[1].op_str!='r1, #0':continue
        call=next((j for j in range(2,min(5,len(ins))) if ins[j].mnemonic=='bl'),None)
        if call is None or ins[call+1].mnemonic!='mov':continue
        reg,value=ins[call+1].op_str.split(', ')
        if value!='r0':continue
        if not any(i.mnemonic=='cmp' and i.op_str==reg+', #1' for i in ins[call+2:]):continue
        matches.append(ins[call].address)
    if len(matches)!=1:raise ValueError('Unrecognized RAM iBEC startup auto-boot decision')
    at=matches[0];replacement=bytes.fromhex('012000bf')
    return data[:at]+replacement+data[at+4:],dict(offset=at,before=data[at:at+4].hex(),after=replacement.hex(),persistent=False)


def target_bootargs(*, verbose=False):
    """Normal A5/A6 boots are graphical; diagnostics must be requested."""
    args = 'rd=disk0s1s3 amfi=0xff cs_enforcement_disable=1'
    return args + (' -v debug=0x14e' if verbose else '')


def prepare_display(data, out, *, verbose=False):
    """Use the same checked logo hook for normal boots on every SoC."""
    if verbose:
        save(out/'display-validation.json', dict(mode='verbose', logo_hook=False))
        return data, None
    params = logo.discover(data, logo.digest(data), 0x2a0)
    code = logo.trampoline(params)
    (out/'stub.bin').write_bytes(code)
    (out/'iBEC.before-logo.raw').write_bytes(data)
    data = logo.apply(data, params, code)
    save(out/'display-validation.json', display(data, params))
    return data, params


def prepare(firmware, *, verbose=False):
    firmware=Path(firmware)
    source=json.loads((firmware/'manifest.json').read_text())
    selected_profile=profile(source['product'])
    first,second=memory_layout(source['product'])
    for name,value in source['files'].items():
        if digest(firmware/name)!=value:
            raise ValueError('Firmware input changed: '+name)
    destination=firmware.parent/('relay-verbose' if verbose else 'relay')
    if destination.exists():
        raise ValueError('Prepared relay already exists: '+str(destination))
    out=Path(tempfile.mkdtemp(prefix='relay-pending-',dir=firmware.parent))
    bootargs=target_bootargs(verbose=verbose)
    patches={}
    for name in ('iBSS','iBEC'):
        raw=(firmware/(name+'.raw')).read_bytes()
        patched=out/(name+'.patched.raw')
        # iOS 8 uses a literal receive buffer on both A5 and A6. The Kit's
        # MOVT-only dualboot iBSS patch cannot recognize the A5 literal either.
        use_literal=(name=='iBSS' and version(source['version'])[0] == 8)
        argv=[tools()/'iBoot32Patcher',firmware/(name+'.raw'),patched,'--rsa']
        if not use_literal:argv+=['--dualboot']
        # Match the Kit's iBEC boot path: image RSA admission and the
        # separate boot ticket check both need the selected patcher recipe.
        if name=='iBEC':argv+=['--debug','--ticket','-b',bootargs]
        log=run(argv,out/(name+'.log'),patcher=True).decode()
        data=patched.read_bytes()
        if len(data)!=len(raw):raise ValueError('Bootloader length changed')
        if use_literal:
            data,patches['relay_address']=literal_ibss(data,second,
                stock_buffer=0x8fe00000 if selected_profile['soc'].startswith('a5') else 0x9fe00000)
        elif name=='iBSS':
            matches=re.findall(r'patch_dualboot_ibss: Found kloader MOV at (0x[0-9a-f]+)',log)
            if len(matches)!=1:raise ValueError('Ambiguous relay address instruction')
            at=int(matches[0],16)
            register=relay_address_register(raw,at)
            expected=dualboot_patcher_marker(source['product'],register,first)
            if data[at:at+4]!=expected:
                raise ValueError('Dualboot patch selected an unexpected relay address')
            replacement=movt(register,second >> 16)
            if len(replacement)!=4:raise ValueError('Invalid MOVT encoding')
            data=data[:at]+replacement+data[at+4:]
            patches['relay_address']=dict(offset=at,before=expected.hex(),after=replacement.hex(),
                                          physical=second,register=register,
                                          original=raw[at:at+4].hex())
            if selected_profile['soc'].startswith('a5'):
                data,patches['preloaded_length']=preloaded_ibss_length(raw,data,log)
        else:
            data,patches['optional_ramdisk']=skip_ramdisk(data)
            data,patches['upgrade_autoboot']=preserve_upgrade_autoboot(data)
            if selected_profile['soc'].startswith('a5'):
                data,patches['ram_autoboot']=ram_autoboot(data)
            data, params = prepare_display(data, out, verbose=verbose)
            if params is not None:
                patches['logo']=params
        patched.write_bytes(data)
    run([tools()/'xpwntool',out/'iBEC.patched.raw',out/'iBEC.img3','-t',firmware/'iBEC.orig'],out/'pack.log')
    container=(out/'iBEC.img3').read_bytes()
    kind,tags,payload=img3(container)
    if kind!='ibec' or 'KBAG' in tags or payload!=(out/'iBEC.patched.raw').read_bytes():
        raise ValueError('iBEC container readback mismatch')
    ibss=(out/'iBSS.patched.raw').read_bytes()
    separate=selected_profile['soc'].startswith('a5')
    # Keep a canonical bundle for cache identity. On A5 only the separately
    # verified files are loaded; this bundle is NOT a contiguous memory image.
    stride=0x20000 if separate else second-first
    if len(ibss)>stride:raise ValueError('iBSS overlaps iBEC')
    relay=ibss+bytes(stride-len(ibss))+container
    if len(relay)>WINDOW:raise ValueError('Relay exceeds loader memory window')
    (out/'relay.bin').write_bytes(relay)
    raw=(firmware/'DeviceTree.raw').read_bytes();nodes=devicetree.parse(raw)
    root=next(n for n in nodes if n['path']=='/device-tree')
    value=next(p['value'] for p in root['properties'] if p['name']=='firmware-min-capacity')
    raw,_=devicetree.add_property(raw,'/device-tree/defaults','no-effaceable-storage',value)
    if uses_tristar_soft_reset(source['product'], source['version']):
        paths=[n['path'] for n in nodes if n['path'].endswith('/tristar')]
        if len(paths)!=1:
            raise ValueError('Qualified TriStar node is missing or ambiguous')
        raw,_=devicetree.add_property(raw,paths[0],'soft-reset',b'')
    (out/'DeviceTree.raw').write_bytes(raw)
    run([tools()/'xpwntool',out/'DeviceTree.raw',out/'devicetree','-t',firmware/'DeviceTree.orig'],out/'tree-pack.log')
    if img3((out/'devicetree').read_bytes())[2]!=raw:raise ValueError('DeviceTree readback mismatch')
    report=dict(recipe_version=RECIPE_VERSION,product=source['product'],version=source['version'],build=source['build'],
                bootargs=bootargs,loader=('a5-two-image' if separate else 'contiguous'),
                relay_memory=dict(first=first,second=second,window=WINDOW),
                patches=patches,physical_boot_validated=False,
                files={n:digest(out/n) for n in ['relay.bin','devicetree','iBSS.patched.raw','iBEC.patched.raw','iBEC.img3','display-validation.json']})
    save(out/'manifest.json',report)
    out.rename(destination)
    return destination,report
