"""Independent Unicorn reference for testing the portable logo interpreter.

Retain the original native execution checks as a test oracle. Production
validation must not import this module or create a native JIT mapping.
"""
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_SP, UC_ARM_REG_PC, UC_ARM_REG_LR,
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R4, UC_ARM_REG_R5,
    UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10,
    UC_ARM_REG_R11)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def display(raw, params):
    base = params['base']
    site = base + params['hook_offset']
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    call = next(decoder.disasm(raw[params['hook_offset']:params['hook_offset']+4], site), None)
    require(call is not None and call.mnemonic == 'bl' and
            call.operands[0].imm & 0xffffffff == base + params['cave_offset'],
            'Logo hook does not call the generated trampoline')
    results = []
    for load_result, picture_result in [(0, 0), (-1, 0), (0, -1)]:
        machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        machine.mem_map(base, (len(raw) + 4095) & ~4095)
        machine.mem_write(base, raw)
        machine.mem_map(0x10000000, 0x10000)
        machine.reg_write(UC_ARM_REG_SP, 0x10008000)
        path = base + raw.index(b'/boot/applelogo\0')
        machine.reg_write(UC_ARM_REG_R0, path)
        machine.reg_write(UC_ARM_REG_R1, 0x6c6f676f)
        registers = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                     UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11]
        initial = [0x12340000 + i for i in range(len(registers))]
        for register, value in zip(registers, initial):
            machine.reg_write(register, value)
        calls, returned = [], []
        targets = {params[n] & ~1: n for n in
                   ['loader', 'setpicture', 'set_bgcolor', 'apply_bgcolor']}

        def hook(uc, address, size, user):
            if address == site + 4:
                returned.append(True)
                uc.emu_stop()
                return
            if address not in targets:
                return
            name = targets[address]
            calls.append(name)
            if name == 'loader':
                require(uc.reg_read(UC_ARM_REG_R0) == path and
                        uc.reg_read(UC_ARM_REG_R1) == 0x6c6f676f, 'Logo load arguments changed')
            if name == 'set_bgcolor':
                require(all(uc.reg_read(r) == 0 for r in
                            [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2]),
                        'Logo background arguments changed')
            value = load_result if name == 'loader' else picture_result if name == 'setpicture' else 0
            uc.reg_write(UC_ARM_REG_R0, value & 0xffffffff)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

        machine.hook_add(UC_HOOK_CODE, hook)
        machine.emu_start(site | 1, base + len(raw), count=1000)
        expected = ['loader'] if load_result < 0 else ['loader', 'setpicture'] if picture_result < 0 else list(targets.values())
        require(calls == expected and returned, 'Logo trampoline control flow failed')
        require(machine.reg_read(UC_ARM_REG_SP) == 0x10008000 and
                machine.reg_read(UC_ARM_REG_R0) == load_result & 0xffffffff and
                [machine.reg_read(r) for r in registers] == initial,
                'Logo trampoline changed preserved registers or stack')
        results.append(dict(loader_result=load_result, picture_result=picture_result,
                            calls=calls, registers_and_stack_preserved=True))
    return dict(trampoline_cases=results, physical_display_validated=False)
