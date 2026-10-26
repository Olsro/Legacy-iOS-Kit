"""Exercise the generated logo trampoline before accepting a prepared relay."""
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from thumb_validation import Thumb


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
        machine = Thumb(raw, base)
        machine.regs[13] = 0x10008000
        # The checked BL enters the cave in Thumb mode and sets its return LR.
        machine.regs[14] = (site + 4) | 1
        path = base + raw.index(b'/boot/applelogo\0')
        machine.regs[0] = path
        machine.regs[1] = 0x6c6f676f
        registers = list(range(4, 12))
        initial = [0x12340000 + i for i in range(len(registers))]
        for register, value in zip(registers, initial):
            machine.regs[register] = value
        calls = []
        targets = {params[n] & ~1: n for n in
                   ['loader', 'setpicture', 'set_bgcolor', 'apply_bgcolor']}

        def invoke(cpu, address):
            require(address in targets, 'Logo trampoline calls an unexpected function')
            name = targets[address]
            calls.append(name)
            if name == 'loader':
                require(cpu.regs[0] == path and
                        cpu.regs[1] == 0x6c6f676f, 'Logo load arguments changed')
            if name == 'set_bgcolor':
                require(all(cpu.regs[r] == 0 for r in (0, 1, 2)),
                        'Logo background arguments changed')
            value = load_result if name == 'loader' else picture_result if name == 'setpicture' else 0
            cpu.regs[0] = value & 0xffffffff

        cave = base + params['cave_offset']
        machine.run(cave, site + 4, cave + 40, invoke)
        expected = ['loader'] if load_result < 0 else ['loader', 'setpicture'] if picture_result < 0 else list(targets.values())
        require(calls == expected, 'Logo trampoline control flow failed')
        require(machine.regs[13] == 0x10008000 and
                machine.regs[0] == load_result & 0xffffffff and
                [machine.regs[r] for r in registers] == initial,
                'Logo trampoline changed preserved registers or stack')
        results.append(dict(loader_result=load_result, picture_result=picture_result,
                            calls=calls, registers_and_stack_preserved=True))
    return dict(trampoline_cases=results, physical_display_validated=False)
