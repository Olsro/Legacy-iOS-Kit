"""Bounded interpreter for the Thumb-1 instructions in the logo trampoline.

No native JIT or executable host mapping is needed. Unknown instructions,
out-of-range accesses and control flow outside the stub are rejected.
"""
import struct


class Thumb:
    STACK_START = 0x10000000
    STACK_END = 0x10010000

    def __init__(self, raw, base):
        self.raw, self.base = raw, base
        self.regs = [0] * 16
        self.stack = {}
        self.negative = self.overflow = False

    def read_word(self, address):
        if address in self.stack:
            return self.stack[address]
        offset = address - self.base
        if address % 4 or not 0 <= offset <= len(self.raw) - 4:
            raise ValueError('Logo trampoline reads outside its image or stack')
        return struct.unpack_from('<I', self.raw, offset)[0]

    def push_word(self, address, value):
        if address % 4 or not self.STACK_START <= address < self.STACK_END:
            raise ValueError('Logo trampoline writes outside its stack')
        self.stack[address] = value

    def run(self, start, stop, end, invoke, limit=1000):
        pc = start
        for _ in range(limit):
            if pc == stop:
                return
            offset = pc - self.base
            if pc % 2 or not start <= pc < end or not 0 <= offset <= len(self.raw) - 2:
                raise ValueError('Logo trampoline leaves its code region')
            op = struct.unpack_from('<H', self.raw, offset)[0]
            following = pc + 2
            if op & 0xfe00 == 0xb400:  # PUSH {r0-r7, lr}
                registers = [r for r in range(8) if op & (1 << r)]
                if op & 0x100:
                    registers.append(14)
                self.regs[13] -= 4 * len(registers)
                for index, register in enumerate(registers):
                    self.push_word(self.regs[13] + index * 4, self.regs[register])
            elif op & 0xfe00 == 0xbc00:  # POP {r0-r7, pc}
                registers = [r for r in range(8) if op & (1 << r)]
                if op & 0x100:
                    registers.append(15)
                for index, register in enumerate(registers):
                    self.regs[register] = self.read_word(self.regs[13] + index * 4)
                self.regs[13] += 4 * len(registers)
                if 15 in registers:
                    if not self.regs[15] & 1:
                        raise ValueError('Logo trampoline returns outside Thumb mode')
                    following = self.regs[15] & ~1
            elif op & 0xf800 == 0x4800:  # LDR Rt, [pc, #imm]
                self.regs[(op >> 8) & 7] = self.read_word(((pc + 4) & ~3) + (op & 255) * 4)
            elif op & 0xff00 == 0x4600:  # MOV Rd, Rm (without flags)
                destination, source = (op & 7) | ((op >> 4) & 8), (op >> 3) & 15
                if 15 in (destination, source):
                    raise ValueError('Unsupported logo trampoline PC move')
                self.regs[destination] = self.regs[source]
            elif op & 0xf800 == 0x2800:  # CMP Rn, #imm
                left, right = self.regs[(op >> 8) & 7], op & 255
                difference = (left - right) & 0xffffffff
                self.negative = bool(difference & 0x80000000)
                self.overflow = bool((left ^ right) & (left ^ difference) & 0x80000000)
            elif op & 0xff00 == 0xdb00:  # BLT: signed less-than, N != V
                if self.negative != self.overflow:
                    immediate = op & 255
                    following = pc + 4 + (immediate if immediate < 128 else immediate - 256) * 2
            elif op & 0xf800 == 0x2000:  # MOVS Rd, #imm; V is unchanged
                self.regs[(op >> 8) & 7] = op & 255
                self.negative = False
            elif op & 0xff87 == 0x4780:  # BLX Rm, with an intercepted stock call
                target = self.regs[(op >> 3) & 15]
                if not target & 1:
                    raise ValueError('Logo trampoline calls outside Thumb mode')
                self.regs[14] = following | 1
                invoke(self, target & ~1)
            elif op != 0xbf00:  # NOP
                raise ValueError('Unsupported logo trampoline instruction: ' + hex(op))
            pc = following
        raise ValueError('Logo trampoline exceeded its instruction limit')
