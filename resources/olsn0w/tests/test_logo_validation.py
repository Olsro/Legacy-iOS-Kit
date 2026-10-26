"""Portable logo execution must agree with an independent native ARM emulator."""
import importlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import logo
import validation
from thumb_validation import Thumb
from unicorn_logo_reference import display as native_display
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R1


def fixture(base=0xbff00000, cave=0x2a0):
    params = dict(base=base, hook_offset=0x400, cave_offset=cave,
                  loader=base+0x601, setpicture=base+0x621,
                  set_bgcolor=base+0x641, apply_bgcolor=base+0x661)
    raw = bytearray(4096)
    path = b'/boot/applelogo\0'
    raw[0x100:0x100+len(path)] = path
    code = logo.trampoline(params)
    raw[cave:cave+len(code)] = code
    raw[0x400:0x404] = logo.bl(base+0x400, base+cave)
    return bytes(raw), params


class PortableLogoValidation(unittest.TestCase):
    def test_all_three_paths_match_unicorn_across_loader_addresses(self):
        for base in (0x80000000, 0x9ff00000, 0xbff00000):
            for cave in (0x200, 0x2a0):
                with self.subTest(base=hex(base), cave=hex(cave)):
                    raw, params = fixture(base, cave)
                    self.assertEqual(validation.display(raw, params), native_display(raw, params))

    def test_validation_runs_when_the_native_emulator_is_unavailable(self):
        raw, params = fixture()
        expected = native_display(raw, params)
        with patch.dict(sys.modules, {'unicorn': None, 'unicorn.arm_const': None}):
            importlib.reload(validation)
            self.assertEqual(validation.display(raw, params), expected)

    def test_corrupt_control_flow_literals_arguments_and_preserved_state_are_rejected(self):
        raw, params = fixture()
        cave = params['cave_offset']
        mutations = (
            (0x400, bytes.fromhex('00bf00bf')),  # hook is no longer BL
            (cave, bytes.fromhex('00bf')),       # no saved r4/lr
            (cave+2, bytes.fromhex('004b')),     # wrong loader literal
            (cave+10, bytes.fromhex('00bf')),    # loader failure is ignored
            (cave+18, bytes.fromhex('00bf')),    # display failure is ignored
            (cave+20, bytes.fromhex('0120')),    # nonzero background argument
            (cave+36, bytes.fromhex('00bf')),    # missing return
            (cave+40, struct.pack('<I', params['base']+0x701)),  # unknown call
        )
        for offset, replacement in mutations:
            with self.subTest(offset=hex(offset)):
                changed = raw[:offset] + replacement + raw[offset+len(replacement):]
                with self.assertRaises((ValueError, UcError)):
                    native_display(changed, params)
                with self.assertRaises(ValueError):
                    validation.display(changed, params)

    def test_signed_comparison_matches_arm_overflow_semantics(self):
        base = 0x80000000
        # ldr r0, [pc, #8]; cmp r0, #1; blt stop; movs r1, #1
        code = bytes.fromhex('0248012800db012100bf00bf')
        for value in (0, 1, 0xffffffff, 0x80000000, 0x7fffffff):
            with self.subTest(value=hex(value)):
                raw = code + struct.pack('<I', value)
                cpu = Thumb(raw, base)
                cpu.run(base, base+8, base+8, lambda *_: self.fail('unexpected call'))
                native = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
                native.mem_map(base, 4096)
                native.mem_write(base, raw)
                native.emu_start(base | 1, base+8, count=1000)
                self.assertEqual(cpu.regs[1], native.reg_read(UC_ARM_REG_R1))

    def test_unknown_instructions_out_of_bounds_and_loops_are_rejected(self):
        base = 0x80000000
        for raw, limit in ((bytes.fromhex('00de'), 1000),  # undefined instruction
                           (bytes.fromhex('0048'), 1000),  # unmapped literal
                           (bytes.fromhex('002801db'), 1000),  # branch outside code
                           (bytes.fromhex('0028fddb'), 5)):  # bounded BLT loop
            with self.subTest(raw=raw.hex()):
                cpu = Thumb(raw, base)
                cpu.regs[0] = 0xffffffff
                with self.assertRaises(ValueError):
                    cpu.run(base, base+0x100, base+len(raw), lambda *_: None, limit=limit)

    def test_stack_accesses_are_bounded(self):
        cpu = Thumb(b'', 0x80000000)
        with self.assertRaises(ValueError):
            cpu.push_word(Thumb.STACK_START-4, 0)
        with self.assertRaises(ValueError):
            cpu.read_word(Thumb.STACK_START)


if __name__ == '__main__':
    unittest.main()
