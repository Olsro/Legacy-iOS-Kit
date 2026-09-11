"""Execute both observed image-pointer register layouts before image parsing."""
import importlib.util
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bootchain import movt, relay_address_register


@unittest.skipUnless(importlib.util.find_spec('unicorn'), 'Unicorn unavailable')
class RelayAddressTests(unittest.TestCase):
    def test_pointer_reaches_the_image_consumer_in_both_register_layouts(self):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP
        # Zero pointer, set upper address, pass pointer to the image parser.
        # The r10 form uses a wide MOVW and a wide STR, unlike the r4 form.
        cases = [
            (bytes.fromhex('0024c9f6e07420460394'), 2, 4),
            (bytes.fromhex('40f2000ac9f6e07a5046cdf818a0'), 4, 10),
        ]
        for original, at, expected_register in cases:
            with self.subTest(register=expected_register):
                register = relay_address_register(original, at)
                self.assertEqual(register, expected_register)
                results = []
                for destination in (register, 4):
                    code = original[:at] + movt(destination, 0xbfe2) + original[at+4:]
                    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
                    cpu.mem_map(0x1000, 0x3000)
                    cpu.mem_write(0x1000, code)
                    cpu.reg_write(UC_ARM_REG_SP, 0x3000)
                    cpu.emu_start(0x1001, 0x1000 + len(code), count=20)
                    results.append(cpu.reg_read(UC_ARM_REG_R0))
                    offset = 12 if register == 4 else 24
                    self.assertEqual(struct.unpack('<I', cpu.mem_read(0x3000+offset, 4))[0], results[-1])
                self.assertEqual(results[0], 0xbfe20000)
                if register != 4:
                    self.assertNotEqual(results[1], results[0])

    def test_unrecognized_instruction_is_rejected(self):
        with self.assertRaises(ValueError):
            relay_address_register(bytes.fromhex('002000bf'), 0)
        with self.assertRaises(ValueError):
            relay_address_register(b'', 0)
