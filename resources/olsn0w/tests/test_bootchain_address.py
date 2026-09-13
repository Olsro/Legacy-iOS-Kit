"""Execute both observed image-pointer register layouts before image parsing."""
import importlib.util
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bootchain import (dualboot_patcher_marker, memory_layout, movt, relay_address_register,
                       uses_tristar_soft_reset)
from common import MODEL_PROFILES


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

    def test_patcher_markers_keep_distinct_a5_and_a6_contracts(self):
        self.assertEqual(
            dualboot_patcher_marker('iPhone4,1',4,0xbfd00000),
            movt(4,0xbfd0))
        # The A6/A6X patcher marker is intentionally r4 even when the source
        # firmware carries the image pointer in r10. olsn0w replaces it only
        # after validating this exact output.
        self.assertEqual(
            dualboot_patcher_marker('iPad3,4',10,0xbfe00000),
            bytes.fromhex('c7f6d074'))

    def test_every_a5_variant_uses_the_a5_relay_contract(self):
        products=[product for product,selected in MODEL_PROFILES.items()
                  if selected['soc'].startswith('a5')]
        self.assertIn('iPod5,1',products)
        self.assertIn('iPad3,1',products)
        for product in products:
            with self.subTest(product=product):
                self.assertEqual(memory_layout(product),(0xbfd00000,0xbfd20000))
                self.assertEqual(dualboot_patcher_marker(product,4,0xbfd00000),
                                 movt(4,0xbfd0))
                self.assertFalse(uses_tristar_soft_reset(product,'6.1.3'))

    def test_tristar_reset_stays_on_explicitly_qualified_releases(self):
        ios6_releases = {
            'iPhone5,1': ('6.0', '6.0.1', '6.0.2', '6.1', '6.1.2', '6.1.3', '6.1.4'),
            'iPhone5,2': ('6.0', '6.0.1', '6.0.2', '6.1', '6.1.2', '6.1.3', '6.1.4'),
            'iPad3,4': ('6.0', '6.0.1', '6.1', '6.1.2', '6.1.3'),
            'iPad3,5': ('6.0.1', '6.1', '6.1.2', '6.1.3'),
            'iPad3,6': ('6.0.1', '6.1', '6.1.2', '6.1.3'),
        }
        for product, versions in ios6_releases.items():
            for release in versions:
                self.assertTrue(uses_tristar_soft_reset(product, release),
                                (product, release))
        ios7_releases = ('7.0', '7.0.2', '7.0.3', '7.0.4', '7.0.6',
                         '7.1', '7.1.1', '7.1.2')
        for product in ('iPad3,4', 'iPad3,5', 'iPad3,6'):
            for release in ios7_releases:
                self.assertTrue(uses_tristar_soft_reset(product, release),
                                (product, release))
        for product in ('iPhone5,1', 'iPhone5,2'):
            self.assertFalse(uses_tristar_soft_reset(product, '7.0'))
            self.assertFalse(uses_tristar_soft_reset(product, '7.1.2'))
        for product in ('iPhone5,1', 'iPhone5,2', 'iPad3,4', 'iPad3,5', 'iPad3,6'):
            self.assertFalse(uses_tristar_soft_reset(product, '8.0'))
            self.assertFalse(uses_tristar_soft_reset(product, '8.4.1'))
        self.assertFalse(uses_tristar_soft_reset('iPhone4,1', '6.1.3'))
