"""Reject ambiguous and changed recovery identities before any device action."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from device import parse_recovery

FIXTURE = 'PRODUCT: iPhone5,2\nMODEL: n42ap\nCPID: 0x8950\nBDID: 0x02\nECID: 0x1234\nMODE: Recovery\n'


class SelectedDevice(unittest.TestCase):
    def test_matching_device(self):
        self.assertEqual(parse_recovery(FIXTURE, 0x1234)['product'], 'iPhone5,2')

    def test_same_model_different_phone(self):
        with self.assertRaisesRegex(ValueError, 'differs'):
            parse_recovery(FIXTURE, 0x5678)

    def test_duplicate_ecid_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            parse_recovery(FIXTURE + 'ECID: 0x5678\n', 0x5678)

    def test_product_name_does_not_override_chip(self):
        with self.assertRaisesRegex(ValueError, 'chip/board'):
            parse_recovery(FIXTURE.replace('0x8950', '0x8955'))


class HardwareBinding(unittest.TestCase):
    def test_mode_transition_preserves_hardware_binding(self):
        from device import same_hardware
        base=dict(ecid=1,product='iPhone5,2',board='n42ap',chip=0x8950,board_id=2,mode='Recovery')
        self.assertTrue(same_hardware(base,dict(base,mode='DFU')))
        self.assertFalse(same_hardware(base,dict(base,ecid=2)))
        self.assertFalse(same_hardware({},{}))
