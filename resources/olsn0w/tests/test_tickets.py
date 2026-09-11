import plistlib
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tickets import binding, tlv


def ticket(ecid=0x1234, chip=0x8950, board=2):
    fields=b''.join(bytes([0x81+i,n])+v.to_bytes(n,'little') for i,(v,n) in enumerate([(ecid,8),(chip,4),(board,4),(1,4),(1,4)]))
    sequence=b'\x30\x00'+bytes([0x31,len(fields)])+fields
    return plistlib.dumps({'APTicket':bytes([0x30,len(sequence)])+sequence})


class TicketBinding(unittest.TestCase):
    def test_same_model_different_device_rejected(self):
        self.assertEqual(binding(ticket(),'iPhone5,2',0x1234)['ecid'],0x1234)
        with self.assertRaises(ValueError):binding(ticket(),'iPhone5,2',0x5678)
        with self.assertRaises(ValueError):binding(ticket(),'iPhone5,1',0x1234)
        with self.assertRaises(ValueError):binding(ticket(chip=0x8955),'iPhone5,2',0x1234)

    def test_invalid_der_lengths_rejected(self):
        for value in (b'\x30',b'\x30\x80',b'\x30\x81\x00',b'\x30\x02\x00'):
            with self.assertRaises(ValueError):tlv(value,0)
