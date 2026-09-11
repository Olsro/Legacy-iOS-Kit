"""Exercise string-based ASR selection with a relocatable synthetic Mach-O."""
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from asr_patch import patch
from bootchain import movt


def fixture(base=0x4000, shift=0):
    data=bytearray(1024)
    struct.pack_into('<7I',data,0,0xfeedface,12,9,2,1,56,0)
    struct.pack_into('<II16s8I',data,28,1,56,b'__TEXT',base,1024,0,1024,7,5,0,0)
    for start,pos,label in ((128+shift,512,'passed'),(200+shift,600,'failed')):
        message=('Image '+label+' signature verification').encode()+b'\0'
        data[pos:pos+len(message)]=message
        immediate=pos-start-12
        first=0xf240 | immediate>>12 | ((immediate>>11)&1)<<10
        second=((immediate>>8)&7)<<12 | immediate&255
        data[start:start+10]=struct.pack('<HH',first,second)+movt(0,0)+b'\x78\x44'
    return bytes(data)


class ASRPatch(unittest.TestCase):
    def test_relocated_references_and_single_code_change(self):
        for base,shift in ((0x4000,0),(0x9000,28)):
            original=fixture(base,shift);result,report=patch(original)
            self.assertEqual(report['offset'],200+shift)
            self.assertEqual(report['destination'],128+shift)
            self.assertEqual(result[:200+shift],original[:200+shift])
            self.assertEqual(result[204+shift:],original[204+shift:])
            with self.assertRaises(ValueError):patch(result)

    def test_missing_ambiguous_and_malformed_inputs_rejected(self):
        original=fixture()
        variants=[original[:-1],original.replace(b'Image failed',b'Other failed'),
                  original+b'Image passed signature verification\0']
        damaged=bytearray(original);damaged[200]=0;variants.append(damaged)
        for data in variants:
            with self.assertRaises(ValueError):patch(data)
