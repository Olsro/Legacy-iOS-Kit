"""Optional real-image checks using an empty journaled HFSX template."""
import hashlib
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hfs import HFS

TEMPLATE = os.environ.get('OLSN0W_TEST_PROTECTION_TEMPLATE')


@unittest.skipUnless(TEMPLATE, 'Set OLSN0W_TEST_PROTECTION_TEMPLATE to a small empty journaled HFSX image')
class ProtectionFormat(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)/'data.hfs'
        self.assertLessEqual(Path(TEMPLATE).stat().st_size, 128*1024**2)
        shutil.copyfile(TEMPLATE, self.path)

    def test_root_attribute_is_on_cnid_one_and_cannot_be_reinitialized(self):
        image = HFS(self.path)
        image.initialize_protection_v4()
        with self.path.open('rb') as stream:
            stream.seek(1024)
            header = stream.read(512)
            block = struct.unpack_from('>I', header, 40)[0]
            start = struct.unpack_from('>I', header, 368)[0]
            stream.seek(start*block)
            tree = stream.read(4096)
            leaf = struct.unpack_from('>I', tree, 24)[0]
            size = struct.unpack_from('>H', tree, 32)[0]
            stream.seek(start*block + leaf*size)
            node = stream.read(size)
        self.assertEqual(struct.unpack_from('>H', node, 10)[0], 1)
        offset = struct.unpack_from('>H', node, size-2)[0]
        key_length = struct.unpack_from('>H', node, offset)[0]
        self.assertEqual(struct.unpack_from('>I', node, offset+4)[0], 1)
        name_length = struct.unpack_from('>H', node, offset+12)[0]
        self.assertEqual(node[offset+14:offset+14+name_length*2].decode('utf-16-be'),
                         'com.apple.system.cprotect')
        record = node[offset+key_length+2:]
        self.assertEqual(struct.unpack_from('>I', record)[0], 0x10)
        self.assertEqual(struct.unpack_from('>I', record, 12)[0], 28)
        self.assertEqual(record[16:44], b'\x04\x00'+bytes(26))
        before = hashlib.sha256(self.path.read_bytes()).digest()
        with self.assertRaises(Exception):
            image.initialize_protection_v4()
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_existing_plaintext_payload_is_rejected_without_mutation(self):
        image = HFS(self.path)
        image.add('/payload', b'Existing plaintext must not be silently converted')
        before = hashlib.sha256(self.path.read_bytes()).digest()
        with self.assertRaises(Exception):
            image.initialize_protection_v4()
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)
