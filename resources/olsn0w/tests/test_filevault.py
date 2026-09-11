"""A fixed OpenSSL-generated fixture checks the envelope and block boundary."""
import base64
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from filevault import decrypt

class FileVaultEnvelope(unittest.TestCase):
    fixture=base64.b64decode((Path(__file__).parent/'fixtures/filevault-v2.b64').read_bytes())
    key=bytes(range(36)).hex()

    def test_partial_last_block_and_original_udif_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'encrypted';out=Path(directory)/'plain'
            source.write_bytes(self.fixture)
            decrypt(source,out,self.key)
            expected=bytearray(900)
            expected[:24]=b'FileVault test payload!!'
            expected[388:400]=struct.pack('>4sII',b'koly',4,512)
            self.assertEqual(out.read_bytes(),expected)
            with self.assertRaises(FileExistsError):decrypt(source,out,self.key)
            self.assertEqual(out.read_bytes(),expected)

    def test_bad_key_and_truncated_or_invalid_envelope_are_not_published(self):
        for blob,key in [(self.fixture,'ff'*36),(self.fixture[:-1],self.key),
                         (b'not fv2',self.key),(self.fixture,'bad-key')]:
            with self.subTest(size=len(blob)),tempfile.TemporaryDirectory() as directory:
                source=Path(directory)/'encrypted';out=Path(directory)/'plain'
                source.write_bytes(blob)
                with self.assertRaises(ValueError):decrypt(source,out,key)
                self.assertFalse(out.exists())
