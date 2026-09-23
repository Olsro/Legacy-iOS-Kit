"""Use a synthetic executable to test signed-page and entitlement validation."""
import hashlib
from pathlib import Path
import plistlib
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from signing import rehash_adhoc, verify


def executable():
    entitlements = plistlib.dumps({'platform-application': True})
    entitlements = struct.pack('>II', 0xfade7171, 8+len(entitlements)) + entitlements
    directory = bytearray(44+20*6)
    struct.pack_into('>9I4BI', directory, 0, 0xfade0c02, len(directory),
                     0x20001, 2, 144, 44, 5, 1, 512, 20, 1, 0, 9, 0)
    directory[44:64] = hashlib.sha1(entitlements).digest()
    size = 28+len(directory)+len(entitlements)
    code = bytearray(512)
    struct.pack_into('<7I', code, 0, 0xfeedface, 12, 9, 2, 1, 16, 0)
    struct.pack_into('<4I', code, 28, 0x1d, 16, 512, size)
    directory[144:] = hashlib.sha1(code).digest()
    blob = struct.pack('>7I', 0xfade0cc0, size, 2, 0, 28, 5, 28+len(directory))
    return code+blob+directory+entitlements


class SignedPages(unittest.TestCase):
    def test_valid_pages_and_entitlements(self):
        self.assertEqual(verify(executable())['entitlements'], {'platform-application': True})

    def test_modified_code_or_entitlements_are_rejected(self):
        for offset in (100, -12):
            data = executable()
            data[offset] ^= 1
            with self.assertRaises(ValueError):
                verify(data)

    def test_rehash_preserves_adhoc_signature_metadata(self):
        original = bytes(executable())
        modified = bytearray(original)
        modified[100] ^= 1
        repaired = rehash_adhoc(original, modified)
        self.assertEqual(verify(repaired), verify(original))
        self.assertEqual(len(repaired), len(original))
        signature = 512
        before, after = original[signature:], repaired[signature:]
        changed = [i for i, values in enumerate(zip(before, after))
                   if values[0] != values[1]]
        self.assertTrue(changed)
        # Only the single SHA-1 code slot changes in this fixture.
        self.assertTrue(all(28+144 <= i < 28+164 for i in changed))

    def test_rehash_rejects_size_or_signature_changes(self):
        original = bytes(executable())
        with self.assertRaisesRegex(ValueError, 'preserve executable size'):
            rehash_adhoc(original, original+b'\0')
        modified = bytearray(original)
        modified[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'preserve the original signature blob'):
            rehash_adhoc(original, modified)

    def test_truncated_signature_is_rejected(self):
        with self.assertRaises(ValueError):
            verify(executable()[:-1])

    def test_embedded_info_plist_is_verified_as_special_slot(self):
        data = executable()
        info = b'<plist><dict/></plist>'
        data[300:300+len(info)] = info
        struct.pack_into('<II', data, 16, 2, 140)
        struct.pack_into('<II16s8I',data,44,1,124,b'__TEXT',0,512,0,512,7,5,1,0)
        struct.pack_into('<16s16s9I',data,100,b'__info_plist',b'__TEXT',300,len(info),300,0,0,0,0,0,0)
        directory = 512+28
        data[directory+124:directory+144] = hashlib.sha1(info).digest()
        data[directory+144:directory+164] = hashlib.sha1(data[:512]).digest()
        self.assertEqual(verify(data)['verified_pages'],1)
        data[300] ^= 1
        data[directory+144:directory+164] = hashlib.sha1(data[:512]).digest()
        with self.assertRaisesRegex(ValueError,'special slot: 1'):
            verify(data)
