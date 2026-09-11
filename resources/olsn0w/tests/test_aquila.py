"""Never select an embedded device payload by a stale host-container offset."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aquila import embedded_payload, job_loader, prepare_ios8_payload, prepare_payload


class ReleasePayload(unittest.TestCase):
    def test_job_loader_matches_sources_and_has_valid_code_pages(self):
        binary, wrapper = job_loader()
        self.assertEqual(binary[:4], b'\xce\xfa\xed\xfe')
        self.assertIn(b'/olsn0w/load-jobs "$@"', wrapper)

    def test_unknown_untether_is_not_patched(self):
        with self.assertRaisesRegex(ValueError, 'Unqualified'):
            prepare_payload(b'unknown', '/dev/disk0s1s3', '/unused')

    def test_ios8_uses_qualified_batch_loader_and_retains_parent(self):
        original = bytearray(0x6e16)
        original[0x6e0c:0x6e14] = bytes.fromhex('42f2107003f000ee')
        original[0x6e14:0x6e16] = bytes.fromhex('12b0')
        original += b'/dev/disk0s1s1\0middle/bin/launchctl\0suffix'
        original = bytes(original)
        with tempfile.TemporaryDirectory() as directory, \
             patch('aquila.hashlib.sha256') as sha256, \
             patch('aquila.verify', return_value={'entitlements': b'plist'}), \
             patch('aquila.resign', return_value={'signed': True}):
            sha256.return_value.hexdigest.return_value = \
                '7f602f8e8e96fd6cbe2d313187ccade85de253ab1db21696ba7402c12ef8495c'
            output = Path(directory)/'everuntether'
            prepare_ios8_payload(original, '/dev/disk0s1s3', output)
            patched = output.read_bytes()
        self.assertIn(b'/dev/disk0s1s3\0', patched)
        self.assertNotIn(b'/bin/launchctl\0', patched)
        self.assertIn(b'/olsn0w/lctl\0', patched)
        self.assertEqual(patched[0x6e0c:0x6e14], bytes.fromhex('40f23c0003f0c8ed'))
        self.assertEqual(patched[0x6e14:0x6e16], bytes.fromhex('fae7'))

    def test_relocation_and_decoy_headers(self):
        payload = b'\xce\xfa\xed\xfe' + bytes(range(64))
        expected = hashlib.sha256(payload).hexdigest()
        for prefix in (b'', b'container-header', b'\xce\xfa\xed\xfe' + b'other'*40):
            self.assertEqual(embedded_payload(prefix + payload + b'tail',
                                              len(payload), expected), payload)

    def test_corrupted_missing_duplicate_and_truncated_components(self):
        payload = b'\xce\xfa\xed\xfe' + bytes(range(64))
        expected = hashlib.sha256(payload).hexdigest()
        for container in (payload[:-1]+b'x', b'absent'*30, payload+payload, payload[:-1]):
            with self.subTest(container=container[:12]), self.assertRaises(ValueError):
                embedded_payload(container, len(payload), expected)
