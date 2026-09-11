"""Cover host-specific DFU preparation sequences."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rescue


class PrepareDFU(unittest.TestCase):
    def session(self, root):
        session = Path(root)
        (session/'device.json').write_text(json.dumps({
            'identity': {'ecid': 0x1305409a38b, 'product': 'iPhone5,2'}
        }))
        return session

    def test_apple_silicon_uses_qualified_rosetta_sequence(self):
        with tempfile.TemporaryDirectory() as root:
            calls=[]
            def run(argv, label, timeout=45):
                calls.append((list(map(str, argv)), label, timeout))
                return 'SRTG: N/A\nIBFL: 0x1b\n' if label == 'ibss-ready' else ''
            with patch.object(rescue.platform, 'system', return_value='Darwin'), \
                 patch.object(rescue.platform, 'machine', return_value='arm64'), \
                 patch.object(rescue, 'unique_usb_target'), \
                 patch.object(rescue, 'recheck_recovery', return_value={'mode':'DFU'}), \
                 patch.object(rescue.time, 'sleep'):
                rescue.prepare_dfu(self.session(root), run=run)
            self.assertEqual(calls[0],
                (['arch','-x86_64',str(rescue.KIT/'bin/macos/ipwnder'),'-pv'],'pwn',60))
            self.assertEqual(calls[1],
                (['arch','-x86_64',str(rescue.KIT/'bin/macos/gaster'),'reset'],'pwn-reset',60))
            self.assertEqual(calls[2][1], 'ibss-ready')

    def test_already_pwned_skips_host_exploit(self):
        with tempfile.TemporaryDirectory() as root:
            calls=[]
            def run(argv, label, timeout=45):
                calls.append(label)
                return 'SRTG: N/A\nIBFL: 0x1b\n'
            with patch.object(rescue, 'unique_usb_target'), \
                 patch.object(rescue, 'recheck_recovery', return_value={'mode':'DFU'}), \
                 patch.object(rescue.time, 'sleep'):
                rescue.prepare_dfu(self.session(root), pwned=True, run=run)
            self.assertEqual(calls, ['ibss-ready'])


if __name__ == '__main__':
    unittest.main()
