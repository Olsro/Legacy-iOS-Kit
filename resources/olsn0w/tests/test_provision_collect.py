"""Collect runtime modem files from the native iOS 6 restore archive."""
from collections import Counter
import io
import json
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import MODELS, baseband_files
from provision_collect import KERNEL, collect, personalized_modem
from test_layout import fixture


def packed_modem(files):
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, 'w') as archive:
        for name, data in files:
            archive.writestr(name, data)
    return packed.getvalue()


class PersonalizedModem(unittest.TestCase):
    def test_mav5_restore_component_is_optional_and_not_installed(self):
        files = {name: ('signed-' + name).encode() for name in baseband_files('Mav5')}
        for extra in ([], [('restoresbl1.mbn', b'signed-restore-loader')]):
            with self.subTest(extra=bool(extra)):
                self.assertEqual(personalized_modem(
                    packed_modem(list(files.items()) + extra), tuple(files),
                    optional=('restoresbl1.mbn',)), files)

    def test_missing_unknown_unsafe_and_duplicate_members_are_reported(self):
        files = [(name, b'signed') for name in baseband_files('Mav5')]
        cases = [
            (files[1:], 'missing', 'apps.mbn'),
            (files + [('unknown.mbn', b'x')], 'unexpected', 'unknown.mbn'),
            (files + [('../restoresbl1.mbn', b'x')], 'unexpected', '../restoresbl1.mbn'),
            (files + [files[0]], 'duplicate', 'apps.mbn'),
            (files + [('restoresbl1.mbn', b'x')] * 2, 'duplicate', 'restoresbl1.mbn'),
        ]
        for members, reason, name in cases:
            with self.subTest(reason=reason, name=name), warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with self.assertRaisesRegex(ValueError, 'unexpected component set') as error:
                    personalized_modem(packed_modem(members), baseband_files('Mav5'),
                                       optional=('restoresbl1.mbn',))
                self.assertIn(reason + ':', str(error.exception))
                self.assertIn(repr(name), str(error.exception))

    def test_empty_required_component_is_rejected(self):
        files = {name: b'signed' for name in baseband_files('Mav5')}
        files['bbticket.der'] = b''
        with self.assertRaisesRegex(ValueError, 'empty component'):
            personalized_modem(packed_modem(files.items()), tuple(files),
                               optional=('restoresbl1.mbn',))

    def test_trek_does_not_accept_mav5_restore_component(self):
        files = [(name, b'signed') for name in baseband_files('Trek')]
        files.append(('restoresbl1.mbn', b'restore'))
        with self.assertRaisesRegex(ValueError, 'unexpected component set'):
            personalized_modem(packed_modem(files), baseband_files('Trek'))

    def test_cellular_mini_native6_collection_uses_only_personalized_runtime_files(self):
        for product in ('iPad2,6', 'iPad2,7'):
            with self.subTest(product=product), tempfile.TemporaryDirectory() as tmp:
                bundle = Path(tmp)
                board, chip, board_id = MODELS[product]
                identity = dict(product=product, board=board, chip=chip, board_id=board_id, ecid=123)
                report = dict(product=product, identity=identity, multipatch=False,
                              restore_environment_build='10B329', reboot_token='a' * 32)
                (bundle/'run.json').write_text(json.dumps(dict(
                    complete=True, stage='authenticated-ram-handoff', returncode=0)))
                (bundle/'restore.log').write_text('DONE\n')
                version = plistlib.dumps(dict(ProductVersion='8.4.1', ProductBuildVersion='12H321'))
                kernel = struct.pack('<5I', int.from_bytes(b'Img3', 'big'), 38, 18, 0,
                                     int.from_bytes(b'krnl', 'big'))
                kernel += struct.pack('<3I', int.from_bytes(b'DATA', 'big'), 18, 6) + b'kernel'
                seeded = bundle/'signed-technical'
                for name, data in [('System/Library/CoreServices/SystemVersion.plist', version),
                                   (KERNEL, kernel)]:
                    path = seeded/name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                files = {name: ('signed-' + name).encode() for name in baseband_files('Mav5')}
                archive = packed_modem(list(files.items()) + [('restoresbl1.mbn', b'restore')])
                base = 'usr/local/standalone/firmware/Baseband/Mav5/'
                replies = {
                    '/sbin/mount': b'/dev/md0 on / (hfs)\n',
                    'mount_hfs -o rdonly /dev/disk0s1s1 /mnt1': b'',
                    'cat /mnt1/' + base + 'Mav5-personalized.zip': archive,
                    'cat /mnt1/System/Library/CoreServices/SystemVersion.plist': version,
                    'unmount /mnt1': b'',
                }
                ram = Mock(identity=identity)
                ram.table.return_value = fixture()
                ram.tool.side_effect = lambda name: name
                ram.run.side_effect = replies.__getitem__
                destination = bundle/'technical'
                with patch('provision_collect.checked_manifest', return_value=report), \
                     patch('provision_collect.read_handoff', return_value=b'a' * 32 + b'\n'):
                    collect(bundle, ram, destination)
                collected = json.loads((destination/'modem-files.json').read_text())
                self.assertEqual(set(collected), {base + name for name in files})
                for name, data in files.items():
                    self.assertEqual((destination/base/name).read_bytes(), data)
                self.assertEqual((destination/KERNEL).read_bytes(), kernel)
                self.assertFalse((destination/base/'restoresbl1.mbn').exists())
                self.assertTrue((destination/'collection.json').is_file())
                commands = Counter(call.args[0] for call in ram.run.call_args_list)
                self.assertEqual(commands['unmount /mnt1'], 1)


if __name__ == '__main__':
    unittest.main()
