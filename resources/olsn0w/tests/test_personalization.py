"""Wi-Fi products retain activation without requiring nonexistent modem files."""
import hashlib
import json
from pathlib import Path
import plistlib
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from personalization import prepare


class RadioCapability(unittest.TestCase):
    def test_fresh_base_defers_to_official_target_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'modem-files.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'activation records'):
                prepare(root,'7.1.2',root/'rejected',has_baseband=False)
            for release in ('7.1.2','8.3'):
                destination=root/release
                result=prepare(root,release,destination,has_baseband=False,activate_on_target=True)
                self.assertTrue(result['activate_on_target'])
                self.assertFalse(result['activation_on_target_verified'])
                with tarfile.open(destination/'data-personalization.tar') as archive:
                    self.assertEqual(archive.getnames(),[])

    def technical(self, root, modem, has_baseband=True):
        report = {}
        record = 'activation_record.plist' if has_baseband else 'pod_record.plist'
        for name in ('activation_records/' + record, 'data_ark.plist'):
            name = 'mobile/Library/mad/' + name
            content = plistlib.dumps({'Fixture': True})
            path = root / 'activation' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            report[name] = dict(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        (root / 'activation-files.json').write_text(json.dumps(report))
        (root / 'modem-files.json').write_text(json.dumps(modem))

    def test_wifi_has_only_its_activation_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.technical(root, {}, has_baseband=False)
            result = prepare(root, '6.1.3', root / 'output', has_baseband=False)
            self.assertFalse(result['has_baseband'])
            with tarfile.open(root / 'output/root-personalization.tar') as archive:
                regular = [m.name for m in archive if m.isfile()]
                # iOS 6 Data is seeded directly before boot. Only protected
                # iOS 7/8 images need to carry this archive inside System for
                # native first-boot extraction.
                self.assertEqual(regular, [])
            with tarfile.open(root / 'output/data-personalization.tar') as archive:
                self.assertIn('root/Library/Lockdown/activation_records/pod_record.plist', archive.getnames())

    def test_ios8_defers_personalization_to_protected_first_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.technical(root, {}, has_baseband=False)
            prepare(root, '8.1.3', root/'output', has_baseband=False)
            with tarfile.open(root/'output/root-personalization.tar') as archive:
                regular = [member.name for member in archive if member.isfile()]
                self.assertEqual(regular, ['usr/local/share/olsn0w/data-personalization.tar'])
                self.assertEqual(archive.extractfile(regular[0]).read(),
                                 (root/'output/data-personalization.tar').read_bytes())

    def test_cellular_still_requires_its_complete_modem(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.technical(root, {})
            with self.assertRaisesRegex(ValueError, 'modem component'):
                prepare(root, '7.1.2', root / 'output')

    def test_preserved_cellular_modem_needs_no_injected_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.technical(root,{})
            result=prepare(root,'7.1.2',root/'output',has_baseband=True,
                           include_modem=False)
            self.assertTrue(result['has_baseband'])
            self.assertFalse(result['modem_payload_included'])
            with tarfile.open(root/'output/root-personalization.tar') as archive:
                self.assertNotIn('usr/local/standalone/firmware/Baseband',
                                 archive.getnames())

    def test_wifi_rejects_unexpected_modem_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.technical(root, {'unexpected': {}}, has_baseband=False)
            with self.assertRaisesRegex(ValueError, 'without a baseband'):
                prepare(root, '6.1.3', root / 'output', has_baseband=False)
