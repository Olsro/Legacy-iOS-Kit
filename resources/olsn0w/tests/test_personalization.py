"""Wi-Fi products retain activation without requiring nonexistent modem files."""
import hashlib
import io
import json
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from personalization import prepare
from archives import write_tar
from system import entry


class RadioCapability(unittest.TestCase):
    def test_modem_archive_uses_ios5_standalone_path_only_on_ios5(self):
        from common import baseband_files
        for family in ('Trek', 'Mav5'):
            for release in ('5.0', '5.0.1', '5.1', '5.1.1', '6.1.3', '7.1.2', '8.3'):
                with self.subTest(family=family, release=release), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    base = 'usr/local/standalone/firmware/Baseband/' + family + '/'
                    modem = {}
                    for name in baseband_files(family):
                        data = ('fixture-' + name).encode()
                        source = root / (base + name)
                        source.parent.mkdir(parents=True, exist_ok=True)
                        source.write_bytes(data)
                        modem[base + name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                    self.technical(root, modem)
                    prepare(root, release, root/'output', baseband_family=family)
                    expected = ('usr/standalone/firmware/' if release.startswith('5.') else base)
                    expected += family + '-personalized.zip'
                    with tarfile.open(root/'output/root-personalization.tar') as archive:
                        self.assertEqual([n for n in archive.getnames() if n.endswith('-personalized.zip')], [expected])
                        with zipfile.ZipFile(io.BytesIO(archive.extractfile(expected).read())) as packed:
                            self.assertEqual(set(packed.namelist()), set(baseband_files(family)))
                            for name in packed.namelist():
                                self.assertEqual(packed.read(name), ('fixture-' + name).encode())

    def test_personalization_preserves_selected_seed_permissions_on_ios6_7_8(self):
        for release in ('6.1.3', '7.1.2', '8.3'):
            with self.subTest(release=release), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.technical(root, {}, has_baseband=False)
                name = 'mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv'
                content = b'test-personalization-content'
                path = root/'activation'/name
                path.parent.mkdir(parents=True)
                path.write_bytes(content)
                report_path = root/'activation-files.json'
                report = json.loads(report_path.read_text())
                report[name] = dict(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
                report_path.write_text(json.dumps(report))
                seed = root/'seed.tar'
                write_tar(seed, [entry(n, mode=0o711, uid=501, gid=501, directory=True)
                                 for n in ('mobile', 'mobile/Library')])
                result = prepare(root, release, root/'output', has_baseband=False,
                                 data_seed=seed)
                self.assertEqual(result['data_seed_sha256'], hashlib.sha256(seed.read_bytes()).hexdigest())
                self.assertEqual(result['preserved_data_directories'], ['mobile', 'mobile/Library'])
                with tarfile.open(root/'output/data-personalization.tar') as archive:
                    for name in ('mobile', 'mobile/Library'):
                        member = archive.getmember(name)
                        self.assertEqual((member.mode, member.uid, member.gid), (0o711, 501, 501))
                    # New private directories still get the requested metadata.
                    self.assertEqual(archive.getmember('root/Library/Lockdown').mode, 0o700)
                if shutil.which('tar'):
                    live = root/'extracted'
                    (live/'mobile/Library').mkdir(parents=True)
                    (live/'mobile').chmod(0o711)
                    (live/'mobile/Library').chmod(0o711)
                    subprocess.run(['tar', '--no-same-owner', '-xpf',
                                    str(root/'output/data-personalization.tar'),
                                    '-C', str(live)], check=True, capture_output=True)
                    for name in ('mobile', 'mobile/Library'):
                        self.assertEqual(stat.S_IMODE((live/name).stat().st_mode), 0o711)
                with tarfile.open(root/'output/root-personalization.tar') as archive:
                    self.assertEqual(archive.extractfile('usr/local/share/olsn0w/data-personalization.tar').read(),
                                     (root/'output/data-personalization.tar').read_bytes())

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
                # iOS 6 now defers activation files alongside the Data payload
                # until the native target keybag exists.
                self.assertEqual(regular, ['usr/local/share/olsn0w/data-personalization.tar'])
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

    def test_setup_removed_mode_omits_available_activation_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.technical(root,{},has_baseband=False)
            result=prepare(root,'6.1.3',root/'output',has_baseband=False,
                           omit_activation=True)
            self.assertTrue(result['activation_omitted'])
            self.assertFalse(result['activate_on_target'])
            self.assertEqual(result['source'],'activation-intentionally-omitted')
            with tarfile.open(root/'output/data-personalization.tar') as archive:
                self.assertEqual(archive.getnames(),[])

    def test_activation_cannot_be_requested_when_records_are_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'modem-files.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'while omitting activation'):
                prepare(root,'6.1.3',root/'output',has_baseband=False,
                        activate_on_target=True,omit_activation=True)
