"""Additional repositories must survive Cydia's generated source-cache updates."""
import unittest
import io
from pathlib import Path
import re
import plistlib
import shlex
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from unittest.mock import patch

from system import (OLSRO_SOURCE_PATH, OLSRO_SOURCES,
                    data_backed_cydia_sources, jailbreak_payload)

KIT = Path(__file__).resolve().parents[3]
SHELL = (KIT/'restore.sh').read_text()


def shell_function(name):
    return re.search(r'^'+name+r'\(\) \{\n.*?^\}', SHELL, re.M | re.S)[0]


class SharedSources(unittest.TestCase):
    def run_shell(self, script, folder):
        setup = ('error() { echo "$@" >&2; exit 1; }\n'
                 'platform='+('macos' if sys.platform == 'darwin' else 'linux')+'\n'
                 'jelbrek='+shlex.quote(str(KIT/'resources/jailbreak'))+'\n')
        result = subprocess.run(['bash', '-c', setup+script], cwd=folder,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_real_tar_overlay_and_append_preserve_payload(self):
        with tempfile.TemporaryDirectory(prefix='olsro-test-') as folder:
            archive = Path(folder)/'Cydia.tar'
            with tarfile.open(archive, 'w') as output:
                item = tarfile.TarInfo('usr/lib/untouched')
                item.size = 4
                output.addfile(item, io.BytesIO(b'keep'))
            self.run_shell(shell_function('jailbreak_sources_tar')+
                           '\njailbreak_sources_tar\n'
                           'jailbreak_sources_tar Cydia.tar append\n', folder)
            for name in ('Olsro.tar', 'Cydia.tar'):
                with tarfile.open(Path(folder)/name) as archive:
                    member = archive.getmember(OLSRO_SOURCE_PATH)
                    self.assertEqual((member.uid, member.gid, member.mode), (0, 0, 0o644))
                    self.assertEqual(archive.extractfile(member).read(), OLSRO_SOURCES)
                    self.assertEqual(archive.getnames().count(OLSRO_SOURCE_PATH), 1)
                    for member in archive.getmembers():
                        self.assertFalse(member.name.startswith('/') or '..' in member.name.split('/'))
                        self.assertNotIn('._', member.name)
                    if name == 'Cydia.tar':
                        self.assertEqual(archive.extractfile('usr/lib/untouched').read(), b'keep')

    def test_jailbreak_cache_names_change_but_stock_names_do_not(self):
        with tempfile.TemporaryDirectory() as folder:
            setup = (shell_function('ipsw_custom_set')+'\n'
                     'device_type=iPhone5,2; device_proc=6; target_vers_maj=8\n'
                     'device_target_vers=8.4.1; device_target_build=12H321\n')
            stock = self.run_shell(setup+'ipsw_jailbreak=0; ipsw_custom_set; echo "$ipsw_custom"', folder)
            jailbroken = self.run_shell(setup+'ipsw_jailbreak=1; ipsw_custom_set; echo "$ipsw_custom"', folder)
            self.assertEqual(stock, '../iPhone5,2_8.4.1_12H321_Custom')
            self.assertEqual(jailbroken, stock+'J-Olsro1')

    @unittest.skipUnless(sys.platform == 'darwin' and (KIT/'bin/macos/dmg').exists(),
                         'requires macOS HFS formatter and kit tools')
    def test_prebuilt_ipsw_real_hfs_roundtrip(self):
        from hfs import HFS
        with tempfile.TemporaryDirectory(prefix='olsro-image-test-') as folder:
            folder = Path(folder)
            raw = folder/'fixture.dmg'
            formatted = subprocess.run(['hdiutil', 'create', '-size', '16m', '-fs', 'HFS+',
                            '-layout', 'NONE', str(raw)],
                           text=True, capture_output=True)
            self.assertEqual(formatted.returncode, 0, formatted.stderr)
            image = HFS(raw)
            image.add('/unchanged', b'existing system content', 0o644)
            image.mkdir('/private/etc/apt/sources.list.d')
            image.add('/private/etc/apt/sources.list.d/LukeZGD.list', b'keep repo\n', 0o644)
            dmg = folder/'root.dmg'
            subprocess.run([str(KIT/'bin/macos/dmg'), 'build', str(raw), str(dmg)],
                           check=True, capture_output=True)
            with zipfile.ZipFile(folder/'temp.ipsw', 'w') as archive:
                archive.writestr('Restore.plist', plistlib.dumps(
                    {'SystemRestoreImages': {'User': 'root.dmg'}}))
                archive.writestr('Firmware/untouched', b'boot firmware')
                archive.write(dmg, 'root.dmg')
            script = '\n'.join(shell_function(name) for name in (
                'jailbreak_sources_tar', 'jailbreak_sources_dmg',
                'jailbreak_sources_prebuilt_ipsw'))
            script += ('\ndir='+shlex.quote(str(KIT/'bin/macos'))+'\n'
                       'PlistBuddy=/usr/libexec/PlistBuddy\n'
                       'file_extract_from_archive() { unzip -oq "$1" "$2"; }\n'
                       'jailbreak_sources_prebuilt_ipsw\n')
            self.run_shell(script, folder)
            with zipfile.ZipFile(folder/'temp.ipsw') as archive:
                self.assertEqual(archive.read('Firmware/untouched'), b'boot firmware')
                self.assertEqual(len(archive.namelist()), 3)
                archive.extract('root.dmg', folder)
            subprocess.run([str(KIT/'bin/macos/dmg'), 'extract', str(dmg), str(raw)],
                           check=True, capture_output=True)
            image = HFS(raw)
            self.assertEqual(image.read('/'+OLSRO_SOURCE_PATH), OLSRO_SOURCES)
            self.assertEqual(image.read('/private/etc/apt/sources.list.d/LukeZGD.list'), b'keep repo\n')
            self.assertEqual(image.read('/unchanged'), b'existing system content')

    def test_all_bootstrap_routes_include_shared_sources(self):
        for name in ('ipsw_prepare_jailbreak', 'ipsw_prepare_32bit',
                     'ipsw_prepare_ios4powder', 'ipsw_prepare_powder'):
            with self.subTest(route=name):
                body = shell_function(name)
                self.assertIn('jailbreak_sources_tar', body)
                self.assertIn('"Olsro.tar"', body)
        self.assertIn('jailbreak_sources_tar', shell_function('ipsw_prepare_specialios7'))
        self.assertIn('jailbreak_sources_tar freeze.tar append', shell_function('ipsw_prepare_sundanceinh2a'))
        self.assertIn('jailbreak_sources_tar freeze.tar append ..', shell_function('device_jailbreak_gilbert'))
        self.assertIn('jailbreak_sources_dmg "$rootfs_name"', shell_function('ipsw_prepare_multipatch'))
        self.assertIn('jailbreak_sources_prebuilt_ipsw', shell_function('ipsw_prepare_s5l8900'))
        # Ramdisk jailbreak, manual bootstrap, FourThree installation.
        self.assertEqual(SHELL.count('            device_send_olsro_sources\n'), 2)
        self.assertIn('    device_send_olsro_sources\n    if [[ $ipsw_openssh', SHELL)


class OlsroSources(unittest.TestCase):
    def test_exact_flat_repository_list(self):
        names = ('bigboss', 'cydiavn', 'eatmyphone', 'hackyouriphone',
                 'modmyi', 'personal', 'rpetrich', 'saurik', 'zodttd')
        expected = ['deb http://cydia.olsro.fr/'+name+'/ ./' for name in names]
        self.assertEqual(OLSRO_SOURCES.decode('ascii').splitlines(), expected)
        self.assertTrue(OLSRO_SOURCES.endswith(b'\n'))
        self.assertEqual(len(set(expected)), 9)

    def test_shared_payload_preserves_other_sources_and_canonical_path(self):
        # The pre-7.1 branch normally fetches Aquila. Repository preparation
        # itself must be offline, so stub only that unrelated binary provider.
        with patch('system.ios7_payload', return_value=(b'aquila', {})):
            for release in ('6.0', '6.0.2', '6.1.3', '6.1.6',
                            '7.0', '7.0.6', '7.1.2',
                            '8.0', '8.1.3', '8.3', '8.4.1'):
                with self.subTest(release=release):
                    payload, _ = jailbreak_payload(release)
                    original = {name: value for name, value in payload.items()
                                if '/sources.list.d/' in name
                                and name != OLSRO_SOURCE_PATH}
                    item, content = payload[OLSRO_SOURCE_PATH]
                    self.assertTrue(item.isfile())
                    self.assertEqual((item.uid, item.gid, item.mode), (0, 0, 0o644))
                    self.assertEqual(item.size, len(OLSRO_SOURCES))
                    self.assertEqual(content, OLSRO_SOURCES)
                    self.assertNotIn('etc/apt/sources.list.d/Olsro.list', payload)
                    luke = 'private/etc/apt/sources.list.d/LukeZGD.list'
                    self.assertEqual(payload[luke][1],
                                     b'deb https://lukezgd.github.io/repo ./\n')
                    data_backed_cydia_sources(payload)
                    self.assertEqual(payload[OLSRO_SOURCE_PATH], (item, content))
                    for name, value in original.items():
                        if not name.endswith('/cydia.list'):
                            self.assertEqual(payload[name], value)


if __name__ == '__main__':
    unittest.main()
