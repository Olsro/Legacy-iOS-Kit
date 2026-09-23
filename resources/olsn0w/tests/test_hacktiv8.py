import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hacktiv8
from common import KIT, run, tools
from hfs import HFS


def stock_lockdownd():
    signature = hacktiv8.LOCKDOWN_PATCHES[0][0]
    return b'prefix' + bytes(value if value is not None else 0xa5
                             for value in signature) + b'suffix'


def tar_entry(name, data=None, mode=0o644, uid=501, gid=501, directory=False):
    item = tarfile.TarInfo(name)
    item.mode, item.uid, item.gid = mode, uid, gid
    if directory:
        item.type = tarfile.DIRTYPE
    elif data is not None:
        item.size = len(data)
    return item, data


class Selection(unittest.TestCase):
    def test_techniques_cover_hacktiv8_ranges(self):
        cases = [
            ('4.0', 'iPhone3,1', '8A293', 'lockdownd-patch'),
            ('6.1.3', 'iPhone4,1', '10B329', 'lockdownd-patch'),
            ('7.1.2', 'iPhone4,1', '11D257', 'mobilegestalt-flag'),
            ('8.4.1', 'iPad2,1', '12H321', 'mobilegestalt-profile'),
            ('8.4.1', 'iPhone5,2', '12H321', 'mobilegestalt-flag'),
            ('9.3.5', 'iPhone4,1', '13G36', 'mobilegestalt-profile'),
            ('10.3.3', 'iPhone5,2', '14G60', 'mobilegestalt-profile'),
            ('10.3.4', 'iPhone5,4', '14G61', 'mobilegestalt-profile'),
        ]
        for release, product, build, expected in cases:
            with self.subTest(release=release, product=product, build=build):
                self.assertEqual(hacktiv8.technique(release, product, build), expected)
                self.assertTrue(hacktiv8.available(release, product, build))
        for release, product, build in [
                ('3.1.3', 'iPhone2,1', '7E18'),
                ('9.3.5', 'iPhone3,1', '13G36'),
                ('10.3.5', 'iPhone5,2', '14G60')]:
            self.assertFalse(hacktiv8.available(release, product, build))

    def test_all_bundled_profiles_are_valid(self):
        profiles = list((hacktiv8.HACKTIV8/'plists').rglob('patched.plist'))
        self.assertEqual(len(profiles), 132)
        for path in profiles:
            value = plistlib.loads(path.read_bytes())
            self.assertIs(value['CacheExtra'][hacktiv8.GESTALT_KEY], True)

    def test_lockdownd_signature_patch_is_exact_and_repeatable(self):
        original = stock_lockdownd()
        patched, offset, changed = hacktiv8.patch_lockdownd(original)
        self.assertTrue(changed)
        self.assertEqual(patched[offset:offset+2], b'\x01\x22')
        repeated, repeated_offset, repeated_changed = hacktiv8.patch_lockdownd(patched)
        self.assertEqual(repeated, patched)
        self.assertEqual(repeated_offset+18, offset)
        self.assertFalse(repeated_changed)

    def test_data_cache_uses_profile_or_stock_flag(self):
        cache = plistlib.dumps({'CacheExtra': {hacktiv8.GESTALT_KEY: False}})
        entries = {
            'mobile': tar_entry('mobile', directory=True),
            'mobile/Library/Caches/com.apple.MobileGestalt.plist':
                tar_entry('mobile/Library/Caches/com.apple.MobileGestalt.plist', cache),
        }
        report = hacktiv8.prepare_data(entries, '7.1.2', 'iPhone4,1', '11D257')
        self.assertEqual(report['method'], 'mobilegestalt-flag')
        self.assertIs(plistlib.loads(entries[report['target'][len('/private/var/'):]][1])
                      ['CacheExtra'][hacktiv8.GESTALT_KEY], True)
        entries = {'mobile': tar_entry('mobile', directory=True)}
        report = hacktiv8.prepare_data(entries, '9.3.5', 'iPhone4,1', '13G36')
        self.assertEqual(report['method'], 'mobilegestalt-profile')
        self.assertEqual(hashlib.sha256(entries[report['target'][len('/private/var/'):]][1]).hexdigest(),
                         report['sha256'])

    def test_activation_policy_distinguishes_hacktiv8_from_setup_removal(self):
        for mode, removed, applied, expected in [
                ('official-on-target', False, None, False),
                ('skipped-setup-removed', True, None, True),
                ('skipped-hacktiv8', False, {'method': 'test'}, True)]:
            self.assertEqual(hacktiv8.activation_skipped(dict(
                activation_mode=mode, setup_app_removed=removed,
                hacktiv8=applied)), expected)
        for mode, removed, applied in [
                ('skipped-setup-removed', False, None),
                ('skipped-hacktiv8', True, {'method': 'test'}),
                ('official-on-target', False, {'method': 'test'})]:
            with self.assertRaises(ValueError):
                hacktiv8.activation_skipped(dict(
                    activation_mode=mode, setup_app_removed=removed,
                    hacktiv8=applied))

    def function(self, name):
        source = (KIT/'restore.sh').read_text()
        return re.search(r'^'+name+r'\(\) \{\n.*?^\}', source,
                         re.M | re.S).group()

    def shell(self, script):
        result = subprocess.run(['bash', '-c', script], text=True,
                                capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        return result.stdout

    def test_restore_sh_asks_and_honors_both_choices(self):
        for supported in (False, True):
            for selected in (0, 1):
                python = ('python3() { echo mobilegestalt-profile; return 0; }\n'
                          if supported else 'python3() { return 1; }\n')
                result = self.shell(self.function('ipsw_hacktiv8_option') + '''
input() { :; }; print() { echo "$*"; }
device_proc=5; device_target_vers=9.3.5; device_target_build=13G36
''' + python + f'select_yesno() {{ echo "$1"; return {selected}; }}\n' + '''
ipsw_hacktiv8_option
echo "choice=$ipsw_hacktiv8"
''')
                self.assertIn('choice='+str(selected), result)
                if supported:
                    self.assertIn('Apply Hacktiv8 and keep Setup.app?', result)
                else:
                    self.assertIn('Remove Setup.app?', result)

    def test_lockdownd_method_enables_jailbreak_when_selected(self):
        for method in ('lockdownd-patch', 'mobilegestalt-flag',
                       'mobilegestalt-profile'):
            result = self.shell(self.function('ipsw_hacktiv8_option') + '''
input() { :; }; print() { :; }
python3() { echo ''' + method + '''; }
select_yesno() { return 1; }
device_proc=5; device_target_vers=6.1.3; device_target_build=10B329
ipsw_hacktiv8_option
echo "$ipsw_hacktiv8:$ipsw_jailbreak"
''')
            self.assertIn('1:1', result)

    def test_deferred_payload_uses_bundled_arm_helper(self):
        report = dict(method='mobilegestalt-flag', target=hacktiv8.GESTALT_OLD,
                      deferred=True)
        files = hacktiv8.firstboot_files(report)
        helper = files[hacktiv8.FIRSTBOOT_HELPER][0]
        script = files[hacktiv8.FIRSTBOOT_SCRIPT][0]
        self.assertEqual(hashlib.sha256(helper).hexdigest(),
                         hacktiv8.HELPER_SHA256)
        self.assertEqual(helper[:4], b'\xce\xfa\xed\xfe')
        self.assertIn(hacktiv8.FIRSTBOOT_HELPER.encode(), script)
        for unavailable in (b'/usr/bin/plutil', b'/usr/bin/sed', b'/usr/bin/grep'):
            self.assertNotIn(unavailable, script)

    def test_declining_option_never_invokes_image_editor(self):
        self.shell(self.function('ipsw_prepare_hacktiv8') + '''
ipsw_hacktiv8=0
python3() { exit 90; }
ipsw_prepare_hacktiv8
''')

    def test_common_restore_dispatch_covers_custom_methods(self):
        definitions = self.function('ipsw_prepare')
        for name in re.findall(r'\b(ipsw_prepare_\w+)\b', definitions):
            definitions += '\n'+name+'() { echo '+name+'; }\n'
        definitions += '\nshsh_save() { :; }\nrestore_usepwndfu64_option() { :; }\n'
        for setup, backend in [
                ('device_proc=5; device_target_powder=1; device_target_drav6=1', 'powder'),
                ('device_proc=6; device_target_powder=1', 'powder'),
                ('device_proc=5; device_target_tethered=1', 'tethered'),
                ('device_proc=5; device_target_other=1', '32bit'),
                ('device_proc=4; device_type=iPhone2,1; device_target_other=1', 'jailbreak')]:
            result = self.shell(definitions +
                '\ndevice_target_vers=6.1.3; target_vers_maj=6; ipsw_hacktiv8=1\n' +
                setup+'\nipsw_prepare\n')
            self.assertIn('ipsw_prepare_'+backend, result)
            self.assertTrue(result.strip().endswith('ipsw_prepare_hacktiv8'))


@unittest.skipUnless(os.environ.get('OLSN0W_TEST_HFS_TEMPLATE'),
                     'Requires a disposable HFS template')
class ImageIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.raw = self.folder/'root.hfs'
        shutil.copyfile(os.environ['OLSN0W_TEST_HFS_TEMPLATE'], self.raw)
        self.image = HFS(self.raw)
        self.image.add('/Applications/Setup.app/test', b'setup')
        self.image.add(hacktiv8.LOCKDOWN, stock_lockdownd(), mode=0o755)
        self.identity('6.1.3', '10B329')

    def identity(self, release, build):
        self.image.add('/System/Library/CoreServices/SystemVersion.plist',
                       plistlib.dumps(dict(ProductVersion=release,
                                           ProductBuildVersion=build)))

    def archive(self):
        packed = self.folder/'root.dmg'
        run([tools()/'dmg', 'build', self.raw, packed])
        archive = self.folder/'test.ipsw'
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('Restore.plist', plistlib.dumps(
                dict(SystemRestoreImages=dict(User='root.dmg'))))
            output.writestr('Firmware/keep', b'unchanged-firmware')
            output.write(packed, 'root.dmg')
        return archive

    def test_lockdownd_patch_keeps_setup_and_original(self):
        original = self.image.read(hacktiv8.LOCKDOWN)
        report = hacktiv8.install(self.image, '6.1.3', 'iPhone4,1', '10B329')
        hacktiv8.verify_installed(self.image, report, '6.1.3', 'iPhone4,1')
        self.assertEqual(self.image.read(hacktiv8.LOCKDOWN_BACKUP), original)
        self.assertEqual(self.image.read('/Applications/Setup.app/test'), b'setup')
        self.assertEqual(hacktiv8.install(
            self.image, '6.1.3', 'iPhone4,1', '10B329'), report)

    def test_gestalt_profile_keeps_setup_and_installs_firstboot_payload(self):
        self.identity('9.3.5', '13G36')
        report = hacktiv8.install(self.image, '9.3.5', 'iPhone4,1', '13G36')
        self.assertEqual(report['method'], 'mobilegestalt-profile')
        self.assertIs(report['deferred'], True)
        self.assertEqual(self.image.read('/Applications/Setup.app/test'), b'setup')
        profile = self.image.read(hacktiv8.FIRSTBOOT_PROFILE)
        self.assertIs(plistlib.loads(profile)['CacheExtra'][hacktiv8.GESTALT_KEY], True)
        hacktiv8.verify_installed(self.image, report, '9.3.5', 'iPhone4,1')

    def test_missing_gestalt_cache_installs_firstboot_patch(self):
        self.identity('7.1.2', '11D257')
        report = hacktiv8.install(self.image, '7.1.2', 'iPhone4,1', '11D257')
        self.assertEqual(report['method'], 'mobilegestalt-flag')
        self.assertIs(report['deferred'], True)
        self.assertEqual(self.image.read('/Applications/Setup.app/test'), b'setup')
        hacktiv8.verify_installed(self.image, report, '7.1.2', 'iPhone4,1')

    def test_unsupported_removes_only_setup(self):
        self.identity('3.1.3', '7E18')
        original = self.image.read(hacktiv8.LOCKDOWN)
        report = hacktiv8.install(self.image, '3.1.3', 'iPhone2,1', '7E18')
        self.assertIsNone(report)
        self.assertEqual(self.image.read(hacktiv8.LOCKDOWN), original)
        hacktiv8.verify_installed(self.image, report, '3.1.3', 'iPhone2,1')

    def test_custom_ipsw_roundtrip_and_failure_preserves_archive(self):
        archive = self.archive()
        before = hashlib.sha256(archive.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'differs'):
            hacktiv8.patch_ipsw(archive, '6.1.3', 'iPhone4,1', 'wrong-build')
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), before)
        report = hacktiv8.patch_ipsw(
            archive, '6.1.3', 'iPhone4,1', '10B329')
        with zipfile.ZipFile(archive) as result:
            self.assertEqual(result.read('Firmware/keep'), b'unchanged-firmware')
            result.extract('root.dmg', self.folder)
        restored = self.folder/'restored.hfs'
        run([tools()/'dmg', 'extract', self.folder/'root.dmg', restored])
        image = HFS(restored)
        hacktiv8.verify_installed(image, report, '6.1.3', 'iPhone4,1')
        self.assertEqual(image.read('/Applications/Setup.app/test'), b'setup')


if __name__ == '__main__':
    unittest.main()
