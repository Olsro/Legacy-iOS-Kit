"""Keep the iPod/4S Aquila recipe separate from the iOS 7.0 layout."""
import plistlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import system
import restore_run


class IPodAquila(unittest.TestCase):
    def test_selection_matrix_preserves_other_devices_and_releases(self):
        for product in system.MODELS:
            for release in ('6.0', '6.0.1', '6.0.2', '6.1', '6.1.2', '6.1.3', '6.1.6',
                            '7.0', '7.0.4', '7.0.6', '7.1', '7.1.1', '7.1.2',
                            '8.0', '8.1.3', '8.3', '8.4.1'):
                with self.subTest(product=product, release=release):
                    stock = release.startswith('7.1')
                    expected = ('everuntether' if release.startswith('8.') else
                                'panguaxe' if stock and product not in {'iPod5,1', 'iPhone4,1'} else 'aquila')
                    self.assertEqual(system.selected_untether(release, product), expected)
                    self.assertEqual(system.uses_stock_daemon_layout(release), stock)

    def test_payload_changes_only_the_untether_and_native_trigger(self):
        before, _ = system.jailbreak_payload('7.1.2', 'iPhone5,2')
        with patch.object(system, 'ios7_payload', return_value=(b'pinned-aquila', {'release': '2.1.1'})):
            for product, release in ((p, r) for p in ('iPod5,1', 'iPhone4,1')
                                     for r in ('7.1', '7.1.1', '7.1.2')):
                after, provenance = system.jailbreak_payload(release, product)
                self.assertEqual(set(before) - set(after), {
                    'panguaxe', 'System/Library/LaunchDaemons/io.pangu.axe.untether.plist'})
                self.assertEqual(set(after) - set(before), {
                    'aquila', 'System/Library/LaunchDaemons/org.olsn0w.aquila.plist'})
                for name in set(before) & set(after):
                    self.assertEqual(before[name][1], after[name][1], name)
                    self.assertEqual(before[name][0].mode, after[name][0].mode, name)
                self.assertIn({'release': '2.1.1'}, provenance)
                self.assertEqual(after['aquila'][0].mode, 0o755)
                self.assertTrue(system.uses_legacy_job_loader(release, 'aquila'))

    def test_trigger_is_single_native_run_not_a_retry_loop(self):
        job = plistlib.loads(system.aquila_startup_job())
        self.assertEqual(job['ProgramArguments'], ['/aquila'])
        self.assertEqual(job['Label'], 'org.olsn0w.aquila')
        self.assertTrue(job['RunAtLoad'])
        self.assertTrue(job['LaunchOnlyOnce'])
        self.assertEqual(job['POSIXSpawnType'], 'Interactive')
        self.assertEqual(job['UserName'], 'root')
        self.assertNotIn('KeepAlive', job)
        self.assertNotIn('StartInterval', job)

    def test_4s_uses_its_own_jetsam_board_and_preserves_multipatch(self):
        job = system.aquila_startup_job()
        original = plistlib.dumps({'Version': 3, 'Defaults': {}})
        configured = system.untether_jetsam_properties(original, 'org.olsn0w.aquila')
        image = Mock()
        image.ls.return_value = []
        image.read.side_effect = [job, job, original, configured]
        name, result = system.prepare_ios71_daemon(image, 'iPhone4,1', 'aquila')
        self.assertEqual(name, 'System/Library/LaunchDaemons/org.olsn0w.aquila.plist')
        self.assertEqual(result, job)
        image.add.assert_any_call(
            '/System/Library/LaunchDaemons/com.apple.jetsamproperties.N94.plist', configured)
        image.command.assert_not_called()
        self.assertTrue(system.profile('iPhone4,1')['multipatch'])

    def test_stock_jobs_and_keybag_are_not_relocated(self):
        root = '/System/Library/LaunchDaemons/'
        jetsam = root + 'com.apple.jetsamproperties.N78.plist'
        native = {root + 'com.apple.mobile.keybagd.plist': b'original keybag',
                  root + 'com.apple.CrashHousekeeping.plist': b'original CrashHousekeeping',
                  root + 'com.apple.SpringBoard.plist': b'original SpringBoard'}

        class Image:
            def __init__(self):
                self.files = dict(native)
                self.files[jetsam] = plistlib.dumps({'Version': 3, 'Defaults': {
                    'com.apple.SpringBoard': {'JetsamMemoryLimit': 200}}})
                self.files[root + 'org.olsn0w.aquila.plist'] = system.aquila_startup_job()
                self.files[root + 'com.apple.mobile.softwareupdated.plist'] = b'OTA'

            def read(self, path):
                return self.files[path]

            def add(self, path, data):
                self.files[path] = data

            def ls(self, path):
                return [{'name': Path(p).name} for p in self.files if str(Path(p).parent) == path]

            def command(self, command, path):
                if command != 'rm' or path != root + 'com.apple.mobile.softwareupdated.plist':
                    raise AssertionError((command, path))
                del self.files[path]

        image = Image()
        name, configured = system.prepare_ios71_daemon(image, 'iPod5,1', 'aquila')
        self.assertEqual(name, 'System/Library/LaunchDaemons/org.olsn0w.aquila.plist')
        self.assertEqual(configured, system.aquila_startup_job())
        for name, data in native.items():
            self.assertEqual(image.files[name], data)
        properties = plistlib.loads(image.files[jetsam])['Defaults']
        self.assertEqual(properties['org.olsn0w.aquila'],
                         {'JetsamPriority': 18, 'JetsamMemoryLimit': 128})
        self.assertEqual(properties['com.apple.SpringBoard'], {'JetsamMemoryLimit': 200})

    def test_aquila_readonly_root_waits_without_pangu_retry_or_activation(self):
        report = dict(product='iPod5,1', version='7.1.2', build='11D257',
                      generation='selected', identity={'board': 'n78ap'},
                      setup_app_removed=True, activation_mode='skipped-setup-removed',
                      layout={'partitions': [{'role': 'system', 'device': '/dev/disk0s1s3'}]})
        base = ('N78AP\n11D257\nselected\nCYDIA_READY:selected\nUNTETHER_READY:ready\n'
                '/dev/disk0s1s3 on / (hfs, local, read-only, journaled)\n'
                'BOOT_SUCCESS:selected\n10 - com.apple.SpringBoard\n'
                '- 0 com.saurik.Cydia.Startup\n- 0 com.apple.accountsd\n'
                '- 0 com.apple.managedconfiguration.profiled\n')
        lockdown = plistlib.dumps(dict(ProductType='iPod5,1', ProductVersion='7.1.2',
                                      BuildVersion='11D257', ActivationState='Unactivated'))
        replies = [subprocess.CompletedProcess([], 0, base.encode(), b''),
                   subprocess.CompletedProcess([], 0, lockdown, b''),
                   subprocess.CompletedProcess([], 0, base.replace('read-only, ', '').encode(), b''),
                   subprocess.CompletedProcess([], 0, lockdown, b'')]
        notices = []
        with tempfile.TemporaryDirectory() as work, \
                patch.object(restore_run, 'checked_manifest', return_value=report), \
                patch.object(restore_run, 'PANGU_READONLY_RETRY_POLLS', 1), \
                patch.object(restore_run.subprocess, 'run', side_effect=replies) as command, \
                patch.object(restore_run.time, 'sleep'), \
                patch.object(restore_run.time, 'monotonic', side_effect=[0, 31, 32, 33, 34, 35]), \
                patch('activation.activate') as activate:
            result = restore_run.qualify(Path(work), ['ssh'], 'fixture', timeout=100,
                                         verify_writable_root=True, progress=notices.append)
        self.assertTrue(result['writable_root_verified'])
        self.assertFalse(result['untether_retry_rebooted'])
        self.assertTrue(result['activation_skipped'])
        activate.assert_not_called()
        self.assertFalse(any('/sbin/reboot' in str(c) for c in command.call_args_list))
        self.assertTrue(any('Waiting for Aquila' in text for text in notices))


if __name__ == '__main__':
    unittest.main()
