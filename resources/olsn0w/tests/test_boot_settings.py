"""Native NVRAM cleanup must preserve unrelated state and gate normal boot."""
import contextlib
import json
import os
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import boot_settings
import provision_restore as pipeline
import restore_run


class NativeNvram:
    def __init__(self, *, deny=None, ignore=None, auto_boot='true'):
        self.settings = {'boot-ramdisk': '/old/disk.dmg', 'boot-partition': '2',
                         'boot-args': '2', 'auto-boot': 'true', 'boot-command': 'fsboot',
                         'unrelated-private-value': b'preserve-me'}
        self.calls = []
        self.deny, self.ignore, self.auto_boot = deny, ignore, auto_boot
        self.guarded = False

    def guard(self):
        self.guarded = True

    def run(self, command):
        if not self.guarded:
            raise AssertionError('Device access before rescue guard')
        self.calls.append(command)
        if command == boot_settings.READ:
            return plistlib.dumps(self.settings)
        if command.startswith('/usr/sbin/nvram -d '):
            key = command.split()[-1]
            if key == self.deny:
                raise RuntimeError('delete denied')
            if key != self.ignore:
                del self.settings[key]
            return b''
        if command == '/usr/sbin/nvram auto-boot=true':
            self.settings['auto-boot'] = self.auto_boot
            return b''
        raise AssertionError('Unexpected device command: ' + command)


class BootSettings(unittest.TestCase):
    def test_private_durable_backup_precedes_writes_and_preserves_unrelated_nvram(self):
        ram = NativeNvram()
        original = dict(ram.settings)
        notices = []
        with tempfile.TemporaryDirectory() as folder:
            bundle = Path(folder)
            native_run = ram.run
            def run(command):
                if command != boot_settings.READ:
                    journal = json.loads((bundle / 'boot-settings.json').read_text())
                    backup = Path(journal['backup'])
                    self.assertFalse(journal['complete'])
                    self.assertEqual(plistlib.loads(backup.read_bytes()), original)
                    self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
                return native_run(command)
            ram.run = run
            result = boot_settings.prepare_normal_boot(ram, bundle, notices.append)
            self.assertTrue(result['complete'])
            self.assertEqual(result['removed_variables'], list(boot_settings.OVERRIDES))
            self.assertEqual(json.loads((bundle / 'boot-settings.json').read_text()), result)
            self.assertNotIn('preserve-me', (bundle / 'boot-settings.json').read_text())
        self.assertEqual(ram.settings, {key: value for key, value in original.items()
                                      if key not in boot_settings.OVERRIDES})
        self.assertNotIn('preserve-me', '\n'.join(notices))
        self.assertEqual(ram.calls, [boot_settings.READ, *['/usr/sbin/nvram -d ' + key
                         for key in boot_settings.OVERRIDES],
                         '/usr/sbin/nvram auto-boot=true', boot_settings.READ])

    def test_already_absent_overrides_are_not_deleted(self):
        ram = NativeNvram()
        for key in boot_settings.OVERRIDES:
            del ram.settings[key]
        with tempfile.TemporaryDirectory() as folder:
            result = boot_settings.prepare_normal_boot(ram, folder, lambda _: None)
        self.assertEqual(result['removed_variables'], [])
        self.assertFalse(any(' -d ' in command for command in ram.calls))

    def test_guard_or_invalid_nvram_stops_before_backup_and_mutation(self):
        for error in (ValueError('wrong RAM'), None):
            ram = Mock()
            ram.guard.side_effect = error
            ram.run.return_value = b'not a plist'
            with self.subTest(error=error), tempfile.TemporaryDirectory() as folder, \
                 patch.object(boot_settings, 'backup_settings') as backup:
                with self.assertRaises(ValueError):
                    boot_settings.prepare_normal_boot(ram, folder, lambda _: None)
                backup.assert_not_called()
                self.assertLessEqual(ram.run.call_count, 1)

    def test_backup_failure_stops_before_nvram_writes(self):
        ram = NativeNvram()
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(boot_settings, 'write_backup', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(OSError, 'disk full'):
                boot_settings.prepare_normal_boot(ram, folder, lambda _: None)
            self.assertFalse((Path(folder) / 'boot-settings.json').exists())
        self.assertEqual(ram.calls, [boot_settings.READ])

    def test_nonprivate_filesystem_uses_retained_private_fallback(self):
        real_write = boot_settings.write_backup
        private_directory = None
        def write(folder, raw):
            nonlocal private_directory
            if private_directory is None:
                private_directory = True
                raise boot_settings.PrivateBackupError('permissions unsupported')
            private_directory = Path(folder)
            return real_write(folder, raw)
        try:
            with tempfile.TemporaryDirectory() as folder, \
                 patch.object(boot_settings, 'write_backup', side_effect=write):
                result = boot_settings.prepare_normal_boot(NativeNvram(), folder, lambda _: None)
                backup = Path(result['backup'])
                self.assertTrue(backup.is_file())
                self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertTrue(backup.is_file())
        finally:
            if isinstance(private_directory, Path):
                for path in private_directory.iterdir():
                    path.unlink()
                private_directory.rmdir()

    def test_nonprivate_backup_is_rejected_before_writing_contents(self):
        info = Mock(st_uid=os.geteuid(), st_mode=stat.S_IFREG | 0o644)
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(boot_settings.os, 'fstat', return_value=info):
            with self.assertRaises(boot_settings.PrivateBackupError):
                boot_settings.write_backup(folder, b'private identifiers')
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_native_error_or_failed_readback_never_marks_boot_settings_complete(self):
        for options, message in (({'deny': 'boot-partition'}, 'delete denied'),
                                 ({'ignore': 'boot-partition'}, 'Old boot overrides remain'),
                                 ({'auto_boot': 'false'}, 'auto-boot=true')):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as folder:
                ram = NativeNvram(**options)
                with self.assertRaisesRegex(RuntimeError, message):
                    boot_settings.prepare_normal_boot(ram, folder, lambda _: None)
                journal = json.loads((Path(folder) / 'boot-settings.json').read_text())
                self.assertFalse(journal['complete'])
                self.assertIn('error', journal)
                self.assertTrue(Path(journal['backup']).is_file())


class BootSettingsIntegration(unittest.TestCase):
    def fixture(self, root):
        session, bundle = root / 'session', root / 'bundle'
        session.mkdir(); bundle.mkdir()
        identity = dict(product='iPhone5,2', ecid=123, board='n42ap', chip=0x8950, board_id=2)
        (session / 'device.json').write_text(json.dumps(dict(identity=identity, ram_udid='a' * 40)))
        (session / 'ssh-prefix.json').write_text(json.dumps(['ssh', '-p', '2200']))
        target = dict(product='iPhone5,2', identity=identity, version='6.1.4', build='10B350')
        reports = [dict(product='iPhone5,2', identity=identity),
                   dict(product='iPhone5,2', base_build='12H321'), target, target]
        args = (session, bundle, root / 'bootstrap', root / 'system', root / 'relay',
                root / 'ticket', root / 'keys')
        return args, reports

    def test_both_restore_routes_prepare_settings_after_install_and_before_reboot(self):
        for integrated in (True, False):
            for fail in (True, False):
                with self.subTest(integrated=integrated, fail=fail), \
                     tempfile.TemporaryDirectory() as folder, contextlib.ExitStack() as stack:
                    args, reports = self.fixture(Path(folder))
                    module = pipeline if integrated else restore_run
                    events = []
                    ram = Mock()
                    ram.run.side_effect = lambda command, **_: events.append(('run', command))
                    stack.enter_context(patch.object(module, 'checked_manifest',
                        **({'side_effect': reports} if integrated else {'return_value': reports[-1]})))
                    def settings(*unused, **kwargs):
                        events.append('settings')
                        if fail:
                            raise RuntimeError('boot settings readback failed')
                    stack.enter_context(patch.object(module, 'prepare_normal_boot', side_effect=settings))
                    stack.enter_context(patch.object(module, 'install', side_effect=lambda *a, **kw: events.append('install')))
                    stack.enter_context(patch.object(module, 'target_prefix', return_value=['ssh']))
                    qualify = stack.enter_context(patch.object(module, 'qualify_installed_target',
                        side_effect=lambda *a, **kw: events.append('qualify')))
                    if integrated:
                        stack.enter_context(patch.object(module, 'provision', return_value=ram))
                        stack.enter_context(patch.object(module, 'collect'))
                        stack.enter_context(patch.object(module, 'bind'))
                        stack.enter_context(patch.object(module, 'prepare',
                            side_effect=lambda *a: (args[1] / 'target').mkdir()))
                        stack.enter_context(patch.object(module, 'cleanup_completed', return_value={'bytes_reclaimed': 0}))
                        stack.enter_context(patch('usb_tunnel.stop'))
                        call = lambda: module.run(*args, erase=True, progress=lambda _: None)
                    else:
                        stack.enter_context(patch.object(module, 'runtime_prefix'))
                        stack.enter_context(patch.object(module, 'connect', return_value=ram))
                        stack.enter_context(patch.object(module, 'refresh_layout'))
                        sock = stack.enter_context(patch.object(module.socket, 'socket'))
                        sock.return_value.__enter__.return_value.connect_ex.return_value = 0
                        call = lambda: module.run(args[0], args[1], erase=True, ram_ready=True,
                                                  progress=lambda _: None)
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, 'boot settings readback failed'):
                            call()
                        self.assertEqual(events, ['install', 'settings'])
                        qualify.assert_not_called()
                        if integrated:
                            journal = json.loads((args[1] / 'pipeline.json').read_text())
                            self.assertEqual(journal['stage'], 'preparing-normal-boot')
                            self.assertFalse(journal['complete'])
                    else:
                        call()
                        self.assertEqual(events[:2], ['install', 'settings'])
                        self.assertEqual(events[-1], 'qualify')
                        reboot = '/sbin/reboot_olsn0w' if integrated else '/sbin/reboot'
                        self.assertIn(('run', reboot), events[2:-1])


if __name__ == '__main__':
    unittest.main()
