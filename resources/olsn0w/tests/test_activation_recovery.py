"""Saved-record recovery must authenticate first and observe real activation."""
from contextlib import contextmanager
import io
from pathlib import Path
import plistlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import activation_recovery as recovery


class ActivationRecovery(unittest.TestCase):
    product = 'iPhone5,2'
    udid = 'a'*40
    info = dict(product=product, ecid=123, version='6.1.4', build='10B350')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.archive = self.folder/'activation.tar'
        self.record = plistlib.dumps(dict(
            AccountToken=plistlib.dumps(dict(UniqueDeviceID=self.udid, ProductType=self.product)),
            AccountTokenCertificate=b'certificate', AccountTokenSignature=b'signature',
            DeviceCertificate=b'device', FairPlayKeyData=b'fairplay'))
        with tarfile.open(self.archive, 'w') as archive:
            item = tarfile.TarInfo('private/var/root/Library/Lockdown/activation_records/activation_record.plist')
            item.size = len(self.record)
            archive.addfile(item, io.BytesIO(self.record))
        self.connection = Mock(prefix=['ssh', 'selected-target'])
        self.report = dict(generation='selected-generation')
        @contextmanager
        def connect(udid, folder):
            self.assertEqual(udid, self.udid)
            self.assertEqual(folder, self.folder)
            yield self.connection
        patches = dict(
            device_info=patch.object(recovery, 'device_info', return_value=self.info),
            backup_path=patch.object(recovery, 'backup_path', return_value=self.archive),
            candidates=patch.object(recovery, 'candidates', return_value=[(self.folder, self.report)]),
            check_target=patch.object(recovery, 'check_target'),
            connect=patch.object(recovery, 'connect', side_effect=connect),
            install=patch.object(recovery, 'install'),
            run=patch.object(recovery.subprocess, 'run'),
            sleep=patch.object(recovery.time, 'sleep'))
        self.mocks = {}
        for name, patcher in patches.items():
            self.mocks[name] = patcher.start()
            self.addCleanup(patcher.stop)

    def response(self, state='Activated', **changes):
        values = dict(ProductType=self.product, UniqueChipID=123, UniqueDeviceID=self.udid,
                      ProductVersion='6.1.4', BuildVersion='10B350', ActivationState=state)
        values.update(changes)
        return subprocess.CompletedProcess([], 0, plistlib.dumps(values), b'')

    def recover(self, **kwargs):
        return recovery.recover(self.product, self.udid, progress=lambda message: None, **kwargs)

    def test_original_record_is_restored_after_target_check_and_read_back(self):
        events = []
        self.mocks['check_target'].side_effect = lambda *args: events.append('check')
        self.mocks['install'].side_effect = lambda *args, **kw: events.append('install')
        self.mocks['run'].side_effect = lambda *args, **kw: events.append('readback') or self.response()
        self.recover()
        self.assertEqual(events, ['check', 'check', 'install', 'readback'])
        self.mocks['install'].assert_called_once_with(self.connection.prefix, self.record, has_baseband=True)
        self.assertEqual(self.mocks['run'].call_args.args[0][1:], ['-u', self.udid, '-s', '-x'])

    def test_reloading_daemon_can_temporarily_disconnect_or_timeout(self):
        self.mocks['run'].side_effect = [subprocess.TimeoutExpired('ideviceinfo', 20),
            subprocess.CompletedProcess([], 1, b'', b'disconnected'),
            self.response('Unactivated'), self.response()]
        self.recover()
        self.assertEqual(self.mocks['sleep'].call_count, 3)
        self.mocks['install'].assert_called_once()

    def test_record_copy_is_not_activation_success(self):
        self.mocks['run'].return_value = self.response('Unactivated')
        with self.assertRaisesRegex(RuntimeError, 'not reported Activated'):
            self.recover(timeout=0)
        self.mocks['install'].assert_called_once()

    def test_foreign_or_changed_target_cannot_confirm_activation(self):
        for changes in (dict(UniqueDeviceID='b'*40), dict(UniqueChipID=456),
                        dict(ProductType='iPhone5,1'), dict(ProductVersion='8.4.1'),
                        dict(BuildVersion='12H321')):
            with self.subTest(changes=changes):
                self.mocks['run'].return_value = self.response(**changes)
                with self.assertRaisesRegex(ValueError, 'different target'):
                    self.recover()

    def test_missing_or_foreign_backup_never_writes(self):
        self.archive.unlink()
        with self.assertRaisesRegex(ValueError, 'No saved activation archive'):
            self.recover()
        self.mocks['install'].assert_not_called()
        self.mocks['connect'].assert_not_called()

    def test_backup_must_belong_to_observed_device_before_ssh(self):
        with self.assertRaisesRegex(ValueError, 'UDID differs'):
            recovery.recover(self.product, 'b'*40)
        self.mocks['install'].assert_not_called()
        self.mocks['connect'].assert_not_called()

    def test_wrong_generation_or_missing_keys_never_writes(self):
        self.mocks['check_target'].side_effect = ValueError('different generation')
        with self.assertRaisesRegex(RuntimeError, 'Cannot authenticate'):
            self.recover()
        self.mocks['install'].assert_not_called()

    def test_target_is_rechecked_on_connection_used_to_install(self):
        self.mocks['check_target'].side_effect = [None, ValueError('generation changed')]
        with self.assertRaisesRegex(ValueError, 'generation changed'):
            self.recover()
        self.mocks['install'].assert_not_called()

    def test_matching_older_session_can_be_skipped_without_writes(self):
        self.mocks['candidates'].return_value = [(self.folder, self.report)]*2
        self.mocks['check_target'].side_effect = [ValueError('old generation'), None, None]
        self.mocks['run'].return_value = self.response()
        self.recover()
        self.mocks['install'].assert_called_once()

    def test_cli_dispatches_recovery_without_restoration(self):
        import olsn0w
        args = ['olsn0w.py', 'restore-activation', '--product', self.product,
                '--udid', self.udid, '--ecid', '123', '--bundle', str(self.folder)]
        with patch.object(sys, 'argv', args), patch('runtime.ensure_runtime'), \
                patch('ssh_client.check'), patch.object(recovery, 'recover') as recover:
            olsn0w.main()
        recover.assert_called_once_with(self.product, self.udid, '123', self.folder)
