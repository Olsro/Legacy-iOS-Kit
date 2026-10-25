"""Old macOS SSH clients and saved preparation arguments must remain usable."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import olsn0w
import provision_run
import ssh_client
from restore import Rescue
from restore_run import target_prefix

IDENTITY = dict(product='iPad3,1', board='j1ap', chip=0x8945, board_id=0, ecid=123)


class SSHCompatibility(unittest.TestCase):
    def test_saved_prefix_is_migrated_without_changing_keys_or_host_pinning(self):
        original = ['ssh', '-i', '/saved/private-key', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'UserKnownHostsFile=/saved/known-hosts',
                    '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa', 'root@127.0.0.1']
        with patch.object(ssh_client, 'private_identity', side_effect=str):
            ram = Rescue(original, IDENTITY, rescue_build='10B329')
        expected = original.copy()
        expected[-2] = 'PubkeyAcceptedKeyTypes=+ssh-rsa'
        expected[6] = 'UserKnownHostsFile="/saved/known-hosts"'
        self.assertEqual(ram.prefix, expected)
        self.assertEqual(original[-2], 'PubkeyAcceptedAlgorithms=+ssh-rsa')

    def test_new_prefix_uses_compatible_option_and_still_pins_host_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder/'ssh_host_rsa_key.pub').write_text('ssh-rsa AAAAFIXTURE comment\n')
            prefix = target_prefix(folder, 6414)
            self.assertIn('PubkeyAcceptedKeyTypes=+ssh-rsa', prefix)
            self.assertNotIn('PubkeyAcceptedAlgorithms=+ssh-rsa', prefix)
            self.assertIn('StrictHostKeyChecking=yes', prefix)
            self.assertIn('UserKnownHostsFile="'+str(folder/'target-known-hosts')+'"', prefix)
            self.assertEqual((folder/'target-known-hosts').read_text(),
                             '[127.0.0.1]:6414 ssh-rsa AAAAFIXTURE\n')

    def test_legacy_client_accepts_new_and_saved_arguments_without_connecting(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            client = folder/'ssh'
            client.write_text('''#!/bin/sh
for argument do
    case "$argument" in
        PubkeyAcceptedAlgorithms=*) echo 'Bad configuration option: pubkeyacceptedalgorithms' >&2; exit 255;;
    esac
done
[ "$1" = -G ] || exit 99
exit 0
''')
            client.chmod(0o755)
            with patch.dict(os.environ, PATH=temporary):
                ssh_client.check()
            prefix = ['ssh', '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa', 'root@127.0.0.1']
            original = subprocess.run([str(client), '-G', *prefix[1:]], capture_output=True)
            self.assertEqual(original.returncode, 255)
            fixed = ssh_client.compatible_prefix(prefix)
            result = subprocess.run([str(client), '-G', *fixed[1:]], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('ssh'), 'requires a host SSH client')
    def test_host_client_parses_compatible_options_without_network_access(self):
        ssh_client.check()

    def test_preflight_failure_stops_cli_before_menu_or_preparation(self):
        with patch.object(sys, 'argv', ['olsn0w.py', 'menu', '--product', 'iPad3,1', '--ecid', '123']), \
             patch('runtime.ensure_runtime'), \
             patch.object(ssh_client, 'check', side_effect=RuntimeError('SSH options rejected')), \
             patch('guided.menu') as menu:
            with self.assertRaisesRegex(RuntimeError, 'SSH options rejected'):
                olsn0w.main()
        menu.assert_not_called()

    def test_host_option_diagnostic_is_not_discarded(self):
        failure = subprocess.CompletedProcess([], 255, b'', b'Bad configuration option: testoption\n')
        with patch.object(ssh_client.subprocess, 'run', return_value=failure) as command:
            with self.assertRaisesRegex(RuntimeError, 'Bad configuration option: testoption'):
                ssh_client.check()
        self.assertIn('-G', command.call_args.args[0])


class SSHPrivateIdentities(unittest.TestCase):
    @unittest.skipUnless(shutil.which('ssh-keygen'), 'requires OpenSSH key reader')
    def test_openssh_accepts_staged_key_from_a_permissionless_volume(self):
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary)/'key'
            subprocess.run(['ssh-keygen', '-q', '-t', 'rsa', '-b', '2048',
                            '-N', '', '-f', str(key)], check=True, capture_output=True)
            expected = (Path(str(key)+'.pub').read_text().split())[:2]
            key.chmod(0o777)
            rejected = subprocess.run(['ssh-keygen', '-y', '-f', str(key)], capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(b'bad permissions', rejected.stderr)
            chmod = Path.chmod
            def volume_chmod(path, mode):
                if path != key:
                    chmod(path, mode)
            with patch.object(Path, 'chmod', volume_chmod):
                staged = ssh_client.private_identity(key)
            accepted = subprocess.run(['ssh-keygen', '-y', '-f', staged], capture_output=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout.decode().split()[:2], expected)

    def test_permissive_key_is_repaired_on_a_unix_filesystem(self):
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary)/'key'
            key.write_bytes(b'fixture private key')
            key.chmod(0o777)
            self.assertEqual(ssh_client.private_identity(key), str(key))
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_saved_ram_prefix_stages_key_when_chmod_has_no_effect(self):
        with tempfile.TemporaryDirectory(prefix='Kit with spaces ') as temporary:
            key = Path(temporary)/'ssh_client_rsa'
            key.write_bytes(b'original RAM key')
            key.chmod(0o777)
            prefix = ['ssh', '-i', str(key), '-o', 'StrictHostKeyChecking=yes',
                      '-o', 'UserKnownHostsFile='+temporary+'/known-hosts',
                      'root@127.0.0.1']
            chmod = Path.chmod
            def volume_chmod(path, mode):
                if path != key:
                    chmod(path, mode)
            with patch.object(Path, 'chmod', volume_chmod):
                ram = Rescue(prefix, IDENTITY, rescue_build='10B329')
                staged = Path(ram.prefix[2])
                self.assertNotEqual(staged, key)
                self.assertEqual(staged.read_bytes(), key.read_bytes())
                self.assertTrue(ssh_client.private_file(staged, 0o600))
                self.assertTrue(ssh_client.private_file(staged.parent, 0o700))
                self.assertEqual(ssh_client.runtime_prefix(prefix), ram.prefix)
                key.write_bytes(b'new RAM key')
                updated = ssh_client.runtime_prefix(prefix)
                self.assertNotEqual(updated[2], str(staged))
                self.assertEqual(Path(updated[2]).read_bytes(), b'new RAM key')
            self.assertEqual(prefix[2], str(key))
            self.assertEqual(key.stat().st_mode & 0o777, 0o777)
            self.assertIn('StrictHostKeyChecking=yes', ram.prefix)
            self.assertIn(ssh_client.known_hosts_option(Path(temporary)/'known-hosts'), ram.prefix)

    def test_unsafe_tmpdir_is_rejected_before_key_is_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            unsafe = Path(temporary)/'unsafe'
            unsafe.mkdir()
            unsafe.chmod(0o777)
            rejected = Mock(name=str(unsafe))
            rejected.name = str(unsafe)
            with patch.object(ssh_client.tempfile, 'TemporaryDirectory', return_value=rejected), \
                 patch.object(Path, 'chmod'):
                with self.assertRaisesRegex(RuntimeError, 'Unix permissions'):
                    ssh_client.private_directory()
            self.assertEqual(rejected.cleanup.call_count, 2)
            self.assertEqual(list(unsafe.iterdir()), [])

    def test_unsafe_tmpdir_falls_back_to_system_tmp(self):
        create = tempfile.TemporaryDirectory
        with tempfile.TemporaryDirectory() as temporary:
            unsafe = Path(temporary)/'unsafe'
            unsafe.mkdir()
            unsafe.chmod(0o777)
            rejected = Mock()
            rejected.name = str(unsafe)
            def directory(**kwargs):
                return rejected if kwargs['dir'] is None else create(**kwargs)
            chmod = Path.chmod
            def volume_chmod(path, mode):
                if path != unsafe:
                    chmod(path, mode)
            with patch.object(ssh_client.tempfile, 'TemporaryDirectory', side_effect=directory), \
                 patch.object(Path, 'chmod', volume_chmod):
                accepted = ssh_client.private_directory()
            try:
                self.assertTrue(ssh_client.private_file(accepted.name, 0o700))
                rejected.cleanup.assert_called_once()
            finally:
                accepted.cleanup()

    def test_preflight_rejects_unusable_private_storage(self):
        with patch.object(ssh_client.subprocess, 'run', return_value=Mock(returncode=0)), \
             patch.object(ssh_client, 'private_directory', side_effect=RuntimeError('Unix permissions')):
            with self.assertRaisesRegex(RuntimeError, 'Unix permissions'):
                ssh_client.check()


@unittest.skipUnless(shutil.which('ssh') and shutil.which('ssh-keygen') and
                     Path('/usr/sbin/sshd').is_file(), 'requires local OpenSSH client and server')
class SSHKnownHostsPaths(unittest.TestCase):
    def test_new_and_saved_paths_with_spaces_keep_strict_host_pinning(self):
        with tempfile.TemporaryDirectory(prefix='olsn0w-ssh-paths-') as temporary:
            root = Path(temporary)
            host = root/'ssh_host_rsa_key'
            subprocess.run(['ssh-keygen', '-q', '-t', 'rsa', '-b', '2048',
                            '-N', '', '-f', str(host)], check=True, capture_output=True)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            with (root/'sshd.log').open('w+') as log:
                server = subprocess.Popen([
                    '/usr/sbin/sshd', '-D', '-e', '-f', '/dev/null', '-h', str(host),
                    '-p', str(port), '-o', 'ListenAddress=127.0.0.1', '-o', 'UsePAM=no',
                    '-o', 'PermitRootLogin=no', '-o', 'PidFile='+str(root/'sshd.pid')],
                    stdout=log, stderr=log)
                try:
                    deadline = time.monotonic()+5
                    while True:
                        if server.poll() is not None:
                            log.seek(0)
                            self.skipTest('Local sshd cannot start: '+log.read()[-500:])
                        with socket.socket() as sock:
                            if sock.connect_ex(('127.0.0.1', port)) == 0:
                                break
                        if time.monotonic() >= deadline:
                            self.fail('Local sshd did not become ready')
                        time.sleep(.05)
                    for name in ('Legacy-iOS-Kit-main 2', 'Kit "quoted" \\ path'):
                        folder = root/name
                        folder.mkdir()
                        shutil.copyfile(str(host)+'.pub', folder/'ssh_host_rsa_key.pub')
                        shutil.copyfile(host, folder/'ssh_client_rsa')
                        current = target_prefix(folder, port)
                        saved = [argument if not argument.startswith('UserKnownHostsFile=')
                                 else 'UserKnownHostsFile='+str(folder/'target-known-hosts')
                                 for argument in current]
                        migrated = Rescue(saved, IDENTITY, rescue_build='10B329').prefix
                        for label, prefix in (('new', current), ('saved', migrated)):
                            with self.subTest(path=name, prefix=label):
                                self.assertEqual(ssh_client.compatible_prefix(prefix), prefix)
                                result = subprocess.run(prefix[:-1]+[
                                    '-vv', '-o', 'PreferredAuthentications=none', prefix[-1]],
                                    capture_output=True, timeout=10)
                                diagnostic = result.stderr.decode(errors='replace')
                                self.assertIn('known and matches the RSA host key', diagnostic)
                                self.assertNotIn('Host key verification failed', diagnostic)
                        # Removing the pinned key must still reject this same server.
                        (folder/'target-known-hosts').write_text('')
                        result = subprocess.run(current[:-1]+[
                            '-o', 'PreferredAuthentications=none', current[-1]],
                            capture_output=True, timeout=10)
                        self.assertIn(b'Host key verification failed', result.stderr)
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()


class HandoffDiagnostics(unittest.TestCase):
    def fixture(self, folder):
        session = Path(folder)
        (session/'device.json').write_text(json.dumps(dict(identity=IDENTITY, rescue_maintenance='/olsn0w-maintenance')))
        (session/'ssh-prefix.json').write_text(json.dumps(['ssh']))
        return session

    def test_timeout_keeps_underlying_ssh_error_in_log_and_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            session = self.fixture(temporary)
            ram = Mock()
            ram.run.side_effect = RuntimeError('ssh: connect to host 127.0.0.1 port 6414: Connection refused')
            with patch.object(provision_run, 'Rescue', return_value=ram), \
                 patch.object(provision_run, 'session_build', return_value='10B329'):
                with self.assertRaisesRegex(RuntimeError, 'Connection refused'):
                    provision_run.connect_handoff(session, timeout=0)
            self.assertIn('Connection refused', (session/'handoff-ssh.log').read_text())
            ram.guard.assert_not_called()

    def test_identity_validation_error_is_logged_without_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            session=self.fixture(temporary)
            ram=Mock()
            ram.run.return_value=b'/dev/md0 on / (hfs)\n'
            detail='Wrong RAM system identity: expected hw.model=K93aAP; received K93AP'
            ram.guard.side_effect=ValueError(detail)
            with patch.object(provision_run,'Rescue',return_value=ram), \
                 patch.object(provision_run,'session_build',return_value='12H321'), \
                 patch.object(provision_run.time,'sleep') as sleep:
                with self.assertRaisesRegex(ValueError,'Wrong RAM system identity') as error:
                    provision_run.connect_handoff(session)
            self.assertIn(detail,(session/'handoff-ssh.log').read_text())
            self.assertIn(str(session/'handoff-ssh.log'),str(error.exception))
            sleep.assert_not_called()
            ram.guard.assert_called_once_with([])

    def test_invalid_client_configuration_fails_immediately_without_usb_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            session = self.fixture(temporary)
            ram = Mock()
            ram.run.side_effect = RuntimeError('Bad configuration option: pubkeyacceptedalgorithms')
            with patch.object(provision_run, 'Rescue', return_value=ram), \
                 patch.object(provision_run, 'session_build', return_value='10B329'), \
                 patch.object(provision_run.time, 'monotonic', return_value=0), \
                 patch.object(provision_run.time, 'sleep') as sleep:
                with self.assertRaisesRegex(RuntimeError, 'Bad configuration option'):
                    provision_run.connect_handoff(session, timeout=120)
            sleep.assert_not_called()
            ram.run.assert_called_once_with('/sbin/mount')

    def test_transient_connection_error_can_still_reach_guarded_ram(self):
        with tempfile.TemporaryDirectory() as temporary:
            session = self.fixture(temporary)
            ram = Mock()
            ram.run.side_effect = [RuntimeError('Connection refused'), b'/dev/disk0s1s1 on /mnt1 (hfs)\n']
            with patch.object(provision_run, 'Rescue', return_value=ram), \
                 patch.object(provision_run, 'session_build', return_value='10B329'), \
                 patch.object(provision_run.time, 'sleep'):
                self.assertIs(provision_run.connect_handoff(session), ram)
            ram.guard.assert_called_once_with(['/dev/disk0s1s1 on /mnt1'])
            self.assertIn('Connection refused', (session/'handoff-ssh.log').read_text())
