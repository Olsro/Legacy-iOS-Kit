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
