import hashlib
import json
import os
from pathlib import Path
import plistlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import external_ssh as ssh

CONFIG = b'''Port 22
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_rsa_key
PermitRootLogin yes
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile /etc/ssh/olsn0w_authorized_keys
AllowUsers root
UsePrivilegeSeparation no
'''
ACCOUNTS = (b'root:old:0:0::0:0:System Administrator:/var/root:/bin/sh\n'
            b'mobile:unchanged:501:501::0:0:Mobile User:/var/mobile:/bin/sh\n')


class LocalTarget:
    """Run the file transaction's real shell operations in a disposable tree."""
    def __init__(self, root, fail_commit=False, corrupt_stage=False, fail_lint=False):
        self.root = root
        self.fail_commit = fail_commit
        self.corrupt_stage = corrupt_stage
        self.fail_lint = fail_lint
        self.commands = []
        for path in ssh.CONFIGS:
            self.path(path).parent.mkdir(parents=True, exist_ok=True)
            self.path(path).write_bytes(CONFIG)
        self.path(ssh.MASTER).write_bytes(ACCOUNTS)
        self.path(ssh.MASTER).chmod(0o600)
        (root/'var/lib/olsn0w').mkdir(parents=True)

    def path(self, path):
        return self.root/path.lstrip('/')

    def read(self, path):
        if self.corrupt_stage and path.endswith('1.new'):
            return b'corrupted'
        return self.path(path).read_bytes()

    def run(self, command, data=None):
        self.commands.append(command)
        if command.startswith('/usr/sbin/sshd -t -f '):
            if self.fail_lint:
                raise RuntimeError('Invalid sshd configuration')
            self.assert_config(self.read(shlex.split(command)[-1]))
            return b''
        if command == '/bin/sh -s':
            script = data.decode()
            if self.fail_commit:
                lines = script.splitlines()
                moves = [i for i, line in enumerate(lines) if line.startswith('/bin/mv -f')]
                if moves:
                    lines[moves[1]] = 'false'
                script = '\n'.join(lines)+'\n'
            command, data = script, None
        command = command.replace('/sbin/mount -u -w /', 'true')
        command = command.replace('/bin/sync', 'true')
        command = command.replace('/bin/launchctl list org.olsn0w.sshd', 'true')
        command = command.replace('/etc/', str(self.root/'etc')+'/')
        command = command.replace('/usr/local/share/', str(self.root/'usr/local/share')+'/')
        command = command.replace('/var/lib/olsn0w/', str(self.root/'var/lib/olsn0w')+'/')
        result = subprocess.run(['/bin/sh', '-c', command], input=data, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stderr.decode() or 'Transaction failed')
        return result.stdout

    @staticmethod
    def assert_config(data):
        assert b'ListenAddress 0.0.0.0\n' in data
        assert b'PasswordAuthentication yes\n' in data


class ExternalSSHTests(unittest.TestCase):
    def test_network_password_settings_preserve_usb_key_and_compatibility(self):
        result = ssh.external_config(CONFIG+b'listenaddress ::1\nPASSWORDauthenticatioN no\n')
        self.assertEqual(result.count(b'ListenAddress '), 2)
        self.assertIn(b'ListenAddress ::\n', result)
        self.assertNotIn(b'127.0.0.1', result)
        self.assertNotIn(b'::1', result)
        self.assertNotIn(b'PASSWORDauthenticatioN no', result)
        self.assertIn(b'AuthorizedKeysFile /etc/ssh/olsn0w_authorized_keys\n', result)
        self.assertIn(b'UsePrivilegeSeparation no\n', result)
        self.assertEqual(ssh.external_config(result), result)

    def test_conditional_configuration_is_rejected(self):
        for directive in (b'Match User root\n', b'Include other.conf\n'):
            with self.assertRaises(ValueError):
                ssh.external_config(CONFIG+directive)

    def test_cydia_default_config_keeps_default_keys_and_adds_olsn0w_key(self):
        result = ssh.external_config(b'#AuthorizedKeysFile .ssh/authorized_keys\n')
        self.assertIn(b'AuthorizedKeysFile /etc/ssh/olsn0w_authorized_keys '
                      b'.ssh/authorized_keys .ssh/authorized_keys2\n', result)
        self.assertIn(b'PubkeyAuthentication yes\n', result)
        self.assertEqual(ssh.external_config(result), result)

    def test_only_root_password_is_reset(self):
        result = ssh.root_password(ACCOUNTS)
        self.assertEqual(result, ACCOUNTS.replace(b'root:old:', b'root:/smx7MYTQIi2M:'))
        self.assertEqual(ssh.root_password(result), result)
        for invalid in (b'', ACCOUNTS+ACCOUNTS, ACCOUNTS.replace(b':0:0:', b':501:0:')):
            with self.assertRaises(ValueError):
                ssh.root_password(invalid)

    def test_commit_saves_originals_and_installs_both_configs(self):
        with tempfile.TemporaryDirectory() as directory:
            target = LocalTarget(Path(directory))
            backup = ssh.apply(target)
            for i, path in enumerate((*ssh.CONFIGS, ssh.MASTER)):
                expected = ssh.root_password(ACCOUNTS) if path == ssh.MASTER else ssh.external_config(CONFIG)
                self.assertEqual(target.read(path), expected)
                self.assertEqual(target.read(backup+'/'+str(i)+'.original'),
                                 ACCOUNTS if path == ssh.MASTER else CONFIG)
            self.assertEqual(target.path(ssh.MASTER).stat().st_mode & 0o777, 0o600)
            self.assertEqual(sum(c.startswith('/usr/sbin/sshd -t') for c in target.commands), 2)
            second = ssh.apply(target)
            self.assertNotEqual(backup, second)
            self.assertEqual(target.read(backup+'/2.original'), ACCOUNTS)

    def test_failed_second_replacement_rolls_back_every_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = LocalTarget(Path(directory), fail_commit=True)
            with self.assertRaises(RuntimeError):
                ssh.apply(target)
            for path in ssh.CONFIGS:
                self.assertEqual(target.read(path), CONFIG)
            self.assertEqual(target.read(ssh.MASTER), ACCOUNTS)

    def test_staging_or_lint_failure_cannot_change_installed_files(self):
        for options in (dict(corrupt_stage=True), dict(fail_lint=True)):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                target = LocalTarget(Path(directory), **options)
                with self.assertRaises(RuntimeError):
                    ssh.apply(target)
                for path in ssh.CONFIGS:
                    self.assertEqual(target.read(path), CONFIG)
                self.assertEqual(target.read(ssh.MASTER), ACCOUNTS)

    def test_password_probe_disables_key_authentication(self):
        prefix = ['ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', 'root@127.0.0.1']
        with patch.object(ssh.subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, b'0\n', b'')
            self.assertEqual(ssh.Connection(prefix).run('id -u', password=True), b'0\n')
            args, kwargs = run.call_args
            argv = args[0]
            self.assertNotIn('BatchMode=yes', argv)
            self.assertIn('PubkeyAuthentication=no', argv)
            self.assertIn('PreferredAuthentications=password', argv)
            self.assertEqual(argv[-2:], ['root@127.0.0.1', 'id -u'])
            self.assertEqual(kwargs['env']['SSHPASS'], 'alpine')
            self.assertNotIn('alpine', argv)
            self.assertEqual(prefix[2], 'BatchMode=yes')

    def test_target_generation_or_service_mismatch_is_rejected(self):
        report = dict(product='iPad2,5', build='11D257', generation='a'*32)
        job = dict(Label='org.olsn0w.sshd', KeepAlive=True,
                   ProgramArguments=['/usr/sbin/sshd', '-D', '-e', '-f', ssh.CONFIGS[1]])
        from unittest.mock import Mock
        connection = Mock()
        connection.run.side_effect = [b'', b'P105AP\n11D257\n'+b'a'*32+b'\n', b'0\n']
        connection.read.return_value = plistlib.dumps(job)
        ssh.check_target(connection, report)
        connection.run.side_effect = [b'', b'P105AP\n11D257\n'+b'b'*32+b'\n']
        with self.assertRaisesRegex(ValueError, 'selected installed'):
            ssh.check_target(connection, report)
        connection.run.side_effect = [b'', b'P105AP\n11D257\n'+b'a'*32+b'\n', b'0\n']
        job['ProgramArguments'][-1] = '/different/config'
        connection.read.return_value = plistlib.dumps(job)
        with self.assertRaisesRegex(ValueError, 'service'):
            ssh.check_target(connection, report)

    def test_configure_restarts_and_requires_a_password_login(self):
        from unittest.mock import Mock
        connection = Mock()
        connection.run.return_value = b'0\n'
        with (patch.object(ssh, 'device_info', return_value={}),
              patch.object(ssh, 'candidates', return_value=[(Path('/fixture'), {})]),
              patch.object(ssh, 'connect') as connect,
              patch.object(ssh, 'check_target'),
              patch.object(ssh, 'apply', return_value='/backup')):
            connect.return_value.__enter__.return_value = connection
            messages = []
            ssh.configure('iPad2,5', 'a'*40, progress=messages.append)
        connection.run.assert_any_call(ssh.RESTART_SSH)
        connection.run.assert_any_call(ssh.ROOT_CHECK, password=True)
        connection.run.assert_any_call(ssh.ROOT_CHECK)
        self.assertTrue(any('OpenSSH verified' in message for message in messages))

    def test_cydia_socket_service_replaces_duplicate_listener_and_supports_retries(self):
        for stock, olsn0w, expected in (
                (True, True, ['unload -w '+ssh.JOB, 'stop com.openssh.sshd']),
                (True, False, ['stop com.openssh.sshd']),
                (False, True, ['stop org.olsn0w.sshd'])):
            with self.subTest(stock=stock, olsn0w=olsn0w), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stub = root/'launchctl'
                stub.write_text('#!'+sys.executable+'\n'+'''import os, sys
from pathlib import Path
root = Path(os.environ['OLSN0W_TEST_SERVICE_DIR'])
args = sys.argv[1:]
if args[0] == 'list':
    sys.exit(0 if (root/args[1]).exists() else 1)
with (root/'calls').open('a') as log:
    log.write(' '.join(args)+'\\n')
if args[0] == 'unload':
    (root/'org.olsn0w.sshd').unlink()
''')
                stub.chmod(0o700)
                if stock: (root/'com.openssh.sshd').touch()
                if olsn0w: (root/'org.olsn0w.sshd').touch()
                result = subprocess.run(['/bin/sh', '-c', ssh.RESTART_SSH.replace(
                    '/bin/launchctl', shlex.quote(str(stub)))], capture_output=True,
                    env=dict(os.environ, OLSN0W_TEST_SERVICE_DIR=directory))
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual((root/'calls').read_text().splitlines(), expected)

    def test_success_is_not_reported_when_password_works_but_key_fails(self):
        from unittest.mock import Mock
        connection = Mock()
        def run(command, password=False):
            if command == ssh.ROOT_CHECK and not password:
                raise RuntimeError('Public key rejected')
            return b'0\n'
        connection.run.side_effect = run
        with (patch.object(ssh, 'device_info', return_value={}),
              patch.object(ssh, 'candidates', return_value=[(Path('/fixture'), {})]),
              patch.object(ssh, 'connect') as connect,
              patch.object(ssh, 'check_target'),
              patch.object(ssh.time, 'sleep'),
              patch.object(ssh, 'apply', return_value='/backup')):
            connect.return_value.__enter__.return_value = connection
            messages = []
            with self.assertRaisesRegex(RuntimeError, 'password and key logins'):
                ssh.configure('iPad2,5', 'a'*40, progress=messages.append)
        self.assertFalse(any('OpenSSH verified' in message for message in messages))

    def test_simple_lockdown_checks_selected_identity_without_pairing(self):
        info = dict(UniqueDeviceID='a'*40, UniqueChipID=123, ProductVersion='7.1.2', BuildVersion='11D257')
        with patch.object(ssh.subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, plistlib.dumps(info), b'')
            selected = ssh.device_info('a'*40, 'iPad2,5', '123')
            self.assertEqual(selected['ecid'], 123)
            self.assertIn('-s', run.call_args[0][0])
            with self.assertRaises(ValueError):
                ssh.device_info('b'*40, 'iPad2,5')
            with self.assertRaises(ValueError):
                ssh.device_info('a'*40, 'iPad2,5', '456')

    def test_discovery_binds_keys_to_hardware_build_and_checks_digests(self):
        info = dict(product='iPad2,5', version='7.1.2', build='11D257', ecid=123)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root/'sessions/example/provision/target'
            bundle.mkdir(parents=True)
            files = {}
            for name in ('ssh_client_rsa', 'ssh_host_rsa_key.pub'):
                (bundle/name).write_bytes(b'test fixture')
                files[name] = hashlib.sha256(b'test fixture').hexdigest()
            report = dict(info, identity=dict(ecid=123), files=files, generation='a'*32)
            (bundle/'manifest.json').write_text(json.dumps(report))
            self.assertEqual(ssh.candidates(info, state=root)[0][0], bundle)
            for key, value in (('ecid', 456), ('build', '10B329'), ('product', 'iPhone4,1')):
                with self.assertRaises(ValueError):
                    ssh.candidates(dict(info, **{key:value}), state=root)
            (bundle/'ssh_client_rsa').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'key differs'):
                ssh.candidates(info, state=root)


if __name__ == '__main__':
    unittest.main()
