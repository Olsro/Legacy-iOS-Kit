"""Stashing must authenticate first and report what Cydia really relocated."""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import stash


class Target:
    def __init__(self, states, fail=None):
        self.states = list(states)
        self.fail = fail
        self.commands = []
        self.prefix = ['ssh', 'selected-target']

    def run(self, command, data=None, timeout=30):
        self.commands.append(data.decode() if data else command)
        if data == stash.RUN.encode() and self.fail:
            raise self.fail
        if command == stash.STATE:
            return ''.join(s+' '+d+'\n' for d, s in zip(stash.DIRECTORIES, self.states.pop(0))).encode()
        return b''


class Stash(unittest.TestCase):
    product = 'iPad2,5'
    udid = 'a'*40
    info = dict(product=product, ecid=123, version='6.1.3', build='10B329')
    fresh = ['directory', 'directory', 'directory', 'missing', 'directory']
    done = ['stashed']*5

    def start(self, target):
        self.folder = Path('bundle')
        self.messages = []
        @contextmanager
        def connect(udid, folder):
            self.assertEqual((udid, folder), (self.udid, self.folder))
            yield target
        patches = dict(
            device_info=patch.object(stash, 'device_info', return_value=self.info),
            candidates=patch.object(stash, 'candidates', return_value=[(self.folder, {})]),
            check_target=patch.object(stash, 'check_target'),
            allow_suid=patch.object(stash, 'allow_suid', return_value=False),
            connect=patch.object(stash, 'connect', side_effect=connect))
        self.mocks = {}
        for name, patcher in patches.items():
            self.mocks[name] = patcher.start()
            self.addCleanup(patcher.stop)

    def stash(self):
        stash.stash(self.product, self.udid, '123', progress=self.messages.append)

    def test_relocates_after_authentication_and_readiness(self):
        target = Target([self.fresh, self.done])
        self.start(target)
        self.stash()
        self.assertEqual(self.mocks['check_target'].call_count, 2)
        self.assertEqual(target.commands[:3], [stash.READY, stash.STATE, stash.RUN])
        self.assertIn('Stashed: '+', '.join(stash.DIRECTORIES), self.messages)
        self.assertIn('Stashing completed', self.messages[-1])

    def test_already_stashed_changes_nothing(self):
        target = Target([self.done])
        self.start(target)
        self.stash()
        self.assertNotIn(stash.RUN, target.commands)
        self.assertIn('already stashed', self.messages[-1])

    def test_already_stashed_target_still_gets_the_mount_fix(self):
        target = Target([self.done])
        self.start(target)
        self.mocks['allow_suid'].return_value = True
        self.stash()
        self.assertNotIn(stash.RUN, target.commands)
        self.assertIn('nosuid', self.messages[0])
        self.assertIn('Restart the device now', self.messages[-1])

    def test_mount_fix_precedes_relocation(self):
        target = Target([self.fresh, self.done])
        self.start(target)
        self.mocks['allow_suid'].side_effect = lambda connection: target.commands.append('fstab') or True
        self.stash()
        self.assertLess(target.commands.index('fstab'), target.commands.index(stash.RUN))
        self.assertIn('Restart the device now', self.messages[-1])

    def test_unexpected_fstab_stops_before_relocation(self):
        target = Target([self.fresh])
        self.start(target)
        self.mocks['allow_suid'].side_effect = ValueError('Unexpected Data mount')
        with self.assertRaisesRegex(ValueError, 'Unexpected Data mount'):
            self.stash()
        self.assertNotIn(stash.RUN, target.commands)

    def test_unauthenticated_target_is_not_modified(self):
        target = Target([self.fresh])
        self.start(target)
        self.mocks['check_target'].side_effect = ValueError('other generation')
        with self.assertRaisesRegex(RuntimeError, 'Cannot authenticate'):
            self.stash()
        self.assertEqual(target.commands, [])

    def test_unexpected_file_is_refused_before_relocation(self):
        target = Target([['other']+self.fresh[1:]])
        self.start(target)
        with self.assertRaisesRegex(ValueError, '/Applications'):
            self.stash()
        self.assertNotIn(stash.RUN, target.commands)

    def test_skipped_directory_is_reported(self):
        target = Target([self.fresh, ['directory']+self.done[1:]])
        self.start(target)
        with self.assertRaisesRegex(RuntimeError, 'Not stashed.*: /Applications\\.'):
            self.stash()
        self.assertIn('Stashed: '+', '.join(stash.DIRECTORIES[1:]), self.messages)

    def test_failure_and_timeout_are_reported(self):
        for error, expected in ((RuntimeError('Cydia relocation failed:'), 'relocation failed'),
                                (subprocess.TimeoutExpired('ssh', 1), 'still running')):
            target = Target([self.fresh], fail=error)
            self.start(target)
            with self.assertRaisesRegex(RuntimeError, expected):
                self.stash()

    def test_cli_dispatches_stash_without_restoration(self):
        import olsn0w
        args = ['olsn0w.py', 'stash', '--product', self.product, '--udid', self.udid, '--ecid', '123']
        with patch.object(sys, 'argv', args), patch('runtime.ensure_runtime'), \
                patch('ssh_client.check'), patch.object(stash, 'stash') as run:
            olsn0w.main()
        run.assert_called_once_with(self.product, self.udid, '123', None)


class Fstab(unittest.TestCase):
    stock = (b'/dev/disk0s1s3 / hfs ro 0 1\n'
             b'/dev/disk0s1s2 /private/var hfs rw,nosuid,nodev,protect 0 2\n')

    def test_only_nosuid_is_removed_from_the_data_mount(self):
        result = stash.suid_fstab(self.stock)
        self.assertEqual(result, self.stock.replace(b'rw,nosuid,nodev', b'rw,nodev'))
        self.assertEqual(stash.suid_fstab(result), result)
        spaced = b'# data\n/dev/disk0s2  /private/var  hfs  nosuid,rw  0 2'
        self.assertEqual(stash.suid_fstab(spaced), b'# data\n/dev/disk0s2 /private/var hfs rw 0 2')

    def test_unfamiliar_fstab_is_refused(self):
        for content in (b'/dev/disk0s1 / hfs ro 0 1\n', self.stock+self.stock.splitlines()[1]+b'\n',
                        self.stock.replace(b'rw,nosuid', b'ro,nosuid'),
                        self.stock.replace(b'/private/var hfs', b'/private/var apfs'),
                        self.stock.replace(b' 0 2', b' 0')):
            with self.subTest(content=content), self.assertRaises(ValueError):
                stash.suid_fstab(content)


class LocalConnection:
    """Run the fstab transaction's real shell operations in a disposable tree."""
    def __init__(self, root, corrupt=False, fail=False):
        self.root, self.corrupt, self.fail = root, corrupt, fail
        (root/'private/etc').mkdir(parents=True)
        (root/'var/lib/olsn0w').mkdir(parents=True)
        (root/'private/etc/fstab').write_bytes(Fstab.stock)

    def local(self, command):
        return (command.replace('/sbin/mount -u -w /', 'true').replace('/bin/sync', 'true')
                .replace('/private/etc/', str(self.root/'private/etc')+'/')
                .replace('/var/lib/olsn0w/', str(self.root/'var/lib/olsn0w')+'/'))

    def read(self, path):
        data = Path(self.local(path)).read_bytes()
        return b'corrupted' if self.corrupt and path == stash.FSTAB and b'nosuid' not in data else data

    def run(self, command, data=None, timeout=30):
        if command == '/bin/sh -s':
            command, data = data.decode(), None
        elif self.fail and '/bin/mv -f' in command:
            command = command.replace('/bin/mv -f', 'false')
        result = subprocess.run(['/bin/sh', '-c', self.local(command)], input=data, capture_output=True)
        if result.returncode:
            raise RuntimeError('Transaction failed')
        return result.stdout


class FstabTransaction(unittest.TestCase):
    def target(self, **options):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        return LocalConnection(self.root, **options)

    def files(self):
        return sorted(p.name for p in (self.root/'private/etc').iterdir())

    def test_updates_once_and_keeps_the_original(self):
        connection = self.target()
        self.assertTrue(stash.allow_suid(connection))
        self.assertEqual((self.root/'private/etc/fstab').read_bytes(), stash.suid_fstab(Fstab.stock))
        backups = list((self.root/'var/lib/olsn0w').glob('stash-fstab-*/original'))
        self.assertEqual([b.read_bytes() for b in backups], [Fstab.stock])
        self.assertFalse(stash.allow_suid(connection))
        self.assertEqual(len(list((self.root/'var/lib/olsn0w').iterdir())), 1)
        self.assertEqual(self.files(), ['fstab'])

    def test_failed_commit_or_readback_restores_the_original(self):
        for options in (dict(fail=True), dict(corrupt=True)):
            with self.subTest(**options):
                connection = self.target(**options)
                with self.assertRaises(RuntimeError):
                    stash.allow_suid(connection)
                self.assertEqual((self.root/'private/etc/fstab').read_bytes(), Fstab.stock)
                self.assertEqual(self.files(), ['fstab'])


class DeviceScripts(unittest.TestCase):
    """Run the real device shell text against a disposable tree."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def local(self, script):
        for path in ('/private/var/lib/olsn0w/', '/var/lib/olsn0w/', '/private/var/run/',
                     '/usr/libexec/cydia/'):
            script = script.replace(path, str(self.root)+'/')
        script = script.replace(stash.PATH, '').replace('/sbin/mount -u -w /', 'true')
        for tool in ('cat', 'rm', 'sync'):
            script = script.replace('/bin/'+tool, tool)
        return script

    def run_script(self, script):
        return subprocess.run(['/bin/sh', '-c', self.local(script)], capture_output=True, cwd=self.root)

    def helpers(self, free='exit 0'):
        for name in ('free.sh', 'move.sh', 'du', 'setnsfpn'):
            (self.root/name).write_text('#!/bin/sh\n'+(free if name == 'free.sh' else '')+'\n')
            (self.root/name).chmod(0o755)

    def test_ready_requires_cydia_marker_and_helpers(self):
        (self.root/'generation').write_text('g\n')
        self.helpers()
        self.assertIn(b'has not completed', self.run_script(stash.READY).stderr)
        (self.root/'cydia-ready').write_text('g\n')
        self.assertEqual(self.run_script(stash.READY).returncode, 0)
        (self.root/'setnsfpn').unlink()
        self.assertIn(b'setnsfpn', self.run_script(stash.READY).stderr)

    def test_run_logs_failure_and_releases_lock(self):
        self.helpers('echo moving; exit 3')
        result = self.run_script(stash.RUN)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'moving', result.stderr)
        self.assertFalse((self.root/'olsn0w-stash.lock').exists())
        self.helpers()
        self.assertEqual(self.run_script(stash.RUN).returncode, 0)

    def test_run_refuses_a_live_lock_from_this_boot_only(self):
        self.helpers('echo ran > '+str(self.root/'ran'))
        boot = subprocess.run(['sysctl', '-n', 'kern.boottime'], capture_output=True)
        if boot.returncode:
            self.skipTest('kern.boottime is unavailable on this host')
        lock = self.root/'olsn0w-stash.lock'
        lock.write_bytes(str(os.getpid()).encode()+b' '+boot.stdout)
        self.assertEqual(self.run_script(stash.RUN).returncode, 75)
        self.assertFalse((self.root/'ran').exists())
        lock.write_text(str(os.getpid())+' another boot\n')
        self.assertEqual(self.run_script(stash.RUN).returncode, 0)
        self.assertTrue((self.root/'ran').exists())

    def test_state_distinguishes_links_and_directories(self):
        script = stash.STATE
        names = ['stashed', 'broken', 'directory', 'other', 'missing']
        for directory, name in zip(stash.DIRECTORIES, names):
            script = script.replace(directory+' ', str(self.root/name)+' ', 1).replace(
                directory+';', str(self.root/name)+';', 1)
        (self.root/'real').mkdir()
        (self.root/'stashed').symlink_to(self.root/'real')
        (self.root/'broken').symlink_to(self.root/'absent')
        (self.root/'directory').mkdir()
        (self.root/'other').write_text('')
        output = subprocess.run(['/bin/sh', '-c', script], capture_output=True).stdout.decode()
        self.assertEqual([line.split()[0] for line in output.splitlines()], names)


if __name__ == '__main__':
    unittest.main()
