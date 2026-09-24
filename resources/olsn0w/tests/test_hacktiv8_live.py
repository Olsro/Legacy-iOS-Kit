from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hacktiv8
import hacktiv8_live as live


class FakeConnection:
    def __init__(self, release='5.1.1', build='9B206'):
        self.files = {'/System/Library/CoreServices/SystemVersion.plist': plistlib.dumps(
            dict(ProductVersion=release, ProductBuildVersion=build)),
            hacktiv8.LOCKDOWN: b'prefix'+bytes(v if v is not None else 0xa5
                for v in hacktiv8.LOCKDOWN_PATCHES[0][0])+b'suffix',
            hacktiv8.GESTALT_OLD: plistlib.dumps({'CacheExtra': {'preserved': 42}})}
        self.commands = []
        self.corrupt_stage = False

    def read(self, path):
        if self.corrupt_stage and '.hacktiv8-' in path and not path.endswith('original'):
            return b'corrupt'
        return self.files[path]

    def run(self, command, data=None):
        self.commands.append(command)
        parts = shlex.split(command)
        if command == live.ROOT_CHECK:return b'0\n'
        if command == '/usr/sbin/sysctl -n hw.machine':return b'iPhone4,1\n'
        if command.startswith('if test -e '):
            return b'yes\n' if parts[3] in self.files else b''
        if data is not None:self.files[parts[-1]] = data
        elif '/bin/cp' in parts:
            at = parts.index('/bin/cp')
            source, destination = parts[at+2:at+4]
            self.files[destination.rstrip(';')] = self.files[source]
        elif command.startswith('/bin/mv -f '):
            self.files[parts[3]] = self.files.pop(parts[2])
        return b''


class LivePatchTests(unittest.TestCase):
    def setUp(self):
        # Synthetic pattern fixtures are not complete Mach-O executables.
        signer = patch.object(live, 'rehash_adhoc', side_effect=lambda original, changed: bytes(changed))
        signer.start()
        self.addCleanup(signer.stop)
        verifier = patch.object(live, 'verify')
        self.verifier = verifier.start()
        self.addCleanup(verifier.stop)

    def test_lockdown_backup_commit_and_idempotency(self):
        connection = FakeConnection()
        original = connection.files[hacktiv8.LOCKDOWN]
        with tempfile.TemporaryDirectory() as folder:
            report = live.apply(connection, Path(folder), 'iPhone4,1', '5.1.1', '9B206')
            self.assertTrue(report['changed'] and report['verified'])
            self.assertEqual(connection.files[hacktiv8.LOCKDOWN_BACKUP], original)
            self.assertEqual(connection.files[hacktiv8.LOCKDOWN], hacktiv8.patch_lockdownd(original)[0])
            self.assertEqual((Path(folder)/'original').read_bytes(), original)
            repeated = live.apply(connection, Path(folder), 'iPhone4,1', '5.1.1', '9B206')
            self.assertFalse(repeated['changed'])
            self.assertEqual(connection.files[hacktiv8.LOCKDOWN_BACKUP], original)
            self.verifier.assert_called_once_with(connection.files[hacktiv8.LOCKDOWN])

    def test_mobilegestalt_preserves_other_keys_without_root_remount(self):
        connection = FakeConnection('7.1.2', '11D257')
        with tempfile.TemporaryDirectory() as folder:
            live.apply(connection, Path(folder), 'iPhone4,1', '7.1.2', '11D257')
        cache = plistlib.loads(connection.files[hacktiv8.GESTALT_OLD])['CacheExtra']
        self.assertEqual(cache['preserved'], 42)
        self.assertIs(cache[hacktiv8.GESTALT_KEY], True)
        self.assertNotIn('/sbin/mount -u -w /', connection.commands)

    def test_backup_conflict_never_overwrites_target_or_backup(self):
        connection = FakeConnection()
        connection.files[hacktiv8.LOCKDOWN_BACKUP] = b'earlier backup'
        before = dict(connection.files)
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, 'backup conflicts'):
                live.apply(connection, Path(folder), 'iPhone4,1', '5.1.1', '9B206')
        self.assertEqual(connection.files, before)

    def test_bad_staged_readback_keeps_original_installed(self):
        connection = FakeConnection()
        original = connection.files[hacktiv8.LOCKDOWN]
        connection.corrupt_stage = True
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, 'Staged patch readback'):
                live.apply(connection, Path(folder), 'iPhone4,1', '5.1.1', '9B206')
        self.assertEqual(connection.files[hacktiv8.LOCKDOWN], original)
        self.assertFalse(any(c.startswith('/bin/mv') for c in connection.commands))

    def test_wrong_ssh_version_is_rejected_before_writes(self):
        connection = FakeConnection()
        before = dict(connection.files)
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, 'differs'):
                live.apply(connection, Path(folder), 'iPhone4,1', '6.1.3', '10B329')
        self.assertEqual(connection.files, before)

    def test_wrong_usb_identity_is_rejected(self):
        info = dict(ProductType='iPhone4,1', ProductVersion='5.1.1', BuildVersion='9B206', UniqueDeviceID='wrong')
        with self.assertRaisesRegex(ValueError, 'identity'):
            live.require_identity(info, 'iPhone4,1', '5.1.1', '9B206', 'selected')

    def test_profile_uses_existing_exact_asset(self):
        self.assertEqual(live.patched_bytes('mobilegestalt-profile', b'', 'iPhone4,1', '13G36'),
                         hacktiv8._profile('iPhone4,1', '13G36'))

    def test_root_probe_without_id_on_legacy_bash(self):
        result = subprocess.run(['bash', '-c', 'PATH=/nonexistent; '+live.ROOT_CHECK], capture_output=True)
        # Host UID may differ; never manufacture root privileges in this test.
        import os
        self.assertEqual(result.returncode, 0 if os.geteuid() == 0 else 1)


class TunnelTests(unittest.TestCase):
    def test_failed_tunnel_start_closes_log_and_stops_before_ssh(self):
        process = Mock()
        process.poll.return_value = 1
        with tempfile.TemporaryDirectory() as folder:
            connection = live.Connection('a'*40, Path(folder), 'unused')
            with patch.object(live.subprocess, 'Popen', return_value=process), \
                    patch.object(live.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, 'USB tunnel could not start'):
                    connection.__enter__()
            self.assertTrue(connection.log.closed)


class LiveMenuTests(unittest.TestCase):
    def function(self, name):
        source = (live.KIT/'restore.sh').read_text()
        return re.search(r'^'+name+r'\(\) \{\n.*?^\}', source, re.M | re.S).group()

    def test_menu_places_hactiv8_after_activation(self):
        source = self.function('menu_miscutilities')
        self.assertLess(source.index('"Attempt Activation"'), source.index('"hactiv8"'))
        self.assertIn('"hactiv8" ) device_hacktiv8;;', source)

    def test_ssh_failure_offers_jailbreak_but_does_not_force_it(self):
        for choice in (0, 1, 2):
            script = self.function('device_hacktiv8') + '''
print() { echo "$*"; }; warn() { echo "$*"; }; input() { :; }; pause() { :; }
device_mode=Normal; device_type=iPhone4,1; device_vers=5.1.1
device_build=9B206; device_udid=selected
select_yesno() { return 1; }
attempt=0
python3() {
    [[ $1 == *hacktiv8.py ]] && return 0
    attempt=$((attempt+1)); [[ $attempt == 1 ]] && return 20
    return 0
}
device_jailbreak_confirm() { echo JAILBREAK_OFFERED; }
''' + f'select_option() {{ return {choice}; }}\n' + '''
device_hacktiv8
echo "attempts=$attempt"
'''
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual('JAILBREAK_OFFERED' in result.stdout, choice == 1)
            self.assertIn('attempts='+('2' if choice == 0 else '1'), result.stdout)
