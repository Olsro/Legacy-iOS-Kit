from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from provision import HANDOFF, copy_ipsw, handoff_sleep, reboot_hook, require_completed_restore
from provision_run import record_failed_restore

class ProvisionHandoff(unittest.TestCase):
    def test_failure_diagnostics_preserve_error_without_reboot_or_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            state={'complete':False,'error':'ASR validation failed'}
            ram=Mock();ram.run.return_value=b'captured\n'
            with patch('provision_run.connect_handoff',return_value=ram):
                record_failed_restore('session',directory,state)
            self.assertEqual(state['error'],'ASR validation failed')
            self.assertFalse(state['complete'])
            self.assertTrue(state['rescue_accessible'])
            self.assertEqual({call.args[0] for call in ram.run.call_args_list},
                             {'/sbin/mount','/bin/launchctl list','/usr/sbin/nvram auto-boot'})
            self.assertEqual((Path(directory)/'failed-restore-boot-setting.txt').read_bytes(),b'captured\n')
            state={'complete':False,'error':'ASR validation failed'}
            with patch('provision_run.connect_handoff',side_effect=RuntimeError('USB closed')):
                record_failed_restore('session',directory,state)
            self.assertEqual(state['error'],'ASR validation failed')
            self.assertEqual(state['rescue_diagnostic_error'],'USB closed')

    def test_reboot_stays_held_without_writing_the_ram_filesystem(self):
        self.assertTrue(handoff_sleep())
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/'nvram'
            script=reboot_hook('a'*32).decode()
            self.assertNotIn('/sbin/mount',script)
            self.assertNotIn('exec /sbin/reboot',script)
            script=script.replace('/usr/sbin/nvram', "printf '%s\\n'")
            script=script.replace(HANDOFF+'='+'a'*32, HANDOFF+'='+'a'*32+' > '+str(marker))
            process=subprocess.Popen(['bash','-c',script],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+3
                while not marker.exists() and time.monotonic()<deadline:
                    time.sleep(.01)
                self.assertEqual(marker.read_text(),HANDOFF+'='+'a'*32+'\n')
                self.assertIsNone(process.poll())
            finally:
                if process.poll() is None:process.terminate()
                process.communicate(timeout=3)

    def test_failed_restore_or_foreign_marker_cannot_authorize_handoff(self):
        token='a'*32
        require_completed_restore(0, 'Cleaning up...\nDONE\n', (token+'\n').encode(), token)
        for code, text, marker in [(1,'DONE',token+'\n'),(0,'not DONE',token+'\n'),
                                   (0,'DONE','b'*32+'\n'),(0,'DONE','')]:
            with self.assertRaises(ValueError):
                require_completed_restore(code,text,marker.encode(),token)
        with self.assertRaises(ValueError):reboot_hook("'; reboot")
        subprocess.run(['bash','-n'],input=reboot_hook(token),check=True)
    def test_repack_preserves_stock_system_and_replaces_only_ram(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);original=directory/'original.zip';target=directory/'target.zip'
            with zipfile.ZipFile(original,'w',compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr('system.dmg',b'original system'*1000)
                z.writestr('ramdisk.dmg',b'original ram')
                z.writestr('Firmware/iBoot',b'signed boot')
            replacement=directory/'replacement';replacement.write_bytes(b'new ram')
            copy_ipsw(original,target,{'ramdisk.dmg':replacement})
            with zipfile.ZipFile(target) as z:
                self.assertEqual(z.read('system.dmg'),b'original system'*1000)
                self.assertEqual(z.read('Firmware/iBoot'),b'signed boot')
                self.assertEqual(z.read('ramdisk.dmg'),b'new ram')
    def test_ambiguous_or_missing_components_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);original=directory/'original.zip'
            with zipfile.ZipFile(original,'w') as z:z.writestr('../ramdisk',b'x')
            with self.assertRaises(ValueError):copy_ipsw(original,directory/'out',{'../ramdisk':b'y'})
            with self.assertRaises(ValueError):copy_ipsw(original,directory/'out',{'missing':b'y'})
