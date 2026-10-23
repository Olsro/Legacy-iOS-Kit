"""Noninteractive nested DFU startup and whole-process-group timeout regressions."""
import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import rescue


class BootCommand(unittest.TestCase):
    def test_command_cannot_read_menu_input_and_diagnostics_are_visible_and_logged(self):
        with tempfile.TemporaryDirectory() as root, contextlib.redirect_stderr(io.StringIO()) as terminal:
            code='import sys; print("stdin="+repr(sys.stdin.read())); print("diagnostic",file=sys.stderr)'
            output=rescue.run_boot_command([sys.executable,'-c',code],Path(root),'kit-pwn',5)
            self.assertIn("stdin=''",output)
            self.assertIn('diagnostic',terminal.getvalue())
            self.assertEqual((Path(root)/'kit-pwn.log').read_text(),output)

    def test_timeout_kills_descendants_that_keep_output_pipe_open(self):
        with tempfile.TemporaryDirectory() as root:
            code=('import subprocess,sys; '
                  'subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
                  'print("spawned child",flush=True)')
            started=time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                rescue.run_boot_command([sys.executable,'-c',code],Path(root),'timeout',.3)
            self.assertLess(time.monotonic()-started,4)
            self.assertIn('spawned child',(Path(root)/'timeout.log').read_text())

    def test_command_failure_retains_the_error_log(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(RuntimeError,'failure.log'):
                rescue.run_boot_command([sys.executable,'-c','print("reason"); raise SystemExit(7)'],
                                        Path(root),'failure',5)
            self.assertIn('reason',(Path(root)/'failure.log').read_text())

    def test_linux_uses_noninteractive_helper_with_selected_identity(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)
            (session/'device.json').write_text(json.dumps({
                'identity':{'ecid':123,'product':'iPhone5,2'}}))
            calls=[]
            def run(argv,label,timeout=45):
                calls.append((list(map(str,argv)),label,timeout))
                return 'SRTG: N/A\nIBFL: 0x1b\n' if label=='ibss-ready' else ''
            with patch.object(rescue.platform,'system',return_value='Linux'), \
                 patch.object(rescue,'unique_usb_target'), \
                 patch.object(rescue,'recheck_recovery',return_value={'mode':'DFU'}), \
                 patch.object(rescue.time,'sleep'):
                rescue.prepare_dfu(session,run=run)
            argv,label,timeout=calls[0]
            self.assertEqual((label,timeout),('kit-pwn',180))
            self.assertIn('--olsn0w-pwn',argv)
            self.assertIn('--device=iPhone5,2',argv)
            self.assertIn('--ecid=123',argv)


class NestedPwnStartup(unittest.TestCase):
    script=(rescue.KIT/'restore.sh').read_text()

    def function(self,name):
        return re.search(r'^'+re.escape(name)+r'\(\) \{\n.*?^\}',self.script,re.M|re.S).group()

    def shell(self,code):
        return subprocess.run(['bash','-c',code],capture_output=True,text=True,timeout=5)

    def test_internal_mode_discovers_identity_instead_of_prompting_for_manual_entry(self):
        result=self.shell('error() { echo "$*"; exit 1; }\n'+self.function('olsn0w_pwn_init')+'''
olsn0w_internal_pwn=1
main_argmode=pwned-ibss
device_type=iPhone5,2
device_ecid=123
device_argmode=entry
olsn0w_pwn_init
echo "$olsn0w_expected_product:$olsn0w_expected_ecid:$device_argmode:$device_type:$device_ecid:$device_disable_usbmuxd"
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'iPhone5,2:123::::1')

    def test_internal_mode_rejects_wrong_operation_or_missing_identity(self):
        for mode,ecid in [('downgrade','123'),('pwned-ibss',''),('pwned-ibss','not-a-number')]:
            result=self.shell('error() { echo "$*"; exit 1; }\n'+self.function('olsn0w_pwn_init')+
                              '\nolsn0w_internal_pwn=1; device_type=iPhone5,2; main_argmode='+mode+
                              '; device_ecid='+ecid+'; olsn0w_pwn_init\n')
            self.assertNotEqual(result.returncode,0)

    def test_actual_usb_identity_must_match_session_before_exploit(self):
        for product,ecid,mode in [('iPhone5,2','123','DFU'),('iPhone5,1','123','DFU'),
                                 ('iPhone5,2','456','DFU'),('iPhone5,2','123','Recovery')]:
            result=self.shell('error() { echo "$*"; exit 1; }\n'+self.function('olsn0w_pwn_check_identity')+
                              '\nolsn0w_internal_pwn=1; olsn0w_expected_product=iPhone5,2; olsn0w_expected_ecid=123; '+
                              'device_type='+product+'; device_ecid='+ecid+'; device_mode='+mode+
                              '; olsn0w_pwn_check_identity\n')
            self.assertEqual(result.returncode==0,(product,ecid,mode)==('iPhone5,2','123','DFU'))

    def test_nested_helper_preserves_parent_tmp_without_opening_a_menu(self):
        start=self.script.index('\nothertmp=$(ls ')
        end=self.script.index('\nothertmp=$(ls ',start+1)
        for internal in ('0','1'):
            with tempfile.TemporaryDirectory() as root:
                root=Path(root);parent=root/'tmp-parent';parent.mkdir()
                (parent/'keep').write_text('parent state')
                script=root/'restore.sh'
                script.write_text('''log() { :; }
print() { :; }
select_yesno() { touch "$(dirname "$0")/prompted"; return 0; }
clean() { touch "$(dirname "$0")/cleaned"; }
olsn0w_internal_pwn='''+internal+'\n'+self.script[start:end])
                result=subprocess.run(['bash',str(script)],capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual((parent/'keep').read_text(),'parent state')
                self.assertEqual((root/'prompted').exists(),internal=='0')
                self.assertFalse((root/'cleaned').exists())


if __name__=='__main__':
    unittest.main()

