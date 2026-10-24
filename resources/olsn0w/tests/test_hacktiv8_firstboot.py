"""Deferred Hacktiv8 must survive cache replacement and cannot reboot forever."""
from pathlib import Path
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import hacktiv8


class FirstBoot(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name)
        self.cache=self.root/'cache.plist';self.cache.write_text('cache')
        self.marker=self.root/'state/mobilegestalt-ready'
        self.events=self.root/'events'
        self.flag=self.root/'patched'
        self.helper=self.command('helper', '''
echo "helper $*" >> "$TEST_EVENTS"
if [ "$1" = --check ]; then test -e "$TEST_FLAG"; exit; fi
test ! -e "$TEST_FAIL_PATCH" || exit 1
test -e "$TEST_BAD_READBACK" || touch "$TEST_FLAG"
''')
        self.lctl=self.command('launchctl', '''
echo "launchctl $*" >> "$TEST_EVENTS"
test ! -e "$TEST_FAIL_DISABLE"
''')
        self.reboot=self.command('reboot','echo reboot >> "$TEST_EVENTS"\n')
        self.sleep=self.command('sleep','exit 0\n')
        self.env=dict(os.environ,TEST_EVENTS=str(self.events),TEST_FLAG=str(self.flag),
                      TEST_FAIL_PATCH=str(self.root/'fail-patch'),
                      TEST_BAD_READBACK=str(self.root/'bad-readback'),
                      TEST_FAIL_DISABLE=str(self.root/'fail-disable'))

    def command(self,name,body):
        path=self.root/name;path.write_text('#!/bin/sh\n'+body);path.chmod(0o755)
        return path

    def run_script(self,cellular=True):
        report=dict(method='mobilegestalt-flag',target=hacktiv8.GESTALT_OLD,
                    deferred=True,cellular_service_disabled=cellular)
        script=hacktiv8.firstboot_files(report)[hacktiv8.FIRSTBOOT_SCRIPT][0].decode()
        for before,after in {
                '/var/lib/hacktiv8':str(self.root/'state'),
                hacktiv8.GESTALT_OLD:str(self.cache),
                hacktiv8.FIRSTBOOT_HELPER:str(self.helper),
                '/bin/launchctl':str(self.lctl),
                '/sbin/reboot':str(self.reboot),
                '/bin/sleep':str(self.sleep)}.items():
            script=script.replace(before,after)
        return subprocess.run(['/bin/sh','-c',script],env=self.env,capture_output=True,text=True,timeout=5)

    def events_read(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def test_stale_success_marker_does_not_hide_replaced_cache_and_reboots_are_bounded(self):
        self.marker.parent.mkdir();self.marker.touch()
        for attempt in (1,2):
            result=self.run_script()
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(self.marker.with_name(self.marker.name+'.attempts').read_text().strip(),str(attempt))
            self.flag.unlink()
        result=self.run_script()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('two restart attempts',result.stderr)
        self.assertEqual(self.events_read().count('reboot'),2)

    def test_already_patched_cache_needs_no_restart(self):
        self.flag.touch()
        self.marker.parent.mkdir();self.marker.touch()
        result=self.run_script()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.events_read()[0],'launchctl disable system/com.apple.CommCenter')
        self.assertNotIn('reboot',self.events_read())

    def test_initial_cellular_disable_still_restarts_a_prepatched_cache(self):
        self.flag.touch()
        result=self.run_script()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.events_read().count('reboot'),1)
        self.assertTrue(self.marker.exists())

    def test_wifi_and_ios7_payloads_do_not_disable_telephony(self):
        self.flag.touch()
        self.assertEqual(self.run_script(cellular=False).returncode,0)
        self.assertFalse(any('launchctl' in line for line in self.events_read()))
        for product,release,expected in (
                ('iPhone5,2','8.3',True),('iPhone4,1','8.4.1',True),
                ('iPad2,6','8.3',True),('iPad3,4','8.3',False),
                ('iPod5,1','8.3',False),('iPhone5,2','7.1.2',False),
                ('iPhone5,2','9.3.5',False)):
            with self.subTest(product=product,release=release):
                self.assertEqual(hacktiv8.requires_cellular_disable(release,product),expected)

    def test_disabling_failure_or_bad_patch_readback_cannot_request_a_restart(self):
        for failure in ('fail-disable','fail-patch','bad-readback'):
            with self.subTest(failure=failure):
                path=self.root/failure;path.touch()
                result=self.run_script()
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn('reboot',self.events_read())
                path.unlink()

    def test_preseeded_cache_still_installs_firstboot_cellular_policy(self):
        from test_hacktiv8 import tar_entry
        entries={'mobile':tar_entry('mobile',directory=True),
                 hacktiv8.GESTALT_OLD[len('/private/var/'):]:
                 tar_entry('cache',plistlib.dumps({'CacheExtra':{}}))}
        report=hacktiv8.prepare_data(entries,'8.3','iPhone5,2','12F70')
        self.assertTrue(report['deferred'])
        self.assertTrue(report['cellular_service_disabled'])
        self.assertIn(hacktiv8.FIRSTBOOT_SCRIPT,hacktiv8.firstboot_files(report))


@unittest.skipUnless(sys.platform=='darwin' and shutil.which('cc'),
                     'Uses host CoreFoundation to test the native helper')
class NativeCheck(unittest.TestCase):
    def test_read_only_check_requires_boolean_true_and_preserves_all_cache_bytes(self):
        with tempfile.TemporaryDirectory() as work:
            root=Path(work);binary=root/'helper'
            source=Path(hacktiv8.__file__).parent/'native/target/hacktiv8_mobilegestalt.c'
            subprocess.run(['cc',str(source),'-framework','CoreFoundation','-o',str(binary)],
                           check=True,capture_output=True)
            for flag in (True,False,'true',1,None):
                with self.subTest(flag=flag):
                    path=root/'cache.plist'
                    extra={} if flag is None else {hacktiv8.GESTALT_KEY:flag}
                    original=plistlib.dumps({'CacheExtra':extra,'preserved':'value'})
                    path.write_bytes(original)
                    result=subprocess.run([str(binary),'--check',str(path)])
                    self.assertEqual(result.returncode==0,flag is True)
                    self.assertEqual(path.read_bytes(),original)
            path.write_bytes(plistlib.dumps({'CacheExtra':{'preserved':'value'}}))
            subprocess.run([str(binary),str(path)],check=True)
            subprocess.run([str(binary),'--check',str(path)],check=True)
            self.assertEqual(plistlib.loads(path.read_bytes())['CacheExtra']['preserved'],'value')


if __name__=='__main__':
    unittest.main()

