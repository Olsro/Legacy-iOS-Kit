from pathlib import Path
import plistlib
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from system import (cydia_startup_job, cydia_startup_script,
                    CYDIA_DEFAULT_SOURCES, data_backed_cydia_sources,
                    defer_profile_service, entry, LATE_MIS_SERVICES,
                    seed_cydia_source_cache, symlink_entry)

class Image:
    def __init__(self):
        self.files={}
        for label,program in LATE_MIS_SERVICES.items():
            self.files['/Library/LaunchDaemons/'+label+'.plist']=plistlib.dumps(dict(
                Label=label,ProgramArguments=[program],MachServices={label:True},UserName='mobile'))
        self.removed=[]
    def read(self,path):return self.files[path]
    def mkdir(self,path):pass
    def add(self,path,data,mode):self.files[path]=data
    def command(self,op,path):
        assert op=='rm'
        self.removed.append(path);del self.files[path]

class ProfileService(unittest.TestCase):
    def test_boot_success_job_rearms_only_after_stable_springboard(self):
        root=Path(__file__).resolve().parents[1]
        job=plistlib.loads((root/'target/boot-success.plist').read_bytes())
        script=(root/'target/boot-success.sh').read_bytes()
        self.assertEqual(job['Label'],'org.olsn0w.boot-success')
        self.assertEqual(job['ProgramArguments'],[
            '/bin/sh','/usr/local/libexec/olsn0w/boot-success.sh'])
        self.assertEqual(job['KeepAlive'],{'SuccessfulExit':False})
        self.assertIn(b'com.apple.SpringBoard',script)
        self.assertIn(b'[ "$stable" -ge 5 ] || exit 1',script)
        self.assertLess(script.index(b'/bin/rm -f "$marker" "$marker.new"'),
                        script.index(b'wait-graphics.sh'))
        self.assertLess(script.index(b'com.apple.SpringBoard'),
                        script.index(b'housekeeper=/usr/libexec/CrashHousekeeping.backup'))
        self.assertIn(b'housekeeper=/usr/libexec/CrashHousekeeping\n',script)
        self.assertIn(b'[ ! -h "$housekeeper" ] || exit 1',script)
        self.assertLess(script.index(b'"$housekeeper"\n'),
                        script.index(b'/usr/sbin/nvram auto-boot=true'))
        self.assertIn(b'$AG_GENERATION',script)

    def test_deferral_preserves_real_apple_services_and_mach_endpoints(self):
        image=Image();original=dict(image.files)
        defer_profile_service(image)
        for source,data in original.items():
            self.assertNotIn(source,image.files)
            self.assertEqual(image.files['/olsn0w/late-jobs/'+source.rsplit('/',1)[1]],data)
        self.assertEqual(image.removed,list(original))
    def test_unknown_program_is_rejected_before_any_job_is_moved(self):
        image=Image();path=list(image.files)[-1]
        job=plistlib.loads(image.files[path]);job['ProgramArguments']=['/another']
        image.files[path]=plistlib.dumps(job)
        with self.assertRaises(ValueError):defer_profile_service(image)
        self.assertFalse(image.removed)
    def test_cydia_retries_failures_only_and_preserves_original_arguments(self):
        job=dict(Label='com.saurik.Cydia.Startup',ProgramArguments=['/bin/bash','/usr/libexec/cydia/startup'])
        result=plistlib.loads(cydia_startup_job(plistlib.dumps(job)))
        self.assertEqual(result['ProgramArguments'],job['ProgramArguments'])
        self.assertEqual(result['KeepAlive'],{'SuccessfulExit':False})
        self.assertTrue(result['RunAtLoad'])
        self.assertGreaterEqual(result['ThrottleInterval'],30)
        job['ProgramArguments']=['/another']
        with self.assertRaises(ValueError):cydia_startup_job(plistlib.dumps(job))

    def test_cydia_completion_marker_is_atomic_and_generation_bound(self):
        original=(b'#!/bin/bash\n/usr/libexec/cydia/firmware.sh\n'
                  b'    sbdidlaunch\n')
        result=cydia_startup_script(original)
        self.assertIn(b'prepare-cydia.sh || exit 1',result)
        self.assertIn(b'/usr/libexec/cydia/firmware.sh || exit 1',result)
        self.assertIn(b'wait-graphics.sh || exit 1',result)
        self.assertIn(b'/bin/cp /var/lib/olsn0w/generation '
                      b'/var/lib/olsn0w/cydia-ready.new || exit 1',result)
        self.assertIn(b'/bin/mv -f /var/lib/olsn0w/cydia-ready.new '
                      b'/var/lib/olsn0w/cydia-ready || exit 1',result)
        self.assertLess(result.index(b'wait-graphics.sh'),result.index(b'cydia-ready.new'))
        with self.assertRaises(ValueError):cydia_startup_script(result)

    def test_cydia_user_link_is_installed_offline(self):
        item,data=symlink_entry('User','/var/mobile')
        self.assertTrue(item.issym())
        self.assertEqual(item.linkname,'/var/mobile')
        self.assertIsNone(data)

    def test_cydia_source_link_uses_real_private_etc_catalog_path(self):
        name='private/etc/apt/sources.list.d/cydia.list'
        payload={name:entry(name,b'',0o644)}
        data_backed_cydia_sources(payload)
        item,data=payload[name]
        self.assertTrue(item.issym())
        self.assertEqual(item.linkname,
                         '/var/mobile/Library/Caches/com.saurik.Cydia/sources.list')
        self.assertIsNone(data)
        self.assertNotIn('etc/apt/sources.list.d/cydia.list',payload)
        with self.assertRaisesRegex(ValueError,'placeholder'):
            data_backed_cydia_sources({name:entry(name,b'changed',0o644)})

    def test_cydia_source_target_is_seeded_with_mobile_ownership(self):
        data={'mobile':entry('mobile',mode=0o755,uid=501,gid=501,directory=True)}
        seed_cydia_source_cache(data)
        directory='mobile/Library/Caches/com.saurik.Cydia'
        item,content=data[directory]
        self.assertTrue(item.isdir())
        self.assertEqual((item.uid,item.gid,item.mode),(501,501,0o755))
        item,content=data[directory+'/sources.list']
        self.assertEqual(content,CYDIA_DEFAULT_SOURCES)
        self.assertEqual((item.uid,item.gid,item.mode),(501,501,0o644))
        self.assertIn(b'apt.thebigboss.org',content)
        with self.assertRaisesRegex(ValueError,'mobile directory'):
            seed_cydia_source_cache({})

    def test_cydia_waits_for_ios7_and_ios8_untether_completion(self):
        script=(Path(__file__).resolve().parents[1]/'target/prepare-cydia.sh').read_bytes()
        self.assertIn(b'[ -x /olsn0w/lctl ]',script)
        self.assertIn(b'/var/run/olsn0w-untether-ready',script)
        self.assertIn(b'$AG_ROOT_DEVICE on / (hfs,',script)
        self.assertIn(b'read-only',script)
        self.assertIn(b'[ "$attempts" -lt 300 ] || exit 1',script)
