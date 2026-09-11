from pathlib import Path
import plistlib
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from system import defer_profile_service, LATE_MIS_SERVICES, cydia_startup_job

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
