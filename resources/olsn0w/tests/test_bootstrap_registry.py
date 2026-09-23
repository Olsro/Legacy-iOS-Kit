import pathlib,sys,struct,plistlib,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from bootstrap_registry import configure,jobs

class Registry(unittest.TestCase):
    def fixture(self):
        payload=plistlib.dumps(dict(VersionNumber=4,LaunchDaemons={},Padding=bytes(3000)),fmt=plistlib.FMT_BINARY)
        data=bytearray(8192);struct.pack_into('<II',data,16,64,1)
        struct.pack_into('<QQQII',data,64,0x1000,4096,4096,1,1)
        data[4096:4096+len(payload)]=payload
        return data,len(payload)
    def test_only_readonly_registry_changes(self):
        delayed=[
            {'Label':'com.apple.notifyd','ProgramArguments':['/usr/sbin/notifyd'],
             'MachServices':{'com.apple.system.notification_center':True}},
            {'Label':'com.apple.powerd','Program':'/System/Library/CoreServices/powerd.bundle/powerd',
             'KeepAlive':True,'MachServices':{'com.apple.PowerManagement.control':True}},
        ]
        data,size=self.fixture();launch=jobs(
            {'Label':'com.apple.MobileFileIntegrity','ProgramArguments':['/usr/libexec/amfid']}, delayed)
        result=configure(data,0x1000,size,launch)
        self.assertEqual(result[:4096],data[:4096]);self.assertEqual(result[4096+size:],data[4096+size:])
        self.assertEqual(plistlib.loads(result[4096:4096+size])['LaunchDaemons'],launch)
        notify=launch['/System/Library/LaunchDaemons/com.apple.notifyd.plist']
        power=launch['/System/Library/LaunchDaemons/com.apple.powerd.plist']
        self.assertEqual(notify['ProgramArguments'], ['/usr/sbin/notifyd'])
        self.assertEqual(power['ProgramArguments'][0], '/olsn0w/service-gate')
        self.assertTrue(notify['RunAtLoad'])
        self.assertTrue(power['RunAtLoad'])
    def test_rejects_executable_mapping_and_outside_range(self):
        data,size=self.fixture();struct.pack_into('<II',data,64+24,5,5)
        with self.assertRaises(ValueError):configure(data,0x1000,size,{})
        data,size=self.fixture()
        with self.assertRaises(ValueError):configure(data,0x2000,size,{})
