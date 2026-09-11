"""A developer cache must not change a user's firmware selection or recovery."""
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import common
import firmware
import restore_run

class DistributedState(unittest.TestCase):
    def test_private_developer_firmware_is_not_used(self):
        with tempfile.TemporaryDirectory() as work:
            root=Path(work);kit=root/'kit';state=kit/'saved/olsn0w'
            name='iPhone5,2_8.3_12F70_Restore.ipsw'
            private=kit/'scratchpad/experiment'/name;private.parent.mkdir(parents=True)
            with zipfile.ZipFile(private,'w') as archive:archive.writestr('BuildManifest.plist',b'fixture')
            checksum=hashlib.sha1(private.read_bytes()).hexdigest()
            keys=root/'keys.json';keys.write_text(json.dumps(dict(identifier='iPhone5,2',buildid='12F70')))
            record=dict(version='8.3',buildid='12F70',sha1sum=checksum,url='https://example.invalid/firmware')
            def fetch(url,destination,**kwargs):
                destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(private,destination)
            with patch.object(firmware,'KIT',kit),patch.object(firmware,'STATE',state),patch.object(firmware,'releases',return_value=[record]),patch.object(firmware,'identity',return_value=({'ProductBuildVersion':'12F70'},{})),patch.object(firmware,'fetch',side_effect=fetch) as request:
                result=firmware.acquire('iPhone5,2','8.3',key_file=keys)[0]
                self.assertEqual(result,(state/'ipsw'/name).resolve())
                request.assert_called_once()
                request.reset_mock()
                self.assertEqual(firmware.acquire('iPhone5,2','8.3',key_file=keys)[0],result)
                request.assert_not_called()
        self.assertEqual(common.STATE,common.KIT/'saved/olsn0w')

    def test_startup_timeout_never_reboots_or_reinstalls(self):
        report=dict(version='8.3',build='12F70',generation='fixture',identity={'board':'n42ap'})
        with tempfile.TemporaryDirectory() as work,patch.object(restore_run,'checked_manifest',return_value=report),patch.object(restore_run.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'')) as command:
            with self.assertRaisesRegex(RuntimeError,'startup is not yet confirmed'):
                restore_run.qualify(Path(work),['ssh'], 'fixture',timeout=0,progress=lambda _:None)
            self.assertEqual(command.call_count,2)
            commands=[call.args[0] for call in command.call_args_list]
            self.assertFalse(any('reboot' in str(item) for item in commands))
            self.assertTrue(any('launchctl list' in item[-1] for item in commands))

    def test_ssh_rejection_does_not_postpone_official_activation(self):
        identity={'board':'n42ap','product':'iPhone5,2','ecid':123}
        report=dict(product='iPhone5,2',version='8.1.3',build='12B466',generation='fixture',
                    identity=identity,activation_mode='official-on-target')
        lockdown=plistlib.dumps(dict(ProductType='iPhone5,2',ProductVersion='8.1.3',
            BuildVersion='12B466',BasebandVersion='11.80.00',ActivationState='Unactivated'))
        replies=[subprocess.CompletedProcess([],255,b'',b'Permission denied (publickey)'),
                 subprocess.CompletedProcess([],0,lockdown,b'')]
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run.subprocess,'run',side_effect=replies), \
             patch('activation.activate') as activate, \
             patch('activation.acknowledge',return_value={'activation_state':'Activated','acknowledged':True}) as acknowledge:
            with self.assertRaisesRegex(RuntimeError,'SSH rejected the prepared key'):
                restore_run.qualify(Path(work),['ssh'],'fixture',timeout=0,progress=lambda _:None)
            activate.assert_called_once()
            acknowledge.assert_called_once()
