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
from activation import ActivationPending, SavedActivationRestored, ActivationRequiresInput

class DistributedState(unittest.TestCase):
    def test_hacktiv8_preserving_setup_requires_activated_usb_state(self):
        report=dict(product='iPhone5,2',version='8.3',build='12F70',generation='selected',
                    identity={'board':'n42ap','product':'iPhone5,2','ecid':123},
                    activation_mode='skipped-hacktiv8',setup_app_removed=False,
                    hacktiv8={'method':'mobilegestalt-flag','deferred':True,
                              'cellular_service_disabled':True})
        jobs=(b'N42AP\n12F70\nselected\nCYDIA_READY:selected\nBOOT_SUCCESS:selected\n'
              b'10 - com.apple.SpringBoard\n- 0 com.saurik.Cydia.Startup\n')
        for state in ('Unactivated','Activated'):
            with self.subTest(state=state),tempfile.TemporaryDirectory() as work:
                # CommCenter is deliberately disabled, so no live modem version
                # is required; the signed-base restore already checked the modem.
                values=plistlib.dumps(dict(ProductType='iPhone5,2',ProductVersion='8.3',
                                           BuildVersion='12F70',ActivationState=state))
                replies=[subprocess.CompletedProcess([],0,jobs,b''),
                         subprocess.CompletedProcess([],0,values,b'')]
                with patch.object(restore_run,'checked_manifest',return_value=report), \
                     patch.object(restore_run.subprocess,'run',side_effect=replies), \
                     patch('activation.activate') as activate, \
                     patch('activation.acknowledge',return_value={'acknowledged':True}) as acknowledge:
                    if state=='Unactivated':
                        with self.assertRaisesRegex(RuntimeError,'Waiting for Hacktiv8'):
                            restore_run.qualify(Path(work),['ssh'],'fixture',timeout=0,progress=lambda _:None)
                        acknowledge.assert_not_called()
                    else:
                        result=restore_run.qualify(Path(work),['ssh'],'fixture',timeout=0,progress=lambda _:None)
                        self.assertTrue(result['activation_skipped'])
                        self.assertTrue(result['cellular_service_disabled'])
                        acknowledge.assert_called_once()
                    activate.assert_not_called()
                self.assertEqual((Path(work)/'qualification.json').exists(),state=='Activated')

    def test_normal_boot_qualification_preserves_board_revision_and_generation(self):
        for board,model in (('k93aap','K93aAP'),('j2aap','J2aAP')):
            with self.subTest(board=board):
                report=dict(identity={'board':board},build='11D257',generation='selected')
                self.assertTrue(restore_run.target_identity_ready([model,'11D257','selected'],report))
                self.assertFalse(restore_run.target_identity_ready([model,'12H321','selected'],report))
                self.assertFalse(restore_run.target_identity_ready([model,'11D257','other'],report))
                self.assertFalse(restore_run.target_identity_ready(['N42AP','11D257','selected'],report))

    def test_stale_usb_pairing_is_renewed_without_bypassing_qualification(self):
        report=dict(product='iPad3,4',version='6.1.3',build='10B329',generation='selected',
                    identity={'board':'p101ap'},activation_mode='skipped-setup-removed',
                    setup_app_removed=True)
        jobs=(b'P101AP\n10B329\nselected\nCYDIA_READY:selected\nBOOT_SUCCESS:selected\n'
              b'10 - com.apple.SpringBoard\n- 0 com.saurik.Cydia.Startup\n')
        stale=subprocess.CompletedProcess([],1,b'',b'Invalid HostID (-21)')
        ready=subprocess.CompletedProcess([],0,jobs,b'')
        paired=subprocess.CompletedProcess([],0,b'SUCCESS: Paired with device fixture\n',b'')
        for product in ('iPad3,4','iPad2,5',None):
            with self.subTest(product=product),tempfile.TemporaryDirectory() as work:
                values=plistlib.dumps(dict(ProductType=product or 'iPad3,4',
                    ProductVersion='6.1.3',BuildVersion='10B329',ActivationState='Unactivated'))
                replies=[ready,stale,paired]
                if product is not None:
                    replies.extend([ready,subprocess.CompletedProcess([],0,values,b'')])
                notices=[]
                with patch.object(restore_run,'checked_manifest',return_value=report), \
                     patch.object(restore_run.subprocess,'run',side_effect=replies) as command, \
                     patch.object(restore_run.time,'sleep'):
                    if product is None:
                        # Even a successful pair command is not target proof.
                        with self.assertRaisesRegex(RuntimeError,'Trust This Computer'):
                            restore_run.qualify(Path(work),['ssh'],'fixture',timeout=0,
                                                progress=notices.append)
                    elif product!='iPad3,4':
                        with self.assertRaisesRegex(ValueError,'different target'):
                            restore_run.qualify(Path(work),['ssh'],'fixture',progress=notices.append)
                    else:
                        result=restore_run.qualify(Path(work),['ssh'],'fixture',progress=notices.append)
                        self.assertTrue(result['normal_boot_verified'])
                pair_commands=[c.args[0] for c in command.call_args_list
                               if Path(c.args[0][0]).name=='idevicepair']
                self.assertEqual(pair_commands,[[str(common.tools()/'idevicepair'),'-u','fixture','pair']])
                self.assertTrue(any('Trust This Computer' in notice for notice in notices))
                self.assertIn('Invalid HostID',(Path(work)/'pairing.log').read_text())
                self.assertEqual((Path(work)/'qualification.json').exists(),product=='iPad3,4')

    def test_restored_certificate_is_not_reinstalled_or_assumed_activated(self):
        report=dict(setup_app_removed=False,product='iPad3,4',version='7.1.2',build='11D257',generation='selected',
                    identity={'board':'p101ap','product':'iPad3,4','ecid':123},
                    activation_mode='official-on-target')
        jobs=('P101AP\n11D257\nselected\nCYDIA_READY:selected\nBOOT_SUCCESS:selected\n'
              '10 - com.apple.SpringBoard\n- 0 com.saurik.Cydia.Startup\n'
              '- 0 com.apple.accountsd\n- 0 com.apple.managedconfiguration.profiled\n')
        replies=[]
        for state in ('Unactivated','Unactivated','Activated'):
            values=plistlib.dumps(dict(ProductType='iPad3,4',ProductVersion='7.1.2',
                                      BuildVersion='11D257',ActivationState=state))
            replies.extend([subprocess.CompletedProcess([],0,jobs.encode(),b''),
                            subprocess.CompletedProcess([],0,values,b'')])
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run.subprocess,'run',side_effect=replies), \
             patch.object(restore_run.time,'sleep'), \
             patch.object(restore_run.time,'monotonic',side_effect=range(0,1000,20)), \
             patch('activation.activate',side_effect=[SavedActivationRestored('reloading'),
                    ActivationPending('not ready')]) as activate, \
             patch('activation.acknowledge',return_value={'acknowledged':True}) as acknowledge:
            result=restore_run.qualify(Path(work),['ssh'],'fixture',timeout=1000,progress=lambda _:None)
            self.assertEqual(result['activation_state'],'Activated')
            self.assertEqual(activate.call_count,2)
            self.assertTrue(activate.call_args_list[0].kwargs['try_saved'])
            self.assertFalse(activate.call_args_list[1].kwargs['try_saved'])
            self.assertEqual(activate.call_args_list[0].kwargs['target_prefix'],['ssh'])
            acknowledge.assert_called_once()

    def test_account_challenge_stops_qualification_without_retry(self):
        report=dict(setup_app_removed=False,product='iPad3,4',version='7.1.2',build='11D257',generation='selected',
                    identity={'board':'p101ap','product':'iPad3,4','ecid':123},
                    activation_mode='official-on-target')
        values=plistlib.dumps(dict(ProductType='iPad3,4',ProductVersion='7.1.2',
                                  BuildVersion='11D257',ActivationState='Unactivated'))
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run.subprocess,'run',side_effect=[
                 subprocess.CompletedProcess([],1,b'',b''),subprocess.CompletedProcess([],0,values,b'')]), \
             patch('activation.activate',side_effect=ActivationRequiresInput('owner input')) as activate:
            with self.assertRaises(ActivationRequiresInput):
                restore_run.qualify(Path(work),['ssh'],'fixture',progress=lambda _:None)
            activate.assert_called_once()
            self.assertFalse((Path(work)/'qualification.json').exists())

    def test_central_qualification_waits_for_pangu_without_rebooting(self):
        result_record={'writable_root_verified':True}
        with patch.object(restore_run,'qualify',return_value=result_record) as qualify:
            result=restore_run.qualify_installed_target(
                Path('/bundle'),['ssh'],'a'*40,'7.1.2',timeout=480,
                progress=lambda _:None)
        self.assertIs(result,result_record)
        qualify.assert_called_once()
        self.assertTrue(qualify.call_args.kwargs['verify_writable_root'])

        with patch.object(restore_run,'qualify',return_value=result_record) as qualify:
            result=restore_run.qualify_installed_target(
                Path('/bundle'),['ssh'],'a'*40,'8.4.1',progress=lambda _:None)
        self.assertIs(result,result_record)
        qualify.assert_called_once()
        self.assertFalse(qualify.call_args.kwargs['verify_writable_root'])

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
        report=dict(setup_app_removed=False,version='8.3',build='12F70',generation='fixture',identity={'board':'n42ap'})
        with tempfile.TemporaryDirectory() as work,patch.object(restore_run,'checked_manifest',return_value=report),patch.object(restore_run.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'')) as command:
            with self.assertRaisesRegex(RuntimeError,'startup is not yet confirmed'):
                restore_run.qualify(Path(work),['ssh'], 'fixture',timeout=0,progress=lambda _:None)
            self.assertEqual(command.call_count,2)
            commands=[call.args[0] for call in command.call_args_list]
            self.assertFalse(any('reboot' in str(item) for item in commands))
            self.assertTrue(any('launchctl list' in item[-1] for item in commands))

    def test_recovery_return_is_reported_as_terminal_boot_failure(self):
        identity={'board':'p101ap','product':'iPad3,4','chip':0x8955,
                  'board_id':0,'ecid':123}
        report=dict(setup_app_removed=False,product='iPad3,4',version='8.1.3',build='12B466',
                    generation='fixture',identity=identity)
        recovery=(b'PRODUCT: iPad3,4\nMODEL: p101ap\nCPID: 0x8955\n'
                  b'BDID: 0x00\nECID: 0x7b\nMODE: Recovery\n')
        replies=[subprocess.CompletedProcess([],1,b'',b''),
                 subprocess.CompletedProcess([],1,b'',b''),
                 subprocess.CompletedProcess([],0,recovery,b'')]
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run.subprocess,'run',side_effect=replies):
            with self.assertRaisesRegex(RuntimeError,'returned to Recovery mode'):
                restore_run.qualify(Path(work),['ssh'],'fixture',progress=lambda _:None)
            detection=json.loads((Path(work)/'recovery-detection.json').read_text())
        self.assertEqual(detection,dict(
            product='iPad3,4',version='8.1.3',build='12B466',mode='Recovery'))

    def test_ssh_rejection_does_not_postpone_official_activation(self):
        identity={'board':'n42ap','product':'iPhone5,2','ecid':123}
        report=dict(setup_app_removed=False,product='iPhone5,2',version='8.1.3',build='12B466',generation='fixture',
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

    def test_transient_activation_failure_stays_in_qualification_loop(self):
        identity={'board':'n42ap','product':'iPhone5,2','ecid':123}
        report=dict(setup_app_removed=False,product='iPhone5,2',version='7.1.2',build='11D257',generation='fixture',
                    identity=identity,activation_mode='official-on-target')
        lockdown=plistlib.dumps(dict(ProductType='iPhone5,2',ProductVersion='7.1.2',
            BuildVersion='11D257',BasebandVersion='11.80.00',ActivationState='Unactivated'))
        replies=[subprocess.CompletedProcess([],1,b'',b''),
                 subprocess.CompletedProcess([],0,lockdown,b'')]
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run.subprocess,'run',side_effect=replies), \
             patch('activation.activate',side_effect=ActivationPending('not ready')) as activate:
            with self.assertRaisesRegex(RuntimeError,'Official activation is not ready'):
                restore_run.qualify(Path(work),['ssh'],'fixture',timeout=0,progress=lambda _:None)
            activate.assert_called_once()

    def test_setup_removed_target_is_qualified_without_activation(self):
        identity={'board':'p101ap','product':'iPad3,4','ecid':123}
        report=dict(product='iPad3,4',version='6.1.3',build='10B329',generation='selected',
                    identity=identity,activation_mode='skipped-setup-removed',
                    setup_app_removed=True)
        jobs=('P101AP\n10B329\nselected\nCYDIA_READY:selected\n'
              'BOOT_SUCCESS:selected\n'
              '10 - com.apple.SpringBoard\n- 0 com.saurik.Cydia.Startup\n')
        lockdown=plistlib.dumps(dict(ProductType='iPad3,4',ProductVersion='6.1.3',
            BuildVersion='10B329',ActivationState='Unactivated'))
        replies=[subprocess.CompletedProcess([],0,jobs.encode(),b''),
                 subprocess.CompletedProcess([],0,lockdown,b'')]
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run.subprocess,'run',side_effect=replies), \
             patch('activation.activate') as activate, \
             patch('activation.acknowledge') as acknowledge:
            result=restore_run.qualify(Path(work),['ssh'],'fixture',progress=lambda _:None)
        self.assertTrue(result['normal_boot_verified'])
        self.assertTrue(result['activation_skipped'])
        self.assertEqual(result['activation_state'],'Unactivated')
        activate.assert_not_called();acknowledge.assert_not_called()

    def test_setup_removed_pangu_stall_gets_one_controlled_retry_boot(self):
        identity={'board':'p101ap','product':'iPad3,4','ecid':123}
        report=dict(product='iPad3,4',version='7.1.2',build='11D257',generation='selected',
                    identity=identity,activation_mode='skipped-setup-removed',
                    setup_app_removed=True,layout={'partitions':[
                        {'role':'system','device':'/dev/disk0s1s3'}]})
        base=('P101AP\n11D257\nselected\nCYDIA_READY:selected\n'
              'UNTETHER_READY:ready\n')
        jobs=('BOOT_SUCCESS:selected\n10 - com.apple.SpringBoard\n'
              '- 0 com.saurik.Cydia.Startup\n'
              '- 0 com.apple.accountsd\n'
              '- 0 com.apple.managedconfiguration.profiled\n')
        readonly=base+'/dev/disk0s1s3 on / (hfs, local, read-only, journaled)\n'+jobs
        writable=base+'/dev/disk0s1s3 on / (hfs, local, journaled)\n'+jobs
        lockdown=plistlib.dumps(dict(ProductType='iPad3,4',ProductVersion='7.1.2',
            BuildVersion='11D257',ActivationState='Unactivated'))
        replies=[subprocess.CompletedProcess([],0,readonly.encode(),b''),
                 subprocess.CompletedProcess([],0,lockdown,b''),
                 subprocess.CompletedProcess([],0,b'',b''),
                 subprocess.CompletedProcess([],0,writable.encode(),b''),
                 subprocess.CompletedProcess([],0,lockdown,b'')]
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run,'PANGU_READONLY_RETRY_POLLS',1), \
             patch.object(restore_run.subprocess,'run',side_effect=replies) as command, \
             patch.object(restore_run.time,'sleep'), \
             patch('activation.activate') as activate, \
             patch('activation.acknowledge') as acknowledge:
            result=restore_run.qualify(
                Path(work),['ssh'],'fixture',progress=lambda _:None,
                verify_writable_root=True)
        self.assertTrue(result['normal_boot_verified'])
        self.assertTrue(result['untether_retry_rebooted'])
        reboots=[call.args[0] for call in command.call_args_list
                 if call.args[0][-1]=='/sbin/reboot']
        self.assertEqual(reboots,[['ssh','/sbin/reboot']])
        activate.assert_not_called();acknowledge.assert_not_called()

    def test_transient_data_generation_mismatch_does_not_prevent_activation(self):
        identity={'board':'p101ap','product':'iPad3,4','ecid':123}
        report=dict(setup_app_removed=False,product='iPad3,4',version='7.1.2',build='11D257',generation='selected',
                    identity=identity,activation_mode='official-on-target')
        unactivated=plistlib.dumps(dict(ProductType='iPad3,4',ProductVersion='7.1.2',
            BuildVersion='11D257',ActivationState='Unactivated'))
        activated=plistlib.dumps(dict(ProductType='iPad3,4',ProductVersion='7.1.2',
            BuildVersion='11D257',ActivationState='Activated'))
        jobs=('P101AP\n11D257\nselected\nCYDIA_READY:selected\n'
              'BOOT_SUCCESS:selected\n'
              '10 - com.apple.SpringBoard\n- 0 com.saurik.Cydia.Startup\n'
              '- 0 com.apple.accountsd\n- 0 com.apple.managedconfiguration.profiled\n')
        replies=[subprocess.CompletedProcess([],0,b'P101AP\n11D257\n',b''),
                 subprocess.CompletedProcess([],0,unactivated,b''),
                 subprocess.CompletedProcess([],0,jobs.encode(),b''),
                 subprocess.CompletedProcess([],0,activated,b'')]
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run.subprocess,'run',side_effect=replies), \
             patch.object(restore_run.time,'sleep'), \
             patch('activation.activate') as activate, \
             patch('activation.acknowledge',return_value={'activation_state':'Activated','acknowledged':True}) as acknowledge:
            result=restore_run.qualify(Path(work),['ssh'],'fixture',progress=lambda _:None)
            self.assertTrue(result['normal_boot_verified'])
            activate.assert_called_once()
            acknowledge.assert_called_once()

    def test_transient_cydia_status_is_retried_until_generation_marker(self):
        identity={'board':'p101ap','product':'iPad3,4','ecid':123}
        report=dict(setup_app_removed=False,product='iPad3,4',version='7.1.2',build='11D257',generation='selected',
                    identity=identity,activation_mode='official-on-target')
        values=plistlib.dumps(dict(ProductType='iPad3,4',ProductVersion='7.1.2',
            BuildVersion='11D257',ActivationState='Activated'))
        failed=('P101AP\n11D257\nselected\nCYDIA_READY:\n'
                '10 - com.apple.SpringBoard\n- 1 com.saurik.Cydia.Startup\n'
                '- 0 com.apple.accountsd\n- 0 com.apple.managedconfiguration.profiled\n')
        ready=failed.replace('CYDIA_READY:','CYDIA_READY:selected\nBOOT_SUCCESS:selected').replace(
            '- 1 com.saurik.Cydia.Startup','- 0 com.saurik.Cydia.Startup')
        replies=[subprocess.CompletedProcess([],0,failed.encode(),b''),
                 subprocess.CompletedProcess([],0,b'',b''),
                 subprocess.CompletedProcess([],0,values,b''),
                 subprocess.CompletedProcess([],0,ready.encode(),b''),
                 subprocess.CompletedProcess([],0,values,b'')]
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run.subprocess,'run',side_effect=replies) as command, \
             patch.object(restore_run.time,'sleep'), \
             patch('activation.acknowledge',return_value={
                 'activation_state':'Activated','acknowledged':True}):
            result=restore_run.qualify(Path(work),['ssh'],'fixture',progress=lambda _:None)
        self.assertTrue(result['normal_boot_verified'])
        self.assertIn('/bin/launchctl start com.saurik.Cydia.Startup',
                      command.call_args_list[1].args[0][-1])

    def test_registered_but_unstarted_cydia_job_is_started_and_marker_is_required(self):
        identity={'board':'p101ap','product':'iPad3,4','ecid':123}
        report=dict(setup_app_removed=False,product='iPad3,4',version='6.1.3',build='10B329',generation='selected',
                    identity=identity,activation_mode='official-on-target')
        lockdown=plistlib.dumps(dict(ProductType='iPad3,4',ProductVersion='6.1.3',
            BuildVersion='10B329',ActivationState='Activated'))
        pending=('P101AP\n10B329\nselected\nCYDIA_READY:\n'
                 '10 - com.apple.SpringBoard\n- 0 com.saurik.Cydia.Startup\n')
        ready=pending.replace('CYDIA_READY:\n',
                              'CYDIA_READY:selected\nBOOT_SUCCESS:selected\n')
        replies=[subprocess.CompletedProcess([],0,pending.encode(),b''),
                 subprocess.CompletedProcess([],0,b'',b''),
                 subprocess.CompletedProcess([],0,lockdown,b''),
                 subprocess.CompletedProcess([],0,ready.encode(),b''),
                 subprocess.CompletedProcess([],0,lockdown,b'')]
        with tempfile.TemporaryDirectory() as work, \
             patch.object(restore_run,'checked_manifest',return_value=report), \
             patch.object(restore_run.subprocess,'run',side_effect=replies) as command, \
             patch.object(restore_run.time,'sleep'), \
             patch('activation.acknowledge',return_value={
                 'activation_state':'Activated','acknowledged':True}):
            result=restore_run.qualify(Path(work),['ssh'],'fixture',progress=lambda _:None)
        self.assertTrue(result['normal_boot_verified'])
        starts=[call.args[0] for call in command.call_args_list
                if call.args[0][-1]=='/bin/launchctl start com.saurik.Cydia.Startup']
        self.assertEqual(starts,[['ssh','/bin/launchctl start com.saurik.Cydia.Startup']])
