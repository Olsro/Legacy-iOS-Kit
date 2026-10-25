from pathlib import Path
import json
import plistlib
import io
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from provision import (HANDOFF, copy_ipsw, handoff_sleep, multipatch_manifest,
                       multipatch_iboot_flags, multipatch_key_metadata,
                       reboot_hook, require_completed_restore)
from provision_run import record_failed_restore
import provision_run
from provision_collect import personalized_modem


class RestoreLogging(unittest.TestCase):
    def test_sigpipe_preserves_process_and_logs_but_does_not_bypass_completion_checks(self):
        # A native shell inherits the launcher's signal disposition, unlike a
        # Python child which would ignore SIGPIPE on interpreter startup.
        # All device operations and the firmware-key server stay mocked.
        for code,done in ((9,True),(0,False),(0,True)):
            with self.subTest(code=code,done=done), tempfile.TemporaryDirectory(prefix='restore logs ') as temporary:
                session=Path(temporary);bundle=session/'provision';bundle.mkdir()
                identity=dict(product='iPhone5,2',board='n42ap',chip=0x8950,board_id=2,ecid=123)
                (session/'device.json').write_text(json.dumps(dict(identity=identity)))
                (session/'ssh-prefix.json').write_text(json.dumps(['ssh']))
                keys=session/'keys.json'
                keys.write_text(json.dumps(dict(identifier='iPhone5,2',buildid='12H321')))
                report=dict(kind='signed-base-restore-handoff',identity=identity,product='iPhone5,2',multipatch=False,
                            restore_environment_build='12H321',rescue_session=str(session),
                            asr_source='original-udif-without-filevault-envelope',handoff_storage='nvram',
                            asr_patch={'method':'kit-asr-failure-to-success'},
                            restore_bootchain_policy='futurerestore-stock-rsa',reboot_token='a'*32)
                argv=['/bin/sh','-c',
                      'kill -PIPE "$$"; printf "restore output\\n"; '
                      'printf "modem error\\n" >&2; '
                      '[ "$2" = yes ] && printf "DONE\\n"; exit "$1"',
                      'restore-fixture',str(code),'yes' if done else 'no']
                log=bundle.resolve()/'restore.log'
                messages=[]
                def progress(message):
                    messages.append(message)
                    if message.startswith('Restore log: '):
                        self.assertEqual(message,'Restore log: '+str(log))
                        self.assertTrue(log.is_file())
                with patch.object(provision_run,'checked_manifest',return_value=report), \
                     patch.object(provision_run,'session_build',return_value='12H321'), \
                     patch.object(provision_run,'restore_arguments',return_value=argv), \
                     patch.object(provision_run,'tool_environment',return_value=None), \
                     patch.object(provision_run,'check_restore_runtime'), \
                     patch.object(provision_run,'prepare_dfu'), \
                     patch.object(provision_run.http.server,'ThreadingHTTPServer'), \
                     patch.object(provision_run,'record_failed_restore'), \
                     patch.object(provision_run,'read_handoff',return_value=b'a'*32+b'\n') as marker, \
                     patch.object(provision_run,'connect_handoff') as handoff:
                    if code or not done:
                        with self.assertRaises(RuntimeError) as error:
                            provision_run.run(session,bundle,session/'ticket',keys,erase=True,progress=progress)
                        self.assertIn(str(log),str(error.exception))
                        self.assertIn('exit code '+str(code),str(error.exception))
                        handoff.assert_not_called();marker.assert_not_called()
                    else:
                        ram=provision_run.run(session,bundle,session/'ticket',keys,erase=True,progress=progress)
                        self.assertIs(ram,handoff.return_value)
                        handoff.assert_called_once_with(session.resolve())
                        marker.assert_called_once_with(ram)
                self.assertIn('Restore log: '+str(log),messages)
                expected={'restore output','modem error'}
                if done:expected.add('DONE')
                self.assertEqual(set(log.read_text().splitlines()),expected)
                state=json.loads((bundle/'run.json').read_text())
                self.assertEqual(state['returncode'],code)
                self.assertEqual(state['complete'],code==0 and done)
                if code or not done:
                    self.assertIn(str(bundle.resolve()),messages[-1])
                    self.assertEqual(state['error'],str(error.exception))
                else:
                    self.assertEqual(state['stage'],'authenticated-ram-handoff')


class ProvisionHandoff(unittest.TestCase):
    def test_personalized_modem_archive_supplies_hidden_restore_component(self):
        packed=io.BytesIO()
        with zipfile.ZipFile(packed,'w') as archive:
            archive.writestr('amss.mbn',b'amss')
            archive.writestr('restoredbl.mbn',b'restore')
        result=personalized_modem(packed.getvalue(),('amss.mbn','restoredbl.mbn'))
        self.assertEqual(result['restoredbl.mbn'],b'restore')
        with zipfile.ZipFile(packed,'a') as archive:archive.writestr('extra',b'x')
        with self.assertRaises(ValueError):
            personalized_modem(packed.getvalue(),('amss.mbn','restoredbl.mbn'))
    def test_checked_multipatch_asr_is_already_signed(self):
        from common import KIT
        from signing import verify
        binary=(KIT/'resources/patch/asr').read_bytes()
        report=verify(binary)
        self.assertEqual(report['directories'],1)
        self.assertGreater(report['verified_pages'],0)

    def test_multipatch_leaves_rsa_and_ticket_to_futurerestore(self):
        self.assertEqual(multipatch_iboot_flags('iBSS'),[])
        ibec=multipatch_iboot_flags('iBEC')
        self.assertIn('--debug',ibec)
        self.assertIn('-b',ibec)
        self.assertNotIn('--rsa',ibec)
        self.assertNotIn('--ticket',ibec)
        with self.assertRaises(ValueError):multipatch_iboot_flags('iBoot')

    def test_multipatch_serves_donor_keys_only_for_encrypted_restore_pair(self):
        keys=lambda build,tree,kernel:{'identifier':'iPhone4,1','buildid':build,'keys':[
            {'image':'iBSS','iv':'base-iv','key':'base-key'},
            {'image':'DeviceTree','iv':tree+'-iv','key':tree+'-key'},
            {'image':'Kernelcache','iv':kernel+'-iv','key':kernel+'-key'}]}
        result=multipatch_key_metadata(keys('12H321','base-tree','base-kernel'),
                                       keys('10B329','donor-tree','donor-kernel'))
        by_image={item['image']:item for item in result['keys']}
        self.assertEqual(by_image['iBSS']['key'],'base-key')
        self.assertEqual(by_image['DeviceTree']['key'],'donor-tree-key')
        self.assertEqual(by_image['Kernelcache']['iv'],'donor-kernel-iv')

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

    def test_explicit_downgrade_members_are_added_without_changing_stock_members(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);original=directory/'original.zip';target=directory/'target.zip'
            with zipfile.ZipFile(original,'w') as archive:archive.writestr('BuildManifest.plist',b'old')
            replacements={'BuildManifest.plist':b'new','Downgrade/RestoreDeviceTree':b'tree'}
            copy_ipsw(original,target,replacements,{'Downgrade/RestoreDeviceTree'})
            with zipfile.ZipFile(target) as archive:
                self.assertEqual(archive.namelist(),['BuildManifest.plist','Downgrade/RestoreDeviceTree'])
                self.assertEqual(archive.read('Downgrade/RestoreDeviceTree'),b'tree')

    def test_4s_multipatch_routes_only_erase_restore_components(self):
        def identity(behavior):
            return {'Info':{'DeviceClass':'n94ap','RestoreBehavior':behavior},
                    'ApChipID':0x8940,'ApBoardID':8,
                    'Manifest':{'RestoreDeviceTree':{'Info':{'Path':'stock-tree'}},
                                'RestoreKernelCache':{'Info':{'Path':'stock-kernel'}}}}
        source=plistlib.dumps({'ProductBuildVersion':'12H321','SupportedProductTypes':['iPhone4,1'],
                               'BuildIdentities':[identity('Erase'),identity('Update')]})
        donor_identity=identity('Erase')
        donor_identity['Manifest']['RestoreKernelCache']['PartialDigest']=b'donor-partial'
        donor={'ProductBuildVersion':'10B329','BuildIdentities':[donor_identity]}
        result=plistlib.loads(multipatch_manifest(source,'iPhone4,1',donor))['BuildIdentities']
        self.assertEqual(result[0]['Manifest']['RestoreDeviceTree']['Info']['Path'],
                         'Downgrade/RestoreDeviceTree')
        self.assertEqual(result[0]['Manifest']['RestoreKernelCache']['Info']['Path'],
                         'Downgrade/RestoreKernelCache')
        self.assertEqual(result[0]['Manifest']['RestoreKernelCache']['PartialDigest'],
                         b'donor-partial')
        self.assertEqual(result[1]['Manifest']['RestoreDeviceTree']['Info']['Path'],'stock-tree')
