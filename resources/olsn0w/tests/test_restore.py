from pathlib import Path
import sys
import json
import tempfile
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from restore import (install,Rescue,preview_matches,copy_image,refresh_layout,
                     resume_system_fsck,data_formatter,require_data_environment,
                     _finish_data,_finish_install)
from layout import encode,editor_commands
from test_layout import fixture


class RescueDiskDiagnostics(unittest.TestCase):
    def setUp(self):
        self.ram=Rescue(['ssh','-o','StrictHostKeyChecking=yes','root@127.0.0.1'],
                        dict(product='iPad2,2',board='k94ap',chip=0x8940,board_id=6),
                        rescue_build='10B329')

    def test_binary_read_keeps_dd_statistics_out_of_partition_bytes(self):
        data=bytes(range(256))*96
        result=Mock(returncode=0,stdout=data,stderr=b'6+0 records in\n6+0 records out\n')
        with patch('restore.subprocess.run',return_value=result) as command:
            self.assertEqual(self.ram.read('/dev/rdisk0s1',0,6),data)
        self.assertEqual(command.call_args.args[0][-1],
                         '/olsn0w-maintenance/dd if=/dev/rdisk0s1 bs=4096 skip=0 count=6')
        self.assertTrue(command.call_args.kwargs['capture_output'])

    def test_failed_table_read_reports_stderr_and_exit_code_without_retry(self):
        for code,diagnostic in ((1,b'dd: /dev/rdisk0s1: No such file or directory\n'),
                                (139,b'Segmentation fault\n'),
                                (255,b'ssh: Connection closed\n')):
            with self.subTest(code=code), \
                 patch('restore.subprocess.run',return_value=Mock(
                     returncode=code,stdout=b'',stderr=diagnostic)) as command:
                with self.assertRaises(RuntimeError) as error:
                    self.ram.table()
                self.assertIn('exit code '+str(code),str(error.exception))
                self.assertIn(diagnostic.decode().strip(),str(error.exception))
                command.assert_called_once()

    def test_short_read_reports_device_and_observed_size(self):
        with patch('restore.subprocess.run',return_value=Mock(
                returncode=0,stdout=b'x'*4096,stderr=b'1+0 records out\n')):
            with self.assertRaisesRegex(RuntimeError,
                    'Short partition read from /dev/rdisk0s1: expected 24576 bytes, received 4096'):
                self.ram.table()

    def test_failed_write_retains_dd_error_and_does_not_start_readback(self):
        with patch('restore.subprocess.run',return_value=Mock(
                returncode=1,stdout=b'',stderr=b'dd: Input/output error\n')) as command:
            with self.assertRaisesRegex(RuntimeError,'Input/output error'):
                self.ram.write('/dev/rdisk0s1s3',0,bytes(4096))
        command.assert_called_once()
        self.assertNotIn('2>/dev/null',command.call_args.args[0][-1])


class RestoreGuards(unittest.TestCase):
    def test_a5_ios6_requires_native6_for_every_minor_release(self):
        for product in ('iPod5,1','iPhone4,1','iPad2,5','iPad3,1'):
            for release in ('6.0','6.0.1','6.0.2','6.1','6.1.2','6.1.3'):
                with self.subTest(product=product,release=release):
                    require_data_environment(product,release,'10B329')
                    with self.assertRaisesRegex(ValueError,'native iOS 6 RAM'):
                        require_data_environment(product,release,'12H321')

    def test_data_environment_does_not_change_qualified_a6_or_ios7_8(self):
        for product in ('iPhone5,1','iPad3,4'):
            for release in ('6.0','6.1.3','6.1.4'):
                require_data_environment(product,release,'12H321')
        for product in ('iPod5,1','iPhone4,1','iPad2,5','iPad3,1'):
            for release in ('7.0','7.1.2','8.0','8.1.3','8.4.1'):
                for build in ('10B329','12H321'):
                    require_data_environment(product,release,build)

    def test_incompatible_data_environment_fails_before_resumed_writes(self):
        ram=Mock(rescue_build='12H321')
        report=dict(product='iPod5,1',version='6.1.3')
        for operation,args in [(_finish_data,('.',ram,report,None,None,{},Mock(),Mock())),
                               (_finish_install,('.',ram,report,None,None,{},[],Mock()))]:
            with self.assertRaisesRegex(ValueError,'native iOS 6 RAM'):
                operation(*args)
        self.assertFalse(ram.method_calls)

    def test_incompatible_data_environment_fails_before_install_device_access(self):
        identity=dict(ecid=1,product='iPod5,1',board='n78ap',chip=0x8942,board_id=0)
        ram=Mock(identity=identity,rescue_build='12H321')
        report=dict(identity=identity,product='iPod5,1',version='6.1.3')
        with tempfile.TemporaryDirectory() as folder, \
             patch('restore.checked_manifest',return_value=report), \
             patch('restore.require_reserve'):
            with self.assertRaisesRegex(ValueError,'native iOS 6 RAM'):
                install(folder,ram,erase=True)
        self.assertFalse(ram.method_calls)

    def test_multipatch_uses_the_ios6_native_data_formatter(self):
        self.assertEqual(data_formatter('10B329'),'/sbin/newfs_hfs')
        self.assertEqual(data_formatter('12H321'),'/mnt1/olsn0w/restore-newfs')
        with self.assertRaises(ValueError):data_formatter('unknown')
    def test_erase_and_identity_checks_precede_device_access(self):
        ram=Mock();ram.identity={'ecid':2}
        with patch('restore.checked_manifest',return_value={'identity':{'ecid':1}}):
            with self.assertRaisesRegex(ValueError,'erase authorization'):install('.',ram)
            with self.assertRaisesRegex(ValueError,'another device'):install('.',ram,erase=True)
        self.assertFalse(ram.method_calls)
    def test_old_capacity_bundle_rejected_before_device_access(self):
        ram=Mock();ram.identity=dict(ecid=1,product='iPhone5,2',board='n42ap',chip=0x8950,board_id=2)
        with tempfile.TemporaryDirectory() as folder:
            with patch('restore.checked_manifest',return_value={'identity':ram.identity}),patch('restore.require_reserve',side_effect=ValueError('Target root capacity reserve insufficient')) as reserve:
                with self.assertRaisesRegex(ValueError,'Target root capacity'):
                    install(folder,ram,erase=True)
                reserve.assert_called_once_with(Path(folder)/'system.hfs',root=True)
        self.assertFalse(ram.method_calls)
    def test_partition_preview_requires_exact_guid_range_and_attributes(self):
        _,_,layout=encode(*fixture(),1024**3,'7.1.2')
        text='\n'.join('Partition unique GUID: {guid}\nFirst sector: {first}\nLast sector: {last}\nAttribute flags: {flags}'.format(**p,flags=format(p['attributes'],'016X')) for p in layout['partitions'])+'\nNo problems found.'
        preview_matches(text,layout)
        with self.assertRaises(ValueError):preview_matches(text.replace('Last sector:','Lost sector:',1),layout)
        with self.assertRaises(ValueError):preview_matches(text.replace('No problems found.','Errors'),layout)
    def test_reinstallation_removes_all_old_mappings_without_prompt_drift(self):
        a,b,_=encode(*fixture(),1024**3,'7.1.2')
        commands=editor_commands(a,b,1024**3+4096,'6.1.3').decode()
        self.assertTrue(commands.startswith('d\n4\nd\n3\nd\n2\nd\nx\ns\n4\n'))
        self.assertNotIn('\nw\n',commands)
        self.assertTrue(editor_commands(a,b,1024**3,'7.1.2',True).endswith(b'v\nw\nY\n'))
    def test_current_layout_can_follow_a_previous_different_target_size(self):
        a,b=fixture();current_a,current_b,_=encode(a,b,1024**3+4096,'6.1.3')
        ram=Mock();ram.identity=dict(ecid=1,product='iPhone5,2',board='n42ap',chip=0x8950,board_id=2);ram.table.return_value=(current_a,current_b)
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder);(folder/'gpt-primary.bin').write_bytes(a);(folder/'gpt-secondary.bin').write_bytes(b)
            with (folder/'system.hfs').open('wb') as f:f.truncate(1024**3)
            report=dict(identity=ram.identity,version='7.1.2',files={})
            with patch('restore.checked_manifest',return_value=report):refresh_layout(folder,ram)
            self.assertEqual((folder/'gpt-primary.bin').read_bytes(),current_a)
            output=json.loads((folder/'manifest.json').read_text())
            self.assertEqual(output['layout']['target_version'],'7.1.2')
            other_a,other_b=fixture(blocks=8*1024*256)
            ram.table.return_value=(other_a,other_b)
            before=(folder/'manifest.json').read_bytes()
            with patch('restore.checked_manifest',return_value=output),self.assertRaisesRegex(ValueError,'capacity changed'):
                refresh_layout(folder,ram)
            self.assertEqual((folder/'manifest.json').read_bytes(),before)

    def test_unpinned_transport_is_rejected(self):
        with self.assertRaises(ValueError):Rescue(['ssh','root@127.0.0.1'],{})
    def test_multipatch_rescue_uses_its_ios6_kernel_identity(self):
        prefix=['ssh','-o','StrictHostKeyChecking=yes','root@127.0.0.1']
        ram=Rescue(prefix,dict(product='iPhone4,1',board='n94ap',chip=0x8940,board_id=8))
        self.assertEqual(ram.rescue_build,'10B329')
    def test_native_fsck_repairs_then_requires_a_clean_verification(self):
        prefix=['ssh','-o','StrictHostKeyChecking=yes','root@127.0.0.1']
        ram=Rescue(prefix,dict(product='iPhone5,2',board='n42ap',chip=0x8950,board_id=2))
        results=[Mock(returncode=8,stdout=b'found corrupt and needs to be repaired',stderr=b''),
                 Mock(returncode=0,stdout=b'FILE SYSTEM WAS MODIFIED',stderr=b''),
                 Mock(returncode=0,stdout=b'appears to be OK',stderr=b'')]
        with patch('restore.subprocess.run',side_effect=results) as run:
            output=ram.fsck('/dev/rdisk0s1s3')
        self.assertIn(b'--- repaired ---',output)
        self.assertEqual([call.args[0][-1] for call in run.call_args_list],
                         ['/sbin/fsck_hfs -fn /dev/rdisk0s1s3','/sbin/fsck_hfs -fy /dev/rdisk0s1s3','/sbin/fsck_hfs -fn /dev/rdisk0s1s3'])
    def test_resume_rejects_any_other_interruption_before_device_access(self):
        identity=dict(ecid=1,product='iPhone5,2',board='n42ap',chip=0x8950,board_id=2)
        ram=Mock();ram.identity=identity
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder);(folder/'installation.json').write_text(json.dumps(dict(stage='writing-bootstrap',complete=False,formatted_data=False,verified_volumes=['system'])))
            with patch('restore.checked_manifest',return_value={'identity':identity}),self.assertRaisesRegex(ValueError,'recovery point'):
                resume_system_fsck(folder,ram)
        self.assertFalse(ram.method_calls)
    def test_failed_chunk_stops_subsequent_writes(self):
        ram=Mock();ram.write.side_effect=RuntimeError('Readback failed')
        with tempfile.TemporaryDirectory() as folder:
            image=Path(folder)/'image';image.write_bytes(bytes(3*4096))
            with patch('restore.CHUNK',1),self.assertRaises(RuntimeError):copy_image(ram,image,'/dev/rdisk0s1s3',progress=lambda _:None)
        self.assertEqual(ram.write.call_count,1)
