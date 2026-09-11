from pathlib import Path
import sys
import json
import tempfile
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from restore import install,Rescue,preview_matches,copy_image,refresh_layout
from layout import encode,editor_commands
from test_layout import fixture

class RestoreGuards(unittest.TestCase):
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
    def test_failed_chunk_stops_subsequent_writes(self):
        ram=Mock();ram.write.side_effect=RuntimeError('Readback failed')
        with tempfile.TemporaryDirectory() as folder:
            image=Path(folder)/'image';image.write_bytes(bytes(3*4096))
            with patch('restore.CHUNK',1),self.assertRaises(RuntimeError):copy_image(ram,image,'/dev/rdisk0s1s3',progress=lambda _:None)
        self.assertEqual(ram.write.call_count,1)
