"""Raw 8 KiB sectors must stay distinct from 4 KiB HFS allocation units."""
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from restore import Rescue, aligned_ranges, align_image, copy_image, read_fresh_image, _finish_install
from test_layout import fixture
import test_hfs_extents
from hfs_extents import allocated_ranges


class DiskSectors(unittest.TestCase):
    def ram(self):
        return Rescue(['ssh','-o','StrictHostKeyChecking=yes','root@127.0.0.1'],
                      dict(product='iPad2,2',board='k94ap',chip=0x8940,board_id=6),
                      rescue_build='10B329')

    def test_raw_table_detection_reads_both_mirrors_on_4k_and_8k_disks(self):
        for sector in (4096,8192):
            with self.subTest(sector=sector):
                primary,backup=fixture(blocks=7815175,sector=sector,system_end=300794)
                start=(7815174-16384//sector)*sector
                ram=self.ram();commands=[]
                def run(command):
                    commands.append(command)
                    args=dict(a.split('=',1) for a in shlex.split(command)[1:])
                    size=int(args['bs']);offset=int(args['skip'])*size;length=int(args['count'])*size
                    self.assertEqual(size%sector,0)
                    self.assertEqual(offset%sector,0)
                    if offset==0:return primary[:length]
                    self.assertEqual(offset,start)
                    return backup[:length]
                with patch.object(ram,'run',side_effect=run):
                    self.assertEqual(ram.table(),(primary,backup))
                    self.assertEqual(ram.block_size,sector)
                self.assertEqual(len(commands),3)
                self.assertIn('bs=16384 skip=0 count=1',commands[0])

    def test_invalid_mirror_never_publishes_geometry_and_sector_changes_fail(self):
        primary,backup=fixture(sector=8192)
        ram=self.ram();bad=bytearray(backup);bad[0]^=1
        with patch.object(ram,'run',side_effect=[primary[:16384],primary,bytes(bad)]):
            with self.assertRaises(ValueError):ram.table()
        self.assertIsNone(ram._block_size)
        ram._block_size=4096
        with patch.object(ram,'run',side_effect=[primary[:16384],primary,backup]):
            with self.assertRaisesRegex(ValueError,'sector size changed'):ram.table()
        self.assertEqual(ram._block_size,4096)

    def transport(self, ram, memory):
        commands=[]
        def run(command,data=None):
            commands.append(command)
            args=dict(a.split('=',1) for a in shlex.split(command)[1:])
            size=int(args['bs']);count=int(args['count'])
            self.assertEqual(size,8192)
            if 'of' in args:
                offset=int(args['seek'])*size
                self.assertEqual(len(data),count*size)
                self.assertLessEqual(offset+len(data),len(memory))
                memory[offset:offset+len(data)]=data
                return b''
            offset=int(args['skip'])*size
            return bytes(memory[offset:offset+count*size])
        ram._block_size=8192
        return run,commands

    def test_subsector_reads_slice_aligned_raw_transfers_and_partial_writes_are_rejected(self):
        ram=self.ram();memory=bytearray(b'a'*4096+b'b'*4096+b'c'*8192)
        run,commands=self.transport(ram,memory)
        with patch.object(ram,'run',side_effect=run):
            self.assertEqual(ram.read('/dev/rdisk0s1s3',1,2),b'b'*4096+b'c'*4096)
            self.assertEqual(len(commands),1)
            with self.assertRaisesRegex(ValueError,'whole disk sectors'):
                ram.write('/dev/rdisk0s1s3',0,b'x'*4096)
            with self.assertRaisesRegex(ValueError,'whole disk sectors'):
                ram.write('/dev/rdisk0s1s3',1,b'x'*8192)
            self.assertEqual(len(commands),1)
            ram.write('/dev/rdisk0s1s3',2,b'd'*8192)
        self.assertEqual(memory[8192:],b'd'*8192)
        self.assertIn('seek=1 count=1',commands[1])

    def test_sparse_hfs_transfer_expands_and_merges_sectors_with_exact_readback(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'data.hfs';test_hfs_extents.Allocation().image(path)
            data=bytearray(path.read_bytes());data[11*4096:12*4096]=b'v'*4096;path.write_bytes(data)
            ram=self.ram();memory=bytearray(len(data));run,commands=self.transport(ram,memory)
            with patch.object(ram,'run',side_effect=run):
                copy_image(ram,path,'/dev/rdisk0s1s2',sparse=True,progress=lambda text:None)
            for first,count in allocated_ranges(path):
                self.assertEqual(memory[first*4096:(first+count)*4096],data[first*4096:(first+count)*4096])
            self.assertEqual(len([c for c in commands if ' of=' in c]),3)
            self.assertEqual(aligned_ranges([(0,1),(1,2),(11,1),(15,1)],2),[(0,4),(10,2),(14,2)])

    def test_native_4k_hfs_collection_uses_aligned_8k_reads(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'source.hfs';test_hfs_extents.Allocation().image(path)
            data=bytearray(path.read_bytes());data[11*4096:12*4096]=b'v'*4096;path.write_bytes(data)
            ram=self.ram();run,_=self.transport(ram,data)
            destination=Path(root)/'collected.hfs'
            with patch.object(ram,'run',side_effect=run):
                read_fresh_image(ram,'/dev/rdisk0s1s2',destination,len(data))
            self.assertEqual(allocated_ranges(destination),allocated_ranges(path))
            with destination.open('rb') as stream:
                for first,count in allocated_ranges(path):
                    stream.seek(first*4096)
                    self.assertEqual(stream.read(count*4096),data[first*4096:(first+count)*4096])

    def test_unaligned_image_is_grown_as_hfs_and_never_sent_as_partial_sector(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'system.hfs';path.write_bytes(bytes(3*4096))
            ram=Mock(block_size=8192)
            with self.assertRaisesRegex(ValueError,'whole disk sectors'):
                copy_image(ram,path,'/dev/rdisk0s1s3')
            ram.write.assert_not_called()
            with patch('restore.HFS') as image,patch('restore.require_reserve') as reserve:
                align_image(path,8192)
            image.return_value.grow.assert_called_once_with(16384)
            reserve.assert_called_once_with(path,root=True)

    def test_parent_mapping_and_partition_endpoint_use_disk_sector_addresses(self):
        with tempfile.TemporaryDirectory() as root:
            bundle=Path(root);(bundle/'system.hfs').write_bytes(bytes(16384))
            ram=Mock(block_size=8192,rescue_build='10B329')
            ram.run.return_value=b'';ram.read.return_value=b'same bytes';ram.fsck.return_value=b'OK'
            report=dict(product='iPad2,2',version='5.1.1')
            layout=dict(block_size=8192,partitions=[dict(role='system',device='/dev/disk0s1s3',
                                                        first=4,bytes=16384)])
            state=dict(verified_volumes=[])
            with patch('restore.copy_image'),patch('restore._finish_data'):
                _finish_install(bundle,ram,report,layout,None,state,[('system','system.hfs')],lambda text:None)
            endpoint=ram.run.call_args.args[0]
            self.assertIn('bs=8192 skip=2 count=1',endpoint)
            self.assertEqual([call.args for call in ram.read.call_args_list],
                             [('/dev/rdisk0s1',8,1),('/dev/rdisk0s1s3',0,1)])


if __name__=='__main__':unittest.main()
