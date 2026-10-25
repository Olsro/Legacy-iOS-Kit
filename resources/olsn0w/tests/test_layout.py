import struct
from pathlib import Path
import sys
import unittest
import uuid
import zlib
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from layout import HFS_TYPE, inspect, plan, partition_names


def fixture(blocks=4*1024*256, overlap=False, revision=0x10000, sector=4096, system_end=262149):
    entry_blocks=16384//sector;first_usable=2+entry_blocks
    entries=bytearray(256)
    for i,(first,last) in enumerate([(first_usable,system_end),(system_end if overlap else system_end+1,blocks-entry_blocks-2)]):
        struct.pack_into('<16s16s3Q',entries,i*128,HFS_TYPE,uuid.UUID(int=i+1).bytes_le,first,last,0)
    def hdr(here,other,entry_lba):
        h=bytearray(sector)
        struct.pack_into('<8s4I4Q16sQIII',h,0,b'EFI PART',revision,92,0,0,here,other,first_usable,blocks-entry_blocks-2,uuid.UUID(int=3).bytes_le,entry_lba,2,128,zlib.crc32(entries))
        struct.pack_into('<I',h,16,zlib.crc32(h[:92]));return h
    return bytes(sector)+hdr(1,blocks-1,2)+entries+bytes(16384-256), entries+bytes(16384-256)+hdr(blocks-1,1,blocks-1-entry_blocks)


class Layout(unittest.TestCase):
    def test_reported_64gb_ipad_geometry_and_encoded_installation(self):
        from layout import encode, editor_commands, probe_sector_size
        a,b=fixture(blocks=7815175,sector=8192,system_end=300794)
        source,stock=inspect(a,b)
        self.assertEqual((source['block_size'],source['first'],source['last']),(8192,4,7815171))
        self.assertEqual([(p['first'],p['last']) for p in stock],[(4,300794),(300795,7815171)])
        self.assertEqual(probe_sector_size(a[:16384]),8192)
        for release in ('5.1.1','6.1.3','7.1.2','8.4.1'):
            with self.subTest(release=release):
                next_a,next_b,layout=encode(a,b,1024**3,release)
                header,parts=inspect(next_a,next_b)
                self.assertEqual(header['guid'],source['guid'])
                self.assertEqual(header['block_size'],8192)
                self.assertEqual(parts[0]['guid'],stock[0]['guid'])
                self.assertEqual(layout['block_size'],8192)
                self.assertEqual(parts[2]['first'],4)
                self.assertEqual(parts[2]['last'],4+1024**3//8192-1)
                self.assertEqual([p['bytes'] for p in layout['partitions'] if p['role'].startswith('bootstrap')],
                                 [30*1024**2,2*1024**2])
                commands=editor_commands(a,b,1024**3,release,True)
                self.assertTrue(commands.endswith(b'v\nw\nY\n'))
                # Reinstallation of the four-volume 8 KiB layout is recognized.
                editor_commands(next_a,next_b,1024**3+8192,release)
                with self.assertRaises(ValueError):inspect(next_a,b)

    def test_sector_detection_and_geometry_reject_ambiguous_or_corrupt_tables(self):
        from layout import encode, probe_sector_size
        a,b=fixture(sector=8192)
        with self.assertRaisesRegex(ValueError,'whole disk sectors'):
            encode(a,b,1024**3+4096,'5.1.1')
        bad=bytearray(a);bad[2*8192]^=1
        with self.assertRaises(ValueError):inspect(bad,b)
        with self.assertRaises(ValueError):inspect(a,b[:-4096])
        small,_=fixture()
        both=bytearray(a[:16384]);both[4096:8192]=small[4096:8192]
        with self.assertRaisesRegex(ValueError,'ambiguous'):probe_sector_size(both)
        with self.assertRaises(ValueError):probe_sector_size(bytes(16384))

    def test_every_ios8_target_uses_the_proven_upgrade_role(self):
        for release in ('8.0', '8.1.3', '8.3', '8.4.1'):
            self.assertEqual(partition_names(release)['system'], 'Update')
        self.assertEqual(partition_names('7.1.2')['system'], 'System')

    def test_editor_retains_boundaries_for_odd_sized_images(self):
        from layout import editor_commands
        a,b=fixture()
        size=1024**3+4096
        layout=plan(a,b,size,'6.1.3')
        data=next(p for p in layout['partitions'] if p['role']=='data')
        self.assertEqual(data['first'] % 2, 1)
        commands=editor_commands(a,b,size,'6.1.3').decode()
        self.assertIn('\nl\n1\nm\nn\n',commands)
        self.assertIn('\nn\n2\n'+str(data['first'])+'\n',commands)
        self.assertTrue(commands.endswith('\nv\nq\n'))

    def test_capacity_drives_partition_boundaries(self):
        for blocks in (4*1024*256,16*1024*256):
            p=plan(*fixture(blocks),1024**3,'7.1.2')
            parts=sorted(p['partitions'],key=lambda x:x['first'])
            self.assertEqual(parts[0]['first'],6)
            self.assertEqual(parts[-1]['last'],blocks-6)
            self.assertTrue(all(a['last']+1==b['first'] for a,b in zip(parts,parts[1:])))
            self.assertEqual(sum(x['bytes'] for x in p['partitions'] if x['role'].startswith('bootstrap')),32*1024**2)
            self.assertEqual(p['partitions'][1]['attributes'],0)

    def test_corruption_overlap_and_insufficient_capacity_rejected(self):
        a,b=fixture();bad=bytearray(a);bad[8192]^=1
        with self.assertRaises(ValueError):inspect(bad,b)
        with self.assertRaises(ValueError):inspect(*fixture(overlap=True))
        with self.assertRaises(ValueError):plan(a,b,4*1024**3,'7.1.2')
        with self.assertRaises(ValueError):plan(a,b,1025,'7.1.2')

    def test_version_rules_do_not_copy_ios6_data_flags_to_newer_os(self):
        a,b=fixture()
        self.assertEqual(plan(a,b,1024**3,'6.0.0')['partitions'][1]['attributes'],0x3000000000000)
        for release in ('7.1.2','8.1.3','9.3.4','10.3.4'):
            self.assertEqual(plan(a,b,1024**3,release)['partitions'][1]['attributes'],0)

    def test_apple_revision_and_mismatched_headers(self):
        self.assertEqual(inspect(*fixture(revision=1))[0]['revision'],1)
        a,_=fixture(revision=1)
        _,b=fixture()
        with self.assertRaises(ValueError):inspect(a,b)
        with self.assertRaises(ValueError):inspect(*fixture(revision=2))

    def test_encoded_mirrors_preserve_identity_and_reject_torn_update(self):
        from layout import encode
        for revision in (1,0x10000):
            old_a,old_b=fixture(revision=revision)
            a,b,p=encode(old_a,old_b,1024**3,'7.1.2')
            h,parts=inspect(a,b)
            self.assertEqual(h['guid'],inspect(old_a,old_b)[0]['guid'])
            self.assertEqual(parts[0]['guid'],inspect(old_a,old_b)[1][0]['guid'])
            self.assertEqual(len(parts),4)
            self.assertEqual(a[:4096],old_a[:4096])
            self.assertEqual(h['revision'],revision)
            self.assertEqual([x['first'] for x in parts],[x['first'] for x in p['partitions']])
            with self.assertRaises(ValueError):inspect(a,old_b)
