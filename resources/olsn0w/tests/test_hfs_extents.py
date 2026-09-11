import pathlib,struct,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from hfs_extents import allocated_ranges

class Allocation(unittest.TestCase):
    def image(self,path):
        data=bytearray(16*4096);data[1024:1026]=b'HX'
        struct.pack_into('>III',data,1024+40,4096,16,11)
        struct.pack_into('>QII',data,1024+112,2,4096,1)
        struct.pack_into('>II',data,1024+128,1,1)
        data[4096:4098]=bytes([0xe0,0x11]) # blocks 0,1,2,11,15
        path.write_bytes(data)
    def test_noncontiguous_allocations_include_both_volume_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'image';self.image(path)
            self.assertEqual(allocated_ranges(path),[(0,3),(11,1),(15,1)])
    def test_rejects_wrong_free_count_outside_bitmap_and_missing_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'image'
            for offset,value in [(1024+48,10),(1024+128,16)]:
                self.image(path);data=bytearray(path.read_bytes());struct.pack_into('>I',data,offset,value);path.write_bytes(data)
                with self.assertRaises(ValueError):allocated_ranges(path)
            self.image(path);data=bytearray(path.read_bytes());data[4097]=0x18;path.write_bytes(data)
            with self.assertRaises(ValueError):allocated_ranges(path)
