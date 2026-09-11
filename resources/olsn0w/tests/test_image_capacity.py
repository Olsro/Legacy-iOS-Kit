from pathlib import Path
import sys
import struct
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from image_capacity import plan, root_reserve_bytes
from hfs_policy import require_reserve

class ImageCapacity(unittest.TestCase):
    def test_small_free_space_grows_for_whole_personalization(self):
        info=dict(block_size=4096,bytes=1300*1024**2,free_bytes=2*1024**2)
        budget=plan(info,[61*1024**2,200000],25)
        gained=budget['image_bytes']-info['bytes']
        self.assertGreaterEqual(gained+info['free_bytes'],budget['required_free_bytes'])
        self.assertGreater(budget['reserve_bytes'],16*1024**2)
        self.assertEqual(budget['image_bytes']%1048576,0)

    def test_sufficient_space_does_not_grow(self):
        info=dict(block_size=4096,bytes=1500*1024**2,free_bytes=300*1024**2)
        self.assertEqual(plan(info,[61*1024**2],25)['image_bytes'],info['bytes'])

    def test_each_file_rounded_and_uncompressible_payload_budgeted(self):
        info=dict(block_size=4096,bytes=1024**3,free_bytes=0)
        budget=plan(info,[1,4097,10*1024**2],3)
        self.assertEqual(budget['payload_bytes'],3*4096+10*1024**2)
        self.assertGreaterEqual(budget['image_bytes']-info['bytes'],budget['required_free_bytes'])

    def test_root_reserve_survives_personalization_and_volume_growth(self):
        info=dict(block_size=4096,bytes=2200*1024**2,free_bytes=174*1024**2)
        budget=plan(info,[61*1024**2],25)
        remaining=info['free_bytes']+budget['image_bytes']-info['bytes']-budget['payload_bytes']-budget['metadata_bytes']
        self.assertGreater(budget['image_bytes'],info['bytes'])
        # Check against the final volume size, not the smaller source image.
        desired=(budget['image_bytes']//4096//100)*11*4096
        self.assertGreaterEqual(remaining,desired+16*1024**2)

    def test_root_reserve_caps_at_hfs_desired_level_with_headroom(self):
        self.assertEqual(root_reserve_bytes(32*1024**3,4096),1296*1024**2)

    def test_image_check_distinguishes_root_from_auxiliary_volume(self):
        with tempfile.TemporaryDirectory() as folder:
            image=Path(folder)/'system.hfs'
            header=bytearray(1536);header[1024:1026]=b'H+'
            struct.pack_into('>III',header,1064,4096,2200*256,174*256)
            image.write_bytes(header)
            require_reserve(image)
            with self.assertRaisesRegex(ValueError,'Target root capacity'):
                require_reserve(image,root=True)
            struct.pack_into('>I',header,1072,300*256)
            image.write_bytes(header)
            require_reserve(image,root=True)
