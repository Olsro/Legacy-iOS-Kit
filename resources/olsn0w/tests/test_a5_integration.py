import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from a5_loader import payload, QUALIFIED_SHA256, WRAPPER
from bootchain import preloaded_ibss_length, ram_autoboot, memory_layout
from logo import bl


class A5Integration(unittest.TestCase):
    def test_personalization_keeps_the_two_image_a5_relay(self):
        from restore import update_bootstrap_relay
        boot=Mock()
        images={'iBSS.raw':b'ibss','iBEC.img3':b'ibec'}
        contents={'/usr/local/bin/kloader':WRAPPER,
                  '/usr/local/bin/4smulti_kloader':payload(),
                  **{'/olsn0w/'+name:data for name,data in images.items()}}
        boot.read.side_effect=contents.__getitem__
        with patch('a5_loader.relay_images',return_value=images):
            update_bootstrap_relay(boot,'iPod5,1',Path('/relay'))
        self.assertEqual([call.args for call in boot.replace_regular.call_args_list],
                         [('/olsn0w/iBSS.raw',b'ibss'),('/olsn0w/iBEC.img3',b'ibec')])

    def test_personalization_keeps_the_contiguous_a6_relay(self):
        from restore import update_bootstrap_relay
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'relay.bin').write_bytes(b'contiguous')
            boot=Mock();boot.read.return_value=b'contiguous'
            update_bootstrap_relay(boot,'iPhone5,2',Path(folder))
            boot.replace_regular.assert_called_once_with('/olsn0w/relay.bin',b'contiguous')

    def test_binding_cannot_replace_encrypted_a5_kernel_with_plaintext(self):
        from provisioned_base import bootstrap_kernel
        def parse(data):return ('krnl',['KBAG'] if data==b'encrypted' else [],b'body')
        with patch('provisioned_base.img3',side_effect=parse):
            self.assertEqual(bootstrap_kernel('iPod5,1','verified-signed-base-bundle',
                                             b'encrypted',b'plain'),b'encrypted')
            with self.assertRaises(ValueError):
                bootstrap_kernel('iPod5,1','restored-system-volume',b'encrypted',b'plain')
            self.assertEqual(bootstrap_kernel('iPhone5,2','restored-system-volume',
                                             b'old',b'plain'),b'plain')

    def test_qualified_loader_is_available_without_session_files(self):
        self.assertEqual(hashlib.sha256(payload()).hexdigest(),QUALIFIED_SHA256)
        self.assertIn(b'/olsn0w/iBSS.raw /olsn0w/iBEC.img3',WRAPPER)
        self.assertNotIn(b'relay-go',WRAPPER)
        self.assertEqual(memory_layout('iPhone5,2'),(0xbfe00000,0xbfe20000))
        self.assertEqual(memory_layout('iPad3,4'),(0xbfe00000,0xbfe20000))

    def test_cache_retains_metadata_and_never_patches_apple_code(self):
        r=json.loads((ROOT/'recipes/dyld-armv7-12H321.recipe').read_text())
        self.assertEqual(r['bootstrap_patches'],[])
        self.assertEqual(r['retained_executable_pages'],2946)
        self.assertEqual(len(set(r['required_metadata_pages'])),136)
        for p in r['required_metadata_pages']:
            self.assertTrue(any(a<=p and p+4096<=a+n for a,n in r['keep_ranges']),hex(p))

    def test_receive_loop_returns_length_not_pointer(self):
        original=bytes.fromhex('4ff40011029020460394')+bl(10,0x100)+bytes.fromhex('0646002ef0db')
        patched=original[:10]+bytes.fromhex('00bf00bf')+original[14:18]+bytes.fromhex('00bf')
        log='patch_dualboot_ibss: Found usb_wait_for_image() at 0xa'
        result,report=preloaded_ibss_length(original,patched,log)
        self.assertEqual(result[10:14],bytes.fromhex('084600bf'))
        self.assertEqual(result[:10],patched[:10]);self.assertEqual(result[14:],patched[14:])
        self.assertEqual(report['length'],0x200000)
        for raw,data,text in [(original,result,log),(original,patched,log+'\n'+log),
                              (bytes(len(original)),patched,log)]:
            with self.assertRaises(ValueError):preloaded_ibss_length(raw,data,text)
        # iOS 7's r10 stack store is wide: the same bounded receive contract.
        wide=bytes.fromhex('4ff4001105905046cdf818a0')+bl(12,0x100)+bytes.fromhex('0646002ef0db')
        patched=wide[:12]+bytes.fromhex('00bf00bf')+wide[16:20]+bytes.fromhex('00bf')
        result,_=preloaded_ibss_length(wide,patched,log.replace('0xa','0xc'))
        self.assertEqual(result[12:16],bytes.fromhex('084600bf'))

    def test_ram_autoboot_changes_only_one_call(self):
        data=bytearray(2048);struct.pack_into('<I',data,32,0x9ff00040)
        data[0x300:0x30a]=b'auto-boot\0';struct.pack_into('<I',data,0x180,0x9ff00300)
        code=bytes.fromhex('1f4800214ff00008')+bl(0x108,0x500)+bytes.fromhex('0446012c00d1')
        data[0x100:0x100+len(code)]=code
        result,report=ram_autoboot(bytes(data))
        self.assertEqual(report['offset'],0x108);self.assertFalse(report['persistent'])
        self.assertEqual(result[:0x108],data[:0x108]);self.assertEqual(result[0x10c:],data[0x10c:])
        self.assertEqual(result[0x108:0x10c],bytes.fromhex('012000bf'))
        with self.assertRaises(ValueError):ram_autoboot(result)
        data[0x400:0x40a]=b'auto-boot\0'
        with self.assertRaises(ValueError):ram_autoboot(bytes(data))

    @unittest.skipUnless(shutil.which('cc'),'C compiler unavailable')
    def test_native_wake_failure_and_notification_contract(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder)
            (folder/'olsn0w_config.h').write_text('#define OLSN0W_BOARD "TESTAP"\n')
            subprocess.run(['cc','-fno-builtin','-I'+str(folder),str(ROOT/'tests/wake_a5_harness.c'),'-o',str(folder/'test')],check=True,capture_output=True)
            result=subprocess.run([folder/'test'],check=True,capture_output=True,text=True)
            self.assertIn('failure guards passed',result.stdout)
