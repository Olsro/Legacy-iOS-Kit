"""Synthetic firmware/cache fixtures, with independent ARM execution checks."""
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bootchain import (literal_ibss, memory_layout, preserve_upgrade_autoboot,
                       skip_ramdisk)
from compact_cache import (ARMV7_REQUIRED_PATCHES, ARMV7_REQUIRED_RANGES,
                           ARMV7_SOURCE)
from ios8_cache import prepare, protect_registry, encode, export_slot
from logo import bl
from system import jailbreak_payload
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R5

BASE=0x10000000


class IOS8Payload(unittest.TestCase):
    def test_every_ios8_release_uses_validated_patcyh_payload(self):
        for release in ('8.0', '8.0.1', '8.0.2', '8.1', '8.1.1', '8.1.2',
                        '8.1.3', '8.2', '8.3', '8.4', '8.4.1'):
            payload, provenance = jailbreak_payload(release)
            self.assertIn('usr/lib/libpatcyh.dylib', payload)
            self.assertIn('Library/MobileSubstrate/DynamicLibraries/patcyh.plist', payload)
            self.assertNotIn('resources/jailbreak/nopatcyh.tar',
                             {item['path'] for item in provenance})

def firmware(token):
    data=bytearray(2048)
    struct.pack_into('<I',data,32,BASE+64)
    data[0x300:0x300+len(token)]=token
    struct.pack_into('<I',data,0x180,BASE+0x300)
    return data

class BootVariants(unittest.TestCase):
    def test_upgrade_keeps_persistent_autoboot_rearmed(self):
        data=firmware(b'auto-boot\0')
        for at,token in [(0x320,b'false\0'),(0x340,b'true\0')]:
            data[at:at+len(token)]=token
        # ldr r0, auto-boot; mov.w r2, #1; ldr r1, false; add r7, sp, #4; bl
        code=bytes.fromhex('1f484ff001021f4917af')+bl(0x10a,0x500)
        data[0x100:0x100+len(code)]=code
        struct.pack_into('<I',data,0x180,BASE+0x300)
        struct.pack_into('<I',data,0x184,BASE+0x320)
        patched,report=preserve_upgrade_autoboot(bytes(data))
        self.assertEqual(report['instruction'],0x100)
        self.assertEqual(report['literal'],0x184)
        self.assertEqual(struct.unpack_from('<I',patched,0x184)[0],BASE+0x340)
        changed=[i for i,(before,after) in enumerate(zip(data,patched)) if before!=after]
        self.assertEqual(changed,[0x184])
        checked,second=preserve_upgrade_autoboot(patched)
        self.assertEqual(checked,patched)
        self.assertTrue(second['already_rearmed'])

    def test_newer_upgrade_handler_is_validated_without_modification(self):
        data=firmware(b'auto-boot\0')
        for at,token in [(0x320,b'false\0'),(0x340,b'true\0'),
                         (0x360,b'upgrade\0'),(0x380,b'boot-command\0')]:
            data[at:at+len(token)]=token
        # push; ldr r0, boot-command; add r7, sp, #8; bl remove; bl save
        code=bytes.fromhex('08b51f4802af')+bl(0x106,0x500)+bl(0x10a,0x600)
        data[0x100:0x100+len(code)]=code
        struct.pack_into('<I',data,0x180,BASE+0x380)
        struct.pack_into('<II',data,0x1a0,BASE+0x360,BASE+0x101)
        # The dualboot patch also references "upgrade" from its fsboot
        # literal pair; the following even pointer proves it is not the
        # command-table entry.
        struct.pack_into('<II',data,0x1c0,BASE+0x360,BASE+0x380)
        patched,report=preserve_upgrade_autoboot(bytes(data))
        self.assertEqual(patched,bytes(data))
        self.assertEqual(report,dict(
            instruction=0x100,form='transient-boot-command',persistent=False))

    def test_preloaded_ibss_uses_memory_and_skips_usb(self):
        data=firmware(b'iBSS ready, asking for DFU...\n\0')
        code=bytes.fromhex('1f48')+bl(0x102,0x500)+bytes.fromhex('1f484ff400110690cdf81480')+bl(0x112,0x600)+bytes.fromhex('0546002df4db')
        data[0x100:0x100+len(code)]=code
        struct.pack_into('<I',data,0x184,0x9fe00000)
        second=memory_layout('iPhone5,2')[1]
        patched,report=literal_ibss(bytes(data),second)
        uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB);uc.mem_map(BASE,4096);uc.mem_write(BASE,patched)
        uc.mem_map(0x20000000,4096);uc.reg_write(UC_ARM_REG_SP,0x20000800)
        uc.emu_start(BASE+0x107,BASE+0x11c,count=20)
        self.assertEqual(uc.reg_read(UC_ARM_REG_R5),0x200000)
        self.assertEqual(struct.unpack('<I',uc.mem_read(0x20000818,4))[0],second)
        self.assertEqual(report['usb_call'],0x112)
        struct.pack_into('<I',data,0x184,123)
        with self.assertRaises(ValueError):literal_ibss(bytes(data),second)
        # A5 iOS 8 uses the same receive-loop form with a different stock
        # buffer. Keep the A6 default strict; require an explicit A5 policy.
        struct.pack_into('<I',data,0x184,0x8fe00000)
        with self.assertRaises(ValueError):literal_ibss(bytes(data),second)
        a5_second=memory_layout('iPod5,1')[1]
        patched,report=literal_ibss(bytes(data),a5_second,stock_buffer=0x8fe00000)
        self.assertEqual(struct.unpack_from('<I',patched,0x184)[0],a5_second)
        self.assertEqual(report['before'],'0x8fe00000')

    def test_ramdisk_failure_branch_can_fall_through(self):
        data=firmware(b'/boot/ramdisk\0')
        code=bytes.fromhex('1f48')+bl(0x102,0x500)+bytes.fromhex('00280ad1')
        data[0x100:0x100+len(code)]=code
        data[0x120:0x122]=bytes.fromhex('1848')
        message=b'failed to load ramdisk\n\0'
        data[0x340:0x340+len(message)]=message
        struct.pack_into('<I',data,0x184,BASE+0x340)
        patched,report=skip_ramdisk(bytes(data))
        self.assertEqual(report['offset'],0x108)
        for result in (0,1,0xffffffff):
            uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB);uc.mem_map(BASE,4096);uc.mem_write(BASE,patched)
            uc.reg_write(UC_ARM_REG_R0,result)
            uc.emu_start(BASE+0x107,BASE+0x10a,count=2)
            self.assertEqual(uc.reg_read(UC_ARM_REG_R0),result)
        data[0x340]=0
        with self.assertRaises(ValueError):skip_ramdisk(bytes(data))

class CacheRemap(unittest.TestCase):
    def test_armv7_recipe_retains_early_initializer_stub_pages(self):
        recipe=json.loads((Path(__file__).resolve().parents[1]/
                           'recipes/dyld-armv7-12H321.recipe').read_text())
        self.assertEqual(recipe['output_sha256'],ARMV7_SOURCE['prepared_sha256'])
        for required,count in ARMV7_REQUIRED_RANGES:
            self.assertTrue(any(offset<=required and required+count<=offset+length
                                for offset,length in recipe['keep_ranges']))
        self.assertEqual(tuple(tuple(item) for item in recipe['bootstrap_patches']),
                         ARMV7_REQUIRED_PATCHES)

    def fixture(self, architecture='armv7s'):
        data=bytearray(0x1d00c)
        data[:16]=b'dyld_v1'+b' '*(8-len(architecture))+architecture.encode()+b'\0'
        struct.pack_into('<4I',data,16,0x80,3,0x200,1)
        maps=[(0x20000000,0x10000,0,5,5),(0x20010000,0x1000,0x10000,3,3),(0x20011000,0xc000,0x11000,1,1)]
        for i,m in enumerate(maps):struct.pack_into('<QQQII',data,0x80+i*32,*m)
        struct.pack_into('<QQQII',data,0x200,0x20008000,0,0,0x240,0)
        name=b'/usr/lib/libmis.dylib\0';data[0x240:0x240+len(name)]=name
        data[0x8000:0x8004]=b'\xce\xfa\xed\xfe'
        struct.pack_into('<II',data,0x8010,1,48)
        struct.pack_into('<II',data,0x801c,0x80000022,48)
        symbol=b'_MISValidateSignature'
        trie=b'\0\1'+symbol+b'\0'+bytes([len(symbol)+4])+b'\3\0'+encode(0x301)+b'\0'
        struct.pack_into('<II',data,0x8044,0x16000,len(trie))
        data[0x16000:0x16000+len(trie)]=trie
        data[0x8200:0x8204]=bytes.fromhex('00207047')
        struct.pack_into('<QQ',data,40,0x1d000,12)
        struct.pack_into('>III',data,0x1d000,0xfade0cc0,12,0)
        return bytes(data),maps

    def test_loaded_cache_preserves_all_bytes_except_thumb_export(self):
        stock,maps=self.fixture();patched,report=prepare(stock)
        loaded=b''.join(patched[m[2]:m[2]+m[1]] for m in report['mappings'])
        original=b''.join(stock[m[2]:m[2]+m[1]] for m in maps)
        changed=[i for i,(a,b) in enumerate(zip(original,loaded)) if a!=b]
        self.assertEqual(changed,[report['export_offset']+1])
        self.assertEqual(report['replacement_export'],0x201)
        self.assertEqual(loaded[0x8000:0x10000],stock[0x8000:0x10000])
        self.assertEqual(struct.unpack_from('<II',patched,20),(6,0x260))
        self.assertEqual(patched[0x2a0:0x2a0+22],b'/usr/lib/libmis.dylib\0')

    def test_unknown_maps_gadgets_and_cyclic_trie_rejected(self):
        stock,_=self.fixture()
        for offset in (0,0x90,0x8200):
            data=bytearray(stock);data[offset]^=1
            with self.assertRaises(ValueError):prepare(bytes(data))
        with self.assertRaisesRegex(ValueError,'Cyclic'):export_slot(b'\0\1x\0\0',b'x')

    def test_armv7_uses_the_same_checked_mapping_transform(self):
        stock,_=self.fixture('armv7')
        patched,report=prepare(stock,'armv7')
        self.assertTrue(patched.startswith(b'dyld_v1   armv7\0'))
        self.assertEqual(report['architecture'],'armv7')
        with self.assertRaises(ValueError):prepare(stock,'armv7s')

    def test_registry_prefix_becomes_read_only_without_changing_loaded_bytes(self):
        stock,_=self.fixture('armv7')
        patched,report=prepare(stock,'armv7')
        before=b''.join(patched[m[2]:m[2]+m[1]] for m in report['mappings'])
        protected,mappings=protect_registry(patched,0x20008800,0x800)
        after=b''.join(protected[m[2]:m[2]+m[1]] for m in mappings)
        self.assertEqual(after,before)
        self.assertEqual(mappings[0][0:2],(0x20000000,0x9000))
        self.assertEqual(mappings[0][3:],(1,1))
        self.assertEqual(mappings[1][0],0x20009000)
