"""Relocated firmware fixtures and ARM execution of target-volume selection."""
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logo import bl
from upgrade_volume import apply
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import *


def fixture(base=0x10000000, shift=0):
    data=bytearray(0x2000)
    struct.pack_into('<I',data,32,base+64)
    start=0x100+shift
    # Flag search, two error paths, and the two-entry literal pool.
    body=bytearray.fromhex('80b56f460000000001e00000000060b1017911f0020ff8d0383000000000002804bf002080bd054800e00348000000004ff0ff3080bd00bf0000000000000000')
    for site,target in [(4,0x480),(10,0x490),(26,0x500),(44,0x700)]:
        body[site:site+4]=bl(start+site,target+shift)
    tokens=[(0x900,b'could not locate upgrade partition\n\0'),
            (0x940,b'failed to mount upgrade partition\0'),
            (0x980,b'boot-device\0'),(0x9a0,b'%s%c\0')]
    for at,text in tokens:data[at+shift:at+shift+len(text)]=text
    struct.pack_into('<II',body,56,base+0x900+shift,base+0x940+shift)
    data[start:start+64]=body
    # Unique nullable environment-string getter.
    getter=bytes.fromhex('80b56f46')+bl(0x604+shift,0x680+shift)+bytes.fromhex('00281cbf006880bd002080bd')
    data[0x600+shift:0x614+shift]=getter
    # Two callers pass a device-name format to the same bounded formatter.
    for at in (0x300+shift,0x340+shift):
        data[at:at+8]=bytes.fromhex('024a2021')+bl(at+4,0x800+shift)
        struct.pack_into('<I',data,at+12,base+0x9a0+shift)
    return bytes(data)


class UpgradeVolume(unittest.TestCase):
    def execute(self,base,shift,stem,partition,mount_result):
        original=fixture(base,shift);data,p=apply(original,partition)
        self.assertEqual(len(original),len(data))
        self.assertEqual(data[:p['offset']],original[:p['offset']])
        self.assertEqual(data[p['offset']+64:],original[p['offset']+64:])
        cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB);cpu.mem_map(base,0x2000);cpu.mem_write(base,data)
        heap=0x40000000;cpu.mem_map(heap,0x20000)
        if stem is not None:cpu.mem_write(heap,stem+b'\0')
        stack=heap+0x1f000;cpu.reg_write(UC_ARM_REG_SP,stack);cpu.reg_write(UC_ARM_REG_LR,base+0x1801)
        regs=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
        for i,r in enumerate(regs):cpu.reg_write(r,0x1200+i)
        mounted=[];returned=[]
        def string(at):return bytes(cpu.mem_read(at,256)).split(b'\0')[0]
        def hook(u,at,size,_):
            if at==base+0x600+shift:
                self.assertEqual(string(u.reg_read(UC_ARM_REG_R0)),b'boot-device')
                u.reg_write(UC_ARM_REG_R0,heap if stem is not None else 0)
            elif at==base+0x800+shift:
                self.assertEqual(string(u.reg_read(UC_ARM_REG_R2)),b'%s%c')
                cap=u.reg_read(UC_ARM_REG_R1);self.assertEqual(cap,128)
                letter=struct.unpack('<I',u.mem_read(u.reg_read(UC_ARM_REG_SP),4))[0]
                out=string(u.reg_read(UC_ARM_REG_R3))+bytes([letter])
                u.mem_write(u.reg_read(UC_ARM_REG_R0),out[:cap-1]+b'\0');u.reg_write(UC_ARM_REG_R0,len(out))
            elif at==base+0x500+shift:
                mounted.append(string(u.reg_read(UC_ARM_REG_R0)));u.reg_write(UC_ARM_REG_R0,mount_result)
            elif at==base+0x1800:returned.append(True);u.emu_stop();return
            else:return
            u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
        cpu.hook_add(UC_HOOK_CODE,hook);cpu.emu_start(base+p['offset']+1,base+0x1900,count=100)
        valid=stem is not None and len(stem)+1<128
        self.assertEqual(mounted,[stem+bytes([ord('a')+partition-1])] if valid else [])
        self.assertTrue(returned);self.assertEqual(cpu.reg_read(UC_ARM_REG_SP),stack)
        self.assertEqual(cpu.reg_read(UC_ARM_REG_R0),mount_result if valid else 0xffffffff)
        self.assertEqual([cpu.reg_read(r) for r in regs],[0x1200+i for i in range(len(regs))])

    def test_device_name_partition_bounds_and_mount_failure(self):
        for base,shift in [(0x10000000,0),(0x20000000,0x100)]:
            for stem,partition,result in [(b'nand0',3,0),(b'flash2',1,0),(b'nand1',26,0),
                                          (b'nand0',3,0xffffffff),(None,3,0),(b'x'*127,3,0),(b'x'*126,3,0)]:
                with self.subTest(base=base,stem=stem,partition=partition):self.execute(base,shift,stem,partition,result)

    def test_unknown_search_and_ambiguous_getter_rejected(self):
        original=fixture()
        for at in (0x116,0x900,0x600):
            bad=bytearray(original);bad[at]^=1
            with self.assertRaises(ValueError):apply(bytes(bad))
        bad=bytearray(original);bad[0xa00:0xa14]=bad[0x600:0x614]
        with self.assertRaises(ValueError):apply(bytes(bad))
        for partition in (0,27,True,'3'):
            with self.assertRaises(ValueError):apply(original,partition)

    def test_disagreeing_formatters_rejected(self):
        bad=bytearray(fixture());bad[0x344:0x348]=bl(0x344,0x820)
        with self.assertRaises(ValueError):apply(bytes(bad))
