"""iOS 5 preparation boundaries; these are not hardware qualification tests."""
import hashlib
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from common import IOS5_MINIMUM, MODELS, target
from bootchain import preloaded_ibss_length, ram_autoboot
from logo import bl
from system import jailbreak_payload, ios6_launchd_conf, uses_protected_data
from restore_environment import selected_build
from restore import require_data_environment
from ios5_helpers import payloads


class IOS5Preparation(unittest.TestCase):
    def test_all_ios5_releases_are_selectable_without_opt_in(self):
        from guided import choose, support_reason
        for release in ('5.0', '5.0.1', '5.1', '5.1.1'):
            option = dict(version=release, buildid='catalog-build')
            self.assertIsNone(support_reason(release))
            for answer in ('1', release):
                messages = []
                self.assertEqual(choose([option], lambda _: answer, messages.append), option)
                self.assertFalse(any('unavailable' in m or 'experimental' in m for m in messages))

    def test_menu_does_not_gate_unvalidated_ios5_models(self):
        import guided
        for product in IOS5_MINIMUM:
            identity = dict(product=product, mode='Normal')
            options = [dict(version='5.1.1', buildid='9B206')]
            messages = []
            # Exercise the real menu/chooser without preparing or modifying a device.
            class Selected(Exception):
                pass
            answers = iter(('1', 'n', ''))
            with tempfile.TemporaryDirectory() as directory, \
                 patch.object(guided, 'STATE', Path(directory)), \
                 patch.object(guided, 'connected', return_value=(identity, None)), \
                 patch.object(guided, 'releases', return_value=options), \
                 patch.object(guided, 'choose_ipsws', return_value={}), \
                 patch.object(guided, 'prepare', side_effect=Selected) as prepare:
                with self.assertRaises(Selected):
                    guided.menu(product, '123', read=lambda _: next(answers), show=messages.append)
                self.assertEqual(prepare.call_args.args[0].parent, Path(directory)/'sessions')
                self.assertEqual(prepare.call_args.args[1], options[0])
            self.assertFalse(any('unavailable' in m or 'experimental' in m for m in messages))

    def test_model_boundaries(self):
        for product in MODELS:
            if product in IOS5_MINIMUM:
                self.assertTrue(target(product,'5.1.1'))
                self.assertEqual(selected_build(product,'5.1.1'),'10B329')
                require_data_environment(product,'5.1.1','10B329')
                with self.assertRaises(ValueError):
                    require_data_environment(product,'5.1.1','12H321')
            else:
                with self.assertRaises(ValueError):target(product,'5.1.1')
        for product in ('iPad2,4','iPad3,1','iPad3,2','iPad3,3'):
            with self.assertRaises(ValueError):target(product,'5.0.1')
        self.assertTrue(target('iPhone4,1','5.0'))

    def test_native5_aquila_is_the_same_checked_legacy_binary(self):
        from aquila import IOS6_SHA256
        with tarfile.open(ROOT.parent/'jailbreak/aquila_5.tar') as archive:
            data=archive.extractfile('./private/var/aquila/aquila').read()
        self.assertEqual(hashlib.sha256(data).hexdigest(),IOS6_SHA256)
        entries,_=jailbreak_payload('5.1.1','iPad3,1')
        conf=ios6_launchd_conf(entries['private/etc/launchd.conf'][1],5)
        self.assertTrue(conf.startswith(b'bsexec .. /bin/sh /usr/local/libexec/olsn0w/ios5-firstboot.sh\n'))
        self.assertIn(b'ios6-start-aquila.sh',conf)
        self.assertTrue(conf.endswith(b'ios5-launchd-socket.sh save\n'))
        self.assertNotIn(b'ios5-launchd-socket.sh',
                         ios6_launchd_conf(entries['private/etc/launchd.conf'][1],6))
        self.assertTrue(uses_protected_data('5.1.1'))

    def test_helpers_have_legacy_entry_and_checked_provenance(self):
        self.assertEqual(set(payloads()),{'keybag-init','protection-probe'})
        script=(ROOT/'target/ios5-firstboot.sh').read_text()
        self.assertIn('protection-probe f ',script)
        self.assertNotIn('protection-probe d ',script)
        self.assertLess(script.index('/keybag-init\n'),script.index('/bin/tar'))
        self.assertLess(script.index('protection-probe f '),script.index('generation.new'))

    def test_packaged_arm_executables_do_not_require_ios6_entry(self):
        entries, _ = jailbreak_payload('5.1.1', 'iPad3,1')
        checked = 0
        for name, (_, blob) in entries.items():
            if not blob:
                continue
            slices = [blob]
            if blob[:4] == b'\xca\xfe\xba\xbe':
                slices = []
                for index in range(struct.unpack_from('>I', blob, 4)[0]):
                    cpu, _, offset, size, _ = struct.unpack_from('>5I', blob, 8+20*index)
                    if cpu == 12:
                        slices.append(blob[offset:offset+size])
            for data in slices:
                if data[:4] != b'\xce\xfa\xed\xfe':
                    continue
                checked += 1
                offset = 28
                for _ in range(struct.unpack_from('<I', data, 16)[0]):
                    command, size = struct.unpack_from('<II', data, offset)
                    self.assertNotEqual(command, 0x80000028, name)
                    if command == 0x25:
                        self.assertLessEqual(struct.unpack_from('<I', data, offset+8)[0],
                                             0x50000, name)
                    offset += size
        self.assertGreater(checked, 10)

    def test_ios5_receive_length_and_mutation_rejection(self):
        original=bytes.fromhex('039420464ff48011')+bl(8,0x100)+bytes.fromhex('00288246f0db')
        patched=original[:8]+bytes.fromhex('00bf00bf')+original[12:16]+bytes.fromhex('00bf')
        log='patch_dualboot_ibss: Found usb_wait_for_image() at 0x8'
        result,report=preloaded_ibss_length(original,patched,log)
        self.assertEqual(report['length'],0x100000)
        self.assertEqual(result[8:12],bytes.fromhex('084600bf'))
        self.assertEqual(result[:8],patched[:8])
        self.assertEqual(result[12:],patched[12:])
        for raw,data in ((original,result),(original[:-1],patched),(bytes(len(original)),patched)):
            with self.assertRaises(ValueError):preloaded_ibss_length(raw,data,log)

    def test_ios5_ram_autoboot_does_not_change_other_calls(self):
        data=bytearray(2048)
        struct.pack_into('<I',data,32,0x9ff00040)
        data[0x300:0x30a]=b'auto-boot\0'
        struct.pack_into('<I',data,0x180,0x9ff00300)
        code=(bytes.fromhex('1f480021')+bl(0x104,0x500)+bytes.fromhex('00240546')
              +bl(0x10c,0x510)+bytes.fromhex('204a214bc2e9000101211846')
              +bl(0x11c,0x520)+bytes.fromhex('002d00d0'))
        data[0x100:0x100+len(code)]=code
        result,report=ram_autoboot(bytes(data))
        self.assertEqual(report['offset'],0x104)
        self.assertFalse(report['persistent'])
        self.assertEqual(result[:0x104],data[:0x104])
        self.assertEqual(result[0x108:],data[0x108:])
        with self.assertRaises(ValueError):ram_autoboot(result)

    def test_separate_protection_format_commands(self):
        from hfs import HFS
        image=object.__new__(HFS);image.path=Path('/unused')
        with patch('native_tools.hfscompress',return_value='/tool'),patch('hfs.run') as run:
            image.initialize_protection_v2()
            self.assertEqual(run.call_args.args[0][-1],'--initialize-protection-v2')
            image.initialize_protection_v4()
            self.assertEqual(run.call_args.args[0][-1],'--initialize-protection-v4')
