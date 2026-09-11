"""Host-independent checks for catalog identity and generated ARM control flow."""
import io
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from bootchain import movt
from common import KIT, tools, target
from firmware import identity, select_release
import firmware
import logo
from validation import display


class HostTools(unittest.TestCase):
    def test_supported_hosts_use_bundled_tools(self):
        for system, arch, relative in [
            ('Linux', 'aarch64', 'linux/arm64'),
            ('Linux', 'x86_64', 'linux/x86_64'),
            ('Darwin', 'arm64', 'macos/arm64'),
            ('Darwin', 'x86_64', 'macos'),
        ]:
            with self.subTest(system=system, arch=arch), patch('platform.system', return_value=system), patch('platform.machine', return_value=arch):
                self.assertEqual(tools(), KIT / 'bin' / relative)

    def test_unknown_arch_does_not_use_wrong_binaries(self):
        with patch('platform.system', return_value='Darwin'), patch('platform.machine', return_value='unknown'):
            with self.assertRaises(ValueError):
                tools()


class CatalogIdentity(unittest.TestCase):
    def test_no_upper_version_cutoff(self):
        for product in ('iPhone5,1', 'iPhone5,2', 'iPad3,4', 'iPad3,5', 'iPad3,6'):
            for release in ('6.0.0', '7.1.2', '8.4.1', '9.3.5', '10.3.4'):
                self.assertTrue(target(product, release))

    def test_reissued_release_requires_build(self):
        records = [dict(version='10.1.1', buildid=b) for b in ('14B100', '14B150')]
        with self.assertRaisesRegex(ValueError, '--build'):
            select_release(records, '10.1.1')
        self.assertEqual(select_release(records, '10.1.1', '14B150')['buildid'], '14B150')
        with self.assertRaises(ValueError):
            select_release(records, '10.1.1', 'unavailable')

    def test_manifest_checks_chip_and_board_before_using_payload(self):
        manifest = dict(ProductVersion='7.1.2', SupportedProductTypes=['iPad3,4'],
                        BuildIdentities=[dict(ApChipID='0x8950', ApBoardID='0',
                                             Info=dict(DeviceClass='p101ap'))])
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('BuildManifest.plist', plistlib.dumps(manifest))
        with zipfile.ZipFile(buffer) as archive, self.assertRaisesRegex(ValueError, 'chip/board'):
            identity(archive, 'iPad3,4', '7.1.2')


class ThumbGeneration(unittest.TestCase):
    def test_movt_decodes_to_requested_value(self):
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        decoder.detail = True
        for register in (0, 4, 12):
            for immediate in (0, 0x800, 0x1000, 0xbfe2, 0xffff):
                instruction = list(decoder.disasm(movt(register, immediate), 0))
                self.assertEqual(len(instruction), 1)
                self.assertEqual(instruction[0].mnemonic, 'movt')
                self.assertEqual(instruction[0].reg_name(instruction[0].operands[0].reg), 'r' + str(register) if register != 12 else 'ip')
                self.assertEqual(instruction[0].operands[1].imm, immediate)

    def test_logo_success_and_failures_preserve_caller_state(self):
        base = 0x80000000
        params = dict(base=base, hook_offset=0x400, cave_offset=0x200,
                      loader=base+0x601, setpicture=base+0x621,
                      set_bgcolor=base+0x641, apply_bgcolor=base+0x661)
        raw = bytearray(4096)
        raw[0x100:0x100+16] = b'/boot/applelogo\0'
        code = logo.trampoline(params)
        raw[0x200:0x200+len(code)] = code
        raw[0x400:0x404] = logo.bl(base+0x400, base+0x200)
        report = display(bytes(raw), params)
        self.assertEqual(len(report['trampoline_cases']), 3)
        self.assertFalse(report['physical_display_validated'])

    def test_invalid_thumb_addresses_rejected(self):
        with self.assertRaises(ValueError):
            logo.trampoline(dict(loader=0, setpicture=1, set_bgcolor=1, apply_bgcolor=1))
        with self.assertRaises(ValueError):
            movt(15, 1)


class ExtractionCompletion(unittest.TestCase):
    def test_extraction_publishes_directory_and_reuses_verified_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipsw = root / 'fixture.ipsw'
            pairs = [('iBSS', 'iBSS'), ('iBEC', 'iBEC'), ('DeviceTree', 'DeviceTree'),
                     ('Kernelcache', 'KernelCache'), ('AppleLogo', 'AppleLogo'), ('RootFS', 'OS')]
            keys = dict(keys=[dict(image=name, filename=name, key='fixture', iv='fixture') for name, _ in pairs])
            selected = dict(Manifest={component: dict(Info=dict(Path=name)) for name, component in pairs})
            manifest = dict(ProductVersion='7.1.2', ProductBuildVersion='11D257')
            with zipfile.ZipFile(ipsw, 'w') as archive:
                for name, _ in pairs:
                    archive.writestr(name, b'synthetic-test-payload')

            def extract_component(argv, *args, **kwargs):
                output = argv[3] if Path(argv[0]).name == 'dmg' else argv[2]
                Path(output).write_bytes(b'synthetic-decoded-payload')

            with patch.object(firmware, 'STATE', root / 'state'), patch.object(firmware, 'acquire', return_value=(ipsw, keys, manifest, selected)), patch.object(firmware, 'run', side_effect=extract_component) as command:
                folder, report = firmware.extract('iPhone5,1', '7.1.2')
                self.assertEqual(folder.name, 'firmware')
                self.assertTrue((folder / 'manifest.json').is_file())
                self.assertFalse(list(folder.parent.glob('firmware-pending-*')))
                command.reset_mock()
                self.assertEqual(firmware.extract('iPhone5,1', '7.1.2'), (folder, report))
                command.assert_not_called()
                (folder / 'iBEC.raw').write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'changed'):
                    firmware.extract('iPhone5,1', '7.1.2')


if __name__ == '__main__':
    unittest.main()
