"""Cover host-specific DFU preparation sequences."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rescue


class PrepareDFU(unittest.TestCase):
    def setUp(self):
        backend = patch('usb_backend.get_backend', return_value=object())
        self.backend = backend.start().return_value
        self.addCleanup(backend.stop)

    def test_unique_dfu_ignores_normal_mode_apple_devices(self):
        selected=SimpleNamespace(idProduct=0x1227,iSerialNumber=1)
        devices=[SimpleNamespace(idProduct=0x12a8),selected,SimpleNamespace(idProduct=0x1261)]
        with patch('usb.core.find',return_value=devices) as find, \
             patch('usb.util.get_string',return_value='CPID:8940 ECID:00000024c0036d8f'), \
             patch('usb.util.dispose_resources') as dispose:
            rescue.unique_usb_target(0x24c0036d8f)
            find.assert_called_once_with(find_all=True,idVendor=0x05ac,backend=self.backend)
            dispose.assert_called_once_with(selected)

    def test_unique_dfu_rejects_other_boot_interfaces_and_wrong_ecid(self):
        selected=SimpleNamespace(idProduct=0x1227,iSerialNumber=1)
        for other in (0x1222,0x1227,0x1280,0x1281,0x1282,0x1283):
            with patch('usb.core.find',return_value=[selected,SimpleNamespace(idProduct=other)]):
                with self.assertRaisesRegex(ValueError,'only the selected device'):
                    rescue.unique_usb_target(0x24c0036d8f)
        with patch('usb.core.find',return_value=[selected]), \
             patch('usb.util.get_string',return_value='ECID:1'), \
             patch('usb.util.dispose_resources') as dispose:
            with self.assertRaisesRegex(ValueError,'identity differs'):
                rescue.unique_usb_target(0x24c0036d8f)
            dispose.assert_called_once_with(selected)

    def test_checkm8_marker_accepts_irecovery_renderings_only(self):
        self.assertTrue(rescue.has_checkm8_marker('PWND: [checkm8]\n'))
        self.assertTrue(rescue.has_checkm8_marker('PWND: checkm8\n'))
        self.assertTrue(rescue.has_checkm8_marker('CPID: 0x8940\nPWND:[checkm8]\nMODE: DFU\n'))
        self.assertFalse(rescue.has_checkm8_marker('PWND: checkm8-extra\n'))
        self.assertFalse(rescue.has_checkm8_marker('note PWND: checkm8\n'))

    def session(self, root):
        session = Path(root)
        (session/'device.json').write_text(json.dumps({
            'identity': {'ecid': 0x1305409a38b, 'product': 'iPhone5,2'}
        }))
        return session

    def test_apple_silicon_uses_qualified_rosetta_sequence(self):
        with tempfile.TemporaryDirectory() as root:
            calls=[]
            def run(argv, label, timeout=45):
                calls.append((list(map(str, argv)), label, timeout))
                return 'SRTG: N/A\nIBFL: 0x1b\n' if label == 'ibss-ready' else ''
            with patch.object(rescue.platform, 'system', return_value='Darwin'), \
                 patch.object(rescue.platform, 'machine', return_value='arm64'), \
                 patch.object(rescue, 'unique_usb_target'), \
                 patch.object(rescue, 'recheck_recovery', return_value={'mode':'DFU'}), \
                 patch.object(rescue.time, 'sleep'):
                rescue.prepare_dfu(self.session(root), run=run)
            self.assertEqual(calls[0],
                (['arch','-x86_64',str(rescue.KIT/'bin/macos/ipwnder'),'-pv'],'pwn',60))
            self.assertEqual(calls[1],
                (['arch','-x86_64',str(rescue.KIT/'bin/macos/gaster'),'reset'],'pwn-reset',60))
            self.assertEqual(calls[2][1], 'ibss-ready')

    def test_already_pwned_skips_host_exploit(self):
        with tempfile.TemporaryDirectory() as root:
            calls=[]
            def run(argv, label, timeout=45):
                calls.append(label)
                return 'SRTG: N/A\nIBFL: 0x1b\n'
            with patch.object(rescue, 'unique_usb_target'), \
                 patch.object(rescue, 'recheck_recovery', return_value={'mode':'DFU'}), \
                 patch.object(rescue.time, 'sleep'):
                rescue.prepare_dfu(self.session(root), pwned=True, run=run)
            self.assertEqual(calls, ['ibss-ready'])


class InteractiveRescue(unittest.TestCase):
    def test_boots_guards_opens_shell_and_stops_owned_tunnel(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)
            (session/'device.json').write_text(json.dumps({'manage_usb_tunnel':True}))
            ram=Mock(prefix=['ssh','root@127.0.0.1'])
            tunnel=Mock()
            result=SimpleNamespace(returncode=0)
            messages=[]
            with patch.object(rescue,'boot') as boot, \
                 patch.object(rescue,'connect',return_value=ram) as connect, \
                 patch('usb_tunnel.start',return_value=tunnel) as start, \
                 patch('usb_tunnel.stop') as stop, \
                 patch.object(rescue.subprocess,'run',return_value=result) as run:
                rescue.interactive(session,progress=messages.append)
            boot.assert_called_once_with(session.resolve(),progress=messages.append)
            start.assert_called_once_with(session.resolve())
            connect.assert_called_once_with(session.resolve())
            ram.guard.assert_called_once_with()
            run.assert_called_once_with(ram.prefix)
            stop.assert_called_once_with(tunnel)
            self.assertTrue(any('no internal volume' in message for message in messages))

    def test_ram_ready_reuses_running_rescue_and_existing_tunnel(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)
            (session/'device.json').write_text(json.dumps({'manage_usb_tunnel':True}))
            ram=Mock(prefix=['ssh','root@127.0.0.1'])
            tunnel=Mock()
            with patch.object(rescue,'boot') as boot, \
                 patch.object(rescue,'connect',return_value=ram), \
                 patch('usb_tunnel.start',return_value=tunnel) as start, \
                 patch('usb_tunnel.stop'), \
                 patch.object(rescue.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
                rescue.interactive(session,ram_ready=True)
            boot.assert_not_called()
            start.assert_not_called()

    def test_stops_tunnel_when_connection_fails(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)
            (session/'device.json').write_text(json.dumps({'manage_usb_tunnel':True}))
            tunnel=Mock()
            with patch.object(rescue,'boot'), \
                 patch.object(rescue,'connect',side_effect=RuntimeError('not ready')), \
                 patch('usb_tunnel.start',return_value=tunnel), \
                 patch('usb_tunnel.stop') as stop:
                with self.assertRaisesRegex(RuntimeError,'not ready'):
                    rescue.interactive(session)
            stop.assert_called_once_with(tunnel)


if __name__ == '__main__':
    unittest.main()
