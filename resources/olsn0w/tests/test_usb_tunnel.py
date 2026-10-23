import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import usb_tunnel

class TunnelTest(unittest.TestCase):
    def setUp(self):
        backend = patch.object(usb_tunnel, 'get_backend', return_value=object())
        self.backend = backend.start().return_value
        self.addCleanup(backend.stop)

    def test_transient_restore_interface_does_not_hide_selected_normal_device(self):
        selected=Mock(idProduct=0x12ab,iSerialNumber=1)
        transient=Mock(idProduct=0x1281,iSerialNumber=2)
        with patch('usb.core.find',return_value=[selected,transient]) as find, \
             patch('usb.util.get_string',side_effect=['A'*40,'CPID:8955 ECID:123']), \
             patch('usb.util.dispose_resources') as dispose:
            self.assertEqual(usb_tunnel.normal_serial(),'a'*40)
            find.assert_called_once_with(find_all=True,idVendor=0x05ac,backend=self.backend)
        self.assertEqual(dispose.call_count,2)

    def test_duplicate_interfaces_for_selected_udid_are_one_target(self):
        devices=[Mock(idProduct=0x12ab,iSerialNumber=1),
                 Mock(idProduct=0x12ab,iSerialNumber=2)]
        with patch('usb.core.find',return_value=devices), \
             patch('usb.util.get_string',side_effect=['A'*40,'a'*40]), \
             patch('usb.util.dispose_resources'):
            self.assertEqual(usb_tunnel.normal_serial(),'a'*40)

    def test_two_distinct_normal_devices_are_still_rejected(self):
        devices=[Mock(idProduct=0x12ab,iSerialNumber=1),
                 Mock(idProduct=0x12ab,iSerialNumber=2)]
        with patch('usb.core.find',return_value=devices), \
             patch('usb.util.get_string',side_effect=['a'*40,'b'*40]), \
             patch('usb.util.dispose_resources'), \
             self.assertRaisesRegex(ValueError,'only the selected'):
            usb_tunnel.normal_serial()

    def test_wrong_returning_device_never_starts_proxy(self):
        with tempfile.TemporaryDirectory() as folder:
            session=Path(folder);(session/'device.json').write_text(json.dumps({'ram_udid':'a'*40}))
            with patch.object(usb_tunnel,'normal_serial',return_value='b'*40),patch.object(usb_tunnel.subprocess,'Popen') as spawn:
                with self.assertRaisesRegex(ValueError,'identity changed'):usb_tunnel.start(session)
                spawn.assert_not_called()

    def test_dfu_only_session_records_discovered_serial_and_scopes_tunnel(self):
        with tempfile.TemporaryDirectory() as folder:
            session=Path(folder);(session/'device.json').write_text('{}')
            (session/'ssh-prefix.json').write_text(json.dumps(['ssh','-p','6414']))
            process=Mock();process.poll.return_value=None
            with patch.object(usb_tunnel,'normal_serial',return_value='b'*40),patch.object(usb_tunnel,'tool',return_value=Path('/tools/iproxy')),patch.object(usb_tunnel.socket,'socket') as socket,patch.object(usb_tunnel.subprocess,'Popen',return_value=process) as spawn,patch.object(usb_tunnel.time,'sleep'):
                socket.return_value.__enter__.return_value.connect_ex.return_value=1
                self.assertIs(usb_tunnel.start(session),process)
                self.assertEqual(json.loads((session/'device.json').read_text())['ram_udid'],'b'*40)
                self.assertEqual(spawn.call_args.args[0],['/tools/iproxy','-u','b'*40,'-s','127.0.0.1','6414:22'])
                usb_tunnel.stop(process);process.terminate.assert_called_once()
