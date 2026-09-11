import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import usb_tunnel

class TunnelTest(unittest.TestCase):
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
