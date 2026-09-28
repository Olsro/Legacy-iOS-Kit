"""Exercise the live socket inode across iOS 5's late temporary-file cleanup."""
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class IOS5LaunchdSocket(unittest.TestCase):
    def test_live_connection_survives_cleanup_and_repeated_boots(self):
        # Short paths fit sockaddr_un on macOS as well as Linux.
        with tempfile.TemporaryDirectory(prefix='l5-', dir='/tmp') as directory:
            base = Path(directory)
            source = (ROOT/'target/ios5-launchd-socket.sh').read_text()
            script = base/'socket.sh'
            script.write_text(source.replace('/private/var', str(base/'var')))
            live = base/'var/tmp/launchd/sock'
            for _ in range(2):
                live.parent.mkdir(parents=True, exist_ok=True)
                with socket.socket(socket.AF_UNIX) as server:
                    server.bind(str(live))
                    server.listen(1)
                    subprocess.run(['/bin/sh', str(script), 'save'], check=True)
                    shutil.rmtree(base/'var/tmp')
                    subprocess.run(['/bin/sh', str(script), 'restore'], check=True)
                    with socket.socket(socket.AF_UNIX) as client:
                        client.connect(str(live))
                        peer, _ = server.accept()
                        with peer:
                            client.sendall(b'launchd')
                            self.assertEqual(peer.recv(7), b'launchd')
                live.unlink()
            self.assertNotEqual(subprocess.run(
                ['/bin/sh', str(script), 'save']).returncode, 0)
            self.assertNotEqual(subprocess.run(
                ['/bin/sh', str(script), 'restore']).returncode, 0)

    def test_dirhelper_retains_native_duties_and_only_restores_at_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            events = base/'events'
            stock = base/'dirhelper.stock'
            stock.write_text('#!/bin/sh\necho "stock:$*" >> '+str(events)+'\nexit 7\n')
            stock.chmod(0o755)
            helper = base/'ios5-launchd-socket.sh'
            helper.write_text('#!/bin/sh\necho "$1" >> '+str(events)+'\n')
            script = base/'dirhelper'
            script.write_text((ROOT/'target/ios5-dirhelper.sh').read_text().replace(
                '/usr/local/libexec/olsn0w', str(base)))
            self.assertEqual(subprocess.run(['/bin/sh',str(script),'-machineBoot']).returncode,7)
            self.assertEqual(events.read_text().splitlines(),['stock:-machineBoot','restore'])
            events.write_text('')
            self.assertEqual(subprocess.run(['/bin/sh',str(script),'-cleanTemporaryItems']).returncode,7)
            self.assertEqual(events.read_text().splitlines(),['stock:-cleanTemporaryItems'])
            stock.unlink()
            events.write_text('')
            self.assertEqual(subprocess.run(['/bin/sh',str(script),'-machineBoot']).returncode,0)
            self.assertEqual(events.read_text().splitlines(),['restore'])
