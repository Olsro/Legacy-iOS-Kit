"""The restore log receives stdout while the tool runs, in stream order."""
from pathlib import Path
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from provision_run import start_logged


# stdout first without an explicit flush, then stderr: with a regular file as
# stdout, the stdout line would reach the log only at exit, after stderr.
CHILD = ("import sys,time\n"
         "print('Sending iBEC (276760 bytes)...')\n"
         "sys.stderr.write('ERROR: Unable to connect to device in restore mode\\n')\n"
         "print('Waiting for device...')\n"
         "time.sleep(30)\n")


class RestoreLogStream(unittest.TestCase):
    def test_stdout_reaches_log_before_exit_in_order(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work)/'restore.log'
            env = dict(os.environ)
            env.pop('PYTHONUNBUFFERED', None)
            with path.open('wb') as log:
                process, finish = start_logged([sys.executable, '-c', CHILD], work, env, log)
                try:
                    deadline = time.monotonic()+10
                    while (b'Waiting for device...' not in path.read_bytes()
                           and time.monotonic() < deadline):
                        time.sleep(0.05)
                    self.assertIsNone(process.poll())
                finally:
                    process.kill();process.wait();finish()
            self.assertEqual(path.read_bytes(),
                             b'Sending iBEC (276760 bytes)...\n'
                             b'ERROR: Unable to connect to device in restore mode\n'
                             b'Waiting for device...\n')

    def test_output_is_complete_after_finish(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work)/'restore.log'
            with path.open('wb') as log:
                process, finish = start_logged(
                    [sys.executable, '-c', "print('x'*200000);print('DONE')"], work, dict(os.environ), log)
                self.assertEqual(process.wait(timeout=30), 0)
                finish()
            lines = path.read_bytes().splitlines()
            self.assertEqual(lines, [b'x'*200000, b'DONE'])


if __name__ == '__main__':
    unittest.main()
