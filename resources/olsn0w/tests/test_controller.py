import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('cc'), 'Native C compiler unavailable')
class ControllerTests(unittest.TestCase):
    def test_power_cut_state_does_not_consume_enablement(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=pathlib.Path(folder)
            (folder/'olsn0w_config.h').write_text('#define OLSN0W_BOARD "TESTAP"\n#define OLSN0W_ROOT_MARKER "olsn0w-bootstrap-v1"\n#define OLSN0W_TARGET_MARKER "olsn0w-target-v1"\n')
            subprocess.run(['cc','-std=gnu11','-fno-builtin','-I'+str(folder),'-I'+str(ROOT/'native/bootstrap'),
                str(ROOT/'tests/controller_harness.c'),'-o',str(folder/'test')],check=True,capture_output=True)
            result=subprocess.run([folder/'test'],check=True,capture_output=True,text=True)
            self.assertIn('identity guards passed',result.stdout)
