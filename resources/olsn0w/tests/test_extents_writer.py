"""Exercise the native writer with fragmented files and partial overflow groups."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

class OverflowWriter(unittest.TestCase):
    def test_logical_keys_zero_tail_and_failures(self):
        compiler=shutil.which('cc')
        if not compiler:self.skipTest('requires a C compiler')
        with tempfile.TemporaryDirectory() as work:
            binary=Path(work)/'extents-test'
            subprocess.run([compiler,'-std=c99','-Wall','-Werror',
                str(Path(__file__).with_name('extents_writer_harness.c')),'-o',str(binary)],
                check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,timeout=10)
