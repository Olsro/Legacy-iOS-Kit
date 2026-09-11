"""Check registration handling without treating query errors as absent jobs."""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


class JobRegistration(unittest.TestCase):
    def test_registered_absent_and_failed_queries(self):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('A C compiler is required')
        source = Path(__file__).with_name('job_loader_harness.c')
        with tempfile.TemporaryDirectory() as work:
            binary = Path(work)/'registration-test'
            dead_strip = '-Wl,-dead_strip' if platform.system() == 'Darwin' else '-Wl,--gc-sections'
            subprocess.run([compiler, '-Os', '-ffunction-sections', '-fdata-sections',
                            str(source), dead_strip, '-o', str(binary)], check=True,
                           capture_output=True)
            subprocess.run([str(binary)], check=True, timeout=10)
