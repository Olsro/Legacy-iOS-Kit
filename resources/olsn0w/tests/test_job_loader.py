"""Check job registration and the precedence of persistent Disabled overrides."""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


class JobRegistration(unittest.TestCase):
    def test_registration_errors_and_persistent_disabled_overrides(self):
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
            empty=Path(work)/'empty.plist';empty.touch()
            malformed=Path(work)/'malformed.plist';malformed.write_bytes(b'broken')
            dictionary=Path(work)/'dictionary.plist';dictionary.write_bytes(b'Dictionary')
            array=Path(work)/'array.plist';array.write_bytes(b'Array')
            for path,optional,expected in (
                    (empty,1,'empty'),(empty,0,'error'),
                    (Path(work)/'missing',1,'empty'),(Path(work)/'missing',0,'error'),
                    (malformed,1,'error'),(malformed,0,'error'),
                    (array,1,'error'),(dictionary,1,'dictionary'),(dictionary,0,'dictionary'),
                    (Path(work),1,'error')):
                with self.subTest(path=path.name,optional=optional):
                    subprocess.run([str(binary),str(path),str(optional),expected],
                                   check=True,timeout=10)
