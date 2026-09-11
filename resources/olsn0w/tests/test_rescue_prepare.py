import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from rescue_prepare import unmount_payload, RC_BOOT, START_SERVICE, ssh_config
from signing import verify

class RescuePreparation(unittest.TestCase):
    def test_helper_matches_source_and_has_valid_signed_pages(self):
        self.assertGreater(verify(unmount_payload())['verified_pages'],0)
    def test_startup_keeps_restore_service_and_avoids_nvram_mutations(self):
        completed=subprocess.run(['sh'],input=RC_BOOT,capture_output=True,timeout=2)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertNotIn(b'restored_external',RC_BOOT)
        self.assertIn(b'exec /usr/local/bin/restored_external_o',START_SERVICE)
        self.assertNotIn(b'nvram',RC_BOOT+START_SERVICE)
        self.assertNotIn(b'mount.sh',RC_BOOT+START_SERVICE)
        self.assertIn(b'PasswordAuthentication no',ssh_config())
        self.assertIn(b'ListenAddress 127.0.0.1',ssh_config())
    def test_unmount_rejects_wrong_boot_and_never_forces(self):
        compiler=shutil.which('cc')
        if not compiler:self.skipTest('Native C compiler unavailable')
        with tempfile.TemporaryDirectory() as work:
            output=Path(work)/'test'
            subprocess.run([compiler,str(Path(__file__).with_name('rescue_unmount_harness.c')),'-o',str(output)],capture_output=True,check=True)
            subprocess.run([str(output)],check=True,timeout=10)
