import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from restore_run import services_ready, startup_status

class StartupQualification(unittest.TestCase):
    def test_active_data_migration_only_blocks_pre_ios8_boots(self):
        jobs='10 - com.apple.SpringBoard\n- 0 com.saurik.Cydia.Startup\n'
        self.assertFalse(services_ready(jobs+'12 - com.apple.datamigrator\n', '6.1.2'))
        self.assertTrue(services_ready(jobs+'- 0 com.apple.datamigrator\n', '6.1.2'))
        self.assertTrue(services_ready(jobs+'12 - com.apple.datamigrator\n', '8.1.3'))
        self.assertIn('initializing its data', startup_status(jobs+'12 - com.apple.datamigrator\n'))

    def test_springboard_alone_does_not_finish_restore(self):
        jobs='10 - com.apple.SpringBoard\n'
        self.assertFalse(services_ready(jobs,'7.1.2'))
        jobs+='- 0 com.saurik.Cydia.Startup\n'
        self.assertTrue(services_ready(jobs,'6.1.3'))
        self.assertFalse(services_ready(jobs,'7.1.2'))
        jobs+='- 0 com.apple.accountsd\n- 0 com.apple.managedconfiguration.profiled\n'
        self.assertTrue(services_ready(jobs,'7.1.2'))
        self.assertFalse(services_ready(jobs.replace('- 0 com.saurik','17 0 com.saurik'),'7.1.2'))
        self.assertFalse(services_ready(jobs.replace('- 0 com.saurik','- 256 com.saurik'),'7.1.2'))
