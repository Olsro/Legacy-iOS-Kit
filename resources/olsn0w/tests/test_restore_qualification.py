import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from restore_run import (boot_success_ready, cydia_initialization_ready, cydia_needs_start,
                         pangu_needs_writable_root,
                         pangu_writable_root_ready, services_ready,
                         startup_failure, startup_status)

class StartupQualification(unittest.TestCase):
    def test_boot_success_is_generation_bound_and_required_by_production_gate(self):
        jobs=('BOOT_SUCCESS:selected\n10 0 com.apple.SpringBoard\n'
              '- 0 com.saurik.Cydia.Startup\n')
        self.assertTrue(boot_success_ready(jobs,'selected'))
        self.assertFalse(boot_success_ready(jobs,'another'))
        self.assertTrue(services_ready(jobs,'8.1.3',True,'selected'))
        self.assertFalse(services_ready(jobs,'8.1.3',True,'another'))

    def test_pangu_completion_requires_marker_and_writable_selected_root(self):
        report={'layout':{'partitions':[
            {'role':'system','device':'/dev/disk0s1s3'},
            {'role':'data','device':'/dev/disk0s1s2'}]}}
        lines=['N42AP','11D257','selected','CYDIA_READY:selected',
               'UNTETHER_READY:ready',
               '/dev/disk0s1s3 on / (hfs, local, journaled)']
        self.assertTrue(pangu_writable_root_ready(lines,report))
        self.assertFalse(pangu_writable_root_ready(
            [*lines[:5],lines[5].replace('journaled','read-only, journaled')],report))
        self.assertFalse(pangu_writable_root_ready(
            [*lines[:4],'UNTETHER_READY:',lines[5]],report))
        self.assertTrue(pangu_needs_writable_root('7.1.2'))
        self.assertFalse(pangu_needs_writable_root('7.0.6'))
        self.assertFalse(pangu_needs_writable_root('8.4.1'))

    def test_active_data_migration_only_blocks_pre_ios8_boots(self):
        jobs='10 - com.apple.SpringBoard\n- 0 com.saurik.Cydia.Startup\n'
        self.assertFalse(services_ready(jobs+'12 - com.apple.datamigrator\n', '6.1.2', True))
        self.assertTrue(services_ready(jobs+'- 0 com.apple.datamigrator\n', '6.1.2', True))
        self.assertTrue(services_ready(jobs+'12 - com.apple.datamigrator\n', '8.1.3', True))
        self.assertIn('initializing its data', startup_status(
            jobs+'12 - com.apple.datamigrator\n', True))

    def test_springboard_alone_does_not_finish_restore(self):
        jobs='10 - com.apple.SpringBoard\n'
        self.assertFalse(services_ready(jobs,'7.1.2',True))
        jobs+='- 0 com.saurik.Cydia.Startup\n'
        self.assertFalse(services_ready(jobs,'6.1.3',False))
        self.assertTrue(services_ready(jobs,'6.1.3',True))
        self.assertFalse(services_ready(jobs,'7.1.2',True))
        jobs+='- 0 com.apple.accountsd\n- 0 com.apple.managedconfiguration.profiled\n'
        self.assertTrue(services_ready(jobs,'7.1.2',True))
        self.assertFalse(services_ready(jobs.replace('- 0 com.saurik','17 0 com.saurik'),'7.1.2',True))
        self.assertFalse(services_ready(jobs.replace('- 0 com.saurik','- 256 com.saurik'),'7.1.2',True))

    def test_cydia_completion_is_bound_to_the_selected_data_generation(self):
        lines=['N42AP','11D257','selected','CYDIA_READY:selected']
        self.assertTrue(cydia_initialization_ready(lines,'selected'))
        self.assertFalse(cydia_initialization_ready(lines,'another'))
        self.assertFalse(cydia_initialization_ready(lines[:3],'selected'))
        jobs='10 - com.apple.SpringBoard\n- 0 com.saurik.Cydia.Startup\n'
        self.assertTrue(cydia_needs_start(jobs,False))
        self.assertFalse(cydia_needs_start(jobs,True))
        self.assertFalse(cydia_needs_start(jobs.replace('- 0 com.saurik','17 0 com.saurik'),False))
        self.assertTrue(cydia_needs_start(jobs.replace('- 0 com.saurik','- 1 com.saurik'),False))

    def test_failed_cydia_attempt_has_an_actionable_diagnostic(self):
        jobs='10 - com.apple.SpringBoard\n- 1 com.saurik.Cydia.Startup\n'
        self.assertIn('status 1',startup_failure(jobs))
        self.assertIn('olsn0w-cydia.log',startup_failure(jobs))
        self.assertIsNone(startup_failure(jobs.replace('- 1','17 0')))
        self.assertIsNone(startup_failure(jobs.replace('- 1','- 0')))
