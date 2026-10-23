"""Reuse completed preparation across launches without retrying a started erase."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import prepared_session
from common import digest
from bootchain import RECIPE_VERSION as RELAY_RECIPE
from system import RECIPE_VERSION as SYSTEM_RECIPE
from rescue_prepare import RECIPE_VERSION as RESCUE_RECIPE

IDENTITY = dict(product='iPad3,1', board='j1ap', chip=0x8945, board_id=0, ecid=123, mode='DFU')
RELEASE = dict(version='5.1.1', buildid='9B206')


class PreparedSession(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name).resolve()
        self.session = self.state/'sessions'/'ready'
        target = self.state/'targets/iPad3,1/9B206'
        self.plan = dict(session=self.session, bundle=self.session/'provision', bootstrap=self.session/'bootstrap',
                         system=target/'system', relay=target/'relay', ticket=self.session/'ticket.shsh',
                         keys=self.session/'base-keys.json', baseband=None, baseband_manifest=None)
        self.session.mkdir(parents=True)
        for key in ('ticket', 'keys'):
            self.plan[key].write_bytes(b'fixture')
        self.write(self.session/'device.json', dict(identity=IDENTITY, device_modified=False, remove_setup_app=False))
        relay = self.manifest(self.plan['relay'], dict(product='iPad3,1', version='5.1.1', build='9B206',
                              recipe_version=RELAY_RECIPE), ['relay.bin', 'devicetree'])
        self.manifest(self.plan['system'], dict(product='iPad3,1', version='5.1.1', build='9B206',
                      recipe_version=SYSTEM_RECIPE, setup_customized=False, relay_recipe_version=RELAY_RECIPE,
                      relay_devicetree_sha256=relay['files']['devicetree'], relay_binary_sha256=relay['files']['relay.bin']), ['system.hfs'])
        self.manifest(self.plan['bootstrap'], dict(product='iPad3,1', base_build='12H321',
                      autoboot_policy='persistent-enable', launchd_policy='stock-signed', target_rearm_required=False), ['root8.hfs'])
        self.manifest(self.plan['bundle'], dict(product='iPad3,1', identity=IDENTITY,
                      kind='signed-base-restore-handoff', rescue_session=str(self.session)), ['base8.ipsw'])
        self.manifest(self.session, dict(product='iPad3,1', recipe_version=RESCUE_RECIPE,
                      automatic_disk_mounts=False, ram_root='md0', restore_environment_build='10B329'),
                      ['Ramdisk.img3'], name='rescue-preparation.json')
        self.path = self.session/'guided-plan.json'
        self.write(self.path, {key:str(value) if value is not None else None for key,value in self.plan.items()})
        ticket = patch('provision_run.restore_arguments')
        self.ticket = ticket.start()
        self.addCleanup(ticket.stop)

    def write(self, path, value):
        path.write_text(json.dumps(value))

    def manifest(self, folder, report, names, name='manifest.json'):
        folder.mkdir(parents=True, exist_ok=True)
        for filename in names:
            (folder/filename).write_bytes(filename.encode())
        report['files'] = {filename:digest(folder/filename) for filename in names}
        self.write(folder/name, report)
        return report

    def find(self, identity=IDENTITY, release=RELEASE, policy=False):
        return prepared_session.find_plan(identity, release, policy, lambda _:None, state=self.state)

    def test_complete_preparation_is_reused_and_ticket_is_rechecked(self):
        self.assertEqual(self.find(), self.plan)
        self.ticket.assert_called_once_with(IDENTITY, self.plan['bundle']/'base8.ipsw',
                                            self.plan['ticket'], None, None)

    def test_no_backend_failure_before_erase_keeps_files_and_archives_only_marker(self):
        journal = self.plan['bundle']/'pipeline.json'
        failure = dict(stage='signed-base', complete=False, error='No backend available')
        self.write(journal, failure)
        self.assertEqual(self.find(), self.plan)
        self.assertFalse(journal.exists())
        self.assertEqual(json.loads((journal.parent/'pipeline-before-retry.json').read_text()), failure)
        self.assertTrue((journal.parent/'base8.ipsw').exists())

    def test_started_or_completed_restore_is_never_retried(self):
        bundle = self.plan['bundle']
        for name in ('run.json', 'work', 'target', 'restore.log'):
            with self.subTest(marker=name):
                (bundle/name).touch()
                self.assertIsNone(self.find())
                (bundle/name).unlink()
        for stage in ('normal-boot', 'qualified', 'installing-target'):
            self.write(bundle/'pipeline.json', dict(stage=stage, complete=False))
            self.assertIsNone(self.find())
        self.ticket.assert_not_called()

    def test_other_device_build_or_activation_policy_is_not_reused(self):
        self.assertIsNone(self.find(identity=dict(IDENTITY, ecid=456)))
        self.assertIsNone(self.find(release=dict(version='6.1.3', buildid='10B329')))
        self.assertIsNone(self.find(policy=True))
        self.ticket.assert_not_called()

    def test_changed_prepared_file_or_old_recipe_is_not_reused(self):
        image = self.plan['system']/'system.hfs'
        original = image.read_bytes()
        image.write_bytes(b'corruption')
        self.assertIsNone(self.find())
        image.write_bytes(original)
        manifest = self.plan['system']/'manifest.json'
        report = json.loads(manifest.read_text())
        report['recipe_version'] -= 1
        self.write(manifest, report)
        self.assertIsNone(self.find())
        self.ticket.assert_not_called()

    def test_changed_rescue_file_or_path_outside_state_is_not_reused(self):
        ramdisk = self.session/'Ramdisk.img3'
        original = ramdisk.read_bytes()
        ramdisk.write_bytes(b'corruption')
        self.assertIsNone(self.find())
        ramdisk.write_bytes(original)
        raw = json.loads(self.path.read_text())
        raw['keys'] = '/tmp/unrelated-keys.json'
        self.write(self.path, raw)
        self.assertIsNone(self.find())
        self.ticket.assert_not_called()

    def test_invalid_ticket_does_not_clear_pre_erase_error_marker(self):
        self.write(self.plan['bundle']/'pipeline.json', dict(stage='signed-base', complete=False))
        self.ticket.side_effect = ValueError('ticket belongs to another ECID')
        self.assertIsNone(self.find())
        self.assertTrue((self.plan['bundle']/'pipeline.json').exists())
