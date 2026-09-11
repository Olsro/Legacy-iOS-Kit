"""Check that provisioning failures cannot advance to erase/normal reboot."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import provision_restore as pipeline


class ProvisionSequence(unittest.TestCase):
    def fixture(self, root):
        session=root/'session';bundle=root/'bundle'
        session.mkdir();bundle.mkdir()
        identity=dict(product='iPhone5,2',ecid=123,board='n42ap',chip=0x8950,board_id=2)
        (session/'device.json').write_text(json.dumps(dict(identity=identity,ram_udid='a'*40)))
        (session/'ssh-prefix.json').write_text(json.dumps(['ssh','-p','2200']))
        reports=[dict(product='iPhone5,2',identity=identity),dict(product='iPhone5,2',base_build='12H321'),
                 dict(product='iPhone5,2',version='7.1.2',build='11D257')]
        args=(session,bundle,root/'bootstrap',root/'system',root/'relay',root/'ticket',root/'keys')
        return args,reports+[reports[-1]]

    def test_corrupt_preparation_stops_before_device_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,reports=self.fixture(Path(tmp))
            with patch.object(pipeline,'checked_manifest',side_effect=ValueError('changed')),patch.object(pipeline,'provision') as restore:
                with self.assertRaisesRegex(ValueError,'changed'):pipeline.run(*args,erase=True)
                restore.assert_not_called()

    def test_failed_base_never_collects_or_installs_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,reports=self.fixture(Path(tmp))
            with patch.object(pipeline,'checked_manifest',side_effect=reports),patch.object(pipeline,'provision',side_effect=RuntimeError('ASR failed')),patch.object(pipeline,'collect') as collect,patch.object(pipeline,'install') as install:
                with self.assertRaisesRegex(RuntimeError,'ASR failed'):pipeline.run(*args,erase=True)
                collect.assert_not_called();install.assert_not_called()
            state=json.loads((args[1]/'pipeline.json').read_text())
            self.assertFalse(state['complete']);self.assertEqual(state['stage'],'signed-base')

    def test_dfu_failure_removes_only_retryable_pipeline_marker(self):
        from provision_run import DfuPreparationError
        with tempfile.TemporaryDirectory() as tmp:
            args,reports=self.fixture(Path(tmp))
            with patch.object(pipeline,'checked_manifest',side_effect=reports), \
                 patch.object(pipeline,'provision',side_effect=DfuPreparationError('checkm8')), \
                 patch.object(pipeline,'collect') as collect,patch.object(pipeline,'install') as install:
                with self.assertRaisesRegex(DfuPreparationError,'checkm8'):
                    pipeline.run(*args,erase=True)
                collect.assert_not_called();install.assert_not_called()
            self.assertFalse((args[1]/'pipeline.json').exists())
            self.assertFalse((args[1]/'run.json').exists())

    def test_unknown_first_boot_recipe_stops_before_signed_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,reports=self.fixture(Path(tmp))
            reports[2]['version']='9.3.5'
            with patch.object(pipeline,'checked_manifest',side_effect=reports),patch.object(pipeline,'provision') as restore:
                with self.assertRaisesRegex(ValueError,'no erase started'):pipeline.run(*args,erase=True)
                restore.assert_not_called()

    def test_no_normal_reboot_when_target_installation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,reports=self.fixture(Path(tmp));ram=Mock()
            with patch.object(pipeline,'checked_manifest',side_effect=reports),patch.object(pipeline,'provision',return_value=ram),patch.object(pipeline,'collect'),patch.object(pipeline,'bind'),patch.object(pipeline,'prepare'),patch.object(pipeline,'install',side_effect=RuntimeError('readback differs')),patch.object(pipeline,'qualify') as qualify:
                with self.assertRaisesRegex(RuntimeError,'readback differs'):pipeline.run(*args,erase=True)
                ram.run.assert_not_called();qualify.assert_not_called()
            state=json.loads((args[1]/'pipeline.json').read_text());self.assertFalse(state['complete'])
