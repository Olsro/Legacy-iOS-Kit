"""Check that provisioning failures cannot advance to erase/normal reboot."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import ANY, patch, Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import provision_restore as pipeline


class ProvisionSequence(unittest.TestCase):
    def test_cleanup_requires_success_and_preserves_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            session=Path(tmp)/'session';bundle=session/'provision';bootstrap=session/'bootstrap'
            (bundle/'target').mkdir(parents=True);(bundle/'base8').mkdir();bootstrap.mkdir()
            (bundle/'restore.log').write_text('diagnostic')
            for path in (bundle/'base8.ipsw',bundle/'system.asr.dmg',bundle/'restore-ram.hfs',
                         bundle/'Ramdisk.img3',bundle/'target/system.hfs',bundle/'target/data-native.hfs',
                         bundle/'base8/system.dmg',bootstrap/'bootstrap.cache'):
                path.write_bytes(b'bulk')
            (bundle/'pipeline.json').write_text(json.dumps(dict(stage='normal-boot',complete=False)))
            with self.assertRaisesRegex(ValueError,'qualified completed'):
                pipeline.cleanup_completed(session,bundle,bootstrap)
            self.assertTrue((bundle/'base8.ipsw').exists())
            (bundle/'pipeline.json').write_text(json.dumps(dict(stage='qualified',complete=True)))
            report=pipeline.cleanup_completed(session,bundle,bootstrap)
            self.assertTrue(report['bytes_reclaimed']>0)
            self.assertEqual((bundle/'restore.log').read_text(),'diagnostic')
            self.assertFalse((bundle/'base8.ipsw').exists())
            self.assertFalse((bundle/'target/system.hfs').exists())
            self.assertTrue((session/'cleanup.json').is_file())

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

    def test_authenticated_pwned_ibss_resume_is_forwarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,reports=self.fixture(Path(tmp))
            with patch.object(pipeline,'checked_manifest',side_effect=reports), \
                 patch.object(pipeline,'provision',side_effect=RuntimeError('stop')) as restore:
                with self.assertRaisesRegex(RuntimeError,'stop'):
                    pipeline.run(*args,erase=True,pwned=True)
            self.assertTrue(restore.call_args.kwargs['pwned'])

    def test_failed_partition_collection_records_error_without_installing_or_rebooting(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,reports=self.fixture(Path(tmp));ram=Mock()
            error='RAM command failed: dd (exit code 1)\ndd: Input/output error'
            with patch.object(pipeline,'checked_manifest',side_effect=reports), \
                 patch.object(pipeline,'provision',return_value=ram), \
                 patch.object(pipeline,'collect',side_effect=RuntimeError(error)), \
                 patch.object(pipeline,'bind') as bind, \
                 patch.object(pipeline,'install') as install:
                with self.assertRaisesRegex(RuntimeError,'Input/output error'):
                    pipeline.run(*args,erase=True,progress=lambda _:None)
            bind.assert_not_called();install.assert_not_called();ram.run.assert_not_called()
            state=json.loads((args[1]/'pipeline.json').read_text())
            self.assertEqual(state['stage'],'collecting-signed-artifacts')
            self.assertEqual(state['error'],error)
            self.assertFalse(state['complete'])

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
            with patch.object(pipeline,'checked_manifest',side_effect=reports),patch.object(pipeline,'provision',return_value=ram),patch.object(pipeline,'collect'),patch.object(pipeline,'bind'),patch.object(pipeline,'prepare'),patch.object(pipeline,'install',side_effect=RuntimeError('readback differs')),patch.object(pipeline,'qualify_installed_target') as qualify:
                with self.assertRaisesRegex(RuntimeError,'readback differs'):pipeline.run(*args,erase=True)
                ram.run.assert_not_called();qualify.assert_not_called()
            state=json.loads((args[1]/'pipeline.json').read_text());self.assertFalse(state['complete'])

    def test_menu_pipeline_uses_central_pangu_post_install_qualification(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,reports=self.fixture(Path(tmp));ram=Mock()
            target=args[1]/'target'
            def prepare_target(*unused):target.mkdir(parents=True)
            qualified={'forced_reset_verified':True}
            cleanup={'bytes_reclaimed':0}
            with patch.object(pipeline,'checked_manifest',side_effect=reports), \
                 patch.object(pipeline,'provision',return_value=ram), \
                 patch.object(pipeline,'collect'),patch.object(pipeline,'bind'), \
                 patch.object(pipeline,'prepare',side_effect=prepare_target), \
                 patch.object(pipeline,'install'), \
                 patch.object(pipeline,'target_prefix',return_value=['ssh']) as target_prefix, \
                 patch.object(pipeline,'qualify_installed_target',return_value=qualified) as qualify, \
                 patch.object(pipeline,'cleanup_completed',return_value=cleanup):
                result=pipeline.run(*args,erase=True,progress=lambda _:None)
            self.assertIs(result,qualified)
            target_prefix.assert_called_once_with(target,2200)
            qualify.assert_called_once_with(
                target,['ssh'],'a'*40,'7.1.2',timeout=480,progress=ANY)
            state=json.loads((args[1]/'pipeline.json').read_text())
            self.assertEqual(state['stage'],'qualified')
            self.assertTrue(state['complete'])
