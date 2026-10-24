import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import MODELS, profile
from restore import Rescue
from restore_environment import checked_build, report_build, selected_build, session_build
import provision_restore as pipeline
import provision_run


class RestoreEnvironment(unittest.TestCase):
    def test_all_models_and_target_majors(self):
        for product in MODELS:
            for release in ('6.0', '6.0.2', '6.1.2', '6.1.3', '6.1.4',
                            '7.0', '7.1.2', '8.0', '8.1.3', '8.3', '8.4.1'):
                with self.subTest(product=product, release=release):
                    expected=('10B329' if profile(product).get('multipatch') or
                              (profile(product)['soc'].startswith('a5') and release.startswith('6.'))
                              else '12H321')
                    self.assertEqual(selected_build(product, release), expected)
        self.assertFalse(profile('iPod5,1').get('multipatch', False))

    def test_incompatible_or_unknown_environment_rejected(self):
        for product, build in [('iPhone5,2', '10B329'), ('iPad3,4', '10B329'),
                               ('iPhone4,1', '12H321'), ('iPod5,1', 'unknown')]:
            with self.subTest(product=product, build=build), self.assertRaises(ValueError):
                checked_build(product, build)

    def test_space_estimate_includes_native6_donor_for_other_ios6_releases(self):
        import guided
        records={
            'iPod5,1':[dict(version=v,buildid=b,filesize=3000) for v,b in
                       [('6.1.2','10B146'),('6.1.3','10B329'),('8.4.1','12H321')]],
            'iPhone4,1':[dict(version='8.4.1',buildid='12H321',filesize=3000)]}
        with tempfile.TemporaryDirectory() as folder,patch.object(guided,'STATE',Path(folder)):
            early=guided.preparation_space('iPod5,1',records['iPod5,1'][0],records.__getitem__)
            donor=guided.preparation_space('iPod5,1',records['iPod5,1'][1],records.__getitem__)
        # One extra IPSW and its extracted HFS; the same peak scratch is reused.
        self.assertEqual(early-donor,7000)

    def test_native6_is_not_an_ipod_gas_gauge_policy(self):
        report=dict(product='iPod5,1',multipatch=False,restore_environment_build='10B329')
        self.assertEqual(report_build(report),'10B329')
        report['multipatch']=True
        with self.assertRaisesRegex(ValueError,'multipatch'):report_build(report)

    def test_rescue_authenticates_the_selected_build_not_only_the_model(self):
        product='iPod5,1';board,chip,board_id=MODELS[product]
        identity=dict(product=product,board=board,chip=chip,board_id=board_id,ecid=123)
        prefix=['ssh','-o','StrictHostKeyChecking=yes','root@127.0.0.1']
        ram=Rescue(prefix,identity,rescue_build='10B329')
        self.assertEqual(ram.rescue_build,'10B329')
        with patch.object(ram,'run',return_value=b'hw.model: N78AP\nkern.osversion: 12H321\n'):
            with self.assertRaisesRegex(ValueError,'Wrong RAM'):ram.guard()
        self.assertEqual(Rescue(prefix,identity).rescue_build,'12H321')

    def test_ram_guard_accepts_apple_board_revision_case_on_both_environments(self):
        prefix=['ssh','-o','StrictHostKeyChecking=yes','root@127.0.0.1']
        for product,model in (('iPad2,4','K93aAP'),('iPad3,3','J2aAP')):
            board,chip,board_id=MODELS[product]
            identity=dict(product=product,board=board,chip=chip,board_id=board_id)
            for build in ('10B329','12H321'):
                with self.subTest(product=product,build=build):
                    ram=Rescue(prefix,identity,rescue_build=build)
                    state=('hw.model: '+model+'\nkern.osversion: '+build+'\n').encode()
                    with patch.object(ram,'run',side_effect=[state,b'/dev/md0 on / (hfs)\n']) as run:
                        ram.guard()
                    self.assertEqual(run.call_args_list[-1].args,('/sbin/mount',))

    def test_ram_guard_rejects_wrong_board_or_build_with_observed_identity(self):
        prefix=['ssh','-o','StrictHostKeyChecking=yes','root@127.0.0.1']
        board,chip,board_id=MODELS['iPad2,4']
        ram=Rescue(prefix,dict(product='iPad2,4',board=board,chip=chip,board_id=board_id),
                   rescue_build='12H321')
        for state in ('hw.model: K93AP\nkern.osversion: 12H321\n',
                      'hw.model: K93aAP\nkern.osversion: 10B329\n'):
            with self.subTest(state=state),patch.object(ram,'run',return_value=state.encode()) as run:
                with self.assertRaisesRegex(ValueError,'expected hw.model=K93aAP.*received') as error:
                    ram.guard()
                self.assertIn(repr(state),str(error.exception))
                run.assert_called_once()

    def test_session_binding_rejects_other_product(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder)
            (folder/'device.json').write_text(json.dumps(dict(identity=dict(product='iPod5,1'))))
            report=dict(product='iPod5,1',multipatch=False,restore_environment_build='10B329')
            (folder/'rescue-preparation.json').write_text(json.dumps(report))
            self.assertEqual(session_build(folder),'10B329')
            report['product']='iPhone4,1'
            (folder/'rescue-preparation.json').write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError,'another product'):session_build(folder)

    def test_native6_restore_uses_donor_keys_without_enabling_multipatch(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);bundle=root/'provision';bundle.mkdir()
            identity=dict(product='iPod5,1',board='n78ap',chip=0x8942,board_id=0,ecid=123)
            (root/'device.json').write_text(json.dumps(dict(identity=identity)))
            metadata=dict(identifier='iPod5,1',buildid='12H321')
            (root/'keys.json').write_text(json.dumps(metadata))
            (bundle/'futurerestore-keys.json').write_text(json.dumps(metadata))
            report=dict(kind='signed-base-restore-handoff',identity=identity,product='iPod5,1',
                        multipatch=False,restore_environment_build='10B329',
                        asr_source='rebuilt-udif-from-signed-base-hfs',handoff_storage='nvram',
                        asr_patch={'method':'legacy-kit-multipatch-asr'},
                        restore_bootchain_policy='futurerestore-unpatched-rsa',
                        multipatch_component_metadata_build='10B329',rescue_session=str(root),
                        multipatch_restore_component_encoding='encrypted-donor-for-libipatcher',
                        restore_key_policy='signed-base-with-10B329-restore-components',
                        restore_filesystem_build='12H321')
            for rescue_build,loader_error in (('12H321',False),('10B329',False),('10B329',True)):
                with self.subTest(rescue_build=rescue_build,loader_error=loader_error), \
                     patch.object(provision_run,'checked_manifest',return_value=report), \
                     patch.object(provision_run,'session_build',return_value=rescue_build), \
                     patch.object(provision_run,'restore_arguments',return_value=['restore']), \
                     patch.object(provision_run,'check_restore_runtime',
                                  side_effect=RuntimeError('missing library') if loader_error else None) as loader, \
                     patch.object(provision_run,'prepare_dfu',side_effect=RuntimeError('stop before USB')) as dfu:
                    if rescue_build=='12H321':
                        with self.assertRaisesRegex(ValueError,'environments differ'):
                            provision_run.run(root,bundle,root/'ticket',root/'keys.json',erase=True)
                        dfu.assert_not_called()
                        loader.assert_not_called()
                    elif loader_error:
                        with self.assertRaisesRegex(RuntimeError,'missing library'):
                            provision_run.run(root,bundle,root/'ticket',root/'keys.json',erase=True)
                        loader.assert_called_once()
                        dfu.assert_not_called()
                    else:
                        with self.assertRaisesRegex(provision_run.DfuPreparationError,'stop before USB'):
                            provision_run.run(root,bundle,root/'ticket',root/'keys.json',erase=True)
                        dfu.assert_called_once()
                        loader.assert_called_once()
                    self.assertFalse((bundle/'run.json').exists())

    def test_ram_connections_use_the_prepared_environment(self):
        import rescue
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'device.json').write_text(json.dumps(dict(
                identity={'product':'iPod5,1'},rescue_maintenance='/olsn0w-maintenance')))
            (root/'ssh-prefix.json').write_text(json.dumps(['ssh']))
            for module,connect in ((rescue,rescue.connect),(provision_run,provision_run.connect_handoff)):
                ram=Mock();ram.run.return_value=b''
                with self.subTest(module=module.__name__), \
                     patch.object(module,'Rescue',return_value=ram) as factory, \
                     patch('restore_environment.session_build',return_value='10B329'), \
                     patch.object(provision_run,'session_build',return_value='10B329'):
                    self.assertIs(connect(root),ram)
                    self.assertEqual(factory.call_args.kwargs,{'rescue_build':'10B329'})
                    ram.guard.assert_called_once()

    def test_stale_ios8_writer_rejected_before_any_erase(self):
        self.pipeline_case('12H321', expect_failure=True)

    def test_one_provisioned_ram_handles_the_entire_native6_installation(self):
        self.pipeline_case('10B329', expect_failure=False)

    def pipeline_case(self, build, expect_failure):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);bundle=root/'provision';bundle.mkdir()
            identity=dict(product='iPod5,1',board='n78ap',chip=0x8942,board_id=0,ecid=123)
            (root/'device.json').write_text(json.dumps(dict(identity=identity,ram_udid='a'*40)))
            (root/'ssh-prefix.json').write_text(json.dumps(['ssh','-p','2200']))
            reports=[dict(product='iPod5,1',identity=identity,restore_environment_build=build),
                     dict(product='iPod5,1',base_build='12H321'),
                     dict(product='iPod5,1',version='6.1.3',build='10B329')]
            reports.append(dict(reports[-1]))
            target=bundle/'target';ram=Mock(rescue_build=build)
            with patch.object(pipeline,'checked_manifest',side_effect=reports), \
                 patch.object(pipeline,'provision',return_value=ram) as provision, \
                 patch.object(pipeline,'collect') as collect,patch.object(pipeline,'bind'), \
                 patch.object(pipeline,'prepare',side_effect=lambda *args:target.mkdir()), \
                 patch.object(pipeline,'install') as install, \
                 patch.object(pipeline,'target_prefix',return_value=['ssh']), \
                 patch.object(pipeline,'qualify_installed_target',return_value={'ok':True}), \
                 patch.object(pipeline,'cleanup_completed',return_value={'bytes_reclaimed':0}), \
                 patch('rescue.boot') as second_boot,patch('usb_tunnel.stop'):
                args=(root,bundle,root/'bootstrap',root/'system',root/'relay',root/'ticket',root/'keys')
                if expect_failure:
                    with self.assertRaisesRegex(ValueError,'native iOS 6 RAM'):
                        pipeline.run(*args,erase=True,progress=lambda _:None)
                    provision.assert_not_called();collect.assert_not_called();install.assert_not_called()
                    self.assertFalse((bundle/'pipeline.json').exists())
                else:
                    pipeline.run(*args,erase=True,progress=lambda _:None)
                    provision.assert_called_once()
                    self.assertIs(collect.call_args.args[1],ram)
                    install.assert_called_once_with(target,ram,erase=True,progress=unittest.mock.ANY)
                    self.assertEqual(ram.run.call_args_list[-1].args[0],'/sbin/reboot_olsn0w')
                second_boot.assert_not_called()
