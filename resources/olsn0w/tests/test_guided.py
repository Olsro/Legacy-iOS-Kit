import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import guided

IDENTITY=dict(product='iPhone5,2',ecid=123,board='n42ap',chip=0x8950,board_id=2,mode='Normal')
RECOVERY=dict(IDENTITY,mode='Recovery')
RELEASE=dict(version='7.1.2',buildid='11D257')
IOS8_RELEASE=dict(version='8.4.1',buildid='12H321')

class GuidedTest(unittest.TestCase):
    def test_selected_recovery_can_be_rearmed_without_preparation_or_erase(self):
        calls=[]
        with patch.object(guided,'query_recovery',return_value=RECOVERY):
            result=guided.exit_selected_recovery(
                RECOVERY,command=lambda argv,**kwargs:calls.append((argv,kwargs)))
        self.assertEqual([call[0][-1] for call in calls],[
            'setenv auto-boot true','saveenv','reboot'])
        self.assertTrue(all(call[1]=={'timeout':15} for call in calls))
        self.assertTrue(result['recovery_repaired'])
        self.assertFalse(result['device_erased'])

    def test_recovery_menu_repair_skips_release_lookup_and_preparation(self):
        repaired={'recovery_repaired':True}
        with patch.object(guided,'connected',return_value=(RECOVERY,None)), \
             patch.object(guided,'exit_selected_recovery',return_value=repaired) as repair, \
             patch.object(guided,'releases') as releases, \
             patch.object(guided,'prepare') as prepare:
            result=guided.menu('iPhone5,2','123',read=lambda _:'y',show=lambda _:None)
        self.assertIs(result,repaired)
        repair.assert_called_once_with(RECOVERY)
        releases.assert_not_called()
        prepare.assert_not_called()

    def test_recovery_menu_can_continue_to_restore_selection(self):
        with patch.object(guided,'connected',return_value=(RECOVERY,None)), \
             patch.object(guided,'releases',return_value=[RELEASE]), \
             patch.object(guided,'prepare') as prepare:
            answers=iter(['n','0'])
            guided.menu('iPhone5,2','123',read=lambda _:next(answers),show=lambda _:None)
        prepare.assert_not_called()

    def test_outdated_reproducible_recipe_is_rebuilt_automatically(self):
        with tempfile.TemporaryDirectory() as folder:
            cached=Path(folder)/'relay';cached.mkdir();(cached/'old').write_bytes(b'x')
            self.assertFalse(guided.reusable_recipe(
                cached,10,lambda _:dict(recipe_version=9)))
            self.assertFalse(cached.exists())
            cached.mkdir();(cached/'current').write_bytes(b'x')
            self.assertTrue(guided.reusable_recipe(
                cached,10,lambda _:dict(recipe_version=10)))
            self.assertTrue((cached/'current').is_file())

    def test_system_cache_is_bound_to_the_exact_relay_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            cached=Path(folder)/'system';cached.mkdir();(cached/'image').write_bytes(b'x')
            report=dict(recipe_version=24, relay_recipe_version=15,
                        relay_devicetree_sha256='old-tree', relay_binary_sha256='relay')
            required=dict(relay_recipe_version=15,
                          relay_devicetree_sha256='new-tree', relay_binary_sha256='relay')
            self.assertFalse(guided.reusable_recipe(cached,24,lambda _:report,required))
            self.assertFalse(cached.exists())

    def test_disk_estimate_shrinks_when_firmware_and_system_are_cached(self):
        records={
            'iPad3,4':[dict(version='8.3',buildid='12F69',filesize=1800),
                       dict(version='8.4.1',buildid='12H321',filesize=1900)],
            'iPhone5,2':[dict(version='8.4.1',buildid='12H321',filesize=1700)],
        }
        selected=records['iPad3,4'][0]
        with tempfile.TemporaryDirectory() as folder,patch.object(guided,'STATE',Path(folder)):
            cold=guided.preparation_space('iPad3,4',selected,records.__getitem__)
            for product,build in [('iPad3,4','12F69'),('iPad3,4','12H321'),('iPhone5,2','12H321')]:
                firmware=Path(folder)/'targets'/product/build/'firmware';firmware.mkdir(parents=True)
                (firmware/'manifest.json').write_text('{}')
            system=Path(folder)/'targets/iPad3,4/12F69/system';system.mkdir(parents=True)
            (system/'manifest.json').write_text('{}')
            for product,record in [('iPad3,4',records['iPad3,4'][0]),('iPad3,4',records['iPad3,4'][1]),
                                   ('iPhone5,2',records['iPhone5,2'][0])]:
                ipsw=Path(folder)/'ipsw'/(product+'_'+record['version']+'_'+record['buildid']+'_Restore.ipsw')
                ipsw.parent.mkdir(exist_ok=True);ipsw.touch()
            warm=guided.preparation_space('iPad3,4',selected,records.__getitem__)
        self.assertGreater(cold,warm);self.assertEqual(warm,guided.SESSION_WORKSPACE)

    def test_selected_phone_base_is_the_qualified_cache_source(self):
        base=Path('/qualified-phone-base')
        extract=lambda *args,**kwargs:self.fail('qualified source should be reused')
        self.assertEqual(guided.bootstrap_cache_firmware('iPhone5,2',base,extract),base)

    def test_iphone4s_uses_its_own_armv7_cache(self):
        base=Path('/qualified-4s-base')
        extract=lambda *args,**kwargs:self.fail('4S cache donor must not be ARMv7s')
        self.assertEqual(guided.bootstrap_cache_firmware('iPhone4,1',base,extract),base)

    def test_ipad_uses_the_physically_qualified_shared_cache_source(self):
        donor=Path('/qualified-phone-donor')
        extract_calls=[];messages=[]
        def extract(*args,**kwargs):
            extract_calls.append((args,kwargs));return donor,dict(product='iPhone5,2')
        self.assertEqual(guided.bootstrap_cache_firmware('iPad3,4',Path('/ipad-base'),extract,messages.append),donor)
        self.assertEqual(extract_calls,[(('iPhone5,2','8.4.1'),{'build':'12H321'})])
        self.assertTrue(any('iPad boot components remain model-specific' in line for line in messages))

    def test_unimplemented_release_never_selected(self):
        answers=iter(['1','2'])
        selected=guided.choose([dict(version='9.3.5',buildid='13G36'),RELEASE],lambda _:next(answers),lambda _:None)
        self.assertEqual(selected,RELEASE)

    def test_direct_version_entry(self):
        self.assertEqual(guided.choose([RELEASE],lambda _:'7.1.2',lambda _:None),RELEASE)

    def test_ios8_release_is_selectable(self):
        self.assertEqual(guided.choose([IOS8_RELEASE],lambda _:'1',lambda _:None),IOS8_RELEASE)

    def test_every_ios7_and_ios8_point_release_is_supported_by_major(self):
        releases=('7.0', '7.0.2', '7.0.3', '7.0.4', '7.0.6',
                  '7.1', '7.1.1', '7.1.2',
                  '8.0', '8.0.1', '8.0.2', '8.1', '8.1.1', '8.1.2',
                  '8.1.3', '8.2', '8.3', '8.4', '8.4.1')
        for release in releases:
            self.assertIsNone(guided.support_reason(release), release)

    def test_back_does_not_prepare(self):
        with patch.object(guided,'connected',return_value=(IDENTITY,None)),patch.object(guided,'releases',return_value=[RELEASE]),patch.object(guided,'prepare') as prepare:
            guided.menu('iPhone5,2','123',read=lambda _:'0',show=lambda _:None)
            prepare.assert_not_called()

    def test_prepare_before_confirmation_cancel_before_dfu(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(guided,'STATE',Path(folder)),patch.object(guided,'connected',return_value=(IDENTITY,None)),patch.object(guided,'releases',return_value=[RELEASE]),patch.object(guided,'enter_dfu') as dfu,patch.object(guided,'prepare',return_value={}) as prepare:
            answers=iter(['1','n'])
            def read(_):
                answer=next(answers)
                if answer=='n':prepare.assert_called_once()
                return answer
            guided.menu('iPhone5,2','123',read=read,show=lambda _:None)
            dfu.assert_not_called()

    def test_one_guided_entry_runs_complete_pipeline(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(guided,'STATE',Path(folder)),patch.object(guided,'connected',return_value=(IDENTITY,None)),patch.object(guided,'releases',return_value=[RELEASE]),patch.object(guided,'enter_dfu') as dfu,patch.object(guided,'prepare',return_value={'session':'prepared'}) as prepare,patch('provision_restore.run',return_value={'success':True}) as restore:
            answers=iter(['1','y'])
            result=guided.menu('iPhone5,2','123',read=lambda _:next(answers),show=lambda _:None)
            self.assertEqual(result,{'success':True});dfu.assert_called_once();restore.assert_called_once()
            self.assertTrue(restore.call_args.kwargs['erase'])
            self.assertEqual(restore.call_args.kwargs['session'],'prepared')

    def test_retryable_dfu_failure_reuses_prepared_plan(self):
        from provision_run import DfuPreparationError
        with tempfile.TemporaryDirectory() as folder,patch.object(guided,'STATE',Path(folder)),patch.object(guided,'connected',return_value=(IDENTITY,None)),patch.object(guided,'releases',return_value=[RELEASE]),patch.object(guided,'enter_dfu') as dfu,patch.object(guided,'prepare',return_value={'session':'prepared'}) as prepare,patch('provision_restore.run',side_effect=[DfuPreparationError('checkm8'),{'success':True}]) as restore:
            answers=iter(['1','y'])
            result=guided.menu('iPhone5,2','123',read=lambda _:next(answers),show=lambda _:None)
            self.assertEqual(result,{'success':True})
            prepare.assert_called_once()
            self.assertEqual(dfu.call_count,2)
            self.assertEqual(restore.call_count,2)

    def test_preparation_failure_never_requests_dfu_or_erase(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(guided,'STATE',Path(folder)),patch.object(guided,'connected',return_value=(IDENTITY,None)),patch.object(guided,'releases',return_value=[RELEASE]),patch.object(guided,'enter_dfu') as dfu,patch.object(guided,'prepare',side_effect=RuntimeError('checksum')):
            with self.assertRaisesRegex(RuntimeError,'checksum'):guided.menu('iPhone5,2','123',read=lambda _:'1',show=lambda _:None)
            dfu.assert_not_called()

    def test_wrong_dfu_identity_rejected(self):
        with patch.object(guided,'query_recovery',return_value=dict(IDENTITY,ecid=456,mode='DFU')):
            with self.assertRaisesRegex(ValueError,'differs'):guided.enter_dfu(IDENTITY,show=lambda _:None)

    def test_already_dfu_requires_no_manual_action(self):
        with patch.object(guided,'query_recovery',return_value=dict(IDENTITY,mode='DFU')):
            guided.enter_dfu(IDENTITY,read=lambda _:self.fail('DFU asked twice'))

    def test_manual_dfu_detection_can_retry_without_returning(self):
        states=[dict(IDENTITY,mode='Normal'),dict(IDENTITY,mode='Normal'),
                dict(IDENTITY,mode='Normal'),dict(IDENTITY,mode='DFU')]
        prompts=[];messages=[]
        with patch.object(guided,'query_recovery',side_effect=states), \
             patch.object(guided.time,'monotonic',side_effect=[0,31,40]):
            guided.enter_dfu(IDENTITY,read=lambda prompt:prompts.append(prompt),show=messages.append)
        self.assertEqual(len(prompts),2)
        self.assertTrue(any('try again with the same prepared files' in line for line in messages))
