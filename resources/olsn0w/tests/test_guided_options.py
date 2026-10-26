"""Local firmware selection and boot policy propagation before device changes."""
import json
from pathlib import Path
import plistlib
import shlex
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import firmware
import guided
from common import MODELS, digest, save, target_paths

PRODUCT='iPhone5,2'
RELEASE=dict(version='7.1.2',buildid='11D257',filesize=1000)


class LocalFirmware(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)

    def archive(self, product=PRODUCT, build='11D257', chip=None):
        board,apchip,board_id=MODELS[product]
        path=self.root/'downloaded firmware.ipsw'
        manifest=dict(ProductVersion='7.1.2',ProductBuildVersion=build,
                      SupportedProductTypes=[product],BuildIdentities=[dict(
                          ApChipID=hex(apchip if chip is None else chip),ApBoardID=hex(board_id),
                          Info=dict(DeviceClass=board,RestoreBehavior='Erase'))])
        with zipfile.ZipFile(path,'w') as archive:
            archive.writestr('BuildManifest.plist',plistlib.dumps(manifest))
        record=dict(RELEASE,sha1sum=digest(path,'sha1'))
        return path,record

    def test_local_archive_is_verified_without_network_or_keys(self):
        path,record=self.archive()
        with patch.object(firmware,'fetch') as fetch:
            actual,manifest,_=firmware.verify_ipsw(path,PRODUCT,record)
        self.assertEqual(actual,path.resolve())
        self.assertEqual(manifest['ProductBuildVersion'],'11D257')
        fetch.assert_not_called()

    def test_wrong_product_build_chip_checksum_and_non_zip_are_rejected(self):
        for kwargs,reason in ((dict(product='iPhone5,1'),'product'),
                              (dict(build='11D201'),'build'),
                              (dict(chip=0x8940),'chip')):
            with self.subTest(kwargs=kwargs):
                path,record=self.archive(**kwargs)
                with self.assertRaisesRegex(ValueError,reason):
                    firmware.verify_ipsw(path,PRODUCT,record)
        path,record=self.archive()
        with self.assertRaisesRegex(ValueError,'checksum'):
            firmware.verify_ipsw(path,PRODUCT,dict(record,sha1sum='0'*40))
        path.write_bytes(b'not a zip')
        with self.assertRaisesRegex(ValueError,'Invalid IPSW'):
            firmware.verify_ipsw(path,PRODUCT,record)
        with zipfile.ZipFile(path,'w') as archive:
            archive.writestr('BuildManifest.plist',b'<?xml version="1.0"?><plist><dict>')
        with self.assertRaisesRegex(ValueError,'Invalid IPSW'):
            firmware.verify_ipsw(path,PRODUCT,record)

    def test_prompt_accepts_literal_quoted_and_dragged_paths_and_retries(self):
        for encode in (str,shlex.quote,lambda p:str(p).replace(' ','\\ ')):
            with self.subTest(encode=encode):
                path,record=self.archive()
                answers=iter(['/missing.ipsw',encode(str(path)),''])
                messages=[]
                with patch.object(firmware,'fetch') as fetch:
                    result=guided.choose_ipsws(PRODUCT,record,lambda _:next(answers),messages.append)
                self.assertEqual(result,{PRODUCT+'/11D257':str(path.resolve())})
                self.assertTrue(any('Cannot use this IPSW' in line for line in messages))
                fetch.assert_not_called()

    def test_empty_input_keeps_automatic_acquisition_without_looking_up_catalogs(self):
        prompts=[]
        with patch.object(guided,'releases') as releases:
            self.assertEqual(guided.choose_ipsws(PRODUCT,RELEASE,
                lambda prompt:prompts.append(prompt) or '',lambda _:None),{})
        releases.assert_not_called()
        self.assertEqual(len(prompts),2)

    def test_dependencies_are_deduplicated_and_include_auxiliary_donors(self):
        self.assertEqual(guided.firmware_requests(PRODUCT,dict(version='8.4.1',buildid='12H321')),
                         [(PRODUCT,'8.4.1','12H321')])
        requests=guided.firmware_requests('iPad2,5',dict(version='6.1.2',buildid='10B146'))
        self.assertEqual(requests,[('iPad2,5','6.1.2','10B146'),('iPad2,5','8.4.1','12H321'),
                                   ('iPhone4,1','8.4.1','12H321'),('iPad2,5','6.1.3','10B329')])

    def test_local_archives_reduce_download_space_but_not_extraction_space(self):
        records=[RELEASE,dict(version='8.4.1',buildid='12H321',filesize=2000)]
        with patch.object(guided,'STATE',self.root):
            cold=guided.preparation_space(PRODUCT,RELEASE,lambda _:records)
            local=guided.preparation_space(PRODUCT,RELEASE,lambda _:records,
                ipsws={PRODUCT+'/11D257':'/local/target',PRODUCT+'/12H321':'/local/base'})
        self.assertEqual(cold-local,3000)


class GuidedBootOptions(unittest.TestCase):
    def test_system_builder_uses_the_boot_and_activation_cache_selected_by_the_relay(self):
        import system
        from bootchain import target_bootargs
        for verbose in (False,True):
            for hacktiv8 in (False,True):
                with self.subTest(verbose=verbose,hacktiv8=hacktiv8),tempfile.TemporaryDirectory() as folder:
                    root=Path(folder);source=dict(product=PRODUCT,version='7.1.2',build='11D257',files={})
                    firmware_path=root/'firmware';firmware_path.mkdir()
                    relay,destination=target_paths(root,verbose=verbose,remove_setup_app=hacktiv8)
                    relay.mkdir();destination.mkdir()
                    save(firmware_path/'manifest.json',source)
                    save(relay/'manifest.json',dict(source,bootargs=target_bootargs(verbose=verbose)))
                    version=plistlib.dumps(dict(ProductVersion='7.1.2',ProductBuildVersion='11D257'))
                    with patch.object(system,'HFS') as hfs, \
                         patch.object(system,'jailbreak_payload',return_value=({},[])), \
                         patch.object(system,'wraps_early_keybag',return_value=False), \
                         patch.object(system,'preflight_hacktiv8'):
                        hfs.return_value.read.return_value=version
                        with self.assertRaisesRegex(ValueError,'already exists') as error:
                            system.prepare(firmware_path,relay,remove_setup_app=hacktiv8)
                    self.assertIn(str(destination),str(error.exception))

    def test_native6_rescue_uses_the_selected_local_ram_archive(self):
        import rescue_prepare
        class SelectedRam(Exception):pass
        board,chip,board_id=MODELS['iPad2,5']
        with tempfile.TemporaryDirectory() as folder:
            session=Path(folder)
            save(session/'device.json',dict(identity=dict(product='iPad2,5',board=board,chip=chip,board_id=board_id)))
            with patch.object(rescue_prepare,'acquire',side_effect=[(Path('/base'),{},None,None),SelectedRam]) as acquire, \
                 patch.object(rescue_prepare,'extract',return_value=(Path('/base-firmware'),{})):
                with self.assertRaises(SelectedRam):
                    rescue_prepare.prepare(session,environment_build='10B329',ram_ipsw=Path('/local/ram.ipsw'))
            self.assertEqual(acquire.call_args.args,('iPad2,5','6.1.3',Path('/local/ram.ipsw')))
            self.assertEqual(acquire.call_args.kwargs,{'build':'10B329'})

    def test_cli_verbose_is_opt_in_and_reaches_the_relay_builder(self):
        import olsn0w
        class Selected(Exception):pass
        for flags,verbose in (([],False),(['--verbose-boot'],True)):
            with self.subTest(flags=flags),tempfile.TemporaryDirectory() as folder, \
                 patch.object(sys,'argv',['olsn0w','prepare','--product',PRODUCT,'--version','7.1.2']+flags), \
                 patch('runtime.ensure_runtime'),patch('ssh_client.check'), \
                 patch.object(olsn0w,'extract',return_value=(Path(folder)/'firmware',dict(RELEASE,product=PRODUCT))), \
                 patch('bootchain.prepare',side_effect=Selected) as prepare:
                with self.assertRaises(Selected):olsn0w.main()
                prepare.assert_called_once_with(Path(folder)/'firmware',verbose=verbose)

    def test_default_no_and_explicit_yes_are_saved_and_used_for_plan_lookup(self):
        identity=dict(product=PRODUCT,ecid=123,mode='Normal')
        for answer,expected in (('',False),('n',False),(' YES ',True)):
            with self.subTest(answer=answer),tempfile.TemporaryDirectory() as folder, \
                 patch.object(guided,'STATE',Path(folder)), \
                 patch.object(guided,'connected',return_value=(identity,None)), \
                 patch.object(guided,'releases',return_value=[RELEASE]), \
                 patch('prepared_session.find_plan',return_value=None) as find, \
                 patch.object(guided,'choose_ipsws',return_value={PRODUCT+'/11D257':'/local/target'}) as choose, \
                 patch.object(guided,'prepare',return_value={}) as prepare, \
                 patch.object(guided,'enter_dfu') as dfu:
                answers=iter(['1','n','invalid',answer,'n'])
                guided.menu(PRODUCT,'123',read=lambda _:next(answers),show=lambda _:None)
                record=json.loads((prepare.call_args.args[0]/'device.json').read_text())
                self.assertIs(record['verbose_boot'],expected)
                self.assertEqual(record['ipsws'],{PRODUCT+'/11D257':'/local/target'})
                self.assertIs(find.call_args.kwargs['verbose'],expected)
                choose.assert_called_once()
                dfu.assert_not_called()

    def test_local_inputs_and_verbose_reach_target_base_donor_and_ram_preparation(self):
        class PreparedRam(Exception):pass
        product='iPad2,5'
        release=dict(version='6.1.2',buildid='10B146')
        inputs={p+'/'+b:'/local/'+p+'-'+b+'.ipsw' for p,_,b in guided.firmware_requests(product,release)}
        for verbose in (False,True):
            with self.subTest(verbose=verbose),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);session=root/'session';session.mkdir()
                save(session/'device.json',dict(identity=dict(product=product),verbose_boot=verbose,ipsws=inputs))
                def extract(p,v,*args,**kwargs):
                    return root/p/kwargs.get('build',args[2] if len(args)>2 else '12H321')/'firmware',{}
                target=root/product/'10B146'/'firmware'
                relay,system=target_paths(target.parent,verbose=verbose)
                with patch.object(guided,'preparation_space',return_value=0), \
                     patch.object(guided,'check_space'), \
                     patch('firmware.acquire',return_value=(Path('/verified/base'),{},None,None)) as acquire, \
                     patch('firmware.extract',side_effect=extract) as extraction, \
                     patch('guided_inputs.ticket'),patch('guided_inputs.modem',return_value=(None,None)), \
                     patch.object(guided,'reusable_recipe',return_value=False), \
                     patch('restore.checked_manifest',return_value=dict(recipe_version=1,files={'devicetree':'tree','relay.bin':'relay'})), \
                     patch('bootchain.prepare') as boot,patch('system.prepare') as image, \
                     patch('rescue_prepare.prepare',side_effect=PreparedRam) as ram:
                    with self.assertRaises(PreparedRam):guided._prepare(session,release,Mock())
                self.assertEqual(acquire.call_args.args[2],Path(inputs[product+'/12H321']))
                extraction.assert_any_call(product,'6.1.2',Path(inputs[product+'/10B146']),build='10B146')
                extraction.assert_any_call('iPhone4,1','8.4.1',build='12H321',ipsw=Path(inputs['iPhone4,1/12H321']))
                boot.assert_called_once_with(target,verbose=verbose)
                image.assert_called_once_with(target,relay,remove_setup_app=False)
                self.assertEqual(ram.call_args.kwargs['ram_ipsw'],Path(inputs[product+'/10B329']))
                self.assertEqual(ram.call_args.kwargs['environment_build'],'10B329')
