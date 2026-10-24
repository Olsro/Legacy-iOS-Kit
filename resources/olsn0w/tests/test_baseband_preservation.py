"""Cellular iPads must disable modem flashing in the restore RAM itself."""
import hashlib
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import MODELS, baseband_strategy
from provision import configure_baseband, require_baseband_policy
import provision_run


class BasebandPreservation(unittest.TestCase):
    def image(self, files):
        image=Mock()
        image.ls.return_value=[dict(name=Path(path).name) for path in files]
        image.read.side_effect=files.__getitem__
        image.add.side_effect=lambda path,data,mode:files.update({path:data})
        return image

    def test_preserved_models_override_ram_options_and_keep_other_settings(self):
        for product in MODELS:
            if baseband_strategy(product)!='preserve':continue
            for fmt in (plistlib.FMT_XML,plistlib.FMT_BINARY):
                with self.subTest(product=product,fmt=fmt):
                    path='/usr/local/share/restore/options.'+MODELS[product][0][:-2]+'.plist'
                    original=dict(UpdateBaseband=True,SystemImage=True,FlashNOR=True,
                                  SystemPartitionSize=2048,CreateFilesystemPartitions=True)
                    files={path:plistlib.dumps(original,fmt=fmt)}
                    image=self.image(files)
                    report=configure_baseband(image,product)
                    self.assertEqual(plistlib.loads(files[path]),dict(original,UpdateBaseband=False))
                    self.assertEqual(files[path].startswith(b'bplist00'),fmt==plistlib.FMT_BINARY)
                    self.assertEqual(report['options_sha256'],hashlib.sha256(files[path]).hexdigest())
                    require_baseband_policy(dict(product=product,baseband_policy=report))
                    image.add.assert_called_once_with(path,files[path],0o644)

    def test_generic_options_are_used_only_without_selected_board_options(self):
        directory='/usr/local/share/restore/'
        generic=directory+'options.plist';board=directory+'options.j2a.plist'
        unrelated=directory+'options.j2.plist'
        for selected in (generic,board):
            with self.subTest(selected=selected):
                stock=plistlib.dumps(dict(SystemImage=True))
                files={generic:stock,unrelated:stock,selected:stock}
                image=self.image(files)
                report=configure_baseband(image,'iPad3,3')
                self.assertEqual(report['options_path'],selected)
                self.assertIs(plistlib.loads(files[selected])['UpdateBaseband'],False)
                self.assertEqual(files[unrelated],stock)
                if selected==board:self.assertEqual(files[generic],stock)

    def test_models_with_other_modem_policies_do_not_edit_ram_options(self):
        for product in MODELS:
            strategy=baseband_strategy(product)
            if strategy=='preserve':continue
            with self.subTest(product=product):
                image=Mock()
                self.assertEqual(configure_baseband(image,product),dict(strategy=strategy))
                self.assertEqual(image.mock_calls,[])

    def test_missing_invalid_or_unwritten_options_cannot_publish_preservation(self):
        path='/usr/local/share/restore/options.j2a.plist'
        for content in (None,b'corrupt',plistlib.dumps([])):
            with self.subTest(content=content):
                image=self.image({} if content is None else {path:content})
                with self.assertRaises(ValueError):configure_baseband(image,'iPad3,3')
                image.add.assert_not_called()
        image=self.image({path:plistlib.dumps(dict(UpdateBaseband=True))})
        image.add.side_effect=None
        with self.assertRaisesRegex(ValueError,'readback'):
            configure_baseband(image,'iPad3,3')

    def test_old_bundle_is_rejected_before_runtime_probe_or_dfu(self):
        with tempfile.TemporaryDirectory() as temporary:
            session=Path(temporary);bundle=session/'provision'
            identity=dict(product='iPad3,3',board='j2aap',chip=0x8945,board_id=4,ecid=123)
            (session/'device.json').write_text(json.dumps(dict(identity=identity)))
            report=dict(kind='signed-base-restore-handoff',product='iPad3,3',identity=identity)
            with patch.object(provision_run,'checked_manifest',return_value=report), \
                 patch.object(provision_run,'check_restore_runtime') as loader, \
                 patch.object(provision_run,'prepare_dfu') as dfu:
                with self.assertRaisesRegex(ValueError,'modem-preserving.*no erase started'):
                    provision_run.run(session,bundle,session/'ticket',session/'keys',erase=True)
            loader.assert_not_called();dfu.assert_not_called()
            self.assertFalse(bundle.exists())

    def test_incomplete_or_foreign_policy_is_not_accepted(self):
        valid=dict(strategy='preserve',update_baseband=False,
                   options_path='/usr/local/share/restore/options.j2a.plist',options_sha256='a'*64)
        for policy in (None,{},dict(valid,update_baseband=True),
                       dict(valid,options_path='/usr/local/share/restore/options.j2.plist'),
                       dict(valid,options_sha256=None),dict(valid,options_sha256='bad')):
            with self.subTest(policy=policy),self.assertRaises(ValueError):
                require_baseband_policy(dict(product='iPad3,3',baseband_policy=policy))


if __name__=='__main__':unittest.main()
