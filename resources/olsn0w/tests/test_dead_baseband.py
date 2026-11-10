"""--dead-bb never flashes, collects or waits for the selected modem."""
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import common
from common import MODELS, baseband_strategy, dead_baseband, profile, set_dead_baseband
import guided_inputs
from provision import configure_baseband, require_baseband_policy
from provision_collect import modem_components
import provision_run


class DeadBaseband(unittest.TestCase):
    def setUp(self):
        set_dead_baseband(True)
        self.addCleanup(set_dead_baseband,False)

    def test_policy_is_explicit_and_disabled_by_default(self):
        set_dead_baseband(False)
        self.assertEqual(baseband_strategy('iPad3,5'),'update')
        self.assertFalse(dead_baseband('iPad3,5'))
        with self.assertRaises(ValueError):set_dead_baseband(1)

    def test_every_cellular_model_preserves_and_wifi_models_are_unaffected(self):
        for product in MODELS:
            with self.subTest(product=product):
                cellular=profile(product)['has_baseband']
                self.assertEqual(baseband_strategy(product),'preserve' if cellular else 'none')
                self.assertIs(dead_baseband(product),cellular)

    def test_no_modem_is_downloaded_collected_or_passed_to_the_restore_tool(self):
        identity=dict(product='iPad3,5',ecid=123)
        with tempfile.TemporaryDirectory() as temporary:
            folder=Path(temporary)
            self.assertEqual(guided_inputs.modem(identity,folder/'modem'),(None,None))
            self.assertFalse((folder/'modem').exists())
            self.assertEqual(modem_components('iPad3,5'),(None,()))
            ticket=folder/'ticket';ticket.write_bytes(b'')
            with patch.object(provision_run,'binding'), \
                 patch.object(provision_run,'tools',return_value=folder):
                (folder/'futurerestore_old').write_bytes(b'')
                argv=provision_run.restore_arguments(identity,folder/'base8.ipsw',ticket)
                self.assertIn('--no-baseband',argv)
                self.assertNotIn('-b',argv)
                with self.assertRaisesRegex(ValueError,'does not accept a baseband update'):
                    provision_run.restore_arguments(identity,folder/'base8.ipsw',ticket,
                                                    folder/'modem.bbfw',folder/'manifest.plist')

    def test_restore_ram_disables_the_update_and_plain_bundles_are_rejected(self):
        path='/usr/local/share/restore/options.p102.plist'
        files={path:plistlib.dumps(dict(UpdateBaseband=True,SystemImage=True))}
        image=Mock()
        image.ls.return_value=[dict(name=Path(path).name)]
        image.read.side_effect=files.__getitem__
        image.add.side_effect=lambda name,data,mode:files.update({name:data})
        report=configure_baseband(image,'iPad3,5')
        self.assertEqual(plistlib.loads(files[path]),dict(UpdateBaseband=False,SystemImage=True))
        require_baseband_policy(dict(product='iPad3,5',baseband_policy=report))
        with self.assertRaisesRegex(ValueError,'no erase started'):
            require_baseband_policy(dict(product='iPad3,5',baseband_policy=dict(strategy='update')))


if __name__=='__main__':unittest.main()
