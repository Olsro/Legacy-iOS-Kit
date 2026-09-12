"""Check ordering and preconditions of the legacy launchd configuration."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from system import ios6_launchd_conf, jailbreak_payload


class LegacyServices(unittest.TestCase):
    def test_untether_binary_stays_with_ios6_data_payload(self):
        payload, _ = jailbreak_payload('6.1.3')
        self.assertIn('private/var/aquila/aquila', payload)
        self.assertNotIn('aquila', payload)

    def test_untether_keeps_historical_data_path_and_stock_commands(self):
        source = b'setenv TEST preserved\nbsexec .. /private/var/aquila/aquila\n'
        result = ios6_launchd_conf(source)
        self.assertEqual(result, source)
        self.assertNotIn(b'keybag-init', result)

    def test_unknown_or_duplicate_configuration_is_rejected(self):
        token = b'bsexec .. /private/var/aquila/aquila\n'
        for content in (b'', b'bsexec .. /some-other-program\n', token * 2):
            with self.subTest(content=content), self.assertRaises(ValueError):
                ios6_launchd_conf(content)
