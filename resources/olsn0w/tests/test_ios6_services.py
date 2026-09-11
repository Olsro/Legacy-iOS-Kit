"""Check ordering and preconditions of the legacy launchd configuration."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from system import ios6_keybag_payload, ios6_launchd_conf


class LegacyServices(unittest.TestCase):
    def test_keybag_precedes_untether_and_keeps_other_commands(self):
        source = b'setenv TEST preserved\nbsexec .. /private/var/aquila/aquila\n'
        result = ios6_launchd_conf(source)
        self.assertTrue(result.startswith(b'bsexec .. /bin/sh /usr/local/libexec/olsn0w/keybag-init.sh\n'))
        self.assertIn(b'setenv TEST preserved\n', result)
        self.assertEqual(result.count(b'bsexec .. /aquila\n'), 1)

    def test_unknown_or_duplicate_configuration_is_rejected(self):
        token = b'bsexec .. /private/var/aquila/aquila\n'
        for content in (b'', b'bsexec .. /some-other-program\n', token * 2):
            with self.subTest(content=content), self.assertRaises(ValueError):
                ios6_launchd_conf(content)

    def test_initializer_matches_source_and_code_signature(self):
        self.assertEqual(ios6_keybag_payload()[:4], b'\xce\xfa\xed\xfe')
