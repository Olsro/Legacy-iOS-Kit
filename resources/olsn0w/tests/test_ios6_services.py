"""Check ordering and preconditions of the legacy launchd configuration."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from system import (ios6_keybag_payload, ios6_launchd_conf,
                    ios6_protection_probe_payload, jailbreak_payload)


class LegacyServices(unittest.TestCase):
    def test_untether_binary_stays_with_ios6_data_payload(self):
        payload, _ = jailbreak_payload('6.1.3')
        self.assertIn('private/var/aquila/aquila', payload)
        self.assertNotIn('aquila', payload)

    def test_protected_firstboot_precedes_guarded_untether(self):
        source = b'setenv TEST preserved\nbsexec .. /private/var/aquila/aquila\n'
        result = ios6_launchd_conf(source)
        self.assertTrue(result.startswith(
            b'bsexec .. /bin/sh /usr/local/libexec/olsn0w/ios6-firstboot.sh\n'))
        self.assertIn(b'setenv TEST preserved\n', result)
        self.assertEqual(result.count(
            b'bsexec .. /bin/sh /usr/local/libexec/olsn0w/ios6-start-aquila.sh\n'), 1)
        self.assertNotIn(b'bsexec .. /private/var/aquila/aquila\n', result)

    def test_launchd_socket_is_saved_after_launchd_conf(self):
        result = ios6_launchd_conf(b'bsexec .. /private/var/aquila/aquila\n')
        self.assertTrue(result.endswith(
            b'bsexec .. /bin/sh /usr/local/libexec/olsn0w/ios5-launchd-socket.sh save\n'))

    def test_unknown_or_duplicate_configuration_is_rejected(self):
        token = b'bsexec .. /private/var/aquila/aquila\n'
        for content in (b'', b'bsexec .. /some-other-program\n', token * 2):
            with self.subTest(content=content), self.assertRaises(ValueError):
                ios6_launchd_conf(content)

    def test_initializer_matches_source_and_code_signature(self):
        self.assertEqual(ios6_keybag_payload()[:4], b'\xce\xfa\xed\xfe')
        self.assertEqual(ios6_protection_probe_payload()[:4], b'\xce\xfa\xed\xfe')

    def test_initializer_only_creates_the_missing_ios6_system_bag(self):
        text = (Path(__file__).resolve().parents[1]/'target/keybag-init.sh').read_text()
        self.assertIn('/usr/local/libexec/olsn0w/guard-target.sh\n', text)
        self.assertIn('/usr/local/libexec/olsn0w/keybag-init\n', text)
        self.assertIn('[ -s /private/var/keybags/systembag.kb ]', text)
        self.assertNotIn('--initialize', text)
        self.assertNotIn('data-firstboot', text)

    def test_ios6_seed_follows_keybag_and_aquila_requires_generation(self):
        root = Path(__file__).resolve().parents[1]/'target'
        firstboot = (root/'ios6-firstboot.sh').read_text()
        self.assertLess(firstboot.index('keybag-init\n'), firstboot.index('data-firstboot.tar.gz'))
        self.assertLess(firstboot.index('data-personalization.tar'),
                        firstboot.index('generation.new'))
        self.assertIn('guard-target.sh --keybag-init', firstboot)
        self.assertLess(firstboot.index('protection-probe d'), firstboot.index('generation.new'))
        self.assertLess(firstboot.index('protection-probe f'), firstboot.index('generation.new'))
        self.assertIn('guard-target.sh\n', (root/'ios6-start-aquila.sh').read_text())
