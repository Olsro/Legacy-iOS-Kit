"""Keep A5Mate guidance and the distributed Wii completion message in sync."""
import hashlib
from pathlib import Path
import re
import unittest


KIT = Path(__file__).resolve().parents[3]
PACKAGE = KIT/'resources/a5mate-wii'
MESSAGE = 'Visit https://olsro.fr for cool stuff and to support Olsro with a donation.'


class A5MateMessages(unittest.TestCase):
    def test_external_pwndfu_guidance_includes_wii(self):
        lines = (KIT/'restore.sh').read_text().splitlines()
        mentions = 0
        for index, line in enumerate(lines):
            if re.search(r'arduino|raspberry|pi pico', line, re.I):
                mentions += 1
                context = '\n'.join(lines[max(0, index-2):index+3])
                self.assertIn('A5Mate Wii', context)
        self.assertGreaterEqual(mentions, 3)

    def test_completion_message_follows_done(self):
        source = (PACKAGE/'sources/a5wii/source/main.c').read_text()
        self.assertIn('report("DONE returning to Homebrew Channel");\n'
                      '    report("'+MESSAGE+'");', source)

    def test_distributed_profiles_have_message_and_valid_hashes(self):
        hashes = dict(line.split()[::-1] for line in
                      (PACKAGE/'SHA256SUMS').read_text().splitlines())
        for profile in ('8940', '8942', '8945'):
            name = 'apps/a5mate-wii-'+profile+'/boot.dol'
            data = (PACKAGE/name).read_bytes()
            with self.subTest(profile=profile):
                self.assertIn(MESSAGE.encode()+b'\0', data)
                self.assertEqual(hashlib.sha256(data).hexdigest(), hashes[name])
