"""User-facing fork branding must not break shell quoting or upstream credits."""
import re
from pathlib import Path
import subprocess
import unittest


KIT = Path(__file__).resolve().parents[3]
NAME = "Olsro's Legacy iOS Kit"
SUPPORT = 'Visit https://olsro.fr for cool stuff and to support Olsro with a donation.'


class BrandingTests(unittest.TestCase):
    def test_help_has_fork_name_and_upstream_credit(self):
        result = subprocess.run(['bash', str(KIT/'restore.sh'), '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(NAME, result.stdout)
        self.assertIn('original script by LukeZGD', result.stdout)
        self.assertIn('original script by LukeZGD -\n'+SUPPORT, result.stdout)
        self.assertNotIn("Olsro's Olsro's", result.stdout)

    def test_startup_and_menu_support_line_is_below_fork_credit(self):
        source = (KIT/'restore.sh').read_text()
        for name in ('main', 'menu_print_info'):
            body = re.search(r'^'+name+r'\(\) \{\n.*?^\}', source, re.M | re.S).group()
            self.assertIn('print " - Olsro fork; original script by LukeZGD -"\n'
                          '    print "'+SUPPORT+'"', body)

    def test_exit_banner_with_and_without_version(self):
        source = (KIT/'restore.sh').read_text()
        function = re.search(r'^exit_message\(\) \{\n.*?^\}', source, re.M | re.S).group()
        for settings in ('', 'version_current=test',
                         'version_current=test; commits_current=2'):
            result = subprocess.run(['bash', '-c',
                'print() { echo "$1"; }\n'+function+'\n'+settings+'\nexit_message'],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(NAME, result.stdout)

    def test_readme_retains_origin_and_separates_hardware_validation(self):
        readme = (KIT/'README.md').read_text()
        self.assertTrue(readme.startswith('# '+NAME+'\n'))
        self.assertIn('https://github.com/LukeZGD/Legacy-iOS-Kit', readme)
        for section in ('### Hardware validation', '### Hacktiv8 and activation choices',
                        '### Returning from DRA and late iPhone 4S revisions'):
            self.assertIn(section, readme)
