"""The fork must never replace itself from upstream during startup."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


KIT = Path(__file__).resolve().parents[3]


class NoSelfUpdateTests(unittest.TestCase):
    def setUp(self):
        self.source = (KIT/'restore.sh').read_text()

    def test_self_update_entry_points_and_destructive_updater_are_absent(self):
        self.assertNotRegex(self.source, r'\bversion_(?:check|update|update_check)\b')
        self.assertNotIn('api.github.com/repos/LukeZGD/Legacy-iOS-Kit/', self.source)
        # A separate downloaded Sundance dependency has its own update path;
        # this test concerns the Kit checkout, not tool installation.
        for name in ('version_get', 'main'):
            body = re.search(r'^'+name+r'\(\) \{\n.*?^\}', self.source, re.M | re.S).group()
            self.assertNotRegex(body, r'git\s+(?:reset|pull|fetch|clone)\b')
        self.assertNotIn('git fetch --unshallow', self.source)
        self.assertNotIn('Failed to check for updates. GitHub', self.source)
        self.assertNotIn('git clone "https://github.com/LukeZGD/Legacy-iOS-Kit"', self.source)

    def test_version_is_local_for_shallow_clone_archive_and_new_marker(self):
        function = re.search(r'^version_get\(\) \{\n.*?^\}', self.source, re.M | re.S).group()
        for kind in ('shallow', 'archive', 'new', 'unknown'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root/'tmp').mkdir()
                (root/'resources').mkdir()
                if kind == 'shallow':
                    (root/'.git').mkdir()
                    (root/'.git/shallow').touch()
                elif kind == 'archive':
                    (root/'resources/git_hash').write_text('abcdef0')
                    (root/'resources/version').write_text('v26.09.01')
                elif kind == 'new':
                    (root/'resources/new').touch()
                script = '''
print() { echo "$1"; }; log() { echo "$1"; }; warn() { echo "$1"; }
curl() { echo FORBIDDEN_NETWORK; return 99; }
download_from_url() { echo FORBIDDEN_NETWORK; return 99; }
git() {
    case "$1 $2" in
        'rev-parse HEAD') echo abcdef012345;;
        'rev-parse --abbrev-ref') echo main;;
        'status --porcelain') :;;
        'log -1') echo 1700000000;;
        'rev-list --count') echo 1;;
        *) echo FORBIDDEN_GIT; return 99;;
    esac
}
''' + function + '\nversion_get\npwd\n'
                result = subprocess.run(['bash', '-c', script], cwd=root/'tmp',
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('FORBIDDEN', result.stdout+result.stderr)
                self.assertNotIn('Failed to check for updates', result.stdout)
                self.assertTrue(result.stdout.strip().endswith(str((root/'tmp').resolve())))
                if kind in ('shallow', 'archive'):
                    self.assertIn('* Version:', result.stdout)

    def test_required_downloads_and_legacy_flag_are_retained(self):
        self.assertIn('download_from_url() {', self.source)
        self.assertIn('"--no-version-check" ) :;;', self.source)
        self.assertIn('/usr/bin/xattr -cr ../bin/macos', self.source)
