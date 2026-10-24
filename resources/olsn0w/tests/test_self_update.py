"""Exercise toolkit updates against fixtures and local repositories only."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import zipfile
import unittest


KIT = Path(__file__).resolve().parents[3]
REPO = 'https://github.com/Olsro/Legacy-iOS-Kit'
UPSTREAM = 'https://github.com/LukeZGD/Legacy-iOS-Kit'
SOURCE = (KIT / 'restore.sh').read_text()


def function(name):
    return re.search(r'^' + name + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S).group()


FUNCTIONS = '\n'.join(function(name) for name in (
    'version_is_newer', 'version_get', 'version_update_check', 'version_update', 'version_check'))
HELPERS = '''
print() { echo "$1"; }; log() { echo "$1"; }; warn() { echo "$1"; }
error() { echo "$1" >&2; exit 1; }
select_yesno() { return 1; }
'''


class UpdateCheckTests(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / 'resources').mkdir()
        jq = shutil.which('jq')
        if not jq:
            platform = 'macos' if os.uname().sysname == 'Darwin' else 'linux/x86_64'
            jq = str(KIT / 'bin' / platform / 'jq')
        self.env = dict(os.environ, TEST_ROOT=str(self.root), TEST_JQ=jq)

    def check(self, settings='', release=None, commits=None, headers=''):
        (self.root / 'release').write_text(json.dumps(release))
        (self.root / 'commits').write_text(json.dumps(commits))
        (self.root / 'headers').write_text(headers)
        script = HELPERS + FUNCTIONS + '''
curl_fixture() {
    printf '%s\n' "$*" >> "$TEST_ROOT/requests"
    local args="$*" output headers
    while (( $# )); do
        case "$1" in
            -o) output="$2"; shift;;
            --dump-header) headers="$2"; shift;;
        esac
        shift
    done
    if [[ $args == *'/releases/latest'* ]]; then
        [[ $(cat "$TEST_ROOT/release") != null ]] || return 22
        cp "$TEST_ROOT/release" "$output"
    else
        [[ $(cat "$TEST_ROOT/commits") != null ]] || return 22
        cp "$TEST_ROOT/commits" "$output"
        cp "$TEST_ROOT/headers" "$headers"
    fi
}
git() {
    case "$1" in
        rev-list) echo 3;;
        merge-base) return 1;;
        *) echo UNEXPECTED_GIT >&2; return 99;;
    esac
}
version_update() { echo UPDATE_OFFERED; }
curl=curl_fixture
jq="$TEST_JQ"
branch_current=main
git_hash=aaaaaaa
version_current=v1.0.0
mkdir "tmp$$"
cd "tmp$$"
''' + settings + '\nversion_check\npwd\n'
        result = subprocess.run(['bash', '-c', script], cwd=self.root,
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('UNEXPECTED_GIT', result.stderr)
        self.assertEqual(Path(result.stdout.strip().splitlines()[-1]).parent, self.root)
        requests = self.root / 'requests'
        if requests.exists():
            for request in requests.read_text().splitlines():
                self.assertIn('https://api.github.com/repos/Olsro/Legacy-iOS-Kit/', request)
                self.assertNotIn('LukeZGD', request)
        return result.stdout

    def test_new_release_offers_update(self):
        output = self.check(release={'name': 'Latest-v1.0.1', 'target_commitish': 'b' * 40})
        self.assertIn('UPDATE_OFFERED', output)
        self.assertNotIn('/commits', (self.root / 'requests').read_text())

    def test_current_dirty_and_newer_local_versions_do_not_offer_update(self):
        for settings in ('git_hash=bbbbbbb', 'git_hash=bbbbbbb-dirty',
                         'version_current=v1.0.2',
                         'branch_current=; version_current=v1.0.1',
                         'branch_current=; version_current=v1.0.2'):
            with self.subTest(settings=settings):
                output = self.check(settings, release={
                    'name': 'Latest-v1.0.1', 'target_commitish': 'b' * 40})
                self.assertNotIn('UPDATE_OFFERED', output)

    def test_main_without_release_falls_back_to_fork_commits(self):
        output = self.check(commits=[{'sha': 'b' * 40}], headers=(
            'Link: <https://api.github.com/repos/Olsro/Legacy-iOS-Kit/commits?'
            'sha=main&per_page=1&page=4>; rel="last"\r\n'))
        self.assertIn('UPDATE_OFFERED', output)
        self.assertIn('sha=main', (self.root / 'requests').read_text())

    def test_development_branch_queries_its_own_history(self):
        output = self.check('branch_current=test', commits=[{'sha': 'b' * 40}], headers=(
            'Link: <https://example.invalid/?page=4>; rel="last"\r\n'))
        self.assertIn('UPDATE_OFFERED', output)
        requests = (self.root / 'requests').read_text()
        self.assertIn('sha=test', requests)
        self.assertNotIn('/releases/latest', requests)

    def test_api_failures_and_invalid_responses_allow_startup(self):
        for commits in (None, {'message': 'Not Found'}, [], [{'sha': 'invalid'}]):
            with self.subTest(commits=commits):
                output = self.check(commits=commits)
                self.assertNotIn('UPDATE_OFFERED', output)
                self.assertIn('Failed to check for updates', output)

    def test_skip_flag_and_internal_restore_helper_make_no_requests(self):
        for settings in ('no_version_check=1', 'olsn0w_internal_pwn=1'):
            with self.subTest(settings=settings):
                output = self.check(settings)
                self.assertNotIn('UPDATE_OFFERED', output)
                self.assertFalse((self.root / 'requests').exists())

    def test_skip_flag_is_respected_even_with_legacy_new_marker(self):
        (self.root / 'resources' / 'new').touch()
        output = self.check('no_version_check=1; branch_current=; git_hash=',
                            release={'name': 'Latest-v1.0.1', 'target_commitish': 'b' * 40})
        self.assertNotIn('UPDATE_OFFERED', output)
        self.assertFalse((self.root / 'requests').exists())

    def test_startup_calls_check_after_dependencies_and_restores_skip_option(self):
        main = function('main')
        self.assertLess(main.index('install_depends'), main.index('\n    version_check\n'))
        self.assertLess(main.index('\n    version_check\n'), main.index('\n    device_get_info\n'))
        self.assertIn('"--no-version-check" ) no_version_check=1;;', SOURCE)

    def test_semantic_versions_compare_components_numerically(self):
        for candidate, current, newer in (
            ('v1.0.1', 'v1.0.0', True), ('v1.10.0', 'v1.9.99', True),
            ('v2.0.0', 'v1.99.99', True), ('v1.0.0', 'v1.0.0', False),
            ('v1.9.99', 'v1.10.0', False), ('invalid', 'v1.0.0', False),
        ):
            with self.subTest(candidate=candidate, current=current):
                result = subprocess.run(['bash', '-c', function('version_is_newer') +
                    '\nversion_is_newer "$1" "$2"', 'test', candidate, current],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0 if newer else 1, result.stderr)

    def test_version_is_local_for_shallow_clone_archive_and_new_marker(self):
        function = re.search(r'^version_get\(\) \{\n.*?^\}', self.source, re.M | re.S).group()
        for kind in ('shallow', 'archive', 'new', 'unknown'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root/'tmp').mkdir()
                (root/'resources').mkdir()
                (root/'VERSION').write_text('1.0.0\n')
                if kind == 'shallow':
                    (root/'.git').mkdir()
                    (root/'.git/shallow').touch()
                elif kind == 'archive':
                    (root/'resources/git_hash').write_text('abcdef0'+'1'*33+'\n')
                    (root/'resources/version').write_text('v1.0.0')
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
                self.assertIn('* Version: v1.0.0', result.stdout)
                if kind == 'archive':
                    self.assertIn('(abcdef0 )', result.stdout)
                    self.assertNotIn('abcdef0'+'1'*33, result.stdout)



class UpdateInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.fork = self.root / 'fork'
        self.fork.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_NOSYSTEM='1', GIT_ALLOW_PROTOCOL='file',
                        GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='url.' + self.fork.as_uri() + '.insteadOf',
                        GIT_CONFIG_VALUE_0=REPO)
        self.git(self.fork, 'init', '-b', 'main')
        self.git(self.fork, 'config', 'user.name', 'Update Test')
        self.git(self.fork, 'config', 'user.email', 'test@example.invalid')
        for path, content in {
            'VERSION': '1.0.0\n', 'restore.sh': 'old script\n', 'README.md': 'old readme\n',
            'LICENSE': 'license\n', 'resources/payload': 'payload\n',
            'bin/tool': 'tool\n', '.gitignore': 'saved/\ntmp*/\n*.ipsw\n',
            '.github/workflows/test.yml': 'workflow\n',
        }.items():
            target = self.fork / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        self.git(self.fork, 'add', '.')
        self.git(self.fork, 'commit', '-m', 'initial')
        self.install = self.root / 'installation with spaces'

    def git(self, cwd, *args):
        result = subprocess.run(['git', *args], cwd=cwd, env=self.env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def clone_then_publish(self, shallow=False):
        args = ['clone'] + (['--depth=1'] if shallow else [])
        self.git(self.root, *args, self.fork.as_uri(), str(self.install))
        self.git(self.install, 'remote', 'set-url', 'origin', UPSTREAM)
        (self.fork / 'restore.sh').write_text('new script\n')
        self.git(self.fork, 'add', '.')
        self.git(self.fork, 'commit', '-m', 'update')

    def saved_data(self):
        (self.install / 'saved').mkdir()
        (self.install / 'saved' / 'blobs').write_text('keep blobs')
        (self.install / 'firmware.ipsw').write_text('keep firmware')

    def update(self, settings=''):
        script = HELPERS + function('version_update') + '''
branch_current=main
mkdir "tmp$$"
''' + settings + '\nversion_update\necho TOOLKIT_CONTINUES\n'
        return subprocess.run(['bash', '-c', script], cwd=self.install, env=self.env,
                              capture_output=True, text=True, timeout=30)

    def test_git_update_uses_fork_even_when_origin_points_upstream(self):
        self.clone_then_publish()
        self.saved_data()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Done! Please run the script again', result.stdout)
        self.assertEqual(self.git(self.install, 'rev-parse', 'HEAD'), self.git(self.fork, 'rev-parse', 'HEAD'))
        self.assertEqual(self.git(self.install, 'remote', 'get-url', 'origin'), UPSTREAM)
        self.assertEqual((self.install / 'saved' / 'blobs').read_text(), 'keep blobs')
        self.assertEqual((self.install / 'firmware.ipsw').read_text(), 'keep firmware')

    def test_shallow_clone_can_update(self):
        self.clone_then_publish(shallow=True)
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.install / 'restore.sh').read_text(), 'new script\n')

    def test_dirty_checkout_is_preserved(self):
        self.clone_then_publish()
        (self.install / 'restore.sh').write_text('local changes\n')
        before = self.git(self.install, 'rev-parse', 'HEAD')
        result = self.update()
        self.assertEqual(result.returncode, 1)
        self.assertIn('Local changes detected', result.stderr)
        self.assertEqual((self.install / 'restore.sh').read_text(), 'local changes\n')
        self.assertEqual(self.git(self.install, 'rev-parse', 'HEAD'), before)

    def test_diverged_history_is_preserved(self):
        self.clone_then_publish()
        self.git(self.install, 'config', 'user.name', 'Update Test')
        self.git(self.install, 'config', 'user.email', 'test@example.invalid')
        (self.install / 'local-file').touch()
        self.git(self.install, 'add', '.')
        self.git(self.install, 'commit', '-m', 'local change')
        before = self.git(self.install, 'rev-parse', 'HEAD')
        result = self.update()
        self.assertEqual(result.returncode, 1)
        self.assertIn('git pull failed', result.stderr)
        self.assertEqual(self.git(self.install, 'rev-parse', 'HEAD'), before)
        self.assertTrue((self.install / 'local-file').exists())

    def archive(self):
        shutil.copytree(self.fork, self.install, ignore=shutil.ignore_patterns('.git'))
        self.saved_data()
        (self.fork / 'restore.sh').write_text('new script\n')
        self.git(self.fork, 'add', '.')
        self.git(self.fork, 'commit', '-m', 'update')

    def test_zip_installation_converts_to_git_and_keeps_user_data(self):
        self.archive()
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.install / 'restore.sh').read_text(), 'new script\n')
        self.assertFalse((self.install / 'resources' / 'new').exists())
        self.assertEqual((self.install / 'saved' / 'blobs').read_text(), 'keep blobs')
        self.assertEqual((self.install / 'firmware.ipsw').read_text(), 'keep firmware')
        self.assertEqual(self.git(self.install, 'config', '--get', 'remote.origin.url'), REPO)

    def test_zip_clone_fallback_for_older_git(self):
        self.archive()
        result = self.update('''
git() {
    if [[ "$1 $2" == 'clone --filter=blob:none' ]]; then
        mkdir Legacy-iOS-Kit
        return 1
    fi
    command git "$@"
}
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.install / 'restore.sh').read_text(), 'new script\n')

    def test_zip_download_failure_preserves_existing_installation(self):
        self.archive()
        result = self.update('git() { return 1; }')
        self.assertEqual(result.returncode, 1)
        self.assertIn('git clone failed', result.stderr)
        self.assertEqual((self.install / 'restore.sh').read_text(), 'old script\n')
        self.assertEqual((self.install / 'resources' / 'payload').read_text(), 'payload\n')

    def test_release_workflow_packages_full_toolkit_version_and_revision(self):
        workflow = (KIT / '.github/workflows/build.yml').read_text()
        body = re.search(r'- name: Create complete release ZIP\n        run: \|\n'
                         r'((?:          .*\n)+)', workflow).group(1)
        script = textwrap.dedent(body).replace('${{ github.event.repository.name }}',
                                               'Legacy-iOS-Kit').replace(
                                                   '${{ env.VERSION_CURRENT }}', 'v1.0.0')
        result = subprocess.run(['bash', '-e', '-c', script], cwd=self.fork,
                                env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.fork / 'Legacy-iOS-Kit_v1.0.0.zip') as archive:
            for member in ('VERSION', 'bin/tool', 'resources/payload',
                           'resources/git_hash', 'restore.sh', '.github/workflows/test.yml'):
                self.assertIn(member, archive.namelist())
            self.assertEqual(archive.read('VERSION').decode().strip(), '1.0.0')
            self.assertEqual(archive.read('resources/git_hash').decode().strip(),
                             self.git(self.fork, 'rev-parse', 'HEAD'))
            self.assertNotIn('resources/new', archive.namelist())

    def test_declining_update_continues_without_changing_files(self):
        self.clone_then_publish()
        result = self.update('select_yesno() { return 0; }')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('Done!', result.stdout)
        self.assertIn('TOOLKIT_CONTINUES', result.stdout)
        self.assertNotIn('cannot continue', result.stdout)
        self.assertEqual((self.install / 'restore.sh').read_text(), 'old script\n')
