"""Host library lookup survives a subprocess changing its working directory."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import common
import provision_run


class ToolEnvironment(unittest.TestCase):
    def test_linux_resolves_inherited_paths_before_changing_directory(self):
        library = (common.KIT/'bin/linux/x86_64/lib').resolve()
        original = 'bin/linux/x86_64/lib:other-libs::/opt/custom/lib'
        with patch.object(common.platform, 'system', return_value='Linux'), \
             patch.object(common, 'tools', return_value=library.parent), \
             patch.dict(os.environ, {'LD_LIBRARY_PATH': original}):
            environment = common.tool_environment()
            self.assertEqual(os.environ['LD_LIBRARY_PATH'], original)
        self.assertEqual(environment['LD_LIBRARY_PATH'].split(':'), list(dict.fromkeys([
            str(library), str(Path('bin/linux/x86_64/lib').resolve()),
            str(Path('other-libs').resolve()), str(Path.cwd()), '/opt/custom/lib'])))

    def test_linux_standalone_has_bundled_libraries_without_inherited_environment(self):
        with patch.object(common.platform, 'system', return_value='Linux'), \
             patch.dict(os.environ, {}, clear=True):
            environment = common.tool_environment()
            self.assertEqual(environment['LD_LIBRARY_PATH'],
                             str((common.tools()/'lib').resolve()))

    def test_macos_preserves_host_environment(self):
        with patch.object(common.platform, 'system', return_value='Darwin'), \
             patch.dict(os.environ, {'LD_LIBRARY_PATH': 'custom:relative'}):
            self.assertEqual(common.tool_environment(), dict(os.environ))


class RestoreLoader(unittest.TestCase):
    def executable(self, folder, body):
        executable = folder/'restore-tool'
        executable.write_text('#!/bin/sh\n'+body)
        executable.chmod(0o755)
        return executable

    def test_real_subprocess_probes_usage_in_empty_workdir_and_keeps_log(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            executable = self.executable(root,
                'test "$#" -eq 0 || exit 2\n'
                'test -z "$(ls -A)" || exit 2\n'
                'test "$OLS_TEST_LIBRARY" = "/absolute/lib" || exit 2\n'
                'printf "Usage: futurerestore [OPTIONS] IPSW\\n" >&2\nexit 255\n')
            environment = dict(os.environ, OLS_TEST_LIBRARY='/absolute/lib')
            log = root/'restore-loader.log'
            provision_run.check_restore_runtime(executable, environment, log)
            self.assertIn('Usage: futurerestore', log.read_text())
            self.assertEqual(sorted(p.name for p in root.iterdir()),
                             ['restore-loader.log', 'restore-tool'])

    def test_loader_failure_is_actionable_and_preserves_original_diagnostic(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            executable = self.executable(root,
                'echo "libssl.so.35: cannot open shared object file" >&2\nexit 127\n')
            log = root/'restore-loader.log'
            with self.assertRaisesRegex(RuntimeError, 'libssl.so.35'):
                provision_run.check_restore_runtime(executable, os.environ.copy(), log)
            self.assertIn('libssl.so.35', log.read_text())

    def test_unexpected_success_output_does_not_pass_as_restore_tool(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            executable = self.executable(root, 'echo "something else"\n')
            with self.assertRaisesRegex(RuntimeError, 'cannot load its runtime'):
                provision_run.check_restore_runtime(executable, os.environ.copy(), root/'probe.log')

    def test_missing_executable_and_timeout_keep_diagnostics(self):
        for failure in (FileNotFoundError('missing binary'),
                        subprocess.TimeoutExpired(['restore'], 15)):
            with self.subTest(failure=type(failure).__name__), \
                 tempfile.TemporaryDirectory() as root, \
                 patch.object(provision_run.subprocess, 'run', side_effect=failure):
                log = Path(root)/'restore-loader.log'
                with self.assertRaisesRegex(RuntimeError, 'Cannot start'):
                    provision_run.check_restore_runtime(Path(root)/'missing', {}, log)
                self.assertTrue(log.read_text())


if __name__ == '__main__':
    unittest.main()

