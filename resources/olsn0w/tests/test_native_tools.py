"""Native build preflight must repair missing tools before downloading sources."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_tools


class BuildPrerequisites(unittest.TestCase):
    def test_missing_cmake_is_reported_without_attempting_a_build(self):
        with patch.object(native_tools.shutil, 'which', return_value=None), \
             patch.object(native_tools.subprocess, 'run') as command:
            self.assertIn('CMake is not installed', native_tools.build_dependencies_problem())
        command.assert_not_called()

    def test_compile_and_link_are_required_even_if_configuration_succeeds(self):
        results = [subprocess.CompletedProcess([], 0, b'', b''),
                   subprocess.CompletedProcess([], 1, b'', b'zlib link failed')]
        with patch.object(native_tools.shutil, 'which', return_value='/cmake'), \
             patch.object(native_tools.subprocess, 'run', side_effect=results) as command:
            self.assertIn('zlib link failed', native_tools.build_dependencies_problem())
        self.assertEqual(command.call_count, 2)

    def test_missing_compiler_or_headers_retains_configuration_diagnostics(self):
        failure = subprocess.CompletedProcess([], 1, b'', b'Could NOT find ZLIB')
        with patch.object(native_tools.shutil, 'which', return_value='/cmake'), \
             patch.object(native_tools.subprocess, 'run', return_value=failure) as command:
            self.assertIn('Could NOT find ZLIB', native_tools.build_dependencies_problem())
        command.assert_called_once()

    def test_ready_host_does_not_install_packages(self):
        with patch.object(native_tools, 'build_dependencies_problem', return_value=None), \
             patch.object(native_tools.subprocess, 'run') as install:
            native_tools.ensure_build_dependencies()
        install.assert_not_called()

    def test_missing_tools_are_installed_once_and_rechecked(self):
        with patch.object(native_tools, 'build_dependencies_problem', side_effect=['CMake missing', None]) as probe, \
             patch.object(native_tools.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as install, \
             contextlib.redirect_stderr(io.StringIO()):
            native_tools.ensure_build_dependencies()
        self.assertEqual(probe.call_count, 2)
        install.assert_called_once_with(['sh', str(native_tools.KIT / 'resources/olsn0w/setup.sh'), '--native-only'])

    def test_package_manager_failure_stops_with_a_retry_message(self):
        with patch.object(native_tools, 'build_dependencies_problem', return_value='CMake missing'), \
             patch.object(native_tools.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)) as install, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'package manager error above'):
                native_tools.ensure_build_dependencies()
        install.assert_called_once()

    def test_unusable_toolchain_after_installation_does_not_loop(self):
        with patch.object(native_tools, 'build_dependencies_problem', return_value='No C compiler'), \
             patch.object(native_tools.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as install, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'No C compiler'):
                native_tools.ensure_build_dependencies()
        install.assert_called_once()

    def test_build_checks_prerequisites_before_fetching_sources(self):
        with patch.object(native_tools, 'STATE', Path('/nonexistent-olsn0w-test-state')), \
             patch.object(native_tools, 'ensure_build_dependencies', side_effect=RuntimeError('install failed')), \
             patch.object(native_tools, 'fetch') as fetch:
            with self.assertRaisesRegex(RuntimeError, 'install failed'):
                native_tools.hfscompress()
        fetch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
