"""Native build preflight must repair missing tools before downloading sources."""
import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_tools


class BuildPrerequisites(unittest.TestCase):
    def setUp(self):
        # These package-manager repair tests exercise Linux, regardless of host.
        host = patch.object(native_tools.platform, 'system', return_value='Linux')
        host.start()
        self.addCleanup(host.stop)

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


class MacCMake(unittest.TestCase):
    def setUp(self):
        host = patch.object(native_tools.platform, 'system', return_value='Darwin')
        host.start()
        self.addCleanup(host.stop)
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)

    def test_working_path_cmake_does_not_download_or_modify_path(self):
        original = os.environ.get('PATH')
        with patch.object(native_tools.shutil, 'which', return_value='/existing/cmake'), \
             patch.object(native_tools, 'usable_cmake', return_value=True), \
             patch.object(native_tools, 'fetch') as fetch:
            native_tools.prepare_macos_cmake()
        self.assertEqual(os.environ.get('PATH'), original)
        fetch.assert_not_called()

    def test_cmake_app_is_detected_without_homebrew_or_symlinks(self):
        candidate = '/Applications/CMake.app/Contents/bin/cmake'
        with patch.object(native_tools.shutil, 'which', return_value=None), \
             patch.object(Path, 'is_file', return_value=True), \
             patch.object(native_tools, 'usable_cmake', return_value=True) as probe, \
             patch.object(native_tools, 'fetch') as fetch:
            native_tools.prepare_macos_cmake()
        probe.assert_called_once_with(Path(candidate))
        self.assertEqual(os.environ['PATH'].split(os.pathsep)[0], str(Path(candidate).parent))
        fetch.assert_not_called()

    def fixture(self, root):
        executable = root / 'fixture' / native_tools.CMAKE_MACOS_PACKAGE / 'CMake.app/Contents/bin/cmake'
        executable.parent.mkdir(parents=True)
        executable.write_text('#!/bin/sh\necho "cmake version fixture"\n')
        executable.chmod(0o755)
        archive = root / 'fixture.tar.gz'
        with tarfile.open(archive, 'w:gz') as bundle:
            bundle.add(executable.parents[3], arcname=native_tools.CMAKE_MACOS_PACKAGE)
        return archive

    def test_missing_or_incompatible_cmake_is_installed_privately_and_reused(self):
        for installed in (None, '/incompatible/cmake'):
            with self.subTest(installed=installed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = self.fixture(root)
                state = root / 'state'
                def fetch_fixture(url, destination):
                    self.assertEqual(url, 'https://cmake.org/files/v3.31/' + native_tools.CMAKE_MACOS_PACKAGE + '.tar.gz')
                    destination.parent.mkdir(parents=True)
                    shutil.copy2(archive, destination)
                real_probe = native_tools.usable_cmake
                def probe(executable):
                    return False if str(executable) == installed else real_probe(executable)
                with patch.object(native_tools, 'STATE', state), \
                     patch.object(Path, 'home', return_value=root), \
                     patch.object(native_tools.shutil, 'which', return_value=installed), \
                     patch.object(native_tools, 'usable_cmake', side_effect=probe), \
                     patch.object(native_tools, 'CMAKE_MACOS_SHA256', native_tools.digest(archive)), \
                     patch.object(native_tools, 'fetch', side_effect=fetch_fixture) as fetch, \
                     contextlib.redirect_stderr(io.StringIO()):
                    native_tools.prepare_macos_cmake()
                    expected = state / 'tools' / native_tools.CMAKE_MACOS_PACKAGE / 'CMake.app/Contents/bin'
                    self.assertEqual(os.environ['PATH'].split(os.pathsep)[0], str(expected))
                    self.assertTrue(native_tools.usable_cmake(expected / 'cmake'))
                    native_tools.prepare_macos_cmake()
                    fetch.assert_called_once()

    def test_bad_checksum_stops_before_extraction_or_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            archive = state / 'sources' / (native_tools.CMAKE_MACOS_PACKAGE + '.tar.gz')
            archive.parent.mkdir()
            archive.write_bytes(b'untrusted archive')
            with patch.object(native_tools, 'STATE', state), \
                 patch.object(native_tools.shutil, 'which', return_value=None), \
                 patch.object(native_tools, 'usable_cmake', return_value=False), \
                 patch.object(native_tools.subprocess, 'run') as command:
                with self.assertRaisesRegex(ValueError, 'CMake archive checksum mismatch'):
                    native_tools.prepare_macos_cmake()
            command.assert_not_called()
            self.assertFalse((state / 'tools').exists())

    def test_missing_apple_toolchain_reports_install_command_without_brew(self):
        with patch.object(native_tools, 'prepare_macos_cmake'), \
             patch.object(native_tools, 'build_dependencies_problem', return_value='No C compiler'), \
             patch.object(native_tools.subprocess, 'run') as install, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'xcode-select --install'):
                native_tools.ensure_build_dependencies()
        install.assert_not_called()


if __name__ == '__main__':
    unittest.main()
