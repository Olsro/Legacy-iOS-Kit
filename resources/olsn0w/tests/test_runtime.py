"""Regression checks for interrupted installs and missing host prerequisites."""
import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runtime


class RuntimeRepair(unittest.TestCase):
    def test_existing_but_incomplete_environment_is_repaired_before_exec(self):
        state = Path('/private-state')
        with patch.object(runtime, 'healthy', side_effect=[False, True]), \
             patch.object(runtime.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as install, \
             patch.object(runtime.os, 'execv') as execute, contextlib.redirect_stderr(io.StringIO()):
            runtime.ensure_runtime(state)
        install.assert_called_once_with(['sh', str(runtime.SOURCE / 'setup.sh')])
        self.assertEqual(execute.call_args.args[0], str(state / 'runtime/bin/python'))

    def test_failed_install_stops_before_device_operations_without_retry_loop(self):
        with patch.object(runtime, 'healthy', return_value=False), \
             patch.object(runtime.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)) as install, \
             patch.object(runtime.os, 'execv') as execute, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'installation error above'):
                runtime.ensure_runtime(Path('/private-state'))
        install.assert_called_once()
        execute.assert_not_called()

    def test_successful_installer_must_produce_a_working_environment(self):
        with patch.object(runtime, 'healthy', return_value=False), \
             patch.object(runtime.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)), \
             patch.object(runtime.os, 'execv') as execute, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError):
                runtime.ensure_runtime(Path('/private-state'))
        execute.assert_not_called()

    def test_healthy_active_environment_never_installs_or_restarts(self):
        with patch.object(runtime, 'healthy', return_value=True), \
             patch.object(runtime.sys, 'prefix', '/private-state/runtime'), \
             patch.object(runtime.subprocess, 'run') as install, \
             patch.object(runtime.os, 'execv') as execute:
            runtime.ensure_runtime(Path('/private-state'))
        install.assert_not_called()
        execute.assert_not_called()

    def test_wrong_pinned_version_is_not_accepted(self):
        with patch.object(runtime, 'import_module'), \
             patch.object(runtime.metadata, 'version', return_value='0.0.0'):
            with self.assertRaisesRegex(RuntimeError, 'requires capstone=='):
                runtime.check()

    def test_native_library_load_failure_is_not_accepted(self):
        versions = dict(line.split('==') for line in (runtime.SOURCE / 'requirements.txt').read_text().splitlines())
        with patch.object(runtime.metadata, 'version', side_effect=versions.__getitem__), \
             patch.object(runtime, 'import_module', side_effect=[object(), OSError('native library missing')]):
            with self.assertRaisesRegex(OSError, 'native library missing'):
                runtime.check()

    def test_help_and_support_checks_skip_environment_installation(self):
        import olsn0w
        for args in (['--help'], ['supports', '--product', 'iPhone5,2']):
            with self.subTest(args=args), patch.object(sys, 'argv', ['olsn0w.py', *args]), \
                 patch.object(runtime, 'ensure_runtime') as ensure, contextlib.redirect_stdout(io.StringIO()):
                try:
                    olsn0w.main()
                except SystemExit as error:
                    self.assertEqual(error.code, 0)
                ensure.assert_not_called()


class HostPrerequisites(unittest.TestCase):
    def test_apt_installs_missing_python_or_venv_and_leaves_ready_hosts_alone(self):
        # Substitute only the host tools: never run a real package manager.
        for missing in ('python', 'venv', 'none'):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory(prefix='olsn0w host ') as temporary:
                root = Path(temporary)
                tools = root / 'tools'
                tools.mkdir()
                ready = root / 'ready'
                if missing == 'none':
                    ready.touch()
                log = root / 'packages.log'
                scripts = {
                    'python3': '''#!/bin/sh
if [ -f "$HOST_READY" ]; then exit 0; fi
case "$2" in *venv*) exit 1;; esac
[ "$MISSING" = venv ]
''',
                    'apt-get': '''#!/bin/sh
echo "$*" >> "$PACKAGE_LOG"
if [ "$1" = install ]; then : > "$HOST_READY"; fi
''',
                    'sudo': '#!/bin/sh\nexec "$@"\n',
                    'id': '#!/bin/sh\necho 1000\n',
                    'uname': '#!/bin/sh\necho Linux\n',
                }
                for name, script in scripts.items():
                    executable = tools / name
                    executable.write_text(script)
                    executable.chmod(0o755)
                (tools / 'dirname').symlink_to(shutil.which('dirname'))
                result = subprocess.run(['/bin/sh', str(runtime.SOURCE / 'setup.sh'), '--host-only'],
                                        env=dict(os.environ, PATH=str(tools), HOST_READY=str(ready),
                                                 PACKAGE_LOG=str(log), MISSING=missing),
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                if missing == 'none':
                    self.assertFalse(log.exists())
                else:
                    self.assertEqual(log.read_text().splitlines(),
                                     ['update', 'install -y python3 python3-venv'])


if __name__ == '__main__':
    unittest.main()
