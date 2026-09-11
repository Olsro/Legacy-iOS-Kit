"""The early keybag guard must not read a still-locked protected file."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TargetGuard(unittest.TestCase):
    def test_keybag_init_uses_unprotected_marker_and_protected_mount(self):
        source = (ROOT/'target/guard-target.sh').read_text()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            marker = base/'var/lib/olsn0w'
            marker.mkdir(parents=True)
            (marker/'generation').write_text('generation\n')
            (marker/'fresh-generation').mkdir()
            tools = base/'tools'
            tools.mkdir()
            reads = base/'reads'
            config = base/'target.conf'
            config.write_text('AG_BOARD=BOARD\nAG_BUILD=BUILD\n'
                              'AG_ROOT_DEVICE=/dev/disk0s1s3\n'
                              'AG_DATA_DEVICE=/dev/disk0s1s2\nAG_GENERATION=generation\n')

            def executable(name, body):
                path = tools/name
                path.write_text('#!/bin/sh\n'+body)
                path.chmod(0o755)

            executable('sysctl', 'case "$2" in hw.model) echo BOARD;; kern.osversion) echo BUILD;; esac\n')
            mounts = ('/dev/disk0s1s3 on / (hfs, local, journaled)\n'
                      '/dev/disk0s1s2 on /private/var (hfs, local, journaled, protect)\n')
            executable('mount', 'printf %s '+shlex.quote(mounts)+'\n')
            executable('cat', 'echo read >> '+shlex.quote(str(reads))+'\nexit 1\n')
            source = (source.replace('PATH=/bin:/sbin:/usr/bin:/usr/sbin', 'PATH='+str(tools))
                      .replace('/usr/local/libexec/olsn0w/target.conf', str(config))
                      .replace('/private/var/lib/olsn0w', str(marker)))
            script = base/'guard'
            script.write_text(source)

            def run(*args):
                return subprocess.run(['/bin/sh', str(script), *args], capture_output=True)

            self.assertEqual(run('--keybag-init').returncode, 0)
            self.assertFalse(reads.exists())
            self.assertNotEqual(run().returncode, 0)
            self.assertEqual(reads.read_text(), 'read\n')


if __name__ == '__main__':
    unittest.main()
