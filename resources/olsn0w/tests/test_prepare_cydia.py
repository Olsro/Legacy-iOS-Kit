"""Cydia preparation must retain the authenticated diagnostic SSH channel."""
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import system


class PrepareCydia(unittest.TestCase):
    def test_target_sshd_uses_reference_config_with_safe_authentication(self):
        source=Path(system.__file__).read_text()
        self.assertIn("'/usr/sbin/sshd','-D','-e','-f','/usr/local/share/olsn0w/sshd_config'",source)
        self.assertIn('ListenAddress 127.0.0.1',source)
        self.assertIn('StrictModes no',source)
        self.assertIn('PasswordAuthentication no',source)

    def test_read_only_system_validation_performs_no_root_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            active=root/'etc/ssh/sshd_config'
            reference=root/'usr/local/share/olsn0w/sshd_config'
            active.parent.mkdir(parents=True);reference.parent.mkdir(parents=True)
            active.write_text('AuthorizedKeysFile /etc/ssh/olsn0w_authorized_keys\n')
            reference.write_text('AuthorizedKeysFile /etc/ssh/olsn0w_authorized_keys\n')
            bag=root/'systembag.kb';bag.write_text('keybag')
            events=root/'events'
            no_op=root/'no-op'
            no_op.write_text('#!/bin/sh\necho "$0 $*" >> '+shlex.quote(str(events))+'\n')
            no_op.chmod(0o755)
            script=(ROOT/'target/prepare-cydia.sh').read_text()
            replacements={
                '/usr/local/libexec/olsn0w/guard-target.sh':str(no_op),
                '/usr/local/libexec/olsn0w/wait-graphics.sh':str(no_op),
                '/private/var/keybags/systembag.kb':str(bag),
                '/usr/local/share/olsn0w/sshd_config':str(reference),
                '/etc/ssh/sshd_config':str(active),
                'sync':str(no_op),
            }
            for before,after in replacements.items():script=script.replace(before,shlex.quote(after))
            command=root/'prepare-cydia.sh';command.write_text(script);command.chmod(0o755)
            result=subprocess.run(['/bin/sh',str(command)],capture_output=True)
            self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode()+script)
            self.assertEqual(active.read_text(),'AuthorizedKeysFile /etc/ssh/olsn0w_authorized_keys\n')
            self.assertFalse((root/'etc/ssh/sshd_config.distrib').exists())
            self.assertNotIn('dpkg-divert',script)
            self.assertNotIn('mkdir -p /usr/share',script)

    def test_pangu_gate_requires_the_selected_root_to_be_writable(self):
        script=(ROOT/'target/prepare-cydia.sh').read_text()
        self.assertIn('. /usr/local/libexec/olsn0w/target.conf',script)
        self.assertIn('$AG_ROOT_DEVICE on / (hfs,',script)
        self.assertIn('read-only',script)
        self.assertIn('[ "$marker" = ready ] && break',script)


if __name__ == '__main__':
    unittest.main()
