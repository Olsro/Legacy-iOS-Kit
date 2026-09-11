"""Exercise the protected-Data handoff before native keybagd."""
from pathlib import Path
import io
import shlex
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProtectedKeybagBoot(unittest.TestCase):
    def exercise(self):
        context = tempfile.TemporaryDirectory()
        base = Path(context.name)
        var, staging, tools = base/'var', base/'stage', base/'tools'
        for directory in (var/'keybags', var/'lib/olsn0w', staging, tools):
            directory.mkdir(parents=True, exist_ok=True)
        events = base/'events'

        def executable(name, body):
            path = tools/name
            path.write_text('#!/bin/sh\n'+body)
            path.chmod(0o755)
            return path

        executable('guard-target.sh', '[ "$1" = --keybag-init ]\n')
        executable('fixkeybag', 'echo create >> '+shlex.quote(str(events))+'\n'
                   'echo native-keybag > '+shlex.quote(str(var/'keybags/systembag.kb'))+'\n')
        native = executable('keybagd', 'echo "native:$*" >> '+shlex.quote(str(events))+'\n')
        (tools/'target.conf').write_text('AG_GENERATION=checked-generation\nAG_KEYBAG_PROGRAM='
                                         +shlex.quote(str(native))+'\n')

        def archive(path, name, value, compressed=False):
            with tarfile.open(path, 'w:gz' if compressed else 'w') as output:
                item = tarfile.TarInfo(name)
                item.size = len(value)
                output.addfile(item, io.BytesIO(value))

        archive(staging/'data-firstboot.tar.gz', 'first.txt', b'payload', True)
        personalization = staging/'data-personalization.tar'
        personalization.write_bytes(b'invalid')
        source = (ROOT/'target/keybag-start-protected.sh').read_text()
        source = (source.replace('/bin/tar', '/usr/bin/tar')
                  .replace('/usr/local/libexec/olsn0w', str(tools))
                  .replace('/private/var', str(var))
                  .replace('/usr/local/share/olsn0w', str(staging))
                  .replace('/bin/sync', ':'))
        script = base/'start.sh'
        script.write_text(source)
        return context, var, staging, events, personalization, archive, script

    def test_failed_extract_is_retryable_and_existing_keybag_is_preserved(self):
        context, var, staging, events, personal, archive, script = self.exercise()
        with context:
            def run():
                return subprocess.run(['/bin/sh', str(script), '--init'], capture_output=True)

            self.assertNotEqual(run().returncode, 0)
            self.assertEqual((var/'first.txt').read_bytes(), b'payload')
            self.assertFalse((var/'lib/olsn0w/generation').exists())
            self.assertEqual(events.read_text().splitlines(), ['create'])
            archive(personal, 'official.txt', b'activation')
            self.assertEqual(run().returncode, 0)
            self.assertEqual((var/'lib/olsn0w/generation').read_text(), 'checked-generation\n')
            self.assertEqual((var/'official.txt').read_bytes(), b'activation')
            self.assertEqual(events.read_text().splitlines(), ['create', 'native:--init'])
            personal.unlink()
            (staging/'data-firstboot.tar.gz').unlink()
            self.assertEqual(run().returncode, 0)
            self.assertEqual(events.read_text().splitlines(),
                             ['create', 'native:--init', 'native:--init'])


if __name__ == '__main__':
    unittest.main()
