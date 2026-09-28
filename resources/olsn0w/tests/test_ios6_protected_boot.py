"""Exercise the iOS 6 protected first-boot handoff without a device."""
from pathlib import Path
import io
import shlex
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class IOS6ProtectedBoot(unittest.TestCase):
    firstboot_script = 'ios6-firstboot.sh'
    expected_events = ['keybag', 'probe:d', 'probe:d', 'probe:f', 'aquila']

    def test_keybag_precedes_content_and_failed_personalization_blocks_aquila(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            var, staging, tools = base/'var', base/'stage', base/'tools'
            for path in (var/'keybags', var/'lib/olsn0w/fresh-checked-generation',
                         var/'aquila', staging, tools):
                path.mkdir(parents=True)
            events = base/'events'

            def executable(name, body):
                path = tools/name
                path.write_text('#!/bin/sh\n'+body)
                path.chmod(0o755)
                return path

            executable('guard-target.sh',
                       'if [ "${1:-}" = --keybag-init ]; then\n'
                       '  [ -d '+shlex.quote(str(var/'lib/olsn0w/fresh-checked-generation'))+' ]\n'
                       'else\n'
                       '  [ "$(cat '+shlex.quote(str(var/'lib/olsn0w/generation'))
                       +')" = checked-generation ]\nfi\n')
            executable('keybag-init',
                       'echo keybag >> '+shlex.quote(str(events))+'\n'
                       'echo native > '+shlex.quote(str(var/'keybags/systembag.kb'))+'\n')
            executable('protection-probe',
                       'echo "probe:$1" >> '+shlex.quote(str(events))+'\n'
                       '[ -e '+shlex.quote(str(base/'probe-ok'))+' ]\n')
            executable('aquila', 'echo aquila >> '+shlex.quote(str(events))+'\n')
            (tools/'target.conf').write_text('AG_GENERATION=checked-generation\n')

            with tarfile.open(staging/'data-firstboot.tar.gz', 'w:gz') as archive:
                data = b'first-boot-payload'
                item = tarfile.TarInfo('first.txt')
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
            personal = staging/'data-personalization.tar'
            personal.write_bytes(b'invalid')

            def script(name):
                source = (ROOT/'target'/name).read_text()
                source = (source.replace('/bin/tar', '/usr/bin/tar')
                          .replace('/usr/local/libexec/olsn0w', str(tools))
                          .replace('/usr/local/share/olsn0w', str(staging))
                          .replace('/private/var/aquila/aquila', str(tools/'aquila'))
                          .replace('/private/var', str(var))
                          .replace('/bin/sync', ':'))
                path = base/name
                path.write_text(source)
                return path

            firstboot = script(self.firstboot_script)
            aquila = script('ios6-start-aquila.sh')

            def run(path):
                return subprocess.run(['/bin/sh', str(path)], capture_output=True)

            self.assertNotEqual(run(firstboot).returncode, 0)
            self.assertEqual(events.read_text().splitlines(), ['keybag'])
            self.assertFalse((var/'lib/olsn0w/generation').exists())
            self.assertNotEqual(run(aquila).returncode, 0)
            self.assertEqual(events.read_text().splitlines(), ['keybag'])
            with tarfile.open(personal, 'w') as archive:
                data = b'personalization'
                item = tarfile.TarInfo('official.txt')
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
            self.assertNotEqual(run(firstboot).returncode, 0)
            self.assertFalse((var/'lib/olsn0w/generation').exists())
            self.assertNotEqual(run(aquila).returncode, 0)
            (base/'probe-ok').touch()
            self.assertEqual(run(firstboot).returncode, 0)
            self.assertEqual((var/'first.txt').read_bytes(), b'first-boot-payload')
            self.assertEqual((var/'official.txt').read_bytes(), b'personalization')
            self.assertEqual(run(aquila).returncode, 0)
            self.assertEqual(events.read_text().splitlines(),
                             self.expected_events)
            personal.unlink()
            (staging/'data-firstboot.tar.gz').unlink()
            self.assertEqual(run(firstboot).returncode, 0)
            self.assertEqual(events.read_text().splitlines(),
                             self.expected_events)


class IOS5ProtectedBoot(IOS6ProtectedBoot):
    firstboot_script = 'ios5-firstboot.sh'
    expected_events = ['keybag', 'probe:f', 'probe:f', 'aquila']
