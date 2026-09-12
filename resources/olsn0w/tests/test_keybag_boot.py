"""Cover early boot admission and native keybag argument forwarding."""
from pathlib import Path
import plistlib
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from system import (early_keybag_job, uses_legacy_job_loader,
                    uses_protected_keybag_start, wraps_early_keybag)


class EarlyKeybag(unittest.TestCase):
    def test_ios7_and_ios8_run_protected_seed_from_keybag_job(self):
        for release in ('7.0', '7.1.2', '8.0', '8.1.3', '8.3', '8.4.1'):
            self.assertTrue(uses_protected_keybag_start(release), release)
        self.assertFalse(uses_protected_keybag_start('6.1.3'))

    def test_supported_untethers_use_batch_loader_and_ios8_uses_early_keybagd(self):
        job = dict(Program='/usr/libexec/keybagd', ProgramArguments=['keybagd', '--init'])
        launchd = plistlib.dumps(dict(Boot=dict(keybag=job)))
        for release in ('8.0', '8.1.3', '8.3', '8.4.1'):
            self.assertTrue(uses_legacy_job_loader(release))
            self.assertFalse(wraps_early_keybag(release, launchd))
        self.assertTrue(uses_legacy_job_loader('7.1.2'))
        self.assertFalse(uses_legacy_job_loader('6.1.3'))
        self.assertTrue(wraps_early_keybag('7.1.2', launchd))

    def test_embedded_boot_job_is_distinct_from_normal_services(self):
        job = dict(Program='/usr/libexec/keybagd', ProgramArguments=['keybagd', '--init'])
        document = plistlib.dumps(dict(Boot=dict(keybag=job)))
        self.assertTrue(early_keybag_job(b'\xce\xfa\xed\xfe\0'+document+b'\0'))
        self.assertTrue(early_keybag_job(b'<?xml version="%s"?>\0other string\0'+document))
        self.assertFalse(early_keybag_job(b'legacy launchd'))
        self.assertFalse(early_keybag_job(plistlib.dumps(dict(Services=dict(keybag=job)))))
        with self.assertRaises(ValueError):
            early_keybag_job(document+b'\0'+document)
        for key, value in [('Program', '/different'), ('ProgramArguments', ['keybagd'])]:
            altered = dict(job, **{key: value})
            with self.assertRaises(ValueError):
                early_keybag_job(plistlib.dumps(dict(Boot=dict(keybag=altered))))

    def exercise(self, *, existing=False, guard=0, create=0):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            events, bag = base/'events', base/'systembag.kb'
            if existing:
                bag.write_text('existing keybag')
            def executable(name, body):
                path = base/name
                path.write_text('#!/bin/sh\n'+body+'\n')
                path.chmod(0o755)
                return path
            quote = shlex.quote
            def record(name):
                return 'echo '+name+' >> '+quote(str(events))+'\n'
            guard_path = executable('guard', record('guard')+'exit '+str(guard))
            helper = executable('create', record('create')+('exit '+str(create) if create else 'echo created > '+quote(str(bag))))
            sync = executable('sync', record('sync'))
            native = executable('native', 'printf "native:%s\\n" "$*" >> '+quote(str(events)))
            config = base/'target.conf'
            config.write_text('AG_KEYBAG_PROGRAM='+quote(str(native))+'\n')
            text = (ROOT/'target/keybag-start.sh').read_text()
            for old, new in [('/usr/local/libexec/olsn0w/guard-target.sh',guard_path),
                             ('/usr/local/libexec/olsn0w/target.conf',config),
                             ('/usr/local/libexec/olsn0w/fixkeybag',helper),
                             ('/private/var/keybags/systembag.kb',bag),('/bin/sync',sync)]:
                text = text.replace(old, quote(str(new)))
            script = base/'start.sh'; script.write_text(text)
            result = subprocess.run(['sh',str(script),'--init'],capture_output=True)
            return result.returncode, events.read_text().splitlines(), bag.read_text() if bag.exists() else None

    def test_missing_keybag_is_created_before_native_init(self):
        code, events, bag = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual(events, ['guard','create','sync','native:--init'])
        self.assertEqual(bag, 'created\n')

    def test_existing_keybag_is_never_replaced(self):
        code, events, bag = self.exercise(existing=True)
        self.assertEqual((code,events,bag), (0,['guard','native:--init'],'existing keybag'))

    def test_wrong_target_or_failed_creation_never_starts_native(self):
        self.assertEqual(self.exercise(guard=81)[:2], (81,['guard']))
        self.assertEqual(self.exercise(create=7)[:2], (7,['guard','create']))
