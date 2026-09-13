import plistlib
import sys
import tarfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from system import (jailbreak_payload, pangu_startup_job,
                    untether_jetsam_properties, uses_legacy_job_loader)


class IOS7Jetsam(unittest.TestCase):
    def test_untether_gets_explicit_memory_budget_without_losing_board_defaults(self):
        source={'Version':3,'Defaults':{'com.apple.SpringBoard':{'JetsamMemoryLimit':200}}}
        for label in ('com.apple.CrashHousekeeping', 'io.pangu.axe.untether'):
            result=plistlib.loads(untether_jetsam_properties(plistlib.dumps(source), label))
            self.assertEqual(result['Defaults']['com.apple.SpringBoard'],
                             {'JetsamMemoryLimit':200})
            self.assertEqual(result['Defaults'][label],
                             {'JetsamPriority':18,'JetsamMemoryLimit':128})

    def test_unknown_schema_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'jetsam'):
            untether_jetsam_properties(plistlib.dumps({'Version':2,'Defaults':{}}),
                                       'com.apple.CrashHousekeeping')

    def test_ios71_uses_bundled_pangu_while_ios70_keeps_aquila(self):
        payload, provenance = jailbreak_payload('7.1.2')
        self.assertIn('panguaxe', payload)
        self.assertNotIn('aquila', payload)
        self.assertNotIn('usr/lib/libmis.dylib', payload)
        self.assertNotIn('System/Library/Caches/com.apple.dyld/enable-dylibs-to-override-cache',
                         payload)
        self.assertNotIn('System/Library/Caches/com.apple.xpcd/xpcd_cache.dylib', payload)
        self.assertNotIn('System/Library/Caches/com.apple.xpcd/xpcd_cache.ipod.dylib', payload)
        self.assertIn('resources/jailbreak/panguaxe.tar',
                      {item['path'] for item in provenance})
        payload, provenance = jailbreak_payload('7.0.6')
        self.assertIn('aquila', payload)
        self.assertNotIn('panguaxe', payload)

    def test_bundled_pangu_admission_overrides_are_intentionally_excluded(self):
        archive=Path(__file__).resolve().parents[2]/'jailbreak/panguaxe.tar'
        with tarfile.open(archive) as payload:
            mis=payload.extractfile('usr/lib/libmis.dylib').read()
            cache=payload.extractfile(
                'System/Library/Caches/com.apple.xpcd/xpcd_cache.dylib').read()
            marker=payload.extractfile(
                'System/Library/Caches/com.apple.dyld/enable-dylibs-to-override-cache').read()
        self.assertIn(b'/usr/lib/libmis.dylib\0', mis)
        self.assertNotIn(b'_MISEnumerateInstalledProvisioningProfiles', mis)
        self.assertIn(b'__xpcd_cache', cache)
        self.assertIn(b'io.pangu.axe.untether', cache)
        self.assertEqual(marker, b'')
        prepared, _ = jailbreak_payload('7.1.2')
        for name in ('usr/lib/libmis.dylib',
                     'System/Library/Caches/com.apple.xpcd/xpcd_cache.dylib',
                     'System/Library/Caches/com.apple.xpcd/xpcd_cache.ipod.dylib',
                     'System/Library/Caches/com.apple.dyld/enable-dylibs-to-override-cache'):
            self.assertNotIn(name, prepared)

    def test_pangu_keeps_native_job_and_uses_guarded_loader(self):
        archive=Path(__file__).resolve().parents[2]/'jailbreak/panguaxe.tar'
        with tarfile.open(archive) as payload:
            original=payload.extractfile(
                'System/Library/LaunchDaemons/io.pangu.axe.untether.plist').read()
        job=plistlib.loads(pangu_startup_job(original))
        self.assertEqual(job['ProgramArguments'], ['/panguaxe'])
        self.assertTrue(job['LaunchOnlyOnce'])
        self.assertNotIn('AbandonProcessGroup', job)
        self.assertEqual(job['StandardOutPath'],
                         '/var/logs/AppleSupport/olsn0w-untether.log')
        self.assertTrue(uses_legacy_job_loader('7.1.2', 'panguaxe'))
        self.assertTrue(uses_legacy_job_loader('7.0.6', 'aquila'))
        self.assertTrue(uses_legacy_job_loader('8.3', 'everuntether'))
