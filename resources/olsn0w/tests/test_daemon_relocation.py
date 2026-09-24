"""Relocation must preserve all checked first-boot overlay services."""
import plistlib
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import system


class DaemonRelocation(unittest.TestCase):
    def image(self, jobs):
        image = Mock()
        library = '/Library/LaunchDaemons/'
        native = '/System/Library/LaunchDaemons/'
        files = {library + name: content for name, content in jobs.items()}
        files[native + 'com.apple.CrashHousekeeping.plist'] = plistlib.dumps({
            'Label': 'com.apple.CrashHousekeeping',
            'Program': '/usr/libexec/CrashHousekeeping'})
        files['/usr/libexec/CrashHousekeeping'] = b'stock binary'
        image.ls.side_effect = lambda path: [
            {'name': Path(name).name, 'mode': stat.S_IFREG | 0o755}
            for name in files if str(Path(name).parent) == path]
        image.read.side_effect = lambda path: files[path]
        image.add.side_effect = lambda path, data, *args: files.__setitem__(path, data)
        image.readlink.return_value = '/everuntether'
        return image, files

    def jobs(self, bypass=False):
        jobs = {'com.saurik.Cydia.Startup.plist': b'cydia',
                'org.olsn0w.boot-success.plist': b'boot success'}
        if bypass:
            jobs['org.legacyioskit.hacktiv8.plist'] = b'hacktiv8'
        return jobs

    def test_preserves_normal_and_bypass_firstboot_jobs(self):
        for bypass in (False, True):
            with self.subTest(bypass=bypass):
                jobs = self.jobs(bypass)
                image, files = self.image(jobs)
                system.move_daemons(image, 8, 'iPhone4,1', 'everuntether', library_jobs=jobs)
                for name, content in jobs.items():
                    self.assertEqual(files['/Library/LaunchDaemons/'+name], content)

    def test_rejects_unknown_missing_or_modified_jobs_before_mutation(self):
        for case in ('extra', 'missing', 'changed', 'collision', 'directory'):
            with self.subTest(case=case):
                jobs = self.jobs()
                image, files = self.image(jobs)
                path = '/Library/LaunchDaemons/org.olsn0w.boot-success.plist'
                if case == 'extra':
                    files['/Library/LaunchDaemons/unknown.plist'] = b'unknown'
                elif case == 'missing':
                    del files[path]
                elif case == 'changed':
                    files[path] = b'changed'
                elif case == 'collision':
                    files['/System/Library/LaunchDaemons/org.olsn0w.boot-success.plist'] = b'collision'
                else:
                    image.ls.side_effect = lambda path: [
                        {'name': name, 'mode': stat.S_IFDIR | 0o755} for name in jobs]
                with self.assertRaises(ValueError):
                    system.move_daemons(image, 8, 'iPhone4,1', 'everuntether', library_jobs=jobs)
                image.command.assert_not_called()
                image.add.assert_not_called()


if __name__ == '__main__':
    unittest.main()
