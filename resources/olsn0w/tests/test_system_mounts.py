"""Preserve firmware mount policy when relocating the target volumes."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from system import relocate_fstab, uses_protected_data


class TargetMounts(unittest.TestCase):
    def test_only_ios7_and_ios8_use_protected_data_policy(self):
        for release in ('7.1.2', '8.0', '8.1.3', '8.3', '8.4.1'):
            self.assertTrue(uses_protected_data(release), release)
        self.assertFalse(uses_protected_data('6.1.3'))
        self.assertFalse(uses_protected_data('9.3.5'))

    def test_protected_data_keeps_security_options_and_root_policy(self):
        source = (b'/dev/disk0s1 / hfs ro 0 1\n'
                  b'/dev/disk0s2 /private/var hfs rw,nosuid,nodev 0 2\n')
        result = relocate_fstab(source, '/dev/disk0s1s3', '/dev/disk0s1s2', protect_data=True)
        self.assertIn(b'/dev/disk0s1s3 / hfs ro 0 1\n', result)
        self.assertIn(b'hfs rw,nosuid,nodev,protect 0 2\n', result)
        self.assertEqual(relocate_fstab(result, '/dev/disk0s1s3', '/dev/disk0s1s2', protect_data=True), result)
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            relocate_fstab(source.replace(b'rw,nosuid',b'rw,noprotect,nosuid'),
                           '/dev/disk0s1s3', '/dev/disk0s1s2', protect_data=True)

    def test_stock_root_stays_read_only_before_untether(self):
        source = (b'/dev/disk0s1 / hfs ro 0 1\n'
                  b'/dev/disk0s2 /private/var hfs rw,nosuid,nodev 0 2\n')
        self.assertEqual(relocate_fstab(source, '/dev/disk0s1s3', '/dev/disk0s1s2'),
                         b'/dev/disk0s1s3 / hfs ro 0 1\n'
                         b'/dev/disk0s1s2 /private/var hfs rw,nosuid,nodev 0 2\n')

    def test_other_policies_and_unrelated_entries_are_preserved(self):
        source = (b'# firmware policy\n/dev/disk0s1s1 / hfs rw 0 1\n'
                  b'/dev/disk0s1s2 /private/var hfs rw,nodev 0 2\n'
                  b'/dev/disk1s1 /extra hfs ro 0 0\n')
        result = relocate_fstab(source, '/dev/disk0s3', '/dev/disk0s4')
        self.assertEqual(result, source.replace(b'/dev/disk0s1s1', b'/dev/disk0s3')
                         .replace(b'/dev/disk0s1s2', b'/dev/disk0s4'))

    def test_incomplete_or_ambiguous_mounts_are_rejected(self):
        root = b'/dev/disk0s1 / hfs ro 0 1\n'
        data = b'/dev/disk0s2 /private/var hfs rw 0 2\n'
        for content in (root, data, root+root+data, root+data.replace(b'hfs', b'apfs')):
            with self.subTest(content=content), self.assertRaises(ValueError):
                relocate_fstab(content, '/dev/disk0s3', '/dev/disk0s4')


if __name__ == '__main__':
    unittest.main()
