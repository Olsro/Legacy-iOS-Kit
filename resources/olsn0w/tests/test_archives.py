"""Reject ambiguous archive paths before image installation."""
import io
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from archives import members, member_path, deb_payload


def archive(names):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as output:
        for name in names:
            item = tarfile.TarInfo(name)
            item.size = 4
            output.addfile(item, io.BytesIO(b'data'))
    return stream.getvalue()


class PayloadArchives(unittest.TestCase):
    def test_paths_and_duplicates(self):
        for name in ('/absolute', '../escape', 'etc/../escape', 'a\0b'):
            with self.assertRaises(ValueError):
                member_path(name)
        with self.assertRaises(ValueError):
            list(members(archive(['./etc/item', 'etc/item'])))
        self.assertEqual(list(members(archive(['./etc/item'])))[0][1], b'data')

    def test_deb_truncation_and_missing_payload(self):
        for data in (b'', b'!<arch>\n', b'!<arch>\nshort'):
            with self.assertRaises(ValueError):
                deb_payload(data)
