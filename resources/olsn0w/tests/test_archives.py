"""Reject ambiguous archive paths before image installation."""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from archives import members, member_path, deb_payload, write_tar, preserve_directory_metadata


def archive(names):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as output:
        for name in names:
            item = tarfile.TarInfo(name)
            item.size = 4
            output.addfile(item, io.BytesIO(b'data'))
    return stream.getvalue()


class PayloadArchives(unittest.TestCase):
    def test_directory_overlay_uses_seed_metadata_without_mutating_original(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'seed.tar'
            original = tarfile.TarInfo('mobile')
            original.type = tarfile.DIRTYPE
            original.mode, original.uid, original.gid = 0o711, 501, 501
            write_tar(path, [(original, None)])
            replacement = tarfile.TarInfo('mobile')
            replacement.type = tarfile.DIRTYPE
            replacement.mode = 0o755
            extra = tarfile.TarInfo('mobile/new')
            extra.type, extra.mode = tarfile.DIRTYPE, 0o700
            entries = {'mobile': (replacement, None), 'mobile/new': (extra, None)}
            self.assertEqual(preserve_directory_metadata(entries, path), ['mobile'])
            item = entries['mobile'][0]
            self.assertEqual((item.mode, item.uid, item.gid), (0o711, 501, 501))
            self.assertEqual((replacement.mode, replacement.uid, replacement.gid),
                             (0o755, 0, 0))
            self.assertIs(entries['mobile/new'][0], extra)

    def test_directory_overlay_rejects_file_or_symlink_ancestor(self):
        for kind in (tarfile.REGTYPE, tarfile.SYMTYPE):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                path = Path(folder)/'seed.tar'
                previous = tarfile.TarInfo('mobile')
                previous.type, previous.linkname = kind, '/elsewhere'
                write_tar(path, [(previous, b'' if kind == tarfile.REGTYPE else None)])
                directory = tarfile.TarInfo('mobile')
                directory.type = tarfile.DIRTYPE
                with self.assertRaisesRegex(ValueError, 'conflicts with Data seed'):
                    preserve_directory_metadata({'mobile': (directory, None)}, path)

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
