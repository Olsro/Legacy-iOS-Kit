"""No plaintext file contents may precede the target's protection initialization."""
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from system import entry, protected_data_seed


class ProtectedSeed(unittest.TestCase):
    def test_contents_and_generation_are_deferred(self):
        generation = str(uuid.uuid4())
        link = tarfile.TarInfo('tmp')
        link.type, link.linkname = tarfile.SYMTYPE, 'mobile/tmp'
        entries = dict([
            ('lib/olsn0w/generation', entry('lib/olsn0w/generation', (generation+'\n').encode())),
            ('mobile', entry('mobile', mode=0o755, uid=501, gid=501, directory=True)),
            ('mobile/payload', entry('mobile/payload', b'private contents', uid=501, gid=501)),
            ('tmp', (link, None)),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'firstboot.tar.gz'
            seed = protected_data_seed(entries, generation, path)
            self.assertTrue(all(m.isdir() or m.issym() for m, _ in seed.values()))
            self.assertEqual(seed['mobile'][0].uid, 501)
            self.assertIn('lib/olsn0w/fresh-'+generation, seed)
            with tarfile.open(path) as archive:
                self.assertNotIn('lib/olsn0w/generation', archive.getnames())
                self.assertEqual(archive.extractfile('mobile/payload').read(), b'private contents')
                self.assertEqual(archive.getmember('mobile/payload').uid, 501)
