"""Check release contents without relying on ignored development files."""
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


KIT = Path(__file__).resolve().parents[3]
TARGET = Path('resources/olsn0w/target')


@unittest.skipUnless(shutil.which('git'), 'Git unavailable')
class PackagedAssets(unittest.TestCase):
    def test_source_archive_includes_target_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            shutil.copyfile(KIT/'.gitignore', folder/'.gitignore')
            shutil.copytree(KIT/TARGET, folder/TARGET,
                            ignore=shutil.ignore_patterns('.DS_Store', '__pycache__'))

            def git(*args):
                return subprocess.run(['git', *args], cwd=folder, check=True,
                                      capture_output=True).stdout

            git('init', '-q')
            git('add', '.')
            tree = git('write-tree').decode().strip()
            with zipfile.ZipFile(io.BytesIO(git('archive', '--format=zip', tree))) as archive:
                for source in (KIT/TARGET).rglob('*.json'):
                    name = source.relative_to(KIT).as_posix()
                    with self.subTest(asset=name):
                        self.assertIn(name, archive.namelist())
                        self.assertEqual(archive.read(name), source.read_bytes())
