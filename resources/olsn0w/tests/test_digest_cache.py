"""Repeated checks reuse hashes, while changed files are always read again."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import common
from restore import checked_manifest


class DigestCache(unittest.TestCase):
    def setUp(self):
        common._DIGEST_CACHE.clear()
        self.addCleanup(common._DIGEST_CACHE.clear)
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.path = self.root/'image'
        self.path.write_bytes(b'original payload')

    def test_repeated_manifest_checks_read_unchanged_file_once(self):
        expected = hashlib.sha256(self.path.read_bytes()).hexdigest()
        (self.root/'manifest.json').write_text(json.dumps(dict(files={'image':expected})))
        with patch.object(common.hashlib, 'new', wraps=hashlib.new) as hash_file:
            checked_manifest(self.root)
            checked_manifest(self.root)
        self.assertEqual(hash_file.call_count, 1)

    def test_same_size_change_with_restored_mtime_is_still_rehashed(self):
        before = self.path.stat()
        old = common.digest(self.path)
        self.path.write_bytes(b'changed! payload')
        os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.path.stat().st_size, before.st_size)
        self.assertNotEqual(common.digest(self.path), old)

    def test_replaced_or_deleted_path_does_not_reuse_previous_contents(self):
        before = self.path.stat()
        old = common.digest(self.path)
        replacement = self.root/'replacement'
        replacement.write_bytes(b'changed! payload')
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        replacement.replace(self.path)
        self.assertNotEqual(common.digest(self.path), old)
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):
            common.digest(self.path)

    def test_algorithms_have_independent_cache_entries(self):
        for algorithm in ('sha1', 'sha256', 'sha1', 'sha256'):
            self.assertEqual(common.digest(self.path, algorithm),
                             hashlib.new(algorithm, self.path.read_bytes()).hexdigest())

    def test_ipsw_sha1_and_sha256_are_computed_in_one_read(self):
        with patch.object(common, 'activity', wraps=common.activity) as read:
            sha1 = common.digest(self.path, 'sha1')
            sha256 = common.digest(self.path, 'sha256')
            common.digest(self.path, 'sha1')
            common.digest(self.path, 'sha256')
        self.assertEqual(read.call_count, 1)
        self.assertEqual(sha1, hashlib.sha1(self.path.read_bytes()).hexdigest())
        self.assertEqual(sha256, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_concurrent_mutation_does_not_publish_a_checksum(self):
        @contextmanager
        def activity(*args):
            def mutate(*args):
                self.path.write_bytes(b'changed! payload')
            yield mutate
        with patch.object(common, 'activity', activity):
            with self.assertRaisesRegex(ValueError, 'changed during integrity verification'):
                common.digest(self.path)
        self.assertFalse(common._DIGEST_CACHE)

    def test_changed_component_is_still_rejected_after_successful_verification(self):
        expected = common.digest(self.path)
        (self.root/'manifest.json').write_text(json.dumps(dict(files={'image':expected})))
        checked_manifest(self.root)
        self.path.write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'Prepared component changed'):
            checked_manifest(self.root)
