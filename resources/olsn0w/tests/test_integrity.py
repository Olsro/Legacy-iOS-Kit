"""Checksum failures preserve evidence and still block invalid preparation."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compact_cache import materialize, prepare
from integrity import require_bytes, require_same_file


class PreparationIntegrity(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)

    def test_valid_bytes_do_not_create_a_report(self):
        report = self.root/'report.json'
        require_bytes(b'qualified', hashlib.sha256(b'qualified').hexdigest(), 'cache', report)
        self.assertFalse(report.exists())

    def test_cache_failure_records_actual_output_and_recipe_without_publishing_it(self):
        source = self.root/'stock'
        source.write_bytes(b'stock')
        recipe = dict(format=1, bootstrap_build='12H321', source_bytes=5,
                      source_sha256=hashlib.sha256(b'stock').hexdigest(),
                      output_bytes=8, output_sha256='0'*64,
                      copy_ranges=[[0, 0, 5]], metadata_patches=[])
        # Exercise the prepare() call site, including the diagnostic path.
        with patch('compact_cache.qualified_source', return_value=dict(
                sha256=recipe['source_sha256'], build='12H321')), \
                patch('compact_cache.Path.glob', return_value=[
                    Path(__file__).resolve().parents[1]/'recipes/dyld-armv7s-12H321.recipe']), \
                patch('compact_cache.json.loads', return_value=recipe):
            destination = self.root/'new'/'cache'
            with self.assertRaisesRegex(ValueError, 'Reproduced cache checksum mismatch') as error:
                prepare(source, destination)
        self.assertFalse(destination.exists())
        report_path = destination.with_name('cache.integrity.json')
        report = json.loads(report_path.read_text())
        self.assertEqual(report['expected_sha256'], '0'*64)
        self.assertEqual(report['actual_sha256'], hashlib.sha256(b'stock\0\0\0').hexdigest())
        self.assertEqual(report['actual_bytes'], 8)
        self.assertEqual(report['source_sha256'], recipe['source_sha256'])
        self.assertEqual(len(report['recipe_sha256']), 64)
        self.assertTrue({'python', 'openssl', 'system', 'release', 'machine'} <= report['host'].keys())
        self.assertIn(str(report_path), str(error.exception))
        self.assertIn(report['actual_sha256'], str(error.exception))

    def test_materialize_remains_usable_without_a_diagnostic_destination(self):
        recipe = dict(format=1, source_bytes=3,
                      source_sha256=hashlib.sha256(b'abc').hexdigest(), output_bytes=3,
                      output_sha256=hashlib.sha256(b'abc').hexdigest(),
                      copy_ranges=[[0, 0, 3]], metadata_patches=[])
        self.assertEqual(materialize(b'abc', recipe), b'abc')
        recipe['output_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'Expected SHA-256: '+('0'*64)):
            materialize(b'abc', recipe)

    def test_image_difference_reports_offset_and_sizes_without_modifying_inputs(self):
        # Cross a read boundary and include equal-length corruption, truncation,
        # and appended zeros: none may be accepted as an equivalent filesystem.
        prefix = b'\0'*(1024**2+13)
        expected = self.root/'stock.hfs'
        actual = self.root/'verified.hfs'
        tool = self.root/'dmg'
        tool.write_bytes(b'extractor fixture')
        expected.write_bytes(prefix+b'original')
        for suffix, difference in ((b'changed!', 0), (b'orig', 4), (b'original\0', 8)):
            with self.subTest(suffix=suffix):
                actual.write_bytes(prefix+suffix)
                report_path = self.root/'system-integrity.json'
                with self.assertRaisesRegex(ValueError, 'ASR image differs'):
                    require_same_file(expected, actual, 'ASR image differs', report_path,
                                      inputs=dict(dmg_tool=tool))
                report = json.loads(report_path.read_text())
                self.assertEqual(report['first_difference'], len(prefix)+difference)
                self.assertEqual(report['expected_bytes'], len(prefix)+8)
                self.assertEqual(report['actual_bytes'], len(prefix)+len(suffix))
                self.assertEqual(report['actual_path'], str(actual.resolve()))
                self.assertEqual(report['inputs']['dmg_tool'], dict(
                    path=str(tool.resolve()), bytes=17,
                    sha256=hashlib.sha256(b'extractor fixture').hexdigest()))
                self.assertNotIn('extractor fixture', report_path.read_text())
                self.assertEqual(expected.read_bytes(), prefix+b'original')
                self.assertEqual(actual.read_bytes(), prefix+suffix)

    def test_equal_images_pass_without_diagnostics(self):
        expected, actual, report = (self.root/name for name in ('stock', 'verified', 'report'))
        expected.write_bytes(b'filesystem')
        actual.write_bytes(b'filesystem')
        require_same_file(expected, actual, 'ASR image differs', report)
        self.assertFalse(report.exists())

    def test_report_write_failure_does_not_hide_integrity_failure(self):
        with patch('integrity.save', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(ValueError, 'cache differs') as error:
                require_bytes(b'changed', '0'*64, 'cache differs', self.root/'report')
        self.assertIn('Actual SHA-256:', str(error.exception))
        self.assertIn('disk full', str(error.exception))
