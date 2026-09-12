"""Keep target-kernel workarounds exact, reproducible and model-qualified."""
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import kernelcache


class TargetKernelTests(unittest.TestCase):
    def test_tristar_fallback_is_only_qualified_for_exact_p101_ios6_kernels(self):
        for release, build in (('6.0', '10A407'), ('6.0.1', '10A523'),
                               ('6.1', '10B141'), ('6.1.2', '10B146'),
                               ('6.1.3', '10B329')):
            source = dict(product='iPad3,4', version=release, build=build)
            self.assertEqual(kernelcache.qualified_patch(source)['name'],
                             'tristar-system-id-retry-fallback')
        for changed in (
                dict(product='iPad3,5', version='6.1.3', build='10B329'),
                dict(product='iPad3,4', version='7.1.2', build='11D257'),
                dict(product='iPad3,4', version='6.0', build='unexpected'),
                dict(product='iPad3,4', version='6.1.2', build='unexpected'),
                dict(product='iPad3,4', version='6.1.3', build='unexpected')):
            self.assertIsNone(kernelcache.qualified_patch(changed))

    def test_apply_changes_only_the_retry_result_branch(self):
        original = b'prefix' + bytes.fromhex('10e0') + b'suffix'
        expected = b'prefix' + bytes.fromhex('86b1') + b'suffix'
        patch = dict(name='test', offset=6, virtual_address=0x1234,
                     before='10e0', after='86b1', validation='unit-test',
                     raw_sha256=hashlib.sha256(original).hexdigest(),
                     patched_sha256=hashlib.sha256(expected).hexdigest())
        result, report = kernelcache.apply(original, patch)
        self.assertEqual(result, expected)
        self.assertEqual(report['offset'], 6)
        self.assertEqual(len(result), len(original))

    def test_apply_rejects_unqualified_input_and_patch_site(self):
        original = b'prefix' + bytes.fromhex('10e0') + b'suffix'
        patch = dict(name='test', offset=6, virtual_address=0x1234,
                     before='10e0', after='86b1', validation='unit-test',
                     raw_sha256='0'*64, patched_sha256='0'*64)
        with self.assertRaisesRegex(ValueError, 'kernel differs'):
            kernelcache.apply(original, patch)
        patch['raw_sha256'] = hashlib.sha256(original).hexdigest()
        patch['before'] = 'ffff'
        with self.assertRaisesRegex(ValueError, 'patch site differs'):
            kernelcache.apply(original, patch)


if __name__ == '__main__':
    unittest.main()
