"""Keep target-kernel workarounds exact, reproducible and model-qualified."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import kernelcache


class TargetKernelTests(unittest.TestCase):
    def test_p101_tristar_fallback_is_only_qualified_for_exact_ios6_kernels(self):
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

    def test_cellular_mini_covers_all_released_ios6_builds_with_exact_identities(self):
        builds = (('6.0.1', '10A8426'), ('6.0.2', '10A8500'), ('6.1', '10B141'),
                  ('6.1.2', '10B147'), ('6.1.3', '10B329'))
        for release, build in builds:
            p106, p107 = [kernelcache.qualified_patch(dict(product=product, version=release, build=build))
                          for product in ('iPad2,6', 'iPad2,7')]
            self.assertIsNotNone(p106); self.assertIsNotNone(p107)
            for key in ('raw_sha256', 'patched_sha256', 'offset', 'virtual_address', 'before', 'after'):
                self.assertEqual(p106[key], p107[key])
            self.assertEqual(p106['validation'], 'exact-structural-match')
            self.assertEqual(p107['validation'], 'physical-mac-and-charger-cold-boot-lockscreen'
                             if build == '10B329' else 'exact-structural-match')
        source = dict(product='iPad2,7', version='6.1.3', build='10B329')
        for changed in (
                dict(source, product='iPad2,4'),
                dict(source, version='6.0', build='10A403'),
                dict(source, version='6.1.2', build='10B146'),
                dict(source, product='iPad2,6', version='6.1.2', build='10B146'),
                dict(source, version='6.1.3', build='unexpected'),
                dict(source, version='7.1.2', build='11D257')):
            with self.subTest(source=changed):
                self.assertIsNone(kernelcache.qualified_patch(changed))

    def test_wifi_mini_covers_all_released_ios6_builds_with_its_own_kernels(self):
        builds = (('6.0', '10A406'), ('6.0.1', '10A523'), ('6.0.2', '10A550'),
                  ('6.1', '10B141'), ('6.1.2', '10B146'), ('6.1.3', '10B329'))
        for release, build in builds:
            with self.subTest(release=release):
                p105 = kernelcache.qualified_patch(dict(product='iPad2,5', version=release, build=build))
                self.assertEqual(p105['name'], 'tristar-system-id-retry-fallback')
                self.assertEqual((p105['before'], p105['after']), ('10e0', '86b1'))
                self.assertEqual(p105['validation'], 'exact-structural-match')
        # P105 6.1.3 is a different kernel from the qualified P107 6.1.3 one.
        self.assertNotEqual(
            kernelcache.qualified_patch(dict(product='iPad2,5', version='6.1.3', build='10B329'))['raw_sha256'],
            kernelcache.qualified_patch(dict(product='iPad2,7', version='6.1.3', build='10B329'))['raw_sha256'])
        for changed in (
                dict(product='iPad2,5', version='6.0.1', build='10A8426'),
                dict(product='iPad2,5', version='6.1.2', build='10B147'),
                dict(product='iPad2,5', version='6.1.3', build='unexpected'),
                dict(product='iPad2,5', version='7.1.2', build='11D257'),
                dict(product='iPad2,5', version='8.3', build='12F69')):
            with self.subTest(source=changed):
                self.assertIsNone(kernelcache.qualified_patch(changed))

    def test_mini_runtime_pins_match_the_recorded_kernel_audits(self):
        evidence = json.loads((Path(kernelcache.__file__).parent/'recipes/tristar-mini-ios6.recipe').read_text())
        identities = set()
        for entry in evidence['entries']:
            source, audit = entry['source'], entry['audit']
            identity = source['product'], source['version'], source['build']
            self.assertNotIn(identity, identities); identities.add(identity)
            runtime = kernelcache.qualified_patch(source)
            self.assertEqual(source['raw_sha256'], audit['patch']['raw_sha256'])
            for key, value in audit['patch'].items():
                if key != 'validation':
                    self.assertEqual(runtime[key], value)
            self.assertEqual(audit['executable_bytes'], 184)
            self.assertEqual(audit['literal_references_verified'], 5)
            self.assertTrue(audit['virtual_method_entry_verified'])
            self.assertTrue(entry['packed_readback_verified'])
            self.assertEqual(entry['installed_patch']['validation'], runtime['validation'])
            self.assertTrue(source['ipsw_url'].startswith('https://secure-appldnld.apple.com/'))
        qualified = {key for key in kernelcache.PATCHES if key[0] in ('iPad2,5', 'iPad2,6', 'iPad2,7')}
        self.assertEqual(identities, qualified)
        self.assertEqual(len(identities), 16)

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
