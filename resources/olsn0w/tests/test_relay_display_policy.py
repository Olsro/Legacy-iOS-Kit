"""Graphical normal boots and explicit diagnostics share one SoC-independent policy."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootchain


class RelayDisplayPolicy(unittest.TestCase):
    def test_normal_arguments_keep_root_and_admission_without_diagnostics(self):
        self.assertEqual(bootchain.target_bootargs(),
                         'rd=disk0s1s3 amfi=0xff cs_enforcement_disable=1')
        self.assertNotIn('-v', bootchain.target_bootargs().split())
        self.assertNotIn('debug=', bootchain.target_bootargs())

    def test_explicit_verbose_keeps_diagnostics_without_touching_display(self):
        self.assertEqual(bootchain.target_bootargs(verbose=True),
                         bootchain.target_bootargs() + ' -v debug=0x14e')
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(bootchain.logo, 'discover') as discover:
            out = Path(directory)
            data, params = bootchain.prepare_display(b'original', out, verbose=True)
            self.assertEqual(data, b'original')
            self.assertIsNone(params)
            discover.assert_not_called()
            self.assertEqual(json.loads((out/'display-validation.json').read_text()),
                             {'mode': 'verbose', 'logo_hook': False})
            self.assertFalse((out/'stub.bin').exists())

    def test_normal_display_applies_and_validates_the_graphical_hook(self):
        params = {'fixture': True}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(bootchain.logo, 'discover', return_value=params) as discover, \
                patch.object(bootchain.logo, 'trampoline', return_value=b'code') as trampoline, \
                patch.object(bootchain.logo, 'apply', return_value=b'patched') as apply, \
                patch.object(bootchain, 'display', return_value={'checked': True}) as validate:
            out = Path(directory)
            self.assertEqual(bootchain.prepare_display(b'original', out), (b'patched', params))
            discover.assert_called_once_with(b'original', bootchain.logo.digest(b'original'), 0x2a0)
            trampoline.assert_called_once_with(params)
            apply.assert_called_once_with(b'original', params, b'code')
            validate.assert_called_once_with(b'patched', params)
            self.assertEqual((out/'stub.bin').read_bytes(), b'code')
            self.assertEqual((out/'iBEC.before-logo.raw').read_bytes(), b'original')

    def test_unknown_graphical_recipe_is_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(bootchain.logo, 'discover', side_effect=ValueError('shape')):
            with self.assertRaisesRegex(ValueError, 'shape'):
                bootchain.prepare_display(b'unknown', Path(directory))


if __name__ == '__main__':
    unittest.main()
