"""Native libusb must load without relying on Homebrew or enumerating devices."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import usb_backend


class USBBackend(unittest.TestCase):
    def test_explicit_private_backend_is_returned_without_device_enumeration(self):
        backend = object()
        with patch('libusb_package.get_libusb1_backend', return_value=backend) as load, \
             patch('usb.core.find') as find:
            self.assertIs(usb_backend.get_backend(), backend)
        load.assert_called_once()
        find.assert_not_called()

    def test_missing_native_backend_has_a_repair_message(self):
        with patch('libusb_package.get_libusb1_backend', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'private libusb.*setup.sh'):
                usb_backend.get_backend()

    def test_missing_package_or_unloadable_library_preserves_the_cause(self):
        for error in (ImportError('missing package'), OSError('wrong architecture')):
            with self.subTest(error=str(error)), \
                 patch('libusb_package.get_libusb1_backend', side_effect=error):
                with self.assertRaisesRegex(RuntimeError, str(error)):
                    usb_backend.get_backend()
