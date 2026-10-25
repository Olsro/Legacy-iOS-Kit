"""USB acknowledgement failures are distinguishable from identity failures."""
import ctypes as C
from pathlib import Path
import plistlib
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from activation import ActivationAcknowledgementPending, acknowledge


class ActivationAcknowledgement(unittest.TestCase):
    udid = 'a'*40
    identity = dict(product='iPod5,1', ecid=123)

    def setUp(self):
        self.mobile, self.plist, self.allocator = Mock(), Mock(), Mock()
        self.values = dict(UniqueChipID=123, ProductType='iPod5,1',
                           ActivationState='Activated', ActivationStateAcknowledged=True)
        self.buffers = []

        def open_device(device, udid, options):
            device._obj.value = 1
            return 0

        def open_client(device, client, label):
            client._obj.value = 2
            return 0

        def get_value(client, domain, key, node):
            self.key = key.decode()
            node._obj.value = 3
            return 0

        def to_xml(node, xml, size):
            data = plistlib.dumps(self.values[self.key])
            buffer = C.create_string_buffer(data)
            self.buffers.append(buffer)
            xml._obj.value = C.addressof(buffer)
            size._obj.value = len(data)

        self.mobile.idevice_new_with_options.side_effect = open_device
        self.mobile.lockdownd_client_new_with_handshake.side_effect = open_client
        self.mobile.lockdownd_get_value.side_effect = get_value
        self.mobile.lockdownd_set_value.return_value = 0
        self.plist.plist_new_bool.return_value = 4
        self.plist.plist_to_xml.side_effect = to_xml
        for patcher in (patch('activation.library', side_effect=[self.mobile, self.plist]),
                        patch('activation.C.CDLL', return_value=self.allocator)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_matching_activated_device_is_acknowledged_and_read_back(self):
        self.assertEqual(acknowledge(self.udid, self.identity),
                         dict(activation_state='Activated', acknowledged=True))
        self.assertEqual(self.mobile.idevice_new_with_options.call_args.args[1:],
                         (self.udid.encode(), 2))
        self.assertEqual(self.mobile.lockdownd_set_value.call_args.args[1:],
                         (None, b'ActivationStateAcknowledged', 4))
        self.assertEqual(self.plist.plist_free.call_count, 4)
        self.mobile.lockdownd_client_free.assert_called_once()
        self.mobile.idevice_free.assert_called_once()

    def test_handshake_failure_keeps_native_code_and_releases_handles(self):
        self.mobile.lockdownd_client_new_with_handshake.side_effect = None
        self.mobile.lockdownd_client_new_with_handshake.return_value = -5
        with self.assertRaisesRegex(ActivationAcknowledgementPending, 'handshake.*-5'):
            acknowledge(self.udid, self.identity)
        self.mobile.lockdownd_set_value.assert_not_called()
        self.mobile.idevice_free.assert_called_once()

    def test_unavailable_device_keeps_native_code(self):
        self.mobile.idevice_new_with_options.side_effect = None
        self.mobile.idevice_new_with_options.return_value = -3
        with self.assertRaisesRegex(ActivationAcknowledgementPending, 'idevice error -3'):
            acknowledge(self.udid, self.identity)
        self.mobile.lockdownd_client_new_with_handshake.assert_not_called()

    def test_foreign_identity_is_terminal_and_never_written(self):
        self.values['UniqueChipID'] = 456
        with self.assertRaisesRegex(ValueError, 'another device'):
            acknowledge(self.udid, self.identity)
        self.mobile.lockdownd_set_value.assert_not_called()
        self.mobile.lockdownd_client_free.assert_called_once()
        self.mobile.idevice_free.assert_called_once()

    def test_read_failure_is_retryable_and_keeps_native_code(self):
        self.mobile.lockdownd_get_value.side_effect = None
        self.mobile.lockdownd_get_value.return_value = -8
        with self.assertRaisesRegex(ActivationAcknowledgementPending, 'UniqueChipID.*-8'):
            acknowledge(self.udid, self.identity)
        self.mobile.lockdownd_set_value.assert_not_called()

    def test_write_failure_is_retryable_and_keeps_native_code(self):
        self.mobile.lockdownd_set_value.return_value = -8
        with self.assertRaisesRegex(ActivationAcknowledgementPending, 'lockdownd error -8'):
            acknowledge(self.udid, self.identity)

    def test_successful_write_requires_true_readback(self):
        self.values['ActivationStateAcknowledged'] = False
        with self.assertRaisesRegex(ActivationAcknowledgementPending, 'readback failed'):
            acknowledge(self.udid, self.identity)

    def test_activation_changing_between_connections_is_retryable(self):
        self.values['ActivationState'] = 'Unactivated'
        with self.assertRaisesRegex(ActivationAcknowledgementPending, 'complete first'):
            acknowledge(self.udid, self.identity)
        self.mobile.lockdownd_set_value.assert_not_called()
