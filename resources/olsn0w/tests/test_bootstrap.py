import plistlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bootstrap import binary_launchd_bootstrap


class LaunchdBootstrapPlist(unittest.TestCase):
    def fixture(self):
        values = {'HighWatermark': 100, 'Boot': {}, 'Bootstrap': {}}
        xml = plistlib.dumps(values, fmt=plistlib.FMT_XML, sort_keys=False)
        data = bytearray(0x1000)
        struct.pack_into('<7I', data, 0, 0xfeedface, 12, 9, 2, 1, 124, 0)
        struct.pack_into('<II16sIIIIIIII', data, 28, 1, 124, b'__TEXT',
                         0x1000, 0x1000, 0, 0x1000, 5, 5, 1, 0)
        section = 28+56
        struct.pack_into('<16s16sIIIIIIIII', data, section,
                         b'__bs_plist', b'__TEXT', 0x1200, len(xml), 0x200,
                         0, 0, 0, 0, 0, 0)
        data[0x200:0x200+len(xml)] = xml
        return bytes(data), values, section, len(xml)

    def test_embedded_xml_becomes_a_smaller_binary_section(self):
        source, values, section, old_size = self.fixture()
        patched = binary_launchd_bootstrap(source)
        size, offset = struct.unpack_from('<II', patched, section+36)
        self.assertLess(size, old_size)
        self.assertEqual(patched[offset:offset+8], b'bplist00')
        self.assertEqual(plistlib.loads(patched[offset:offset+size]), values)
        self.assertEqual(patched[offset+size:offset+old_size],
                         bytes(old_size-size))
        changed = bytearray(source)
        changed[section+36:section+40] = patched[section+36:section+40]
        changed[offset:offset+old_size] = patched[offset:offset+old_size]
        self.assertEqual(patched, bytes(changed))

    def test_already_binary_or_unexpected_plist_is_rejected(self):
        source, _, section, _ = self.fixture()
        patched = binary_launchd_bootstrap(source)
        with self.assertRaisesRegex(ValueError, 'XML'):
            binary_launchd_bootstrap(patched)
        data = bytearray(source)
        size, offset = struct.unpack_from('<II', data, section+36)
        xml = plistlib.dumps({'Boot': {}}, fmt=plistlib.FMT_XML)
        data[offset:offset+size] = xml+bytes(size-len(xml))
        struct.pack_into('<I', data, section+36, len(xml))
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            binary_launchd_bootstrap(bytes(data))


if __name__ == '__main__':
    unittest.main()
