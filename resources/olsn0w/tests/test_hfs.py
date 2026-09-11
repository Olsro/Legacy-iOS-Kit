"""Exercise both inline compression forms used by stock Apple filesystems."""
from pathlib import Path
import struct
import sys
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from unittest.mock import Mock
from hfs import HFS, inline_decmpfs, image_path


class InlineCompression(unittest.TestCase):
    def test_raw_short_file(self):
        payload = b'forward\n'
        attribute = struct.pack('<IIQ', 0x636d7066, 3, len(payload)) + b'\xff' + payload
        self.assertEqual(inline_decmpfs(attribute), payload)

    def test_zlib_and_incorrect_length(self):
        payload = b'property-list-data' * 100
        header = struct.pack('<IIQ', 0x636d7066, 3, len(payload))
        encoded = zlib.compress(payload)
        self.assertEqual(inline_decmpfs(header + encoded), payload)
        with self.assertRaises(ValueError):
            inline_decmpfs(header + encoded[:-1])
        with self.assertRaises(ValueError):
            inline_decmpfs(header + encoded + b'extra')
        with self.assertRaises(ValueError):
            inline_decmpfs(struct.pack('<IIQ', 0x636d7066, 3, len(payload)-1) + encoded)

    def test_image_paths_cannot_escape(self):
        for path in ('relative', '/private/../other', '/name\0tail'):
            with self.assertRaises(ValueError):
                image_path(path)

    def test_internal_catalog_directories_are_not_payload_paths(self):
        image = object.__new__(HFS)
        image.command = Mock(return_value=(
            '040000 0 0 96 5/12/2014 12:23 \0\0\0\0HFS+ Private Data\n'
            '041555 0 0 0 5/12/2014 12:23 .HFS+ Private Directory Data\r\n'
            '040755 0 0 1 5/12/2014 12:23 private\n').encode())
        self.assertEqual([r['name'] for r in image.ls('/')], ['private'])
        with self.assertRaises(ValueError):
            image.ls('/private')

    def test_readlink_preserves_target_instead_of_following_it(self):
        image = object.__new__(HFS)
        image.command = Mock(return_value=b'lrw-r--r-- 1 0 0 7 08-09-2026 15:27 usr/libexec/service -> /handler\n')
        self.assertEqual(image.readlink('/usr/libexec/service'), '/handler')
        image.command.assert_called_once_with('ls', '-l', '/usr/libexec/service')
        with self.assertRaises(ValueError):
            image.readlink('/different')

    def test_missing_file_is_not_accepted_as_empty_file(self):
        image = object.__new__(HFS)
        def command(*args):
            if args[0] == 'getattr':
                return b''
            Path(args[2]).write_bytes(b'')
            return b'No such file or directory\n'
        image.command = command
        with self.assertRaises(ValueError):
            image.read('/missing')
