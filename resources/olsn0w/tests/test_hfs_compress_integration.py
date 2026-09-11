"""Optional real-image tests: supply an empty HFSX image made by mkfs.hfsplus."""
import os
from pathlib import Path
import random
import shutil
import struct
import sys
import tempfile
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import digest, run
from hfs import HFS
from archives import write_tar


def resource_fork(image, basename):
    """Read the test file's fork directly, independently of xpwn's decoder."""
    with image.open('rb') as stream:
        stream.seek(1024)
        header = stream.read(512)
        block = struct.unpack_from('>I', header, 40)[0]

        def read_fork(record):
            size = struct.unpack_from('>Q', record)[0]
            parts = []
            for index in range(8):
                start, count = struct.unpack_from('>II', record, 16+index*8)
                if count:
                    stream.seek(start*block)
                    parts.append(stream.read(count*block))
            data = b''.join(parts)
            if len(data) < size:
                raise ValueError('Test fixture requires overflow extents')
            return data[:size]

        catalog = read_fork(header[272:352])
        node_size = struct.unpack_from('>H', catalog, 32)[0]
        leaf = struct.unpack_from('>I', catalog, 24)[0]
        visited = set()
        while leaf:
            if leaf in visited:
                raise ValueError('Catalog leaf cycle')
            visited.add(leaf)
            node = catalog[leaf*node_size:(leaf+1)*node_size]
            for index in range(struct.unpack_from('>H', node, 10)[0]):
                offset = struct.unpack_from('>H', node, node_size-2-index*2)[0]
                record = node[offset:]
                key_length = struct.unpack_from('>H', record)[0]
                length = struct.unpack_from('>H', record, 6)[0]
                name = record[8:8+length*2].decode('utf-16be')
                value = record[2+key_length:]
                if name == basename and struct.unpack_from('>H', value)[0] == 2:
                    return read_fork(value[168:248])
            leaf = struct.unpack_from('>I', node)[0]
    raise ValueError('Missing test file')


@unittest.skipUnless(os.environ.get('OLSN0W_TEST_HFS_TEMPLATE'), 'requires an empty HFSX image')
class CompressedImage(unittest.TestCase):
    def test_rename_preserves_compressed_file_and_directory_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            work=Path(temporary);path=work/'image.hfs'
            shutil.copyfile(os.environ['OLSN0W_TEST_HFS_TEMPLATE'],path)
            image=HFS(path);image.mkdir('/bin')
            content=work/'content';content.write_bytes(b'compressed program'*10000)
            image.add_compressed('/bin/reboot',content,0o755)
            image.rename_file('/bin/reboot','/bin/reboot_original')
            image.add('/bin/reboot',b'#!/bin/sh\nexit 0\n',0o755)
            self.assertEqual(image.read('/bin/reboot_original'),content.read_bytes())
            self.assertEqual(next(r for r in image.ls('/') if r['name']=='bin')['size'],2)
            before=digest(path)
            with self.assertRaises(ValueError):image.rename_file('/bin/reboot','/bin/reboot_original')
            self.assertEqual(digest(path),before)

    def test_replace_regular_preserves_other_compressed_files_and_rejects_them(self):
        with tempfile.TemporaryDirectory() as work:
            work=Path(work);path=work/'image.hfs'
            shutil.copyfile(os.environ['OLSN0W_TEST_HFS_TEMPLATE'],path)
            image=HFS(path)
            image.add('/relay',b'old relay',mode=0o600)
            cache=work/'cache';cache.write_bytes(b'cache data'*10000)
            image.add_compressed('/cache',cache)
            image.replace_regular('/relay',b'new relay'*10000)
            self.assertEqual(image.read('/relay'),b'new relay'*10000)
            self.assertEqual(image.read('/cache'),cache.read_bytes())
            image.replace_regular('/relay',b'short')
            self.assertEqual(image.read('/relay'),b'short')
            before=digest(path)
            with self.assertRaises(RuntimeError):image.replace_regular('/cache',b'invalid')
            self.assertEqual(digest(path),before)

    def test_tar_symlink_metadata_does_not_change_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            path = temporary / 'image.hfs'
            shutil.copyfile(os.environ['OLSN0W_TEST_HFS_TEMPLATE'], path)
            image = HFS(path)
            image.add('/existing', b'existing target', mode=0o755)
            program = tarfile.TarInfo('program')
            program.mode, program.size = 0o755, 7
            links = []
            for name, target in [('z-link', 'program'), ('old-link', '/existing')]:
                link = tarfile.TarInfo(name)
                link.type, link.linkname, link.mode = tarfile.SYMTYPE, target, 0o644
                link.uid, link.gid = 501, 501
                links.append((link, None))
            archive = temporary / 'payload.tar'
            write_tar(archive, [(program, b'payload')] + links)
            image.command('untar', archive)
            entries = {r['name']: r for r in image.ls('/')}
            for name in ('program', 'existing'):
                self.assertEqual((entries[name]['mode'], entries[name]['uid'], entries[name]['gid']),
                                 (0o100755, 0, 0))
            for name, target in [('z-link', 'program'), ('old-link', '/existing')]:
                self.assertEqual(image.readlink('/'+name), target)
                self.assertEqual((entries[name]['mode'], entries[name]['uid'], entries[name]['gid']),
                                 (0o120644, 501, 501))
            self.assertEqual(image.read('/program'), b'payload')
            self.assertEqual(image.read('/existing'), b'existing target')

    def check_resource_map(self, image, basename):
        fork = resource_fork(image, basename)
        data_start, map_start, data_size, map_size = struct.unpack_from('>IIII', fork)
        self.assertEqual(data_start, 256)
        self.assertEqual(map_start, data_start+data_size)
        self.assertEqual(len(fork), map_start+map_size)
        resource_map = fork[map_start:]
        types, names = struct.unpack_from('>HH', resource_map, 24)
        self.assertEqual(names, map_size)
        self.assertEqual(struct.unpack_from('>H', resource_map, types)[0], 0)
        self.assertEqual(resource_map[types+2:types+6], b'cmpf')
        count, references = struct.unpack_from('>HH', resource_map, types+6)
        self.assertEqual(count, 0)
        reference = types+references
        # Resource ID 1, no name, attributes/data offset zero, handle zero.
        self.assertEqual(struct.unpack_from('>HHII', resource_map, reference),
                         (1, 0xffff, 0, 0))

    def test_compression_boundaries_readback_and_failed_replacement(self):
        template = Path(os.environ['OLSN0W_TEST_HFS_TEMPLATE'])
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            image_path = temporary / 'image.hfs'
            shutil.copyfile(template, image_path)
            image = HFS(image_path)
            image.add('/plain', b'ordinary file')
            generator = random.Random(8675309)
            cases = [b'x', b'hello\n', b'abc'*24000,
                     bytes(generator.getrandbits(8) for _ in range(65536)),
                     bytes(generator.getrandbits(8) for _ in range(65537))]
            for index, data in enumerate(cases):
                source = temporary / 'input'
                source.write_bytes(data)
                path = '/usr/lib/payload-' + str(index)
                image.add_compressed(path, source, mode=0o755)
                self.assertEqual(image.read(path), data)
                self.check_resource_map(image_path, Path(path).name)
            before = digest(image_path)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                image.add_compressed('/usr/lib/payload-0', source)
            self.assertEqual(digest(image_path), before)
            source.write_bytes(b'')
            with self.assertRaises(ValueError):
                image.add_compressed('/empty', source)
            self.assertEqual(digest(image_path), before)
            self.assertEqual(image.read('/plain'), b'ordinary file')
            image.normalize_root()
            normalized = digest(image_path)
            image.normalize_root()
            self.assertEqual(digest(image_path), normalized)
            self.assertEqual(image.read('/usr/lib/payload-0'), b'x')
            checker = os.environ.get('OLSN0W_TEST_FSCK')
            if checker:
                report = run([checker, '-fn', image_path]).decode()
                self.assertIn('appears to be OK', report)
