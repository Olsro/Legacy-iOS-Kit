"""Edit regular HFS image files with the kit's portable hfsplus binary."""
from collections import deque
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tempfile
import zlib

from common import clone_or_copy, digest, run, tools


def image_path(value):
    value = str(value)
    path = PurePosixPath(value)
    if not value.startswith('/') or '..' in path.parts or '\0' in value:
        raise ValueError('Expected an absolute path within the image')
    return str(path)


def inline_decmpfs(attribute):
    """Decode type-3 inline data, including Apple's uncompressed 0xff form."""
    if len(attribute) < 17:
        raise ValueError('Truncated inline decmpfs attribute')
    magic, kind, size = struct.unpack_from('<IIQ', attribute)
    if magic != 0x636d7066 or kind != 3 or size > 128*1024**2:
        raise ValueError('Invalid inline decmpfs header')
    payload = attribute[16:]
    if payload[0] == 0xff:
        result = payload[1:]
    else:
        decoder = zlib.decompressobj()
        result = decoder.decompress(payload, size+1)
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('Invalid inline decmpfs compressed stream')
    if len(result) != size:
        raise ValueError('Inline decmpfs size mismatch')
    return result


class HFS:
    def __init__(self, path):
        self.path = Path(path).resolve(strict=True)
        if not self.path.is_file() or str(self.path).startswith('/dev/'):
            raise ValueError('HFS editing requires a regular image file')
        self.info()

    def command(self, *args):
        if args and args[0] == 'untar':
            if len(args) != 2:
                raise ValueError('Expected one tar archive')
            from native_tools import hfscompress
            return run([hfscompress(), self.path, '--untar', args[1]], timeout=600)
        return run([tools() / 'hfsplus', self.path, *args], timeout=600)

    def info(self):
        with self.path.open('rb') as stream:
            stream.seek(1024)
            header = stream.read(512)
        if len(header) != 512 or header[:2] not in (b'H+', b'HX'):
            raise ValueError('Expected an unwrapped HFS+ or HFSX image')
        block, total, free = struct.unpack_from('>III', header, 40)
        if block < 512 or block > 65536 or block & (block-1) or not 0 <= free <= total:
            raise ValueError('Invalid HFS allocation geometry')
        if total * block > self.path.stat().st_size:
            raise ValueError('Truncated HFS image')
        return dict(block_size=block, total_blocks=total, free_blocks=free,
                    bytes=block*total, free_bytes=block*free)

    def ls(self, path):
        path = image_path(path)
        listing = self.command('ls', path).decode()
        pattern = re.compile(r'^([0-7]{6})\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+/\s*\d+/\d+\s+\d+:\d+\s+(.+)$')
        records = []
        for line in listing.split('\n'):
            match = pattern.match(line)
            if match:
                mode, uid, gid, size, name = match.groups()
                # HFS hard-link backing directories are volume metadata, not
                # paths that the payload installer may traverse or replace.
                if path == '/' and stat.S_ISDIR(int(mode, 8)) and name in (
                        '\0\0\0\0HFS+ Private Data', '.HFS+ Private Directory Data\r'):
                    continue
                if name in ('.', '..') or '/' in name or '\0' in name:
                    raise ValueError('Invalid HFS catalog name')
                records.append(dict(name=name, mode=int(mode,8), uid=int(uid),
                                    gid=int(gid), size=int(size)))
            elif re.match(r'^[0-7]{6}\s', line):
                raise ValueError('Unrecognized HFS catalog entry: '+line)
        if any(re.match(r'^(error:|not found|no such)', line.lower()) for line in listing.splitlines()):
            raise ValueError('HFS directory lookup failed: '+path)
        if len({r['name'] for r in records}) != len(records):
            raise ValueError('Duplicate HFS catalog entries')
        return records

    def tree(self, path):
        path = image_path(path)
        queue, entries = deque([path]), []
        while queue:
            parent = queue.popleft()
            for item in self.ls(parent):
                item['path'] = str(PurePosixPath(parent) / item['name'])
                entries.append(item)
                if len(entries) > 200000:
                    raise ValueError('Unexpectedly large HFS catalog walk')
                if stat.S_ISDIR(item['mode']):
                    queue.append(item['path'])
        return entries

    def read(self, path):
        path = image_path(path)
        try:
            attribute = self.command('getattr', path, 'com.apple.decmpfs')
        except RuntimeError as error:
            # xpwn's attribute lookup aborts when the requested key sorts
            # before the first key. Its file extractor checks UF_COMPRESSED
            # before touching that tree, so ordinary files remain readable.
            # A compressed-file extraction error still propagates below.
            if str(error).strip() != 'hfsplus: BTree inconsistent!':
                raise
            attribute = b''
        if len(attribute) >= 16 and attribute[:4] == b'fpmc' and struct.unpack_from('<I', attribute, 4)[0] == 3:
            return inline_decmpfs(attribute)
        with tempfile.TemporaryDirectory(prefix='olsn0w-hfs-read-') as temporary:
            output = Path(temporary) / 'content'
            result = self.command('extract', path, output)
            if any(message in result for message in (b'No such file or directory', b'Not a file', b'cannot create file')):
                raise ValueError('HFS extraction failed: '+path)
            if not output.is_file():
                raise ValueError('HFS extraction failed: '+path)
            return output.read_bytes()

    def readlink(self, path):
        path = image_path(path)
        listing = self.command('ls', '-l', path).decode()
        pattern = (r'l[rswxtST-]{9}\s+\d+\s+\d+\s+\d+\s+\d+\s+'
                   r'\d+-\d+-\d+\s+\d+:\d+\s+' + re.escape(path.lstrip('/')) + r' -> ([^\n\0]+)\n')
        match = re.fullmatch(pattern, listing)
        if not match:
            raise ValueError('Expected one symbolic link: '+path)
        return match.group(1)

    def mkdir(self, path):
        path = PurePosixPath(image_path(path))
        for parent in [*reversed(path.parents), path]:
            if str(parent) == '/':
                continue
            existing = next((r for r in self.ls(str(parent.parent)) if r['name'] == parent.name), None)
            if existing:
                if not stat.S_ISDIR(existing['mode']):
                    raise ValueError('Expected a real directory in image: '+str(parent))
            else:
                self.command('mkdir', str(parent))

    def add(self, path, data, mode=0o644):
        path = image_path(path)
        self.mkdir(str(PurePosixPath(path).parent))
        previous = next((r for r in self.ls(str(PurePosixPath(path).parent)) if r['name'] == PurePosixPath(path).name), None)
        if previous:
            if stat.S_ISDIR(previous['mode']):
                raise ValueError('Refusing to replace an image directory with a file')
            # Replace compressed stock records rather than retaining decmpfs metadata.
            self.command('rm', path)
        with tempfile.TemporaryDirectory(prefix='olsn0w-hfs-add-') as temporary:
            source = Path(temporary) / 'content'
            source.write_bytes(data)
            self.command('add', source, path)
        self.command('chmod', format(mode, '04o'), path)
        self.command('chown', '0:0', path)
        if self.read(path) != data:
            raise ValueError('HFS write readback mismatch: '+path)
        entry = next(r for r in self.ls(str(PurePosixPath(path).parent)) if r['name'] == PurePosixPath(path).name)
        if (entry['uid'], entry['gid'], stat.S_IMODE(entry['mode'])) != (0, 0, mode):
            raise ValueError('HFS ownership or permissions differ from requested metadata')

    def rename_file(self, source, destination):
        """Preserve a file's catalog identity and repair xpwn's move counts."""
        from native_tools import hfscompress
        source, destination = image_path(source), image_path(destination)
        before = self.read(source)
        if any(r['name'] == PurePosixPath(destination).name for r in self.ls(str(PurePosixPath(destination).parent))):
            raise ValueError('Rename destination already exists')
        with tempfile.TemporaryDirectory(prefix='olsn0w-rename-', dir=self.path.parent) as work:
            candidate = Path(work)/'candidate.hfs'
            clone_or_copy(self.path, candidate)
            image = HFS(candidate)
            image.command('mv', source, destination)
            for parent in sorted({str(PurePosixPath(p).parent) for p in (source, destination)}):
                run([hfscompress(), candidate, '--recount-directory', parent])
            if image.read(destination) != before or any(r['name'] == PurePosixPath(source).name for r in image.ls(str(PurePosixPath(source).parent))):
                raise ValueError('Renamed file content or catalog differs')
            candidate.replace(self.path)

    def replace_regular(self, path, data):
        """Replace an ordinary data fork without removing its catalog identity.

        Removing a file can trigger the old xpwn missing-attribute lookup bug
        on a volume containing compressed files. Preserve its metadata and
        publish a candidate only after complete content/metadata readback.
        """
        from native_tools import hfscompress
        path = image_path(path)
        parent, name = str(PurePosixPath(path).parent), PurePosixPath(path).name
        before = next(r for r in self.ls(parent) if r['name'] == name)
        if not stat.S_ISREG(before['mode']):
            raise ValueError('Expected an ordinary file')
        with tempfile.TemporaryDirectory(prefix='olsn0w-replace-', dir=self.path.parent) as work:
            candidate, source = Path(work)/'candidate.hfs', Path(work)/'content'
            clone_or_copy(self.path, candidate); source.write_bytes(data)
            run([hfscompress(), candidate, '--replace-regular', source, path])
            image = HFS(candidate)
            after = next(r for r in image.ls(parent) if r['name'] == name)
            if image.read(path) != data or any(before[k] != after[k] for k in ('mode','uid','gid')):
                raise ValueError('Replacement content or metadata readback differs')
            candidate.replace(self.path)

    def grow(self, size):
        current = self.info()
        if size < current['bytes'] or size % current['block_size']:
            raise ValueError('HFS grow size must preserve existing allocation blocks')
        self.command('grow', size)
        if self.info()['bytes'] != size:
            raise ValueError('HFS grow result differs from requested size')

    def add_compressed(self, path, source, mode=0o644):
        """Insert a new compressed file; publish only after an independent readback.

        All writes happen on a sibling candidate image. The caller still checks
        the complete filesystem before it can be installed on a device.
        """
        from native_tools import hfscompress
        path = image_path(path)
        source = Path(source).resolve(strict=True)
        if not source.is_file() or source == self.path or not 0 < source.stat().st_size <= 512*1024**2:
            raise ValueError('Expected a distinct nonempty regular source of at most 512 MiB')
        if mode not in (0o600, 0o644, 0o700, 0o755):
            raise ValueError('Unexpected compressed payload permissions')
        checksum = digest(source)
        helper = hfscompress()
        with tempfile.TemporaryDirectory(prefix='olsn0w-compressed-', dir=self.path.parent) as temporary:
            temporary = Path(temporary)
            candidate = temporary / 'candidate.hfs'
            clone_or_copy(self.path, candidate)
            image = HFS(candidate)
            parent = str(PurePosixPath(path).parent)
            image.mkdir(parent)
            if any(r['name'] == PurePosixPath(path).name for r in image.ls(parent)):
                raise ValueError('Compressed destination already exists: '+path)
            run([helper, candidate, source, path], timeout=600)
            image.command('chmod', format(mode, '04o'), path)
            image.command('chown', '0:0', path)
            readback = temporary / 'readback'
            image.command('extract', path, readback)
            if not readback.is_file() or digest(readback) != checksum or digest(source) != checksum:
                raise ValueError('Compressed HFS readback mismatch')
            entry = next(r for r in image.ls(parent) if r['name'] == PurePosixPath(path).name)
            if (entry['uid'], entry['gid'], stat.S_IMODE(entry['mode']), entry['size']) != (
                    0, 0, mode, source.stat().st_size):
                raise ValueError('Compressed HFS file metadata mismatch')
            candidate.replace(self.path)

    def normalize_root(self):
        """Complete root metadata for newly formatted HFSX bootstrap/data images."""
        from native_tools import hfscompress
        with self.path.open('rb') as stream:
            stream.seek(1024)
            if stream.read(2) != b'HX':
                raise ValueError('Root normalization requires HFSX')
        run([hfscompress(), self.path, '--normalize-root'], timeout=120)

    def initialize_protection_v4(self):
        """Initialize iOS 6/7 format metadata before the first protected mount.

        Only journal files, directories and symlinks may exist. This does not
        convert existing user data or generate any encryption keys.
        """
        from native_tools import hfscompress
        run([hfscompress(), self.path, '--initialize-protection-v4'], timeout=120)

    def initialize_protection_v2(self):
        """Initialize fresh iOS 5 metadata, never convert an existing volume."""
        from native_tools import hfscompress
        run([hfscompress(), self.path, '--initialize-protection-v2'], timeout=120)
