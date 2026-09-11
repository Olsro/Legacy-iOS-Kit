"""Reproduce a qualified bootstrap cache from the selected stock firmware.

Recipes contain source ranges and checked metadata edits. They do not embed a
device's cache, activation state, or a target iOS version. Unknown stock cache
digests require a separately qualified recipe.
"""
import hashlib
import json
from pathlib import Path
import struct
import tempfile

from common import digest

# The compact bootstrap was qualified from this exact stock cache.  The
# resulting cache is deliberately shared by the armv7s bootstrap: it was also
# used for the physical iPad3,4 bootstrap qualification.  A device's own 8.4.1
# cache is not interchangeable with this reconstruction source.
QUALIFIED_SOURCE = dict(product='iPhone5,2', release='8.4.1', build='12H321',
                        sha256='f640e8a12e5e660e6059ed1a97461c13678a38503c6e9410d6154db22baed9d8')


def qualified_source():
    """Return the firmware identity required to reproduce the shared cache."""
    return dict(QUALIFIED_SOURCE)


def materialize(source, recipe):
    if recipe['format'] != 1 or len(source) != recipe['source_bytes'] or hashlib.sha256(source).hexdigest() != recipe['source_sha256']:
        raise ValueError('Stock cache does not match the qualified recipe')
    size = recipe['output_bytes']
    if not 0 < size <= 512*1024**2:
        raise ValueError('Invalid compact cache size')
    output = bytearray(size)
    end = 0
    for destination, offset, count in recipe['copy_ranges']:
        if destination < end or offset < 0 or count <= 0 or offset+count > len(source) or destination+count > size:
            raise ValueError('Overlapping or out-of-bounds cache source range')
        output[destination:destination+count] = source[offset:offset+count]
        end = destination+count
    end = 0
    for offset, before, after in recipe['metadata_patches']:
        before, after = bytes.fromhex(before), bytes.fromhex(after)
        if offset < end or not before or len(before) != len(after) or offset+len(after) > size:
            raise ValueError('Overlapping or out-of-bounds cache metadata edit')
        if output[offset:offset+len(before)] != before:
            raise ValueError('Cache metadata edit precondition failed')
        output[offset:offset+len(after)] = after
        end = offset+len(after)
    if hashlib.sha256(output).hexdigest() != recipe['output_sha256']:
        raise ValueError('Reproduced cache checksum mismatch')
    return output


def verify_mappings(source, output, recipe):
    if output[:16] != source[:16] or not output.startswith(b'dyld_v1'):
        raise ValueError('Unexpected cache architecture/header')
    offset, count = struct.unpack_from('<II', output, 16)
    if not 0 < count <= 7 or offset+count*32 > len(output):
        raise ValueError('Cache mappings exceed the bootstrap kernel limit')
    mappings = [list(struct.unpack_from('<QQQII', output, offset+i*32)) for i in range(count)]
    if mappings != recipe['mappings']:
        raise ValueError('Cache mappings differ from the recipe')
    last = None
    retained = 0
    for address, size, start, maximum, initial in mappings:
        if size <= 0 or any(n % 4096 for n in (address, size, start)) or start+size > len(output):
            raise ValueError('Invalid cache mapping extent')
        if last is not None and address != last:
            raise ValueError('Cache virtual mappings are not contiguous')
        last = address+size
        if initial & ~maximum or maximum & ~7 or maximum & 6 == 6:
            raise ValueError('Invalid cache mapping protections')
        if initial & 4:
            for page in range(start, start+size, 4096):
                data = output[page:page+4096]
                if any(data):
                    if data != source[page:page+4096]:
                        raise ValueError('Modified executable cache page')
                    retained += 1
    return retained


def prepare(source, destination):
    source, destination = Path(source), Path(destination)
    if not source.is_file() or not 0 < source.stat().st_size <= 512*1024**2:
        raise ValueError('Expected a regular stock dyld cache')
    if destination.exists():
        raise ValueError('Preserve the existing compact cache output')
    checksum = digest(source)
    candidates = [json.loads(path.read_text()) for path in
                  (Path(__file__).parent / 'recipes').glob('dyld-*.recipe')]
    qualified = qualified_source()
    if not any(r['source_sha256'] == qualified['sha256'] and
               r['bootstrap_build'] == qualified['build'] for r in candidates):
        raise ValueError('Qualified compact-cache source metadata differs from its recipe')
    matches = [r for r in candidates if r['source_sha256'] == checksum]
    if len(matches) != 1:
        raise ValueError('No unique qualified recipe for this stock cache')
    recipe = matches[0]
    stock = source.read_bytes()
    output = materialize(stock, recipe)
    retained = verify_mappings(stock, output, recipe)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='olsn0w-cache-', dir=destination.parent) as temporary:
        result = Path(temporary) / 'cache'
        with result.open('xb') as stream:
            for offset in range(0, len(output), 4096):
                page = output[offset:offset+4096]
                if any(page):
                    stream.seek(offset)
                    stream.write(page)
            stream.truncate(len(output))
        if digest(result) != recipe['output_sha256']:
            raise ValueError('Compact cache disk readback mismatch')
        result.rename(destination)
    return dict(sha256=recipe['output_sha256'], bytes=len(output),
                source_sha256=checksum, mappings=len(recipe['mappings']),
                preserved_executable_pages=retained)
