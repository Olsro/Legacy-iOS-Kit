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
ARMV7_SOURCE = dict(product='iPhone4,1', release='8.4.1', build='12H321',
                    sha256='ce591173973c04c2289784e897d3e2a47c9aed7776f7575fbcdece861e4cc9da',
                    bytes=428327698,
                    prepared_sha256='11bbcaa49f8fdc068a286cc278b0f8da3d203a500fe055a2daf76707f98d8d1d',
                    registry=dict(address=0x201995d0,bytes=338480))
# The A5/A5X bootstrap reaches launchd through dyld, libobjc, libdispatch and
# libsp's early XPC event handler. Keep their executable import/lazy-binding
# stubs, Objective-C registration metadata, initializer tables, and libsp's
# data page. Missing one of these pages can leave pid 1 asleep in a zero page.
ARMV7_REQUIRED_RANGES = ((0x01c1d000,0x4000),(0x10195000,0x2000),
                         (0x1043a000,0x1d000),(0x10545000,0x1000),
                         (0x1059b000,0x1000),(0x12e10000,0x1000),
                         (0x12e3f000,0x2000))
# Preserve Apple's executable pages (including their code-directory hashes).
# Missing ObjC selectors and LINKEDIT tables must be retained, not worked
# around by NOPing dispatch releases. Qualified on N78AP with stock launchd.
ARMV7_REQUIRED_PATCHES = ()


def qualified_source(architecture='armv7s'):
    """Return the firmware identity required to reproduce the shared cache."""
    if architecture == 'armv7s':return dict(QUALIFIED_SOURCE)
    if architecture == 'armv7':
        result=dict(ARMV7_SOURCE);result['registry']=dict(result['registry']);return result
    raise ValueError('No qualified bootstrap cache architecture')


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


def write_sparse(data, destination):
    """Write zero pages as holes while preserving the exact logical bytes."""
    destination=Path(destination)
    with destination.open('xb') as stream:
        for offset in range(0,len(data),4096):
            page=data[offset:offset+4096]
            if any(page):
                stream.seek(offset);stream.write(page)
        stream.truncate(len(data))
    return destination


def prepare(source, destination, architecture='armv7s'):
    source, destination = Path(source), Path(destination)
    if not source.is_file() or not 0 < source.stat().st_size <= 512*1024**2:
        raise ValueError('Expected a regular stock dyld cache')
    if destination.exists():
        raise ValueError('Preserve the existing compact cache output')
    checksum = digest(source)
    if architecture == 'armv7':
        qualified=qualified_source(architecture)
        if source.stat().st_size != qualified['bytes'] or checksum != qualified['sha256']:
            raise ValueError('Stock ARMv7 cache does not match the qualified source')
        recipe=json.loads((Path(__file__).parent/'recipes/dyld-armv7-12H321.recipe').read_text())
        if (recipe.get('format')!=2 or recipe.get('architecture')!=architecture or
                recipe.get('source_bytes')!=qualified['bytes'] or
                recipe.get('source_sha256')!=qualified['sha256'] or
                recipe.get('output_sha256')!=qualified['prepared_sha256'] or
                recipe.get('registry')!=qualified['registry']):
            raise ValueError('ARMv7 compact-cache recipe metadata differs')
        for required,count in ARMV7_REQUIRED_RANGES:
            if not any(offset<=required and required+count<=offset+length
                       for offset,length in recipe['keep_ranges']):
                raise ValueError('ARMv7 compact-cache recipe omits a required system stub page')
        if tuple((offset,before,after) for offset,before,after in
                 recipe.get('bootstrap_patches',())) != ARMV7_REQUIRED_PATCHES:
            raise ValueError('ARMv7 compact-cache bootstrap patches differ')
        from ios8_cache import prepare as remap, protect_registry
        stock=source.read_bytes();transformed,report=remap(stock,architecture)
        region=qualified['registry']
        transformed,mappings=protect_registry(transformed,region['address'],region['bytes'])
        if [list(item) for item in mappings]!=recipe['mappings'] or len(transformed)!=recipe['output_bytes']:
            raise ValueError('ARMv7 cache mapping transform differs from recipe')
        output=bytearray(len(transformed));last=0
        for offset,count in recipe['keep_ranges']:
            if (offset<last or count<=0 or offset%4096 or
                    offset+count>len(stock) or (count%4096 and offset+count!=len(stock))):
                raise ValueError('Invalid ARMv7 compact-cache source range')
            output[offset:offset+count]=transformed[offset:offset+count]
            last=offset+count
        # The admission page and the read-only XPC prefix were relocated past
        # the stock EOF by the checked mapping transform. Preserve only those
        # referenced ranges; every other omitted page remains a sparse zero.
        for _,size,offset,_,_ in mappings:
            if offset>=len(stock):output[offset:offset+size]=transformed[offset:offset+size]
        if hashlib.sha256(output).hexdigest() != qualified['prepared_sha256']:
            raise ValueError('Prepared ARMv7 cache checksum mismatch')
        retained=verify_mappings(stock,output,recipe)
        if retained != recipe['retained_executable_pages']:
            raise ValueError('ARMv7 retained executable page count differs')
        destination.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='olsn0w-cache-',dir=destination.parent) as temporary:
            result=Path(temporary)/'cache';write_sparse(output,result)
            if digest(result)!=qualified['prepared_sha256']:
                raise ValueError('ARMv7 cache disk readback mismatch')
            result.rename(destination)
        return dict(sha256=qualified['prepared_sha256'],bytes=len(output),
                    source_sha256=checksum,mappings=len(mappings),registry=region,
                    architecture=architecture,
                    preserved_executable_pages=retained)
    if architecture != 'armv7s':
        raise ValueError('No qualified bootstrap cache architecture')
    candidates = [json.loads(path.read_text()) for path in
                  (Path(__file__).parent / 'recipes').glob('dyld-*.recipe')]
    qualified = qualified_source(architecture)
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
        write_sparse(output,result)
        if digest(result) != recipe['output_sha256']:
            raise ValueError('Compact cache disk readback mismatch')
        result.rename(destination)
    return dict(sha256=recipe['output_sha256'], bytes=len(output),
                source_sha256=checksum, mappings=len(recipe['mappings']),
                preserved_executable_pages=retained,architecture=architecture)
