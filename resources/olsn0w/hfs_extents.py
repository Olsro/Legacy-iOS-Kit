"""Read the allocation bitmap of an offline HFS image for bounded sparse copying."""
import struct
from pathlib import Path


def allocated_ranges(path):
    path=Path(path)
    with path.open('rb') as stream:
        stream.seek(1024);header=stream.read(512)
        if header[:2] not in (b'H+',b'HX'):
            raise ValueError('Expected HFS image')
        block,total,free=struct.unpack_from('>III',header,40)
        if block!=4096 or path.stat().st_size!=block*total:
            raise ValueError('Unsupported HFS image geometry')
        logical,_,fork_blocks=struct.unpack_from('>QII',header,112)
        extents=[struct.unpack_from('>II',header,128+i*8) for i in range(8)]
        if sum(n for _,n in extents)!=fork_blocks or logical<(total+7)//8:
            raise ValueError('Allocation bitmap requires unsupported overflow extents')
        bitmap=bytearray()
        for start,count in extents:
            if not count:continue
            if start+count>total:
                raise ValueError('Bitmap extent outside image')
            stream.seek(start*block);data=stream.read(count*block)
            if len(data)!=count*block:raise ValueError('Short bitmap read')
            bitmap.extend(data)
        if len(bitmap)<logical:raise ValueError('Truncated allocation bitmap')
    ranges=[];begin=None;used=0
    for i in range(total):
        allocated=bool(bitmap[i//8]&(0x80>>(i%8)))
        if allocated:
            used+=1
            if begin is None:begin=i
        elif begin is not None:
            ranges.append((begin,i-begin));begin=None
    if begin is not None:ranges.append((begin,total-begin))
    if used!=total-free or not ranges or ranges[0][0]!=0 or sum(ranges[-1])!=total:
        raise ValueError('Allocation bitmap disagrees with HFS header/reserved blocks')
    return ranges
