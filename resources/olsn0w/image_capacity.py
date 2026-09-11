"""Budget target-root additions and HFS free-space notification headroom."""


def root_reserve_bytes(size, block):
    # HFS root volumes clear their low-space notification at 11% or 1.25 GiB,
    # whichever is smaller. Keep room for post-install metadata and caches too.
    desired=min(1280*1024**2//block,(size//block//100)*11)*block
    return desired+16*1024**2


def plan(info, sizes, records):
    block=info['block_size'];current=info['bytes'];free=info['free_bytes']
    if block<=0 or current%block or not 0<=free<=current or records<0 or any(size<0 for size in sizes):
        raise ValueError('Invalid image capacity inputs')
    allocated=sum((size+block-1)//block*block for size in sizes)
    # Allow catalog, extents and compression metadata growth without counting
    # on replaced files or compressibility to provide any free blocks.
    metadata=(records+1)*8*block+4*1024**2
    proposed=current
    for _ in range(8):
        reserve=root_reserve_bytes(proposed,block)
        needed=allocated+metadata+reserve
        size=max(current,current+needed-free)
        size=(size+1024**2-1)//1024**2*1024**2
        if size==proposed:break
        proposed=size
    else:raise ValueError('Image capacity estimate did not converge')
    return dict(original_bytes=current,image_bytes=proposed,payload_bytes=allocated,
                metadata_bytes=metadata,reserve_bytes=reserve,required_free_bytes=needed)


def reserve(image, entries, extra=()):
    entries=list(entries)
    sizes=[len(data) for item,data in entries if data is not None]+list(extra)
    budget=plan(image.info(),sizes,len(entries)+len(extra))
    if budget['image_bytes']>image.info()['bytes']:image.grow(budget['image_bytes'])
    if image.info()['free_bytes']<budget['required_free_bytes']:
        raise ValueError('Image still lacks space for personalization after growth')
    return budget
