"""Portable iOS 8 cache remapping used by the Kit's daibutsu preparation.

Reference: LukeZGD/EverUntether, commit 0e4bff009872f8668ffec59775002b04d20255ec,
dyld/dsc_override/haxx_override.c (kok3shidoll & Clarity). The executable pages
remain intact; a copied export-table page supplies early signature admission.
"""
import hashlib
import struct


def uleb(data, at):
    value=0;start=at
    for shift in range(0,64,7):
        if at>=len(data):raise ValueError('Truncated export trie')
        byte=data[at];at+=1;value|=(byte&127)<<shift
        if not byte&128:return value,at
    raise ValueError('Oversized export value at '+str(start))


def encode(value):
    if value<0:raise ValueError('Negative export address')
    result=bytearray()
    while True:
        byte=value&127;value>>=7;result.append(byte|(128 if value else 0))
        if not value:return bytes(result)


def export_slot(trie, symbol):
    pending=[(0,b'')];seen=set();found=[]
    while pending:
        at,name=pending.pop()
        if at in seen or len(seen)>10000:raise ValueError('Cyclic or oversized export trie')
        seen.add(at);size,terminal=uleb(trie,at);children=terminal+size
        if children>=len(trie):raise ValueError('Export terminal outside trie')
        if size and name==symbol:
            flags,address=uleb(trie,terminal)
            if flags&0x1c:raise ValueError('Unsupported export flags')
            value,end=uleb(trie,address)
            if end!=children:raise ValueError('Unexpected export terminal')
            found.append((address,end,value))
        count=trie[children];at=children+1
        for _ in range(count):
            end=trie.find(b'\0',at)
            if end<0:raise ValueError('Unterminated export edge')
            edge=trie[at:end];offset,at=uleb(trie,end+1)
            if len(name+edge)>4096:raise ValueError('Invalid export edge')
            pending.append((offset,name+edge))
    if len(found)!=1:raise ValueError('Missing or ambiguous signature export')
    return found[0]


def prepare(stock):
    if not stock.startswith(b'dyld_v1  armv7s\0') or len(stock)<0x8000:
        raise ValueError('Expected a stock ARMv7s dyld cache')
    mo,mc,io,ic=struct.unpack_from('<4I',stock,16)
    if mc!=3 or not 0<ic<4096 or io+ic*32>0x8000 or mo+mc*32>io:
        raise ValueError('Unsupported stock cache tables')
    maps=[struct.unpack_from('<QQQII',stock,mo+i*32) for i in range(3)]
    first,data,link=maps
    if first[2]!=0 or first[3:]!=(5,5) or data[3:]!=(3,3) or link[3:]!=(1,1):
        raise ValueError('Unexpected cache protections')
    for i,m in enumerate(maps):
        if m[2]+m[1]>len(stock) or any(v%4096 for v in m[:3]):raise ValueError('Invalid cache map')
        if i and maps[i-1][0]+maps[i-1][1]!=m[0]:raise ValueError('Discontinuous virtual maps')
    images=[struct.unpack_from('<QQQII',stock,io+i*32) for i in range(ic)]
    header_size=images[0][0]-first[0]
    if header_size!=0x8000:raise ValueError('Unrecognized cache header extent')
    def path(offset):
        end=stock.find(b'\0',offset,offset+4096)
        if end<0:raise ValueError('Unterminated image path')
        return stock[offset:end]
    matches=[im for im in images if path(im[3])==b'/usr/lib/libmis.dylib']
    if len(matches)!=1:raise ValueError('Ambiguous libmis cache image')
    image=matches[0];image_offset=image[0]-first[0]
    if stock[image_offset:image_offset+4]!=b'\xce\xfa\xed\xfe':raise ValueError('Invalid libmis header')
    count,size=struct.unpack_from('<II',stock,image_offset+16)
    if size>0x10000 or count>size//8:raise ValueError('Invalid libmis commands')
    at=image_offset+28;exports=[]
    for _ in range(count):
        cmd,length=struct.unpack_from('<II',stock,at)
        if length<8 or at+length>image_offset+28+size:raise ValueError('Invalid libmis command')
        if cmd==0x80000022:
            if length!=48:raise ValueError('Invalid dyld command')
            exports.append(struct.unpack_from('<II',stock,at+40))
        at+=length
    if len(exports)!=1:raise ValueError('Ambiguous libmis export table')
    off,size=exports[0]
    if not link[2]<=off<off+size<=link[2]+link[1]:raise ValueError('Export trie outside LINKEDIT')
    start,end,old=export_slot(stock[off:off+size],b'_MISValidateSignature')
    # Preserve the original ARM/Thumb convention of the export trie.
    gadget=stock.find(bytes.fromhex('00207047'),image_offset,min(first[1],image_offset+0x10000))
    if gadget<0 or gadget%2:raise ValueError('Missing aligned return-zero gadget')
    new=encode((gadget-image_offset)|(old&1))
    if len(new)!=end-start:raise ValueError('Replacement export width differs')
    changed=off+start;page=changed&~0x3fff
    if not link[2]<page<page+0x4000<link[2]+link[1] or changed+len(new)>page+0x4000:
        raise ValueError('Cannot split export page safely')
    appended=(len(stock)&~0x3fff)+0x4000;copied=appended+header_size
    result=bytearray(stock);result.extend(bytes(copied+0x4000-len(result)))
    result[appended:copied]=stock[:header_size]
    result[copied:copied+0x4000]=stock[page:page+0x4000]
    result[copied+changed-page:copied+changed-page+len(new)]=new
    mappings=[(first[0],header_size,appended,1,1),
              (first[0]+header_size,first[1]-header_size,header_size,5,5),data,
              (link[0],page-link[2],link[2],1,1),
              (link[0]+page-link[2],0x4000,copied,1,1),
              (link[0]+page-link[2]+0x4000,link[1]-(page-link[2])-0x4000,page+0x4000,1,1)]
    # Move the on-disk image index and header-resident paths to fit three maps.
    shift=96
    if any(stock[header_size-shift:header_size]):raise ValueError('No room for expanded cache index')
    result[io+shift:header_size]=stock[io:header_size-shift]
    struct.pack_into('<II',result,20,6,io+shift)
    for i,im in enumerate(images):
        if im[3]<header_size:
            if im[3]<io+ic*32:raise ValueError('Path overlaps cache tables')
            struct.pack_into('<I',result,io+shift+i*32+24,im[3]+shift)
    for i,m in enumerate(mappings):struct.pack_into('<QQQII',result,mo+i*32,*m)
    signature,extent=struct.unpack_from('<QQ',stock,40)
    if not 0<signature<len(stock)-8:raise ValueError('Signature outside cache')
    extent=extent or len(stock)-signature
    magic,length=struct.unpack_from('>II',stock,signature)
    if magic!=0xfade0cc0 or not 12<=length<=extent or signature+extent>len(stock):
        raise ValueError('Invalid stock cache signature')
    struct.pack_into('<Q',result,48,length)
    # All loaded virtual bytes must match stock except the selected export.
    for m in mappings:
        original=next(v for v in maps if v[0]<=m[0]<v[0]+v[1])
        source=original[2]+m[0]-original[0]
        expected=bytearray(stock[source:source+m[1]])
        if source<=changed<source+m[1]:expected[changed-source:changed-source+len(new)]=new
        if result[m[2]:m[2]+m[1]]!=expected:raise ValueError('Cache remapping changed unrelated virtual bytes')
    return bytes(result),dict(source_sha256=hashlib.sha256(stock).hexdigest(),
        output_sha256=hashlib.sha256(result).hexdigest(),mappings=mappings,
        export_offset=changed,original_export=old,replacement_export=uleb(new,0)[0],
        executable_pages_preserved=True)
