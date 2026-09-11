"""Remove the firmware's FileVault v2 envelope, preserving its original UDIF.

The on-disk fields and per-block IV follow xpwn's dmg/filevault.c. This does
not rebuild the disk image or discard the ASR scan/checksum metadata.
"""
import hashlib
import hmac
from pathlib import Path
import re
import struct

from Crypto.Cipher import AES
from progress import activity


def decrypt_stream(incoming, encrypted_bytes, destination, key):
    """Decrypt a sequential firmware member without storing its envelope."""
    destination = Path(destination)
    if not re.fullmatch(r'[0-9a-fA-F]{72}', key):
        raise ValueError('Expected a FileVault AES/HMAC firmware key')
    key = bytes.fromhex(key)
    header = incoming.read(72)
    if len(header) != 72 or header[:8] != b'encrcdsa' or struct.unpack_from('>I', header, 8)[0] != 2:
        raise ValueError('Expected a FileVault v2 firmware image')
    block, size, offset = struct.unpack_from('>IQQ', header, 52)
    count = (size + block - 1) // block if block else 0
    if (block < 16 or block > 4096 or block % 16 or size < 512 or
            count > 2**32 or offset < 72 or offset + count * block > encrypted_bytes):
        raise ValueError('Invalid or truncated FileVault image geometry')
    skip=offset-72
    while skip:
        chunk=incoming.read(min(skip,1024**2))
        if not chunk:raise ValueError('Truncated FileVault header area')
        skip-=len(chunk)
    # Exclusive creation prevents replacing an earlier qualified image.
    with activity('Decrypting signed system image',size) as update, destination.open('xb') as outgoing:
        try:
            remaining = size
            for index in range(count):
                data = incoming.read(block)
                if len(data) != block:
                    raise ValueError('Truncated encrypted block')
                iv = hmac.new(key[16:], struct.pack('>I', index), hashlib.sha1).digest()[:16]
                plain = AES.new(key[:16], AES.MODE_CBC, iv).decrypt(data)
                outgoing.write(plain[:min(remaining, block)])
                remaining -= min(remaining, block)
                if index%256==0:update(size-remaining)
            outgoing.flush()
            with destination.open('rb') as check:
                check.seek(-512, 2)
                trailer = check.read(512)
            if trailer[:4] != b'koly' or struct.unpack_from('>II', trailer, 4) != (4, 512):
                raise ValueError('Decrypted image has no valid UDIF trailer')
        except BaseException:
            outgoing.close()
            destination.unlink()
            raise
    return destination


def decrypt(source, destination, key):
    source=Path(source)
    with source.open('rb') as incoming:
        return decrypt_stream(incoming,source.stat().st_size,destination,key)
