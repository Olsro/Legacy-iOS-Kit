"""Qualified two-image A5 loader; never substitute the contiguous A6 loader."""
import json
from pathlib import Path

from common import digest
from signing import verify

QUALIFIED_SHA256 = 'bfd4cf716271522e6a1e62393b3c44a0de50adb288b6692b372498c0f5658df1'


def payload():
    base=Path(__file__).parent
    assets=base/'target/a5-loader'
    report=json.loads((assets/'manifest.json').read_text())
    binary=assets/'multi_kloader'
    if report.get('sha256')!=QUALIFIED_SHA256 or digest(binary)!=QUALIFIED_SHA256:
        raise ValueError('Unqualified A5 two-image loader')
    if digest(base/'native/a5-loader/multi_kloader.c')!=report['source_sha256']:
        raise ValueError('A5 loader source provenance changed')
    data=binary.read_bytes();verify(data)
    return data


WRAPPER = (b'#!/bin/bash\nexec /usr/local/bin/4smulti_kloader '
           b'/olsn0w/iBSS.raw /olsn0w/iBEC.img3 '
           b'>>/var/log/olsn0w-multi-kloader.log 2>&1\n')


def relay_images(product, folder):
    from bootchain import RECIPE_VERSION, memory_layout
    from restore import checked_manifest
    folder=Path(folder);chain=checked_manifest(folder)
    first,second=memory_layout(product)
    if (chain.get('recipe_version')!=RECIPE_VERSION or chain.get('product')!=product
            or chain.get('loader')!='a5-two-image'
            or not {'relay.bin','iBSS.patched.raw','iBEC.img3'}<=set(chain['files'])
            or chain['relay_memory']['first']!=first or chain['relay_memory']['second']!=second):
        raise ValueError('A5 relay does not match the two-image loader contract')
    return {'iBSS.raw':(folder/'iBSS.patched.raw').read_bytes(),
            'iBEC.img3':(folder/'iBEC.img3').read_bytes()}
