"""Instantiate checked ARM templates without a host SDK or Mach-O linker."""
import gzip
import hashlib
import json
from pathlib import Path

from bootstrap_native import PROGRAMS, ENTITLEMENTS, configuration
from common import MODELS, digest, hardware_model, save
from signing import resign, verify


def prepare(product, serial, destination):
    configuration(product, serial)
    destination=Path(destination)
    source=Path(__file__).parent
    assets=source/'target/bootstrap'
    report=json.loads((assets/'manifest.json').read_text())
    expected=set(PROGRAMS)|{'root.hfs.gz','var.hfs.gz'}
    if report['format']!=1 or set(report['files'])!=expected:
        raise ValueError('Incomplete bootstrap templates')
    for root,table in ((source,report['sources']),(assets,report['files'])):
        for name,sha in table.items():
            if Path(name).is_absolute() or '..' in Path(name).parts or digest(root/name)!=sha:
                raise ValueError('Bootstrap template/source changed: '+name)
    destination.mkdir(parents=True,exist_ok=False)
    board=report['board_placeholder'].encode()+b'\0'
    serial_token=report['serial_placeholder'].encode()+b'\0'
    for name in PROGRAMS:
        data=(assets/name).read_bytes();verify(data)
        board_count=1
        serial_count=1 if name=='root_start' else 0
        if data.count(board)!=board_count or data.count(serial_token)!=serial_count:
            raise ValueError('Ambiguous template constants: '+name)
        data=data.replace(board,hardware_model(MODELS[product][0]).encode().ljust(len(board),b'\0'))
        data=data.replace(serial_token,serial.lower().encode()+b'\0')
        output=destination/name;output.write_bytes(data)
        resign(output,ENTITLEMENTS)
    for name,mib in [('root',30),('var',2)]:
        size=mib*1024**2
        with gzip.open(assets/(name+'.hfs.gz'),'rb') as stream:
            data=stream.read(size+1)
        if len(data)!=size or hashlib.sha256(data).hexdigest()!=report['templates'][name]['sha256']:
            raise ValueError('Invalid empty volume template')
        (destination/(name+'.hfs')).write_bytes(data)
    save(destination/'manifest.json',dict(product=product,base_build='12H321',
        files={p.name:digest(p) for p in destination.iterdir()},physical_boot_verified=False))
    return destination
