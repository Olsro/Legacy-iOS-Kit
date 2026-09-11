"""Build generic device executables and empty volumes; no connected device needed.

Usage: python build.py CLANG MACH_O_LD STOCK_LIBRARIES MKFS_HFSPLUS OUTPUT
Run with the project's Python dependencies installed on Linux or macOS.
"""
from pathlib import Path
import gzip
import json
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from bootstrap_native import prepare, PROGRAMS
from common import digest
from hfs import HFS


def build(compiler,linker,libraries,formatter,output):
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    # P101AP is a model placeholder of the longest supported board-name length.
    native=output/'native'
    prepare('iPad3,4','0'*40,compiler,linker,libraries,native)
    for name in PROGRAMS:
        (output/name).write_bytes((native/name).read_bytes())
    for name,mib,clumps,label in [('root',30,'a=60,c=60,e=60','Olsn0wRoot'),('var',2,'a=16,c=8,e=8','Olsn0wVar')]:
        file=output/(name+'.hfs')
        with file.open('xb') as f:f.truncate(mib*1024**2)
        subprocess.run([formatter,'-s','-b','4096','-c',clumps,'-U','0','-G','0','-M','0755','-v',label,str(file)],check=True)
        image=HFS(file)
        if image.tree('/'):raise ValueError('Template is not empty')
        (output/(name+'.hfs.gz')).write_bytes(gzip.compress(file.read_bytes(),mtime=0))
    source=Path(__file__).resolve().parents[2]
    names=list(PROGRAMS)+['root.hfs.gz','var.hfs.gz']
    report=dict(format=1,board_placeholder='P101AP',serial_placeholder='0'*40,
        files={name:digest(output/name) for name in names},
        sources={str(p.relative_to(source)):digest(p) for p in list((source/'native/bootstrap').glob('*.[ch]'))+[source/'bootstrap_native.py',Path(__file__).resolve()]},
        templates={name:dict(bytes=(output/(name+'.hfs')).stat().st_size,sha256=digest(output/(name+'.hfs'))) for name in ('root','var')},
        native_provenance=json.loads((native/'manifest.json').read_text()))
    (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':build(*sys.argv[1:])
