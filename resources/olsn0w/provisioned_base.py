"""Bind a freshly signed technical collection to a prepared compact bootstrap."""
import json
from pathlib import Path
import shutil

from common import clone_or_copy, digest
from hfs import HFS
from hfs_policy import require_reserve
from layout import inspect
from provision_collect import KERNEL
from restore import checked_manifest, checkpoint


def prepare(collection, bootstrap, destination):
    collection, bootstrap, destination = map(Path, (collection, bootstrap, destination))
    technical = json.loads((collection/'collection.json').read_text())
    compact = checked_manifest(bootstrap)
    if (technical.get('source') != 'completed-signed-base-restore' or technical.get('build') != '12H321' or
            compact.get('product') != technical['identity']['product'] or compact.get('base_build') != '12H321'):
        raise ValueError('Fresh signed collection and compact bootstrap differ')
    for name, expected in technical['files'].items():
        path = collection/name
        if Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink():
            raise ValueError('Invalid technical collection path')
        if path.stat().st_size != expected['bytes'] or digest(path) != expected['sha256']:
            raise ValueError('Fresh technical artifact changed')
    if not {KERNEL, 'gpt-primary.bin', 'gpt-secondary.bin'}.issubset(technical['files']):
        raise ValueError('Incomplete signed technical collection')
    inspect((collection/'gpt-primary.bin').read_bytes(), (collection/'gpt-secondary.bin').read_bytes())
    if destination.exists():raise ValueError('Preserve the earlier signed base')
    destination.mkdir(parents=True, mode=0o700)
    shutil.copytree(collection, destination/'technical')
    for name in ('root8.hfs', 'data8.hfs'):
        clone_or_copy(bootstrap/name, destination/name)
    root = HFS(destination/'root8.hfs')
    if root.read('/olsn0w/bootstrap.marker') != b'olsn0w-bootstrap-v1':
        raise ValueError('Invalid compact bootstrap marker')
    # Personalization belongs to this completed restore, even if an earlier
    # same-model kernel was used while preparing the host image.
    root.replace_regular('/'+KERNEL, (collection/KERNEL).read_bytes())
    if root.read('/'+KERNEL) != (collection/KERNEL).read_bytes():
        raise ValueError('Fresh signed kernel readback differs')
    for name in ('root8.hfs', 'data8.hfs'):require_reserve(destination/name)
    for name in ('gpt-primary.bin', 'gpt-secondary.bin'):
        shutil.copyfile(collection/name, destination/name)
    report = dict(kind='fresh-signed-base', identity=technical['identity'],
                  signed_restore_verified=True, bootstrap_inputs_verified=True,
                  activated_base_verified=False, autonomous_boot_verified=False,
                  activation_mode='official-on-target',
                  files={str(p.relative_to(destination)):digest(p) for p in destination.rglob('*') if p.is_file()})
    checkpoint(destination/'manifest.json', report)
    return report
