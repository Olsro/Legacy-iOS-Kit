"""Capacity policy for HFS target roots and small bootstrap volumes.

The target root keeps the HFS desired free-space level plus headroom. Small
auxiliary volumes retain the non-root warning fraction (2%, rounded in blocks).
No thresholds are changed. Device names and sizes come from the volume layout.
"""
import re
import struct
from image_capacity import root_reserve_bytes


def reserve_report(image, staging_bytes=0, *, root=False):
    with open(image, 'rb') as stream:
        stream.seek(1024)
        header = stream.read(512)
    if header[:2] not in (b'H+', b'HX'):
        raise ValueError('Expected an HFS+ or HFSX image')
    block, total, free = struct.unpack_from('>III', header, 40)
    if block not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
        raise ValueError('Unsupported allocation block size')
    if not 0 <= staging_bytes <= block * total or free > total:
        raise ValueError('Invalid staging budget or free block count')
    warning = min(150 * 1024 * 1024 // block, (total // 100) * 2)
    required = warning * block + ((staging_bytes + block - 1) // block) * block + 65536
    if root:
        warning = min(1024**3 // block, (total // 100) * 10)
        required = root_reserve_bytes(block * total, block) + ((staging_bytes + block - 1) // block) * block
    report = dict(volume_bytes=block * total, free_bytes=block * free,
                  staging_bytes=staging_bytes, required_bytes=required,
                  warning_blocks=warning, sufficient=block * free >= required)
    return report


def require_reserve(image, staging_bytes=0, *, root=False):
    report = reserve_report(image, staging_bytes, root=root)
    if not report['sufficient']:
        role = 'Target root' if root else 'Bootstrap'
        raise ValueError(f'{role} capacity reserve insufficient; regenerate the restore bundle: {report}')
    return report


def render_layout(root_device, root_bytes, data_device, data_bytes):
    """Generate a shell config from a validated restoration layout, not an OS version."""
    if root_device == data_device:
        raise ValueError('Auxiliary volumes must be distinct')
    lines = ['# Generated bootstrap volume layout.']
    for role, device, size in [('ROOT', root_device, root_bytes), ('DATA', data_device, data_bytes)]:
        if not re.fullmatch(r'/dev/disk[0-9]+s[0-9]+(?:s[0-9]+)?', device):
            raise ValueError('Invalid volume device')
        if type(size) is not int or not 1048576 <= size <= 67108864 or size % 4096:
            raise ValueError('Invalid auxiliary volume size')
        lines += [f'RB_{role}_DEVICE={device}', f'RB_{role}_BYTES={size}']
    return '\n'.join(lines) + '\n'
