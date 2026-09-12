"""Select and recheck a recovery device before device-specific preparation."""
import json
import os
from pathlib import Path
import uuid

from common import MODELS, STATE, integer, run, tools


def same_hardware(left, right):
    """A DFU/recovery transition does not change the selected hardware."""
    fields=('product','board','chip','board_id','ecid')
    return all(key in left and key in right and left[key]==right[key] for key in fields)


def parse_recovery(output, expected_ecid=None):
    fields = {}
    for line in output.splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key, value = key.strip(), value.strip()
        if key in fields:
            raise ValueError('Duplicate recovery identity field: ' + key)
        fields[key] = value
    product = fields.get('PRODUCT')
    if product not in MODELS:
        raise ValueError('Recovery device is not in the signed iOS 8.4.1 product set')
    board, chip, board_id = MODELS[product]
    if (fields.get('MODEL', '').lower() != board or integer(fields['CPID']) != chip
            or integer(fields['BDID']) != board_id):
        raise ValueError('Recovery product/chip/board mismatch')
    ecid = integer(fields['ECID'])
    if not 0 < ecid < 2**64:
        raise ValueError('Invalid recovery ECID')
    if expected_ecid is not None and ecid != integer(expected_ecid):
        raise ValueError('Connected device differs from the selected restoration target')
    mode = fields.get('MODE')
    if mode not in ('Recovery', 'DFU'):
        raise ValueError('Unsupported recovery device mode: ' + str(mode))
    # Keep only what the restore needs; serial numbers and nonces are omitted.
    return dict(product=product, board=board, chip=chip, board_id=board_id,
                ecid=ecid, mode=mode)


def query_recovery(ecid):
    expected = integer(ecid)
    if not 0 < expected < 2**64:
        raise ValueError('An explicit valid ECID is required')
    result = run([tools() / 'irecovery', '-i', hex(expected), '-q'], timeout=15)
    return parse_recovery(result.decode(), expected)


def select_recovery(ecid):
    identity = query_recovery(ecid)
    folder = STATE / 'sessions' / str(uuid.uuid4())
    folder.mkdir(parents=True, mode=0o700)
    record = dict(identity=identity, device_modified=False, state='selected')
    with os.fdopen(os.open(folder / 'device.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    return folder


def recheck_recovery(session):
    expected = json.loads((Path(session) / 'device.json').read_text())['identity']
    actual = query_recovery(expected['ecid'])
    for key in ('product', 'board', 'chip', 'board_id', 'ecid'):
        if actual[key] != expected[key]:
            raise ValueError('Restoration target changed: ' + key)
    return actual
