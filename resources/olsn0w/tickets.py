"""Check the hardware binding in a legacy APTicket before handing it to the kit.

These checks do not replace Apple's signature verification in the restore tools.
"""
import plistlib
from common import MODELS, integer


def tlv(data, at):
    if at+2 > len(data):
        raise ValueError('Truncated DER item')
    tag, length = data[at:at+2]
    at += 2
    if tag & 31 == 31:
        raise ValueError('Unexpected extended DER tag')
    if length & 128:
        count = length & 127
        if not 1 <= count <= 4 or at+count > len(data) or data[at] == 0:
            raise ValueError('Invalid DER length')
        length = int.from_bytes(data[at:at+count], 'big')
        if length < 128:
            raise ValueError('Noncanonical DER length')
        at += count
    if at+length > len(data):
        raise ValueError('DER item extends outside container')
    return tag, data[at:at+length], at+length


def binding(shsh, product, ecid):
    record = plistlib.loads(shsh)
    ticket = record.get('APTicket')
    if not isinstance(ticket, bytes):
        raise ValueError('Missing legacy APTicket')
    tag, sequence, end = tlv(ticket, 0)
    if tag != 0x30 or end != len(ticket):
        raise ValueError('Invalid APTicket container')
    _, _, after_algorithm = tlv(sequence, 0)
    tag, fields, _ = tlv(sequence, after_algorithm)
    if tag != 0x31:
        raise ValueError('Missing APTicket field set')
    # Read the five fixed identity fields before the firmware digest tags,
    # which may use extended tag numbers in older ticket formats.
    values, at = {}, 0
    for expected, length in ((1,8),(2,4),(3,4),(4,4),(5,4)):
        tag, value, at = tlv(fields, at)
        if tag != 0x80+expected or len(value) != length:
            raise ValueError('Unrecognized APTicket hardware fields')
        values[expected] = int.from_bytes(value, 'little')
    _, chip, board = MODELS[product]
    if (values[1], values[2], values[3]) != (integer(ecid), chip, board):
        raise ValueError('APTicket belongs to a different device')
    if values[4] != 1 or values[5] != 1:
        raise ValueError('Unexpected production/security domain in APTicket')
    return dict(ecid=values[1], chip=values[2], board_id=values[3],
                signature_verification='delegated to the kit restore tool')
