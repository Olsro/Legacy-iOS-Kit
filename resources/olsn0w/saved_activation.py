"""Read a Kit activation backup without extracting or modifying its certificate.

Identity checks are a selection guard, not signature verification. The target's
lockdownd must accept the original Apple record before activation is successful.
"""
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import tarfile

from common import KIT, MODELS
from archives import member_path


def backup_path(identity):
    product, ecid = identity.get('product'), identity.get('ecid')
    if product not in MODELS or type(ecid) is not int or ecid <= 0:
        raise ValueError('Invalid saved activation device identity')
    return KIT/'saved'/product/('activation-'+str(ecid)+'.tar')


def _openstep_string(text):
    """Decode a quoted OpenStep string for identity inspection only."""
    escapes = {'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r',
               't': '\t', 'v': '\v', '"': '"', '\\': '\\'}
    def replace(match):
        value = match[1]
        if value.startswith('U') and len(value) == 5:
            return chr(int(value[1:], 16))
        if value[0] in '01234567':
            return chr(int(value, 8))
        if value not in escapes:
            raise ValueError('Unsupported escape in saved activation token')
        return escapes[value]
    return re.sub(r'\\(U[0-9a-fA-F]{4}|[0-7]{1,3}|.)', replace, text, flags=re.S)


def token_identity(data):
    """Apple's older AccountToken uses an OpenStep string dictionary."""
    try:
        value = plistlib.loads(data)
    except plistlib.InvalidFileException:
        text = data.decode('utf-8')
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            if not text.strip().startswith('{') or not text.strip().endswith('}'):
                raise ValueError('Unrecognized saved activation token')
            text = text.strip()[1:-1]
            # A cellular WildcardTicket can contain escaped newlines. Parse
            # string boundaries before decoding escapes so ticket contents
            # cannot be confused with dictionary delimiters or identity keys.
            pattern = re.compile(r'\s*"((?:[^"\\]|\\.)+)"\s*=\s*"((?:[^"\\]|\\.)*)"\s*;', re.S)
            value = {}
            while text.strip():
                match = pattern.match(text)
                if not match:
                    raise ValueError('Ambiguous saved activation token')
                key = _openstep_string(match[1])
                if key in value:
                    raise ValueError('Ambiguous saved activation token')
                value[key] = _openstep_string(match[2])
                text = text[match.end():]
    if not isinstance(value, dict):
        raise ValueError('Expected saved activation token dictionary')
    return value


def load(path, identity, udid):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16*1024*1024:
        raise ValueError('Invalid saved activation archive')
    if not isinstance(udid, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', udid):
        raise ValueError('Observed device UDID required for saved activation')
    # Check the selection even for explicitly supplied test/staging paths.
    backup_path(identity)
    raw = path.read_bytes()
    import io
    files, seen = {}, set()
    total = 0
    roots = ('root/Library/Lockdown/', 'mobile/Library/mad/')
    record_paths = {r+'activation_records/'+n for r in roots
                    for n in ('activation_record.plist', 'pod_record.plist')}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as archive:
        for item in archive:
            name = member_path(item.name)
            if name is None:
                continue
            if name in seen:
                raise ValueError('Duplicate saved activation archive member')
            seen.add(name)
            if len(seen) > 1024:
                raise ValueError('Oversized saved activation archive')
            if item.isdir():
                continue
            if not item.isfile() or item.size > 4*1024*1024:
                raise ValueError('Unsafe saved activation archive member')
            total += item.size
            if total > 16*1024*1024:
                raise ValueError('Oversized expanded activation archive')
            if not name.startswith('private/var/'):
                raise ValueError('Unexpected saved activation archive path')
            relative = name[len('private/var/'):]
            # Do not overwrite current data_ark, pairing, FairPlay or radio
            # preferences. lockdownd installs the accepted record itself.
            if relative in record_paths:
                files[relative] = archive.extractfile(item).read()
    records = sorted(record_paths & files.keys())
    if len(records) != 1:
        raise ValueError('Saved activation needs exactly one record')
    record = plistlib.loads(files[records[0]])
    if not isinstance(record, dict):
        raise ValueError('Invalid saved Apple activation record')
    for key in ('AccountToken', 'AccountTokenSignature', 'AccountTokenCertificate',
                'DeviceCertificate', 'FairPlayKeyData'):
        if not isinstance(record.get(key), bytes) or not record[key]:
            raise ValueError('Incomplete saved Apple activation record')
    token = token_identity(record['AccountToken'])
    # Older Apple tokens omit ProductType (observed in a stock pod_record).
    # The real target UDID remains mandatory; ECID/product are independently
    # checked by activation.activate before this archive is selected.
    token_udid = token.get('UniqueDeviceID')
    if not isinstance(token_udid, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', token_udid):
        raise ValueError('Saved activation record lacks a valid device UDID')
    if token_udid.lower() != udid.lower():
        raise ValueError('Saved activation record belongs to another device (UDID differs)')
    if 'ProductType' in token and token['ProductType'] != identity['product']:
        raise ValueError('Saved activation record belongs to another model (ProductType differs)')
    return files[records[0]], dict(source='saved-selected-device-records',
                          archive_sha256=hashlib.sha256(raw).hexdigest(),
                          record_sha256=hashlib.sha256(files[records[0]]).hexdigest(),
                          product=identity['product'], ecid=identity['ecid'],
                          activation_on_target_verified=False)


def install(prefix, record, *, has_baseband):
    """Restore just the signed record through the authenticated target SSH.

    No data_ark or activation-state flag is written. lockdownd must independently
    validate the restored record after reloading. Keep any previous record for
    recovery, and do not follow device-side symlinks.
    """
    name = 'activation_record.plist' if has_baseband else 'pod_record.plist'
    script = r'''set -eu
umask 077
base=/private/var/root/Library/Lockdown
test -d "$base"
test ! -L "$base"
dir="$base/activation_records"
test ! -L "$dir"
if test ! -d "$dir"; then mkdir -m 700 "$dir"; fi
file="$dir/RECORD_NAME"
test ! -L "$file"
if test -e "$file"; then
    test -f "$file"
    backup=$(mktemp -d "$base/olsn0w-record-backup.XXXXXX")
    cp -p "$file" "$backup/RECORD_NAME"
fi
tmp=$(mktemp "$dir/olsn0w-record.XXXXXX")
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
chmod 600 "$tmp"
chown 0:0 "$tmp"
mv "$tmp" "$file"
sync
/usr/bin/killall -TERM lockdownd
'''.replace('RECORD_NAME', name)
    result = subprocess.run(prefix+[script], input=record, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Could not restore saved activation record through target SSH: '+
                           result.stderr.decode('utf-8', errors='replace')[-1000:])
