"""Retain actionable evidence when preparation rejects a checksum."""
import hashlib
from pathlib import Path
import platform
import ssl
import sys

from common import KIT, digest, save


def mismatch(message, expected, actual, report_path=None, **details):
    report = dict(error=message, kit_version=(KIT/'VERSION').read_text().strip(),
                  expected_sha256=expected, actual_sha256=actual,
                  host=dict(system=platform.system(), release=platform.release(),
                            machine=platform.machine(), python=sys.version,
                            openssl=ssl.OPENSSL_VERSION), **details)
    description = (message+'\nExpected SHA-256: '+expected+
                   '\nActual SHA-256:   '+actual)
    if report_path is not None:
        report_path = Path(report_path).resolve()
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            save(report_path, report)
            description += '\nIntegrity report: '+str(report_path)
        except OSError as error:
            description += '\nCould not save integrity report: '+str(error)
    raise ValueError(description)


def require_bytes(data, expected, message, report_path=None, **details):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        mismatch(message, expected, actual, report_path, actual_bytes=len(data), **details)


def require_same_file(expected_path, actual_path, message, report_path, inputs=None):
    expected_path, actual_path = map(Path, (expected_path, actual_path))
    expected, actual = digest(expected_path), digest(actual_path)
    if expected == actual:
        return
    # Read only on failure. Include an offset, never image contents or keys.
    offset = 0
    first_difference = None
    with expected_path.open('rb') as original, actual_path.open('rb') as reproduced:
        while True:
            before, after = original.read(1024**2), reproduced.read(1024**2)
            if before != after:
                common = min(len(before), len(after))
                first_difference = offset + next(
                    (i for i in range(common) if before[i] != after[i]), common)
                break
            if not before:
                break
            offset += len(before)
    mismatch(message, expected, actual, report_path,
             expected_path=str(expected_path.resolve()), actual_path=str(actual_path.resolve()),
             expected_bytes=expected_path.stat().st_size, actual_bytes=actual_path.stat().st_size,
             first_difference=first_difference,
             inputs={name: dict(path=str(Path(path).resolve()), sha256=digest(path),
                               bytes=Path(path).stat().st_size)
                     for name, path in (inputs or {}).items()})
