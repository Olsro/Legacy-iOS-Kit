"""Qualify complete retry semantics rather than a coincidental branch pattern."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import kernelcache
import kernelcache_audit as audit

FUNCTION = 0x1200
FUNCTION_VA = 0x80a60200
THUNK_VA = 0x80a60800


def bl(source, target):
    bits = (target-source-4) & 0x1ffffff
    s, i1, i2 = bits >> 24, (bits >> 23) & 1, (bits >> 22) & 1
    return struct.pack('<HH', 0xf000 | s << 10 | (bits >> 12) & 0x3ff,
                       0xd000 | (1 ^ (i1 ^ s)) << 13 | (1 ^ (i2 ^ s)) << 11 | (bits >> 1) & 0x7ff)


def fixture(template=audit.RETRY_CODE):
    data = bytearray(0x4000)
    commands = b''
    for name, va, offset, size in ((b'__TEXT', 0x80001000, 0, 0x1000),
                                   (b'__PRELINK_TEXT', 0x80a60000, 0x1000, 0x2000),
                                   (b'__LINKEDIT', 0x80b00000, 0x3000, 0x1000)):
        commands += struct.pack('<II16s8I', 1, 56, name, va, size, offset, size, 7, 5, 0, 0)
    commands += struct.pack('<6I', 2, 24, 0x3000, 1, 0x3100, 0x20)
    data[:28] = struct.pack('<7I', 0xfeedface, 12, 9, 2, 4, len(commands), 0)
    data[28:28+len(commands)] = commands
    data[FUNCTION:FUNCTION+len(template)] = template
    for at in audit.LOG_CALLS:
        data[FUNCTION+at:FUNCTION+at+4] = bl(FUNCTION_VA+at, THUNK_VA)
    # movw ip,#0xf4; movt ip,#0; add ip,pc; ldr.w ip,[ip]; bx ip
    data[0x1800:0x1810] = bytes.fromhex('40f2f40cc0f2000cfc44dcf800c06047')
    struct.pack_into('<I', data, 0x1900, 0x80001501)
    struct.pack_into('<IBBHI', data, 0x3000, 1, 0xf, 1, 0, 0x80001500)
    data[0x3100:0x3109] = b'\0_IOLog\0\0'
    string_offset = 0x2000
    for slot, relative, text in audit.LITERALS:
        data[string_offset:string_offset+len(text)+1] = text+b'\0'
        address = 0x80a60000+string_offset-0x1000
        struct.pack_into('<i', data, FUNCTION+slot, address-FUNCTION_VA-relative)
        string_offset += len(text)+1
    struct.pack_into('<I', data, 0x1a00, FUNCTION_VA | 1)
    return data


class AuditTests(unittest.TestCase):
    def test_both_exact_layouts_propose_only_the_retry_branch_change(self):
        for template in (audit.RETRY_CODE, audit.IOS60_RETRY_CODE):
            with self.subTest(member=template[0x2c]):
                raw = bytes(fixture(template))
                report = audit.audit(raw)
                patch = report['patch']
                self.assertEqual(patch['offset'], FUNCTION+0x8a)
                self.assertEqual(patch['virtual_address'], FUNCTION_VA+0x8a)
                changed, _ = kernelcache.apply(raw, patch)
                self.assertEqual([i for i, (a,b) in enumerate(zip(raw, changed)) if a != b],
                                 [FUNCTION+0x8a, FUNCTION+0x8b])
                self.assertEqual(report['literal_references_verified'], 5)
                self.assertEqual(report['unchanged_member_load'], template[0x2c])
                self.assertFalse(report['physical_boot_verified'])

    def test_changed_error_check_retry_fallback_return_or_unknown_layout_is_rejected(self):
        for offset in (0x20, 0x28, 0x2c, 0x80, 0x88, 0x8a, 0x90, 0xa8, 0xac, 0xae):
            with self.subTest(offset=offset):
                raw = fixture(); raw[FUNCTION+offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'complete TriStar'):
                    audit.audit(raw)

    def test_masked_logging_calls_still_must_resolve_to_iolog(self):
        for change in ('not-call', 'wrong-target', 'wrong-import', 'missing-symbol'):
            with self.subTest(change=change):
                raw = fixture()
                if change == 'not-call':
                    raw[FUNCTION+0x74:FUNCTION+0x78] = bytes.fromhex('00bf00bf')
                elif change == 'wrong-target':
                    raw[FUNCTION+0x74:FUNCTION+0x78] = bl(FUNCTION_VA+0x74, THUNK_VA+0x20)
                elif change == 'wrong-import':
                    struct.pack_into('<I', raw, 0x1900, 0x80001505)
                else:
                    raw[0x3102] = ord('X')
                with self.assertRaises(ValueError):
                    audit.audit(raw)

    def test_property_and_each_diagnostic_reference_is_verified(self):
        for slot, _, _ in audit.LITERALS:
            with self.subTest(slot=slot):
                raw = fixture()
                struct.pack_into('<i', raw, FUNCTION+slot, 0)
                with self.assertRaisesRegex(ValueError, 'reference differs'):
                    audit.audit(raw)

    def test_missing_or_ambiguous_virtual_method_is_rejected(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                raw = fixture()
                struct.pack_into('<I', raw, 0x1a04 if duplicate else 0x1a00,
                                 FUNCTION_VA | 1 if duplicate else 0)
                with self.assertRaisesRegex(ValueError, 'virtual-method'):
                    audit.audit(raw)

    def test_duplicate_function_is_rejected_before_reference_resolution(self):
        raw = fixture()
        raw[0x1400:0x1400+0xd0] = raw[FUNCTION:FUNCTION+0xd0]
        with self.assertRaisesRegex(ValueError, 'ambiguous complete'):
            audit.audit(raw)

    def test_truncated_or_invalid_kernel_cannot_be_qualified(self):
        for raw in (b'', bytes(fixture()[:50]), bytes(0x4000)):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                audit.audit(raw)


if __name__ == '__main__':
    unittest.main()
