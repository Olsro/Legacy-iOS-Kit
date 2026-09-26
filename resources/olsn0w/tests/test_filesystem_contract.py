"""Keep the stock application contract distinct from runtime qualification."""
import copy
from pathlib import Path, PurePosixPath
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from filesystem_contract import (
    SYSTEM_DIRECTORIES, DATA_DIRECTORIES, STOCK_FILES, verify_ios6_contract,
    verify_directory_contract,
)


class Image:
    def __init__(self):
        self.records = {}
        self.contents = {}

    def ls(self, parent):
        return [dict(name=PurePosixPath(name).name, **record)
                for name, record in self.records.items()
                if str(PurePosixPath(name).parent) == parent]

    def read(self, name):
        return self.contents[name]


class StockContract(unittest.TestCase):
    def setUp(self):
        self.stock = Image()
        self.data = {}
        for name in SYSTEM_DIRECTORIES:
            self.stock.records[name] = dict(mode=0o40775, uid=0, gid=80)
        for name in (*DATA_DIRECTORIES, 'mobile/Applications'):
            mode = 0o1777 if name == 'tmp' else 0o711
            uid = 0 if name == 'tmp' else 501
            self.stock.records['/private/var/'+name] = dict(
                mode=0o40000 | mode, uid=uid, gid=uid)
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.uid, item.gid = tarfile.DIRTYPE, mode, uid, uid
            self.data[name] = (item, None)
        for arch in ('armv7', 'armv7s'):
            cache = '/System/Library/Caches/com.apple.dyld/dyld_shared_cache_'+arch
            for name in (*STOCK_FILES, cache):
                self.stock.records[name] = dict(mode=0o100755, uid=0, gid=0)
                self.stock.contents[name] = name.encode()
        self.prepared = copy.deepcopy(self.stock)

    def verify(self, arch='armv7'):
        return verify_ios6_contract(self.stock, self.prepared, self.data, arch)

    def test_stock_contract_does_not_claim_runtime_or_protection_validation(self):
        for arch in ('armv7', 'armv7s'):
            report = self.verify(arch)
            self.assertEqual(len(report['files']), 6)
            self.assertEqual(len(report['directories']), 12)
            self.assertFalse(report['content_protection_verified'])
            self.assertFalse(report['application_runtime_verified'])

    def test_system_directory_permissions_and_owner(self):
        for field, value in (('mode', 0o40755), ('uid', 501), ('gid', 0)):
            with self.subTest(field=field):
                self.prepared = copy.deepcopy(self.stock)
                self.prepared.records['/Library'][field] = value
                with self.assertRaisesRegex(ValueError, 'directory metadata'):
                    self.verify()

    def test_data_mode_and_sticky_bit_are_preserved(self):
        for name in ('mobile', 'tmp'):
            with self.subTest(name=name):
                original = self.data[name][0].mode
                self.data[name][0].mode = 0o755
                with self.assertRaisesRegex(ValueError, 'Data directory'):
                    self.verify()
                self.data[name][0].mode = original

    def test_missing_data_directory(self):
        self.data.pop('mobile/Library/Preferences')
        with self.assertRaisesRegex(ValueError, 'Data directory'):
            self.verify()

    def test_modified_installer_job_is_not_silently_admitted(self):
        self.prepared.contents[STOCK_FILES[-1]] += b'injection'
        with self.assertRaisesRegex(ValueError, 'service content'):
            self.verify()

    def test_executable_permissions_are_checked(self):
        self.prepared.records['/usr/libexec/installd']['mode'] = 0o100644
        with self.assertRaisesRegex(ValueError, 'service metadata'):
            self.verify()

    def test_unknown_cache_architecture(self):
        with self.assertRaisesRegex(ValueError, 'architecture'):
            self.verify('unknown')

    def test_common_check_accepts_stock_container_layout_without_apps_directory(self):
        old, new = 'mobile/Applications', 'mobile/Containers'
        self.stock.records['/private/var/'+new] = self.stock.records.pop('/private/var/'+old)
        item, content = self.data.pop(old)
        item.name = new
        self.data[new] = item, content
        # iOS 7/8 may intentionally modify services; common checks must not
        # compare their binaries to the iOS 6 unchanged-service contract.
        self.prepared.contents.clear()
        result = verify_directory_contract(self.stock, self.prepared, self.data)
        self.assertIn('/private/var/'+new, result)
        self.assertNotIn('/private/var/'+old, result)
        item.uid = 0
        with self.assertRaisesRegex(ValueError, 'Data directory'):
            verify_directory_contract(self.stock, self.prepared, self.data)


if __name__ == '__main__':
    unittest.main()
