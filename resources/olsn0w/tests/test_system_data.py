"""Package overlays must retain the selected firmware's directory access policy."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from system import entry, merge_data_payload, remove_setup_application


class DataOverlay(unittest.TestCase):
    def test_setup_application_removal_is_verified(self):
        class Image:
            present=True
            def ls(self,path):
                self.assert_path=path
                return ([{'name':'Setup.app','mode':0o040755}]
                        if self.present else [])
            def command(self,action,path):
                if (action,path)!=('rmall','/Applications/Setup.app'):
                    raise AssertionError((action,path))
                self.present=False
        image=Image()
        remove_setup_application(image)
        self.assertFalse(image.present)

    def test_stock_directories_survive_restrictive_package_metadata(self):
        for stock_mode in (0o711, 0o755):
            with self.subTest(stock_mode=stock_mode):
                stock = {name: entry(name, mode=stock_mode, uid=501, gid=501,
                                     directory=True)
                         for name in ('mobile', 'mobile/Library')}
                payload = {name: entry(name, mode=mode, uid=0, gid=0, directory=True)
                           for name, mode in (('private/var/mobile', 0o750),
                                              ('private/var/mobile/Library', 0o700))}
                merge_data_payload(stock, payload)
                self.assertFalse(payload)
                for item, _ in stock.values():
                    self.assertEqual((item.mode, item.uid, item.gid),
                                     (stock_mode, 501, 501))

    def test_files_and_new_directories_are_still_overlaid(self):
        stock = {'lib/status': entry('lib/status', b'old')}
        new_dir = entry('private/var/lib/new', mode=0o700, directory=True)
        root_file = entry('usr/bin/tool', b'tool', 0o755)
        payload = {'private/var/lib/status': entry('private/var/lib/status', b'new'),
                   'private/var/lib/new': new_dir,
                   'private/var': entry('private/var', directory=True),
                   'usr/bin/tool': root_file}
        merge_data_payload(stock, payload)
        self.assertEqual(stock['lib/status'][1], b'new')
        self.assertEqual(stock['lib/new'][0].mode, 0o700)
        self.assertEqual(new_dir[0].name, 'private/var/lib/new')
        self.assertEqual(payload, {'usr/bin/tool': root_file})


if __name__ == '__main__':
    unittest.main()
