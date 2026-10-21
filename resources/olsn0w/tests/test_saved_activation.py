"""Saved certificates are untrusted until scoped and accepted by lockdownd."""
import io
import json
import plistlib
import subprocess
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from saved_activation import backup_path, load, token_identity, install


class SavedActivation(unittest.TestCase):
    identity = dict(product='iPod5,1', ecid=123)
    udid = 'a'*40
    name = 'private/var/root/Library/Lockdown/activation_records/activation_record.plist'

    def record(self, product='iPod5,1', udid=None):
        token = ('{ "ProductType" = "'+product+'"; "UniqueDeviceID" = "'+
                 (udid or self.udid)+'"; }').encode()
        return plistlib.dumps(dict(AccountToken=token, AccountTokenSignature=b'sig',
                                  AccountTokenCertificate=b'cert', DeviceCertificate=b'device',
                                  FairPlayKeyData=b'fairplay'))

    def archive(self, directory, entries):
        path = Path(directory)/'activation.tar'
        with tarfile.open(path, 'w') as tar:
            for name, data in entries:
                item = tarfile.TarInfo(name)
                if data is None:
                    item.type = tarfile.SYMTYPE
                    item.linkname = '/etc/passwd'
                    tar.addfile(item)
                else:
                    item.size = len(data)
                    tar.addfile(item, io.BytesIO(data))
        return path

    def test_select_only_device_ecid_and_product(self):
        with patch('saved_activation.KIT', Path('/kit')):
            self.assertEqual(backup_path(self.identity), Path('/kit/saved/iPod5,1/activation-123.tar'))
        for identity in (dict(product='../bad', ecid=123), dict(product='iPod5,1', ecid=True),
                         dict(product='iPod5,1', ecid=-1)):
            with self.assertRaises(ValueError):
                backup_path(identity)

    def test_recognized_locations_return_original_signed_bytes_only(self):
        for root in ('root/Library/Lockdown', 'mobile/Library/mad'):
            for filename in ('activation_record.plist', 'pod_record.plist'):
                with self.subTest(root=root, filename=filename), tempfile.TemporaryDirectory() as d:
                    original = self.record()
                    name = 'private/var/'+root+'/activation_records/'+filename
                    archive = self.archive(d, [(name, original),
                        ('private/var/'+root+'/data_ark.plist', b'ignored old state')])
                    record, report = load(archive, self.identity, self.udid.upper())
                    self.assertEqual(record, original)
                    self.assertFalse(report['activation_on_target_verified'])
                    self.assertEqual(report['ecid'], 123)

    def test_foreign_device_or_missing_observed_identity_rejected(self):
        for record, observed in ((self.record(udid='b'*40), self.udid),
                                 (self.record(product='iPhone4,1'), self.udid),
                                 (self.record(), None), (self.record(), 'invalid')):
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as d:
                archive = self.archive(d, [(self.name, record)])
                with self.assertRaises(ValueError):load(archive, self.identity, observed)

    def test_legacy_token_without_product_still_requires_matching_udid(self):
        for udid in (self.udid, 'b'*40, None, 123, ''):
            with self.subTest(udid=udid), tempfile.TemporaryDirectory() as d:
                record=plistlib.loads(self.record())
                token={} if udid is None else {'UniqueDeviceID':udid}
                record['AccountToken']=plistlib.dumps(token)
                original=plistlib.dumps(record)
                archive=self.archive(d,[(self.name,original)])
                if udid==self.udid:
                    restored,_=load(archive,self.identity,self.udid)
                    self.assertEqual(restored,original)
                else:
                    with self.assertRaises(ValueError):load(archive,self.identity,self.udid)

    def test_explicit_empty_or_foreign_product_is_not_treated_as_missing(self):
        for product in ('',None,'iPhone4,1'):
            with self.subTest(product=product), tempfile.TemporaryDirectory() as d:
                record=plistlib.loads(self.record())
                token={'UniqueDeviceID':self.udid,'ProductType':product}
                record['AccountToken']=json.dumps(token).encode()
                archive=self.archive(d,[(self.name,plistlib.dumps(record))])
                with self.assertRaisesRegex(ValueError,'ProductType differs'):
                    load(archive,self.identity,self.udid)

    def test_unsafe_ambiguous_incomplete_archives_rejected(self):
        original = self.record()
        cases = [
            [(self.name, original), (self.name, original)],
            [(self.name, original), ('../escape', b'bad')],
            [(self.name, original), ('/absolute', b'bad')],
            [(self.name, original), ('private/var/link', None)],
            [(self.name, original), (self.name.replace('activation_record.plist', 'pod_record.plist'), original)],
            [(self.name, plistlib.dumps(dict(AccountToken=b'x')))],
            [(self.name, plistlib.dumps([]))],
            [('private/var/unrelated', b'no record')],
            [(self.name, b'x'*(4*1024*1024+1))],
        ]
        for entries in cases:
            with self.subTest(names=[n for n, _ in entries]), tempfile.TemporaryDirectory() as d:
                archive = self.archive(d, entries)
                with self.assertRaises(ValueError):load(archive, self.identity, self.udid)

    def test_archive_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            archive = self.archive(d, [(self.name, self.record())])
            link = Path(d)/'link.tar'; link.symlink_to(archive)
            with self.assertRaises(ValueError):load(link, self.identity, self.udid)

    def test_token_formats_and_ambiguity(self):
        self.assertEqual(token_identity(b'{"ProductType":"iPod5,1"}')['ProductType'], 'iPod5,1')
        self.assertEqual(token_identity(plistlib.dumps({'ProductType':'iPod5,1'}))['ProductType'], 'iPod5,1')
        for token in (b'{ "a" = "b"; "a" = "c"; }', b'{ "a" = "b"; garbage }', b'[]'):
            with self.assertRaises(ValueError):token_identity(token)

    def test_installer_writes_only_signed_record_and_reloads_daemon(self):
        for cellular, name in ((True, 'activation_record.plist'), (False, 'pod_record.plist')):
            with self.subTest(cellular=cellular), patch('saved_activation.subprocess.run',
                    return_value=subprocess.CompletedProcess([],0,b'',b'')) as run:
                record=self.record()
                install(['ssh','selected-device'],record,has_baseband=cellular)
                command=run.call_args.args[0]
                self.assertEqual(command[:2],['ssh','selected-device'])
                self.assertEqual(run.call_args.kwargs['input'],record)
                script=command[-1]
                self.assertIn('file="$dir/'+name+'"',script)
                self.assertIn('test ! -L "$file"',script)
                self.assertIn('cp -p "$file"',script)
                self.assertIn('mv "$tmp" "$file"',script)
                self.assertIn('/usr/bin/killall -TERM lockdownd',script)
                self.assertNotIn('data_ark',script)
                self.assertNotIn('reboot',script)

    def test_installer_failure_cannot_be_reported_as_activation(self):
        with patch('saved_activation.subprocess.run',
                   return_value=subprocess.CompletedProcess([],1,b'',b'write failure')):
            with self.assertRaisesRegex(RuntimeError,'write failure'):
                install(['ssh','selected-device'],self.record(),has_baseband=False)
