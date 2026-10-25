"""Cover host-specific DFU preparation sequences."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rescue


class PrepareDFU(unittest.TestCase):
    def setUp(self):
        backend = patch('usb_backend.get_backend', return_value=object())
        self.backend = backend.start().return_value
        self.addCleanup(backend.stop)

    def test_unique_dfu_ignores_normal_mode_apple_devices(self):
        selected=SimpleNamespace(idProduct=0x1227,iSerialNumber=1)
        devices=[SimpleNamespace(idProduct=0x12a8),selected,SimpleNamespace(idProduct=0x1261)]
        with patch('usb.core.find',return_value=devices) as find, \
             patch('usb.util.get_string',return_value='CPID:8940 ECID:00000024c0036d8f'), \
             patch('usb.util.dispose_resources') as dispose:
            rescue.unique_usb_target(0x24c0036d8f)
            find.assert_called_once_with(find_all=True,idVendor=0x05ac,backend=self.backend)
            dispose.assert_called_once_with(selected)

    def test_unique_dfu_rejects_other_boot_interfaces_and_wrong_ecid(self):
        selected=SimpleNamespace(idProduct=0x1227,iSerialNumber=1)
        for other in (0x1222,0x1227,0x1280,0x1281,0x1282,0x1283):
            with patch('usb.core.find',return_value=[selected,SimpleNamespace(idProduct=other)]):
                with self.assertRaisesRegex(ValueError,'only the selected device'):
                    rescue.unique_usb_target(0x24c0036d8f)
        with patch('usb.core.find',return_value=[selected]), \
             patch('usb.util.get_string',return_value='ECID:1'), \
             patch('usb.util.dispose_resources') as dispose:
            with self.assertRaisesRegex(ValueError,'identity differs'):
                rescue.unique_usb_target(0x24c0036d8f)
            dispose.assert_called_once_with(selected)

    def test_checkm8_marker_accepts_irecovery_renderings_only(self):
        self.assertTrue(rescue.has_checkm8_marker('PWND: [checkm8]\n'))
        self.assertTrue(rescue.has_checkm8_marker('PWND: checkm8\n'))
        self.assertTrue(rescue.has_checkm8_marker('CPID: 0x8940\nPWND:[checkm8]\nMODE: DFU\n'))
        self.assertFalse(rescue.has_checkm8_marker('PWND: checkm8-extra\n'))
        self.assertFalse(rescue.has_checkm8_marker('note PWND: checkm8\n'))

    def session(self, root):
        session = Path(root)
        (session/'device.json').write_text(json.dumps({
            'identity': {'ecid': 0x1305409a38b, 'product': 'iPhone5,2'}
        }))
        return session

    def test_apple_silicon_uses_qualified_rosetta_sequence(self):
        with tempfile.TemporaryDirectory() as root:
            calls=[]
            def run(argv, label, timeout=45):
                calls.append((list(map(str, argv)), label, timeout))
                return 'SRTG: N/A\nIBFL: 0x1b\n' if label == 'ibss-ready' else ''
            with patch.object(rescue.platform, 'system', return_value='Darwin'), \
                 patch.object(rescue.platform, 'machine', return_value='arm64'), \
                 patch.object(rescue, 'unique_usb_target'), \
                 patch.object(rescue, 'recheck_recovery', return_value={'mode':'DFU'}), \
                 patch.object(rescue.time, 'sleep'):
                rescue.prepare_dfu(self.session(root), run=run)
            self.assertEqual(calls[0],
                (['arch','-x86_64',str(rescue.KIT/'bin/macos/ipwnder'),'-pv'],'pwn',60))
            self.assertEqual(calls[1],
                (['arch','-x86_64',str(rescue.KIT/'bin/macos/gaster'),'reset'],'pwn-reset',60))
            self.assertEqual(calls[2][1], 'ibss-ready')

    def test_already_pwned_skips_host_exploit(self):
        with tempfile.TemporaryDirectory() as root:
            calls=[]
            def run(argv, label, timeout=45):
                calls.append(label)
                return 'SRTG: N/A\nIBFL: 0x1b\n'
            with patch.object(rescue, 'unique_usb_target'), \
                 patch.object(rescue, 'recheck_recovery', return_value={'mode':'DFU'}), \
                 patch.object(rescue.time, 'sleep'):
                rescue.prepare_dfu(self.session(root), pwned=True, run=run)
            self.assertEqual(calls, ['ibss-ready'])

    def test_a5_kdfu_skips_initial_ibss_but_external_checkm8_uploads_it(self):
        for product in ('iPad2,5', 'iPad3,1', 'iPhone4,1', 'iPod5,1'):
            for query, upload in [('SRTG: N/A\n', False),
                                  ('SRTG: iBoot-1704.10\nPWND: [checkm8]\n', True)]:
                with self.subTest(product=product, upload=upload), tempfile.TemporaryDirectory() as root:
                    session=self.session(root)
                    (session/'device.json').write_text(json.dumps({
                        'identity': {'ecid':123, 'product':product}}))
                    calls=[]
                    def run(argv,label,timeout=45):
                        calls.append((list(map(str,argv)),label))
                        return query if label=='a5-pwndfu-ready' else 'SRTG: N/A\n'
                    with patch.object(rescue,'unique_usb_target') as unique, \
                         patch.object(rescue,'recheck_recovery',return_value={'mode':'DFU'}), \
                         patch.object(rescue.time,'sleep'):
                        rescue.prepare_dfu(session,run=run)
                    self.assertEqual([label for _,label in calls],
                        ['a5-pwndfu-ready']+(['a5-ibss-upload'] if upload else [])+['ibss-ready'])
                    unique.assert_called_once_with(123)
                    self.assertTrue(all('-i' in argv for argv,label in calls if 'ready' in label))

    def test_a5_stock_dfu_or_forged_ready_text_cannot_bypass_exploit(self):
        queries=('SRTG: iBoot-1704.10\n', '', 'note SRTG: N/A\n',
                 'SRTG: N/A-extra\n', 'SRTG: N/A\nSRTG: iBoot-1704.10\n')
        for query in queries:
            with self.subTest(query=query), tempfile.TemporaryDirectory() as root:
                session=self.session(root)
                (session/'device.json').write_text(json.dumps({
                    'identity': {'ecid':123, 'product':'iPad2,5'}}))
                run=Mock(return_value=query)
                with patch.object(rescue,'unique_usb_target'), \
                     patch.object(rescue,'recheck_recovery',return_value={'mode':'DFU'}), \
                     self.assertRaisesRegex(RuntimeError,'requires manually entered kDFU'):
                    rescue.prepare_dfu(session,run=run)
                self.assertEqual(run.call_count,1)

    def test_explicit_pwned_flag_still_requires_valid_ibss(self):
        with tempfile.TemporaryDirectory() as root, \
             patch.object(rescue,'unique_usb_target'), \
             patch.object(rescue,'recheck_recovery',return_value={'mode':'DFU'}), \
             patch.object(rescue.time,'sleep'), \
             self.assertRaisesRegex(RuntimeError,'required pwned iBSS'):
            rescue.prepare_dfu(self.session(root),pwned=True,run=Mock(return_value='SRTG: iBoot-1\n'))


class RecoveryTransition(unittest.TestCase):
    def test_disconnect_and_lingering_dfu_wait_for_matching_recovery(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)
            ready=dict(mode='Recovery',product='iPad2,2',ecid=123)
            observations=[RuntimeError('irecovery: ERROR: Unable to connect to device'),
                          {'mode':'DFU'},ready]
            with patch.object(rescue,'recheck_recovery',side_effect=observations) as check, \
                 patch.object(rescue.time,'monotonic',return_value=0), \
                 patch.object(rescue.time,'sleep') as sleep:
                self.assertIs(rescue.wait_for_recovery(session),ready)
            self.assertEqual(check.call_count,3)
            self.assertEqual(sleep.call_count,2)
            log=(session/'ibec-ready.log').read_text()
            self.assertIn('Unable to connect',log)
            self.assertIn('still in DFU',log)
            self.assertIn('entered Recovery',log)

    def test_timeout_preserves_last_usb_error_and_log_path(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)
            detail='irecovery: ERROR: Unable to connect to device'
            with patch.object(rescue,'recheck_recovery',side_effect=RuntimeError(detail)), \
                 patch.object(rescue.time,'monotonic',side_effect=[0,0,30]), \
                 patch.object(rescue.time,'sleep') as sleep:
                with self.assertRaises(RuntimeError) as error:
                    rescue.wait_for_recovery(session)
            self.assertIn(detail,str(error.exception))
            self.assertIn(str(session/'ibec-ready.log'),str(error.exception))
            self.assertEqual((session/'ibec-ready.log').read_text(),detail+'\n')
            sleep.assert_called_once_with(1)

    def test_wrong_identity_is_not_retried(self):
        with tempfile.TemporaryDirectory() as root:
            detail='Connected device differs from the selected restoration target'
            with patch.object(rescue,'recheck_recovery',side_effect=ValueError(detail)) as check, \
                 patch.object(rescue.time,'sleep') as sleep:
                with self.assertRaisesRegex(ValueError,'selected restoration target'):
                    rescue.wait_for_recovery(root)
            check.assert_called_once();sleep.assert_not_called()
            self.assertIn(detail,(Path(root)/'ibec-ready.log').read_text())

    def test_boot_does_not_send_ram_payload_until_recovery_is_verified(self):
        for ready in (True,False):
            with self.subTest(ready=ready),tempfile.TemporaryDirectory() as root:
                session=Path(root)
                (session/'device.json').write_text(json.dumps(dict(identity={'ecid':123})))
                names=('iBEC.img3','DeviceTree.img3','Kernelcache.img3','Ramdisk.img3')
                report=dict(automatic_disk_mounts=False,ram_root='md0',files={name:'hash' for name in names})
                (session/'rescue-preparation.json').write_text(json.dumps(report))
                events=[]
                def command(argv,folder,label,timeout):
                    events.append(label)
                    return ''
                def wait(folder):
                    events.append('recovery-verified' if ready else 'recovery-failed')
                    if not ready:raise RuntimeError('RAM iBEC did not enter recovery')
                with patch.object(rescue,'digest',return_value='hash'), \
                     patch.object(rescue,'prepare_dfu'), \
                     patch.object(rescue,'run_boot_command',side_effect=command), \
                     patch.object(rescue,'wait_for_recovery',side_effect=wait):
                    if ready:
                        rescue.boot(session,progress=lambda message:None)
                    else:
                        with self.assertRaisesRegex(RuntimeError,'did not enter recovery'):
                            rescue.boot(session,progress=lambda message:None)
                state=json.loads((session/'rescue-run.json').read_text())
                if ready:
                    self.assertEqual(events[:3],['ibec-upload','recovery-verified','ramdisk-upload'])
                    self.assertTrue(state['ram_boot_requested'])
                else:
                    self.assertEqual(events,['ibec-upload','recovery-failed'])
                    self.assertEqual(state['stage'],'ibec-ready')
                    self.assertFalse(state['ram_boot_requested'])
                self.assertFalse(state['persistent_storage_commands_sent'])


class RescueConnectionDiagnostics(unittest.TestCase):
    def session(self, root):
        session=Path(root)
        (session/'device.json').write_text(json.dumps(dict(identity={'product':'iPad2,2'})))
        (session/'ssh-prefix.json').write_text(json.dumps(['ssh']))
        return session

    def test_timeout_includes_original_ssh_error_and_log_path(self):
        for detail in ('ssh: connect to host 127.0.0.1 port 6414: Connection refused',
                       'root@127.0.0.1: Permission denied (publickey).'):
            with self.subTest(detail=detail), tempfile.TemporaryDirectory() as root:
                session=self.session(root);ram=Mock()
                ram.guard.side_effect=RuntimeError(detail)
                with patch.object(rescue,'Rescue',return_value=ram), \
                     patch('restore_environment.session_build',return_value='10B329'), \
                     patch.object(rescue.time,'monotonic',side_effect=[0,120]), \
                     patch.object(rescue.time,'sleep') as sleep:
                    with self.assertRaises(RuntimeError) as error:
                        rescue.connect(session)
                self.assertIn(detail,str(error.exception))
                self.assertIn(str(session/'rescue-ssh.log'),str(error.exception))
                self.assertEqual((session/'rescue-ssh.log').read_text(),detail+'\n')
                ram.guard.assert_called_once();sleep.assert_not_called()

    def test_transient_failures_retry_without_duplicate_log_entries(self):
        with tempfile.TemporaryDirectory() as root:
            session=self.session(root);ram=Mock()
            ram.guard.side_effect=[RuntimeError('Connection refused'),
                                   RuntimeError('Connection refused'),None]
            with patch.object(rescue,'Rescue',return_value=ram), \
                 patch('restore_environment.session_build',return_value='10B329'), \
                 patch.object(rescue.time,'monotonic',return_value=0), \
                 patch.object(rescue.time,'sleep') as sleep:
                self.assertIs(rescue.connect(session),ram)
            self.assertEqual(sleep.call_count,2)
            self.assertEqual((session/'rescue-ssh.log').read_text(),'Connection refused\n')

    def test_invalid_configuration_and_wrong_ram_fail_without_retry(self):
        cases=(RuntimeError('Bad configuration option: testoption'),
               ValueError('Wrong RAM system identity: expected K94AP; received K93AP'))
        for failure in cases:
            with self.subTest(failure=str(failure)), tempfile.TemporaryDirectory() as root:
                session=self.session(root);ram=Mock()
                ram.guard.side_effect=failure
                with patch.object(rescue,'Rescue',return_value=ram), \
                     patch('restore_environment.session_build',return_value='10B329'), \
                     patch.object(rescue.time,'sleep') as sleep:
                    with self.assertRaises(type(failure)) as error:
                        rescue.connect(session)
                self.assertIn(str(failure),str(error.exception))
                self.assertEqual((session/'rescue-ssh.log').read_text(),str(failure)+'\n')
                ram.guard.assert_called_once();sleep.assert_not_called()


class InteractiveRescue(unittest.TestCase):
    def test_boots_guards_opens_shell_and_stops_owned_tunnel(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)
            (session/'device.json').write_text(json.dumps({'manage_usb_tunnel':True}))
            ram=Mock(prefix=['ssh','root@127.0.0.1'])
            tunnel=Mock()
            result=SimpleNamespace(returncode=0)
            messages=[]
            with patch.object(rescue,'boot') as boot, \
                 patch.object(rescue,'connect',return_value=ram) as connect, \
                 patch('usb_tunnel.start',return_value=tunnel) as start, \
                 patch('usb_tunnel.stop') as stop, \
                 patch.object(rescue.subprocess,'run',return_value=result) as run:
                rescue.interactive(session,progress=messages.append)
            boot.assert_called_once_with(session.resolve(),progress=messages.append)
            start.assert_called_once_with(session.resolve())
            connect.assert_called_once_with(session.resolve())
            ram.guard.assert_called_once_with()
            run.assert_called_once_with(ram.prefix)
            stop.assert_called_once_with(tunnel)
            self.assertTrue(any('no internal volume' in message for message in messages))

    def test_ram_ready_reuses_running_rescue_and_existing_tunnel(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)
            (session/'device.json').write_text(json.dumps({'manage_usb_tunnel':True}))
            ram=Mock(prefix=['ssh','root@127.0.0.1'])
            tunnel=Mock()
            with patch.object(rescue,'boot') as boot, \
                 patch.object(rescue,'connect',return_value=ram), \
                 patch('usb_tunnel.start',return_value=tunnel) as start, \
                 patch('usb_tunnel.stop'), \
                 patch.object(rescue.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
                rescue.interactive(session,ram_ready=True)
            boot.assert_not_called()
            start.assert_not_called()

    def test_stops_tunnel_when_connection_fails(self):
        with tempfile.TemporaryDirectory() as root:
            session=Path(root)
            (session/'device.json').write_text(json.dumps({'manage_usb_tunnel':True}))
            tunnel=Mock()
            with patch.object(rescue,'boot'), \
                 patch.object(rescue,'connect',side_effect=RuntimeError('not ready')), \
                 patch('usb_tunnel.start',return_value=tunnel), \
                 patch('usb_tunnel.stop') as stop:
                with self.assertRaisesRegex(RuntimeError,'not ready'):
                    rescue.interactive(session)
            stop.assert_called_once_with(tunnel)


if __name__ == '__main__':
    unittest.main()
