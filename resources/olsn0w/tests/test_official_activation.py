"""Official activation is scoped to the selected USB identity and read back."""
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from activation import ActivationPending, ActivationRequiresInput, SavedActivationRestored, activate

class OfficialActivation(unittest.TestCase):
    identity={'product':'iPhone5,1','ecid':1}
    udid='a'*40
    def setUp(self):
        # Unit tests must never consume a real saved certificate on the host.
        self.backup=patch('saved_activation.backup_path',return_value=Path('/nonexistent-activation-test.tar'))
        self.backup.start()
        self.addCleanup(self.backup.stop)
    def response(self,state,ecid=1):
        return subprocess.CompletedProcess([],0,plistlib.dumps(dict(ProductType='iPhone5,1',UniqueChipID=ecid,UniqueDeviceID=self.udid,ActivationState=state)),b'')

    def test_saved_certificate_is_tried_before_online_and_read_back(self):
        with tempfile.TemporaryDirectory() as d:
            archive=Path(d)/'backup.tar';archive.touch()
            with patch('saved_activation.backup_path',return_value=archive), \
                 patch('saved_activation.load',return_value=(b'original signed record',{})) as load, \
                 patch('saved_activation.install') as restore, \
                 patch('activation.subprocess.run',side_effect=[self.response('Unactivated'),self.response('Activated')]) as run:
                with self.assertRaises(SavedActivationRestored):
                    activate(self.udid,self.identity,Path(d)/'activation.log',target_prefix=['ssh','selected'])
                load.assert_called_once_with(archive,self.identity,self.udid)
                restore.assert_called_once_with(['ssh','selected'],b'original signed record',has_baseband=True)
                activate(self.udid,self.identity,Path(d)/'activation.log',try_saved=False)
                self.assertEqual(run.call_count,2)
                self.assertTrue(all('ideviceactivation' not in str(c.args[0]) for c in run.call_args_list))

    def test_unconfirmed_saved_certificate_falls_back_to_online(self):
        with tempfile.TemporaryDirectory() as d:
            archive=Path(d)/'backup.tar';archive.touch()
            replies=[self.response('Unactivated'),self.response('Unactivated'),
                     subprocess.CompletedProcess([],0,b'online',b''),self.response('Activated')]
            with patch('saved_activation.backup_path',return_value=archive), \
                 patch('saved_activation.load',return_value=(b'record',{})), \
                 patch('saved_activation.install') as install, \
                 patch('activation.subprocess.run',side_effect=replies) as run:
                with self.assertRaises(SavedActivationRestored):
                    activate(self.udid,self.identity,Path(d)/'activation.log',target_prefix=['ssh','selected'])
                activate(self.udid,self.identity,Path(d)/'activation.log',try_saved=False)
                install.assert_called_once()
                self.assertTrue(any('ideviceactivation' in str(c.args[0]) for c in run.call_args_list))

    def test_saved_record_waits_for_authenticated_ssh_without_online_request(self):
        with tempfile.TemporaryDirectory() as d:
            archive=Path(d)/'backup.tar';archive.touch()
            with patch('saved_activation.backup_path',return_value=archive), \
                 patch('saved_activation.load',return_value=(b'record',{})), \
                 patch('saved_activation.install') as install, \
                 patch('activation.subprocess.run',return_value=self.response('Unactivated')) as run:
                with self.assertRaises(ActivationPending) as caught:
                    activate(self.udid,self.identity,Path(d)/'activation.log')
                self.assertNotIsInstance(caught.exception,SavedActivationRestored)
                install.assert_not_called();self.assertEqual(run.call_count,1)

    def test_mismatched_saved_certificate_is_never_submitted(self):
        with tempfile.TemporaryDirectory() as d:
            archive=Path(d)/'backup.tar';archive.touch()
            with patch('saved_activation.backup_path',return_value=archive), \
                 patch('saved_activation.load',side_effect=ValueError('foreign record')), \
                 patch('saved_activation.install') as restore, \
                 patch('activation.subprocess.run',return_value=self.response('Unactivated')) as run:
                with self.assertRaises(ValueError):activate(self.udid,self.identity,Path(d)/'activation.log')
                restore.assert_not_called();self.assertEqual(run.call_count,1)

    def test_saved_attempt_can_be_disabled_on_subsequent_online_retry(self):
        with tempfile.TemporaryDirectory() as d, \
             patch('saved_activation.load') as load, \
             patch('activation.subprocess.run',side_effect=[self.response('Unactivated'),
                   subprocess.CompletedProcess([],0,b'online',b''),self.response('Activated')]):
            activate(self.udid,self.identity,Path(d)/'activation.log',try_saved=False)
            load.assert_not_called()

    def test_account_challenge_is_terminal_not_retryable(self):
        for response in (b'Activation Lock', b"Server requires input for Password"):
            with self.subTest(response=response),tempfile.TemporaryDirectory() as d:
                replies=[self.response('Unactivated'),subprocess.CompletedProcess([],1,b'',response)]
                with patch('activation.subprocess.run',side_effect=replies):
                    with self.assertRaises(ActivationRequiresInput):
                        activate(self.udid,self.identity,Path(d)/'activation.log')
    def test_activated_device_needs_no_activation_request(self):
        with patch('activation.subprocess.run',return_value=self.response('Activated')) as run:
            activate(self.udid,self.identity,'unused')
            self.assertEqual(run.call_count,1)
    def test_foreign_identity_cannot_be_activated(self):
        with patch('activation.subprocess.run',return_value=self.response('Unactivated',2)) as run:
            with self.assertRaises(ValueError):activate(self.udid,self.identity,'unused')
            self.assertEqual(run.call_count,1)
    def test_server_command_success_requires_activated_readback(self):
        for state in ('Activated','Unactivated'):
            with self.subTest(state=state),tempfile.TemporaryDirectory() as d:
                replies=[self.response('Unactivated'),subprocess.CompletedProcess([],0,b'activation response',b''),self.response(state)]
                with patch('activation.subprocess.run',side_effect=replies) as run:
                    if state=='Activated':activate(self.udid,self.identity,Path(d)/'activation.log')
                    else:
                        with self.assertRaises(RuntimeError):activate(self.udid,self.identity,Path(d)/'activation.log')
                    command=run.call_args_list[1].args[0]
                    self.assertEqual(command[1:],['activate','-u',self.udid,'-b'])

    def test_transient_failure_is_retryable_and_preserves_both_responses(self):
        with tempfile.TemporaryDirectory() as d:
            log=Path(d)/'activation.log'
            replies=[
                self.response('Unactivated'),
                subprocess.CompletedProcess([],1,b'',b'Failed to create activation request.\n'),
                self.response('Unactivated'),
            ]
            with patch('activation.subprocess.run',side_effect=replies):
                with self.assertRaises(ActivationPending):
                    activate(self.udid,self.identity,log)
            replies=[
                self.response('Unactivated'),
                subprocess.CompletedProcess([],0,b'Successfully activated device.\n',b''),
                self.response('Activated'),
            ]
            with patch('activation.subprocess.run',side_effect=replies):
                activate(self.udid,self.identity,log)
            text=log.read_text()
            self.assertIn('Failed to create activation request.',text)
            self.assertIn('Successfully activated device.',text)
