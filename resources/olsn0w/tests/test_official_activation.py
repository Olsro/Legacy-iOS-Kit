"""Official activation is scoped to the selected USB identity and read back."""
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from activation import activate

class OfficialActivation(unittest.TestCase):
    identity={'product':'iPhone5,1','ecid':1}
    udid='a'*40
    def response(self,state,ecid=1):
        return subprocess.CompletedProcess([],0,plistlib.dumps(dict(ProductType='iPhone5,1',UniqueChipID=ecid,ActivationState=state)),b'')
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
