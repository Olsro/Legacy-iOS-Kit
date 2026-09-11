from pathlib import Path
import plistlib
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from job_sockets import numeric_loopback_sockets


class LoopbackSockets(unittest.TestCase):
    def test_local_listener_keeps_both_families_and_service_options(self):
        listener = dict(SockNodeName='localhost', SockServiceName='8021', SockType='stream')
        job = dict(Label='example.proxy', UserName='_ftp', Program='/usr/libexec/ftp-proxy',
                   Sockets=dict(Listeners=listener), inetdCompatibility=dict(Wait=False))
        result = plistlib.loads(numeric_loopback_sockets(plistlib.dumps(job)))
        expected = dict(job, Sockets=dict(Listeners=[dict(listener, SockNodeName='127.0.0.1'),
                                                   dict(listener, SockNodeName='::1')]))
        self.assertEqual(result, expected)
        self.assertEqual(job['Sockets']['Listeners']['SockNodeName'], 'localhost')

    def test_explicit_address_family_is_preserved(self):
        for family, address in [('IPv4', '127.0.0.1'), ('IPv6', '::1')]:
            listener = dict(SockNodeName='localhost', SockFamily=family, SockServiceName='8021')
            result = plistlib.loads(numeric_loopback_sockets(plistlib.dumps(dict(Sockets=dict(L=listener)))))
            self.assertEqual(result['Sockets']['L'], dict(listener, SockNodeName=address))

    def test_existing_array_and_unix_socket_are_preserved(self):
        unix = dict(SockFamily='Unix', SockPathName='/var/run/example', SockPathMode=0o600)
        job = dict(Sockets=dict(L=[unix, dict(SockNodeName='localhost', SockServiceName='8021')]))
        result = plistlib.loads(numeric_loopback_sockets(plistlib.dumps(job)))
        self.assertEqual(result['Sockets']['L'][0], unix)
        self.assertEqual(len(result['Sockets']['L']), 3)

    def test_numeric_or_remote_hosts_are_not_rewritten(self):
        for host in ['127.0.0.1', '::1', 'example.org']:
            content = plistlib.dumps(dict(Sockets=dict(L=dict(SockNodeName=host))))
            self.assertEqual(numeric_loopback_sockets(content), content)
        content = plistlib.dumps(dict(Label='no-sockets'))
        self.assertEqual(numeric_loopback_sockets(content), content)

    def test_repeated_preparation_does_not_duplicate_listeners(self):
        content = plistlib.dumps(dict(Sockets=dict(L=dict(SockNodeName='localhost', SockServiceName='8021'))))
        result = numeric_loopback_sockets(content)
        self.assertEqual(numeric_loopback_sockets(result), result)
