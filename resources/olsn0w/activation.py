"""Acknowledge existing official activation through the selected USB device."""
import ctypes as C
import ctypes.util
import plistlib
import platform
import re
import subprocess
from pathlib import Path

from common import tools


class ActivationPending(RuntimeError):
    """The selected target is valid, but Apple's activation is not ready yet."""


def activate(udid, identity, log):
    """Ask the Kit to perform official activation on the installed target."""
    if not re.fullmatch(r'[0-9a-fA-F]{40}',udid):raise ValueError('Invalid USB identity')
    def query():
        result=subprocess.run([str(tools()/'ideviceinfo'),'-u',udid,'-x'],capture_output=True,timeout=20)
        if result.returncode:raise RuntimeError('Cannot read selected activation device')
        values=plistlib.loads(result.stdout)
        if values.get('UniqueChipID') != identity['ecid'] or values.get('ProductType') != identity['product']:
            raise ValueError('Activation device identity differs')
        return values
    if query().get('ActivationState') == 'Activated':return
    result=subprocess.run([str(tools()/'ideviceactivation'),'activate','-u',udid,'-b'],
                          capture_output=True,timeout=120)
    # Keep every response: early iOS first boots can expose lockdownd shortly
    # before it is able to create an activation request, and a later retry can
    # then succeed without any change to the installed system.
    path=Path(log)
    with path.open('ab') as stream:
        if stream.tell():stream.write(b'\n')
        stream.write(result.stdout+result.stderr)
    if result.returncode or query().get('ActivationState') != 'Activated':
        raise ActivationPending('Official target activation is not ready yet')


def library(name):
    if platform.system()=='Darwin':
        candidates=list((tools()/'lib').glob('lib'+name+'.*.dylib'))
        if len(candidates)==1:return C.CDLL(str(candidates[0]))
    path=C.util.find_library(name)
    if not path:raise RuntimeError('Legacy iOS Kit dependency is missing: '+name)
    return C.CDLL(path)


def acknowledge(udid, identity):
    """Set the handshake acknowledgement only after Apple activation is present.

    This does not create activation records, alter activation state, or complete
    Setup Assistant. The ECID and product are checked through this connection.
    """
    if not re.fullmatch(r'[0-9a-fA-F]{40}',udid):raise ValueError('Invalid USB identity')
    mobile,plist=library('imobiledevice-1.0'),library('plist-2.0')
    ptr=C.c_void_p;out=C.POINTER(ptr)
    specifications=[
        (mobile,'idevice_new_with_options',[out,C.c_char_p,C.c_int],C.c_int),
        (mobile,'lockdownd_client_new_with_handshake',[ptr,out,C.c_char_p],C.c_int),
        (mobile,'lockdownd_get_value',[ptr,C.c_char_p,C.c_char_p,out],C.c_int),
        (mobile,'lockdownd_set_value',[ptr,C.c_char_p,C.c_char_p,ptr],C.c_int),
        (mobile,'lockdownd_client_free',[ptr],C.c_int),(mobile,'idevice_free',[ptr],C.c_int),
        (plist,'plist_new_bool',[C.c_uint8],ptr),(plist,'plist_free',[ptr],None),
        (plist,'plist_to_xml',[ptr,out,C.POINTER(C.c_uint32)],None)]
    for lib,name,args,result in specifications:
        fn=getattr(lib,name);fn.argtypes=args;fn.restype=result
    allocator=C.CDLL(None);allocator.free.argtypes=[ptr];allocator.free.restype=None
    device,client=ptr(),ptr()
    def get(key):
        node=ptr();code=mobile.lockdownd_get_value(client,None,key.encode(),C.byref(node))
        if code or not node:raise RuntimeError('Cannot read activation handshake value: '+key)
        xml=ptr();size=C.c_uint32()
        try:
            plist.plist_to_xml(node,C.byref(xml),C.byref(size))
            if not xml:raise RuntimeError('Cannot decode activation value')
            return plistlib.loads(C.string_at(xml,size.value))
        finally:
            if xml:allocator.free(xml)
            plist.plist_free(node)
    try:
        if mobile.idevice_new_with_options(C.byref(device),udid.encode(),2):raise RuntimeError('Selected USB device unavailable')
        if mobile.lockdownd_client_new_with_handshake(device,C.byref(client),b'olsn0w'):
            raise RuntimeError('Cannot open selected activation handshake')
        if get('UniqueChipID')!=identity['ecid'] or get('ProductType')!=identity['product']:
            raise ValueError('Activation handshake belongs to another device')
        if get('ActivationState')!='Activated':raise ValueError('Official activation must complete first')
        value=plist.plist_new_bool(1)
        if not value:raise RuntimeError('Cannot allocate activation acknowledgement')
        # lockdownd_set_value transfers this node into its request dictionary
        # and frees the dictionary, including the value. Do not free it twice.
        if mobile.lockdownd_set_value(client,None,b'ActivationStateAcknowledged',value):
            raise RuntimeError('Cannot acknowledge official activation')
        if get('ActivationStateAcknowledged') is not True:raise RuntimeError('Activation acknowledgement readback failed')
        return dict(activation_state='Activated',acknowledged=True)
    finally:
        if client:mobile.lockdownd_client_free(client)
        if device:mobile.idevice_free(device)
