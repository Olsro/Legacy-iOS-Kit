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


class ActivationRequiresInput(RuntimeError):
    """A server challenge requires the owner's intervention, not polling."""


class SavedActivationRestored(ActivationPending):
    """The signed file was restored; the reloaded daemon must still accept it."""


def activate(udid, identity, log, *, try_saved=True, target_prefix=None):
    """Ask the Kit to perform official activation on the installed target."""
    if not re.fullmatch(r'[0-9a-fA-F]{40}',udid):raise ValueError('Invalid USB identity')
    def query():
        result=subprocess.run([str(tools()/'ideviceinfo'),'-u',udid,'-x'],capture_output=True,timeout=20)
        if result.returncode:raise RuntimeError('Cannot read selected activation device')
        values=plistlib.loads(result.stdout)
        if values.get('UniqueChipID') != identity['ecid'] or values.get('ProductType') != identity['product']:
            raise ValueError('Activation device identity differs')
        return values
    values=query()
    if values.get('ActivationState') == 'Activated':return
    path=Path(log)
    if try_saved:
        from saved_activation import backup_path, load, install
        archive=backup_path(identity)
        if archive.exists() or archive.is_symlink():
            # The RAM rescue can advertise a synthetic USB serial. Bind the
            # certificate to the real target UDID, not that transport serial.
            record, _=load(archive,identity,values.get('UniqueDeviceID'))
            if target_prefix is None:
                raise ActivationPending('Waiting for authenticated target SSH to restore the saved activation record')
            with path.open('ab') as stream:
                stream.write(b'\nRestoring the saved official activation record; awaiting lockdownd readback.\n')
            from common import profile
            install(target_prefix,record,has_baseband=profile(identity['product'])['has_baseband'])
            # A cached certificate is bound to an earlier ActivationRandomness.
            # Restore its signed file rather than submit it as a new Activate
            # response. Never carry over old data_ark activation-state flags.
            raise SavedActivationRestored('Saved record restored; waiting for lockdownd to validate it')
    result=subprocess.run([str(tools()/'ideviceactivation'),'activate','-u',udid,'-b'],
                          capture_output=True,timeout=120)
    # Keep every response: early iOS first boots can expose lockdownd shortly
    # before it is able to create an activation request, and a later retry can
    # then succeed without any change to the installed system.
    with path.open('ab') as stream:
        if stream.tell():stream.write(b'\n')
        stream.write(result.stdout+result.stderr)
    response=(result.stdout+result.stderr).lower()
    if (b'activation lock' in response or b'server requires input' in response):
        raise ActivationRequiresInput(
            'Apple activation requires owner input; automatic retries stopped. '
            'Use the associated Apple account to complete activation. See activation.log')
    if result.returncode or query().get('ActivationState') != 'Activated':
        raise ActivationPending('Official target activation is not ready yet')


def library(name):
    if platform.system()=='Darwin':
        candidates=list((tools()/'lib').glob('lib'+name+'.*.dylib'))
        if len(candidates)==1:return C.CDLL(str(candidates[0]))
    path=C.util.find_library(name)
    if not path:raise RuntimeError("Olsro's Legacy iOS Kit dependency is missing: "+name)
    return C.CDLL(path)


def acknowledge(udid, identity):
    """Acknowledge the handshake only after the device reports Activated.

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
        if get('ActivationState')!='Activated':raise ValueError('Device activation must complete first')
        value=plist.plist_new_bool(1)
        if not value:raise RuntimeError('Cannot allocate activation acknowledgement')
        # lockdownd_set_value transfers this node into its request dictionary
        # and frees the dictionary, including the value. Do not free it twice.
        if mobile.lockdownd_set_value(client,None,b'ActivationStateAcknowledged',value):
            raise RuntimeError('Cannot acknowledge device activation')
        if get('ActivationStateAcknowledged') is not True:raise RuntimeError('Activation acknowledgement readback failed')
        return dict(activation_state='Activated',acknowledged=True)
    finally:
        if client:mobile.lockdownd_client_free(client)
        if device:mobile.idevice_free(device)
