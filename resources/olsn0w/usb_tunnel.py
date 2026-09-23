"""Own the selected restore RAM's USB tunnel through target qualification."""
import json
from pathlib import Path
import re
import socket
import subprocess
import time

from common import save
from guided_inputs import tool


def normal_serial():
    import usb.core
    import usb.util
    devices=[d for d in usb.core.find(find_all=True,idVendor=0x05ac) if 0x1200<=d.idProduct<=0x12ff]
    serials=set()
    for device in devices:
        try:
            value=usb.util.get_string(device,device.iSerialNumber) or ''
            if re.fullmatch('[0-9a-fA-F]{40}',value):serials.add(value.lower())
        except (usb.core.USBError,ValueError):
            # Restore-to-normal transitions can leave a disappearing Apple USB
            # interface, or one without a readable language descriptor, in the
            # libusb snapshot. It is not a selectable target.
            pass
        finally:
            usb.util.dispose_resources(device)
    if len(serials)>1:raise ValueError('Keep only the selected iOS device connected')
    return next(iter(serials),None)


def start(session,timeout=120):
    session=Path(session);record=json.loads((session/'device.json').read_text())
    deadline=time.monotonic()+timeout
    while True:
        serial=normal_serial()
        if serial:break
        if time.monotonic()>=deadline:raise RuntimeError('The restored device did not return on USB')
        time.sleep(2)
    if record.get('ram_udid') and serial!=record['ram_udid']:
        raise ValueError('USB identity changed after restoring the selected device')
    record['ram_udid']=serial;save(session/'device.json',record)
    prefix=json.loads((session/'ssh-prefix.json').read_text())
    port=prefix[prefix.index('-p')+1]
    with socket.socket() as sock:
        if sock.connect_ex(('127.0.0.1',int(port)))==0:
            raise RuntimeError('Selected USB tunnel port is already occupied')
    with (session/'iproxy.log').open('ab') as log:
        process=subprocess.Popen([str(tool('iproxy')),'-u',serial,'-s','127.0.0.1',str(port)+':22'],stdout=log,stderr=subprocess.STDOUT)
    time.sleep(.3)
    if process.poll() is not None:raise RuntimeError('USB tunnel could not start')
    return process


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
