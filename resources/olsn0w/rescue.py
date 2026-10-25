"""Load a selected RAM rescue using Legacy iOS Kit's host-specific DFU tools."""
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import time

from common import KIT, digest, profile, tools, tool_environment
from device import recheck_recovery
from restore import Rescue, checkpoint


def run_boot_command(argv, session, label, timeout=45):
    """Keep live diagnostics and bound the entire DFU tool process group."""
    argv = list(map(str, argv))
    log = Path(session)/(label+'.log')
    output = bytearray()
    with log.open('wb') as stream, selectors.DefaultSelector() as selector:
        process = subprocess.Popen(argv, cwd=session, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True, env=tool_environment())
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic()+timeout
            while selector.get_map():
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout, output=bytes(output))
                for key, _ in selector.select(min(remaining, .25)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    stream.write(chunk)
                    stream.flush()
                    output.extend(chunk)
                    if label == 'kit-pwn':
                        sys.stderr.write(chunk.decode(errors='replace'))
                        sys.stderr.flush()
            remaining = max(.001, deadline-time.monotonic())
            process.wait(timeout=remaining)
        except BaseException:
            # Killing only bash leaves menu/exploit descendants holding the
            # output pipe open, so subprocess.run can hang beyond its timeout.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                # macOS can report EPERM for a group containing only zombies.
                if process.poll() is None:
                    process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()
    if process.returncode:
        raise RuntimeError('DFU/RAM command failed at '+label+'; see '+str(log))
    return output.decode(errors='replace')


def has_checkm8_marker(output):
    """Accept the two exact PWND field renderings emitted by irecovery."""
    return bool(re.search(r'^PWND:\s*\[?checkm8\]?\s*$', output, re.MULTILINE))


def has_pwned_ibss(output, product):
    """kloader runs patched iBSS, whose USB identity has no boot-ROM SRTG."""
    fields = {}
    for line in output.splitlines():
        if ':' not in line:
            continue
        key, value = (part.strip() for part in line.split(':', 1))
        if key in fields:
            return False
        fields[key] = value
    return (fields.get('SRTG') == 'N/A' and
            (profile(product)['soc'].startswith('a5') or fields.get('IBFL') == '0x1b'))


def unique_usb_target(ecid):
    # libusb works on Linux and macOS; no system_profiler/ioreg dependency.
    import usb.core
    import usb.util
    from usb_backend import get_backend
    # The unaddressed exploit tools operate on DFU/recovery interfaces, not
    # normal-mode iPhones or iPods (which also use Apple 0x12xx product IDs).
    # Reject a second boot interface, while retaining the exact ECID check.
    devices=[d for d in usb.core.find(find_all=True,idVendor=0x05ac,backend=get_backend())
             if d.idProduct in (0x1222,0x1227,0x1280,0x1281,0x1282,0x1283)]
    if len(devices)!=1 or devices[0].idProduct!=0x1227:
        raise ValueError('Connect only the selected device in DFU before loading the rescue')
    try:
        serial=usb.util.get_string(devices[0],devices[0].iSerialNumber)
        match=re.search(r'ECID:([0-9a-fA-F]+)',serial or '')
        if not match or int(match[1],16)!=ecid:raise ValueError('DFU USB identity differs from session')
    finally:
        usb.util.dispose_resources(devices[0])


def wait_for_recovery(session, timeout=30):
    """Wait for the selected iBEC to re-enumerate without resending it."""
    session=Path(session)
    diagnostic=session/'ibec-ready.log'
    deadline=time.monotonic()+timeout
    previous_error=None
    with diagnostic.open('w') as log:
        while True:
            try:
                actual=recheck_recovery(session)
                if actual['mode']=='Recovery':
                    log.write('Selected device entered Recovery\n')
                    return actual
                detail='Selected device is still in '+actual['mode']
            except ValueError as error:
                # A different model/ECID is not a transient USB disconnect.
                log.write(str(error)+'\n')
                raise
            except (RuntimeError,subprocess.TimeoutExpired) as error:
                detail=str(error)
            if detail != previous_error:
                log.write(detail+'\n');log.flush()
                previous_error=detail
            if time.monotonic()>=deadline:
                raise RuntimeError('RAM iBEC did not enter recovery. See '+str(diagnostic)+'\n'+detail)
            time.sleep(1)


def boot(session, *, progress=print, pwned=False):
    session=Path(session).resolve()
    identity=json.loads((session/'device.json').read_text())['identity']
    report=json.loads((session/'rescue-preparation.json').read_text())
    if report.get('automatic_disk_mounts') is not False or report.get('ram_root')!='md0':
        raise ValueError('Rescue must boot RAM without automatically mounting internal volumes')
    required={'iBEC.img3','DeviceTree.img3','Kernelcache.img3','Ramdisk.img3'}
    if not required.issubset(report['files']):raise ValueError('Incomplete RAM rescue')
    for name,expected in report['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or digest(session/name)!=expected:
            raise ValueError('RAM rescue component changed')
    state=dict(stage='verified',ram_boot_requested=False,persistent_storage_commands_sent=False)
    checkpoint(session/'rescue-run.json',state)
    def run(argv,label,timeout=45):
        state['stage']=label;checkpoint(session/'rescue-run.json',state);progress(label)
        return run_boot_command(argv,session,label,timeout)
    prepare_dfu(session, pwned=pwned, progress=progress, run=run)
    run([tools()/'irecovery','-i',hex(identity['ecid']),'-f',session/'iBEC.img3'],'ibec-upload')
    state['stage']='ibec-ready';checkpoint(session/'rescue-run.json',state)
    progress('Waiting for the selected iBEC to reconnect in Recovery')
    wait_for_recovery(session)
    for name,command in [('Ramdisk.img3','ramdisk'),('DeviceTree.img3','devicetree'),('Kernelcache.img3','bootx')]:
        run([tools()/'irecovery','-i',hex(identity['ecid']),'-f',session/name],command+'-upload')
        run([tools()/'irecovery','-i',hex(identity['ecid']),'-c',command],command)
    state.update(stage='ram-boot-requested',ram_boot_requested=True);checkpoint(session/'rescue-run.json',state)
    return identity


def prepare_dfu(session, *, pwned=False, progress=print, run=None):
    session=Path(session).resolve()
    identity=json.loads((session/'device.json').read_text())['identity']
    if run is None:
        def run(argv,label,timeout=45):
            progress(label)
            return run_boot_command(argv,session,label,timeout)
    if recheck_recovery(session)['mode']!='DFU':raise ValueError('The selected device must be in DFU')
    unique_usb_target(identity['ecid'])
    selected_profile=profile(identity['product'])
    if pwned:
        progress('Checking software-entered pwned iBSS')
    elif selected_profile.get('external_pwndfu'):
        progress('Checking A5 kDFU or external pwnDFU')
        query=run([tools()/'irecovery','-i',hex(identity['ecid']),'-q'],'a5-pwndfu-ready')
        if has_pwned_ibss(query, identity['product']):
            progress('Selected device is already running pwned iBSS (kDFU)')
        elif has_checkm8_marker(query):
            # External boot-ROM pwnDFU needs the raw RSA-patched base iBSS.
            # kDFU already runs that stage and must not receive it a second time.
            run([tools()/'primepwn',session/'pwnediBSS'],'a5-ibss-upload',60)
        else:
            raise RuntimeError('A5 requires manually entered kDFU from a jailbroken system, '
                               'or PWND:[checkm8] from A5Mate before the host can send iBSS')
    elif platform.system()=='Darwin' and platform.machine()=='arm64':
        # The native arm64 ipwnder can exit without leaving A6/A6X in the
        # required pwned-iBSS state. The qualified Apple Silicon sequence is
        # the Rosetta exploit followed by gaster's USB reset.
        run(['arch','-x86_64',KIT/'bin/macos/ipwnder','-pv'],'pwn',60)
        run(['arch','-x86_64',KIT/'bin/macos/gaster','reset'],'pwn-reset',60)
    else:
        # Reuse the kit's A6/A6X selection, USB setup, and pwned-iBSS loader.
        run(['bash',KIT/'restore.sh','--pwn','--olsn0w-pwn','--device='+identity['product'],
             '--ecid='+str(identity['ecid']),'--no-version-check','--no-internet-check','--no-color'],
            'kit-pwn',180)
    time.sleep(2)
    if recheck_recovery(session)['mode'] != 'DFU':
        raise RuntimeError('The selected device left DFU before iBSS verification')
    query=run([tools()/'irecovery','-i',hex(identity['ecid']),'-q'],'ibss-ready')
    if not has_pwned_ibss(query, identity['product']):
        raise RuntimeError('The Kit did not return the required pwned iBSS state')


def connect(session, timeout=120):
    session=Path(session)
    record=json.loads((session/'device.json').read_text())
    prefix=json.loads((session/'ssh-prefix.json').read_text())
    maintenance=record.get('rescue_maintenance','/olsn0w-maintenance')
    from restore_environment import session_build
    ram=Rescue(prefix,record['identity'],maintenance,rescue_build=session_build(session))
    deadline=time.monotonic()+timeout
    diagnostic=session/'rescue-ssh.log'
    previous_error=None
    while True:
        try:
            ram.guard()
            return ram
        except (RuntimeError,subprocess.TimeoutExpired,ValueError) as error:
            detail=str(error)
            if detail != previous_error:
                with diagnostic.open('a') as log:
                    log.write(detail+'\n')
                previous_error=detail
            if isinstance(error,ValueError):
                raise ValueError('RAM rescue validation failed. See '+str(diagnostic)+'\n'+detail) from error
            if 'bad configuration option' in detail.lower() or time.monotonic()>=deadline:
                raise RuntimeError('RAM SSH did not become ready. See '+str(diagnostic)+'\n'+detail) from error
            time.sleep(3)


def interactive(session, *, ram_ready=False, progress=print):
    """Boot a prepared rescue and keep its selected USB tunnel for a root shell."""
    session=Path(session).resolve()
    record=json.loads((session/'device.json').read_text())
    if ram_ready:
        progress('Reusing the already running RAM rescue')
    else:
        boot(session,progress=progress)
    tunnel=None
    try:
        ram=None
        if ram_ready:
            try:
                ram=connect(session,timeout=1)
                progress('Reusing the existing selected USB tunnel')
            except RuntimeError:
                pass
        if ram is None and record.get('manage_usb_tunnel'):
            from usb_tunnel import start
            progress('Waiting for the RAM rescue USB connection')
            tunnel=start(session)
        if ram is None:
            ram=connect(session)
        # connect() already applies this guard while waiting, but repeat it at
        # the boundary before handing an interactive root shell to the user.
        ram.guard()
        progress('RAM rescue ready; root is in memory and no internal volume is mounted.')
        progress('Opening the authenticated root shell. Type exit to leave it.')
        result=subprocess.run(ram.prefix)
        if result.returncode:
            raise RuntimeError('RAM rescue shell exited with status '+str(result.returncode))
    finally:
        if tunnel is not None:
            from usb_tunnel import stop
            stop(tunnel)
