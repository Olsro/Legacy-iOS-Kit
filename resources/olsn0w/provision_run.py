"""Run the Kit signed-base restore and authenticate its held RAM handoff."""
import http.server
import json
import os
from pathlib import Path
import plistlib
import platform
import posixpath
import subprocess
import threading
import time

from common import KIT, MODELS, integer, profile, tools
from device import same_hardware
from provision import read_handoff, require_completed_restore
from rescue import prepare_dfu, connect
from restore import Rescue, checked_manifest, checkpoint
from tickets import binding


class DfuPreparationError(RuntimeError):
    """A retryable DFU exploit failure that happened before any erase."""


def restore_arguments(identity, ipsw, ticket, baseband=None, baseband_manifest=None):
    binding(Path(ticket).read_bytes(), identity['product'], identity['ecid'])
    executable=tools()/'futurerestore_old'
    if not executable.is_file() and platform.system()=='Darwin':
        executable=KIT/'bin/macos/futurerestore_old'
    if not executable.is_file():raise ValueError('Kit legacy restore tool is missing')
    argv=[str(executable), '--use-pwndfu', '-t', str(Path(ticket).resolve())]
    if not profile(identity['product'])['has_baseband']:
        if baseband or baseband_manifest:raise ValueError('Wi-Fi product has no baseband')
        argv+=['--no-baseband']
    else:
        if not baseband or not baseband_manifest:raise ValueError('Selected cellular firmware and manifest required')
        baseband,baseband_manifest=Path(baseband).resolve(),Path(baseband_manifest).resolve()
        manifest=plistlib.loads(baseband_manifest.read_bytes())
        board,chip,board_id=MODELS[identity['product']]
        matches=[i for i in manifest['BuildIdentities'] if i['Info']['DeviceClass']==board
                 and integer(i['ApChipID'])==chip and integer(i['ApBoardID'])==board_id]
        if identity['product'] not in manifest['SupportedProductTypes'] or not matches:
            raise ValueError('Baseband manifest belongs to another product')
        if not baseband.is_file() or not any(Path(i['Manifest']['BasebandFirmware']['Info']['Path']).name==baseband.name for i in matches):
            raise ValueError('Baseband file differs from selected manifest')
        argv+=['-b',str(baseband),'-p',str(baseband_manifest)]
    return argv+[str(Path(ipsw).resolve())]


def connect_handoff(session, timeout=120):
    session=Path(session)
    record=json.loads((session/'device.json').read_text())
    ram=Rescue(json.loads((session/'ssh-prefix.json').read_text()),record['identity'],record['rescue_maintenance'])
    allowed={'/dev/disk0s1s1 on /mnt1','/dev/disk0s1s2 on /mnt2'}
    deadline=time.monotonic()+timeout
    while True:
        try:
            mounts=ram.run('/sbin/mount').decode().splitlines()
            internal=[line.split(' (',1)[0] for line in mounts if line.startswith(('/dev/disk','/dev/rdisk'))]
            if not set(internal).issubset(allowed):
                raise ValueError('Unexpected internal mount after signed-base restore')
            ram.guard(internal)
            return ram
        except (RuntimeError,subprocess.TimeoutExpired):
            if time.monotonic()>=deadline:raise RuntimeError('Restore RAM handoff did not open SSH')
            time.sleep(3)


def record_failed_restore(session, bundle, state):
    """Preserve available RAM diagnostics without restarting or erasing again."""
    try:
        ram=connect_handoff(session,timeout=5)
        state['rescue_accessible']=True
        commands={
            'failed-restore-mounts.txt':'/sbin/mount',
            'failed-restore-jobs.txt':'/bin/launchctl list',
            'failed-restore-boot-setting.txt':'/usr/sbin/nvram auto-boot',
        }
        for name,command in commands.items():
            (Path(bundle)/name).write_bytes(ram.run(command,timeout=10))
    except Exception as error:
        # A failed diagnostic must not hide the original restore failure.
        state['rescue_diagnostic_error']=str(error)


def run(session, bundle, ticket, keys, *, baseband=None, baseband_manifest=None,
        erase=False, pwned=False, progress=print):
    session,bundle=Path(session).resolve(),Path(bundle).resolve()
    record=json.loads((session/'device.json').read_text())
    report=checked_manifest(bundle)
    if not erase or report.get('kind')!='signed-base-restore-handoff' or not same_hardware(record['identity'],report['identity']):
        raise ValueError('Explicit erase and matching provisioning identity required')
    expected_asr=('legacy-kit-multipatch-asr' if report.get('multipatch')
                  else 'kit-asr-failure-to-success')
    if (report.get('asr_source') != 'original-udif-without-filevault-envelope'
            or report.get('handoff_storage') != 'nvram'
            or report.get('asr_patch',{}).get('method') != expected_asr):
        raise ValueError('Prepare the current plaintext ASR/NVRAM handoff recipe first')
    if Path(report['rescue_session']).resolve()!=session:
        raise ValueError('Provisioning RAM belongs to another session')
    journal=bundle/'run.json'
    if journal.exists():raise ValueError('Inspect the previous provisioning run before retrying')
    metadata=json.loads(Path(keys).read_text())
    if metadata.get('identifier')!=record['identity']['product'] or metadata.get('buildid')!='12H321':
        raise ValueError('Firmware keys differ from selected base')
    argv=restore_arguments(record['identity'],bundle/'base8.ipsw',ticket,baseband,baseband_manifest)
    try:
        prepare_dfu(session,pwned=pwned,progress=progress)
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        # prepare_dfu only talks to the USB boot ROM/iBoot. At this point the
        # restore tool has not started, its work directory does not exist and
        # persistent storage has not been touched, so retrying is safe.
        raise DfuPreparationError(str(error)) from error
    route='/firmware/'+metadata['identifier']+'/12H321'
    body=json.dumps(metadata).encode()
    class Keys(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if posixpath.normpath(self.path) not in (route,route+'/index.html'):
                self.send_error(404);return
            self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    # Bundled legacy restore binaries use the Kit's fixed loopback port.
    server=http.server.ThreadingHTTPServer(('127.0.0.1',8888),Keys)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    env=os.environ.copy()
    state=dict(stage='signed-base-restore-prepared',complete=False,erase_requested=True)
    work=bundle/'work';work.mkdir()
    checkpoint(journal,state)
    tunnel=None
    try:
        progress('Step 1: restoring the temporary signed iOS 8.4.1 base. Keep the cable connected; do not restart the device.')
        progress('The phone progress bar belongs to this base restore. Later installation progress will be shown on this computer.')
        from progress import RestoreProgress
        display=RestoreProgress(progress)
        with (bundle/'restore.log').open('wb') as log:
            process=subprocess.Popen(argv,cwd=work,env=env,stdout=log,stderr=subprocess.STDOUT)
            state.update(pid=process.pid,stage='signed-base-restore-started');checkpoint(journal,state)
            with (bundle/'restore.log').open('r',errors='replace') as status:
                while True:
                    display.feed(status.read());display.tick()
                    try:
                        code=process.wait(timeout=2)
                        display.feed(status.read())
                        break
                    except subprocess.TimeoutExpired:
                        pass
        state.update(stage='restore-tool-exited',returncode=code);checkpoint(journal,state)
        output=(bundle/'restore.log').read_text(errors='replace')
        if code or not any(line.strip()=='DONE' for line in output.splitlines()):
            raise RuntimeError('Kit restore did not report success; inspect restore.log')
        if record.get("manage_usb_tunnel"):
            from usb_tunnel import start
            tunnel=start(session)
        ram=connect_handoff(session)
        ram.owned_tunnel=tunnel
        # DONE can reach the host just before the restore daemon invokes its
        # reboot hook. Wait for this run's marker without restarting anything.
        deadline=time.monotonic()+30
        while True:
            try:
                observed=read_handoff(ram)
                if observed == (report['reboot_token']+'\n').encode():break
            except RuntimeError:
                pass
            if time.monotonic()>=deadline:
                raise RuntimeError('Completed restore did not publish its handoff marker')
            time.sleep(1)
        require_completed_restore(code,output,observed,report['reboot_token'])
        state.update(stage='authenticated-ram-handoff',complete=True)
        checkpoint(journal,state)
        return ram
    except Exception as error:
        state['error']=str(error)
        checkpoint(journal,state)
        record_failed_restore(session,bundle,state)
        checkpoint(journal,state)
        from usb_tunnel import stop
        stop(tunnel)
        progress('Signed-base restore failed. Logs retained; no automatic retry or reboot.')
        raise
    finally:
        server.shutdown();server.server_close();worker.join(timeout=5)
