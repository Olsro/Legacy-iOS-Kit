"""Run the Kit signed-base restore and authenticate its held RAM handoff."""
import http.server
import json
from pathlib import Path
import plistlib
import platform
import posixpath
import subprocess
import threading
import time
import tempfile

from common import KIT, MODELS, baseband_strategy, integer, profile, tools, tool_environment
from device import same_hardware
from provision import read_handoff, require_baseband_policy, require_completed_restore
from rescue import prepare_dfu, connect
from restore import Rescue, checked_manifest, checkpoint
from tickets import binding
from restore_environment import report_build, session_build


class DfuPreparationError(RuntimeError):
    """A retryable DFU exploit failure that happened before any erase."""


def check_restore_runtime(executable, env, log):
    """Load the binary with no restore arguments before touching USB or disks."""
    log = Path(log)
    with tempfile.TemporaryDirectory(prefix='restore-loader-', dir=log.parent) as work:
        try:
            result = subprocess.run([str(executable)], cwd=work, env=env,
                                    capture_output=True, timeout=15, restore_signals=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            log.write_text(str(error)+'\n')
            raise RuntimeError('Cannot start the Kit restore tool; see '+str(log)) from error
    output = result.stdout+result.stderr
    log.write_bytes(output)
    # This legacy binary returns -1 (255 on POSIX) for its no-argument usage.
    if result.returncode not in (0, 1, 255) or b'Usage: futurerestore' not in output:
        raise RuntimeError('Kit restore tool cannot load its runtime; see '+str(log)+'\n'+
                           output.decode(errors='replace')[-2000:])


def start_logged(argv, cwd, env, log):
    """Start a tool whose stdout reaches the log as it is written.

    A file descriptor makes C stdio buffer stdout in blocks, while stderr is
    unbuffered: futurerestore's recovery steps then reach the log only at exit,
    after its later errors. A pseudo-terminal keeps stdout line-buffered and
    both streams in their original order. Returns the process and a finisher
    that waits until all output has been copied.
    """
    import os, pty, termios
    try:
        master,slave=pty.openpty()
    except OSError:
        process=subprocess.Popen(argv,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,
                                 restore_signals=False)
        return process,lambda:None
    try:
        # Keep newlines byte-for-byte; the terminal would otherwise add CR.
        attributes=termios.tcgetattr(slave)
        attributes[1]&=~termios.OPOST
        termios.tcsetattr(slave,termios.TCSANOW,attributes)
        process=subprocess.Popen(argv,cwd=cwd,env=env,stdout=slave,stderr=slave,
                                 restore_signals=False)
    except BaseException:
        os.close(master);raise
    finally:
        os.close(slave)
    def pump():
        try:
            while True:
                try:
                    data=os.read(master,65536)
                except OSError:
                    break  # Linux reports EIO once every writer has closed.
                if not data:break
                try:
                    log.write(data);log.flush()
                except ValueError:
                    break  # The caller closed the log while unwinding.
        finally:
            os.close(master)
    worker=threading.Thread(target=pump,daemon=True);worker.start()
    def finish():
        # A descendant still holding the terminal must not block failure handling.
        worker.join(timeout=10)
    return process,finish


def restore_arguments(identity, ipsw, ticket, baseband=None, baseband_manifest=None):
    binding(Path(ticket).read_bytes(), identity['product'], identity['ecid'])
    executable=tools()/'futurerestore_old'
    if not executable.is_file() and platform.system()=='Darwin':
        executable=KIT/'bin/macos/x86_64/futurerestore_old'
    if not executable.is_file():raise ValueError('Kit legacy restore tool is missing')
    argv=[str(executable), '--use-pwndfu', '-t', str(Path(ticket).resolve())]
    strategy=baseband_strategy(identity['product'])
    if strategy!='update':
        if baseband or baseband_manifest:
            raise ValueError('Selected modem policy does not accept a baseband update')
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
    ram=Rescue(json.loads((session/'ssh-prefix.json').read_text()),record['identity'],record['rescue_maintenance'],
               rescue_build=session_build(session))
    allowed={'/dev/disk0s1s1 on /mnt1','/dev/disk0s1s2 on /mnt2'}
    deadline=time.monotonic()+timeout
    diagnostic=session/'handoff-ssh.log'
    previous_error=None
    while True:
        try:
            mounts=ram.run('/sbin/mount').decode().splitlines()
            internal=[line.split(' (',1)[0] for line in mounts if line.startswith(('/dev/disk','/dev/rdisk'))]
            if not set(internal).issubset(allowed):
                raise ValueError('Unexpected internal mount after signed-base restore')
            ram.guard(internal)
            return ram
        except (RuntimeError,subprocess.TimeoutExpired,ValueError) as error:
            detail=str(error)
            if detail != previous_error:
                with diagnostic.open('a') as log:
                    log.write(detail+'\n')
                previous_error=detail
            if isinstance(error,ValueError):
                raise ValueError('RAM handoff validation failed. See '+str(diagnostic)+'\n'+detail) from error
            message='Restore RAM handoff did not open SSH. See '+str(diagnostic)+'\n'+detail
            if 'bad configuration option' in detail.lower() or time.monotonic()>=deadline:
                raise RuntimeError(message) from error
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
    require_baseband_policy(report)
    environment=report_build(report)
    if session_build(session)!=environment:
        raise ValueError('Provisioning and rescue RAM environments differ; no erase started')
    native6=environment=='10B329'
    expected_asr=('legacy-kit-multipatch-asr' if native6
                  else 'kit-asr-failure-to-success')
    expected_source=('rebuilt-udif-from-signed-base-hfs' if native6
                     else 'original-udif-without-filevault-envelope')
    if (report.get('asr_source') != expected_source
            or report.get('handoff_storage') != 'nvram'
            or report.get('asr_patch',{}).get('method') != expected_asr):
        raise ValueError('Prepare the current plaintext ASR/NVRAM handoff recipe first')
    expected_bootchain=('futurerestore-unpatched-rsa' if native6
                        else 'futurerestore-stock-rsa')
    if report.get('restore_bootchain_policy') != expected_bootchain:
        raise ValueError('Prepare the current futurerestore boot-chain recipe first')
    if (native6 and
            report.get('multipatch_component_metadata_build') != '10B329'):
        raise ValueError('Prepare the current multipatch component metadata first')
    if Path(report['rescue_session']).resolve()!=session:
        raise ValueError('Provisioning RAM belongs to another session')
    journal=bundle/'run.json'
    restore_log=bundle/'restore.log'
    if journal.exists():raise ValueError('Inspect the previous provisioning run before retrying')
    base_metadata=json.loads(Path(keys).read_text())
    if base_metadata.get('identifier')!=record['identity']['product'] or base_metadata.get('buildid')!='12H321':
        raise ValueError('Firmware keys differ from selected base')
    metadata=base_metadata
    if native6:
        if (report.get('multipatch_restore_component_encoding') !=
                'encrypted-donor-for-libipatcher' or
                report.get('restore_key_policy') !=
                'signed-base-with-10B329-restore-components' or
                report.get('restore_filesystem_build') != '12H321'):
            raise ValueError('Prepare the current encrypted multipatch restore components first')
        metadata=json.loads((bundle/'futurerestore-keys.json').read_text())
        if (metadata.get('identifier')!=record['identity']['product'] or
                metadata.get('buildid')!='12H321'):
            raise ValueError('Multipatch firmware keys differ from selected base route')
    argv=restore_arguments(record['identity'],bundle/'base8.ipsw',ticket,baseband,baseband_manifest)
    env=tool_environment()
    check_restore_runtime(argv[0],env,bundle/'restore-loader.log')
    from ssh_client import runtime_prefix
    runtime_prefix(json.loads((session/'ssh-prefix.json').read_text()))
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
    state=dict(stage='signed-base-restore-prepared',complete=False,erase_requested=True)
    work=bundle/'work';work.mkdir()
    checkpoint(journal,state)
    tunnel=None
    try:
        progress('Step 1: restoring the temporary signed iOS 8.4.1 base. Keep the cable connected; do not restart the device.')
        progress('The phone progress bar belongs to this base restore. Later installation progress will be shown on this computer.')
        from progress import RestoreProgress
        display=RestoreProgress(progress)
        with restore_log.open('wb') as log:
            progress('Restore log: '+str(restore_log))
            # Keep Python's ignored SIGPIPE in this legacy network client.
            # Restoring SIG_DFL can kill the whole restore on a closed socket
            # before its transport code can report EPIPE or finish cleanup.
            process,finish=start_logged(argv,work,env,log)
            state.update(pid=process.pid,stage='signed-base-restore-started');checkpoint(journal,state)
            with restore_log.open('r',errors='replace') as status:
                while True:
                    chunk=status.read();display.feed(chunk);display.tick()
                    try:
                        code=process.wait(timeout=2)
                        finish()
                        display.feed(status.read())
                        break
                    except subprocess.TimeoutExpired:
                        pass
        state.update(stage='restore-tool-exited',returncode=code);checkpoint(journal,state)
        output=restore_log.read_text(errors='replace')
        if code or not any(line.strip()=='DONE' for line in output.splitlines()):
            raise RuntimeError('Kit restore did not report success (exit code '+str(code)+
                               '); inspect '+str(restore_log))
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
        progress('Signed-base restore failed. Diagnostics retained in '+str(bundle)+
                 '; no automatic retry or reboot.')
        raise
    finally:
        server.shutdown();server.server_close();worker.join(timeout=5)
