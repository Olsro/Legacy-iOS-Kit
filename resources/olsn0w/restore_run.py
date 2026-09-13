"""Run the prepared erase, then qualify the target reached by normal boot."""
import json
from pathlib import Path
import plistlib
import re
import socket
import subprocess
import time

from common import profile, tools, version
from device import same_hardware
from rescue import boot, connect
from restore import checked_manifest, checkpoint, install, refresh_layout


def target_prefix(bundle, port):
    public=(bundle/'ssh_host_rsa_key.pub').read_text().split()
    if len(public)<2 or public[0]!='ssh-rsa':raise ValueError('Invalid target host public key')
    known=bundle/'target-known-hosts'
    known.write_text(f'[127.0.0.1]:{port} '+public[0]+' '+public[1]+'\n')
    return ['ssh','-F','/dev/null','-p',str(port),'-i',str(bundle/'ssh_client_rsa'),
            '-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ConnectTimeout=5',
            '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),
            '-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlgorithms=+ssh-rsa',
            '-o','PubkeyAcceptedAlgorithms=+ssh-rsa','root@127.0.0.1']


def startup_jobs(text):
    jobs = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 3:
            jobs[fields[2]] = fields[:2]
    return jobs


def startup_status(text, cydia_initialized):
    jobs = startup_jobs(text)
    if jobs.get('com.apple.datamigrator', ['-'])[0].isdigit():
        return 'iOS is initializing its data; an Apple logo with a progress bar may remain visible.'
    if not cydia_initialized:
        return 'Waiting for Cydia first-start initialization to finish.'
    cydia = jobs.get('com.saurik.Cydia.Startup')
    if cydia and cydia != ['-', '0']:
        return 'Waiting for Cydia first-start initialization to finish.'
    return 'Waiting for the target interface and services.'


def startup_failure(text):
    """Describe the latest failed Cydia attempt while launchd can retry it."""
    cydia = startup_jobs(text).get('com.saurik.Cydia.Startup')
    if cydia and cydia[0] == '-' and cydia[1] not in {'-', '0'}:
        return ('Cydia first-start initialization failed with status '+cydia[1]+'. '
                'Inspect /var/logs/AppleSupport/olsn0w-cydia.log on the target.')
    return None


def services_ready(text, release, cydia_initialized):
    jobs = startup_jobs(text)
    # On iOS 8 datamigrator can remain alive while Setup Assistant waits for
    # activation. Requiring it to exit before activating creates a deadlock.
    # SpringBoard plus the completed jailbreak job is the qualified iOS 8 gate.
    major=version(release)[0]
    if major != 8 and jobs.get('com.apple.datamigrator', ['-'])[0].isdigit():
        return False
    if not jobs.get('com.apple.SpringBoard', ['-'])[0].isdigit():
        return False
    if not cydia_initialized:
        return False
    if jobs.get('com.saurik.Cydia.Startup') != ['-', '0']:
        return False
    if major == 7:
        from system import LATE_MIS_SERVICES
        if any(label not in jobs for label in LATE_MIS_SERVICES):
            return False
    return True


def target_identity_ready(lines, report):
    """Require the selected root and Data generation without failing early boot."""
    expected=[report['identity']['board'].upper(),report['build'],report['generation']]
    return lines[:3] == expected


def cydia_initialization_ready(lines, generation):
    """Prove that Cydia startup completed on this exact Data generation."""
    return len(lines) > 3 and lines[3] == 'CYDIA_READY:' + generation


def cydia_needs_start(text, initialized):
    """Start an idle registered job when its generation marker is absent."""
    job=startup_jobs(text).get('com.saurik.Cydia.Startup')
    return not initialized and bool(job) and job[0] == '-'


def pangu_needs_writable_root(release):
    """Return whether qualification must prove Pangu's writable root."""
    return version(release)[0] == 7 and version(release) >= version('7.1')


def pangu_writable_root_ready(lines, report):
    """Require the untether marker and the selected root mounted read-write."""
    if len(lines) < 6 or lines[4] != 'UNTETHER_READY:ready':
        return False
    partitions=report.get('layout',{}).get('partitions',[])
    roots=[item.get('device') for item in partitions if item.get('role')=='system']
    if len(roots) != 1:
        return False
    mount=lines[5]
    return (mount.startswith(roots[0]+' on / (hfs,') and
            'read-only' not in mount)


def qualify_installed_target(bundle, prefix, udid, release, timeout=360,
                             progress=print):
    """Qualify the first boot, including Pangu's completed root remount."""
    return qualify(bundle,prefix,udid,timeout=timeout,progress=progress,
                   verify_writable_root=pangu_needs_writable_root(release))


def qualify(bundle, prefix, udid, timeout=360, progress=print,
            verify_writable_root=False):
    report=checked_manifest(bundle)
    started=time.monotonic();deadline=started+timeout;last_notice=started
    status='Waiting for the target USB connection.'
    values=None;activation_acknowledgement=None
    cydia_start_attempted=False
    startup_error=None
    activation_attempts=0;next_activation_attempt=started
    progress('Waiting for iOS '+report['version']+' to start. The Apple logo can change and the display can go black during the boot handoff; keep the cable connected.')
    command=('/usr/sbin/sysctl -n hw.model; /usr/sbin/sysctl -n kern.osversion; '
             '/bin/cat /var/lib/olsn0w/generation; '
             'if [ -s /var/lib/olsn0w/cydia-ready ]; then printf "CYDIA_READY:"; '
             '/bin/cat /var/lib/olsn0w/cydia-ready; else printf "CYDIA_READY:\\n"; fi; '
             + ('if [ -s /var/run/olsn0w-untether-ready ]; then printf "UNTETHER_READY:"; '
                '/bin/cat /var/run/olsn0w-untether-ready; else printf "UNTETHER_READY:\\n"; fi; '
                '/sbin/mount; ' if verify_writable_root else '') +
             '/bin/launchctl list')
    while True:
        status='Waiting for the target USB connection.'
        services=False
        try:
            r=subprocess.run(prefix+[command],capture_output=True,timeout=15)
            text=r.stdout.decode(errors='replace')
            lines=text.splitlines()
            if r.returncode==0:
                if target_identity_ready(lines,report):
                    initialized=cydia_initialization_ready(lines,report['generation'])
                    writable=(not verify_writable_root or
                              pangu_writable_root_ready(lines,report))
                    if not writable:
                        # Pangu calls its launchctl endpoint before finishing
                        # the kernel patch and root remount.  Its marker alone
                        # is therefore not a completion signal, and rebooting
                        # here strands the next boot behind Pangu's own
                        # panguaxe.installed shortcut.
                        status='Waiting for Pangu to remount the selected System volume read-write.'
                    else:
                        failure=startup_failure(text)
                        if failure:
                            # The Cydia job deliberately has KeepAlive on
                            # unsuccessful exit.  First boot can expose status
                            # 1 briefly while Data and the package cache settle;
                            # the generation-bound completion marker, not that
                            # intermediate status, is the authoritative gate.
                            startup_error=failure
                            status=failure.replace(
                                'Inspect /var/logs/AppleSupport/olsn0w-cydia.log on the target.',
                                'Waiting for its automatic retry.')
                        else:
                            startup_error=None
                            status=startup_status(text,initialized)
                        services=services_ready(text,report['version'],initialized)
                    if (writable and not cydia_start_attempted and
                            cydia_needs_start(text,initialized) and
                            startup_jobs(text).get('com.apple.SpringBoard',['-'])[0].isdigit()):
                        job_result=subprocess.run(
                            prefix+['/bin/launchctl start com.saurik.Cydia.Startup'],
                            capture_output=True,timeout=15)
                        if job_result.returncode==0:
                            cydia_start_attempted=True
                            status='Starting Cydia first-start initialization.'
                else:
                    # iOS 7 can expose SSH before protected Data first boot has
                    # atomically published its generation marker.  Lockdown
                    # below remains the strict hardware/firmware identity gate;
                    # keep polling SSH until the selected Data is also proven.
                    status='Target SSH is reachable; waiting for the selected Data generation to finish initializing.'
            elif b'Permission denied' in r.stderr:
                status='Target SSH rejected the prepared key; activation is being checked independently.'
        except subprocess.TimeoutExpired:
            pass
        # Official activation travels through lockdownd and does not depend on
        # the diagnostic SSH account. Do it as soon as the selected firmware
        # and personalized baseband are visible, so Setup Assistant cannot be
        # stranded by a later SSH qualification failure.
        output=subprocess.run([str(tools()/'ideviceinfo'),'-u',udid,'-x'],capture_output=True,timeout=20)
        if output.returncode==0:
            values=plistlib.loads(output.stdout)
            if (values.get('ProductType'),values.get('ProductVersion'),values.get('BuildVersion'))!=(report['product'],report['version'],report['build']):
                raise ValueError('Lockdown reports a different target')
            baseband_ready=(not profile(report['product'])['has_baseband']
                            or bool(values.get('BasebandVersion')))
            if baseband_ready and values.get('ActivationState')!='Activated' and report.get('activation_mode')=='official-on-target':
                from activation import ActivationPending, activate
                if time.monotonic()>=next_activation_attempt:
                    if activation_attempts==0:
                        progress('Completing official activation through the connected computer.')
                    try:
                        activate(udid,report['identity'],bundle/'activation.log')
                    except ActivationPending:
                        activation_attempts+=1
                        next_activation_attempt=time.monotonic()+10
                    else:
                        values['ActivationState']='Activated'
                if values.get('ActivationState')!='Activated':
                    status='Official activation is not ready; retrying through the connected computer.'
            if baseband_ready and values.get('ActivationState')=='Activated' and activation_acknowledgement is None:
                from activation import acknowledge
                activation_acknowledgement=acknowledge(udid,report['identity'])
            if services and baseband_ready and values.get('ActivationState')=='Activated':
                break
        if time.monotonic()>=deadline:
            detail=startup_error or status
            raise RuntimeError('Installation was written and verified, but startup is not yet confirmed. '+detail+' Keep the device connected and inspect its startup logs before retrying the installation.')
        now=time.monotonic()
        if now-last_notice>=30:
            progress(status+' ('+str(int(now-started))+' s; startup is not confirmed yet.)')
            last_notice=now
        time.sleep(5)
    (bundle/'target-services.txt').write_text(text)
    result=dict(product=report['product'],version=report['version'],build=report['build'],
                normal_boot_verified=True,activation_state=values.get('ActivationState'),
                baseband_version=values.get('BasebandVersion'),springboard_verified=True,
                generation_verified=True,forced_reset_verified=False,
                writable_root_verified=verify_writable_root)
    result['activation_acknowledgement']=activation_acknowledgement
    checkpoint(bundle/'qualification.json',result)
    return result


def run(session, bundle, *, erase=False, ram_ready=False, progress=print):
    session,bundle=Path(session).resolve(),Path(bundle).resolve()
    report=checked_manifest(bundle);record=json.loads((session/'device.json').read_text())
    if not erase or not same_hardware(record['identity'],report['identity']):
        raise ValueError('Explicit erase and matching selected device are required')
    if (bundle/'installation.json').exists():raise ValueError('Inspect the previous installation before retrying')
    prefix=json.loads((session/'ssh-prefix.json').read_text());port=int(prefix[prefix.index('-p')+1])
    udid=record['ram_udid']
    if not re.fullmatch(r'[a-fA-F0-9]{40}',udid):raise ValueError('Invalid selected USB identity')
    proxy=None;log=None
    try:
        # Existing pinned tunnels can be reused. Start one for standalone runs.
        with socket.socket() as probe:
            listening=probe.connect_ex(('127.0.0.1',port))==0
        if not listening:
            log=(bundle/'iproxy.log').open('wb')
            proxy=subprocess.Popen([str(tools()/'iproxy'),'-u',udid,'-s','127.0.0.1',f'{port}:22'],stdout=log,stderr=log)
        if not ram_ready:boot(session,progress=progress)
        ram=connect(session)
        refresh_layout(bundle,ram)
        install(bundle,ram,erase=True,progress=progress)
        new_prefix=target_prefix(bundle,port)
        checkpoint(bundle/'target-ssh-prefix.json',new_prefix)
        progress('All volumes verified. Starting normal boot.')
        ram.run('/sbin/reboot')
        result=qualify_installed_target(bundle,new_prefix,udid,report['version'],
                                        progress=progress)
        progress('Target boot, writable System state, Data generation, SpringBoard and activation verified.')
        return result
    finally:
        if proxy is not None:
            proxy.terminate()
            try:proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:proxy.kill();proxy.wait()
        if log:log.close()
