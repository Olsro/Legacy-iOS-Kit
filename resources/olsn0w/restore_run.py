"""Run the prepared erase, then qualify the target reached by normal boot."""
import json
from pathlib import Path
import plistlib
import re
import socket
import subprocess
import time

from common import tools
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


def startup_status(text):
    jobs = startup_jobs(text)
    if jobs.get('com.apple.datamigrator', ['-'])[0].isdigit():
        return 'iOS is initializing its data; an Apple logo with a progress bar may remain visible.'
    cydia = jobs.get('com.saurik.Cydia.Startup')
    if cydia and cydia != ['-', '0']:
        return 'Waiting for Cydia first-start initialization to finish.'
    return 'Waiting for the target interface and services.'


def services_ready(text, release):
    jobs = startup_jobs(text)
    # On iOS 8 datamigrator can remain alive while Setup Assistant waits for
    # activation. Requiring it to exit before activating creates a deadlock.
    # SpringBoard plus the completed jailbreak job is the qualified iOS 8 gate.
    if release.split('.')[0] != '8' and jobs.get('com.apple.datamigrator', ['-'])[0].isdigit():
        return False
    if not jobs.get('com.apple.SpringBoard', ['-'])[0].isdigit():
        return False
    if jobs.get('com.saurik.Cydia.Startup') != ['-', '0']:
        return False
    if release.split('.')[0] == '7':
        from system import LATE_MIS_SERVICES
        if any(label not in jobs for label in LATE_MIS_SERVICES):
            return False
    return True


def qualify(bundle, prefix, udid, timeout=360, progress=print):
    report=checked_manifest(bundle)
    started=time.monotonic();deadline=started+timeout;last_notice=started
    status='Waiting for the target USB connection.'
    values=None;activation_acknowledgement=None
    progress('Waiting for iOS '+report['version']+' to start. The Apple logo can change and the display can go black during the boot handoff; keep the cable connected.')
    command='/usr/sbin/sysctl -n hw.model; /usr/sbin/sysctl -n kern.osversion; cat /var/lib/olsn0w/generation; /bin/launchctl list'
    while True:
        status='Waiting for the target USB connection.'
        services=False
        try:
            r=subprocess.run(prefix+[command],capture_output=True,timeout=15)
            text=r.stdout.decode(errors='replace')
            lines=text.splitlines()
            if r.returncode==0:
                if lines[:3]!=[report['identity']['board'].upper(),report['build'],report['generation']]:
                    raise ValueError('Booted target identity or Data generation differs')
                status=startup_status(text)
                services=services_ready(text, report['version'])
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
            baseband_ready=report['product']=='iPad3,4' or bool(values.get('BasebandVersion'))
            if baseband_ready and values.get('ActivationState')!='Activated' and report.get('activation_mode')=='official-on-target':
                from activation import activate
                progress('Completing official activation through the connected computer.')
                activate(udid,report['identity'],bundle/'activation.log')
                values['ActivationState']='Activated'
            if baseband_ready and values.get('ActivationState')=='Activated' and activation_acknowledgement is None:
                from activation import acknowledge
                activation_acknowledgement=acknowledge(udid,report['identity'])
            if services and baseband_ready and values.get('ActivationState')=='Activated':
                break
        if time.monotonic()>=deadline:
            raise RuntimeError('Installation was written and verified, but startup is not yet confirmed. '+status+' Keep the device connected and inspect its startup logs before retrying the installation.')
        now=time.monotonic()
        if now-last_notice>=30:
            progress(status+' ('+str(int(now-started))+' s; startup is not confirmed yet.)')
            last_notice=now
        time.sleep(5)
    (bundle/'target-services.txt').write_text(text)
    result=dict(product=report['product'],version=report['version'],build=report['build'],
                normal_boot_verified=True,activation_state=values.get('ActivationState'),
                baseband_version=values.get('BasebandVersion'),springboard_verified=True,
                generation_verified=True,forced_reset_verified=False)
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
        result=qualify(bundle,new_prefix,udid,progress=progress)
        progress('Target boot, Data generation, SpringBoard and activation verified.')
        return result
    finally:
        if proxy is not None:
            proxy.terminate()
            try:proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:proxy.kill();proxy.wait()
        if log:log.close()
