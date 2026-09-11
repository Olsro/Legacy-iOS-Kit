"""Restore a signed base and the selected target through one DFU/RAM session."""
import json
from pathlib import Path
import subprocess

from device import same_hardware
from provision_run import DfuPreparationError, run as provision
from provision_collect import collect
from provisioned_base import prepare as bind
from restore import checked_manifest, checkpoint, prepare, install
from restore_run import target_prefix, qualify
from common import version


def run(session, bundle, bootstrap, system, relay, ticket, keys, *,
        baseband=None, baseband_manifest=None, erase=False, progress=print):
    session,bundle,bootstrap,system,relay=map(Path,(session,bundle,bootstrap,system,relay))
    device=json.loads((session/'device.json').read_text())
    reports=[checked_manifest(p) for p in (bundle,bootstrap,system,relay)]
    if not erase or not same_hardware(reports[0]['identity'],device['identity']):
        raise ValueError('Explicit erase and matching provisioning identity required')
    if any(r['product']!=device['identity']['product'] for r in reports):
        raise ValueError('Prepared provisioning components belong to another product')
    if any(reports[2][key]!=reports[3][key] for key in ('version','build')):
        raise ValueError('Target system and relay differ')
    from system import PREPARABLE_MAJORS
    if version(reports[2]['version'])[0] not in PREPARABLE_MAJORS:
        raise ValueError('Target first-boot integration is unavailable; no erase started')
    if reports[1].get('base_build')!='12H321':
        raise ValueError('Expected the prepared compact signed base')
    journal=bundle/'pipeline.json'
    if journal.exists() or (bundle/'run.json').exists():
        raise ValueError('Inspect the existing provisioning attempt before retrying')
    prefix=json.loads((session/'ssh-prefix.json').read_text())
    port=int(prefix[prefix.index('-p')+1])
    state=dict(stage='prepared',complete=False)
    def stage(name):
        state['stage']=name;checkpoint(journal,state)
    stage('signed-base')
    ram=None
    try:
        ram=provision(session,bundle,ticket,keys,baseband=baseband,
                      baseband_manifest=baseband_manifest,erase=True,progress=progress)
        stage('collecting-signed-artifacts')
        progress('Signed base verified. Collecting its kernel and modem for the compact installation; the phone bar may stay unchanged.')
        collect(bundle,ram,bundle/'technical')
        stage('preparing-target')
        progress('Preparing iOS '+reports[2]['version']+' and the compact bootstrap on this computer.')
        bind(bundle/'technical',bootstrap,bundle/'compact-base')
        target=bundle/'target'
        prepare(session,system,relay,bundle/'compact-base',target)
        stage('installing-target')
        install(target,ram,erase=True,progress=progress)
        next_prefix=target_prefix(target,port)
        checkpoint(target/'target-ssh-prefix.json',next_prefix)
        ram.run('/usr/sbin/nvram -d olsn0w-restore-handoff')
        ram.run('/usr/sbin/nvram auto-boot=true')
        stage('normal-boot')
        progress('All volumes verified. Starting the selected target.')
        try:ram.run('/sbin/reboot_olsn0w',timeout=20)
        except (RuntimeError,subprocess.TimeoutExpired):
            # Reboot can close SSH before it returns; target qualification
            # still has to prove the selected generation actually started.
            pass
        device=json.loads((session/'device.json').read_text())
        result=qualify(target,next_prefix,device['ram_udid'],timeout=480,progress=progress)
        state.update(stage='qualified',complete=True,qualification=result)
        checkpoint(journal,state)
        return result
    except DfuPreparationError:
        # The pipeline marker is written before entering provision() so that
        # every destructive phase is journaled. A typed DFU failure is the one
        # exception: provision() guarantees futurerestore never started and no
        # device storage changed. Remove only this premature marker, allowing
        # the same fully prepared plan to be attempted again.
        if (bundle/'run.json').exists():
            raise RuntimeError('DFU failed after a provisioning journal was created; inspect it before retrying')
        journal.unlink()
        raise
    except Exception as error:
        state['error']=str(error);checkpoint(journal,state)
        raise

    finally:
        from usb_tunnel import stop
        stop(getattr(ram,"owned_tunnel",None))
