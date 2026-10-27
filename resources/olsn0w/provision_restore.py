"""Restore a signed base and the selected target through one DFU/RAM session."""
import json
from pathlib import Path
import shutil
import subprocess

from device import same_hardware
from provision_run import DfuPreparationError, run as provision
from provision_collect import collect
from provisioned_base import prepare as bind
from restore import checked_manifest, checkpoint, prepare, install
from restore_run import target_prefix, qualify_installed_target
from common import version
from boot_settings import prepare_normal_boot


def cleanup_completed(session, bundle, bootstrap):
    """Prune only reconstructible bulk data after final boot qualification."""
    session,bundle,bootstrap=(Path(path).resolve() for path in (session,bundle,bootstrap))
    state=json.loads((bundle/'pipeline.json').read_text())
    if state.get('stage')!='qualified' or state.get('complete') is not True:
        raise ValueError('Bulk cleanup requires a qualified completed restoration')
    root=session.resolve()
    targets=[bundle/'base8.ipsw',bundle/'system.asr.dmg',bundle/'base8',
             bundle/'restore-ram.hfs',bundle/'Ramdisk.img3',
             bundle/'target/system.hfs',bundle/'target/data-native.hfs']
    if root in bootstrap.resolve().parents:
        targets.append(bootstrap/'bootstrap.cache')
    targets.extend(session.glob('rescue-pending-*'))
    targets=[path for path in targets if path.exists()]
    if any(root not in path.resolve().parents or path.is_symlink() for path in targets):
        raise ValueError('Cleanup target escaped the completed session')
    removed=[];physical=0
    for path in targets:
        items=[path] if path.is_file() else [p for p in path.rglob('*') if p.is_file() or p.is_symlink()]
        physical+=sum(p.lstat().st_blocks*512 for p in items)
        removed.append(str(path.relative_to(session)))
        if path.is_dir():shutil.rmtree(path)
        else:path.unlink()
    report=dict(kind='completed-session-pruning',bytes_reclaimed=physical,removed=removed)
    checkpoint(session/'cleanup.json',report)
    return report


def run(session, bundle, bootstrap, system, relay, ticket, keys, *,
        baseband=None, baseband_manifest=None, erase=False, pwned=False,
        progress=print):
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
    # Reject an old iOS 8 writer before even restoring the temporary base.
    # The selected RAM must handle the complete installation in one DFU run.
    from restore_environment import selected_build
    from restore import require_data_environment
    require_data_environment(device['identity']['product'],reports[2]['version'],
        reports[0].get('restore_environment_build',selected_build(device['identity']['product'])))
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
                      baseband_manifest=baseband_manifest,erase=True,pwned=pwned,
                      progress=progress)
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
        stage('preparing-normal-boot')
        prepare_normal_boot(ram,target,progress=progress)
        ram.run('/usr/sbin/nvram -d olsn0w-restore-handoff')
        stage('normal-boot')
        progress('All volumes verified. Starting the selected target.')
        try:ram.run('/sbin/reboot_olsn0w',timeout=20)
        except (RuntimeError,subprocess.TimeoutExpired):
            # Reboot can close SSH before it returns; target qualification
            # still has to prove the selected generation actually started.
            pass
        device=json.loads((session/'device.json').read_text())
        result=qualify_installed_target(
            target,next_prefix,device['ram_udid'],reports[2]['version'],
            timeout=480,progress=progress)
        state.update(stage='qualified',complete=True,qualification=result)
        checkpoint(journal,state)
        try:
            cleanup=cleanup_completed(session,bundle,bootstrap)
            progress('Removed '+str(cleanup['bytes_reclaimed']//1048576)+' MiB of reconstructible completed-session files.')
        except Exception as error:
            # Cleanup must never turn an already qualified restoration into a
            # reported failure. Its exact error remains visible to the user.
            progress('Restoration is qualified; automatic disk cleanup was skipped: '+str(error))
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
