"""Connected-device selection, automatic preparation and a single guided DFU."""
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import socket
import subprocess
import time
import uuid

from common import KIT, MODELS, STATE, integer, run, save, version
from device import query_recovery, same_hardware
from firmware import releases
from guided_inputs import tool


def connected(product, ecid, udid=None):
    if ecid is None:raise ValueError('Connect a device and open olsn0w from the Restore menu')
    expected=integer(ecid)
    if udid and re.fullmatch('[0-9a-fA-F]{40}',udid):
        try:
            fields=plistlib.loads(run([tool('ideviceinfo'),'-u',udid,'-x'],timeout=15))
        except (RuntimeError,subprocess.TimeoutExpired):fields=None
        if fields is not None:
            board,chip,board_id=MODELS[product]
            if (fields['ProductType']!=product or int(fields['UniqueChipID'])!=expected
                    or fields['HardwareModel'].lower()!=board):
                raise ValueError('Connected device differs from the menu selection')
            return dict(product=product,ecid=expected,board=board,chip=chip,board_id=board_id,mode='Normal'),udid.lower()
    identity=query_recovery(expected)
    if identity['product']!=product:raise ValueError('Connected product differs from the menu selection')
    return identity,None


def support_reason(release):
    # This follows the implemented first-boot recipes, not an arbitrary ceiling.
    from system import SUPPORTED_MAJORS, PREPARABLE_MAJORS
    major=version(release)[0]
    if major in SUPPORTED_MAJORS:return None
    if major in PREPARABLE_MAJORS:return 'device validation is pending'
    return 'first-boot integration is not implemented yet'


def choose(options, read=input, show=print):
    while True:
        for index,release in enumerate(options,1):
            reason=support_reason(release['version'])
            show(str(index)+'. iOS '+release['version']+' ('+release['buildid']+')'+(' — unavailable: '+reason if reason else ''))
        show('0. Go Back')
        answer=read('Select a number or iOS version (for example 6.1.2): ').strip()
        if answer=='0':return None
        if answer.isdigit() and 1<=int(answer)<=len(options):
            selected=options[int(answer)-1]
        else:
            try:matches=[release for release in options if version(release['version'])==version(answer)]
            except ValueError:matches=[]
            if len(matches)!=1:
                show('Several builds match; select a number.' if matches else 'Choose a listed number or version.');continue
            selected=matches[0]
        if support_reason(selected['version']):
            show('This release cannot be restored with the current olsn0w recipes. No device changes made.');continue
        return selected


def check_space():
    STATE.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(STATE).free < 20*1024**3:
        raise RuntimeError('Preparation needs 20 GiB of free disk space for firmware and temporary images. Free space and try again; no device was erased.')


def prepare(session, release, show=print):
    from progress import LiveProgress
    with LiveProgress(show) as display:
        return _prepare(session,release,display)


def bootstrap_cache_firmware(product, base_firmware, extract_firmware, show=lambda _:None):
    """Select the exact stock-cache donor used by the qualified recipe."""
    from compact_cache import qualified_source
    source=qualified_source()
    if product==source['product']:
        return base_firmware
    show('Obtaining the qualified shared armv7s bootstrap source; all iPad boot components remain model-specific.')
    firmware,_=extract_firmware(source['product'],source['release'],build=source['build'])
    return firmware


def _prepare(session, release, display):
    from progress import activity
    show=display.message
    from firmware import acquire, extract
    from bootchain import prepare as relay_prepare, RECIPE_VERSION as RELAY_RECIPE
    from system import prepare as system_prepare, RECIPE_VERSION as SYSTEM_RECIPE
    from restore import checked_manifest
    from rescue_prepare import prepare as rescue_prepare
    from provision import prepare as provision_prepare
    from bootstrap_assets import prepare as native_prepare
    from bootstrap import prepare as bootstrap_prepare
    from compact_cache import prepare as cache_prepare
    from hfs import HFS
    from guided_inputs import ticket, modem
    record=json.loads((session/'device.json').read_text());identity=record['identity'];product=identity['product']
    check_space()
    display.phase(1,'obtaining the signed base, selected firmware and Apple ticket. The device is not being erased yet.')
    with activity('obtaining the signed base, selected firmware and Apple ticket. The device is not being erased yet'):
        base_ipsw,keys,_,_=acquire(product,'8.4.1',build='12H321')
        base_keys=session/'base-keys.json';save(base_keys,keys)
        ticket_file=ticket(identity,session/'ticket')
        baseband,baseband_manifest=modem(identity,session/'modem')
        firmware,_=extract(product,release['version'],build=release['buildid'])
        base_firmware,_=extract(product,'8.4.1',base_ipsw,base_keys,'12H321')
        cache_firmware=bootstrap_cache_firmware(product,base_firmware,extract,show)
    display.phase(2,'preparing the selected system and boot relay.')
    with activity('preparing the selected system and boot relay'):
        relay=firmware.parent/'relay'
        if relay.exists():
            if checked_manifest(relay).get('recipe_version')!=RELAY_RECIPE:raise ValueError('Cached relay recipe is outdated')
        else:relay_prepare(firmware)
        system=firmware.parent/'system'
        if system.exists():
            if checked_manifest(system).get('recipe_version')!=SYSTEM_RECIPE:raise ValueError('Cached system recipe is outdated')
        else:system_prepare(firmware,relay)
    display.phase(3,'preparing the restore environment and compact bootstrap.')
    with activity('preparing the restore environment and compact bootstrap'):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        rescue_prepare(session,base_ipsw,base_keys,port)
        serial=record.get('ram_udid') or hashlib.sha1(('olsn0w:'+str(identity['ecid'])).encode()).hexdigest()
        native=native_prepare(product,serial,session/'native')
        libraries=session/'libraries';(libraries/'usr/lib').mkdir(parents=True)
        (libraries/'usr/lib/libutil.dylib').write_bytes(HFS(session/'rescue-ram.hfs').read('/usr/lib/libutil.dylib'))
        cache_source=session/'stock-cache'
        cache_source.write_bytes(HFS(cache_firmware/'rootfs.hfs').read('/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7s'))
        cache=session/'compact-cache';cache_prepare(cache_source,cache)
        bootstrap=session/'bootstrap'
        bootstrap_prepare(product,base_firmware,libraries,native,relay/'relay.bin',base_firmware/'Kernelcache.img3',
                          cache,native/'root.hfs',native/'var.hfs',bootstrap)
        # Both cache inputs are reproducible; the verified bootstrap now contains them.
        cache_source.unlink();cache.unlink()
    display.phase(4,'preparing the temporary signed-base restoration.')
    with activity('preparing the temporary signed-base restoration'):
        bundle=session/'provision'
        provision_prepare(session,bundle,base_ipsw,base_keys)
    display.phase(5,'checking all prepared components before erasing.')
    with activity('checking all prepared components before erasing'):
        for path in (bundle,bootstrap,system,relay):checked_manifest(path)
        from provision_run import restore_arguments
        restore_arguments(identity,bundle/'base8.ipsw',ticket_file,baseband,baseband_manifest)
        plan=dict(session=session,bundle=bundle,bootstrap=bootstrap,system=system,relay=relay,
                  ticket=ticket_file,keys=base_keys,baseband=baseband,baseband_manifest=baseband_manifest)
        save(session/'guided-plan.json',{k:str(v) if v is not None else None for k,v in plan.items()})
        return plan


def enter_dfu(identity, read=input, show=print):
    def ready():
        try:actual=query_recovery(identity['ecid'])
        except (RuntimeError,subprocess.TimeoutExpired):return False
        if not same_hardware(identity,actual):raise ValueError('DFU target differs from the selected device')
        return actual['mode']=='DFU'
    while not ready():
        show('Keep the selected device connected by USB. Prepared files are retained across every DFU attempt.')
        show('Hold Power + Home for 10 seconds, then release Power while continuing to hold Home for about 10 seconds. The screen must remain black.')
        read('Press Enter once the device is in DFU (Ctrl+C to cancel): ')
        deadline=time.monotonic()+30
        detected=ready()
        while not detected and time.monotonic()<deadline:
            time.sleep(2)
            detected=ready()
        if detected:return
        show('Selected device was not detected in DFU. No erase started; try again with the same prepared files.')


def menu(product,ecid,udid=None,refresh=False,read=input,show=print):
    identity,udid=connected(product,ecid,udid)
    show('\nolsn0w — '+product+' — connected in '+identity['mode'])
    selected=choose(releases(product,refresh),read,show)
    if selected is None:return
    session=STATE/'sessions'/str(uuid.uuid4());session.mkdir(parents=True,mode=0o700)
    record=dict(identity=identity,device_modified=False,state='selected',manage_usb_tunnel=True)
    if udid:record['ram_udid']=udid
    save(session/'device.json',record)
    show('Preparing iOS '+selected['version']+' for '+product+'. Logs: '+str(session))
    plan=prepare(session,selected,show)
    show('Ready: restore '+product+' to iOS '+selected['version']+'. This erases all data on this device.')
    if read('Continue with restoration? [y/N]: ').strip().lower() not in ('y','yes'):
        show('Cancelled. Prepared files retained; no device was erased.');return
    from provision_restore import run as restore
    from provision_run import DfuPreparationError
    while True:
        enter_dfu(identity,read,show)
        show('Restoration: signed 8.4.1 base → compact bootstrap → selected iOS → activation and boot verification.')
        show('Apple logos, a stationary progress bar and black-screen transitions can occur. Follow the status here and keep the cable connected; an error will be reported explicitly.')
        try:
            result=restore(**plan,erase=True,progress=show)
            break
        except DfuPreparationError as error:
            show('DFU exploit failed before any erase: '+str(error))
            show('All preparation is retained. Re-enter DFU to retry, or press Ctrl+C to cancel.')
    show('Restoration verified: iOS '+selected['version']+'. Complete Setup Assistant on the device.')
    return result
