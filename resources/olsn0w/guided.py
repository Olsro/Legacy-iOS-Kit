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

from common import KIT, MODELS, STATE, integer, profile, run, save, tools, version
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


GIB=1024**3
SESSION_WORKSPACE=8*GIB


def preparation_space(product, selected, records_provider=releases):
    """Estimate the remaining peak from artifacts that are not cached yet."""
    from firmware import select_release
    from compact_cache import qualified_source
    source=qualified_source(profile(product)['cache_arch'])
    requested={(product,selected['version'],selected['buildid']),
               (product,'8.4.1','12H321'),
               (source['product'],source['release'],source['build'])}
    records=[]
    for item_product,item_version,item_build in requested:
        if (item_product,item_version,item_build)==(product,selected['version'],selected['buildid']):
            record=selected
        else:
            record=select_release(records_provider(item_product),item_version,item_build)
        records.append((item_product,record))
    permanent=0;extraction_scratch=0
    selected_firmware=None;selected_record=None
    for item_product,record in records:
        size=int(record['filesize'])
        ipsw=STATE/'ipsw'/(item_product+'_'+record['version']+'_'+record['buildid']+'_Restore.ipsw')
        firmware=STATE/'targets'/item_product/record['buildid']/'firmware'
        if not ipsw.is_file():permanent+=size
        if not (firmware/'manifest.json').is_file():
            # Root HFS images for these releases are at most about 1.3 times
            # their IPSW. The encrypted member also exists transiently while
            # it is being decoded, but is removed after verification.
            permanent+=(size*4+2)//3
            extraction_scratch=max(extraction_scratch,size)
        if (item_product,record['version'],record['buildid'])==(product,selected['version'],selected['buildid']):
            selected_firmware=firmware;selected_record=record
    system=STATE/'targets'/product/selected['buildid']/'system/manifest.json'
    if not system.is_file():
        root=selected_firmware/'rootfs.hfs'
        permanent+=root.stat().st_size if root.is_file() else (int(selected_record['filesize'])*4+2)//3
    return permanent+max(SESSION_WORKSPACE,extraction_scratch)


def check_space(required):
    STATE.mkdir(parents=True,exist_ok=True)
    free=shutil.disk_usage(STATE).free
    if free < required:
        need=(required+GIB-1)//GIB;available=free//GIB
        raise RuntimeError('Preparation needs about '+str(need)+' GiB for the files still missing and temporary images; '
                           +str(available)+' GiB is available. Free space and try again; no device was erased.')
    return required


def reusable_recipe(path, expected, checker):
    """Retain a reproducible cache only when its recipe is current."""
    path=Path(path)
    if not path.exists():return False
    if checker(path).get('recipe_version')==expected:return True
    shutil.rmtree(path)
    return False


def prepare(session, release, show=print):
    from progress import LiveProgress
    with LiveProgress(show) as display:
        return _prepare(session,release,display)


def bootstrap_cache_firmware(product, base_firmware, extract_firmware, show=lambda _:None):
    """Select the exact stock-cache donor used by the qualified recipe."""
    from compact_cache import qualified_source
    architecture=profile(product)['cache_arch']
    source=qualified_source(architecture)
    if product==source['product']:
        return base_firmware
    kind='iPad' if product.startswith('iPad') else 'device'
    show('Obtaining the qualified shared '+architecture+' bootstrap source; all '+kind+' boot components remain model-specific.')
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
    required=preparation_space(product,release)
    show('Disk space needed for the remaining preparation: about '+str((required+GIB-1)//GIB)+' GiB.')
    check_space(required)
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
        if not reusable_recipe(relay,RELAY_RECIPE,checked_manifest):
            relay_prepare(firmware)
        system=firmware.parent/'system'
        if not reusable_recipe(system,SYSTEM_RECIPE,checked_manifest):
            # Both caches are generated solely from verified firmware and
            # payload inputs. Rebuild an obsolete recipe in place so a safety
            # correction never requires manual cache surgery.
            system_prepare(firmware,relay)
    display.phase(3,'preparing the restore environment and compact bootstrap.')
    with activity('preparing the restore environment and compact bootstrap'):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        rescue_prepare(session,base_ipsw,base_keys,port)
        serial=record.get('ram_udid') or hashlib.sha1(('olsn0w:'+str(identity['ecid'])).encode()).hexdigest()
        native=native_prepare(product,serial,session/'native')
        libraries=session/'libraries';(libraries/'usr/lib').mkdir(parents=True)
        source=(session/'bootstrap-libutil.dylib' if (session/'bootstrap-libutil.dylib').is_file()
                else None)
        library=(source.read_bytes() if source else HFS(session/'rescue-ram.hfs').read('/usr/lib/libutil.dylib'))
        (libraries/'usr/lib/libutil.dylib').write_bytes(library)
        architecture=profile(product)['cache_arch']
        cache_source=session/'stock-cache'
        cache_source.write_bytes(HFS(cache_firmware/'rootfs.hfs').read(
            '/System/Library/Caches/com.apple.dyld/dyld_shared_cache_'+architecture))
        cache=session/'compact-cache';cache_prepare(cache_source,cache,architecture)
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
        if actual['mode']!='DFU':return False
        if profile(identity['product']).get('external_pwndfu'):
            result=subprocess.run([str(tools()/'irecovery'),'-i',hex(identity['ecid']),'-q'],
                                  capture_output=True,timeout=15)
            text=(result.stdout+result.stderr).decode(errors='replace')
            return result.returncode==0 and ('PWND: [checkm8]' in text or 'PWND:[checkm8]' in text)
        return True
    while not ready():
        show('Keep the selected device connected by USB. Prepared files are retained across every DFU attempt.')
        if profile(identity['product']).get('external_pwndfu'):
            show('Put the iPhone 4S in DFU, run the A5_8940 A5Mate profile, eject it cleanly with A, then reconnect it to this computer. The host requires PWND:[checkm8].')
            prompt='Press Enter once the externally pwned DFU device is reconnected (Ctrl+C to cancel): '
        else:
            show('Hold Power + Home for 10 seconds, then release Power while continuing to hold Home for about 10 seconds. The screen must remain black.')
            prompt='Press Enter once the device is in DFU (Ctrl+C to cancel): '
        read(prompt)
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
