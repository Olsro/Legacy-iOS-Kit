#!/usr/bin/env python3
"""Prepare olsn0w firmware for a 32-bit device with signed iOS 8.4.1."""
import argparse
import json
import os
from pathlib import Path
import sys

from common import MODELS, STATE, SUPPORT_MESSAGE, tool_environment
from firmware import releases, extract


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(line_buffering=True)
    if not __debug__:
        raise RuntimeError('Run without Python optimization; binary validation is required')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['supports','list','prepare','prepare-system','prepare-restore','restore','select','prepare-rescue','rescue','prepare-provision','provision-restore','menu','configure-ssh'])
    parser.add_argument('--product',required=True,choices=sorted(MODELS))
    parser.add_argument('--version')
    parser.add_argument('--udid',help='Connected normal-mode device from the Kit menu')
    parser.add_argument('--ecid',help='Select a recovery device by ECID')
    parser.add_argument('--port',type=int,default=6414,help='Local USB SSH port for a prepared rescue')
    parser.add_argument('--build', help='Select an exact build when Apple released several for one version')
    parser.add_argument('--ipsw',type=Path)
    parser.add_argument('--keys',type=Path)
    parser.add_argument('--refresh',action='store_true')
    parser.add_argument('--session',type=Path,help='Selected device provisioning/rescue session')
    parser.add_argument('--bootstrap',type=Path,help='Prepared generic compact bootstrap')
    parser.add_argument('--ticket',type=Path,help='Selected-device signed base ticket')
    parser.add_argument('--base-keys',type=Path,help='Keys for the signed 8.4.1 base')
    parser.add_argument('--baseband',type=Path)
    parser.add_argument('--baseband-manifest',type=Path)
    parser.add_argument('--base',type=Path,help='Verified compact base belonging to the selected device')
    parser.add_argument('--bundle',type=Path,help='Prepared device-bound restoration bundle')
    parser.add_argument('--erase',action='store_true',help='Erase the selected device during restoration')
    parser.add_argument('--ram-ready',action='store_true',help='Resume from an already authenticated RAM rescue')
    parser.add_argument('--hacktiv8','--remove-setup-app',dest='remove_setup_app',action='store_true',
                        help='Apply Hacktiv8 keeping Setup.app (iOS 8 cellular service is disabled), or remove Setup.app when unsupported')
    args=parser.parse_args()
    if (args.remove_setup_app and
            args.action not in ('prepare-system','prepare-restore','provision-restore')):
        parser.error('--hacktiv8 applies to system and restoration preparation')
    if args.action=='supports':
        return
    if args.action != 'list':
        from runtime import ensure_runtime
        ensure_runtime(STATE)
        os.environ.update(tool_environment())
        from ssh_client import check as check_ssh_client
        check_ssh_client()
    if args.action == 'configure-ssh':
        if not args.udid:
            parser.error('configure-ssh requires --udid')
        from external_ssh import configure
        configure(args.product, args.udid, args.ecid, args.bundle)
        return
    if args.action == 'provision-restore' and not all((args.session,args.bundle,args.bootstrap,args.ticket,args.base_keys,args.version,args.erase)):
        parser.error('provision-restore requires --session, --bundle, --bootstrap, --ticket, --base-keys, --version and --erase')
    if args.action == 'select':
        if not args.ecid:parser.error('select requires --ecid')
        from device import query_recovery, select_recovery
        if query_recovery(args.ecid)['product'] != args.product:
            raise ValueError('Connected product differs from selection')
        print(select_recovery(args.ecid))
        return
    if args.action == 'prepare-provision':
        if not args.session or not args.bundle:
            parser.error('prepare-provision requires --session and --bundle')
        if json.loads((args.session/'device.json').read_text())['identity']['product'] != args.product:
            raise ValueError('Provisioning session product differs from selection')
        from provision import prepare as prepare_provision
        prepare_provision(args.session,args.bundle,args.ipsw,args.keys)
        print('Prepared signed-base restore with RAM handoff; no device modified: '+str(args.bundle))
        return
    if args.action == 'prepare-rescue':
        if not args.session:parser.error('prepare-rescue requires --session')
        if json.loads((args.session/'device.json').read_text())['identity']['product'] != args.product:
            raise ValueError('Rescue session product differs from selection')
        from rescue_prepare import prepare as prepare_rescue
        from restore_environment import selected_build
        prepare_rescue(args.session,args.ipsw,args.keys,args.port,
                       environment_build=selected_build(args.product,args.version))
        print('Prepared model-specific RAM rescue; no device was modified: '+str(args.session))
        return
    if args.action == 'rescue':
        if not args.session:parser.error('rescue requires --session')
        if json.loads((args.session/'device.json').read_text())['identity']['product'] != args.product:
            raise ValueError('Rescue session product differs from selection')
        from rescue import interactive
        interactive(args.session,ram_ready=args.ram_ready)
        return
    if args.action == 'restore':
        if not args.session or not args.bundle or not args.erase:
            parser.error('restore requires --session, --bundle and --erase')
        from restore import checked_manifest
        if checked_manifest(args.bundle)['product'] != args.product:
            raise ValueError('Restore bundle product differs from selection')
        from restore_run import run as restore_run
        restore_run(args.session,args.bundle,erase=args.erase,ram_ready=args.ram_ready)
        print(SUPPORT_MESSAGE)
        return
    if args.action=='list':
        for f in releases(args.product,args.refresh):
            print(f['version']+' ('+f['buildid']+')')
        return
    if args.action=='menu':
        from guided import menu
        menu(args.product,args.ecid,args.udid,args.refresh)
        return
    if not args.version:parser.error('--version is required for preparation')
    from bootchain import prepare, RECIPE_VERSION
    folder,metadata=extract(args.product,args.version,args.ipsw,args.keys,args.build)
    relay=folder.parent/'relay'
    if relay.exists():
        from common import digest
        report=json.loads((relay/'manifest.json').read_text())
        if report.get('recipe_version') != RECIPE_VERSION:
            raise ValueError('Prepared relay uses an older recipe; preserve or move it before preparing again')
        if any(digest(relay/n)!=h for n,h in report['files'].items()):
            raise ValueError('Prepared relay changed')
    else:
        relay,report=prepare(folder)
    print('Prepared '+metadata['product']+' / iOS '+metadata['version']+': '+str(relay))
    if args.action in ('prepare-system','prepare-restore','provision-restore'):
        from system import prepare as prepare_system
        system_folder=folder.parent/('system-hacktiv8-v1' if args.remove_setup_app else 'system')
        if system_folder.exists():
            from restore import checked_manifest
            from system import RECIPE_VERSION as SYSTEM_RECIPE_VERSION
            system_report=checked_manifest(system_folder)
            if system_report.get('recipe_version') != SYSTEM_RECIPE_VERSION:
                raise ValueError('Prepared system uses an older recipe; preserve it and prepare a new system')
            if system_report.get('setup_customized') is not args.remove_setup_app:
                raise ValueError('Prepared system uses another Hacktiv8/Setup.app policy')
        else:
            system_folder, system_report = prepare_system(
                folder,relay,remove_setup_app=args.remove_setup_app)
        print('Prepared target filesystem and Data seed: '+str(system_folder))
        if args.remove_setup_app:
            print('Hacktiv8 applied; Setup.app preserved.' if system_report.get('hacktiv8') else
                  'Setup.app removed; Hacktiv8 unavailable for this device/build.')
            print('Official target activation will be skipped.')
        else:
            print('Device-specific baseband, activation, and bootstrap installation remain required.')
    if args.action == 'provision-restore':
        from provision_restore import run as provision_restore
        provision_restore(args.session,args.bundle,args.bootstrap,system_folder,relay,args.ticket,args.base_keys,
                          baseband=args.baseband,baseband_manifest=args.baseband_manifest,erase=args.erase)
        print(SUPPORT_MESSAGE)
        return
    if args.action == 'prepare-restore':
        if not args.session or not args.base or not args.bundle:
            parser.error('prepare-restore requires --session, --base and --bundle')
        from restore import prepare as prepare_restore
        prepare_restore(args.session,system_folder,relay,args.base,args.bundle)
        print('Prepared device-bound restoration: '+str(args.bundle))
    print('Host preparation completed; no device was restored.')


if __name__=='__main__':
    try:
        main()
    except (KeyboardInterrupt,EOFError):
        print('olsn0w: interrupted; inspect the session log before restarting a restoration.',file=sys.stderr)
        sys.exit(130)
    except (ValueError,RuntimeError,OSError,KeyError) as error:
        print('olsn0w: '+str(error),file=sys.stderr)
        sys.exit(1)
