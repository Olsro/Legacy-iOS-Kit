"""Reuse completed host preparation only while the device has not been erased."""
import json
from pathlib import Path

from common import STATE, hardware_model
from device import same_hardware
from restore import checked_manifest

PLAN_FIELDS = {'session', 'bundle', 'bootstrap', 'system', 'relay', 'ticket',
               'keys', 'baseband', 'baseband_manifest'}


def load_plan(path, identity, release, remove_setup_app, *, state=None):
    from bootchain import RECIPE_VERSION as RELAY_RECIPE
    from system import RECIPE_VERSION as SYSTEM_RECIPE
    from rescue_prepare import RECIPE_VERSION as RESCUE_RECIPE
    from restore_environment import selected_build
    from provision_run import restore_arguments

    path = Path(path)
    raw = json.loads(path.read_text())
    if set(raw) != PLAN_FIELDS:
        raise ValueError('Incomplete saved preparation plan')
    plan = {key: Path(value).resolve() if value is not None else None for key, value in raw.items()}
    root = Path(STATE if state is None else state).resolve()
    if any(value is not None and root not in value.parents for value in plan.values()):
        raise ValueError('Saved preparation path escaped the private working directory')
    session = path.parent.resolve()
    target = root / 'targets' / identity['product'] / release['buildid']
    expected = dict(session=session, bundle=session/'provision', bootstrap=session/'bootstrap',
                    relay=target/'relay', system=target/('system-hacktiv8-v1' if remove_setup_app else 'system'))
    if any(plan[key] != value for key, value in expected.items()):
        raise ValueError('Saved preparation belongs to another target or session')
    for key in ('ticket', 'keys', 'baseband', 'baseband_manifest'):
        value = plan[key]
        if value is None and key in ('baseband', 'baseband_manifest'):
            continue
        if value is None or session not in value.parents or not value.is_file():
            raise ValueError('Missing or misplaced saved ' + key)
    record = json.loads((session/'device.json').read_text())
    if (not same_hardware(record['identity'], identity) or record.get('device_modified') is not False
            or record.get('remove_setup_app', False) is not remove_setup_app):
        raise ValueError('Saved preparation identity or activation policy differs')
    bundle = plan['bundle']
    # work and run.json are created before the restore process can start.
    # Never retry a session that may already have changed internal storage.
    if any((bundle/name).exists() for name in ('run.json', 'work', 'target', 'restore.log')):
        raise ValueError('An earlier restore may have started; preserve its diagnostics')
    journal = bundle/'pipeline.json'
    if journal.exists():
        journal_state = json.loads(journal.read_text())
        if journal_state.get('stage') != 'signed-base' or journal_state.get('complete') is not False:
            raise ValueError('The saved restore advanced beyond pre-erase preparation')
    # Reject obsolete metadata before spending time hashing large images.
    manifests = [(plan[key], 'manifest.json') for key in ('relay', 'system', 'bootstrap', 'bundle')]
    manifests.append((session, 'rescue-preparation.json'))
    reports = [json.loads((folder/name).read_text()) for folder, name in manifests]
    relay, system, bootstrap, provision, rescue = reports
    if (relay.get('recipe_version') != RELAY_RECIPE or system.get('recipe_version') != SYSTEM_RECIPE
            or rescue.get('recipe_version') != RESCUE_RECIPE):
        raise ValueError('Saved preparation uses an older recipe')
    if any(report.get('product') != identity['product'] for report in (relay, system, bootstrap, provision, rescue)):
        raise ValueError('Saved components belong to another product')
    for report in (relay, system):
        if (report.get('version'), report.get('build')) != (release['version'], release['buildid']):
            raise ValueError('Saved target version differs')
    if (system.get('setup_customized') is not remove_setup_app
            or system.get('relay_recipe_version') != RELAY_RECIPE
            or system.get('relay_devicetree_sha256') != relay['files']['devicetree']
            or system.get('relay_binary_sha256') != relay['files']['relay.bin']):
        raise ValueError('Saved system inputs differ from the selected relay or activation policy')
    if (bootstrap.get('base_build') != '12H321' or bootstrap.get('autoboot_policy') != 'persistent-enable'
            or bootstrap.get('hardware_model') != hardware_model(identity['board'])
            or bootstrap.get('launchd_policy') != 'stock-signed'
            or bootstrap.get('target_rearm_required') is not False):
        raise ValueError('Saved bootstrap uses an older boot policy')
    if (not same_hardware(provision.get('identity', {}), identity)
            or provision.get('kind') != 'signed-base-restore-handoff'
            or Path(provision['rescue_session']).resolve() != session
            or rescue.get('automatic_disk_mounts') is not False
            or rescue.get('ram_root') != 'md0'
            or rescue.get('restore_environment_build') != selected_build(identity['product'], release['version'])):
        raise ValueError('Saved restore environment differs from the selected hardware')
    for (folder, name), report in zip(manifests, reports):
        if checked_manifest(folder, name) != report:
            raise ValueError('Saved preparation metadata changed during verification')
    restore_arguments(identity, bundle/'base8.ipsw', plan['ticket'], plan['baseband'], plan['baseband_manifest'])
    return plan


def find_plan(identity, release, remove_setup_app, show=print, *, state=None):
    state = Path(STATE if state is None else state)
    candidates = sorted((state/'sessions').glob('*/guided-plan.json'),
                        key=lambda path: path.stat().st_mtime_ns, reverse=True)
    for path in candidates:
        try:
            # Filter unrelated sessions before reading any large images.
            record = json.loads((path.parent/'device.json').read_text())
            if (not same_hardware(record['identity'], identity)
                    or record.get('remove_setup_app', False) is not remove_setup_app):
                continue
            raw = json.loads(path.read_text())
            system = json.loads((Path(raw['system'])/'manifest.json').read_text())
            if (system.get('version'), system.get('build')) != (release['version'], release['buildid']):
                continue
            show('Checking saved preparation: ' + str(path.parent))
            plan = load_plan(path, identity, release, remove_setup_app, state=state)
        except (OSError, ValueError, KeyError, TypeError) as error:
            show('Earlier preparation cannot be reused: ' + str(error))
            continue
        journal = plan['bundle']/'pipeline.json'
        if journal.exists():
            journal.replace(plan['bundle']/'pipeline-before-retry.json')
        show('Reusing the completed preparation. The five preparation steps will not be rebuilt.')
        return plan
    return None
