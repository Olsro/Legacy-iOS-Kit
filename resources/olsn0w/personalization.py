"""Transfer the selected device's activation and modem files into prepared images."""
import hashlib
import io
import json
from pathlib import Path
import plistlib
import zipfile

from common import baseband_files, digest, version
from hfs import HFS
from system import entry, add_parents, PREPARABLE_MAJORS, uses_protected_data
from archives import write_tar, preserve_directory_metadata


def prepare(technical, target_version, destination, *, has_baseband=True,
            baseband_family='Mav5', include_modem=None, activate_on_target=False,
            omit_activation=False, data_seed=None):
    technical, destination = Path(technical), Path(destination)
    if destination.exists():
        raise ValueError('Preserve existing personalization output')
    if version(target_version)[0] not in PREPARABLE_MAJORS:
        raise ValueError('Activation destination needs a qualified version recipe')
    if type(has_baseband) is not bool:
        raise ValueError('Expected an explicit modem capability')
    if type(activate_on_target) is not bool or type(omit_activation) is not bool:
        raise ValueError('Expected an explicit activation policy')
    if activate_on_target and omit_activation:
        raise ValueError('Cannot activate a target while omitting activation')
    if include_modem is None:
        include_modem=has_baseband
    if type(include_modem) is not bool or (include_modem and not has_baseband):
        raise ValueError('Expected a compatible modem payload policy')
    if not isinstance(baseband_family,str) or not baseband_family.isalnum():
        raise ValueError('Expected a safe modem family')
    activation_path = technical/'activation-files.json'
    supplied_activation = json.loads(activation_path.read_text()) if activation_path.exists() else {}
    activation = {} if omit_activation else supplied_activation
    record_name = 'activation_record.plist' if has_baseband else 'pod_record.plist'
    required = ('mobile/Library/mad/activation_records/' + record_name,
                'mobile/Library/mad/data_ark.plist')
    if (not omit_activation and not (activate_on_target and not activation) and
            any(name not in activation or activation[name].get('unavailable') for name in required)):
        raise ValueError('Missing selected-device activation records')
    data_entries, missing = {}, []
    for name, report in activation.items():
        if report.get('unavailable'):
            missing.append(name);continue
        if name.startswith('mobile/Library/mad/'):
            dest='root/Library/Lockdown/'+name[len('mobile/Library/mad/'):]
            uid,gid=0,0
        elif name in ('mobile/Media/iTunes_Control/iTunes/IC-Info.sidv',
                      'mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv'):
            dest=name;uid=gid=501
        elif name=='wireless/Library/Preferences/com.apple.commcenter.plist':
            dest=name;uid=gid=25
        else:
            raise ValueError('Unrecognized activation artifact path')
        source=technical/'activation'/name
        if digest(source)!=report['sha256'] or source.stat().st_size!=report['bytes']:
            raise ValueError('Activation artifact checksum mismatch')
        content=source.read_bytes()
        if name.endswith('.plist'):plistlib.loads(content)
        data_entries[dest]=entry(dest,content,0o600,uid,gid)
    add_parents(data_entries)
    for name,(item,_) in data_entries.items():
        if item.isdir():
            if name.startswith('mobile'):item.uid=item.gid=501
            elif name.startswith('wireless'):item.uid=item.gid=25
            if name in ('root','root/Library/Lockdown'):item.mode=0o700
    retained_directories = (preserve_directory_metadata(data_entries, data_seed)
                            if data_seed is not None else [])
    modem=json.loads((technical/'modem-files.json').read_text())
    root_entries = {}
    if not include_modem and modem:
        reason=('a device without a baseband' if not has_baseband
                else 'a device whose baseband is preserved')
        raise ValueError('Modem artifacts supplied for '+reason)
    if include_modem:
        base='usr/local/standalone/firmware/Baseband/'+baseband_family+'/'
        expected=set(baseband_files(baseband_family))
        if set(modem)!={base+n for n in expected}:
            raise ValueError('Unqualified modem component set')
        packed=io.BytesIO()
        with zipfile.ZipFile(packed,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(modem):
                source=technical/name;report=modem[name]
                if digest(source)!=report['sha256'] or source.stat().st_size!=report['bytes']:
                    raise ValueError('Modem artifact checksum mismatch')
                content=source.read_bytes();root_entries[name]=entry(name,content)
                archive.writestr(name[len(base):],content)
        # iOS 5 loads the personalized archive from the older standalone
        # directory; the iOS 6+ Baseband/<family> location is not searched.
        archive_base=('usr/standalone/firmware/' if version(target_version)[0]==5
                      else base)
        archive_name=archive_base+baseband_family+'-personalized.zip'
        root_entries[archive_name]=entry(archive_name,packed.getvalue())
    add_parents(root_entries)
    destination.mkdir(parents=True)
    write_tar(destination/'data-personalization.tar',data_entries.values())
    if uses_protected_data(target_version):
        name = 'usr/local/share/olsn0w/data-personalization.tar'
        root_entries[name] = entry(name, (destination/'data-personalization.tar').read_bytes(), 0o600)
        add_parents(root_entries)
    write_tar(destination/'root-personalization.tar',root_entries.values())
    source=('activation-intentionally-omitted' if omit_activation else
            'selected-device-activated-8.4.1' if activation else 'fresh-signed-base')
    report=dict(source=source,
        activate_on_target=activate_on_target and not activation,target_version=target_version,has_baseband=has_baseband,
        activation_omitted=omit_activation,
        modem_payload_included=include_modem,
        data_seed_sha256=digest(data_seed) if data_seed is not None else None,
        preserved_data_directories=retained_directories,
        missing_optional_activation_files=missing,activation_on_target_verified=False,
        files={n:digest(destination/n) for n in ('data-personalization.tar','root-personalization.tar')})
    (destination/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
