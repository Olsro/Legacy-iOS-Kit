"""Install a prepared, device-bound restore in one RAM rescue session.

The device's native tools format and check filesystems. Host code only edits
regular files; Linux and macOS use the same partition and image operations.
"""
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess

from archives import members
from common import MODELS, baseband_strategy, clone_or_copy, digest, profile, version
from hfs import HFS
from hfs_extents import allocated_ranges
from hfs_policy import require_reserve
from device import same_hardware
from layout import header, inspect, encode, editor_commands
from personalization import prepare as personalize
from system import uses_protected_data

BLOCK = 4096
CHUNK = 4096


def checkpoint(path, value):
    """Publish a durable stage record before each destructive operation."""
    path = Path(path)
    temporary = path.with_suffix('.pending')
    with temporary.open('w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


def checked_manifest(folder):
    folder = Path(folder)
    report = json.loads((folder/'manifest.json').read_text())
    for name, expected in report['files'].items():
        path = folder/name
        if Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink():
            raise ValueError('Invalid prepared component path')
        if digest(path) != expected:
            raise ValueError('Prepared component changed: '+name)
    return report


def prepare(session, system, relay, base, destination):
    """Reuse an attested compact base belonging to this same device.

    base/manifest.json binds the technical files and bootstrap to the ECID.
    A fresh device needs signed-base provisioning before this path is available.
    """
    session, system, relay, base, destination = map(Path, (session,system,relay,base,destination))
    identity = json.loads((session/'device.json').read_text())['identity']
    source, chain, provision = [checked_manifest(p) for p in (system,relay,base)]
    for key in ('product','version','build'):
        if source[key] != chain[key]:raise ValueError('Target system and relay differ')
    if source['product'] != identity['product'] or not same_hardware(provision['identity'],identity):
        raise ValueError('Signed base does not belong to the selected device')
    fresh = (provision.get('kind') == 'fresh-signed-base' and
             provision.get('signed_restore_verified') is True and
             provision.get('bootstrap_inputs_verified') is True)
    if not fresh and (not provision.get('activated_base_verified') or not provision.get('autonomous_boot_verified')):
        raise ValueError('Existing base must have verified activation and autonomous boot')
    from system import PREPARABLE_MAJORS
    if version(source['version'])[0] not in PREPARABLE_MAJORS:
        raise ValueError('Target needs a qualified first-boot filesystem recipe')
    from bootchain import RECIPE_VERSION
    if chain.get('recipe_version') != RECIPE_VERSION:
        raise ValueError('Regenerate the target relay with the current recipe')
    if destination.exists():raise ValueError('Preserve the previous restore bundle')
    setup_app_removed=source.get('setup_app_removed')
    if type(setup_app_removed) is not bool:
        raise ValueError('Target system lacks an explicit Setup.app policy')
    destination.mkdir(parents=True,mode=0o700)
    selected_profile=profile(source['product'])
    personalized=personalize(
        base/'technical',source['version'],destination/'personalization',
        has_baseband=selected_profile['has_baseband'],
        baseband_family=selected_profile.get('baseband_family','Mav5'),
        include_modem=baseband_strategy(source['product'])=='update',
        activate_on_target=fresh and not setup_app_removed,
        omit_activation=setup_app_removed)
    if (personalized.get('activation_omitted') is not setup_app_removed or
            personalized.get('activate_on_target') is not (fresh and not setup_app_removed)):
        raise ValueError('Personalization activation policy differs from the target system')
    for name, source_path in [('system.hfs',system/'system.hfs'),('root8.hfs',base/'root8.hfs'),
                              ('data8.hfs',base/'data8.hfs'),('data-seed.tar',system/'data-seed.tar')]:
        (clone_or_copy if name.endswith('.hfs') else shutil.copyfile)(source_path,destination/name)
    target=HFS(destination/'system.hfs')
    # Use the selected firmware's formatter, never a host-specific filesystem API.
    if version(source['version'])[0]==6:
        formatter=target.read('/sbin/newfs_hfs')
    else:
        formatter=target.read('/System/Library/Filesystems/hfs.fs/Contents/Resources/newfs_hfs')
    from image_capacity import reserve
    additions=list(members(destination/'personalization/root-personalization.tar'))
    capacity=reserve(target,additions,extra=(len(formatter),))
    checkpoint(destination/'capacity.json',capacity)
    target.command('untar',destination/'personalization/root-personalization.tar')
    for item,data in additions:
        if data is not None and target.read('/'+item.name)!=data:
            raise ValueError('Personalized system file readback differs: '+item.name)
    target.add('/olsn0w/restore-newfs',formatter,0o755)
    require_reserve(destination/'system.hfs',root=True)
    target.normalize_root()
    boot=HFS(destination/'root8.hfs')
    boot.replace_regular('/olsn0w/relay.bin',(relay/'relay.bin').read_bytes())
    boot.normalize_root()
    for name in ('root8.hfs','data8.hfs'):
        require_reserve(destination/name)
    for name in ('ssh_client_rsa','ssh_host_rsa_key.pub'):
        shutil.copyfile(system/name,destination/name)
        (destination/name).chmod(0o600)
    # The table is captured again in RAM before the erase. The saved table
    # binds its disk identity; it is never used as an unchecked write target.
    for name in ('gpt-primary.bin','gpt-secondary.bin'):
        shutil.copyfile(base/name,destination/name)
    old_a=(destination/'gpt-primary.bin').read_bytes();old_b=(destination/'gpt-secondary.bin').read_bytes()
    size=(destination/'system.hfs').stat().st_size
    new_a,new_b,layout=encode(old_a,old_b,size,source['version'])
    editor_commands(old_a,old_b,size,source['version'])
    (destination/'next-primary.bin').write_bytes(new_a);(destination/'next-secondary.bin').write_bytes(new_b)
    # Validate archive paths/types before any device operation.
    for name in ('data-seed.tar','personalization/data-personalization.tar'):
        list(members(destination/name))
    names=['capacity.json','system.hfs','root8.hfs','data8.hfs','data-seed.tar','personalization/data-personalization.tar',
           'gpt-primary.bin','gpt-secondary.bin','next-primary.bin','next-secondary.bin',
           'ssh_client_rsa','ssh_host_rsa_key.pub']
    report=dict(identity=identity,product=source['product'],version=source['version'],build=source['build'],
                generation=source['generation'],layout=layout,kind='install-fresh-base' if fresh else 'reinstall-provisioned-base',
                setup_app_removed=setup_app_removed,
                activation_mode=('skipped-setup-removed' if setup_app_removed else
                                 'official-on-target' if fresh else 'preserved-official-records'),
                files={n:digest(destination/n) for n in names},physical_boot_verified=False)
    checkpoint(destination/'manifest.json',report)
    return destination


class Rescue:
    """Authenticated RAM connection supplied by the selected-device loader."""
    def __init__(self, prefix, identity, maintenance='/olsn0w-maintenance'):
        if not isinstance(prefix,list) or not prefix or Path(prefix[0]).name!='ssh':
            raise ValueError('Expected an SSH argument vector')
        if prefix[-1]!='root@127.0.0.1' or 'StrictHostKeyChecking=yes' not in prefix:
            raise ValueError('RAM SSH must use a pinned local USB tunnel')
        if not re.fullmatch(r'/[a-zA-Z0-9_-]+',maintenance):raise ValueError('Invalid maintenance directory')
        board,chip,board_id=MODELS[identity['product']]
        if (identity['board'],identity['chip'],identity['board_id'])!=(board,chip,board_id):
            raise ValueError('Invalid selected hardware identity')
        self.prefix,self.identity,self.maintenance=prefix,identity,maintenance
    def run(self, command, data=None, timeout=180):
        result=subprocess.run(self.prefix+[command],input=data,capture_output=True,timeout=timeout)
        if result.returncode:
            raise RuntimeError('RAM command failed: '+command+'\n'+(result.stdout+result.stderr).decode(errors='replace')[-1800:])
        return result.stdout
    def tool(self,name):return self.maintenance+'/'+name
    def guard(self, mounted=()):
        state=self.run(self.tool('sysctl')+' hw.model kern.osversion').decode()
        if ('hw.model: '+self.identity['board'].upper()+'\n' not in state or 'kern.osversion: 12H321\n' not in state):
            raise ValueError('Wrong RAM system identity')
        mounts=self.run('/sbin/mount').decode().splitlines()
        if not any(x.startswith('/dev/md0 on / ') for x in mounts):raise ValueError('Root is not RAM')
        internal=[x.split(' (',1)[0] for x in mounts if re.match(r'/dev/r?disk',x)]
        if sorted(internal)!=sorted(mounted):raise ValueError('Unexpected mounted internal volumes: '+repr(internal))
    def read(self,device,first,count):
        if not re.fullmatch(r'/dev/rdisk0s1(?:s[1-4])?',device) or first<0 or count<=0:
            raise ValueError('Invalid partition read')
        blob=self.run(f'{self.tool("dd")} if={device} bs={BLOCK} skip={first} count={count} 2>/dev/null')
        if len(blob)!=count*BLOCK:raise RuntimeError('Short partition read')
        return blob
    def write(self,device,first,blob):
        if not re.fullmatch(r'/dev/rdisk0s1s[1-4]',device) or first<0 or not blob or len(blob)%BLOCK:
            raise ValueError('Invalid partition write')
        self.run(f'{self.tool("dd")} of={device} bs={BLOCK} seek={first} count={len(blob)//BLOCK} iflag=fullblock conv=notrunc,fsync 2>/dev/null',blob)
        if self.read(device,first,len(blob)//BLOCK)!=blob:raise RuntimeError('Partition readback mismatch')
    def table(self):
        first=self.read('/dev/rdisk0s1',0,6)
        hdr=header(first[BLOCK:2*BLOCK])
        last=self.read('/dev/rdisk0s1',hdr['other']-4,5)
        inspect(first,last)
        return first,last
    def fsck(self,device):
        command='/sbin/fsck_hfs'
        def execute(option):
            return subprocess.run(self.prefix+[command+' '+option+' '+device],capture_output=True,timeout=300)
        initial=execute('-fn');initial_output=initial.stdout+initial.stderr
        if initial.returncode==0 and b'appears to be OK' in initial_output:
            return initial_output
        repair=execute('-fy');repair_output=repair.stdout+repair.stderr
        verified=execute('-fn');verified_output=verified.stdout+verified.stderr
        if repair.returncode or verified.returncode or b'appears to be OK' not in verified_output:
            output=(initial_output+b'\n--- repair ---\n'+repair_output+b'\n--- verification ---\n'+verified_output)
            raise RuntimeError('Filesystem repair did not certify '+device+'\n'+output.decode(errors='replace')[-3000:])
        return initial_output+b'\n--- repaired ---\n'+repair_output+b'\n--- verification ---\n'+verified_output


def preview_matches(output, layout):
    fields=re.findall(r'Partition unique GUID: ([A-Fa-f0-9-]+).*?First sector: (\d+).*?Last sector: (\d+).*?Attribute flags: ([A-Fa-f0-9]+)',output,re.S)
    expected=[(p['guid'].upper(),str(p['first']),str(p['last']),format(p['attributes'],'016X')) for p in layout['partitions']]
    if [(g.upper(),a,b,c.upper()) for g,a,b,c in fields]!=expected or 'No problems found.' not in output:
        raise ValueError('Native partition editor disagrees with planned layout')


def refresh_layout(bundle, ram):
    """Bind preparation to the current table without another DFU cycle.

    Capacity, disk identity and signed-base identity must still match the
    provisioned base. Only recognized stock/olsn0w geometries are accepted.
    The installer independently verifies this new snapshot before committing.
    """
    bundle=Path(bundle);report=checked_manifest(bundle)
    if not same_hardware(report['identity'],ram.identity) or (bundle/'installation.json').exists():
        raise ValueError('Cannot refresh an unrelated or already started restore')
    previous=inspect((bundle/'gpt-primary.bin').read_bytes(),(bundle/'gpt-secondary.bin').read_bytes())
    ram.guard();a,b=ram.table();current=inspect(a,b)
    for key in ('guid','first','last','other'):
        if previous[0][key]!=current[0][key]:raise ValueError('Provisioned disk identity or capacity changed')
    if previous[1][0]['guid']!=current[1][0]['guid']:
        raise ValueError('Signed base partition identity changed')
    size=(bundle/'system.hfs').stat().st_size
    editor_commands(a,b,size,report['version'])
    next_a,next_b,layout=encode(a,b,size,report['version'])
    for name,blob in [('gpt-primary.bin',a),('gpt-secondary.bin',b),
                      ('next-primary.bin',next_a),('next-secondary.bin',next_b)]:
        (bundle/name).write_bytes(blob);report['files'][name]=digest(bundle/name)
    report['layout']=layout
    checkpoint(bundle/'manifest.json',report)


def copy_image(ram, path, device, *, sparse=False, progress=print, label='Image'):
    size=Path(path).stat().st_size
    if size%BLOCK:raise ValueError('Unaligned image')
    spans=list(allocated_ranges(path)) if sparse else [(0,size//BLOCK)]
    total=sum(count for _,count in spans)*BLOCK
    done=0;last_percent=-1
    with Path(path).open('rb') as stream:
        for first,count in spans:
            while count:
                n=min(count,CHUNK);stream.seek(first*BLOCK);blob=stream.read(n*BLOCK)
                if len(blob)!=n*BLOCK:raise ValueError('Short image read')
                ram.write(device,first,blob)
                first+=n;count-=n
                done+=n*BLOCK;percent=done*100//total
                if percent//5>last_percent//5 or done==total:
                    progress(f'{label}: {percent}% — {done/1048576:.1f}/{total/1048576:.1f} MiB written and read back.')
                    last_percent=percent


def _finish_install(bundle,ram,report,layout,expected,state,roles,progress):
    journal=bundle/'installation.json'
    messages={
        'writing-system':'Installing iOS '+report['version']+'. The phone bar may remain unchanged; follow the progress below.',
        'writing-bootstrap':'Installing the 30 MiB boot system.',
        'writing-bootstrap-data':'Installing the 2 MiB boot data volume.',
        'formatting-data':'Preparing the user data filesystem and its initial files.',
        'writing-data':'Writing initial user data. The total below counts transferred blocks, not the full storage capacity.',
        'installed-and-verified':'Installation complete: every volume has passed readback and filesystem checks.',
    }
    def stage(value):
        state['stage']=value;state.pop('error',None);checkpoint(journal,state);progress(messages.get(value,value))
    for role,name in roles:
        part=next(p for p in layout['partitions'] if p['role']==role)
        if (bundle/name).stat().st_size!=part['bytes']:raise ValueError('Image does not fill planned partition')
        dev=part['device'].replace('/dev/disk','/dev/rdisk')
        # Verify that the native child mapping has the exact new endpoint.
        probe=ram.run(f'{ram.tool("dd")} if={dev} bs=4096 skip={part["bytes"]//4096} count=1 2>/dev/null')
        if probe:raise RuntimeError('Stale child partition endpoint')
        stage('writing-'+role);copy_image(ram,bundle/name,dev,progress=progress,label={'system':'iOS '+report['version'],'bootstrap':'Boot system','bootstrap-data':'Boot data'}[role])
        if ram.read('/dev/rdisk0s1',part['first'],1)!=ram.read(dev,0,1):raise RuntimeError('Parent/child mapping differs')
        (bundle/(role+'-fsck.log')).write_bytes(ram.fsck(dev));state['verified_volumes'].append(role);checkpoint(journal,state)
    stage('formatting-data')
    ram.run(ram.tool('mount_hfs')+' /dev/disk0s1s3 /mnt1')
    ram.guard(['/dev/disk0s1s3 on /mnt1'])
    protect=uses_protected_data(report['version'])
    options=' -P -n a=4096,c=4096,e=4096' if protect else ''
    (bundle/'data-format.log').write_bytes(ram.run('/mnt1/olsn0w/restore-newfs -s -J'+options+' -v Data -b 4096 /dev/rdisk0s1s2'))
    state['formatted_data']=True;checkpoint(journal,state)
    ram.run('rm /mnt1/olsn0w/restore-newfs')
    ram.run(ram.tool('unmount')+' /mnt1');ram.guard()
    part=next(p for p in layout['partitions'] if p['role']=='data')
    path=bundle/'data-native.hfs'
    read_fresh_image(ram,'/dev/rdisk0s1s2',path,part['bytes'])
    image=HFS(path)
    if protect:image.initialize_protection_v4()
    image.command('untar',bundle/'data-seed.tar')
    if not protect:image.command('untar',bundle/'personalization/data-personalization.tar')
    image.normalize_root()
    stage('writing-data');copy_image(ram,path,'/dev/rdisk0s1s2',sparse=True,progress=progress,label='Initial user data')
    for role,dev in [('data','/dev/rdisk0s1s2'),('system','/dev/rdisk0s1s3')]:
        (bundle/(role+'-final-fsck.log')).write_bytes(ram.fsck(dev))
    state['verified_volumes'].append('data')
    ram.guard()
    if ram.table()!=expected:raise RuntimeError('Final partition table differs')
    state['complete']=True;stage('installed-and-verified')
    return state


def read_fresh_image(ram, device, path, expected_bytes):
    """Copy only allocated native-format blocks into a sparse host file."""
    first=ram.read(device,0,1)
    if first[1024:1026]!=b'HX':raise ValueError('Native formatter did not create HFSX')
    block,total=struct.unpack_from('>II',first,1024+40)
    if block!=BLOCK or total*block!=expected_bytes:raise ValueError('Formatted geometry differs')
    with Path(path).open('xb') as stream:stream.truncate(expected_bytes)
    with Path(path).open('r+b') as stream:
        stream.write(first)
        # The fresh allocation bitmap has no overflow extents.
        for i in range(8):
            start,count=struct.unpack_from('>II',first,1024+128+i*8)
            if not count:continue
            if start+count>total:raise ValueError('Bitmap extent outside partition')
            while count:
                n=min(count,CHUNK);stream.seek(start*BLOCK);stream.write(ram.read(device,start,n));start+=n;count-=n
        for start,count in allocated_ranges(path):
            while count:
                n=min(count,CHUNK);stream.seek(start*BLOCK);stream.write(ram.read(device,start,n));start+=n;count-=n


def install(bundle, ram, *, erase=False, progress=print):
    bundle=Path(bundle);report=checked_manifest(bundle)
    if not erase:raise ValueError('Restoration requires explicit erase authorization')
    if not same_hardware(report['identity'],ram.identity):raise ValueError('Restore bundle belongs to another device')
    journal=bundle/'installation.json'
    if journal.exists():raise ValueError('Previous install exists; inspect its stage before retrying')
    # Reject cached bundles with the old non-root reserve before touching USB.
    require_reserve(bundle/'system.hfs',root=True)
    if type(report.get('setup_app_removed')) is not bool:
        raise ValueError('Restore bundle lacks an explicit Setup.app policy')
    if ((report.get('activation_mode')=='skipped-setup-removed') is not
            report['setup_app_removed']):
        raise ValueError('Restore activation and Setup.app policies differ')
    setup_present=any(item['name']=='Setup.app'
                      for item in HFS(bundle/'system.hfs').ls('/Applications'))
    if setup_present == report['setup_app_removed']:
        raise ValueError('Restore Setup.app state differs from its manifest')
    old=(bundle/'gpt-primary.bin').read_bytes(),(bundle/'gpt-secondary.bin').read_bytes()
    expected=(bundle/'next-primary.bin').read_bytes(),(bundle/'next-secondary.bin').read_bytes()
    new_a,new_b,layout=encode(*old,(bundle/'system.hfs').stat().st_size,report['version'])
    if expected!=(new_a,new_b) or layout!=report['layout']:raise ValueError('Restore layout changed')
    for role,name in [('system','system.hfs'),('bootstrap','root8.hfs'),('bootstrap-data','data8.hfs')]:
        part=next(p for p in layout['partitions'] if p['role']==role)
        if (bundle/name).stat().st_size!=part['bytes']:
            raise ValueError('Image does not fill planned partition')
        HFS(bundle/name)
    for name in ('data-seed.tar','personalization/data-personalization.tar'):
        list(members(bundle/name))
    if report['generation'] not in HFS(bundle/'system.hfs').read('/usr/local/libexec/olsn0w/target.conf').decode():
        raise ValueError('System and Data generation differ')
    ram.guard()
    if ram.table()!=old:raise ValueError('Partition table changed since preparation')
    size=(bundle/'system.hfs').stat().st_size
    preview=ram.run(ram.tool('gptfdisk')+' /dev/rdisk0s1',editor_commands(*old,size,report['version']))
    (bundle/'gpt-preview.log').write_bytes(preview);preview_matches(preview.decode(),layout)
    ram.guard()
    if ram.table()!=old:raise ValueError('Preview changed the device')
    state=dict(stage='preflight-complete',complete=False,formatted_data=False,verified_volumes=[])
    def stage(value):
        state['stage']=value;checkpoint(journal,state)
        progress('Step 2: preparing partitions for the selected system and the 32 MiB bootstrap.' if value=='committing-partitions' else value)
    try:
        stage('committing-partitions')
        (bundle/'gpt-commit.log').write_bytes(ram.run(ram.tool('gptfdisk')+' /dev/rdisk0s1',editor_commands(*old,size,report['version'],True)))
        ram.guard()
        if ram.table()!=expected:raise RuntimeError('Native partition commit differs')
        _finish_install(bundle,ram,report,layout,expected,state,
                        [('system','system.hfs'),('bootstrap','root8.hfs'),('bootstrap-data','data8.hfs')],progress)
    except Exception as error:
        state['error']=str(error);checkpoint(journal,state);raise
    return state


def resume_system_fsck(bundle,ram,progress=print):
    """Resume the one safe interrupted state after repairing the written root."""
    bundle=Path(bundle);report=checked_manifest(bundle);journal=bundle/'installation.json'
    if not same_hardware(report['identity'],ram.identity):raise ValueError('Restore bundle belongs to another device')
    state=json.loads(journal.read_text())
    error=state.get('error','')
    if (state.get('stage')!='writing-system' or state.get('complete') is not False
            or state.get('formatted_data') is not False or state.get('verified_volumes')!=[]
            or '/sbin/fsck_hfs -fn /dev/rdisk0s1s3' not in error
            or 'found corrupt and needs to be repaired' not in error):
        raise ValueError('Restore is not at the qualified system-fsck recovery point')
    expected=(bundle/'next-primary.bin').read_bytes(),(bundle/'next-secondary.bin').read_bytes()
    layout=report['layout'];ram.guard()
    if ram.table()!=expected:raise ValueError('Interrupted restore partition table changed')
    part=next(p for p in layout['partitions'] if p['role']=='system')
    if ram.read('/dev/rdisk0s1',part['first'],1)!=ram.read('/dev/rdisk0s1s3',0,1):
        raise RuntimeError('Interrupted system parent/child mapping differs')
    progress('Repairing and verifying the prepared iOS filesystem metadata.')
    try:
        (bundle/'system-fsck.log').write_bytes(ram.fsck('/dev/rdisk0s1s3'))
        state['verified_volumes'].append('system');state.pop('error',None);checkpoint(journal,state)
        return _finish_install(bundle,ram,report,layout,expected,state,
                               [('bootstrap','root8.hfs'),('bootstrap-data','data8.hfs')],progress)
    except Exception as error:
        state['error']=str(error);checkpoint(journal,state);raise
