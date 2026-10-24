"""Assemble the compact bootstrap from firmware and Kit inputs on regular images."""
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import stat
import struct
import tarfile

from archives import members, write_tar
from bootstrap_registry import configure, jobs
from compact_cache import write_sparse
from common import KIT, digest, profile, run, tools
from hfs import HFS
from img3 import img3
from signing import resign, verify
from system import entry, add_parents, jetsam_properties_path

STOCK_FILES = '''bin/launchctl sbin/fsck sbin/launchd sbin/mount
private/etc/group private/etc/master.passwd usr/lib/dyld usr/libexec/amfid
usr/libexec/cc_fips_test usr/libexec/tzinit usr/libexec/xpcproxy usr/sbin/notifyd
System/Library/AppleUSBDevice/USBDeviceConfiguration.plist
System/Library/CoreServices/SystemVersion.plist
System/Library/CoreServices/powerd.bundle/powerd
System/Library/Filesystems/hfs.fs/Contents/Resources/fsck_hfs
System/Library/Filesystems/hfs.fs/Contents/Resources/mount_hfs
usr/share/zoneinfo.default/+VERSION usr/share/zoneinfo.default/UTC
usr/share/zoneinfo.default/posixrules usr/share/zoneinfo.default/Etc/UTC'''.split()


def binary_launchd_bootstrap(original):
    """Replace launchd's embedded XML bootstrap plist without moving sections."""
    data = bytearray(original)
    if len(data) < 28 or data[:4] != b'\xce\xfa\xed\xfe':
        raise ValueError('Expected a thin 32-bit launchd executable')
    commands, command_bytes = struct.unpack_from('<II', data, 16)
    if command_bytes > len(data)-28 or commands > command_bytes//8:
        raise ValueError('Invalid launchd load commands')
    found = []
    at = 28
    for _ in range(commands):
        command, length = struct.unpack_from('<II', data, at)
        if length < 8 or at+length > 28+command_bytes:
            raise ValueError('Invalid launchd load command')
        if command == 1:
            if length < 56:
                raise ValueError('Truncated launchd segment')
            sections, = struct.unpack_from('<I', data, at+48)
            if length != 56+68*sections:
                raise ValueError('Invalid launchd section table')
            for section in range(sections):
                position = at+56+section*68
                name = data[position:position+16].rstrip(b'\0')
                segment = data[position+16:position+32].rstrip(b'\0')
                if (name, segment) == (b'__bs_plist', b'__TEXT'):
                    found.append(position)
        at += length
    if len(found) != 1:
        raise ValueError('Expected one launchd bootstrap plist section')
    section = found[0]
    size, offset = struct.unpack_from('<II', data, section+36)
    if not size or offset+size > len(data):
        raise ValueError('Invalid launchd bootstrap plist section')
    source = bytes(data[offset:offset+size])
    if not source.startswith(b'<?xml'):
        raise ValueError('Expected an XML launchd bootstrap plist')
    values = plistlib.loads(source)
    if not isinstance(values, dict) or not {'Boot','Bootstrap'} <= set(values):
        raise ValueError('Unexpected launchd bootstrap plist')
    binary = plistlib.dumps(values, fmt=plistlib.FMT_BINARY, sort_keys=False)
    if len(binary) >= size or plistlib.loads(binary) != values:
        raise ValueError('Launchd bootstrap plist conversion failed')
    data[offset:offset+size] = binary + bytes(size-len(binary))
    struct.pack_into('<I', data, section+36, len(binary))
    return bytes(data)


def held_untether(original, output):
    if hashlib.sha256(original).hexdigest() != '7f602f8e8e96fd6cbe2d313187ccade85de253ab1db21696ba7402c12ef8495c':
        raise ValueError('Unqualified Kit untether binary')
    data = bytearray(original)
    edits = [(0x9c84,'b0b5','7047'), (0xac18,'f0b5','10b53c2003f0c2eefbe7'),
             (0xae1c,'80b5','7047'), (0xaf5c,'03f002ed','00bf00bf'),
             (0xd81c,'01f082e8','022000bf')]
    for address, before, after in edits:
        offset = address-0x4000
        before, after = bytes.fromhex(before), bytes.fromhex(after)
        if data[offset:offset+len(before)] != before:
            raise ValueError('Untether instruction precondition failed')
        data[offset:offset+len(after)] = after
    output.write_bytes(data)
    resign(output, verify(original)['entitlements'])
    return output.read_bytes()


def prepare(product, firmware, loose_libraries, native, relay_file, kernel_file,
            compact_cache, root_template, var_template, destination):
    """Inputs are already selected/verified by the caller; no device I/O occurs."""
    architecture=profile(product)['cache_arch']
    firmware, native, destination = map(Path, (firmware, native, destination))
    if destination.exists():
        raise ValueError('Preserve existing bootstrap output')
    destination.mkdir(parents=True)
    stock = HFS(firmware/'rootfs.hfs')
    version = plistlib.loads(stock.read('/System/Library/CoreServices/SystemVersion.plist'))
    if version['ProductBuildVersion'] != '12H321' or version['ProductVersion'] != '8.4.1':
        raise ValueError('Unqualified bootstrap firmware')
    payload = {}
    paths = STOCK_FILES+[jetsam_properties_path(stock,product).lstrip('/')]
    for name in paths:
        parent, leaf = name.rsplit('/',1)
        record = next((r for r in stock.ls('/'+parent) if r['name'] == leaf), None)
        if record is None:
            raise ValueError('Missing stock bootstrap file for '+product+': /'+name)
        if not stat.S_ISREG(record['mode']):
            raise ValueError('Expected a stock regular file: '+name)
        data = stock.read('/'+name)
        # launchd must retain its Apple signature before the bootstrap untether
        # can run. Rehashing its embedded plist strands a normal ARMv7s boot;
        # USB boots with AMFI disabled can hide that failure.
        if name == 'System/Library/CoreServices/SystemVersion.plist':
            data = plistlib.dumps(plistlib.loads(data),fmt=plistlib.FMT_BINARY,sort_keys=False)
        payload[name] = entry(name, data, stat.S_IMODE(record['mode']))
    selected_packages = {
        'resources/jailbreak/freeze.tar.gz': ['bin/bash','usr/lib/libhistory.6.0.dylib','usr/lib/libreadline.6.0.dylib'],
        'resources/sshrd/ssh.tar.gz': ['bin/chmod','sbin/sshd','usr/lib/libcrypto.0.9.8.dylib','usr/lib/libiconv.2.dylib','usr/lib/libncurses.5.dylib'],
        'resources/jailbreak/everuntether.tar': ['everuntether','usr/libexec/dirhelper'],
    }
    provenance = {}
    for package, wanted in selected_packages.items():
        source = KIT/package
        found = {item.name: (item,data) for item,data in members(source) if item.name in wanted and item.isfile()}
        if set(found) != set(wanted):
            raise ValueError('Missing Kit bootstrap payload')
        provenance[package] = digest(source)
        for name,(item,data) in found.items():
            payload[name] = entry(name,data,0o755)
    # The rescue library is extracted from the selected stock restore ramdisk.
    for name in ('usr/lib/libutil.dylib',):
        source = Path(loose_libraries)/name
        if source.is_symlink() or not source.is_file():
            raise ValueError('Expected a regular stock rescue library')
        payload[name] = entry(name,source.read_bytes(),0o755)
    sshd = destination/'sshd'
    sshd.write_bytes(payload['sbin/sshd'][1])
    ent = verify(sshd.read_bytes())['entitlements']
    ent.update({'platform-application':True,'com.apple.private.skip-library-validation':True})
    resign(sshd,ent)
    payload['sbin/sshd'] = entry('sbin/sshd',sshd.read_bytes(),0o755)
    payload['olsn0w/untether-held'] = entry('olsn0w/untether-held',held_untether(payload['everuntether'][1],destination/'untether-held'),0o755)
    mapping = {'controller':'controller','root-start':'root_start','held-control':'untether_supervisor',
               'service-gate':'service_gate',
               'bootstrap_pm_ready':'power_ready','bootstrap_wake':'wake'}
    if architecture == 'armv7':
        mapping['bootstrap_wake']='wake_a5'
    for name,source in mapping.items():
        data = (native/source).read_bytes();verify(data)
        payload['olsn0w/'+name] = entry('olsn0w/'+name,data,0o755)
    if architecture == 'armv7':
        from a5_loader import payload as loader_payload, WRAPPER, relay_images
        images=relay_images(product,Path(relay_file).parent)
        payload['usr/local/bin/kloader']=entry('usr/local/bin/kloader',WRAPPER,0o755)
        payload['usr/local/bin/4smulti_kloader']=entry('usr/local/bin/4smulti_kloader',loader_payload(),0o755)
        for name,data in images.items():
            payload['olsn0w/'+name]=entry('olsn0w/'+name,data,0o600)
    else:
        kloader = KIT/'resources/kloader/kloader'
        if digest(kloader) != 'bec212b4d99a1e3b9fa4add663fa884a2435045d1e47051415f4e26e197f8132':
            raise ValueError('Unqualified kloader binary')
        payload['usr/local/bin/kloader'] = entry('usr/local/bin/kloader',kloader.read_bytes(),0o755)
        payload['olsn0w/relay.bin'] = entry('olsn0w/relay.bin',Path(relay_file).read_bytes(),0o600)
    kernel = Path(kernel_file).read_bytes()
    kernel_kind, kernel_tags, _ = img3(kernel)
    # A5/A5R2 reaches this filesystem through Apple's ordinary signed iBoot.
    # It must therefore receive the encrypted stock IMG3, whose KBAG iBoot can
    # unwrap on the device.  The host-repacked plaintext IMG3 is appropriate
    # only after our admitted relay is running; stock A5 iBoot rejects it as an
    # invalid kernelcache before the bootstrap kernel can start.
    a5_boot = profile(product)['soc'].startswith('a5')
    if kernel_kind != 'krnl' or (('KBAG' in kernel_tags) is not a5_boot):
        raise ValueError('Bootstrap kernel container differs from the selected boot policy')
    payload['System/Library/Caches/com.apple.kernelcaches/kernelcache'] = entry(
        'System/Library/Caches/com.apple.kernelcaches/kernelcache',kernel)
    tree = destination/'DeviceTree8.img3'
    run([tools()/'xpwntool',firmware/'DeviceTree.raw',tree,'-t',firmware/'DeviceTree.orig'])
    if img3(tree.read_bytes())[2] != (firmware/'DeviceTree.raw').read_bytes():
        raise ValueError('Bootstrap DeviceTree packing failed')
    payload['boot/DeviceTree8.img3'] = entry('boot/DeviceTree8.img3',tree.read_bytes())
    for name,value in [('bootstrap.marker',b'olsn0w-bootstrap-v1'),('autoboot.enabled',b'olsn0w-target-v1')]:
        payload['olsn0w/'+name] = entry('olsn0w/'+name,value,0o600)
    fstab = b'/dev/disk0s1s1 / hfs ro 0 1\n/dev/disk0s1s4 /private/var hfs rw,nosuid,nodev 0 2\n'
    payload['private/etc/fstab'] = entry('private/etc/fstab',fstab)
    for name in ('ssh_client_rsa','ssh_host_rsa_key'):
        run(['ssh-keygen','-q','-t','rsa','-b','2048','-m','PEM','-N','','-f',destination/name])
    payload['olsn0w/authorized_keys'] = entry('olsn0w/authorized_keys',(destination/'ssh_client_rsa.pub').read_bytes(),0o600)
    payload['olsn0w/ssh_host_rsa_key'] = entry('olsn0w/ssh_host_rsa_key',(destination/'ssh_host_rsa_key').read_bytes(),0o600)
    config = '''Protocol 2
Port 22
ListenAddress 127.0.0.1
HostKey /olsn0w/ssh_host_rsa_key
AuthorizedKeysFile /olsn0w/authorized_keys
PidFile /var/run/olsn0w-sshd.pid
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePrivilegeSeparation no
'''
    if architecture == 'armv7':config+='UseDNS no\n'
    payload['olsn0w/sshd_config'] = entry('olsn0w/sshd_config',config.encode(),0o600)
    delayed_services = [plistlib.loads(stock.read('/System/Library/LaunchDaemons/'+name))
                        for name in ('com.apple.notifyd.plist','com.apple.powerd.plist')]
    launch_jobs = jobs(
        plistlib.loads(stock.read('/System/Library/LaunchDaemons/com.apple.MobileFileIntegrity.plist')),
        delayed_services)
    for path, job in launch_jobs.items():
        payload[path[1:]] = entry(path[1:],plistlib.dumps(job,fmt=plistlib.FMT_BINARY))
    cache = Path(compact_cache).read_bytes()
    if architecture == 'armv7s':
        recipe = json.loads((Path(__file__).parent/'recipes/dyld-armv7s-12H321.recipe').read_text())
        expected=recipe['output_sha256'];region=recipe['registry']
    else:
        from compact_cache import qualified_source
        source=qualified_source(architecture)
        expected=source['prepared_sha256'];region=source['registry']
    if hashlib.sha256(cache).hexdigest() != expected:
        raise ValueError('Bootstrap cache differs from qualified output')
    configured = configure(cache,region['address'],region['bytes'],launch_jobs)
    cache_path=destination/'bootstrap.cache';write_sparse(configured,cache_path)
    for name,target in {'etc':'private/etc','var':'private/var','tmp':'private/var/tmp','bin/sh':'bash',
        'sbin/fsck_hfs':'/System/Library/Filesystems/hfs.fs/Contents/Resources/fsck_hfs',
        'usr/libexec/CrashHousekeeping':'/everuntether','usr/share/zoneinfo':'/var/db/timezone/zoneinfo'}.items():
        item=tarfile.TarInfo(name);item.type=tarfile.SYMTYPE;item.linkname=target;item.mode=0o644
        payload[name]=(item,None)
    for name in ('dev','private/var','Library/LaunchDaemons','Library/NanoLaunchDaemons',
                 'Library/Preferences/SystemConfiguration','System/Library/Caches/com.apple.dyld'):
        payload[name]=entry(name,mode=0o755,directory=True)
    add_parents(payload)
    for name in ('olsn0w',):payload[name]=entry(name,mode=0o700,directory=True)
    archive=destination/'bootstrap.tar';write_tar(archive,payload.values())
    root=destination/'root8.hfs';shutil.copyfile(root_template,root)
    image=HFS(root);image.command('untar',archive)
    image.command('chmod','040755','/');image.command('chown','0:0','/')
    image.add_compressed('/System/Library/Caches/com.apple.dyld/dyld_shared_cache_'+architecture,cache_path)
    cache_path.unlink()
    var=destination/'data8.hfs';shutil.copyfile(var_template,var)
    var_image=HFS(var)
    for name in ('db','db/FIPS','db/timezone','db/timezone/tz','empty','log','mobile','mobile/Library','mobile/Library/Preferences','root','run','tmp'):
        var_image.mkdir('/'+name)
    var_image.command('chmod','1777','/tmp');var_image.command('chmod','0700','/root')
    var_image.command('chown','501:501','/mobile')
    var_image.command('symlink','/db/timezone/zoneinfo','/usr/share/zoneinfo.default')
    var_image.command('symlink','/db/timezone/localtime','/usr/share/zoneinfo.default/UTC')
    image.normalize_root();var_image.normalize_root()
    if image.info()['bytes']!=30*1024**2 or var_image.info()['bytes']!=2*1024**2:
        raise ValueError('Compact bootstrap must remain 30 MiB System + 2 MiB Data')
    records = {record['path']: record for record in image.tree('/')}
    for path,(item,data) in payload.items():
        if item.isfile() and image.read('/'+path)!=data:
            raise ValueError('Bootstrap readback mismatch: '+path)
        if not item.isdir():
            record = records['/'+path]
            if (stat.S_IMODE(record['mode']), record['uid'], record['gid']) != (item.mode, item.uid, item.gid):
                raise ValueError('Bootstrap permissions readback mismatch: '+path)
    report=dict(product=product,base_build='12H321',cache_architecture=architecture,
        relay_policy=('a5-two-image-relative-wake' if a5_boot else 'a6-contiguous'),
        kernel_policy=('stock-encrypted-a5' if a5_boot else 'relay-admitted-plaintext'),
        kernel_sha256=hashlib.sha256(kernel).hexdigest(),
        autoboot_policy='persistent-enable',launchd_policy='stock-signed',
        target_rearm_required=False,source_packages=provenance,root=image.info(),var=var_image.info(),
        files={p.name:digest(p) for p in (root,var,archive)},physical_boot_verified=False)
    (destination/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
