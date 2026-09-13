"""Prepare target filesystems using firmware identities and existing kit payloads."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import shlex
import stat
import tarfile
import tempfile
import uuid

from archives import members, deb_payload, write_tar
from aquila import (ios7_payload, job_loader, prepare_payload,
                    prepare_ios6_payload, prepare_ios8_payload,
                    prepare_pangu71_payload)
from common import KIT, MODELS, clone_or_copy, digest, profile, run, save, version
from hfs import HFS
from img3 import img3
from signing import resign, verify

PACKAGE_ROOT = KIT / 'resources/jailbreak'
TARGET_SCRIPTS = Path(__file__).parent / 'target'
RECIPE_VERSION = 30

CYDIA_DEFAULT_SOURCES = (
    b'deb http://apt.saurik.com/ ios/847.27 main\n'
    b'deb http://repo666.ultrasn0w.com/ ./\n'
    b'deb http://apt.thebigboss.org/repofiles/cydia/ stable main\n'
    b'deb http://modmyi.saurik.com/ stable main\n'
    b'deb http://zodttd.saurik.com/repo/cydia/ stable main\n'
)


def uses_protected_data(release):
    """Return whether this recipe needs native HFS content protection."""
    # iOS 6's stock fstab mounts Data without the `protect` option. Applying
    # the iOS 7/8 protected-volume bootstrap to 6.1.3 makes the A6/A6X kernel
    # stall while Aquila is restarting services. Keep the firmware's proven
    # unprotected Data contract on iOS 6.
    return version(release)[0] in (7, 8)


def uses_protected_keybag_start(release):
    """These releases seed protected Data from the native keybag job."""
    return version(release)[0] in (7, 8)


def relocate_fstab(content, root_device, data_device, *, protect_data=False):
    """Change partition paths while retaining the selected firmware's mount policy."""
    devices = {'/': root_device, '/private/var': data_device}
    if len(set(devices.values())) != 2 or any(
            not re.fullmatch(r'/dev/disk\d+(?:s\d+)+', value) for value in devices.values()):
        raise ValueError('Invalid target partition devices')
    seen, lines = set(), []
    for line in content.decode('ascii').splitlines():
        fields = line.split()
        if fields and not fields[0].startswith('#'):
            if len(fields) < 6:
                raise ValueError('Malformed stock fstab entry')
            mountpoint = fields[1]
            if mountpoint in devices:
                if mountpoint in seen or fields[2] != 'hfs':
                    raise ValueError('Ambiguous stock target mount')
                seen.add(mountpoint)
                fields[0] = devices[mountpoint]
                if mountpoint == '/private/var' and protect_data:
                    options = fields[3].split(',')
                    if 'noprotect' in options:
                        raise ValueError('Conflicting Data protection mount policy')
                    if 'protect' not in options:
                        options.append('protect')
                    fields[3] = ','.join(options)
                line = ' '.join(fields)
        lines.append(line)
    if seen != set(devices):
        raise ValueError('Stock fstab lacks root or Data mount')
    return ('\n'.join(lines)+'\n').encode('ascii')


def entry(name, data=None, mode=0o644, uid=0, gid=0, directory=False):
    item = tarfile.TarInfo(name)
    item.mode, item.uid, item.gid = mode, uid, gid
    if directory:
        item.type = tarfile.DIRTYPE
    else:
        item.size = len(data)
    return item, data


def symlink_entry(name, target, uid=0, gid=0):
    item = tarfile.TarInfo(name)
    item.type, item.linkname = tarfile.SYMTYPE, target
    item.mode, item.uid, item.gid = 0o777, uid, gid
    return item, None


def data_backed_cydia_sources(entries):
    """Replace Cydia's empty package file at its canonical HFS path."""
    name = 'private/etc/apt/sources.list.d/cydia.list'
    try:
        item, data = entries[name]
    except KeyError as error:
        raise ValueError('Cydia source placeholder is missing') from error
    if not item.isfile() or data != b'':
        raise ValueError('Unrecognized Cydia source placeholder')
    entries[name] = symlink_entry(
        name, '/var/mobile/Library/Caches/com.saurik.Cydia/sources.list',
        item.uid, item.gid)


def seed_cydia_source_cache(entries):
    """Create Cydia's mobile-owned source target instead of trusting its UI cache."""
    mobile=entries.get('mobile')
    if mobile is None or not mobile[0].isdir():
        raise ValueError('Stock Data seed is missing the mobile directory')
    uid,gid=mobile[0].uid,mobile[0].gid
    directory='mobile/Library/Caches/com.saurik.Cydia'
    entries[directory]=entry(directory,mode=0o755,uid=uid,gid=gid,directory=True)
    name=directory+'/sources.list'
    entries[name]=entry(name,CYDIA_DEFAULT_SOURCES,0o644,uid,gid)


def seed_data(image):
    result = {}
    for record in image.tree('/private/var'):
        name = record['path'][len('/private/var/'):]
        mode = record['mode']
        item = tarfile.TarInfo(name)
        item.mode, item.uid, item.gid = stat.S_IMODE(mode), record['uid'], record['gid']
        data = None
        if stat.S_ISDIR(mode):
            item.type = tarfile.DIRTYPE
        elif stat.S_ISREG(mode):
            data = image.read(record['path'])
            item.size = len(data)
        elif stat.S_ISLNK(mode):
            item.type = tarfile.SYMTYPE
            item.linkname = image.readlink(record['path'])
        else:
            raise ValueError('Unsupported stock Data seed file type')
        result[name] = (item, data)
    if 'keybags/systembag.kb' in result:
        raise ValueError('Stock seed unexpectedly contains an initialized keybag')
    return result


def add_parents(entries):
    for name in list(entries):
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.' and str(parent) not in entries:
                entries[str(parent)] = entry(str(parent), mode=0o755, directory=True)


def protected_data_seed(entries, generation, destination):
    """Defer file contents until the target kernel has initialized protection."""
    if str(uuid.UUID(generation)) != generation:
        raise ValueError('Invalid Data generation')
    marker = 'lib/olsn0w/generation'
    if entries[marker][1] != (generation+'\n').encode():
        raise ValueError('Data generation differs from target')
    deferred = {name: value for name, value in entries.items() if name != marker}
    write_tar(destination, deferred.values())
    if Path(destination).name.endswith('.gz'):
        Path(destination).write_bytes(gzip.compress(Path(destination).read_bytes(), mtime=0))
    metadata = {name: value for name, value in deferred.items()
                if value[0].isdir() or value[0].issym()}
    name = 'lib/olsn0w/fresh-'+generation
    metadata[name] = entry(name, mode=0o700, directory=True)
    add_parents(metadata)
    return metadata


def merge_data_payload(data_entries, payload):
    """Overlay package files without replacing firmware directory permissions."""
    for name in list(payload):
        if name.startswith('private/var/'):
            item, data = payload.pop(name)
            item = copy.copy(item)
            item.name = name[len('private/var/'):]
            existing = data_entries.get(item.name)
            if existing and existing[0].isdir() and item.isdir():
                # Services other than mobile need to traverse some stock paths.
                # Package directory modes are not the firmware's access policy.
                continue
            data_entries[item.name] = (item, data)
        elif name == 'private/var':
            payload.pop(name)


# These releases have complete first-boot recipes and can be selected from the
# guided restore menu.
SUPPORTED_MAJORS = (6, 7, 8)
PREPARABLE_MAJORS = SUPPORTED_MAJORS


def remove_pangu_admission_overrides(entries):
    """Discard Pangu's stock-jailbreak admission files after validating them.

    The olsn0w relay already supplies the target AMFI boot arguments, so the
    signed Pangu untether can start from its ordinary LaunchDaemon. Retaining
    Pangu's global dyld overrides would replace the complete stock MIS API and
    make every mobile-user xpcd load a system-only launchd cache.
    """
    names = (
        'usr/lib/libmis.dylib',
        'System/Library/Caches/com.apple.xpcd/xpcd_cache.dylib',
        'System/Library/Caches/com.apple.xpcd/xpcd_cache.ipod.dylib',
        'System/Library/Caches/com.apple.dyld/enable-dylibs-to-override-cache',
    )
    try:
        removed = {name: entries.pop(name) for name in names}
    except KeyError as error:
        raise ValueError('Pangu admission override is missing: ' + error.args[0]) from error
    macho_magics = {
        b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
        b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce',
        b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
    }
    item, data = removed['usr/lib/libmis.dylib']
    if (not item.isfile() or data is None or data[:4] not in macho_magics or
            b'/usr/lib/libmis.dylib\0' not in data or
            b'_MISEnumerateInstalledProvisioningProfiles' in data):
        raise ValueError('Unrecognized Pangu reduced MIS library')
    for name in names[1:3]:
        item, data = removed[name]
        if (not item.isfile() or data is None or data[:4] not in macho_magics or
                b'__xpcd_cache' not in data or
                b'io.pangu.axe.untether' not in data):
            raise ValueError('Unrecognized Pangu xpcd admission cache')
    item, data = removed[names[3]]
    if not item.isfile() or data != b'':
        raise ValueError('Unrecognized Pangu dyld override marker')


def jailbreak_payload(release):
    major = version(release)[0]
    if major not in PREPARABLE_MAJORS:
        raise ValueError('This firmware needs its own first-boot service integration')
    pangu71 = major == 7 and version(release) >= version('7.1')
    packages = (['daibutsu/untether.tar'] if major==8 else
                ['panguaxe.tar'] if pangu71 else ['aquila_'+str(major)+'.tar'])
    packages += ['freeze.tar.gz', 'openssh.tar.gz', 'openssl.tar.gz','sshdeb.tar', 'LukeZGD.tar']
    # EverUntether's validated iOS 8 path installs patcyh and invokes its
    # extrainst hook.  Keep that same payload for every iOS 8 release instead
    # of switching older releases to the unvalidated nopatcyh package set.
    patcyh=major==8
    if not patcyh:packages.append('nopatcyh.tar')
    entries, provenance = {}, []
    for package in packages:
        path = PACKAGE_ROOT / package
        provenance.append(dict(path=str(path.relative_to(KIT)), sha256=digest(path)))
        for item, data in members(path):
            name = item.name
            if package=='daibutsu/untether.tar' and name not in ('everuntether','usr/libexec/dirhelper','taig','taig/taig'):
                continue
            if name in ('private/etc/fstab', 'private/etc/ssh/sshd_config',
                        'Library/LaunchDaemons/com.openssh.sshd.plist'):
                continue
            if not patcyh and 'patcyh' in name and not name.endswith(('/status', '/available')):
                continue
            if not name.startswith('private/var/'):
                item.uid = item.gid = 0
            entries[name] = (item, data)
    if pangu71:
        remove_pangu_admission_overrides(entries)
    if major != 6 and major != 8 and not pangu71:
        aquila, origin = ios7_payload()
        entries.pop('private/var/aquila/aquila', None)
        entries['aquila'] = entry('aquila', aquila, 0o755)
        provenance.append(origin)
    return entries, provenance


def ios6_keybag_payload():
    root = Path(__file__).parent
    report = json.loads((TARGET_SCRIPTS/'keybag-init.json').read_text())
    expected = {'native/target/keybag_init.c', 'native/target/build-keybag.sh', 'target/keybag-init', 'target/keybag-init.sh'}
    if set(report['files']) != expected or any(digest(root/n) != h for n,h in report['files'].items()):
        raise ValueError('Keybag initializer source or binary checksum mismatch')
    blob = (TARGET_SCRIPTS/'keybag-init').read_bytes()
    verify(blob)
    return blob


def ios6_launchd_conf(content):
    token = b'bsexec .. /private/var/aquila/aquila\n'
    if content.count(token) != 1:
        raise ValueError('Unrecognized Kit iOS 6 launchd configuration')
    initializer = b'bsexec .. /bin/sh /usr/local/libexec/olsn0w/keybag-init.sh\n'
    if initializer in content:
        raise ValueError('iOS 6 keybag initializer is already present')
    # Data is populated offline on iOS 6, but Apple's native keybagd still
    # requires a system bag on a freshly formatted volume. Create only that
    # missing bag before launchd starts Aquila; retain the historical Data
    # path and every package command unchanged.
    return initializer + content


def keybag_tool():
    package = PACKAGE_ROOT / 'dualbootstuff.tar'
    debs = [data for item, data in members(package) if item.name.endswith('.deb') and '/com.nyansatan.dualbootstuff_' in item.name]
    if len(debs) != 1:
        raise ValueError('Expected one bundled dualbootstuff package')
    found = [data for item, data in members(deb_payload(debs[0])) if item.name == 'usr/share/dualbootstuff/fixkeybag' and item.isfile()]
    if len(found) != 1:
        raise ValueError('Bundled fixkeybag is missing or ambiguous')
    verify(found[0])
    return found[0], dict(path=str(package.relative_to(KIT)), sha256=digest(package))


def early_keybag_job(launchd):
    """Recognize the keybag initialization job embedded in Apple's launchd.

    A LaunchDaemons plist does not intercept this earlier invocation.
    Unknown arguments must be reviewed before wrapping the stock program.
    """
    jobs = []
    for match in re.finditer(rb'<\?xml\b[^\0]*?</plist>', launchd, re.S):
        document = plistlib.loads(match.group())
        if isinstance(document, dict) and isinstance(document.get('Boot'), dict):
            job = document['Boot'].get('keybag')
            if job is not None:
                jobs.append(job)
    if not jobs:
        return False
    if (len(jobs) != 1 or not isinstance(jobs[0], dict)
            or jobs[0].get('Program') != '/usr/libexec/keybagd'
            or jobs[0].get('ProgramArguments') != ['keybagd', '--init']):
        raise ValueError('Unrecognized early keybag initialization job')
    return True


def uses_legacy_job_loader(release, untether=None):
    """The qualified iOS 7/8 untethers use the guarded batch loader."""
    return version(release)[0] in (7, 8)


def wraps_early_keybag(release, launchd):
    """Only iOS 7 needs the pre-untether keybag admission wrapper."""
    return version(release)[0] == 7 and early_keybag_job(launchd)


LATE_MIS_SERVICES = {
    'com.apple.managedconfiguration.profiled':
        '/System/Library/PrivateFrameworks/ManagedConfiguration.framework/Support/profiled',
    'com.apple.accountsd': '/System/Library/Frameworks/Accounts.framework/accountsd',
}


def defer_profile_service(image):
    """Keep MIS consumers outside early launchd discovery until Aquila patches.

    Early amfid still needs the package's reduced libmis. Profile and account
    services require the complete shared-cache implementation. Preserve their
    Apple jobs and let Aquila's post-patch loader register them.
    """
    jobs = []
    for label, program in LATE_MIS_SERVICES.items():
        source = '/Library/LaunchDaemons/' + label + '.plist'
        data = image.read(source)
        job = plistlib.loads(data)
        if job.get('Label') != label or job.get('ProgramArguments') != [program]:
            raise ValueError('Unrecognized firmware MIS consumer: ' + label)
        jobs.append((source, data))
    image.mkdir('/olsn0w/late-jobs')
    for source, data in jobs:
        destination = '/olsn0w/late-jobs/' + source.rsplit('/', 1)[1]
        image.add(destination, data, 0o644)
        if image.read(destination) != data:
            raise ValueError('Deferred Apple service readback differs')
        image.command('rm', source)


def cydia_startup_job(data):
    """Retry failed first-boot preparation without repeating successful runs."""
    job = plistlib.loads(data)
    if (job.get('Label') != 'com.saurik.Cydia.Startup' or
            job.get('ProgramArguments') != ['/bin/bash', '/usr/libexec/cydia/startup']):
        raise ValueError('Unrecognized Cydia startup job')
    job['RunAtLoad'] = True
    job['KeepAlive'] = {'SuccessfulExit': False}
    job['ThrottleInterval'] = 30
    job['StandardOutPath'] = '/var/logs/AppleSupport/olsn0w-cydia.log'
    job['StandardErrorPath'] = job['StandardOutPath']
    return plistlib.dumps(job)


def cydia_startup_script(content):
    """Prepare Cydia and publish completion for the selected Data generation."""
    token = b'/usr/libexec/cydia/firmware.sh\n'
    if content.count(token) != 1:
        raise ValueError('Unrecognized kit Cydia startup script')
    content = content.replace(
        token,
        b'cd /\n/usr/local/libexec/olsn0w/prepare-cydia.sh || exit 1\n'
        b'/usr/libexec/cydia/firmware.sh || exit 1\n')
    content = content.replace(
        b'    sbdidlaunch\n',
        b'    /usr/local/libexec/olsn0w/wait-graphics.sh || exit 1\n')
    marker = b'/var/lib/olsn0w/cydia-ready'
    if marker in content:
        raise ValueError('Cydia startup completion marker already exists')
    # launchctl reports an unstarted on-demand job as "- 0", which is
    # indistinguishable from a successful run. Publish an atomic, generation-
    # bound marker only after the complete script reaches its final command.
    content += (
        b'\n/bin/cp /var/lib/olsn0w/generation /var/lib/olsn0w/cydia-ready.new || exit 1\n'
        b'/bin/chmod 644 /var/lib/olsn0w/cydia-ready.new || exit 1\n'
        b'/bin/mv -f /var/lib/olsn0w/cydia-ready.new /var/lib/olsn0w/cydia-ready || exit 1\n'
        b'/bin/sync\n')
    return content


def untether_jetsam_properties(data, label):
    """Give the selected iOS 7 untether enough memory to patch and remount."""
    document = plistlib.loads(data)
    defaults = document.get('Defaults')
    if document.get('Version') != 3 or not isinstance(defaults, dict):
        raise ValueError('Unrecognized iOS 7 jetsam properties')
    properties = copy.deepcopy(defaults.get(label, {}))
    if not isinstance(properties, dict):
        raise ValueError('Unrecognized untether jetsam properties')
    properties.update(JetsamPriority=18, JetsamMemoryLimit=128)
    defaults[label] = properties
    return plistlib.dumps(document)


def configure_untether_jetsam(image, product, label):
    if product not in MODELS:
        raise ValueError('Expected an iOS 7 jetsam board identity')
    system = '/System/Library/LaunchDaemons'
    board = MODELS[product][0]
    path = system+'/com.apple.jetsamproperties.'+board[:-2].upper()+'.plist'
    configured = untether_jetsam_properties(image.read(path), label)
    image.add(path, configured)
    if image.read(path) != configured:
        raise ValueError('Untether jetsam properties readback differs')


def pangu_startup_job(data):
    """Retain Pangu's established launch contract while recording diagnostics."""
    job = plistlib.loads(data)
    if (job.get('Label') != 'io.pangu.axe.untether' or
            job.get('ProgramArguments') != ['/panguaxe'] or
            job.get('RunAtLoad') is not True or
            job.get('LaunchOnlyOnce') is not True or
            job.get('UserName') != 'root'):
        raise ValueError('Unrecognized Pangu untether job')
    job['StandardOutPath'] = '/var/logs/AppleSupport/olsn0w-untether.log'
    job['StandardErrorPath'] = job['StandardOutPath']
    return plistlib.dumps(job)


def prepare_pangu_daemon(image, product):
    """Keep the Kit's proven stock-daemon layout for the iOS 7.1 untether."""
    system = '/System/Library/LaunchDaemons'
    for name in ('com.apple.mobile.softwareupdated.plist',
                 'com.apple.softwareupdateservicesd.plist'):
        if any(r['name'] == name for r in image.ls(system)):
            image.command('rm', system+'/'+name)
    path = system+'/io.pangu.axe.untether.plist'
    configured = pangu_startup_job(image.read(path))
    image.add(path, configured)
    configure_untether_jetsam(image, product, 'io.pangu.axe.untether')
    return configured


def move_daemons(image, major=7, product=None, untether=None):
    """Apply the Kit's daemon ordering while retaining the native DNS service."""
    system, library = '/System/Library/LaunchDaemons', '/Library/LaunchDaemons'
    if {r['name'] for r in image.ls(library)} != {'com.saurik.Cydia.Startup.plist'}:
        raise ValueError('Unexpected daemons before kit daemon relocation')
    keep = {'bootps.plist', 'com.apple.CrashHousekeeping.plist',
            'com.apple.MobileFileIntegrity.plist', 'com.apple.sandboxd.plist'}
    if major==8:keep.remove('com.apple.sandboxd.plist')
    ota = {'com.apple.mobile.softwareupdated.plist', 'com.apple.softwareupdateservicesd.plist'}
    # Move the jobs individually. The bundled HFS tool's directory move does
    # not update HFSX folder counts when crossing parent directories.
    for record in image.ls(system):
        name = record['name']
        if not stat.S_ISREG(record['mode']):
            raise ValueError('Unexpected non-file launch daemon entry: '+name)
        if name in ota:
            image.command('rm', system+'/'+name)
        elif name not in keep and not name.startswith('com.apple.jetsamproperties.'):
            image.command('mv', system+'/'+name, library+'/'+name)
    if untether not in {'aquila', 'everuntether'}:
        raise ValueError('Expected a qualified untether trigger')
    # A same-parent rename in hfsplus also increments the parent's item
    # count. Copy and remove explicitly, checking the replacement bytes.
    original = '/usr/libexec/CrashHousekeeping'
    mode = next(r['mode'] for r in image.ls('/usr/libexec')
                if r['name'] == 'CrashHousekeeping')
    image.add(original+'.backup', image.read(original), stat.S_IMODE(mode))
    image.command('rm', original)
    program = '/everuntether' if untether == 'everuntether' else '/aquila'
    image.command('symlink', original, program)
    if image.readlink(original) != program:
        raise ValueError('Untether startup symlink readback mismatch')
    job_path = system + '/com.apple.CrashHousekeeping.plist'
    job = plistlib.loads(image.read(job_path))
    if (job.get('Label') != 'com.apple.CrashHousekeeping' or
            job.get('Program') != original):
        raise ValueError('Unrecognized CrashHousekeeping job')
    job['AbandonProcessGroup'] = True
    job['StandardOutPath'] = '/var/logs/AppleSupport/olsn0w-untether.log'
    job['StandardErrorPath'] = job['StandardOutPath']
    image.add(job_path, plistlib.dumps(job))
    if major == 7:
        configure_untether_jetsam(image, product, 'com.apple.CrashHousekeeping')


def prepare(firmware, relay, root_device='/dev/disk0s1s3', data_device='/dev/disk0s1s2'):
    firmware, relay = Path(firmware), Path(relay)
    source = json.loads((firmware/'manifest.json').read_text())
    chain = json.loads((relay/'manifest.json').read_text())
    for key in ('product', 'version', 'build'):
        if source[key] != chain[key]:
            raise ValueError('Firmware and relay identities differ')
    for folder, report in [(firmware, source), (relay, chain)]:
        for name, expected in report['files'].items():
            if digest(folder/name) != expected:
                raise ValueError('Prepared input changed: '+name)
    # The checked iBEC recipe selects the third GPT entry as the target volume.
    if root_device != '/dev/disk0s1s3' or data_device != '/dev/disk0s1s2':
        raise ValueError('Selected devices do not match this relay partition recipe')
    payload, provenance = jailbreak_payload(source['version'])
    major = version(source['version'])[0]
    untether_name=('everuntether' if major==8 else
                   'panguaxe' if major==7 and version(source['version'])>=version('7.1') else 'aquila')
    data_payload_checks = {}
    stock = HFS(firmware/'rootfs.hfs')
    system_version = plistlib.loads(stock.read('/System/Library/CoreServices/SystemVersion.plist'))
    if system_version['ProductBuildVersion'] != source['build'] or version(system_version['ProductVersion']) != version(source['version']):
        raise ValueError('Root filesystem version differs from IPSW manifest')
    # The physically qualified iOS 8 path keeps Apple's early keybagd in place.
    # iOS 7 still needs the wrapper because launchd starts keybagd before Aquila.
    early_keybag = wraps_early_keybag(source['version'], stock.read('/sbin/launchd'))
    destination = firmware.parent/'system'
    if destination.exists():
        raise ValueError('Prepared target filesystem already exists: '+str(destination))
    out = Path(tempfile.mkdtemp(prefix='system-pending-', dir=firmware.parent))
    # iOS 6's shipped launchd contract executes Aquila from Data. Retarget the
    # qualified binary before Data entries are split out of the root overlay.
    if major == 6:
        aquila_path = 'private/var/aquila/aquila'
        untether_item, original = payload[aquila_path]
        untether = out/'aquila'
        signature = prepare_ios6_payload(original, root_device, untether)
        prepared = untether.read_bytes()
        payload[aquila_path] = entry(aquila_path, prepared, untether_item.mode)
        data_payload_checks['aquila/aquila'] = hashlib.sha256(prepared).hexdigest()
    generation = str(uuid.uuid4())
    data_entries = seed_data(stock)
    merge_data_payload(data_entries, payload)
    seed_cydia_source_cache(data_entries)
    data_entries['lib/olsn0w/generation'] = entry('lib/olsn0w/generation', (generation+'\n').encode(), 0o600)
    for directory in ('logs/AppleSupport', 'run', 'lib/olsn0w'):
        data_entries.setdefault(directory, entry(directory, mode=0o755, directory=True))
    add_parents(data_entries)
    protected_data = uses_protected_data(source['version'])
    if protected_data:
        metadata = protected_data_seed(data_entries, generation, out/'data-firstboot.tar.gz')
        write_tar(out/'data-seed.tar', metadata.values())
        payload['usr/local/share/olsn0w/data-firstboot.tar.gz'] = entry(
            'usr/local/share/olsn0w/data-firstboot.tar.gz', (out/'data-firstboot.tar.gz').read_bytes(), 0o600)
    else:
        write_tar(out/'data-seed.tar', data_entries.values())

    if major != 6:
        untether_item, original = payload[untether_name]
        untether = out/untether_name
        prepare_untether={'everuntether':prepare_ios8_payload,
                          'panguaxe':prepare_pangu71_payload,
                          'aquila':prepare_payload}[untether_name]
        signature=prepare_untether(original,root_device,untether)
        payload[untether_name]=entry(untether_name,untether.read_bytes(),untether_item.mode)
    if uses_legacy_job_loader(source['version'], untether_name):
        loader, wrapper = job_loader()
        payload['olsn0w/load-jobs'] = entry('olsn0w/load-jobs', loader, 0o755)
        payload['olsn0w/lctl'] = entry('olsn0w/lctl', wrapper, 0o755)
    if major == 6:
        item, conf = payload['private/etc/launchd.conf']
        payload['private/etc/launchd.conf'] = entry(item.name, ios6_launchd_conf(conf), item.mode)
        payload['usr/local/libexec/olsn0w/keybag-init'] = entry(
            'usr/local/libexec/olsn0w/keybag-init', ios6_keybag_payload(), 0o755)
        payload['usr/local/libexec/olsn0w/keybag-init.sh'] = entry(
            'usr/local/libexec/olsn0w/keybag-init.sh', (TARGET_SCRIPTS/'keybag-init.sh').read_bytes(), 0o755)

    for name in ('ssh_host_rsa_key', 'ssh_client_rsa'):
        run(['ssh-keygen', '-q', '-t', 'rsa', '-b', '2048', '-m', 'PEM', '-N', '', '-f', out/name])
    ssh_config = '''Protocol 2
Port 22
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_rsa_key
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile /etc/ssh/olsn0w_authorized_keys
StrictModes no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePrivilegeSeparation no
UseDNS no
AllowUsers root
Subsystem sftp /usr/libexec/sftp-server
'''
    payload['private/etc/ssh/sshd_config'] = entry('private/etc/ssh/sshd_config', ssh_config.encode(), 0o600)
    payload['usr/local/share/olsn0w/sshd_config'] = entry(
        'usr/local/share/olsn0w/sshd_config', ssh_config.encode(), 0o600)
    payload['private/etc/ssh/ssh_host_rsa_key'] = entry('private/etc/ssh/ssh_host_rsa_key', (out/'ssh_host_rsa_key').read_bytes(), 0o600)
    payload['private/etc/ssh/olsn0w_authorized_keys'] = entry('private/etc/ssh/olsn0w_authorized_keys', (out/'ssh_client_rsa.pub').read_bytes(), 0o600)
    for script in ('guard-target.sh', 'keybag-start.sh', 'wait-graphics.sh', 'prepare-cydia.sh'):
        name = 'usr/local/libexec/olsn0w/'+script
        source_script = ('keybag-start-protected.sh'
                         if script == 'keybag-start.sh' and uses_protected_keybag_start(source['version']) else script)
        payload[name] = entry(name, (TARGET_SCRIPTS/source_script).read_bytes(), 0o755)
    config = dict(AG_BOARD=MODELS[source['product']][0].upper(), AG_BUILD=source['build'],
                  AG_ROOT_DEVICE=root_device, AG_DATA_DEVICE=data_device, AG_GENERATION=generation)
    # The physically qualified iOS 8 first boot keeps the native daemon at a
    # private path and leaves a tiny wrapper at Apple's executable path.  The
    # plist also invokes keybag-start directly, but retaining this fallback
    # makes every launch route pass through the same protected-Data setup.
    wrapped_keybag = early_keybag or major == 8
    if wrapped_keybag:
        preserved = 'usr/local/libexec/olsn0w/keybagd'
        original = next(r for r in stock.ls('/usr/libexec') if r['name'] == 'keybagd')
        if not stat.S_ISREG(original['mode']):
            raise ValueError('Expected the stock keybag executable')
        payload[preserved] = entry(preserved, stock.read('/usr/libexec/keybagd'), stat.S_IMODE(original['mode']))
        payload['usr/libexec/keybagd'] = entry('usr/libexec/keybagd',
            b'#!/bin/sh\nexec /bin/sh /usr/local/libexec/olsn0w/keybag-start.sh "$@"\n', 0o755)
        config['AG_KEYBAG_PROGRAM'] = '/'+preserved
    config_bytes = ''.join(k+'='+shlex.quote(v)+'\n' for k,v in config.items()).encode()
    payload['usr/local/libexec/olsn0w/target.conf'] = entry('usr/local/libexec/olsn0w/target.conf', config_bytes, 0o600)
    fixkeybag, origin = keybag_tool()
    if early_keybag or uses_protected_keybag_start(source['version']):
        # Protected Data creation runs before the untether on both the embedded
        # iOS 7 job and the iOS 7/8 LaunchDaemon. Retain Apple's KeyStore access
        # instead of relying on sandbox patches that have not run yet.
        helper = out/'fixkeybag'
        helper.write_bytes(fixkeybag)
        entitlement_source = payload[preserved][1] if wrapped_keybag else stock.read('/usr/libexec/keybagd')
        resign(helper, verify(entitlement_source)['entitlements'])
        fixkeybag = helper.read_bytes()
    provenance.append(origin)
    payload['usr/local/libexec/olsn0w/fixkeybag'] = entry('usr/local/libexec/olsn0w/fixkeybag', fixkeybag, 0o755)
    payload['.cydia_no_stash'] = entry('.cydia_no_stash', b'')
    # firmware.sh creates this compatibility link at runtime. The iOS 7 Pangu
    # path keeps System read-only at that point, so include it in the image.
    payload['User'] = symlink_entry('User', '/var/mobile')
    # Cydia normally replaces its empty package-owned source file with this
    # Data-backed cache link on first launch. Use /private/etc, the real HFS
    # directory: /etc is a symbolic link that the offline catalog editor must
    # not be expected to traverse.
    data_backed_cydia_sources(payload)
    startup, content = payload['usr/libexec/cydia/startup']
    content = cydia_startup_script(content)
    payload['usr/libexec/cydia/startup'] = entry('usr/libexec/cydia/startup', content, startup.mode)
    startup_path = 'Library/LaunchDaemons/com.saurik.Cydia.Startup.plist'
    item, job_data = payload[startup_path]
    payload[startup_path] = entry(startup_path, cydia_startup_job(job_data), item.mode)
    add_parents(payload)
    write_tar(out/'root-overlay.tar', payload.values())

    clone_or_copy(stock.path, out/'system.hfs')
    image = HFS(out/'system.hfs')
    image.command('rmall', '/private/var')
    image.mkdir('/private/var')
    needed = sum(len(data) for _,data in payload.values() if data is not None) + 16*1024**2
    if image.info()['free_bytes'] < needed:
        block = image.info()['block_size']
        size = image.info()['bytes'] + needed - image.info()['free_bytes']
        image.grow((size+block-1)//block*block)
    directories = [(item, data) for item,data in payload.values() if item.isdir()]
    write_tar(out/'overlay-directories.tar', directories)
    image.command('untar', out/'overlay-directories.tar')
    catalog = {}
    for name, (item, _) in payload.items():
        if item.isdir():
            continue
        parent = str(PurePosixPath('/'+name).parent)
        if parent not in catalog:
            catalog[parent] = {r['name']:r for r in image.ls(parent)}
        previous = catalog[parent].get(PurePosixPath(name).name)
        if previous:
            if stat.S_ISDIR(previous['mode']):
                raise ValueError('Payload would replace a system directory: '+name)
            image.command('rm', '/'+name)
    image.command('untar', out/'root-overlay.tar')
    if image.readlink('/User') != '/var/mobile':
        raise ValueError('Cydia User compatibility symlink readback differs')
    if image.readlink('/private/etc/apt/sources.list.d/cydia.list') != \
            '/var/mobile/Library/Caches/com.saurik.Cydia/sources.list':
        raise ValueError('Cydia source cache symlink readback differs')
    # SSH StrictModes checks every ancestor of the authorized-keys file.
    # Stock / can be group-writable too, despite safe /private/etc metadata.
    image.command('chown', '0:0', '/')
    image.command('chmod', '0755', '/')
    for path in ('/private', '/private/etc', '/private/etc/ssh'):
        image.command('chown', '0:0', path)
        image.command('chmod', '0755', path)
        parent = PurePosixPath(path)
        record = next(r for r in image.ls(str(parent.parent)) if r['name'] == parent.name)
        if (record['uid'], record['gid'], stat.S_IMODE(record['mode'])) != (0, 0, 0o755):
            raise ValueError('SSH directory metadata readback failed: '+path)
    # The sharing daemon can submit this job while Wi-Fi and DNS are still
    # initializing. Preserve its loopback listeners without a name lookup.
    from job_sockets import numeric_loopback_sockets
    socket_job = '/System/Library/LaunchDaemons/com.apple.ftp-proxy-embedded.plist'
    if any(r['name'] == 'com.apple.ftp-proxy-embedded.plist' for r in image.ls('/System/Library/LaunchDaemons')):
        before = image.read(socket_job)
        after = numeric_loopback_sockets(before)
        if after != before:
            image.add(socket_job, after)
            if image.read(socket_job) != after:
                raise ValueError('Local socket configuration readback differs')
    if major in (7,8):
        if untether_name == 'panguaxe':
            configured = prepare_pangu_daemon(image, source['product'])
            name = 'System/Library/LaunchDaemons/io.pangu.axe.untether.plist'
            item, _ = payload[name]
            payload[name] = entry(name, configured, item.mode)
        else:
            move_daemons(image,major,source['product'],untether_name)
        if major == 7:
            if untether_name != 'panguaxe':
                defer_profile_service(image)
        else:
            from ios8_cache import prepare as prepare_cache
            architecture=profile(source['product'])['cache_arch']
            cache_path='/System/Library/Caches/com.apple.dyld/dyld_shared_cache_'+architecture
            stock_cache=stock.read(cache_path)
            cache,cache_report=prepare_cache(stock_cache,architecture)
            needed=max(0,len(cache)-len(stock_cache))+16*1024**2
            geometry=image.info()
            if geometry['free_bytes']<needed:
                block=geometry['block_size']
                size=geometry['bytes']+needed-geometry['free_bytes']
                image.grow((size+block-1)//block*block)
            # Preserve the existing large data fork and its allocation extents.
            image.replace_regular(cache_path,cache)
            if image.read(cache_path)!=cache:raise ValueError('iOS 8 cache readback mismatch')
            save(out/'cache-remapping.json',cache_report)
    else:
        for name in ('com.apple.mobile.softwareupdated.plist', 'com.apple.softwareupdateservicesd.plist'):
            if any(r['name'] == name for r in image.ls('/System/Library/LaunchDaemons')):
                image.command('rm', '/System/Library/LaunchDaemons/'+name)
    # The untether remounts the root after patching the kernel. Forcing rw
    # before it starts makes stock iOS 7 reject the mount and shut down.
    fstab = relocate_fstab(stock.read('/private/etc/fstab'), root_device, data_device,
                           protect_data=protected_data)
    image.command('rm', '/private/etc/fstab')
    image.add('/private/etc/fstab', fstab)
    from kernelcache import prepare as prepare_kernelcache
    kernel_path, kernel_patch = prepare_kernelcache(
        source, firmware, out/'kernelcache.patched.img3')
    for name, path, expected_type in [('applelogo',firmware/'AppleLogo.img3','logo'),
                                      ('devicetree',relay/'devicetree','dtre'),
                                      ('kernelcache',kernel_path,'krnl')]:
        blob = path.read_bytes()
        kind, tags, _ = img3(blob)
        if kind != expected_type or 'KBAG' in tags:
            raise ValueError('Wrong or encrypted target boot component: '+name)
        image.add('/'+name, blob)
    if kernel_patch is not None:
        kernel_path.unlink()
    if major in (7,8):
        daemon_root = ('/System/Library/LaunchDaemons' if untether_name == 'panguaxe'
                       else '/Library/LaunchDaemons')
        job_path = daemon_root+'/com.apple.mobile.keybagd.plist'
        job = plistlib.loads(image.read(job_path))
        if job['ProgramArguments'][0] != '/usr/libexec/keybagd':
            raise ValueError('Unrecognized native keybag daemon job')
        job['ProgramArguments'] = ['/bin/sh', '/usr/local/libexec/olsn0w/keybag-start.sh', *job['ProgramArguments'][1:]]
        job['StandardOutPath'] = '/var/logs/AppleSupport/olsn0w-keybag.log'
        job['StandardErrorPath'] = job['StandardOutPath']
        image.add(job_path, plistlib.dumps(job))
    ssh_job = dict(Label='org.olsn0w.sshd', ProgramArguments=[
                       '/usr/sbin/sshd','-D','-e','-f','/usr/local/share/olsn0w/sshd_config'],
                   RunAtLoad=True, KeepAlive=True, StandardErrorPath='/var/logs/AppleSupport/olsn0w-sshd.log')
    image.add('/Library/LaunchDaemons/org.olsn0w.sshd.plist', plistlib.dumps(ssh_job))
    checks = {}
    for name, (item, data) in payload.items():
        if data is not None and name != 'Library/LaunchDaemons/com.saurik.Cydia.Startup.plist':
            if image.read('/'+name) != data:
                raise ValueError('Installed payload differs: '+name)
            checks[name] = hashlib.sha256(data).hexdigest()
    if image.ls('/private/var'):
        raise ValueError('Target root still contains Data payload')
    # These archives and temporary binaries have all been read back from the
    # finished image. Keep the source provenance in the manifest, not another
    # copy of payload bytes already embedded in system.hfs.
    for temporary in ('root-overlay.tar','data-firstboot.tar.gz','overlay-directories.tar',
                      'aquila','panguaxe','everuntether','fixkeybag'):
        path=out/temporary
        if path.exists():path.unlink()
    report = dict(recipe_version=RECIPE_VERSION,
                  product=source['product'], version=source['version'], build=source['build'],
                  relay_recipe_version=chain['recipe_version'],
                  relay_devicetree_sha256=chain['files']['devicetree'],
                  relay_binary_sha256=chain['files']['relay.bin'],
                  generation=generation, root_device=root_device, data_device=data_device,
                  early_keybag_initialization=early_keybag,
                  data_attributes=0x3000000000000 if major == 6 else 0,
                  data_seed_entries=len(metadata if protected_data else data_entries), volume=image.info(),
                  data_initialization=('native-newfs-hfs-P-cprotect-v4-metadata-only-then-target-firstboot'
                                       if protected_data else 'offline-seed'),
                  packages=provenance, untether=untether_name,
                  untether_signature=signature, payload_readback=checks,
                  data_payload_readback=data_payload_checks,
                  kernel_patch=kernel_patch,
                  service_loading=('stock-daemon-layout' if untether_name == 'panguaxe'
                                   else 'skip-registered-jobs-before-creating-sockets'),
                  activation='official activation required for the selected device',
                  restore_ready=False, filesystem_check_required=True, physical_boot_validated=False,
                  files={n:digest(out/n) for n in ('system.hfs','data-seed.tar')})
    save(out/'manifest.json', report)
    if major==8:
        report['files']['cache-remapping.json']=digest(out/'cache-remapping.json')
        report['untether']='EverUntether with Kit daibutsu cache admission'
        save(out/'manifest.json',report)
    out.rename(destination)
    return destination, report
