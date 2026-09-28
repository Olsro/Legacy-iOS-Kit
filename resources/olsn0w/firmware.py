"""Resolve model-specific releases and extract verified IPSW components."""
import json
from pathlib import Path
import plistlib
import shutil
import urllib.parse
import tempfile
import zipfile
import subprocess
import time
from progress import activity, display_if_needed, copy_stream, message

from common import KIT, STATE, MODELS, target, version, tools, run, digest, save, integer, minimum_release


def content_length(headers):
    """Use only the last HTTP response, never a redirect's body length."""
    response=headers.replace('\r\n','\n').split('\n\n')
    response=[block for block in response if block.startswith('HTTP/')]
    if not response:return None
    lines=response[-1].splitlines()
    status=lines[0].split()
    if len(status)<2 or not status[1].startswith('2'):return None
    fields={line.split(':',1)[0].strip().lower():line.split(':',1)[1].strip() for line in lines[1:] if ':' in line}
    if 'transfer-encoding' in fields:return None
    value=fields.get('content-length','')
    return int(value) if value.isdigit() and int(value)>0 else None


def fetch(url, destination, total=None):
    if urllib.parse.urlsplit(url).scheme != 'https':
        raise ValueError('HTTPS required for firmware metadata and downloads')
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + '.download')
    with display_if_needed(), activity('Downloading firmware' if destination.suffix=='.ipsw' else 'Downloading required file',total) as update, tempfile.TemporaryDirectory(prefix='olsn0w-download-') as folder:
        headers=Path(folder)/'headers';errors=Path(folder)/'errors'
        argv=['curl','--silent','--show-error','--fail','--location','--proto','=https','--proto-redir','=https',
              '--retry','3','--connect-timeout','20','--dump-header',str(headers),'--output',str(temporary),url]
        with errors.open('wb') as log:
            process=subprocess.Popen(argv,stdout=subprocess.DEVNULL,stderr=log)
            started=time.monotonic()
            try:
                while True:
                    length=total or (content_length(headers.read_text(errors='replace')) if headers.exists() else None)
                    update(temporary.stat().st_size if temporary.exists() else 0,length)
                    try:code=process.wait(timeout=.25);break
                    except subprocess.TimeoutExpired:
                        if time.monotonic()-started>=3600:raise RuntimeError('Download timed out')
                if code:raise RuntimeError('Download failed: '+errors.read_text(errors='replace')[-2000:])
                if total and temporary.stat().st_size!=total:raise RuntimeError('Downloaded file size differs from the firmware catalog')
                temporary.replace(destination)
                update(destination.stat().st_size,total or length)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()


def releases(product, refresh=False):
    if product not in MODELS:
        raise ValueError('Unsupported product')
    path = STATE / 'catalog' / (product + '.json')
    if refresh or not path.exists():
        fetch('https://api.ipsw.me/v4/device/' + product + '?type=ipsw', path)
    data = json.loads(path.read_text())
    if data['identifier'] != product:
        raise ValueError('Firmware catalog product mismatch')
    return sorted([f for f in data['firmwares'] if
                   version(minimum_release(product)) <= version(f['version'])],
                  key=lambda f: (version(f['version']), f['buildid']))


def select_release(records, release, build=None):
    matches = [f for f in records if version(f['version']) == version(release)
               and (build is None or f['buildid'] == build)]
    if not matches:
        raise ValueError('No released firmware matches this product/version/build')
    if len(matches) != 1:
        builds = ', '.join(sorted({f['buildid'] for f in matches}))
        raise ValueError('This version has several builds; select --build from: ' + builds)
    return matches[0]


def identity(archive, product, release):
    board, chip, board_id = target(product, release)
    manifest = plistlib.loads(archive.read('BuildManifest.plist'))
    if version(manifest['ProductVersion']) != version(release) or product not in manifest['SupportedProductTypes']:
        raise ValueError('IPSW version/product mismatch')
    matches = [i for i in manifest['BuildIdentities'] if i['Info']['DeviceClass'] == board
               and integer(i['ApChipID']) == chip and integer(i['ApBoardID']) == board_id]
    if not matches:
        raise ValueError('IPSW chip/board identity mismatch')
    erase = [i for i in matches if i['Info'].get('RestoreBehavior') == 'Erase']
    selected = (erase or matches)[0]
    return manifest, selected


def acquire(product, release, ipsw=None, key_file=None, build=None):
    target(product, release)
    # A supplied IPSW identifies the build, including releases reissued by Apple.
    if ipsw is not None:
        with zipfile.ZipFile(ipsw) as archive:
            manifest, _ = identity(archive, product, release)
        if build is not None and build != manifest['ProductBuildVersion']:
            raise ValueError('Requested build does not match the IPSW')
        build = manifest['ProductBuildVersion']
    record = select_release(releases(product), release, build)
    if ipsw is None:
        ipsw = STATE / 'ipsw' / (product + '_' + record['version'] + '_' + record['buildid'] + '_Restore.ipsw')
        if not ipsw.exists():
            # Reuse only the distributed Kit's normal firmware locations.
            candidates=list(KIT.glob(ipsw.name))
            for cache in (KIT/'saved',):
                if cache.is_dir():candidates.extend(cache.rglob(ipsw.name))
            existing=next((p for p in candidates if p.is_file() and digest(p,'sha1')==record['sha1sum'].lower()),None)
            if existing is not None:
                ipsw=existing
                message('Using verified iOS '+record['version']+' firmware already on disk.')
            else:
                message('Downloading iOS ' + record['version'] + '…')
                fetch(record['url'], ipsw, total=record.get('filesize'))
    ipsw = Path(ipsw).resolve(strict=True)
    if digest(ipsw, 'sha1') != record['sha1sum'].lower():
        raise ValueError('IPSW checksum mismatch')
    with zipfile.ZipFile(ipsw) as archive:
        manifest, selected = identity(archive, product, release)
    if manifest['ProductBuildVersion'] != record['buildid']:
        raise ValueError('Catalog/manifest build mismatch')
    if key_file is None:
        cached = KIT / 'resources' / 'firmware' / product / record['buildid'] / 'index.html'
        key_file = cached if cached.exists() else STATE / 'keys' / product / (record['buildid'] + '.json')
        if not key_file.exists():
            fetch('https://raw.githubusercontent.com/LukeZGD/Legacy-iOS-Kit-Keys/'
                  'af6bf5934dc61ed557a967a3f42ab7fb8ed8c45e/' + product + '/' + record['buildid'] + '/index.html', key_file)
    keys = json.loads(Path(key_file).read_text())
    if keys['identifier'] != product or keys['buildid'] != record['buildid']:
        raise ValueError('Firmware keys do not match the selected product/build')
    return ipsw, keys, manifest, selected


def extract(product, release, ipsw=None, key_file=None, build=None):
    ipsw, keys, manifest, selected = acquire(product, release, ipsw, key_file, build)
    destination = STATE / 'targets' / product / manifest['ProductBuildVersion'] / 'firmware'
    if destination.exists():
        if not (destination / 'manifest.json').is_file():
            raise ValueError('Incomplete earlier extraction at ' + str(destination) + '; move it into a diagnostic folder before retrying')
        report = json.loads((destination / 'manifest.json').read_text())
        if report['ipsw_sha256'] != digest(ipsw) or any(digest(destination / n) != h for n, h in report['files'].items()):
            raise ValueError('Prepared firmware changed')
        # Older extractions retained the encrypted RootFS member even though
        # the verified IPSW and extracted HFS are the reproducible inputs.
        if 'RootFS.orig' in report['files']:
            report['files'].pop('RootFS.orig')
            save(destination/'manifest.json',report)
            (destination/'RootFS.orig').unlink()
        return destination, report
    destination.parent.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='firmware-pending-', dir=destination.parent))
    try:
        by_name = {k['image']: k for k in keys['keys']}
        with zipfile.ZipFile(ipsw) as archive:
            for name, component in [('iBSS','iBSS'), ('iBEC','iBEC'), ('DeviceTree','DeviceTree'),
                                    ('Kernelcache','KernelCache'), ('AppleLogo','AppleLogo'), ('RootFS','OS')]:
                member = selected['Manifest'][component]['Info']['Path']
                key = by_name[name]
                if Path(member).name != key['filename'] or archive.namelist().count(member) != 1:
                    raise ValueError('Component/key path mismatch: ' + name)
                original = out / (name + '.orig')
                with archive.open(member) as source, original.open('wb') as output_stream:
                    copy_stream(source,output_stream,archive.getinfo(member).file_size,'Extracting '+name)
                if name == 'RootFS':
                    run([tools()/'dmg', 'extract', original, out/'rootfs.hfs', '-k', key['key']], out/'rootfs.log', timeout=600)
                    original.unlink()
                else:
                    run([tools()/'xpwntool', original, out/(name+'.raw'), '-iv',key['iv'],'-k',key['key']], out/(name+'.log'))
                    if name in ('AppleLogo', 'Kernelcache'):
                        run([tools()/'xpwntool', original, out/(name+'.img3'), '-iv',key['iv'],'-k',key['key'],'-decrypt'], out/(name+'-container.log'))
        report = dict(product=product, version=manifest['ProductVersion'], build=manifest['ProductBuildVersion'],
                      board=MODELS[product][0], ipsw_sha256=digest(ipsw),
                      files={p.name:digest(p) for p in out.iterdir() if p.suffix != '.log'})
        save(out/'manifest.json',report)
        out.rename(destination)
        return destination, report
    except Exception as error:
        # Keep failed preparation for diagnosis; it has no completion manifest.
        raise RuntimeError(str(error) + '\nIncomplete extraction retained at ' + str(out)) from error
