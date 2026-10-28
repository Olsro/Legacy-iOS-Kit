"""Apply narrowly qualified target-kernel fixes and verify their containers."""
import hashlib
from pathlib import Path

from common import digest, run, tools
from img3 import img3


# These p101/p105/p106/p107 iOS 6 kernels retry TriStar System-ID IPC after a reset,
# but this hardware can return kIOReturnBadMessageID a second time. Apple's
# function already contains a failure fallback which publishes 0xffff and
# continues. The stock instruction branches over that fallback regardless of
# the retry result; CBZ retains the stock success path and enters Apple's own
# fallback only when the retry still failed.
PATCHES = {
    ('iPad3,4', '6.0', '10A407'): dict(
        name='tristar-system-id-retry-fallback',
        raw_sha256='540b4e5d81a1df218c593fcbe38090cb4fc8d9a3e030879657cbf067f15044c4',
        patched_sha256='45c9f4579fd968137f3b7d26a75635731c4362f6cb7b15edcb3c315733f3fc45',
        offset=0x9f24a2,
        virtual_address=0x80a334a2,
        before='10e0',
        after='86b1',
        validation='exact-structural-match',
    ),
    ('iPad3,4', '6.0.1', '10A523'): dict(
        name='tristar-system-id-retry-fallback',
        raw_sha256='317bf0667f7f04628196e1ffadba3e23f2d9043fc4bd8eefab939cde6c4988cf',
        patched_sha256='d77f1214ce957cb659bd75bd7dc5c5184925bc9c14af7c38791f94125a7ffb09',
        offset=0x9f24a2,
        virtual_address=0x80a334a2,
        before='10e0',
        after='86b1',
        validation='exact-structural-match',
    ),
    ('iPad3,4', '6.1', '10B141'): dict(
        name='tristar-system-id-retry-fallback',
        raw_sha256='fefc5803a59d07f735af838a82e16e944f0f817b67bb81373d9cbdbc01e3b972',
        patched_sha256='582523267f0561d86414aada691f41757ad2a1aa3952665957bbc5e6b90698f2',
        offset=0x9ec17e,
        virtual_address=0x80a2d17e,
        before='10e0',
        after='86b1',
        validation='exact-structural-match',
    ),
    ('iPad3,4', '6.1.2', '10B146'): dict(
        name='tristar-system-id-retry-fallback',
        raw_sha256='58d798979dd3cc2f50d32350ffd22847958738e47321db5ea148e3b49d4f4837',
        patched_sha256='69e67bf25aca6643ea4315d95bb2e587a7031c1596c2b004ab8b8b40afb89d22',
        offset=0x9ec17e,
        virtual_address=0x80a2d17e,
        before='10e0',
        after='86b1',
        validation='physical-boot-activation-ssh-cydia-startup',
    ),
    ('iPad3,4', '6.1.3', '10B329'): dict(
        name='tristar-system-id-retry-fallback',
        raw_sha256='5471d5d55c582ecd8a3e14314cbb1744a416422ecfa1a736ac14d3dca7861dbe',
        patched_sha256='8e481c2e013f547110382cdaaf3e0cdb24fff9de5af8c64612741c816ad8bf4d',
        offset=0x9ec17e,
        virtual_address=0x80a2d17e,
        before='10e0',
        after='86b1',
        validation='physical-boot-reboot-activation-wifi-cydia',
    ),
}


# Each released P106/P107 iOS 6 pair has an identical raw kernel. The complete
# retry/fallback code was audited against P107 10B329, including IOLog targets
# and literal references. iOS 6.0.x differs only in an unchanged member load.
# Evidence: recipes/tristar-mini-ios6.recipe; offline checker: kernelcache_audit.
_CELLULAR_MINI_IOS6 = {
    ('6.0.1', '10A8426'): dict(
        raw_sha256='110419bdb7162b9897414cd4095b4e439d813a63a573fd3e7c09cad9fe39c4db',
        patched_sha256='33f959c8ca4188b23daec9ab7b03447936abb9b4a7d51c6ceed6e9e176441557',
        offset=0xa224a2, virtual_address=0x80a634a2),
    ('6.0.2', '10A8500'): dict(
        raw_sha256='97441fc40dc00d1f45132a0273b440b05633f646a91465f2df3654a546c89a9a',
        patched_sha256='f0b888136ff929752adb65f09a3c05b05f6aebd995798368c0bef1df354aca9c',
        offset=0xa224a2, virtual_address=0x80a634a2),
    ('6.1', '10B141'): dict(
        raw_sha256='eab6ec1a845b8931fe9df91ea495d25716200af1af7c6e7ae8b46b7699fa5f7d',
        patched_sha256='f18931b51389daf21845929dfc3f9048b4ad72d2857b8c7775d2571dcb3a1570',
        offset=0xa1c10e, virtual_address=0x80a5d10e),
    ('6.1.2', '10B147'): dict(
        raw_sha256='d5d51cde7a227d2b76bf9ed0a897986bb93fdad1f9d3e776c703d282aeb16e8b',
        patched_sha256='22da143afc1e011df531bd15cd6a4c99a69446c6126513e566eae64cfbfbdf22',
        offset=0xa1b10e, virtual_address=0x80a5c10e),
    ('6.1.3', '10B329'): dict(
        raw_sha256='6642753b73af33e8490db4183612efc227f4c388fbeb46936355b58a8f369b30',
        patched_sha256='e5f9decc9b7e0619c7f0e8aae1d235f1e3d0525813d0091bc274db3063ce1211',
        offset=0xa1d10e, virtual_address=0x80a5e10e),
}
# The Wi-Fi P105 kernels differ from P106/P107 but contain the same complete
# function: 6.0.x uses the 0xdc member template and 6.1.x the 0xe8 one.
# Evidence: recipes/tristar-mini-ios6.recipe; offline checker: kernelcache_audit.
_WIFI_MINI_IOS6 = {
    ('6.0', '10A406'): dict(
        raw_sha256='9b4acd2d171f8e39b1e047daf067ccfbdd7ce1b2382ddeb82247543e1adbd100',
        patched_sha256='fe4664b6c019bcafcfc4a886b2b402104b7e86d279ff23a1da084280e996a0f8',
        offset=0xa144a2, virtual_address=0x80a554a2),
    ('6.0.1', '10A523'): dict(
        raw_sha256='326d129e1e28fa70ab003cd4a09516430cc2036c274c94d970852d5d59c1e34d',
        patched_sha256='192fee6687a4c18252df5e192eee001936fcbbdb814924ec6c39688d0e3d1912',
        offset=0xa144a2, virtual_address=0x80a554a2),
    ('6.0.2', '10A550'): dict(
        raw_sha256='29663a730bff885ed431e35823c89076ed1d3782af9e8204bdcb06bcfe50b2ad',
        patched_sha256='58a898e33890b6f4d45c71b5dbfbcd58fa513f7727e64e211627ea0d63c55682',
        offset=0xa144a2, virtual_address=0x80a554a2),
    ('6.1', '10B141'): dict(
        raw_sha256='743295ac713d425ac79f966270cf50436d106224e60591881555912e35fc47f3',
        patched_sha256='2a95095f0aa7d87f71972fb43f0b403198346ae6d2f5a8d1a872655be85e2b97',
        offset=0xa0e10e, virtual_address=0x80a4f10e),
    ('6.1.2', '10B146'): dict(
        raw_sha256='ccbeaffa71c880067d8d22620bdc48cd2b0731d9b0550e87f970c88029cec57c',
        patched_sha256='1a711ccb3bf594f193edd794e3d176872aaa11e29ccbe5755595dfe82e19fac3',
        offset=0xa0e10e, virtual_address=0x80a4f10e),
    ('6.1.3', '10B329'): dict(
        raw_sha256='4d9ee55163f133f53689184d58ec8d9023e61a63a025e60b65e25f552356a828',
        patched_sha256='e3d98407c08d05e9d4f98feb110656c99326550ed7116dac1056ed6672a19eee',
        offset=0xa0f10e, virtual_address=0x80a5010e),
}
for (_release, _build), _pin in _WIFI_MINI_IOS6.items():
    PATCHES['iPad2,5', _release, _build] = dict(
        name='tristar-system-id-retry-fallback', before='10e0', after='86b1',
        validation='exact-structural-match', **_pin)
for _product in ('iPad2,6', 'iPad2,7'):
    for (_release, _build), _pin in _CELLULAR_MINI_IOS6.items():
        PATCHES[_product, _release, _build] = dict(
            name='tristar-system-id-retry-fallback', before='10e0', after='86b1',
            validation=('physical-mac-and-charger-cold-boot-lockscreen'
                        if (_product, _build) == ('iPad2,7', '10B329')
                        else 'exact-structural-match'), **_pin)


def qualified_patch(source):
    """Return a fix only for an explicitly qualified firmware identity."""
    return PATCHES.get((source['product'], source['version'], source['build']))


def apply(data, patch):
    """Apply one exact byte change after checking the complete raw kernel."""
    original_hash = hashlib.sha256(data).hexdigest()
    if original_hash != patch['raw_sha256']:
        raise ValueError('Qualified target kernel differs')
    before, after = bytes.fromhex(patch['before']), bytes.fromhex(patch['after'])
    offset = patch['offset']
    if len(before) != len(after) or data[offset:offset+len(before)] != before:
        raise ValueError('Qualified target kernel patch site differs')
    result = data[:offset] + after + data[offset+len(before):]
    patched_hash = hashlib.sha256(result).hexdigest()
    if patched_hash != patch['patched_sha256']:
        raise ValueError('Patched target kernel digest differs')
    report = {key: patch[key] for key in (
        'name', 'offset', 'virtual_address', 'before', 'after', 'validation')}
    report.update(raw_sha256=original_hash, patched_sha256=patched_hash)
    return result, report


def prepare(source, firmware, destination):
    """Pack and read back the selected fix, or retain the stock container."""
    firmware, destination = Path(firmware), Path(destination)
    patch = qualified_patch(source)
    if patch is None:
        return firmware/'Kernelcache.img3', None
    raw, report = apply((firmware/'Kernelcache.raw').read_bytes(), patch)
    patched_raw = destination.with_suffix('.raw')
    readback = destination.with_suffix('.readback.raw')
    try:
        patched_raw.write_bytes(raw)
        run([tools()/'xpwntool', patched_raw, destination,
             '-t', firmware/'Kernelcache.img3'], destination.with_suffix('.pack.log'))
        kind, tags, _ = img3(destination.read_bytes())
        if kind != 'krnl' or 'KBAG' in tags:
            raise ValueError('Patched target kernel container is not bootable')
        run([tools()/'xpwntool', destination, readback],
            destination.with_suffix('.readback.log'))
        if readback.read_bytes() != raw:
            raise ValueError('Patched target kernel container readback differs')
        report['container_sha256'] = digest(destination)
        return destination, report
    finally:
        for path in (patched_raw, readback):
            if path.exists():
                path.unlink()
