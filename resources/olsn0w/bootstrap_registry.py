"""Configure launchd's embedded service registry without changing executable pages."""
import copy
import plistlib
import struct


def jobs(amfid, delayed_services=()):
    result = {}
    amfid = copy.deepcopy(amfid)
    if amfid.get('Label') != 'com.apple.MobileFileIntegrity':
        raise ValueError('Unexpected stock amfid job')
    amfid.update(RunAtLoad=True, StandardOutPath='/var/log/amfid-startup.log',
                 StandardErrorPath='/var/log/amfid-startup.log')
    result['/System/Library/LaunchDaemons/com.apple.MobileFileIntegrity.plist'] = amfid
    expected = {
        'com.apple.notifyd': '/usr/sbin/notifyd',
        'com.apple.powerd': '/System/Library/CoreServices/powerd.bundle/powerd',
    }
    for original in delayed_services:
        job = copy.deepcopy(original)
        label = job.get('Label')
        if label not in expected:
            raise ValueError('Unexpected delayed bootstrap service')
        arguments = job.pop('ProgramArguments', None)
        program = job.pop('Program', None)
        if arguments is None:
            arguments = [program] if program else None
        if not arguments or arguments[0] != expected[label]:
            raise ValueError('Unexpected delayed bootstrap service executable')
        # everuntether uses libsystem_notify while acquiring tfp0.  Delaying
        # notifyd until after that acquisition deadlocks every A5/A5X target.
        # powerd remains gated because it must not inspect power state while
        # the held untether is changing the kernel.
        job['ProgramArguments'] = (['/olsn0w/service-gate', *arguments]
                                   if label == 'com.apple.powerd' else arguments)
        job['RunAtLoad'] = True
        job['StandardOutPath'] = '/var/log/'+label+'.log'
        job['StandardErrorPath'] = '/var/log/'+label+'.log'
        result['/System/Library/LaunchDaemons/'+label+'.plist'] = job
    for label, arguments in [('org.olsn0w.boot', ['/olsn0w/controller']),
                             ('org.olsn0w.services', ['/olsn0w/root-start', 'start'])]:
        result['/System/Library/LaunchDaemons/'+label+'.plist'] = dict(
            Label=label, ProgramArguments=arguments, RunAtLoad=True, KeepAlive=False,
            StandardOutPath='/var/log/'+label+'.log', StandardErrorPath='/var/log/'+label+'.log')
    return result


def configure(cache, address, extent, launch_jobs):
    """Replace an existing plist in one strictly read-only cache mapping."""
    offset, count = struct.unpack_from('<II', cache, 16)
    if not 0 < count <= 7 or offset+count*32 > len(cache) or extent <= 0:
        raise ValueError('Invalid registry mapping geometry')
    matches = []
    for i in range(count):
        va, size, start, maximum, initial = struct.unpack_from('<QQQII', cache, offset+i*32)
        if va <= address and address+extent <= va+size:
            if (maximum, initial) != (1, 1):
                raise ValueError('Registry must occupy a strictly read-only mapping')
            matches.append(start+address-va)
    if len(matches) != 1 or matches[0]+extent > len(cache):
        raise ValueError('Registry is not within one cache mapping')
    start = matches[0]
    original = plistlib.loads(cache[start:start+extent])
    if original.get('VersionNumber') != 4 or not isinstance(original.get('LaunchDaemons'), dict):
        raise ValueError('Unrecognized XPC registry')
    registry = {k: v for k, v in original.items() if not k.endswith('Padding')}
    registry['LaunchDaemons'] = copy.deepcopy(launch_jobs)
    padding = extent
    for _ in range(8):
        if padding < 0:
            raise ValueError('Service registry exceeds its reserved extent')
        registry['_Olsn0wPadding'] = bytes(padding)
        payload = plistlib.dumps(registry, fmt=plistlib.FMT_BINARY, sort_keys=True)
        if len(payload) == extent:
            break
        padding += extent-len(payload)
    if len(payload) != extent or plistlib.loads(payload) != registry:
        raise ValueError('Service registry encoding failed')
    result = bytearray(cache)
    result[start:start+extent] = payload
    if result[:start] != cache[:start] or result[start+extent:] != cache[start+extent:]:
        raise ValueError('Registry edit changed unrelated cache bytes')
    return result
