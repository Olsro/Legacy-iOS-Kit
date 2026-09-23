"""Build the selected bootstrap with Clang, a Mach-O linker and stock libraries."""
import json
from pathlib import Path
import re

from common import MODELS, digest, run
from restore import checkpoint
from signing import resign

PROGRAMS = ('controller', 'root_start', 'untether_supervisor', 'service_gate', 'power_ready', 'wake', 'wake_a5')
LIBRARIES = ('usr/lib/libSystem.B.dylib',
             'System/Library/Frameworks/CoreFoundation.framework/CoreFoundation',
             'System/Library/Frameworks/IOKit.framework/Versions/A/IOKit')
ENTITLEMENTS = {'platform-application': True, 'get-task-allow': True,
                'task_for_pid-allow': True, 'run-unsigned-code': True}


def configuration(product, usb_serial):
    if product not in MODELS or not re.fullmatch(r'[a-fA-F0-9]{40}', usb_serial):
        raise ValueError('Expected a supported product and selected USB identity')
    return ('#pragma once\n#define OLSN0W_BOARD '+json.dumps(MODELS[product][0].upper())+
            '\n#define OLSN0W_USB_SERIAL '+json.dumps(usb_serial.lower())+'''
#define OLSN0W_DISK_DEFAULT_ROOT
#define OLSN0W_ROOT_MARKER_PATH "/olsn0w/bootstrap.marker"
#define OLSN0W_ROOT_MARKER "olsn0w-bootstrap-v1"
#define OLSN0W_TARGET_MARKER "olsn0w-target-v1"
#define OLSN0W_UNTETHER_MARKER_PATH OLSN0W_ROOT_MARKER_PATH
#define OLSN0W_UNTETHER_MARKER OLSN0W_ROOT_MARKER
''').encode()


def prepare(product, usb_serial, compiler, linker, libraries, destination):
    """No SDK headers or host filesystem mounts; tool paths are caller supplied."""
    config=configuration(product,usb_serial)
    source=Path(__file__).parent/'native/bootstrap'
    libraries,destination=Path(libraries).resolve(),Path(destination).resolve()
    if destination.exists():raise ValueError('Preserve the previous native build')
    for name in LIBRARIES:
        if not (libraries/name).is_file():raise ValueError('Missing stock link library: '+name)
    destination.mkdir(parents=True,mode=0o700)
    (destination/'olsn0w_config.h').write_bytes(config)
    for name in PROGRAMS:
        run([compiler,'-target','armv7-apple-ios8.0','-mthumb','-Os','-fblocks','-nostdinc',
             '-I',destination,'-c',source/(name+'.c'),'-o',destination/(name+'.o')],
            destination/(name+'-compile.log'))
        run([linker,'-arch','armv7','-iphoneos_version_min','8.0','-syslibroot',libraries,
             *[libraries/lib for lib in LIBRARIES],'-o',destination/name,destination/(name+'.o')],
            destination/(name+'-link.log'))
        resign(destination/name,ENTITLEMENTS)
    report=dict(product=product,base_build='12H321',
                configuration_sha256=digest(destination/'olsn0w_config.h'),
                sources={p.name:digest(p) for p in source.iterdir() if p.suffix in ('.c','.h')},
                libraries={name:digest(libraries/name) for name in LIBRARIES},
                files={name:digest(destination/name) for name in PROGRAMS},
                physical_boot_verified=False)
    checkpoint(destination/'manifest.json',report)
    return report
