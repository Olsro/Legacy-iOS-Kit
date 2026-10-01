"""Apply the existing Hacktiv8 recipes to one connected, root-SSH device."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import uuid

from common import KIT, tools
import hacktiv8

ROOT_CHECK = ('if command -v id >/dev/null 2>&1; then id -u; '
              'elif test "$EUID" = 0 && test "$UID" = 0; then echo 0; '
              'else exit 1; fi')

class SSHUnavailable(RuntimeError):
    pass


def device_info(udid):
    result = subprocess.run([str(tools()/'ideviceinfo'), '-u', udid, '-x'],
                            capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Unlock/pair the selected device before using Hacktiv8.')
    return plistlib.loads(result.stdout)


def require_identity(info, product, release, build, udid):
    if tuple(info.get(k) for k in ('ProductType', 'ProductVersion',
                                   'BuildVersion', 'UniqueDeviceID')) != (product, release, build, udid):
        raise ValueError('Connected device identity/version differs from the menu selection')


def patched_bytes(method, original, product, build):
    if method == 'lockdownd-patch':
        return hacktiv8.patch_lockdownd(original, product, build, sign=True)[0]
    if method == 'mobilegestalt-flag':
        return hacktiv8._patch_gestalt(original)
    if method == 'mobilegestalt-profile':
        return hacktiv8._profile(product, build)
    raise ValueError('Unsupported Hacktiv8 method; no device changes made')


class Connection:
    def __init__(self, udid, directory, password):
        self.udid, self.directory = udid, directory
        self.password = password
        self.process = None

    def __enter__(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.log = (self.directory/'iproxy.log').open('ab')
        try:
            self.process = subprocess.Popen([str(tools()/'iproxy'), '-u', self.udid,
                '-s', '127.0.0.1', str(port)+':22'], stdout=self.log, stderr=subprocess.STDOUT)
        except OSError:
            self.log.close()
            raise
        ssh = tools()/'ssh'
        if not ssh.is_file():
            ssh = shutil.which('ssh')
        self.prefix = [str(tools()/'sshpass'), '-e', str(ssh), '-F', '/dev/null',
            '-p', str(port), '-o', 'ConnectTimeout=5', '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'PreferredAuthentications=password,keyboard-interactive',
            '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'HostKeyAlias=hacktiv8-'+self.udid,
            '-o', 'UserKnownHostsFile='+str(self.directory.parent/'known_hosts'),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'HostKeyAlgorithms=+ssh-rsa',
            '-o', 'KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1',
            'root@127.0.0.1']
        time.sleep(.5)
        if self.process.poll() is not None:
            self.log.close()
            raise RuntimeError('USB tunnel could not start; inspect iproxy.log. No device changes made.')
        return self

    def __exit__(self, *args):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait()
        self.log.close()

    def run(self, command, data=None, timeout=20):
        result = subprocess.run(self.prefix+[command], input=data, capture_output=True,
                                timeout=timeout, env=dict(os.environ, SSHPASS=self.password))
        if result.returncode:
            error = result.stderr.decode(errors='replace')[-1200:]
            raise RuntimeError('Device SSH command failed: '+error)
        return result.stdout

    def read(self, path):
        name = shlex.quote(path)
        return self.run('test -f '+name+' && test ! -L '+name+' && /bin/cat '+name)


def apply(connection, directory, product, release, build):
    method = hacktiv8.technique(release, product, build)
    if method is None:
        raise ValueError('No Hacktiv8 recipe for this device/build')
    if connection.run(ROOT_CHECK).strip() != b'0':
        raise ValueError('A root jailbreak session is required')
    system = plistlib.loads(connection.read('/System/Library/CoreServices/SystemVersion.plist'))
    if (system.get('ProductVersion'), system.get('ProductBuildVersion')) != (release, build):
        raise ValueError('SSH target system differs from the selected release')
    if connection.run('/usr/sbin/sysctl -n hw.machine').strip().decode() != product:
        raise ValueError('SSH target model differs from selection')
    if hacktiv8.version(release) >= (5,):
        connection.run('test -d /Applications/Setup.app')
    else:
        connection.run('test -d /Applications/Setup.app || '
                       '{ test ! -e /Applications/Setup.app && test ! -L /Applications/Setup.app; }')
    target = hacktiv8.LOCKDOWN if method == 'lockdownd-patch' else hacktiv8._gestalt_target(release)
    original = connection.read(target)
    (directory/'original').write_bytes(original)
    patched = patched_bytes(method, original, product, build)
    (directory/'patched').write_bytes(patched)
    report = dict(product=product, version=release, build=build, method=method,
                  target=target, original_sha256=hashlib.sha256(original).hexdigest(),
                  patched_sha256=hashlib.sha256(patched).hexdigest(),
                  changed=patched != original, verified=False)
    journal = directory/'result.json'
    journal.write_text(json.dumps(report, indent=2)+'\n')
    if patched == original:
        report.update(verified=True, already_applied=True)
        journal.write_text(json.dumps(report, indent=2)+'\n')
        return report
    backup = target+'.hacktiv8-original'
    q, b = shlex.quote(target), shlex.quote(backup)
    # Never overwrite an earlier recovery copy or another pending transaction.
    present = connection.run('if test -e '+b+' || test -L '+b+'; then echo yes; fi').strip()
    if present and connection.read(backup) != original:
        raise ValueError('Existing Hacktiv8 backup conflicts; retained without changes')
    if method == 'lockdownd-patch':
        connection.run('/sbin/mount -u -w /')
    if connection.read(target) != original:
        raise ValueError('Target changed during preparation; refusing to overwrite it')
    connection.run('test ! -L '+b+' && if test ! -e '+b+'; then /bin/cp -p '+q+' '+b+'; fi')
    if connection.read(backup) != original:
        raise ValueError('Original backup readback failed; target left unchanged')
    pending = target+'.hacktiv8-'+uuid.uuid4().hex
    p = shlex.quote(pending)
    connection.run('test ! -e '+p+' && /bin/cp -p '+q+' '+p+' && /bin/cat > '+p, patched)
    if connection.read(pending) != patched:
        raise ValueError('Staged patch readback failed; target left unchanged')
    if connection.read(target) != original:
        raise ValueError('Target changed before commit; target left unchanged')
    connection.run('/bin/mv -f '+p+' '+q+' && /bin/sync')
    if connection.read(target) != patched:
        connection.run('/bin/cp -p '+b+' '+q+' && /bin/sync')
        raise ValueError('Installed patch readback failed; original restored')
    report.update(verified=True, backup=backup)
    journal.write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('product', 'version', 'build', 'udid'):
        parser.add_argument('--'+key, required=True)
    parser.add_argument('--probe', action='store_true', help='Read-only root SSH check')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-fA-F0-9]{40}', args.udid):
        raise ValueError('Expected a 32-bit device UDID')
    if not hacktiv8.available(args.version, args.product, args.build):
        raise ValueError('Hacktiv8 does not support this device/build; no changes made')
    require_identity(device_info(args.udid), args.product, args.version, args.build, args.udid)
    directory = KIT/'saved/hacktiv8'/args.udid/str(uuid.uuid4())
    directory.mkdir(parents=True, mode=0o700)
    password = os.environ.get('SSHPASS') or getpass.getpass('Root SSH password (Enter: alpine): ') or 'alpine'
    print('Hacktiv8 logs and backup: '+str(directory), flush=True)
    with Connection(args.udid, directory, password) as connection:
        try:
            if connection.run(ROOT_CHECK).strip() != b'0':
                raise RuntimeError('SSH login is not root')
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            raise SSHUnavailable('Root SSH unavailable. This does not prove the device is not jailbroken.\n'+str(error)) from error
        if args.probe:
            print('Root SSH is available; no device changes made.')
            return
        require_identity(device_info(args.udid), args.product, args.version, args.build, args.udid)
        result = apply(connection, directory, args.product, args.version, args.build)
        print('Hacktiv8 file patch verified; Setup.app left unchanged.', flush=True)
        if not result['changed']:
            print('Already applied; no restart requested.')
            return
        # Reboot once, only after the original and replacement passed readback.
        try:connection.run('/sbin/reboot', timeout=15)
        except (RuntimeError, subprocess.TimeoutExpired):pass
    print('Restart requested. Complete Setup Assistant after the device returns.\n'
          'Hacktiv8 is not official activation and does not unlock a carrier or Apple account.')


if __name__ == '__main__':
    try:main()
    except SSHUnavailable as error:
        print(str(error), file=sys.stderr);sys.exit(20)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print('Hacktiv8: '+str(error), file=sys.stderr);sys.exit(1)
    except (EOFError, KeyboardInterrupt):
        print('Hacktiv8 cancelled.', file=sys.stderr);sys.exit(130)
