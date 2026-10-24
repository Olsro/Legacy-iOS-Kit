"""Enable network/password SSH on an already restored olsn0w target over USB."""
from contextlib import contextmanager
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
import tempfile
import time
import uuid

from common import MODELS, STATE, hardware_model, integer, tools
from restore_run import target_prefix

CONFIGS = ('/etc/ssh/sshd_config', '/usr/local/share/olsn0w/sshd_config')
MASTER = '/etc/master.passwd'
JOB = '/Library/LaunchDaemons/org.olsn0w.sshd.plist'
# Traditional iOS DES crypt("alpine", "/s"). Only root is reset.
ALPINE_HASH = '/smx7MYTQIi2M'
ROOT_CHECK = ('if command -v id >/dev/null 2>&1; then id -u; '
              'elif test "$EUID" = 0 && test "$UID" = 0; then echo 0; '
              'else exit 1; fi')
RESTART_SSH = ('if /bin/launchctl list com.openssh.sshd >/dev/null 2>&1; then '
               'if /bin/launchctl list org.olsn0w.sshd >/dev/null 2>&1; then '
               '/bin/launchctl unload -w '+JOB+' || exit 1; fi; '
               '/bin/launchctl stop com.openssh.sshd; '
               'else /bin/launchctl stop org.olsn0w.sshd; fi')


def external_config(data):
    text = data.decode()
    replaced = {'port', 'listenaddress', 'addressfamily', 'permitrootlogin',
                'passwordauthentication', 'pubkeyauthentication', 'authorizedkeysfile'}
    key_paths = ['.ssh/authorized_keys', '.ssh/authorized_keys2']
    lines = []
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0].lower() in {'match', 'include'}:
            raise ValueError('Conditional/custom SSH configuration needs manual configuration')
        if fields and fields[0].lower() == 'authorizedkeysfile':
            key_paths = shlex.split(line, comments=True)[1:]
        if not fields or fields[0].lower() not in replaced:
            lines.append(line)
    if '/etc/ssh/olsn0w_authorized_keys' not in key_paths:
        key_paths.insert(0, '/etc/ssh/olsn0w_authorized_keys')
    return ('Port 22\nAddressFamily any\nListenAddress 0.0.0.0\nListenAddress ::\nPermitRootLogin yes\n'
            'PasswordAuthentication yes\nPubkeyAuthentication yes\nAuthorizedKeysFile '+
            ' '.join('"'+path.replace('"', '\\"')+'"' if ' ' in path else path for path in key_paths)+
            '\n'+'\n'.join(lines)+'\n').encode()


def root_password(data):
    lines = data.decode().splitlines(keepends=True)
    roots = [i for i, line in enumerate(lines) if line.startswith('root:')]
    if len(roots) != 1:
        raise ValueError('Expected exactly one root account in master.passwd')
    index = roots[0]
    fields = lines[index].rstrip('\r\n').split(':')
    if len(fields) != 10 or fields[2] != '0':
        raise ValueError('Unexpected iOS root account format')
    fields[1] = ALPINE_HASH
    lines[index] = ':'.join(fields) + '\n'
    return ''.join(lines).encode()


def device_info(udid, product, ecid=None):
    if not re.fullmatch(r'[a-fA-F0-9]{40}', udid or ''):
        raise ValueError('Select a normal-mode device with a valid USB UDID')
    # Simple lockdown works even if the device has not trusted this host.
    result = subprocess.run([str(tools()/'ideviceinfo'), '-u', udid, '-s', '-x'],
                            capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Cannot read the selected USB device identity')
    info = plistlib.loads(result.stdout)
    if (info.get('UniqueDeviceID', '').lower() != udid.lower() or
            info.get('ProductType', product) != product):
        raise ValueError('Connected device differs from the selected product/UDID')
    chip = integer(info['UniqueChipID'])
    if ecid is not None and chip != integer(ecid):
        raise ValueError('Connected device differs from the selected ECID')
    return dict(product=product, ecid=chip, version=info['ProductVersion'],
                build=info['BuildVersion'])


def candidates(info, bundle=None, state=STATE):
    paths = ([Path(bundle)/'manifest.json'] if bundle is not None else
             sorted(Path(state).glob('sessions/*/provision/target/manifest.json'),
                    key=lambda p: p.stat().st_mtime, reverse=True))
    found = []
    for path in paths:
        try:
            report = json.loads(path.read_text())
            if (any(report.get(k) != info[k] for k in ('product', 'version', 'build')) or
                    report.get('identity', {}).get('ecid') != info['ecid']):
                continue
            for name in ('ssh_client_rsa', 'ssh_host_rsa_key.pub'):
                if hashlib.sha256((path.parent/name).read_bytes()).hexdigest() != report['files'][name]:
                    raise ValueError('Saved target SSH key differs from its manifest')
            if not re.fullmatch(r'[a-fA-F0-9-]{32,36}', report['generation']):
                raise ValueError('Invalid saved target generation')
        except (OSError, KeyError, json.JSONDecodeError) as error:
            if bundle is not None:
                raise ValueError('Cannot read the selected target bundle') from error
            continue
        found.append((path.parent, report))
    if not found:
        raise ValueError('No matching olsn0w target SSH keys found. Use the original Kit folder '
                         'or supply --bundle pointing to its device-bound target bundle.')
    return found


class Connection:
    def __init__(self, prefix):
        self.prefix = prefix

    def check_password_client(self):
        # Parse the real password-verification command without connecting. In
        # particular, sshpass must be able to execute the selected SSH binary
        # before we change any target files or restart its listener.
        prefix = [self.prefix[0], '-G', *self.prefix[1:]]
        try:
            Connection(prefix).run('', timeout=15, password=True)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            raise RuntimeError('Cannot run the host password SSH verifier (sshpass/ssh). '
                               'Target configuration left unchanged. '+str(error)) from error

    def run(self, command, data=None, timeout=30, password=False):
        prefix = self.prefix
        env = None
        if password:
            # Explicitly disable public keys to prove root/alpine really works.
            prefix = [str(tools()/'sshpass'), '-e',
                      *('BatchMode=no' if x == 'BatchMode=yes' else x for x in prefix)]
            prefix[-1:-1] = ['-o', 'PubkeyAuthentication=no',
                              '-o', 'PreferredAuthentications=password',
                              '-o', 'NumberOfPasswordPrompts=1']
            env = dict(os.environ, SSHPASS='alpine')
        result = subprocess.run(prefix+[command], input=data, capture_output=True,
                                timeout=timeout, env=env)
        if result.returncode:
            raise RuntimeError('Target SSH command failed: '+result.stderr.decode(errors='replace')[-1000:])
        return result.stdout

    def read(self, path):
        q = shlex.quote(path)
        return self.run('test -f '+q+' && test ! -L '+q+' && /bin/cat '+q)


@contextmanager
def connect(udid, bundle):
    with tempfile.TemporaryDirectory(prefix='olsn0w-ssh-') as temporary:
        directory = Path(temporary)
        for name in ('ssh_client_rsa', 'ssh_host_rsa_key.pub'):
            shutil.copyfile(bundle/name, directory/name)
            (directory/name).chmod(0o600)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        prefix = target_prefix(directory, port)
        bundled = tools()/'ssh'
        if bundled.is_file():
            prefix[0] = str(bundled)
        prefix[-1:-1] = ['-o', 'KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1']
        with (directory/'iproxy.log').open('wb') as log:
            process = subprocess.Popen([str(tools()/'iproxy'), '-u', udid, '-s',
                '127.0.0.1', str(port)+':22'], stdout=log, stderr=subprocess.STDOUT)
            try:
                time.sleep(.5)
                if process.poll() is not None:
                    raise RuntimeError('Cannot start the selected device USB tunnel')
                yield Connection(prefix)
            finally:
                from usb_tunnel import stop
                stop(process)


def check_target(connection, report):
    connection.run('/usr/local/libexec/olsn0w/guard-target.sh')
    expected = [hardware_model(MODELS[report['product']][0]), report['build'], report['generation']]
    actual = connection.run('/usr/sbin/sysctl -n hw.model; /usr/sbin/sysctl -n kern.osversion; '
                            '/bin/cat /var/lib/olsn0w/generation').decode().splitlines()
    if actual != expected or connection.run(ROOT_CHECK).strip() != b'0':
        raise ValueError('SSH target is not the selected installed olsn0w system')
    job = plistlib.loads(connection.read(JOB))
    if (job.get('Label') != 'org.olsn0w.sshd' or job.get('ProgramArguments') !=
            ['/usr/sbin/sshd', '-D', '-e', '-f', CONFIGS[1]] or not job.get('KeepAlive')):
        raise ValueError('Unexpected olsn0w OpenSSH service')


def apply(connection):
    originals = {path: connection.read(path) for path in (*CONFIGS, MASTER)}
    updated = {path: external_config(originals[path]) for path in CONFIGS}
    updated[MASTER] = root_password(originals[MASTER])
    # iOS uses flat password files. Refuse an unfamiliar account database rather
    # than changing only one of its representations.
    connection.run('test ! -e /etc/pwd.db && test ! -e /etc/spwd.db && '
                   '{ /bin/launchctl list org.olsn0w.sshd >/dev/null 2>&1 || '
                   '/bin/launchctl list com.openssh.sshd >/dev/null 2>&1; }')
    backup = '/var/lib/olsn0w/ssh-external-'+uuid.uuid4().hex
    connection.run('umask 077; /bin/mkdir '+backup)
    for index, (path, data) in enumerate(updated.items()):
        q = shlex.quote(path)
        connection.run('/bin/cp -p '+q+' '+backup+'/'+str(index)+'.original && '
                       '/bin/cat > '+backup+'/'+str(index)+'.new', data)
        if connection.read(backup+'/'+str(index)+'.original') != originals[path]:
            raise RuntimeError('Backup readback failed; target configuration left unchanged')
        if connection.read(backup+'/'+str(index)+'.new') != data:
            raise RuntimeError('Staged file readback failed; target configuration left unchanged')
    for index in range(2):
        connection.run('/usr/sbin/sshd -t -f '+backup+'/'+str(index)+'.new')
    # Each replacement is renamed on the System filesystem. On any failure,
    # restore all three originals before leaving the current SSH session.
    rollback = '\n'.join('/bin/cp -p '+backup+'/'+str(i)+'.original '+shlex.quote(path)
                         for i, path in enumerate(updated))
    script = 'set -eu\n/sbin/mount -u -w /\nrollback() {\n'+rollback+'\n/bin/sync\n}\n'
    script += "trap 'rollback' 0\ntrap 'exit 1' 1 2 15\n"
    for index, path in enumerate(updated):
        q = shlex.quote(path)
        pending = shlex.quote(path+'.'+backup.rsplit('/', 1)[1])
        script += ('test ! -e '+pending+' && test ! -L '+pending+'\n'
                   '/bin/cp -p '+backup+'/'+str(index)+'.original '+pending+'\n'
                   '/bin/cat '+backup+'/'+str(index)+'.new > '+pending+'\n'
                   '/bin/mv -f '+pending+' '+q+'\n')
    script += '/bin/sync\ntrap - 0 1 2 15\n'
    connection.run('/bin/sh -s', script.encode())
    try:
        for path, data in updated.items():
            if connection.read(path) != data:
                raise RuntimeError('Configuration readback failed')
    except Exception:
        connection.run('/bin/sh -s', ('set -e\n'+rollback+'\n/bin/sync\n').encode())
        raise
    return backup


def configure(product, udid, ecid=None, bundle=None, progress=print):
    info = device_info(udid, product, ecid)
    selected = None
    # Probe matching saved generations without writes. Old sessions may belong to
    # the same hardware/build but contain a different installation's key.
    for folder, report in candidates(info, bundle):
        try:
            with connect(udid, folder) as connection:
                check_target(connection, report)
            selected = folder, report
            break
        except (RuntimeError, ValueError, subprocess.TimeoutExpired):
            continue
    if selected is None:
        raise RuntimeError('Cannot authenticate the installed target with the saved olsn0w keys')
    folder, report = selected
    with connect(udid, folder) as connection:
        check_target(connection, report)
        connection.check_password_client()
        progress('Saving the original configuration and enabling root/alpine network SSH.')
        backup = apply(connection)
        try:
            # Cydia's socket-activated service reads /etc/ssh/sshd_config on
            # every connection. Keep one owner of port 22 when it is installed.
            connection.run(RESTART_SSH)
        except (RuntimeError, subprocess.TimeoutExpired):
            pass  # Stopping the listener can close the current SSH channel.
        for attempt in range(10):
            try:
                result = connection.run(ROOT_CHECK, password=True)
                if result.strip() != b'0':
                    raise RuntimeError('Password SSH did not yield a root session')
                if connection.run(ROOT_CHECK).strip() != b'0':
                    raise RuntimeError('The existing olsn0w SSH key no longer works')
                break
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                if attempt == 9:
                    raise RuntimeError('SSH configuration was applied, but could not verify password and key '
                                       'logins after restarting OpenSSH. Network SSH may already be enabled. '
                                       'Originals are saved on the device in '+backup+
                                       '\nLast SSH error: '+str(error)) from error
                time.sleep(1)
        progress('OpenSSH verified: root / alpine, TCP port 22 on all network interfaces. '
                 'The existing USB SSH key remains valid. Backup: '+backup)
        try:
            addresses = connection.run('if command -v ifconfig >/dev/null 2>&1; then '
                                       'ifconfig en0 2>/dev/null; fi; true').decode()
        except (RuntimeError, subprocess.TimeoutExpired):
            return  # Address discovery is optional after both logins passed.
        for address in re.findall(r'\binet (\d+\.\d+\.\d+\.\d+)', addresses):
            progress('Wi-Fi connection: ssh root@'+address)
