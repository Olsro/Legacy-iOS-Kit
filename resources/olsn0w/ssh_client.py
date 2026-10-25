"""Use SSH options understood by both High Sierra and current OpenSSH clients."""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile

RSA_OPTIONS = ['-o', 'HostKeyAlgorithms=+ssh-rsa',
               '-o', 'PubkeyAcceptedKeyTypes=+ssh-rsa']

# Keep temporary identities alive until process exit. TemporaryDirectory removes
# them then; persisted SSH vectors always retain the original session paths.
_IDENTITIES = {}


def private_file(path, mode):
    info = Path(path).stat()
    return (info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == mode
            and (stat.S_ISDIR(info.st_mode) if mode == 0o700
                 else stat.S_ISREG(info.st_mode)))


def private_directory():
    # TMPDIR can itself point at an NTFS/exFAT volume. Check actual permissions
    # before writing any key, and fall back to the host's /tmp if necessary.
    for parent in (None, '/tmp'):
        temporary = None
        try:
            temporary = tempfile.TemporaryDirectory(prefix='olsn0w-identity-', dir=parent)
            directory = Path(temporary.name)
            directory.chmod(0o700)
            if private_file(directory, 0o700):
                return temporary
        except OSError:
            pass
        if temporary is not None:
            temporary.cleanup()
    raise RuntimeError('Cannot create a private SSH identity directory. '
                       'Set TMPDIR to a local filesystem supporting Unix permissions.')


def private_identity(path):
    path = Path(path)
    if private_file(path, 0o600):
        return str(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    if private_file(path, 0o600):
        return str(path)
    data = path.read_bytes()
    digest = hashlib.sha256(data).digest()
    cached = _IDENTITIES.get(digest)
    if cached is not None:
        key = Path(cached.name)/'identity'
        if (private_file(key.parent, 0o700) and private_file(key, 0o600)
                and key.read_bytes() == data):
            return str(key)
    temporary = private_directory()
    key = Path(temporary.name)/'identity'
    try:
        with key.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        if not private_file(key, 0o600):
            raise RuntimeError('Temporary SSH identity does not have private Unix permissions')
    except Exception:
        temporary.cleanup()
        raise
    _IDENTITIES[digest] = temporary
    return str(key)


def runtime_prefix(prefix):
    """Resolve private identities only in memory, including saved preparations."""
    result = compatible_prefix(prefix)
    for index, argument in enumerate(result[:-1]):
        if argument == '-i':
            result[index+1] = private_identity(result[index+1])
    return result


def known_hosts_option(path):
    # OpenSSH parses this option as a list of filenames even when subprocess
    # supplies it in one argv element. Quote for SSH's parser, not a shell.
    value = str(path).replace('\\', '\\\\').replace('"', '\\"')
    return 'UserKnownHostsFile="' + value + '"'


def compatible_prefix(prefix):
    # OpenSSH 8.5 renamed this keyword, retaining the old name as an alias.
    # Older saved preparations must remain usable without regenerating keys.
    result = []
    for argument in prefix:
        name, separator, value = argument.partition('=')
        if separator and name.lower() == 'pubkeyacceptedalgorithms':
            argument = 'PubkeyAcceptedKeyTypes=' + value
        elif separator and name.lower() == 'userknownhostsfile' and not value.startswith('"'):
            # Saved olsn0w prefixes contain exactly one path, previously raw.
            argument = known_hosts_option(value)
        result.append(argument)
    return result


def check():
    # -G parses configuration and exits; it neither opens a connection nor
    # needs a target key. Check before expensive preparation or any erase.
    argv = ['ssh', '-G', '-F', '/dev/null', *RSA_OPTIONS, 'root@127.0.0.1']
    try:
        result = subprocess.run(argv, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError('Cannot check the host SSH client: ' + str(error)) from error
    if result.returncode:
        raise RuntimeError('The host SSH client cannot parse the required restoration options:\n'
                           + result.stderr.decode(errors='replace')[-2000:])
    # Qualify a private runtime location before preparation or device erasure.
    private_directory().cleanup()
