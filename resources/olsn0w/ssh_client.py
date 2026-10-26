"""Adapt restoration SSH options to older and current OpenSSH clients."""
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

RSA_OPTIONS = ['-o', 'HostKeyAlgorithms=+ssh-rsa',
               '-o', 'PubkeyAcceptedKeyTypes=+ssh-rsa']

# Keep temporary identities alive until process exit. TemporaryDirectory removes
# them then; persisted SSH vectors always retain the original session paths.
_IDENTITIES = {}


@lru_cache(maxsize=None)
def _rsa_options(client):
    # OpenSSH < 7.0 has neither the '+' list syntax nor the client-side
    # PubkeyAcceptedKeyTypes option. It already permits RSA user keys.
    # Put -V LAST: preceding -o arguments are validated before it exits,
    # without connecting or requiring -G (introduced only in OpenSSH 6.8).
    for options in (tuple(RSA_OPTIONS), ('-o', 'HostKeyAlgorithms=ssh-rsa')):
        try:
            result = subprocess.run([client, '-F', '/dev/null', *options, '-V'],
                                    capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError('Cannot check the host SSH client: ' + str(error)) from error
        if result.returncode == 0:
            return options
    raise RuntimeError('The host SSH client cannot parse the required restoration options:\n'
                       + result.stderr.decode(errors='replace')[-2000:])


def rsa_options(client='ssh'):
    # Key the cache by executable so a different SSH selected in PATH is checked.
    return _rsa_options(shutil.which(client) or client)


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
    arguments = iter(prefix)
    for argument in arguments:
        option = argument == '-o'
        if option:
            argument = next(arguments)
        name, separator, value = argument.partition('=')
        if separator and name.lower() == 'pubkeyacceptedalgorithms':
            name = 'PubkeyAcceptedKeyTypes'
            argument = name + '=' + value
        if (separator and name.lower() in ('hostkeyalgorithms', 'pubkeyacceptedkeytypes')
                and value in ('ssh-rsa', '+ssh-rsa')):
            supported = dict(item.split('=', 1) for item in rsa_options(prefix[0]) if item != '-o')
            keyword = 'HostKeyAlgorithms' if name.lower() == 'hostkeyalgorithms' else 'PubkeyAcceptedKeyTypes'
            if keyword not in supported:
                continue
            argument = keyword + '=' + supported[keyword]
        elif separator and name.lower() == 'userknownhostsfile' and not value.startswith('"'):
            # Saved olsn0w prefixes contain exactly one path, previously raw.
            argument = known_hosts_option(value)
        if option:
            result.append('-o')
        result.append(argument)
    return result


def check():
    rsa_options()
    # Qualify a private runtime location before preparation or device erasure.
    private_directory().cleanup()
