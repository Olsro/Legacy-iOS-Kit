"""Use SSH options understood by both High Sierra and current OpenSSH clients."""
import subprocess

RSA_OPTIONS = ['-o', 'HostKeyAlgorithms=+ssh-rsa',
               '-o', 'PubkeyAcceptedKeyTypes=+ssh-rsa']


def compatible_prefix(prefix):
    # OpenSSH 8.5 renamed this keyword, retaining the old name as an alias.
    # Older saved preparations must remain usable without regenerating keys.
    result = []
    for argument in prefix:
        name, separator, value = argument.partition('=')
        if separator and name.lower() == 'pubkeyacceptedalgorithms':
            argument = 'PubkeyAcceptedKeyTypes=' + value
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
