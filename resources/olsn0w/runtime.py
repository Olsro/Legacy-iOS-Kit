"""Install and check the private Python environment before device operations."""
from importlib import import_module, metadata
import os
from pathlib import Path
import subprocess
import sys

SOURCE = Path(__file__).resolve().parent


def check():
    if sys.version_info < (3, 8):
        raise RuntimeError('olsn0w requires Python 3.8 or newer')
    import_module('pip')
    for requirement in (SOURCE / 'requirements.txt').read_text().splitlines():
        name, expected = requirement.split('==')
        if metadata.version(name) != expected:
            raise RuntimeError('olsn0w requires ' + requirement)
    # Importing metadata alone does not check the bundled native libraries.
    import_module('capstone').cs_version()
    import_module('unicorn').uc_version()
    import_module('usb.core')
    aes = import_module('Crypto.Cipher.AES')
    aes.new(bytes(16), aes.MODE_ECB).encrypt(bytes(16))


def healthy(python):
    try:
        return subprocess.run([str(python), str(SOURCE / 'runtime.py')],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except OSError:
        return False


def ensure_runtime(state):
    runtime = state / 'runtime'
    python = runtime / 'bin/python'
    if not healthy(python):
        print('Installing or repairing the olsn0w Python environment…', file=sys.stderr, flush=True)
        result = subprocess.run(['sh', str(SOURCE / 'setup.sh')])
        if result.returncode or not healthy(python):
            raise RuntimeError('Could not prepare the olsn0w Python environment; see the installation error above. '
                               'Run olsn0w again to retry.')
    if Path(sys.prefix).resolve() != runtime.resolve():
        os.execv(str(python), [str(python), str(SOURCE / 'olsn0w.py'), *sys.argv[1:]])


if __name__ == '__main__':
    try:
        check()
    except Exception as error:
        print('olsn0w Python environment: ' + str(error), file=sys.stderr)
        sys.exit(1)
