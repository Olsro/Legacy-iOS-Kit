"""Load the private libusb library explicitly instead of relying on host lookup."""


def get_backend():
    try:
        from libusb_package import get_libusb1_backend
        backend = get_libusb1_backend()
    except (ImportError, OSError) as error:
        raise RuntimeError('Could not load the private libusb USB backend. '
                           'Run sh resources/olsn0w/setup.sh from the Kit directory, then retry: '
                           + str(error)) from error
    if backend is None:
        raise RuntimeError('Could not load the private libusb USB backend. '
                           'Run sh resources/olsn0w/setup.sh from the Kit directory, then retry. '
                           'Check the library loading diagnostics above; no USB device was selected.')
    return backend
