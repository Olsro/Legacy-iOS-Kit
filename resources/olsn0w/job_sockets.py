"""Keep local launchd sockets independent of DNS during startup."""
import plistlib


def numeric_loopback_sockets(content):
    job = plistlib.loads(content)
    changed = False
    for name, value in job.get('Sockets', {}).items():
        entries = value if isinstance(value, list) else [value]
        result = []
        for entry in entries:
            family = entry.get('SockFamily')
            if entry.get('SockNodeName') != 'localhost' or family not in (None, 'IPv4', 'IPv6'):
                result.append(entry)
                continue
            # Retain both address families when the stock job leaves it open.
            # Resolving localhost through DNS can deadlock services which are
            # themselves needed to start mDNSResponder and Wi-Fi.
            addresses = {'IPv4': ('127.0.0.1',), 'IPv6': ('::1',)}.get(family, ('127.0.0.1', '::1'))
            result.extend(dict(entry, SockNodeName=address) for address in addresses)
            changed = True
        job['Sockets'][name] = result if isinstance(value, list) or len(result) != 1 else result[0]
    return plistlib.dumps(job, fmt=plistlib.FMT_BINARY) if changed else content
