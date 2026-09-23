"""Select the RAM writer independently of the signed OS and gas-gauge policy."""
from common import profile, version


def selected_build(product, release=None):
    model = profile(product)
    if model.get('multipatch') or (release is not None and
            model['soc'].startswith('a5') and version(release)[0] == 6):
        return '10B329'
    return '12H321'


def checked_build(product, build):
    if build not in ('10B329', '12H321'):
        raise ValueError('Unknown restore RAM environment')
    model = profile(product)
    if build == '10B329' and not model['soc'].startswith('a5'):
        raise ValueError('Native iOS 6 restore RAM is restricted to A5-family devices')
    if model.get('multipatch') and build != '10B329':
        raise ValueError('The iPhone 4S requires its gas-gauge multipatch environment')
    return build


def report_build(report):
    product = report['product']
    if report.get('multipatch') is not bool(profile(product).get('multipatch')):
        raise ValueError('Restore RAM multipatch policy differs from selected model')
    return checked_build(product, report.get('restore_environment_build', selected_build(product)))


def session_build(session):
    import json
    from pathlib import Path
    session = Path(session)
    record = json.loads((session/'device.json').read_text())
    report = json.loads((session/'rescue-preparation.json').read_text())
    if report['product'] != record['identity']['product']:
        raise ValueError('Prepared RAM rescue belongs to another product')
    return report_build(report)
