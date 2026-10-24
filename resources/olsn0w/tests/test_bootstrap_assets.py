import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from signing import verify
from bootstrap_native import PROGRAMS, configuration
from common import MODELS, hardware_model

class AssetsTest(unittest.TestCase):
    def test_board_revision_configuration_keeps_apple_case(self):
        for product,model in (('iPad2,4','K93aAP'),('iPad3,3','J2aAP'),('iPhone5,2','N42AP')):
            with self.subTest(product=product):
                self.assertEqual(hardware_model(MODELS[product][0]),model)
                self.assertIn(('#define OLSN0W_BOARD "'+model+'"\n').encode(),
                              configuration(product,'0'*40))

    def test_templates_match_sources_and_valid_signatures(self):
        base=Path(__file__).resolve().parents[1];assets=base/'target/bootstrap'
        report=json.loads((assets/'manifest.json').read_text())
        self.assertEqual(hashlib.sha256(configuration('iPad3,4','0'*40)).hexdigest(),
                         report['native_provenance']['configuration_sha256'])
        for root,table in ((base,report['sources']),(assets,report['files'])):
            for name,digest in table.items():self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),digest,name)
        for name in PROGRAMS:
            data=(assets/name).read_bytes();verify(data)
            self.assertEqual(data.count(b'P101AP\0'),1)
            self.assertEqual(data.count(b'0'*40+b'\0'),int(name=='root_start'))
