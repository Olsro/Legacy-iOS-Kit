from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import devicetree


def node(name, children=(), **properties):
    properties = dict(name=name.encode()+b'\0', **properties)
    data = struct.pack('<II', len(properties), len(children))
    for key, value in properties.items():
        data += key.encode().ljust(32, b'\0')+struct.pack('<I', len(value))
        data += value+b'\0'*(-len(value) % 4)
    return data+b''.join(children)


class DeviceTreeTests(unittest.TestCase):
    def test_tristar_soft_reset_is_added_only_to_the_tristar_node(self):
        raw = node('device-tree', [node('arm-io', [node('i2c0', [
            node('tristar', compatible=b'tristar,ths7383\0')])])])
        result = devicetree.add_tristar_soft_reset(raw)
        nodes = {n['path']: {p['name']: bytes(p['value']) for p in n['properties']}
                 for n in devicetree.parse(result)}
        self.assertEqual(nodes['/device-tree/arm-io/i2c0/tristar']['soft-reset'], b'')
        self.assertEqual(sum('soft-reset' in props for props in nodes.values()), 1)
        with self.assertRaises(ValueError):
            devicetree.add_tristar_soft_reset(result)

    def test_missing_or_ambiguous_tristar_node_is_rejected(self):
        for raw in (node('device-tree', [node('arm-io')]),
                    node('device-tree', [node('a', [node('tristar')]), node('b', [node('tristar')])])):
            with self.assertRaises(ValueError):
                devicetree.add_tristar_soft_reset(raw)


if __name__ == '__main__':
    unittest.main()
