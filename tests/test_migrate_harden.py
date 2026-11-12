import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "mp", Path(__file__).parent / ".." / "tools" / "migrate_patterns.py")
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)


class TestHardenSig(unittest.TestCase):
    def test_extends_to_unique(self):
        seen = []

        def scan(toks):
            seen.append(len(toks))
            return [0x100, 0x200] if len(toks) < 4 else [0x100]

        out = mp.harden_sig(["AA", "BB"], 0x100,
                            bytes.fromhex("AA BB CC DD EE"), scan)
        self.assertEqual(out, "AA BB CC DD")
        self.assertEqual(seen, [3, 4])

    def test_unique_hit_must_be_true_rva(self):
        out = mp.harden_sig(["AA", "BB"], 0x100,
                            bytes.fromhex("AA BB CC DD"),
                            lambda toks: [0x200])
        self.assertIsNone(out)

    def test_none_when_cap_reached(self):
        out = mp.harden_sig(["AA"], 0x100, bytes.fromhex("AA BB"),
                            lambda toks: [0x100, 0x200])
        self.assertIsNone(out)

    def test_none_when_no_bytes_left(self):
        out = mp.harden_sig(["AA", "BB"], 0x100, bytes.fromhex("AA BB"),
                            lambda toks: [0x100, 0x200])
        self.assertIsNone(out)


if __name__ == "__main__":
    unittest.main()
