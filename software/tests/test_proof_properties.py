"""Generated round-trip properties for valid inventory and request shapes."""
from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from compact_proof import pack, unpack
from evaluate import fixture_salts, synthetic
from sbom_disclosure import commit, disclose, verify


class WireProperties(unittest.TestCase):
    def test_generated_membership(self):
        rng = random.Random(18032026)
        sizes = [1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127]
        for n in sizes:
            doc = synthetic(n)
            doc["components"][0]["name"] = "é / 海"
            seeds = fixture_salts(n)
            anchor, tree = commit(doc, seeds)
            for k in (1, max(1, n//2), n):
                positions = sorted(rng.sample(range(n), k))
                for mode in ("full", "individual", "batch"):
                    with self.subTest(n=n, k=k, mode=mode):
                        proof = disclose(doc["components"], seeds, tree, positions, mode, anchor)
                        decoded = unpack(pack(proof), n, positions)
                        self.assertEqual(decoded, proof)
                        self.assertTrue(verify(anchor, decoded, positions))
                        indices = range(n) if mode == "full" else positions
                        self.assertEqual([row["component"] for row in decoded["records"]],
                                         [doc["components"][i] for i in indices])


if __name__ == "__main__":
    unittest.main()
