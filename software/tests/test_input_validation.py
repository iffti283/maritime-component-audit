"""Verifier and compact-reader behaviour at the release profile boundaries."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from compact_proof import pack, unpack
from evaluate import fixture_salts, synthetic
from sbom_disclosure import LEGACY_PROFILE, commit, disclose, verify


class InputValidation(unittest.TestCase):
    def setUp(self):
        self.document = synthetic(5)
        self.positions = [0, 4]
        self.seeds = fixture_salts(5)
        self.anchor, tree = commit(self.document, self.seeds)
        self.proof = disclose(self.document["components"], self.seeds, tree,
                              self.positions, "batch", self.anchor)

    def test_requested_positions_are_a_set(self):
        self.assertTrue(verify(self.anchor, self.proof, [4, 0]))
        for positions in ([0, 3], [4, 4], [], [0, 5]):
            with self.subTest(positions=positions), self.assertRaises(ValueError):
                verify(self.anchor, self.proof, positions)

    def test_records_must_be_in_position_order(self):
        bad = {**self.proof, "records": list(reversed(self.proof["records"]))}
        with self.assertRaises(ValueError):
            verify(self.anchor, bad, self.positions)

    def test_same_height_count_is_bound(self):
        self.assertFalse(verify({**self.anchor, "componentCount": 6}, self.proof, self.positions))

    def test_digest_and_salt_widths(self):
        for n in (15, 17):
            proof = deepcopy(self.proof)
            proof["records"][0]["salt"] = "00" * n
            with self.subTest(salt_bytes=n), self.assertRaises(ValueError):
                verify(self.anchor, proof, self.positions)
        for n in (31, 33):
            proof = deepcopy(self.proof)
            proof["siblings"][0] = "00" * n
            with self.subTest(hash_bytes=n), self.assertRaises(ValueError):
                verify(self.anchor, proof, self.positions)

    def test_binary_framing(self):
        wire = pack(self.proof)
        for label, data in (("missing mode", b""), ("unknown mode", bytes([3])+wire[1:]),
                            ("incomplete length", wire[:3]), ("incomplete frontier", wire[:-1]),
                            ("trailing data", wire+b"0")):
            with self.subTest(label=label), self.assertRaises(ValueError):
                unpack(data, 5, self.positions)

    def test_legacy_requires_explicit_opt_in(self):
        anchor, tree = commit(self.document, self.seeds, LEGACY_PROFILE)
        proof = disclose(self.document["components"], self.seeds, tree, self.positions, "batch", anchor)
        with self.assertRaises(ValueError):
            verify(anchor, proof, self.positions)
        self.assertTrue(verify(anchor, proof, self.positions, allow_legacy=True))
