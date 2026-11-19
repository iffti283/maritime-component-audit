"""Reproduce the byte counts, verifier timings and adversarial tests in the paper."""
import argparse
import copy
import csv
import gzip
import math
from pathlib import Path
import random
from statistics import median
from time import perf_counter_ns

from sbom_disclosure import (attach, commit, disclose, encode, IDENTITY, parse_json,
                             read, read_receipt, verify, write)

MODES = ("full", "individual", "batch")
TRIALS = 12


def synthetic(count):
    rng = random.Random(1729 + count)
    components = []
    for index in range(count):
        name = f"audit-fixture-{index:04d}"
        version = f"1.{rng.randrange(50)}.{rng.randrange(100)}"
        components.append({
            "type": "library", "name": name, "version": version, "bom-ref": name,
            "purl": f"pkg:generic/{name}@{version}",
            "hashes": [{"alg": "SHA-256", "content": f"{rng.getrandbits(256):064x}"}],
        })
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "serialNumber": "urn:uuid:803cbbea-53ee-4c19-be0a-127710581f11",
            "version": 1, "metadata": {}, "components": components}


def fixture_salts(count):
    rng = random.Random(1147 + count)
    return [f"{rng.getrandbits(128):032x}" for _ in range(count)]


def acceptance(anchor, proof, requested):
    try:
        return verify(anchor, proof, requested)
    except (KeyError, ValueError, TypeError):
        return False


def test_cases():
    document = synthetic(9)
    salts = fixture_salts(9)
    anchor, tree = commit(document, salts)
    attached = attach(document, anchor)
    receipt = {**{key: document[key] for key in IDENTITY},
               "metadata": encode(attached["metadata"]).decode()}
    assert read_receipt(receipt) == anchor

    def bad_receipt():
        try:
            read_receipt({**receipt, "version": 2})
        except ValueError:
            return True
        return False

    def duplicate_json():
        try:
            parse_json('{"version":1,"version":2}')
        except ValueError:
            return True
        return False

    checks = [{"case": "receipt_round_trip", "mode": "metadata", "passed": True},
              {"case": "receipt_identity_mismatch", "mode": "metadata", "passed": bad_receipt()},
              {"case": "duplicate_json_keys", "mode": "parser", "passed": duplicate_json()}]
    requested = [0, 4, 8]

    def record(case, mode, passed):
        checks.append({"case": case, "mode": mode, "passed": bool(passed)})

    for mode in MODES:
        proof = disclose(document["components"], salts, tree, requested, mode, anchor)
        record("valid_disclosure", mode, acceptance(anchor, proof, requested))
        record("other_revision", mode, not acceptance({**anchor, "version": 2}, proof, requested))
        record("altered_count", mode, not acceptance({**anchor, "componentCount": 10}, proof, requested))
        record("other_serial", mode, not acceptance(
            {**anchor, "serialNumber": "urn:uuid:018f815c-d85c-75a1-ad2c-58f0b505306e"},
            proof, requested))
        changed = copy.deepcopy(proof)
        changed["records"][0]["component"]["version"] = "9.9.9"
        record("modified_component", mode, not acceptance(anchor, changed, requested))
        changed = copy.deepcopy(proof)
        changed["records"][0]["salt"] = "00" * 16
        record("modified_salt", mode, not acceptance(anchor, changed, requested))
        changed = copy.deepcopy(proof)
        changed["records"][0]["index"] = 1
        record("modified_position", mode, not acceptance(anchor, changed, requested))
        changed = copy.deepcopy(proof)
        del changed["records"][0]
        record("omitted_record", mode, not acceptance(anchor, changed, requested))
        if mode != "full":
            record("different_requested_positions", mode, not acceptance(anchor, proof, [1, 4, 8]))
            changed = copy.deepcopy(proof)
            path = changed["siblings"] if mode == "batch" else changed["records"][0]["siblings"]
            path[0] = "00" * 32
            record("modified_sibling", mode, not acceptance(anchor, changed, requested))
            path.pop()
            record("truncated_proof", mode, not acceptance(anchor, changed, requested))
    for count in (1, 2, 3, 5, 8, 9, 17):
        sample = synthetic(count)
        prepared = fixture_salts(count)
        sample_anchor, sample_tree = commit(sample, prepared)
        for mode in MODES:
            positions = list(range(count))
            proof = disclose(sample["components"], prepared, sample_tree, positions, mode, sample_anchor)
            record(f"all_{count}_positions", mode, acceptance(sample_anchor, proof, positions))
    assert all(check["passed"] for check in checks), checks
    return checks


def run_sample(name, document):
    components = document["components"]
    count = len(components)
    salts = fixture_salts(count)
    anchor, tree = commit(document, salts)
    for k in (1, math.ceil(count * 0.05), math.ceil(count * 0.25), count):
        for layout in ("random", "contiguous"):
            rng = random.Random(6007 + count * 101 + k)
            for trial in range(TRIALS):
                if layout == "contiguous":
                    start = rng.randrange(count - k + 1)
                    selected = list(range(start, start + k))
                else:
                    selected = sorted(rng.sample(range(count), k))
                proofs = {mode: disclose(components, salts, tree, selected, mode, anchor) for mode in MODES}
                order = MODES[trial % len(MODES):] + MODES[:trial % len(MODES)]
                for mode in order:
                    proof = proofs[mode]
                    payload = encode(proof)
                    timed = []
                    for _ in range(5):
                        start_time = perf_counter_ns()
                        valid = verify(anchor, proof, selected)
                        timed.append(perf_counter_ns() - start_time)
                        if not valid:
                            raise RuntimeError(f"valid proof rejected in {name}/{mode}")
                    if mode == "full":
                        sibling_count = 0
                    elif mode == "individual":
                        sibling_count = sum(len(row["siblings"]) for row in proof["records"])
                    else:
                        sibling_count = len(proof["siblings"])
                    yield {
                        "dataset": name, "n": count, "k": k, "layout": layout, "trial": trial,
                        "mode": mode, "records_sent": len(proof["records"]), "siblings": sibling_count,
                        "json_bytes": len(payload),
                        "gzip_bytes": len(gzip.compress(payload, compresslevel=6, mtime=0)),
                        "verify_ns": median(timed),
                    }


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results"))
    parser.add_argument("--upstream-fixture", type=Path)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=True, parents=True)
    checks = test_cases()
    write(args.output / "conformance.json", checks)
    groups = [(f"synthetic-{count}", synthetic(count)) for count in (64, 256, 1024)]
    if args.upstream_fixture:
        groups.append(("upstream-fixture", read(args.upstream_fixture)))
    with (args.output / "benchmark.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = None
        for name, document in groups:
            for row in run_sample(name, document):
                if writer is None:
                    writer = csv.DictWriter(stream, list(row))
                    writer.writeheader()
                writer.writerow(row)
    print(f"{len(checks)} conformance checks passed across {len(groups)} datasets.")


if __name__ == "__main__":
    run()
