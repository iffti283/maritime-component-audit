"""Reproduce wire-size predictions, full-disclosure controls and the ordering study."""
import csv
import gzip
import hashlib
import hmac
import json
import random
from argparse import ArgumentParser
from collections import defaultdict
from pathlib import Path
from statistics import median, quantiles

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmark import FREEBOARD
from compact_proof import pack, unpack
from evaluate import fixture_salts, synthetic
from sbom_disclosure import commit, disclose, encode, read, verify


SOFTWARE = Path(__file__).resolve().parents[1]


def compressed(value):
    return len(gzip.compress(encode(value), compresslevel=6, mtime=0))


def sibling_count(positions, height):
    # Each occupied parent contributes one sibling when only one child is active.
    active = set(positions)
    count = 0
    for _ in range(height):
        parents = {node // 2 for node in active}
        count += 2 * len(parents) - len(active)
        active = parents
    return count


def verify_cost_model(path):
    groups = defaultdict(lambda: defaultdict(dict))
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            group = (row["dataset"], int(row["n"]), row["fraction"], int(row["k"]), row["layout"])
            groups[group][int(row["trial"])][row["mode"]] = row
    compared = 0
    for (_, n, _, k, layout), trials in groups.items():
        rng = random.Random(9613 + n * 101 + k)
        height = (n - 1).bit_length()
        for trial in sorted(trials):
            if layout == "all":
                selected = list(range(n))
            elif layout == "random":
                selected = sorted(rng.sample(range(n), k))
            else:
                first = rng.randrange(n - k + 1)
                selected = list(range(first, first + k))
            methods = trials[trial]
            digest = hashlib.sha256(encode(selected)).hexdigest()
            assert all(r["position_digest"] == digest for r in methods.values())
            paths, batch = methods["individual"], methods["batch"]
            independent = k * height
            shared = sibling_count(selected, height)
            assert int(paths["siblings"]) == independent and int(batch["siblings"]) == shared
            assert int(paths["binary"]) - int(batch["binary"]) == 32 * (independent - shared)
            compared += 1
    return compared


def full_controls(doc):
    # Fixed public inputs make these measurements reproducible. A deployed supplier
    # would generate an independent, secret master for each release.
    master = hashlib.sha256(b"MCA full-opening measurement fixture").digest()
    def seeds_for(key, count):
        return [hmac.digest(key, b"MCA-seed-v1" + i.to_bytes(4, "big"), "sha256")[:16].hex()
                for i in range(count)]

    records = doc["components"]
    n = len(records)
    seeds = seeds_for(master, n)
    anchor, tree = commit(doc, seeds)
    message = {"mode": "full-seed", "master": master.hex(), "components": records}
    decoded = json.loads(encode(message))
    restored, _ = commit({**doc, "components": decoded["components"]},
                         seeds_for(bytes.fromhex(decoded["master"]), len(decoded["components"])))
    assert restored == anchor
    full = disclose(records, seeds, tree, [0], "full", anchor)
    assert verify(anchor, full, [0])
    secret = hashlib.sha256(b"MCA detached signature measurement fixture").digest()
    key = Ed25519PrivateKey.from_private_bytes(secret)
    canonical = encode(doc)
    signature = key.sign(canonical)
    key.public_key().verify(signature, canonical)
    partial = {}
    for k in (4, 20):
        rng = random.Random(9613 + n * 101 + k)
        sizes = []
        for _ in range(20):
            pos = sorted(rng.sample(range(n), k))
            proof = disclose(records, seeds, tree, pos, "batch", anchor)
            assert verify(anchor, proof, pos)
            sizes.append(compressed(proof))
        partial[str(k)] = sizes
    return {"derived_full_gzip": compressed(message), "explicit_full_same_root_gzip": compressed(full),
            "explicit_seed_array_gzip": compressed({"mode": "full-seeds", "seeds": seeds, "components": records}),
            "derived_batch_gzip": partial, "signed_document_gzip_plus_detached": compressed(doc) + len(signature),
            "signature_bytes": len(signature), "full_document_gzip": compressed(doc),
            "same_anchor_reconstructed": restored == anchor}


def ordering(doc):
    lock = read(SOFTWARE / "inputs/freeboard/package-lock.json")
    names = set(lock["packages"]["node_modules/@signalk/server-api"]["dependencies"])
    records = doc["components"]
    targets = [i for i, r in enumerate(records) if r["bom-ref"] in {"npm:node_modules/" + s for s in names}]
    assert len(targets) == len(names)
    selected = set(targets)
    perms = {"location": list(range(len(records))),
             "grouped": targets + [i for i in range(len(records)) if i not in selected]}
    data = {}
    original_seeds = fixture_salts(len(records))
    for version, (name, perm) in enumerate(perms.items(), 1):
        arr = [records[i] for i in perm]
        positions = [i for i, original in enumerate(perm) if original in selected]
        modified = {**doc, "components": arr, "version": version}
        seeds = [original_seeds[i] for i in perm]
        anchor, tree = commit(modified, seeds)
        proof = disclose(arr, seeds, tree, positions, "batch", anchor)
        assert verify(anchor, proof, positions)
        assert [r["component"] for r in proof["records"]] == [records[i] for i in targets]
        data[name] = {"positions": positions, "siblings": len(proof["siblings"]), "binary_bytes": len(pack(proof))}
    return {"names": sorted(names), "layouts": data}


def scale_case():
    count = 65536
    doc = synthetic(count)
    seeds = fixture_salts(count)
    anchor, tree = commit(doc, seeds)
    pos = sorted(random.Random(9613).sample(range(count), 64))
    sizes = {}
    for mode in ("individual", "batch"):
        proof = disclose(doc["components"], seeds, tree, pos, mode, anchor)
        blob = pack(proof)
        assert verify(anchor, unpack(blob, count, pos), pos)
        sizes[mode] = len(blob)
    return {"components": count, "requested": len(pos), "binary_bytes": sizes,
            "individual_siblings": len(pos) * (count-1).bit_length(), "batch_siblings": sibling_count(pos, 16)}


def encoding_results():
    rows = list(csv.DictReader((SOFTWARE / "results/measurements.csv").open()))
    by_name = defaultdict(lambda: defaultdict(dict))
    for row in rows:
        if row["layout"] == "random" and row["fraction"] == "five":
            by_name[row["dataset"]][int(row["trial"])][row["mode"]] = row
    out = []
    for name, trials in by_name.items():
        line = {"dataset": name, "k": int(trials[0]["batch"]["k"])}
        for enc in ("json", "json_gzip", "binary", "binary_gzip"):
            pairs = [(int(v["individual"][enc]), int(v["batch"][enc])) for v in trials.values()]
            savings = [100*(a-b)/a for a,b in pairs]
            q1, _, q3 = quantiles(savings, n=4, method="inclusive")
            line[enc] = {"median_pct": median(savings), "q1_pct": q1, "q3_pct": q3,
                         "median_bytes_saved": median(a-b for a,b in pairs)}
        out.append(line)
    return out


def main():
    cli = ArgumentParser(description=__doc__)
    cli.add_argument("output", type=Path)
    args = cli.parse_args()
    doc = read(SOFTWARE / "maritime-data/freeboard-inventory.json")
    result = {"cost_model_trials": verify_cost_model(SOFTWARE / "results/measurements.csv"),
              "inventory": FREEBOARD, "full_controls": full_controls(doc), "ordering": ordering(doc),
              "scale": scale_case(), "five_percent": encoding_results()}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Verified", result["cost_model_trials"], "matched cost predictions.")

if __name__ == "__main__":
    main()
