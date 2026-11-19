"""Paired measurement of disclosure methods across inventories, layouts and encodings."""
import argparse
import csv
import gzip
import hashlib
import math
from pathlib import Path
import platform
import random
from statistics import median
from time import perf_counter_ns
import zlib

from compact_proof import pack, unpack
from maritime_inventory import ADMIN, FREEBOARD, inventory
from evaluate import fixture_salts, synthetic, test_cases
from sbom_disclosure import LEGACY_PROFILE, commit, disclose, encode, read, verify, write

TRIALS = 20
GZIP_LEVEL = 6
GZIP_MTIME = 0
MODES = ("full", "individual", "batch")
CASE_FILES = {
    "CERN VdM Editor": "SBOM/cern-lhc-vdm-editor-e564943/bom.json",
    "Dropwizard": "SBOM/dropwizard-1.3.15/bom.json",
    "Juice Shop": "SBOM/juice-shop/v11.1.2/bom.json",
    "Keycloak": "SBOM/keycloak-10.0.2/bom.json",
}


def measure(proof, retain_wire=True):
    payload = encode(proof)
    binary = pack(proof)
    sizes = {
        "json": len(payload),
        "json_gzip": len(gzip.compress(payload, compresslevel=GZIP_LEVEL, mtime=GZIP_MTIME)),
        "binary": len(binary),
        "binary_gzip": len(gzip.compress(binary, compresslevel=GZIP_LEVEL, mtime=GZIP_MTIME)),
    }
    return sizes, binary if retain_wire else None


def dataset(name, origin, document, raw_bytes, source):
    components = document["components"]
    count = len(components)
    info = {
        "dataset": name, "origin": origin, "n": count,
        "component_json_bytes": len(encode(components)), "source_json_bytes": len(raw_bytes),
        "source_sha256": hashlib.sha256(raw_bytes).hexdigest(), "source_file": source,
        "bom_encoding_version": document["specVersion"],
    }
    salts = fixture_salts(count)
    started = perf_counter_ns()
    anchor, tree = commit(document, salts)
    info["build_ns"] = perf_counter_ns() - started
    info["anchor_json_bytes"] = len(encode(anchor))
    width = len(tree[0])
    height = len(tree) - 1
    info["tree_width"] = width
    info["tree_height"] = height
    full = disclose(components, salts, tree, [0], "full", anchor)
    full_sizes, full_wire = measure(full)
    if unpack(full_wire, count, [0]) != full or not verify(anchor, full, [0]):
        raise RuntimeError(f"full proof round trip failed: {name}")
    measurements = []
    for fraction, k in (("one", 1), ("five", math.ceil(count * .05)),
                        ("quarter", math.ceil(count * .25)), ("all", count)):
        layouts = ("all",) if fraction == "all" else ("random", "contiguous")
        for layout in layouts:
            rng = random.Random(9613 + count * 101 + k)
            for trial in range(TRIALS if layout != "all" else 1):
                if layout == "all":
                    chosen = list(range(count))
                elif layout == "random":
                    chosen = sorted(rng.sample(range(count), k))
                else:
                    start = rng.randrange(count - k + 1)
                    chosen = list(range(start, start + k))
                offset = trial % len(MODES)
                for mode in MODES[offset:] + MODES[:offset]:
                    if mode == "full":
                        proof, sizes = full, full_sizes
                    else:
                        proof = disclose(components, salts, tree, chosen, mode, anchor)
                        sizes, wire = measure(proof)
                        if unpack(wire, count, chosen) != proof:
                            raise RuntimeError(f"wire round trip failed: {name}, {fraction}, {mode}")
                    if mode == "individual":
                        siblings = sum(len(record["siblings"]) for record in proof["records"])
                        assert siblings == k * height
                    elif mode == "batch":
                        siblings = len(proof["siblings"])
                        assert siblings <= k * height
                    else:
                        siblings = 0
                    times = []
                    for _ in range(9 if layout == "all" else 3):
                        start = perf_counter_ns()
                        valid = verify(anchor, proof, chosen)
                        times.append(perf_counter_ns() - start)
                        assert valid
                    measurements.append({
                        "dataset": name, "origin": origin, "n": count, "fraction": fraction,
                        "k": k, "layout": layout, "trial": trial, "mode": mode,
                        "records_sent": len(proof["records"]), "siblings": siblings,
                        **sizes, "verify_ns": median(times),
                        "position_digest": hashlib.sha256(encode(chosen)).hexdigest(),
                    })
    return info, measurements


def add_wire_checks(checks):
    document = synthetic(9)
    salts = fixture_salts(9)
    anchor, tree = commit(document, salts)
    positions = [0, 4, 8]
    for mode in MODES:
        proof = disclose(document["components"], salts, tree, positions, mode, anchor)
        wire = pack(proof)
        checks.append({"case": "binary_round_trip", "mode": mode,
                       "passed": verify(anchor, unpack(wire, 9, positions), positions)})
        for case, modified in (("binary_truncated", wire[:-1]),
                               ("binary_trailing_data", wire + b"\x00")):
            rejected = False
            try:
                unpack(modified, 9, positions)
            except ValueError:
                rejected = True
            checks.append({"case": case, "mode": mode, "passed": rejected})
    return checks


def add_release_checks(checks):
    document = synthetic(9)
    other = {**document, "version": 2}
    seeds = fixture_salts(9)
    old_anchor, old_tree = commit(document, seeds, LEGACY_PROFILE)
    other_legacy_anchor, _ = commit(other, seeds, LEGACY_PROFILE)
    anchor, tree = commit(document, seeds)
    second_anchor, _ = commit(other, seeds)
    positions = [0, 4, 8]
    for mode in MODES:
        old_proof = disclose(document["components"], seeds, old_tree, positions, mode, old_anchor)
        proof = disclose(document["components"], seeds, tree, positions, mode, anchor)
        checks.append({"case": "legacy_reused_salts_control", "mode": mode,
                       "passed": verify(other_legacy_anchor, old_proof, positions, allow_legacy=True)})
        checks.append({"case": "version_bound_opening_refused", "mode": mode,
                       "passed": not verify(second_anchor, proof, positions)})
    return checks


def table(path, records):
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, list(records[0]))
        writer.writeheader()
        writer.writerows(records)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-examples", type=Path, required=True)
    firmware_input = parser.add_mutually_exclusive_group(required=True)
    firmware_input.add_argument("--firmware-fixture", type=Path)
    firmware_input.add_argument("--bundled-inputs-only", action="store_true",
                                help="omit the separately retrieved firmware fixture")
    parser.add_argument("--freeboard-lock", type=Path)
    parser.add_argument("--signalk-admin-lock", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    checks = add_release_checks(add_wire_checks(test_cases()))
    assert all(check["passed"] for check in checks)
    write(args.output / "conformance.json", checks)
    infos, rows = [], []
    for size in (64, 256, 1024):
        doc = synthetic(size)
        info, measured = dataset(f"Synthetic {size}", "synthetic", doc, encode(doc), "seeded generator")
        infos.append(info)
        rows.extend(measured)
    files = [(name, args.public_examples / rel, rel) for name, rel in CASE_FILES.items()]
    if args.firmware_fixture is not None:
        files.append(("Firmware fixture", args.firmware_fixture, "caliper/workloads/SBOM_TEST.json"))
    for name, path, source in files:
        info, measured = dataset(name, "public case", read(path), path.read_bytes(), source)
        infos.append(info)
        rows.extend(measured)
    for name, path in ((FREEBOARD, args.freeboard_lock), (ADMIN, args.signalk_admin_lock)):
        if path is None:
            continue
        raw = path.read_bytes()
        info, measured = dataset(name, "maritime case", inventory(raw), raw, path.name)
        infos.append(info)
        rows.extend(measured)
    table(args.output / "datasets.csv", infos)
    table(args.output / "measurements.csv", rows)
    write(args.output / "runtime.json", {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "zlib_compile_version": zlib.ZLIB_VERSION,
        "zlib_runtime_version": zlib.ZLIB_RUNTIME_VERSION,
        "gzip_compresslevel": GZIP_LEVEL,
        "gzip_mtime": GZIP_MTIME,
    })
    print(f"{len(rows)} method observations, {len(infos)} inventories, {len(checks)} checks")


if __name__ == "__main__":
    run()
