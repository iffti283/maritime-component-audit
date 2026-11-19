"""Audit measurement invariants and produce paired summaries from raw CSV."""
import argparse
from collections import defaultdict
import csv
from pathlib import Path
from statistics import median, quantiles

from sbom_disclosure import write

ENCODINGS = ("json", "json_gzip", "binary", "binary_gzip")


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def summarize(results):
    observations = read_csv(results / "measurements.csv")
    dimensions = {row["dataset"]: row for row in read_csv(results / "datasets.csv")}
    requests, groups, pairs = defaultdict(dict), defaultdict(list), defaultdict(list)
    matches = defaultdict(set)
    violations = []
    for row in observations:
        name, fraction, layout, mode = [row[key] for key in ("dataset", "fraction", "layout", "mode")]
        n, k, h = int(row["n"]), int(row["k"]), int(dimensions[name]["tree_height"])
        if mode == "individual" and int(row["siblings"]) != h * k:
            violations.append("independent path length")
        if mode == "batch" and int(row["siblings"]) > h * k:
            violations.append("batch path upper bound")
        if int(row["records_sent"]) != (n if mode == "full" else k):
            violations.append("record count")
        cell = (name, fraction, layout)
        request = (*cell, row["trial"])
        if mode in requests[request]:
            violations.append("duplicate method at a request")
        requests[request][mode] = row
        groups[(*cell, mode)].append(row)
        if mode == "full":
            matches[name].add(tuple(int(row[e]) for e in ENCODINGS))
    for request, methods in requests.items():
        if set(methods) != {"full", "individual", "batch"}:
            violations.append("missing comparator")
        if len({row["position_digest"] for row in methods.values()}) != 1:
            violations.append("unpaired request")
        batch = methods["batch"]
        for comparison in ("individual", "full"):
            other = methods[comparison]
            for encoding in ENCODINGS:
                reduction = 100 * (1 - int(batch[encoding]) / int(other[encoding]))
                pairs[(*request[:3], comparison, encoding)].append(reduction)
    if any(len(v) != 1 for v in matches.values()):
        violations.append("full payload differs within dataset")
    if violations:
        raise RuntimeError(violations)
    summary = []
    for item, measurements in groups.items():
        dataset, fraction, layout, mode = item
        row = {"dataset": dataset, "fraction": fraction, "layout": layout, "mode": mode,
               "k": int(measurements[0]["k"]), "trials": len(measurements)}
        for field in (*ENCODINGS, "verify_ns", "siblings"):
            values = [int(m[field]) for m in measurements]
            row[field] = median(values)
            row[f"{field}_min"] = min(values)
            row[f"{field}_max"] = max(values)
            if len(values) > 1:
                q1, _, q3 = quantiles(values, n=4, method="inclusive")
            else:
                q1 = q3 = values[0]
            row[f"{field}_q1"], row[f"{field}_q3"] = q1, q3
        summary.append(row)
    effects = []
    for key, values in pairs.items():
        dataset, fraction, layout, comparison, encoding = key
        effects.append({"dataset": dataset, "fraction": fraction, "layout": layout,
                        "comparison": comparison, "encoding": encoding, "trials": len(values),
                        "median_pct": median(values), "min_pct": min(values), "max_pct": max(values)})
    audit = {
        "observations": len(observations), "method_triplets": len(requests), "datasets": len(dimensions),
        "unique_position_sets": {
            name: len({row["position_digest"] for row in observations if row["dataset"] == name})
            for name in dimensions
        },
        "violations": len(violations),
        "structural_invariants": [
            "The three methods used identical positions within each trial.",
            "Full payload sizes were constant across requests from the same inventory.",
            "Independent sibling counts equaled requested positions times the tree height.",
            "Batch sibling counts were at most the independent proof count.",
        ],
    }
    write(results / "summary.json", summary)
    write(results / "paired_effects.json", effects)
    write(results / "audit.json", audit)
    return audit


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    print(summarize(args.results))
