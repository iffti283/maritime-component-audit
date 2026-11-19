"""Estimate within-inventory uncertainty for nominal 5% random requests."""
import argparse
import csv
from collections import defaultdict
from pathlib import Path
from random import Random
from statistics import median, quantiles


def summarise(source, destination):
    pairs = defaultdict(dict)
    with source.open(newline="") as stream:
        for row in csv.DictReader(stream):
            if row["layout"] != "random" or row["fraction"] != "five" or row["mode"] == "full":
                continue
            key = (int(row["n"]), row["dataset"], int(row["k"]))
            trial = pairs[key].setdefault(int(row["trial"]), {})
            if row["mode"] in trial:
                raise ValueError("duplicate mode within request")
            trial[row["mode"]] = row
    rng = Random(20261120)
    with destination.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("inventory", "n", "tree_depth", "k", "draws", "median_pct", "lower95_pct", "upper95_pct"))
        for (n, name, k), trials in sorted(pairs.items()):
            savings = []
            for _, pair in sorted(trials.items()):
                a, b = pair["individual"], pair["batch"]
                if a["position_digest"] != b["position_digest"]:
                    raise ValueError("positions differ within request")
                x, y = int(a["json_gzip"]), int(b["json_gzip"])
                savings.append(100 * (x - y) / x)
            draws = [median(rng.choices(savings, k=len(savings))) for _ in range(10000)]
            cuts = quantiles(draws, n=1000, method="inclusive")
            writer.writerow((name, n, (n-1).bit_length(), k, len(savings),
                             median(savings), cuts[24], cuts[974]))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("measurements", type=Path)
    cli.add_argument("output", type=Path)
    args = cli.parse_args()
    summarise(args.measurements, args.output)
