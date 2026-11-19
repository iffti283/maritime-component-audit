"""Export verified Freeboard-SK demo results for use in an audit worksheet."""

from argparse import ArgumentParser
import json
from pathlib import Path

from demo_case import demo_cases
from sbom_disclosure import verify


def export(output: Path):
    cases = demo_cases()
    anchor, disclosure, positions = cases["original"]
    if not verify(anchor, disclosure, positions):
        raise RuntimeError("Cannot export verified records because the demo opening was rejected.")

    report = {
        "inventory": "Freeboard-SK",
        "release_version": anchor["version"],
        "inventory_count": anchor["componentCount"],
        "anchor_source": "Local demonstration",
        "positions": positions,
        "records": [
            {"position": record["index"], "name": record["component"]["name"],
             "version": record["component"]["version"], "result": "Verified"}
            for record in disclosure["records"]
        ],
        "checks": [
            {"input": name, "result": "Accepted" if verify(*cases[key]) else "Rejected"}
            for key, name in (("altered", "Altered component version"),
                              ("replay", "Cross-release replay"))
        ],
    }
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    export(parser.parse_args().output)
