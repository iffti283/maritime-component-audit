"""Screen CycloneDX inventories shipped in Python wheels against the MCA input profile."""
import argparse
import csv
from email.parser import BytesParser
from hashlib import sha256
from importlib.metadata import distributions
import json
from pathlib import Path
from zipfile import ZipFile

from sbom_disclosure import commit, parse_json


def candidate(path):
    return path.endswith(".json") and (".dist-info/sboms/" in path or path.endswith(".cdx.json"))


def installed():
    for dist in distributions():
        for item in dist.files or ():
            if candidate(str(item)):
                yield dist.metadata["Name"], dist.version, str(item), dist.locate_file(item).read_bytes()


def wheels(directory):
    for path in sorted(directory.glob("*.whl")):
        with ZipFile(path) as archive:
            meta = BytesParser().parsebytes(archive.read(next(n for n in archive.namelist()
                                                               if n.endswith(".dist-info/METADATA"))))
            for name in archive.namelist():
                if candidate(name):
                    yield meta["Name"], meta["Version"], name, archive.read(name)


def screen(items, output):
    rows = []
    for name, release, member, raw in items:
        info = json.loads(raw)
        if not isinstance(info, dict) or info.get("bomFormat") != "CycloneDX":
            continue
        try:
            document = parse_json(raw.decode("utf-8"))
            commit(document, ["00"*16] * len(document["components"]))
            result = "accepted"
        except (KeyError, ValueError, TypeError) as error:
            result = str(error)
        rows.append((name, release, member, sha256(raw).hexdigest(), info.get("specVersion"),
                     len(info.get("components", [])), result))
    if not rows:
        raise ValueError("No CycloneDX inventories found")
    with output.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("project", "release", "member", "sha256", "spec_version", "records", "profile_result"))
        writer.writerows(sorted(rows))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("output", type=Path)
    cli.add_argument("--wheels", type=Path, help="scan downloaded wheels in this directory")
    args = cli.parse_args()
    screen(wheels(args.wheels) if args.wheels else installed(), args.output)
