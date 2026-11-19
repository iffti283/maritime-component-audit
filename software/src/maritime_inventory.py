"""Derive ordered component inventories from pinned maritime application lockfiles."""
import argparse
from hashlib import sha256
from pathlib import Path
import uuid

from sbom_disclosure import parse_json, write

FREEBOARD = "Freeboard-SK chartplotter"
ADMIN = "Signal K admin dependencies"


def entries_from_v1(dependencies, parent=""):
    for name, item in dependencies.items():
        path = f"{parent}node_modules/{name}"
        yield path, item
        yield from entries_from_v1(item.get("dependencies", {}), path + "/")


def inventory(lock_bytes):
    lock = parse_json(lock_bytes.decode("utf-8"))
    if lock["lockfileVersion"] == 1:
        entries = entries_from_v1(lock["dependencies"])
    elif lock["lockfileVersion"] in (2, 3):
        entries = ((path, item) for path, item in lock["packages"].items()
                   if path.startswith("node_modules/"))
    else:
        raise ValueError("unsupported npm lockfile version")
    components = []
    for path, entry in sorted(entries):
        if entry.get("dev") or entry.get("link") or not isinstance(entry.get("version"), str):
            continue
        name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
        components.append({"type": "library", "name": name,
                           "version": entry["version"], "bom-ref": "npm:" + path})
    identity = uuid.uuid5(uuid.NAMESPACE_URL, "npm-lock-sha256:" + sha256(lock_bytes).hexdigest())
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": identity.urn,
            "version": 1, "metadata": {"component": {"type": "application", "name": lock["name"],
                                                     "version": lock["version"]}},
            "components": components}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    write(args.output, inventory(args.lock.read_bytes()))
