"""Build the Freeboard-SK opening and its two rejection controls."""

from copy import deepcopy
from pathlib import Path
import secrets
from uuid import NAMESPACE_URL, uuid5

from sbom_disclosure import commit, disclose, read

INVENTORY = Path(__file__).resolve().parents[1] / "maritime-data/freeboard-inventory.json"


def demo_cases():
    inventory = read(INVENTORY)
    components = inventory["components"]
    seeds = [secrets.token_hex(16) for _ in components]
    positions = [0, 4, 8]
    anchor, tree = commit(inventory, seeds)
    proof = disclose(components, seeds, tree, positions, "batch", anchor)

    altered = deepcopy(proof)
    altered["records"][0]["component"]["version"] += "-altered"
    second = {
        **inventory,
        "serialNumber": uuid5(NAMESPACE_URL, anchor["serialNumber"] + "/example-next").urn,
        "version": 2,
    }
    second_anchor, _ = commit(second, seeds)
    return {
        "original": (anchor, proof, positions),
        "altered": (anchor, altered, positions),
        "replay": (second_anchor, proof, positions),
    }
