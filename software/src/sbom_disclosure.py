"""Commit to ordered CycloneDX components and verify their selective disclosure."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sys
import uuid

LEGACY_PROFILE = "sbom-component-merkle-sha256-v1"
PROFILE = "sbom-component-merkle-sha256-v2"
PROFILES = (LEGACY_PROFILE, PROFILE)
PROPERTY = "urn:sbom-audit:component-commitment:v1"
IDENTITY = ("bomFormat", "specVersion", "serialNumber", "version")
MAX_COMPONENTS = 1 << 20


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def unsupported_number(value):
    raise ValueError(f"unsupported JSON number {value!r}")


def parse_json(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_float=unsupported_number, parse_constant=unsupported_number)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def checked_identity(document):
    identity = {key: document[key] for key in IDENTITY}
    if identity["bomFormat"] != "CycloneDX" or identity["specVersion"] not in ("1.2", "1.6"):
        raise ValueError("expected CycloneDX 1.2 or 1.6")
    serial = identity["serialNumber"]
    if type(serial) is not str or not serial.startswith("urn:uuid:"):
        raise ValueError("expected a canonical UUID URN")
    identifier = serial.removeprefix("urn:uuid:")
    if str(uuid.UUID(identifier)) != identifier:
        raise ValueError("expected a canonical UUID URN")
    version = identity["version"]
    if type(version) is not int or not 1 <= version <= 2147483647:
        raise ValueError("expected a positive 32-bit version")
    return identity


def digest(*parts):
    result = hashlib.sha256()
    for part in parts:
        result.update(part)
    return result.digest()


def leaf(index, component, salt):
    if type(component) is not dict:
        raise ValueError("each component must be a JSON object")
    return digest(b"\x00", index.to_bytes(4, "big"), salt, encode(component))


def parent(left, right):
    return digest(b"\x01", left, right)


def encoded_header(anchor):
    return encode({key: value for key, value in anchor.items() if key != "root"})


def root_digest(anchor, tree_root):
    return digest(b"\x03", encoded_header(anchor), tree_root)


def opening_context(anchor):
    if anchor["profile"] == LEGACY_PROFILE:
        return b""
    return digest(b"\x04", encoded_header(anchor))


def opening_salt(seed, context, index):
    raw = decode_hex(seed, 16)
    if not context:
        return raw
    return digest(b"\x05", context, index.to_bytes(4, "big"), raw)[:16]


def decode_hex(value, byte_count):
    if type(value) is not str or not re.fullmatch(f"[0-9a-f]{{{2 * byte_count}}}", value):
        raise ValueError(f"expected {byte_count} bytes in lower-case hexadecimal")
    return bytes.fromhex(value)


def shape(count):
    if type(count) is not int or not 1 <= count <= MAX_COMPONENTS:
        raise ValueError("component count outside supported range")
    height = (count - 1).bit_length()
    return 1 << height, height


def make_tree(components, salts, context):
    width, _ = shape(len(components))
    if len(salts) != len(components):
        raise ValueError("each component requires one salt")
    leaves = [leaf(index, component, opening_salt(salts[index], context, index))
              for index, component in enumerate(components)]
    leaves.extend(digest(b"\x02", index.to_bytes(4, "big"))
                  for index in range(len(components), width))
    levels = [leaves]
    while len(levels[-1]) > 1:
        level = levels[-1]
        levels.append([parent(level[index], level[index + 1])
                       for index in range(0, len(level), 2)])
    return levels


def commit(document, salts, profile=PROFILE):
    identity = checked_identity(document)
    components = document["components"]
    if type(components) is not list:
        raise ValueError("components must be an array")
    if profile not in PROFILES:
        raise ValueError("unsupported profile")
    anchor = {**identity, "profile": profile, "componentCount": len(components)}
    tree = make_tree(components, salts, opening_context(anchor))
    anchor["root"] = root_digest(anchor, tree[-1][0]).hex()
    return anchor, tree


def checked_anchor(anchor):
    if type(anchor) is not dict or set(anchor) != {*IDENTITY, "profile", "componentCount", "root"}:
        raise ValueError("invalid commitment envelope")
    checked_identity(anchor)
    shape(anchor["componentCount"])
    if anchor["profile"] not in PROFILES:
        raise ValueError("unsupported profile")
    decode_hex(anchor["root"], 32)
    return anchor


def attach(document, anchor):
    if document["specVersion"] != "1.6":
        raise ValueError("the registration workflow requires CycloneDX 1.6")
    metadata = dict(document["metadata"])
    properties = metadata.get("properties", [])
    if type(properties) is not list:
        raise ValueError("metadata.properties must be an array")
    if any(entry["name"] == PROPERTY for entry in properties):
        raise ValueError("commitment property already exists")
    metadata["properties"] = [*properties, {"name": PROPERTY, "value": encode(anchor).decode("utf-8")}]
    return {**document, "metadata": metadata}


def read_receipt(receipt):
    identity = checked_identity(receipt)
    metadata = receipt["metadata"]
    if type(metadata) is not str:
        raise ValueError("expected metadata string from the upstream ReadAsset contract")
    properties = parse_json(metadata)["properties"]
    roots = [entry["value"] for entry in properties if entry["name"] == PROPERTY]
    if len(roots) != 1:
        raise ValueError("expected exactly one commitment property")
    anchor = checked_anchor(parse_json(roots[0]))
    if any(identity[key] != anchor[key] for key in IDENTITY):
        raise ValueError("receipt identity differs from the commitment")
    return anchor


def indices_for(indices, count):
    if not indices or any(type(index) is not int or not 0 <= index < count for index in indices):
        raise ValueError("component positions must be nonempty and within range")
    if len(set(indices)) != len(indices):
        raise ValueError("duplicate component positions")
    return sorted(indices)


def frontier(positions, height):
    active = set(positions)
    coordinates = []
    for level in range(height):
        coordinates.extend((level, index ^ 1)
                           for index in sorted(active) if index ^ 1 not in active)
        active = {index >> 1 for index in active}
    return coordinates


def disclose(components, salts, tree, indices, mode, anchor):
    indices = indices_for(indices, len(components))
    height = len(tree) - 1
    positions = range(len(components)) if mode == "full" else indices
    context = opening_context(anchor)
    records = [{"index": index, "component": components[index],
                "salt": opening_salt(salts[index], context, index).hex()}
               for index in positions]
    proof = {"mode": mode, "records": records}
    if mode == "individual":
        for entry in records:
            index = entry["index"]
            entry["siblings"] = [tree[level][(index >> level) ^ 1].hex()
                                 for level in range(height)]
    elif mode == "batch":
        proof["siblings"] = [tree[level][index].hex()
                             for level, index in frontier(indices, height)]
    elif mode != "full":
        raise ValueError("unknown disclosure mode")
    return proof


def matches(anchor, tree_root):
    return hmac.compare_digest(root_digest(anchor, tree_root), bytes.fromhex(anchor["root"]))


def verify(anchor, proof, expected_indices, *, allow_legacy=False):
    """Verify v2 by default. Legacy compatibility is for comparison experiments."""
    checked_anchor(anchor)
    if anchor["profile"] == LEGACY_PROFILE and not allow_legacy:
        raise ValueError("release-bound v2 profile required for verification")
    count = anchor["componentCount"]
    width, height = shape(count)
    wanted = indices_for(expected_indices, count)
    if type(proof) is not dict:
        raise ValueError("invalid proof envelope")
    mode = proof["mode"]
    fields = {"mode", "records", "siblings"} if mode == "batch" else {"mode", "records"}
    if mode not in {"full", "individual", "batch"} or set(proof) != fields:
        raise ValueError("invalid proof envelope")
    records = proof["records"]
    expected = list(range(count)) if mode == "full" else wanted
    if type(records) is not list or len(records) != len(expected):
        raise ValueError("proof record count differs from the request")
    leaves = {}
    for index, record in zip(expected, records):
        record_fields = {"index", "component", "salt"}
        if mode == "individual":
            record_fields.add("siblings")
        if type(record) is not dict or set(record) != record_fields:
            raise ValueError("invalid proof record")
        if type(record["index"]) is not int or record["index"] != index:
            raise ValueError("proof records must match the requested positions")
        node = leaf(index, record["component"], decode_hex(record["salt"], 16))
        if mode == "individual":
            siblings = record["siblings"]
            if type(siblings) is not list or len(siblings) != height:
                raise ValueError("incorrect inclusion path length")
            for level, sibling in enumerate(siblings):
                other = decode_hex(sibling, 32)
                node = parent(other, node) if (index >> level) & 1 else parent(node, other)
            if not matches(anchor, node):
                return False
        else:
            leaves[index] = node
    if mode == "individual":
        return True
    if mode == "full":
        level = [leaves[index] if index < count else digest(b"\x02", index.to_bytes(4, "big"))
                 for index in range(width)]
        while len(level) > 1:
            level = [parent(level[index], level[index + 1]) for index in range(0, len(level), 2)]
        return matches(anchor, level[0])
    coordinates = frontier(wanted, height)
    siblings = proof["siblings"]
    if type(siblings) is not list or len(siblings) != len(coordinates):
        raise ValueError("incorrect multiproof frontier length")
    nodes = leaves
    offset = 0
    for level in range(height):
        parent_positions = {index >> 1 for index in nodes}
        while offset < len(coordinates) and coordinates[offset][0] == level:
            nodes[coordinates[offset][1]] = decode_hex(siblings[offset], 32)
            offset += 1
        nodes = {index: parent(nodes[2 * index], nodes[2 * index + 1])
                 for index in parent_positions}
    return matches(anchor, nodes[0])


def read(path):
    return parse_json(Path(path).read_text(encoding="utf-8"))


def write(path, obj):
    Path(path).write_bytes(encode(obj) + b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    publish = sub.add_parser("commit", help="create a registration document and a private seed file")
    for argument in ("input", "output", "salts"):
        publish.add_argument(argument)
    extract = sub.add_parser("extract", help="extract the anchor from a trusted ReadAsset response")
    extract.add_argument("receipt")
    extract.add_argument("anchor")
    prove = sub.add_parser("prove")
    for argument in ("input", "salts", "proof"):
        prove.add_argument(argument)
    prove.add_argument("indices", nargs="+", type=int)
    prove.add_argument("--mode", choices=["full", "individual", "batch"], default="batch")
    check = sub.add_parser("verify")
    check.add_argument("anchor")
    check.add_argument("proof")
    check.add_argument("indices", nargs="+", type=int)
    args = parser.parse_args()
    try:
        if args.command == "commit":
            document = read(args.input)
            shape(len(document["components"]))
            salts = [secrets.token_hex(16) for _ in document["components"]]
            anchor, _ = commit(document, salts)
            registered = attach(document, anchor)
            if Path(args.output).resolve() in {Path(args.salts).resolve(), Path(args.input).resolve()}:
                raise ValueError("use distinct input, output, and salt paths")
            with private_salt_file(args.salts) as output:
                output.write(encode(salts) + b"\n")
            try:
                with Path(args.output).open("xb") as output:
                    output.write(encode(registered) + b"\n")
            except OSError:
                Path(args.salts).unlink()
                raise
        elif args.command == "extract":
            write(args.anchor, read_receipt(read(args.receipt)))
        elif args.command == "prove":
            document, salts = read(args.input), read(args.salts)
            metadata = document.get("metadata", {})
            has_anchor = any(item.get("name") == PROPERTY for item in metadata.get("properties", []))
            stored = read_receipt({**checked_identity(document), "metadata": encode(metadata).decode()}) if has_anchor else None
            anchor, tree = commit(document, salts, stored["profile"] if stored else PROFILE)
            if stored is not None and anchor != stored:
                raise ValueError("inventory or seed file does not open the registered commitment")
            write(args.proof, disclose(document["components"], salts, tree, args.indices, args.mode, anchor))
        else:
            accepted = verify(read(args.anchor), read(args.proof), args.indices)
            print("VERIFIED" if accepted else "REJECTED")
            return 0 if accepted else 1
    except (ValueError, AttributeError, KeyError, TypeError, OSError, OverflowError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


def private_salt_file(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "wb")


if __name__ == "__main__":
    raise SystemExit(main())
