"""Compact binary encoding of a proof for an independently known position list."""
from io import BytesIO

from sbom_disclosure import decode_hex, encode, frontier, indices_for, parse_json, shape

MODE_CODES = {"full": b"\x00", "individual": b"\x01", "batch": b"\x02"}
CODE_MODES = {value: mode for mode, value in MODE_CODES.items()}


def pack(proof):
    mode = proof["mode"]
    output = BytesIO()
    output.write(MODE_CODES[mode])
    for record in proof["records"]:
        body = encode(record["component"])
        output.write(len(body).to_bytes(4, "big"))
        output.write(decode_hex(record["salt"], 16))
        output.write(body)
        if mode == "individual":
            for sibling in record["siblings"]:
                output.write(decode_hex(sibling, 32))
    if mode == "batch":
        for sibling in proof["siblings"]:
            output.write(decode_hex(sibling, 32))
    return output.getvalue()


def unpack(blob, count, requested):
    stream = BytesIO(blob)
    mode = CODE_MODES.get(stream.read(1))
    if mode is None:
        raise ValueError("unknown wire mode")
    wanted = indices_for(requested, count)
    _, height = shape(count)
    records = []

    def take(length):
        data = stream.read(length)
        if len(data) != length:
            raise ValueError("truncated wire payload")
        return data

    positions = range(count) if mode == "full" else wanted
    for index in positions:
        length = int.from_bytes(take(4), "big")
        salt = take(16).hex()
        component_bytes = take(length)
        component = parse_json(component_bytes.decode("utf-8"))
        if encode(component) != component_bytes:
            raise ValueError("noncanonical wire component")
        record = {"index": index, "salt": salt, "component": component}
        if mode == "individual":
            record["siblings"] = [take(32).hex() for _ in range(height)]
        records.append(record)
    proof = {"mode": mode, "records": records}
    if mode == "batch":
        proof["siblings"] = [take(32).hex() for _ in frontier(wanted, height)]
    if stream.read(1):
        raise ValueError("trailing bytes")
    return proof
