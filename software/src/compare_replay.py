"""Check the archived and rerun benchmark CSVs, excluding measured timings."""
import argparse
import csv
from pathlib import Path


def load(path, timing_field):
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None or not {"dataset", timing_field}.issubset(reader.fieldnames):
            raise ValueError(f"{path}: expected dataset and {timing_field} columns")
        if len(set(reader.fieldnames)) != len(reader.fieldnames):
            raise ValueError(f"{path}: duplicate column names")
        columns = [column for column in reader.fieldnames if column != timing_field]
        rows = []
        for row in reader:
            if None in row or None in row.values():
                raise ValueError(f"{path}:{reader.line_num}: incomplete or extra CSV fields")
            rows.append({column: row[column] for column in columns})
        if not rows:
            raise ValueError(f"{path}: no observations")
        return set(columns), rows


def compare(archive, rerun, timing_field, bundled_only):
    reference_columns, expected = load(archive, timing_field)
    actual_columns, actual = load(rerun, timing_field)
    if reference_columns != actual_columns:
        raise ValueError(f"{rerun.name}: rerun columns differ from the archive")
    if bundled_only:
        expected = [row for row in expected if row["dataset"] != "Firmware fixture"]
    if len(expected) != len(actual):
        raise ValueError(f"{rerun.name}: expected {len(expected)} rows, found {len(actual)}")
    for index, (reference_row, actual_row) in enumerate(zip(expected, actual), start=1):
        if reference_row != actual_row:
            fields = sorted(column for column in reference_columns
                            if reference_row[column] != actual_row[column])
            raise ValueError(f"{rerun.name}: row {index} ({reference_row['dataset']}) "
                             f"differs in {', '.join(fields)}")
    return len(actual)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="directory of reference CSVs")
    parser.add_argument("rerun", type=Path, help="directory of newly generated CSVs")
    parser.add_argument("--bundled-inputs-only", action="store_true",
                        help="exclude the firmware fixture from the reference")
    args = parser.parse_args()
    try:
        inventories = compare(args.archive / "datasets.csv", args.rerun / "datasets.csv",
                              "build_ns", args.bundled_inputs_only)
        observations = compare(args.archive / "measurements.csv", args.rerun / "measurements.csv",
                               "verify_ns", args.bundled_inputs_only)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Replay comparison failed: {error}\n")
    print(f"All non-timing fields match for {inventories} inventories "
          f"and {observations:,} method observations.")


if __name__ == "__main__":
    main()
