"""Check a selective opening and two rejection cases using a local fixture."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from demo_case import demo_cases
from sbom_disclosure import verify


def main():
    cases = demo_cases()
    outcomes = [
        ("Original chartplotter opening verified", verify(*cases["original"])),
        ("Altered component opening refused", not verify(*cases["altered"])),
        ("First opening refused under the second release", not verify(*cases["replay"])),
    ]
    for label, matched in outcomes:
        print(f"{'PASS' if matched else 'FAIL'} {label}")
    return 0 if all(matched for _, matched in outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
