"""Run the published local checks and release-policy and trace regressions offline."""
import json
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from unittest.mock import patch

from benchmark import add_release_checks, add_wire_checks
from evaluate import fixture_salts, synthetic, test_cases
from native.fabric_run import Network
from sbom_disclosure import LEGACY_PROFILE, commit, disclose, verify


def main():
    cases = add_release_checks(add_wire_checks(test_cases()))
    failed = [case for case in cases if not case["passed"]]
    if failed:
        raise RuntimeError(failed)
    document = synthetic(3)
    seeds = fixture_salts(3)
    anchor, tree = commit(document, seeds, LEGACY_PROFILE)
    opening = disclose(document["components"], seeds, tree, [1], "batch", anchor)
    try:
        verify(anchor, opening, [1])
    except ValueError as error:
        if "v2 profile required" not in str(error):
            raise
    else:
        raise AssertionError("The default verifier accepted a legacy anchor")
    with TemporaryDirectory() as folder:
        directory = Path(folder)
        # Only command logging is under test. No Fabric processes are started.
        network = Network.__new__(Network)
        network.fabric = directory
        network.env = {"CORE_PEER_LOCALMSPID": "Org1MSP"}
        network.commands = directory / "commands.log"
        request = json.dumps({"Args": ["ReadSbomPrivate", "private fixture"]})
        for status in (0, 1):
            result = CompletedProcess([], status, stdout="private fixture", stderr="private fixture")
            with patch("native.fabric_run.subprocess.run", return_value=result):
                network.run("peer", "chaincode", "query", "-c", request, expected=None)
        rows = [json.loads(line) for line in network.commands.read_text().splitlines()]
        expected = [{"tool": "peer", "operation": "query", "exit_code": status,
                     "contract_function": "ReadSbomPrivate", "organization": "Org1MSP"}
                    for status in (0, 1)]
        if rows != expected:
            raise AssertionError("A private read must export only operation, organisation and status")
    print(f"{len(cases)} published checks and 2 release regression checks passed.")


if __name__ == "__main__":
    main()
