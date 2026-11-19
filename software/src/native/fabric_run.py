"""Run a three-organization Fabric integration check with existing Java chaincode classes."""
from argparse import ArgumentParser
import base64
from contextlib import ExitStack
import io
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import uuid
import tarfile
from time import sleep

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sbom_disclosure import attach, commit, disclose, encode, read, read_receipt, verify
from evaluate import synthetic

CHANNEL = "sbomchannel"
NAME = "sbom"
HOST = "127.0.0.1"
ORDERER = f"{HOST}:17050"
ADMIN = f"{HOST}:17053"
ORGS = (1, 2, 3)


def cat_bytes(obj):
    return json.dumps(obj).encode()


def package(path, org):
    buffer = io.BytesIO()
    address = f"{HOST}:{17700 + org}"
    def entry(archive, name, data):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    with tarfile.open(fileobj=buffer, mode="w:gz") as code:
        entry(code, "connection.json", cat_bytes({
            "address": address, "dial_timeout": "10s", "tls_required": False
        }))
    with tarfile.open(path, mode="w:gz") as outer:
        entry(outer, "metadata.json", cat_bytes({
            "type": "ccaas", "label": f"sbom_{org}", "path": ""
        }))
        entry(outer, "code.tar.gz", buffer.getvalue())


def policies(msp, orderer=False):
    values = {"Readers": "member", "Writers": "member", "Admins": "admin"}
    if not orderer:
        values["Endorsement"] = "peer"
    return {name: {"Type": "Signature", "Rule": f"OR('{msp}.{role}')"}
            for name, role in values.items()}


def command_summary(tool, args, returncode, organization=None):
    """Export only known operation labels and status from a command."""
    entry = {"tool": tool, "exit_code": returncode}
    if organization in {"Org1MSP", "Org2MSP", "Org3MSP"}:
        entry["organization"] = organization
    if tool == "peer" and args[:2] in (("chaincode", "query"), ("chaincode", "invoke")):
        entry["operation"] = args[1]
        function = json.loads(args[args.index("-c") + 1])["Args"][0]
        if function in {"CreateAsset", "ReadAsset", "ReadSbomPrivate"}:
            entry["contract_function"] = function
    elif tool == "peer" and args[:2] == ("lifecycle", "chaincode"):
        if args[2] in {"install", "calculatepackageid", "approveformyorg", "commit", "querycommitted"}:
            entry["operation"] = args[2]
    elif tool in {"peer", "osnadmin"} and args[:2] == ("channel", "join"):
        entry["operation"] = "channel join"
    return entry


class Network:
    def __init__(self, args):
        self.args = args
        self.base = args.work.resolve()
        self.base.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.config = self.base / "config"
        self.config.mkdir()
        self.crypto = self.base / "crypto"
        self.orderer = self.crypto / "ordererOrganizations/order.test/orderers/localhost.order.test"
        self.root = self.orderer / "tls/ca.crt"
        self.java = args.java.resolve()
        self.fabric = args.fabric.resolve()
        self.logs = self.base / "logs"
        self.logs.mkdir()
        self.block = self.base / "channel.block"
        self.env = {**os.environ, "FABRIC_CFG_PATH": str(self.config),
                    "FABRIC_LOGGING_SPEC": "info"}
        self.events = []
        self.commands = self.logs / "commands.log"

    def run(self, tool, *args, env=None, expected=0, timeout=75):
        result = subprocess.run([self.fabric / "bin" / tool, *map(str, args)],
                                env=env or self.env, text=True, capture_output=True,
                                timeout=timeout)
        organization = (env or self.env).get("CORE_PEER_LOCALMSPID")
        entry = command_summary(tool, args, result.returncode, organization)
        with self.commands.open("a") as stream:
            stream.write(json.dumps(entry) + "\n")
        if expected is not None and result.returncode != expected:
            raise RuntimeError(f"{tool} {args[:3]} returned {result.returncode}: {result.stderr}")
        return result

    def prepare(self):
        for tool in ("core", "orderer"):
            raw = (self.fabric / "config" / f"{tool}.yaml").read_text()
            (self.config / f"{tool}.yaml").write_text(raw)
        builder = self.base / "builder/bin"
        builder.mkdir(parents=True)
        scripts = {
            "detect": 'test "$(jq -r .type "$2/metadata.json")" = ccaas',
            "build": 'cp "$1/connection.json" "$3/connection.json"',
            "release": 'mkdir -p "$2/chaincode/server"; cp "$1/connection.json" "$2/chaincode/server/"',
        }
        for name, command in scripts.items():
            path = builder / name
            path.write_text(f"#!/bin/sh\nset -eu\n{command}\n")
            path.chmod(0o755)
        self.env["CORE_CHAINCODE_EXTERNALBUILDERS"] = json.dumps([
            {"name": "local_ccaas", "path": str(builder.parent)}
        ])
        self.env["CORE_VM_ENDPOINT"] = ""
        cryptoconfig = self.base / "crypto.yaml"
        cryptoconfig.write_text(json.dumps({
            "OrdererOrgs": [{"Name": "Orderer", "Domain": "order.test", "EnableNodeOUs": True,
                             "Specs": [{"Hostname": "localhost", "SANS": [HOST]}]}],
            "PeerOrgs": [{"Name": f"Org{i}", "Domain": f"org{i}.test", "EnableNodeOUs": True,
                          "Template": {"Count": 1, "SANS": [HOST]}, "Users": {"Count": 1}}
                         for i in ORGS],
        }))
        self.run("cryptogen", "generate", "--config", cryptoconfig, "--output", self.crypto)
        orderer = {"Name": "OrdererMSP", "ID": "OrdererMSP",
                   "MSPDir": str(self.orderer.parent.parent / "msp"),
                   "Policies": policies("OrdererMSP", orderer=True), "OrdererEndpoints": [ORDERER]}
        peers = [{"Name": f"Org{i}MSP", "ID": f"Org{i}MSP",
                  "MSPDir": str(self.organization(i) / "msp"),
                  "Policies": policies(f"Org{i}MSP"),
                  "AnchorPeers": [{"Host": HOST, "Port": 17100 + i}]}
                 for i in ORGS]
        implicit = {"Readers": {"Type": "ImplicitMeta", "Rule": "ANY Readers"},
                    "Writers": {"Type": "ImplicitMeta", "Rule": "ANY Writers"},
                    "Admins": {"Type": "ImplicitMeta", "Rule": "MAJORITY Admins"}}
        endorsement = {**implicit,
                       "LifecycleEndorsement": {"Type": "ImplicitMeta", "Rule": "MAJORITY Endorsement"},
                       "Endorsement": {"Type": "ImplicitMeta", "Rule": "MAJORITY Endorsement"}}
        tls = self.orderer / "tls/server.crt"
        profile = {
            "Policies": implicit,
            "Capabilities": {"V2_0": True},
            "Orderer": {"OrdererType": "etcdraft", "Addresses": [ORDERER],
                        "BatchTimeout": "500ms", "BatchSize": {
                            "MaxMessageCount": 10, "AbsoluteMaxBytes": 10485760,
                            "PreferredMaxBytes": 524288},
                        "EtcdRaft": {"Consenters": [{"Host": HOST, "Port": 17050,
                                                     "ClientTLSCert": str(tls), "ServerTLSCert": str(tls)}],
                                     "Options": {"TickInterval": "500ms", "ElectionTick": 10,
                                                 "HeartbeatTick": 1, "MaxInflightBlocks": 5,
                                                 "SnapshotIntervalSize": 16777216}},
                        "Organizations": [orderer], "Capabilities": {"V2_0": True},
                        "Policies": {**implicit, "BlockValidation": {"Type": "ImplicitMeta",
                                                                     "Rule": "ANY Writers"}}},
            "Application": {"Organizations": peers, "Policies": endorsement,
                            "Capabilities": {"V2_0": True}},
        }
        (self.config / "configtx.yaml").write_text(json.dumps({"Profiles": {"Study": profile}}))
        self.run("configtxgen", "-profile", "Study", "-channelID", CHANNEL,
                 "-outputBlock", self.block)

    def organization(self, i):
        return self.crypto / f"peerOrganizations/org{i}.test"

    def peer_directory(self, i):
        return self.organization(i) / f"peers/peer0.org{i}.test"

    def peer_env(self, i, msp_directory):
        peer = self.peer_directory(i)
        address = f"{HOST}:{17100 + i}"
        return {**self.env,
                "CORE_PEER_ID": f"peer0.org{i}.test", "CORE_PEER_ADDRESS": address,
                "CORE_PEER_LISTENADDRESS": address,
                "CORE_PEER_CHAINCODELISTENADDRESS": f"{HOST}:{17500 + i}",
                "CORE_PEER_CHAINCODEADDRESS": f"{HOST}:{17500 + i}",
                "CORE_PEER_LOCALMSPID": f"Org{i}MSP", "CORE_PEER_MSPCONFIGPATH": str(msp_directory),
                "CORE_PEER_FILESYSTEMPATH": str(self.base / f"peer{i}"),
                "CORE_PEER_GOSSIP_EXTERNALENDPOINT": address,
                "CORE_PEER_GOSSIP_BOOTSTRAP": address,
                "CORE_PEER_GOSSIP_USELEADERELECTION": "false", "CORE_PEER_GOSSIP_ORGLEADER": "true",
                "CORE_PEER_GOSSIP_PVTDATA_PULLRETRYTHRESHOLD": "6s",
                "CORE_PEER_TLS_ENABLED": "true",
                "CORE_PEER_TLS_CERT_FILE": str(peer / "tls/server.crt"),
                "CORE_PEER_TLS_KEY_FILE": str(peer / "tls/server.key"),
                "CORE_PEER_TLS_ROOTCERT_FILE": str(peer / "tls/ca.crt")}

    def client(self, i, *args, user=None, expected=0):
        identity = user or f"Admin@org{i}.test"
        env = self.peer_env(i, self.organization(i) / f"users/{identity}/msp")
        return self.run("peer", *args, env=env, expected=expected)

    @staticmethod
    def start(stack, path, env, output, args=()):
        log = stack.enter_context(output.open("w"))
        process = subprocess.Popen([path, *args], env=env, stdout=log, stderr=log)
        stack.callback(Network.stop, process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    @staticmethod
    def wait_socket(port, process):
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(f"process exited before opening port {port}")
            try:
                with socket.create_connection((HOST, port), timeout=.15):
                    return
            except OSError:
                sleep(.15)
        raise RuntimeError(f"port {port} did not open")

    def orderer_args(self):
        return ("-o", ORDERER, "--tls", "--cafile", self.root)

    def start_peers(self, stack):
        orderer_env = {**self.env, "ORDERER_GENERAL_LISTENADDRESS": HOST,
                       "ORDERER_GENERAL_LISTENPORT": "17050", "ORDERER_GENERAL_LOCALMSPID": "OrdererMSP",
                       "ORDERER_GENERAL_LOCALMSPDIR": str(self.orderer / "msp"),
                       "ORDERER_GENERAL_BOOTSTRAPMETHOD": "none", "ORDERER_CHANNELPARTICIPATION_ENABLED": "true",
                       "ORDERER_FILELEDGER_LOCATION": str(self.base / "orderer-ledger"),
                       "ORDERER_CONSENSUS_WALDIR": str(self.base / "wal"),
                       "ORDERER_CONSENSUS_SNAPDIR": str(self.base / "snap"),
                       "ORDERER_OPERATIONS_LISTENADDRESS": f"{HOST}:17054",
                       "ORDERER_ADMIN_LISTENADDRESS": ADMIN,
                       "ORDERER_GENERAL_TLS_ENABLED": "true",
                       "ORDERER_GENERAL_TLS_PRIVATEKEY": str(self.orderer / "tls/server.key"),
                       "ORDERER_GENERAL_TLS_CERTIFICATE": str(self.orderer / "tls/server.crt"),
                       "ORDERER_GENERAL_TLS_ROOTCAS": f"[{self.root}]"}
        proc = self.start(stack, self.fabric / "bin/orderer", orderer_env, self.logs / "orderer.log")
        self.wait_socket(17053, proc)
        self.run("osnadmin", "channel", "join", "--channelID", CHANNEL,
                 "--config-block", self.block, "-o", ADMIN)
        for i in ORGS:
            env = self.peer_env(i, self.peer_directory(i) / "msp")
            env["CORE_OPERATIONS_LISTENADDRESS"] = f"{HOST}:{17600+i}"
            proc = self.start(stack, self.fabric / "bin/peer", env,
                              self.logs / f"peer{i}.log", ("node", "start"))
            self.wait_socket(17100 + i, proc)
            self.client(i, "channel", "join", "-b", self.block)
        sleep(6)

    def deploy(self, stack):
        lifecycle = ("lifecycle", "chaincode")
        definition = ("--channelID", CHANNEL, "--name", NAME, "--version", "1.0", "--sequence", "1",
                      "--signature-policy", "OR('Org1MSP.peer','Org2MSP.peer')",
                      "--collections-config", self.args.collections.resolve())
        for i in ORGS:
            archive = self.base / f"sbom_{i}.tgz"
            package(archive, i)
            self.client(i, *lifecycle, "install", archive)
            result = self.client(i, *lifecycle, "calculatepackageid", archive)
            package_id = result.stdout.strip()
            env = {**self.env, "CORE_CHAINCODE_ID_NAME": package_id,
                   "CHAINCODE_SERVER_ADDRESS": f"{HOST}:{17700+i}", "CORE_PEER_TLS_ENABLED": "false"}
            proc = self.start(stack, self.java, env,
                              self.logs / f"chaincode{i}.log", ("-cp", self.args.classpath, "org.hyperledger.fabric.contract.ContractRouter"))
            self.wait_socket(17700 + i, proc)
            self.client(i, *lifecycle, "approveformyorg", *self.orderer_args(), *definition,
                        "--package-id", package_id)
        addresses = [argument for i in (1, 2)
                     for argument in ("--peerAddresses", f"{HOST}:{17100+i}", "--tlsRootCertFiles",
                                      str(self.peer_directory(i) / "tls/ca.crt"))]
        self.client(1, *lifecycle, "commit", *self.orderer_args(), *definition, *addresses)
        self.client(1, *lifecycle, "querycommitted", "--channelID", CHANNEL, "--name", NAME,
                    "--output", "json")

    def query(self, i, *args):
        return self.client(i, "chaincode", "query", "-C", CHANNEL, "-n", NAME,
                           "-c", json.dumps({"Args": list(args)}),
                           user=f"User1@org{i}.test", expected=None)

    def read_denial(self, organization, result, collection):
        tx = re.search(r"\[([a-f0-9]{8})\]", result.stderr)
        if result.returncode == 0 or tx is None:
            return ""
        logs = (self.logs / f"peer{organization}.log").read_text()
        for line in logs.splitlines():
            if (f"[{tx.group(1)}]" in line and "does not have read access permission" in line
                    and f"collectionName: {collection}" in line):
                return re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        return ""

    def record(self, check, success, detail, **metrics):
        self.events.append({"check": check, "passed": bool(success), **metrics})
        report = self.base / "outcomes.json"
        report.write_bytes(encode(self.events) + b"\n")
        if not success:
            raise RuntimeError(f"{check} failed: {detail}")

    def submit_inventory(self, document, anchor, expected=0):
        registered = attach(document, anchor)
        payload = base64.b64encode(encode(registered)).decode()
        return self.client(1, "chaincode", "invoke", *self.orderer_args(),
                           "-C", CHANNEL, "-n", NAME,
                           "--peerAddresses", f"{HOST}:17101", "--tlsRootCertFiles",
                           self.peer_directory(1) / "tls/ca.crt",
                           "--waitForEvent", "--waitForEventTimeout", "30s",
                           "-c", '{"Args":["CreateAsset"]}',
                           "--transient", json.dumps({"sbom_property": payload}),
                           user="User1@org1.test", expected=expected)

    def read_anchor(self, organization, serial):
        result = self.query(organization, "ReadAsset", serial)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        return read_receipt(json.loads(result.stdout))

    def evaluate(self):
        document = read(self.args.inventory) if self.args.inventory else synthetic(9)
        salts = [os.urandom(16).hex() for _ in document["components"]]
        anchor, tree = commit(document, salts)
        serial = anchor["serialNumber"]
        result = self.submit_inventory(document, anchor)
        self.record("native_commit", result.returncode == 0 and "VALID" in result.stderr,
                    result.stderr.strip())
        for i in (1, 2):
            result = self.query(i, "ReadAsset", serial)
            parsed = read_receipt(json.loads(result.stdout)) if result.returncode == 0 else {}
            self.record(f"org{i}_read_committed_anchor", parsed == anchor,
                        "Parsed root equals the locally computed anchor" if parsed == anchor else result.stderr)
        outsider = self.query(3, "ReadAsset", serial)
        reason = self.read_denial(3, outsider, "assetCollection")
        self.record("org3_metadata_denied", bool(reason), reason or outsider.stderr.strip())
        for i in ORGS:
            result = self.query(i, "ReadSbomPrivate", "Org1MSPPrivateCollection", serial)
            if i == 1:
                raw = json.loads(result.stdout) if result.returncode == 0 else {}
                saved = json.loads(raw["components"]) if "components" in raw else None
                self.record("org1_private_read", saved == document["components"],
                            "Private inventory comparison", record_count=len(saved) if isinstance(saved, list) else 0,
                            matches_input=(saved == document["components"]))
            else:
                reason = self.read_denial(i, result, "Org1MSPPrivateCollection")
                self.record(f"org{i}_private_read_denied", bool(reason), reason or result.stderr.strip())
        received = self.read_anchor(2, serial)
        requests = [0, 4, 8]
        for mode in ("full", "individual", "batch"):
            proof = disclose(document["components"], salts, tree, requests, mode, anchor)
            self.record(f"{mode}_verified_against_native_anchor", verify(received, proof, requests),
                        f"Verified selected positions {requests}")
        original_proof = disclose(document["components"], salts, tree, requests, "batch", anchor)
        proof = disclose(document["components"], salts, tree, requests, "batch", anchor)
        proof["records"][0]["component"] = {"name": "changed"}
        self.record("tampered_component_rejected", not verify(received, proof, requests),
                    "Component mutation failed against the same committed root")

        if self.args.inventory:
            duplicate = self.submit_inventory(document, anchor, expected=None)
            detail = f"Asset {serial} already exists"
            chaincode_log = (self.logs / "chaincode1.log").read_text()
            self.record("duplicate_serial_refused",
                        duplicate.returncode != 0 and (detail in duplicate.stderr or detail in chaincode_log),
                        detail if detail in duplicate.stderr or detail in chaincode_log else duplicate.stderr)
            self.record("original_anchor_survived_duplicate", self.read_anchor(2, serial) == anchor,
                        "Fleet reader recovered the original anchor after the rejected registration")
            second = {**document, "serialNumber": uuid.uuid5(uuid.UUID(serial.removeprefix("urn:uuid:")),
                                                             "simulated-next-release").urn,
                      "version": 2}
            second_anchor, second_tree = commit(second, salts)
            result = self.submit_inventory(second, second_anchor)
            self.record("second_release_native_commit", result.returncode == 0 and "VALID" in result.stderr,
                        result.stderr.strip())
            trusted_second = self.read_anchor(2, second_anchor["serialNumber"])
            new_proof = disclose(second["components"], salts, second_tree, requests, "batch", second_anchor)
            self.record("second_release_proof_verified",
                        trusted_second == second_anchor and verify(trusted_second, new_proof, requests),
                        "Fleet reader verified the selected positions for the second test release")
            self.record("cross_release_proof_refused", not verify(trusted_second, original_proof, requests),
                        "The first test release's opening failed against the second committed identity")


def main():
    parser = ArgumentParser(description=__doc__)
    for name in ("fabric", "java", "collections", "work"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--classpath", required=True)
    parser.add_argument("--inventory", type=Path, help="maritime scenario input, with at least nine components")
    n = Network(parser.parse_args())
    n.prepare()
    with ExitStack() as stack:
        n.start_peers(stack)
        n.deploy(stack)
        n.evaluate()
    print(f"{sum(item['passed'] for item in n.events)} native integration checks passed")


if __name__ == "__main__":
    main()
