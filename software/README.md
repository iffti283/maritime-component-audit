# Maritime Component Audit

Release 0.1.0-rc4. The Python 3.11+ command-line tools build release commitments and verify selective disclosures. The command-line tools and benchmark use the standard library. Plotting uses Matplotlib 3.10 and Pillow. The additional full-disclosure comparator uses the cryptography package. Tested versions are recorded in requirements files and results/environment.txt. Run the commands below from `software/`.

## Verify one named dependency offline

The public Freeboard-SK fixture represents release 3.5.0-beta.1. The inventory orders components by package location. The operator derives the expected position and reference version from the pinned public lockfile. The test publisher commits the bundled declaration and creates a local receipt.

Run from `software/` with a fresh `walkthrough/` directory.

```sh
(
set -e
mkdir walkthrough
python3 src/sbom_disclosure.py commit maritime-data/freeboard-inventory.json \
  walkthrough/registered.json walkthrough/private-seeds.json
python3 src/maritime_inventory.py inputs/freeboard/package-lock.json walkthrough/operator-reference.json
python3 - <<'PYTHON'
import json
from pathlib import Path
import subprocess
import sys

directory = Path("walkthrough")


def read(filename):
    return json.loads((directory / filename).read_text())


def mca(*args):
    subprocess.run([sys.executable, "src/sbom_disclosure.py", *args], check=True)


registered = read("registered.json")
receipt = {key: registered[key] for key in ("bomFormat", "specVersion", "serialNumber", "version")}
receipt["metadata"] = json.dumps(registered["metadata"])
receipt_path = directory / "local-demo-receipt.json"
receipt_path.write_text(json.dumps(receipt))

reference = read("operator-reference.json")
location = "npm:node_modules/baconjs"
matches = [
    (position, component) for position, component in enumerate(reference["components"])
    if component["bom-ref"] == location
]
if len(matches) != 1:
    raise SystemExit("Expected one package location in the fixture reference")
position, expected = matches[0]

anchor_path = directory / "anchor.json"
opening_path = directory / "opening.json"
mca("extract", receipt_path, anchor_path)
anchor = read("anchor.json")
for field in ("serialNumber", "version"):
    if anchor[field] != reference[field]:
        raise SystemExit(f"Unexpected {field} in anchor")

mca("prove", directory / "registered.json", directory / "private-seeds.json",
    opening_path, str(position), "--mode", "batch")
mca("verify", anchor_path, opening_path, str(position))
disclosed = read("opening.json")["records"][0]["component"]
for field in ("bom-ref", "version"):
    if disclosed[field] != expected[field]:
        raise SystemExit(f"Disclosed {field} differs from the operator reference")
print(f"Verified component at position {position}: "
      f"{disclosed['name']} {disclosed['version']} ({disclosed['bom-ref']})")
print("Package location and version match the reference")
PYTHON
)
```

The verifier prints `VERIFIED`. The script then reports `baconjs` version `3.0.23` from the verified opening at position `8` and confirms that its location and version match the lockfile. In an operational audit, the disclosed version can be the value the operator is seeking. A name with several independently known locations requires a request for every relevant position. A claim of package absence requires a complete, independently established position map. The verification establishes membership at the requested position in the supplier’s committed declaration.

For an operational audit, obtain the authorised `ReadAsset` response through an authenticated peer on the expected channel, supply it to `extract`, and match the anchor serial number and document version to the independently obtained release reference. The supplier retains the seed file. The local receipt above serves only the offline example. The four CLI operations exchange JSON. Python’s `compact_proof.pack` and `unpack` provide the binary encoding. Command-line verification returns 0 on success, 1 on a hash mismatch, or 2 on a format, input, I/O or profile error. Both user interfaces require the release-bound v2 profile. The research API accepts v1 only with explicit `allow_legacy=True` for compatibility studies.

The offline core applies a restricted profile to CycloneDX-labelled 1.2 and 1.6 JSON. It checks the documented identity fields and a nonempty array of at most 1,048,576 component objects. Full CycloneDX schema conformance requires a separate validator. Registration expects a 1.6 inventory with metadata. The JSON reader rejects duplicate keys, floating-point tokens and non-finite numbers. Component objects are encoded as UTF-8 JSON with sorted keys, compact separators and preserved array order.

For a private declaration, an operator needs the position map from an independently authenticated release source, such as its build authority. Fractional numeric evidence, including confidence values permitted by the CycloneDX schema, is outside the accepted file profile. Such a release needs a verifier supporting that encoding or a separately identified declaration from the supplier.

### Compact encoding examples

For a public test vector use a CycloneDX 1.6 document with serial number `urn:uuid:00000000-0000-4000-8000-000000000001`, document version 1, and the single component `{"name":"a","type":"library"}`. Use the v2 profile, position 0 and a 16-byte all-zero test seed. Operational commitments use fresh secret seeds. The expected anchor root is `00de7e4ae50cd6a8a2d235dee296b5fd8907064a6897c875bc29f0664352e0b1`. The 50-byte batch opening is the concatenation of these hexadecimal fields in order.

| Field | Bytes in hexadecimal |
| --- | --- |
| Batch mode | 02 |
| Big-endian JSON length | 0000001d |
| Derived opening salt | 2b654357199ff54b76afe7aa04307a96 |
| UTF-8 component | 7b226e616d65223a2261222c2274797065223a226c696272617279227d |

A second public vector uses the same document identifiers and five components named `a`, `b`, `c`, `d`, `e` in that order, each of type `library`. Position `i` uses the single byte `i` repeated 16 times as its test seed. Request positions 0 and 4. The padded width is eight and the expected anchor root is `a28e506150744445434188ad69d67652fd83c5db314956ea7b1a039215dcad30`.

The binary opening is 227 bytes. It starts with `02`, followed by the two records in position order, then the four 32-byte frontier hashes in the order shown. Each record consists of its four-byte big-endian JSON length, its 16-byte opening salt and its canonical UTF-8 JSON. Both JSON lengths are `0000001d`.

| Record | Opening salt (hexadecimal) | Canonical JSON |
| --- | --- | --- |
| 0 | `2f0f3627235e1d8fa674f7c2ece0526e` | `{"name":"a","type":"library"}` |
| 4 | `0f0a2834712cb165d7d1fe6bd230f821` | `{"name":"e","type":"library"}` |

| Frontier node (level, index) | Hash in hexadecimal |
| --- | --- |
| (0, 1) | `aa24538f0f4f8718d335728b813a27be3d93450bd8172bb4898fe6741e7b7bab` |
| (0, 5), padding leaf | `498c05f710dd18727aa9fc4b019e826ce370ac716bf6bca069648dfcb7817013` |
| (1, 1) | `d82f67eef6c6ba1f5861954f7cb8e9ed370242f6c7106694b394133324cd8642` |
| (1, 3), padding subtree | `73b723d792615fe82a5a5e33e6b4b242b2def292dd8859ffd3d7f9d0acec7171` |

The batch encoding transmits these frontier entries, including those for deterministic padding. The wire and CLI mode named `individual` corresponds to independent paths.

## Offline checks

```sh
python3 src/check_release.py
python3 -m unittest discover -s tests
python3 examples/demo.py
```

These commands run the 69 published local cases and two release regressions, the generated property suite, and the demo for three selected records from the 80-record Freeboard-SK inventory.

## Desktop verifier

```sh
python3 -m pip install -r requirements-desktop.txt
python3 src/frontend.py
```

Select **Load demo**, **Verify selection** and **Run integrity checks** for three selected records from the 80-record Freeboard-SK inventory. For an imported opening, choose the independent anchor and the disclosure, enter the expected positions and verify. The result initially lists the requested records, with up to 50 rows per page. Select a row to inspect the component name, version and BOM reference. For a full opening covering extra positions, **Show all disclosed records** reveals the complete inventory. Changing inputs clears the previous result. The displayed SBOM version and serial come from the anchor. The application release name comes from the independent mapping.

Figure 3 shows the running desktop verifier with its built-in Freeboard-SK example and local demo anchor. Figure 5 shows the separate file-import workflow. Both views report the expected and observed responses for the integrity checks.

The example results are also available in `examples/Freeboard_Audit.xlsx`. To run the verifier and export the results as JSON, use `python3 src/export_demo_audit.py audit_results.json`.

## Regenerate the manuscript figures

From the package root, run the following commands to generate all five vector PDFs and 600-dpi PNGs. The desktop figures use Qt's offscreen platform and system fonts.

```sh
python3 -m pip install -r software/requirements-study.txt -r software/requirements-desktop.txt
python3 paper/draw_workflow.py rerun-figures
python3 paper/draw_frontier.py rerun-figures
QT_QPA_PLATFORM=offscreen python3 paper/draw_figure3.py --output rerun-figures
python3 paper/draw_coverage_matrix.py software/results/measurements.csv rerun-figures
QT_QPA_PLATFORM=offscreen python3 paper/draw_frontend_panels.py --output rerun-figures
```

| Figure | Filename stem | Contents |
| --- | --- | --- |
| 1 | `workflow` | Fabric registration and local verification |
| 2 | `frontier_example` | Shared siblings in an eight-leaf tree |
| 3 | `desktop_verification` | Built-in Freeboard-SK demo |
| 4 | `coverage` | Four-panel disclosure-size comparison |
| 5 | `desktop_import_workflow` | File-import workflow |

`maritime-data/` contains the two derived inventories. `results/` contains the paired measurements, input fingerprints, summaries, conformance outcomes, replay comparison and Fabric evidence.

## Paired benchmark

Six pinned external inputs are included under `inputs/` with their upstream licence files. Their original bytes match the SHA-256 values in `results/datasets.csv`. The separate firmware fixture and Java contract can be retrieved together at the published revision. The fetched firmware file must match SHA-256 `497ec737481150d4cae70c3d4d8e6267a0da3e9fe387ae6f59bca3ff9f27af90`.

```sh
git clone https://github.com/saheuLL/Hyperledger-fabric.git upstream
git -C upstream checkout --detach 16447abeb9ec50a1673da02bfb39d403b478ec3a
printf '%s  %s\n' 497ec737481150d4cae70c3d4d8e6267a0da3e9fe387ae6f59bca3ff9f27af90 upstream/caliper/workloads/SBOM_TEST.json | sha256sum -c - &&
python3 src/benchmark.py --output rerun --public-examples inputs/public-examples \
  --firmware-fixture upstream/caliper/workloads/SBOM_TEST.json \
  --freeboard-lock inputs/freeboard/package-lock.json \
  --signalk-admin-lock inputs/signalk-admin/package-lock.json &&
python3 src/compare_replay.py results rerun &&
python3 src/analyze.py rerun
```

For a fresh offline replay of the nine locally available inventories, use the same bundled source locks and public examples and omit the external firmware fixture:

```sh
python3 src/benchmark.py --output rerun-bundled --public-examples inputs/public-examples \
  --bundled-inputs-only --freeboard-lock inputs/freeboard/package-lock.json \
  --signalk-admin-lock inputs/signalk-admin/package-lock.json &&
python3 src/compare_replay.py results rerun-bundled --bundled-inputs-only
```

The comparison checks every CSV field except `build_ns` in the dataset catalogue and `verify_ns` in the measurements. A full replay compares 3,630 method rows from ten inventories. The bundled replay compares 3,267 rows from nine inventories. Each rerun writes `runtime.json` with its Python and zlib versions and gzip settings. Differences in compression across runtime versions can affect payload sizes.

The input origins and exact revisions are in `inputs/SOURCES.md`. To reproduce the full-disclosure and proof-size checks using the archived measurements:

```sh
python3 -m pip install -r requirements-study.txt
python3 src/disclosure_study.py replay-study.json
python3 -m unittest discover -s tests
```

`results/disclosure_study.json` records the wire-cost model checks, the four direct dependencies used in the ordering study, the large synthetic case, the full-disclosure controls and the four encoding summaries for each inventory. The compact full-opening control uses a 32-byte release master and the first 16 bytes of HMAC-SHA-256(master, ASCII "MCA-seed-v1" || four-byte big-endian index) for each position seed. The receiving comparator reconstructs the anchor using the known release header. The detached Ed25519 comparator signs canonical bytes of the entire derived SBOM and measures the gzip document plus the raw signature. Its public key is assumed to be available to the recipient. The executable study fixes public test keys for reproducible measurement. Both comparators are research encodings outside the operational CLI. Local timing measurements are archived separately in the original CSV.

Trial identifiers are local to an inventory, request fraction and layout. Methods in a trial share the selected-position digest. Payload sizes omit the common anchor. Timing is the median of three verifier calls per partial request or nine per complete request and excludes serialisation and network operations. Seeds and request draws are fixed for benchmark replay.

## Native Fabric checks

Use Linux with Fabric 2.5.12 binaries and config, JDK 21, Gradle, jq and the pinned Java chaincode above. When the host restricts network interface discovery, the peer can be built at Fabric tag `v2.5.12` with `src/native/peer-loopback.patch`. The patch selects the configured loopback address when automatic address detection is disabled. Use the Fabric directory containing `bin/` and `config/` and a new work path. Keep publisher seeds private. The bundled Gradle invocation builds the pinned upstream contract, which is an external dependency.

```sh
gradle -p src/native/java-build classes copyRuntime -PupstreamPath="$(pwd)/upstream"
python3 src/native/fabric_run.py --fabric /absolute/fabric-release-directory \
  --java /absolute/jdk-21/bin/java \
  --classpath "$(pwd)/src/native/java-build/build/classes/java/main:$(pwd)/src/native/java-build/build/runtime/*" \
  --collections upstream/asset-transfer-sbom/chaincode-java/collections_config.json \
  --work native-rerun --inventory maritime-data/freeboard-inventory.json
```

For a fresh build and run from those prerequisites, use the wrapper below. The optional final argument is a local Fabric Git checkout containing tag v2.5.12. With this argument the wrapper builds the loopback-patched peer from an isolated copy of the pinned revision. Without it the runner uses the supplied binaries. The release results in this archive are the archived observations listed below.

```sh
bash src/native/run_integration.sh /path/to/fabric-release /path/to/jdk21 upstream native-work /path/to/fabric-source
```

The archive documents one local network with one Raft orderer and three peer organisations. The peers were rebuilt from Fabric 2.5.12 with the supplied loopback patch and Go 1.24.4. The run recorded ten Fabric operations and six separate local verifier decisions. [Run metadata](results/native_rc4_run_metadata.json) lists the source and executable digests, pinned Java contract, dependency versions and the archived peer block-store readback for two valid registrations. The release contains the recorded [check outcomes](results/native_rc4_outcomes.json) and [masked command trace](results/native_rc4_trace.jsonl). The shipped runner reproduces the submit and role checks. The archived peer block-store readback is documented in the metadata. The second registration used a different serial and document version. The evidence covers the tested topology and leaves same-serial version progression and post-retention reads unverified. The collection settings retain the private array for three blocks and shared metadata for one million blocks. Later openings depend on the supplier retaining the array and seeds.

The runner creates a private work directory for generated credentials and network diagnostics. The shareable outputs are the operation trace and named decision results.

## Upstream sources

The Java registration interface and firmware fixture originate in Geunhee Cho, Yoomin Go and Mihui Kim, “A Hyperledger Fabric-Based SBOM Management System for Secure Software Supply Chain Integrity,” *Electronics* 15(12), 2573 (2026), https://doi.org/10.3390/electronics15122573. The inputs are identified in inputs/SOURCES.md. The Java implementation remains an external dependency. The proof implementation uses the shared-sibling approach described by Lum Ramabaja and Arber Avdullahu, https://doi.org/10.48550/arXiv.2002.07648. The implementation reads [CycloneDX 1.6 JSON](https://cyclonedx.org/docs/1.6/json/).

## Licence

MCA code is released under the [MIT licence](../LICENSE). See [third-party notices](third_party/README.md) and [input provenance](inputs/SOURCES.md) for material under separate terms. The optional PyQt5 dependency is obtained separately under Riverbank's [licensing terms](https://riverbankcomputing.com/commercial/license-faq).

## Request-level uncertainty and input compatibility

From `software/`, run:

```sh
python3 src/request_intervals.py results/measurements.csv request_intervals.csv
python3 src/wheel_profiles.py wheel_profiles.csv --wheels wheels
```

The first command pairs modes by inventory, trial and position digest. It resamples the 20
nominal 5% random requests within each inventory 10,000 times with replacement (seed
20261120). The saved bounds are the 2.5th and 97.5th interpolated percentiles of the
bootstrap median. They describe request sampling conditional on the observed inventory.

The second command reads wheel archives without installing them. The source sample
comprised every CycloneDX JSON document found in the analysis environment under a
distribution's `.dist-info/sboms/` directory or with a `.cdx.json` suffix in its file
list. Platform-specific wheel variants can contain different documents. The reference CSV
identifies the project, release, archive member, SHA-256 and first acceptance error. To
obtain the seven wheel distributions on CPython 3.12, Linux x86-64, use:

```sh
python3 -m pip download --only-binary=:all: --no-deps -d wheels cryptography==50.0.0 pillow==13.0.0 pip==26.2.2 pydantic_core==2.46.4 rpds-py==2026.6.3 scikit-learn==1.8.0 uv==0.13.9
```

To screen the distributions in another installed environment, omit `--wheels wheels`.
File-level results reflect the shipped data and the unmodified reader and commitment
code. A profile acceptance check does not establish full CycloneDX schema conformance.

For a tree of height d with k requested leaves, independent paths transmit kd sibling
hashes. If a[j] counts active nodes at level j (the leaves are level 0), the batch frontier
has F = sum(2 a[j+1] - a[j]) for j = 0 through d-1. Each active parent needs two children,
and a[j] are already available. The matched uncompressed binary saving is 32(kd-F) bytes.
Compressed sizes also depend on the encoding and contents of the disclosed records.

The authors reviewed the AI-assisted software implementation and technical documentation and take responsibility for both.
