#!/bin/sh
# Maritime Component Audit | Manuscript companion 1 | MIT
#
# Run in a directory where MCA_Companion_1.zip does not already exist:
#   sh MCA_Companion_1.sh
# To use your own copy of the published RC4 software asset:
#   sh MCA_Companion_1.sh /path/to/MCA_Software.zip
# Requires a POSIX shell and Python 3.11+. Extract the resulting archive
# and open software/README.md for the named walkthrough and five figures.
set -eu
if [ "$#" -gt 1 ]; then
    echo "Usage: sh MCA_Companion_1.sh [MCA_Software.zip]" >&2
    exit 2
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' 0
mkdir -p "$work/overlay/software" "$work/overlay/paper"

cat > "$work/overlay/README.md" <<'MCA_FILE_END_0'
# Maritime Component Audit

Manuscript companion 1 for software version 0.1.0-rc4. It contains the verifier, six pinned inputs, archived measurements and Fabric evidence, and the five figure-generation recipes.

Open [the developer manual](software/README.md) for the [named-component walkthrough](software/README.md#verify-one-named-dependency-offline), [figure commands](software/README.md#regenerate-the-manuscript-figures), [benchmark](software/README.md#paired-benchmark) and native Fabric dependencies. The firmware input and external Java contract are retrieved from the revision in [the input manifest](software/inputs/SOURCES.md).

The offline core requires Python 3.11 or later. From the archive root, run:

```sh
cd software
python3 src/check_release.py
python3 -m unittest discover -s tests
python3 examples/demo.py
```

MCA code is distributed under the [MIT licence](LICENSE). Upstream inputs retain their own licences.
MCA_FILE_END_0

cat > "$work/overlay/software/README.md" <<'MCA_FILE_END_1'
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

The manuscript companion contains the inputs and plotting scripts for all five figures. Run the following commands from the archive root. They create vector PDFs and 600-dpi PNGs. Figure 3 creates a fresh local commitment, so its displayed anchor digest changes between runs. The verified package, positions and integrity outcomes are reproducible. Desktop rendering also depends on the system fonts and Qt platform.

```sh
(
set -e
python3 -m pip install -r software/requirements-study.txt -r software/requirements-desktop.txt
output=rerun-figures
mkdir -p "$output"
auxiliary=$(mktemp -d)
trap 'rm -rf "$auxiliary"' 0

# Figure 1
python3 paper/draw_workflow.py "$output"

# Figure 2
python3 software/src/plot_softwarex.py software/results "$auxiliary" --png
cp "$auxiliary/frontier_example.pdf" "$auxiliary/frontier_example.png" "$output/"

# Figure 3
QT_QPA_PLATFORM=offscreen python3 paper/draw_figure3.py --output "$output"

# Figure 4
python3 paper/draw_coverage_matrix.py software/results/measurements.csv "$output"

# Figure 5
QT_QPA_PLATFORM=offscreen python3 paper/draw_frontend_panels.py --output "$output"
)
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

The size benchmark uses fixed pseudorandom per-position seeds. The Freeboard-SK and Signal K administration inventories come from public npm lockfiles in the same ecosystem. The random and contiguous request patterns are constructed workloads.

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

The archive documents one local network with one Raft orderer and three peer organisations. The peers were rebuilt from Fabric 2.5.12 with the supplied loopback patch and Go 1.24.4. The archive records ten Fabric checks across twelve contract calls and six separate local verifier decisions. The fleet operator read the shared anchor and was denied access to the supplier’s private component array. [Run metadata](results/native_rc4_run_metadata.json) lists the source and executable digests, pinned Java contract, dependency versions and the archived peer block-store readback for two valid registrations. The release contains the recorded [check outcomes](results/native_rc4_outcomes.json) and [masked command trace](results/native_rc4_trace.jsonl). The shipped runner reproduces the submit and role checks. The archived peer block-store readback is documented in the metadata. The second registration used a different serial and document version. The evidence covers the tested topology and leaves same-serial version progression and post-retention reads unverified. The collection settings retain the private array for three blocks and shared metadata for one million blocks. Later openings depend on the supplier retaining the array and seeds.

The runner creates a private work directory for generated credentials and network diagnostics. The shareable outputs are the operation trace and named decision results.

## Upstream sources

The Java registration interface and firmware fixture originate in Geunhee Cho, Yoomin Go and Mihui Kim, “A Hyperledger Fabric-Based SBOM Management System for Secure Software Supply Chain Integrity,” *Electronics* 15(12), 2573 (2026), https://doi.org/10.3390/electronics15122573. The inputs are identified in inputs/SOURCES.md. The Java implementation remains an external dependency. The proof implementation uses the shared-sibling approach described by Lum Ramabaja and Arber Avdullahu, https://doi.org/10.48550/arXiv.2002.07648. The implementation reads [CycloneDX 1.6 JSON](https://cyclonedx.org/docs/1.6/json/).

## Licence

MCA code is released under the [MIT licence](../LICENSE). See [third-party notices](third_party/README.md) and [input provenance](inputs/SOURCES.md) for material under separate terms. The optional PyQt5 dependency is obtained separately under Riverbank's [licensing terms](https://riverbankcomputing.com/commercial/license-faq).
MCA_FILE_END_1

cat > "$work/overlay/paper/draw_coverage_matrix.py" <<'MCA_FILE_END_2'
"""Plot the distribution of compressed payload sizes in the ten-inventory benchmark."""
from argparse import ArgumentParser
from collections import defaultdict
import csv
from pathlib import Path
from statistics import median, quantiles

import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, FuncFormatter


def plot(measurements, destination):
    groups = defaultdict(list)
    catalog = {}
    with measurements.open(newline="") as file:
        for row in csv.DictReader(file):
            if row["layout"] in ("random", "all"):
                name = row["dataset"]
                catalog[name] = int(row["n"])
                groups[name, row["fraction"], row["mode"]].append(int(row["json_gzip"]) / 1024)
    fig, axes = plt.subplots(1, 4, figsize=(7.2, 4.0), sharex=True, sharey=True)
    names = sorted(catalog, key=catalog.get)
    modes = [("batch", "#194c78", "o", "Batch"),
             ("individual", "#a75421", "^", "Independent"), ("full", "#676e76", "s", "Full")]
    for ax, fraction, title in zip(axes, ("one", "five", "quarter", "all"),
                                   ("One record", "5% of records", "25% of records", "All records")):
        ax.set_title(title, fontsize=8.5, loc="center", pad=5, color="#283644")
        for row, name in enumerate(names):
            if row % 2 == 0:
                ax.axhspan(row-.45, row+.45, color="#f0f3f4", linewidth=0, zorder=0)
            for shift, (mode, color, marker, _) in zip((-.21, 0, .21), modes):
                sizes = groups[name, fraction, mode]
                value = median(sizes)
                low, _, high = quantiles(sizes, n=4, method="inclusive") if len(sizes)>1 else sizes*3
                ax.errorbar(value, row+shift, xerr=[[value-low],[high-value]], marker=marker,
                            color=color, markersize=3.5, capsize=1.8, elinewidth=1.1)
        ax.set_xscale("log")
        ax.set_xlim(.22, 4500)
        ax.xaxis.set_major_locator(FixedLocator([1, 32, 1024]))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v,_: f"{v:g}"))
        ax.xaxis.set_minor_locator(FixedLocator([]))
        ax.grid(axis="x", lw=.45, color="#ced5d9")
        ax.spines[["top","right","left"]].set_visible(False)
        ax.spines["bottom"].set_color("#b6c1c7")
        ax.tick_params(axis="y",length=0, labelsize=8)
        ax.tick_params(axis="x",length=2.2, labelsize=7.5)
    short = {"Signal K admin dependencies":"Signal K admin", "Freeboard-SK chartplotter":"Freeboard-SK"}
    axes[0].set_yticks(range(len(names)), [f"{short.get(n,n)} ({catalog[n]:,})" for n in names])
    axes[0].set_ylim(len(names)-.42, -.55)
    fig.supxlabel("Gzip-compressed JSON payload (KiB, log scale)", y=.017, fontsize=9)
    fig.legend(handles=[Line2D([],[],color=c,marker=m,ls="none",ms=4,label=t) for _,c,m,t in modes],
               ncol=3,loc="upper center",bbox_to_anchor=(.58,1.007),frameon=False,fontsize=9)
    fig.subplots_adjust(top=.845,bottom=.125,left=.245,right=.985,wspace=.10)
    destination.mkdir(exist_ok=True, parents=True)
    fig.savefig(destination/"coverage.pdf")
    fig.savefig(destination/"coverage.png",dpi=600)
    plt.close(fig)


if __name__ == "__main__":
    cli = ArgumentParser(description=__doc__)
    cli.add_argument("measurements", type=Path)
    cli.add_argument("output", type=Path)
    args = cli.parse_args()
    plot(args.measurements, args.output)
MCA_FILE_END_2

cat > "$work/overlay/paper/draw_figure3.py" <<'MCA_FILE_END_3'
"""Capture Figure 3 from the running desktop verifier; optionally record its workflow."""

import argparse
from pathlib import Path
import sys

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtTest import QTest
from PyQt5.QtWidgets import QApplication, QToolBar

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "software/src"))

from capture_frontend import render
from frontend import VerifierWindow, configure_application


def capture(output, frames=None):
    app = QApplication([])
    configure_application(app)
    capture_font = app.font()
    capture_font.setPointSizeF(16.5)
    app.setFont(capture_font)
    window = VerifierWindow()
    serial_font = window.serial.font()
    serial_font.setPointSize(12)
    window.serial.setFont(serial_font)
    window.serial.setMinimumWidth(224)
    result_font = window.result_group.font()
    result_font.setPointSizeF(18)
    window.result_group.setFont(result_font)
    row_height = window.records.fontMetrics().height() + 10
    for table in (window.records, window.controls):
        table.verticalHeader().setDefaultSectionSize(row_height)
    window.controls.setFixedHeight(window.controls.horizontalHeader().sizeHint().height() + 2 * row_height + 6)
    window.records.setMinimumHeight(window.records.horizontalHeader().sizeHint().height() + 3 * row_height + 6)
    window.resize(1160, 755)
    window.show()
    window.result_group.parentWidget().setSizes([402, 726])
    app.processEvents()
    toolbar = window.findChild(QToolBar)

    def click(action):
        QTest.mouseClick(toolbar.widgetForAction(action), Qt.LeftButton)
        app.processEvents()

    output.mkdir(parents=True, exist_ok=True)
    timer = QTimer()
    frame_count = 0

    def grab():
        nonlocal frame_count
        if not window.grab().save(str(frames / f"{frame_count:05d}.png")):
            raise IOError("Cannot record desktop window.")
        frame_count += 1

    if frames:
        frames.mkdir(parents=True, exist_ok=True)
        timer.timeout.connect(grab)
        timer.start(100)

    def pause(milliseconds):
        if frames:
            QTest.qWait(milliseconds)
        else:
            app.processEvents()

    pause(900)
    click(window.demo_action)
    assert window.using_demo and window.positions.text() == "0, 4, 8"
    pause(1300)
    click(window.verify_action)
    assert window.inventory_count.text() == "80"
    assert window.release.text() == "1"
    assert [window.records.item(i, 0).text() for i in range(window.records.rowCount())] == ["0", "4", "8"]
    pause(1300)
    for row in (1, 2):
        cell = window.records.visualItemRect(window.records.item(row, 1)).center()
        QTest.mouseClick(window.records.viewport(), Qt.LeftButton, pos=cell)
        pause(900)
    assert window.component.text() == "8 · baconjs" and window.component_version.text() == "3.0.23"
    assert window.location.text() == "npm:node_modules/baconjs"
    click(window.controls_action)
    for row in range(2):
        assert [window.controls.item(row, col).text() for col in (1, 2, 3)] == ["Block", "Blocked", "Passed"]
    assert window.records.verticalScrollBar().maximum() == 0
    assert window.statusBar().currentMessage().startswith("Verified: 3 ")
    pause(1900)
    timer.stop()
    render(window, output, "desktop_verification", "Maritime Component Audit desktop verifier")
    window.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "paper/figures")
    parser.add_argument("--frames", type=Path, help="Store window captures at 10 frames per second.")
    args = parser.parse_args()
    capture(args.output, args.frames)
MCA_FILE_END_3

cat > "$work/overlay/paper/draw_frontend_panels.py" <<'MCA_FILE_END_4'
"""Generate the manuscript figure from three actual desktop verifier states."""

import argparse
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from PyQt5.QtCore import QMarginsF, QPoint, QRect, QRectF, QSizeF, Qt, QTimer
from PyQt5.QtGui import (
    QColor, QFont, QImage, QPageSize, QPainter, QPdfWriter, QPicture, QRegion,
)
from PyQt5.QtTest import QTest
from PyQt5.QtWidgets import QApplication, QFileDialog, QLineEdit, QToolBar

DPI = 600
WIDTH_INCHES = 6.6
PANEL_LABELS = (
    "(a) Load the release anchor and opening",
    "(b) Verify the requested records",
    "(c) Run integrity checks",
)


def rectangle_for(group, last_child):
    """Crop the group after the last relevant widget."""
    bottom = last_child.mapTo(group, QPoint(0, last_child.height())).y()
    return QRect(0, 0, group.width(), min(group.height(), bottom + 4))


def capture(widget, rect):
    """Record the widget's paint operations rather than resampling a screenshot."""
    picture = QPicture()
    painter = QPainter(picture)
    widget.render(painter, -rect.topLeft(), QRegion(rect))
    painter.end()
    return picture, rect.width(), rect.height()


def capture_workflow(software_root, app):
    sys.path.insert(0, str(software_root / "src"))
    from frontend import VerifierWindow, configure_application
    from sbom_disclosure import write

    configure_application(app)
    font = app.font()
    font.setPointSizeF(16)
    app.setFont(font)
    window = VerifierWindow()
    window.serial.setFont(QFont("DejaVu Sans Mono", 12))
    window.serial.setMinimumWidth(240)
    rows = window.records
    row_height = rows.fontMetrics().height() + 9
    rows.verticalHeader().setDefaultSectionSize(row_height)
    rows.setFixedHeight(rows.horizontalHeader().sizeHint().height() + 3 * row_height + 3)
    rows.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    window.resize(1110, 560)
    window.show()
    window.result_group.parentWidget().setSizes([475, 605])
    app.processEvents()
    toolbar = window.findChild(QToolBar)
    inputs = window.positions.parentWidget()

    def click(action):
        QTest.mouseClick(toolbar.widgetForAction(action), Qt.LeftButton)
        app.processEvents()

    def import_file(action, path):
        def choose():
            dialog = app.activeModalWidget()
            assert isinstance(dialog, QFileDialog)
            filename = dialog.findChild(QLineEdit, "fileNameEdit")
            filename.clear()
            QTest.keyClicks(filename, str(path))
            QTest.keyClick(filename, Qt.Key_Return)

        QTimer.singleShot(40, choose)
        click(action)

    def input_excerpt():
        return capture(inputs, rectangle_for(inputs, window.positions))

    def result_excerpt(last_widget):
        group = window.result_group
        return capture(group, rectangle_for(group, last_widget))

    first, original, positions = window.cases["original"]
    _, altered, _ = window.cases["altered"]
    second, _, _ = window.cases["replay"]
    with TemporaryDirectory() as directory:
        paths = {}
        for stem, data in (
            ("release-1", first), ("opening", original),
            ("altered", altered), ("release-2", second),
        ):
            paths[stem] = Path(directory) / f"{stem}.json"
            write(paths[stem], data)

        import_file(window.anchor_action, paths["release-1"])
        import_file(window.disclosure_action, paths["opening"])
        QTest.mouseClick(window.positions, Qt.LeftButton)
        QTest.keyClicks(window.positions, ", ".join(map(str, positions)))
        app.processEvents()
        assert window.files == {"anchor": paths["release-1"], "proof": paths["opening"]}
        assert window.positions.text() == "0, 4, 8"
        assert window.result_title.text() == "No verification result."
        loaded = (input_excerpt(),)

        click(window.verify_action)
        assert window.release.text() == "1" and window.inventory_count.text() == "80"
        assert [rows.item(i, 0).text() for i in range(3)] == ["0", "4", "8"]
        assert rows.item(2, 1).text() == "baconjs" and rows.item(2, 2).text() == "3.0.23"
        assert "3 records verified" in window.result_title.text()
        cell = rows.visualItemRect(rows.item(2, 1)).center()
        QTest.mouseClick(rows.viewport(), Qt.LeftButton, pos=cell)
        app.processEvents()
        assert window.location.text() == "npm:node_modules/baconjs"
        verified = (result_excerpt(rows),)

        import_file(window.disclosure_action, paths["altered"])
        click(window.verify_action)
        assert window.files == {"anchor": paths["release-1"], "proof": paths["altered"]}
        assert window.release.text() == "1" and rows.rowCount() == 0
        assert window.statusBar().currentMessage() == "Disclosure rejected."

        import_file(window.anchor_action, paths["release-2"])
        import_file(window.disclosure_action, paths["opening"])
        click(window.verify_action)
        assert window.files == {"anchor": paths["release-2"], "proof": paths["opening"]}
        assert window.release.text() == "2" and rows.rowCount() == 0
        assert window.statusBar().currentMessage() == "Disclosure rejected."
        controls = window.controls
        controls.setFixedHeight(controls.horizontalHeader().sizeHint().height() + 66)
        click(window.controls_action)
        for i in range(2):
            assert controls.item(i, 1).text() == "Block"
            assert controls.item(i, 2).text() == "Blocked"
            assert controls.item(i, 3).text() == "Passed"
            assert controls.item(i, 3).foreground().color().name() == "#176549"
        integrity = capture(window.controls_group, window.controls_group.rect())

    window.close()
    return loaded[0], verified[0], integrity


def export(output, panels):
    output.mkdir(exist_ok=True, parents=True)
    margin, gutter, row_gap, caption_height = 12, 28, 22, 38
    panel_width = 544
    full_width = 2 * panel_width + gutter
    logical_width = 2 * margin + full_width
    panel_widths = (panel_width, panel_width, full_width)
    panel_heights = [
        height * width / original_width
        for (_, original_width, height), width in zip(panels, panel_widths)
    ]
    upper_height = max(panel_heights[:2])
    tops = (margin, margin, margin + upper_height + caption_height + row_gap)
    lefts = (margin, margin + panel_width + gutter, margin)
    caption_tops = (margin + upper_height, margin + upper_height, tops[2] + panel_heights[2])
    logical_height = caption_tops[2] + caption_height + margin
    pixels = round(WIDTH_INCHES * DPI)
    scale = pixels / logical_width
    height = round(logical_height * scale)

    def draw(device):
        painter = QPainter(device)
        painter.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing)
        painter.scale(scale, scale)
        painter.fillRect(QRectF(0, 0, logical_width, logical_height), Qt.white)
        caption_font = QFont("DejaVu Sans")
        caption_font.setPixelSize(20)
        painter.setFont(caption_font)
        for i, (picture, original_width, _) in enumerate(panels):
            left, top = lefts[i], tops[i]
            width, panel_height = panel_widths[i], panel_heights[i]
            widget_scale = width / original_width
            fragment = QRectF(left, top, width, panel_height)
            painter.save()
            painter.setClipRect(fragment)
            painter.translate(left, top)
            painter.scale(widget_scale * picture.logicalDpiX() / device.logicalDpiX(),
                          widget_scale * picture.logicalDpiY() / device.logicalDpiY())
            painter.drawPicture(QPoint(0, 0), picture)
            painter.restore()
            # Blank the area below the crop if a widget restored its own clip.
            painter.fillRect(QRectF(left - 1, fragment.bottom(), width + 2,
                                    logical_height - fragment.bottom() + 1), Qt.white)
            painter.setPen(QColor("#c7ccd3"))
            painter.drawRect(fragment)
            painter.setPen(QColor("#152941"))
            painter.drawText(
                QRectF(left, caption_tops[i] + 4, width, caption_height - 4),
                Qt.AlignHCenter | Qt.AlignVCenter, PANEL_LABELS[i],
            )
        painter.end()

    png = QImage(pixels, height, QImage.Format_RGB32)
    for setter in (png.setDotsPerMeterX, png.setDotsPerMeterY):
        setter(round(DPI / .0254))
    draw(png)
    if not png.save(str(output / "desktop_import_workflow.png")):
        raise RuntimeError("Could not write the frontend figure PNG.")

    pdf = QPdfWriter(str(output / "desktop_import_workflow.pdf"))
    pdf.setTitle("Maritime Component Audit desktop verification workflow")
    pdf.setCreator("Qt")
    pdf.setResolution(DPI)
    pdf.setPageSize(QPageSize(QSizeF(WIDTH_INCHES, height / DPI), QPageSize.Inch))
    pdf.setPageMargins(QMarginsF(0, 0, 0, 0))
    draw(pdf)


if __name__ == "__main__":
    parent = Path(__file__).resolve().parent
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--software-root", type=Path, default=parent.parent / "software")
    cli.add_argument("--output", type=Path, default=parent / "figures")
    args = cli.parse_args()
    QApplication.setAttribute(Qt.AA_DontUseNativeDialogs)
    app = QApplication([])
    export(args.output, capture_workflow(args.software_root.resolve(), app))
MCA_FILE_END_4

cat > "$work/overlay/paper/draw_workflow.py" <<'MCA_FILE_END_5'
"""Draw the manuscript's numbered registration and disclosure sequence."""

from argparse import ArgumentParser
from io import BytesIO
from math import inf, nextafter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt
from matplotlib.patches import Circle, FancyArrowPatch, Rectangle
from PIL import Image

CONNECTOR = "#39768b"
GOLD_EDGE = "#dfc878"
INK = "#27313e"
MUTED = "#777d85"
NAVY = "#213e6b"
OCHRE = "#9e5b23"
PALE = "#f5ecd0"
PAPER = "#ffffff"
RULE = "#e5e7e8"

DPI = 600
PRINT_WIDTH_INCH = 6
ROLES = ((PAPER, NAVY), (RULE, NAVY), (PALE, OCHRE), (PAPER, CONNECTOR))
PHASES = ((PAPER, RULE), (RULE, MUTED), (PALE, GOLD_EDGE), (PALE, OCHRE))
LABEL_BG = {"facecolor": PAPER, "edgecolor": "none", "pad": .8}
PDF_METADATA = {"Creator": "Matplotlib", "CreationDate": None, "ModDate": None}

plt.rcParams.update({
    "font.family": "STIXGeneral",
    "font.size": 12,
    "text.color": INK,
    "axes.labelcolor": INK,
    "xtick.color": INK,
    "ytick.color": INK,
    "pdf.fonttype": 42,
    "mathtext.fontset": "stix",
    "hatch.linewidth": 1.15,
})


def canvas(w, h):
    fig, ax = plt.subplots(figsize=(w, h))
    fig.subplots_adjust(left=0, right=1, bottom=0, top=1)
    ax.set(xlim=(0, w), ylim=(0, h))
    ax.axis("off")
    return fig, ax


def arrow(ax, x1, y1, x2, y2, *, dashed=False, color=INK, style="-|>"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                mutation_scale=13, shrinkA=0, shrinkB=0, lw=1.46,
                                color=color, linestyle=(0, (4, 3)) if dashed else "-", zorder=2))


def box(ax, x, y, w, h, palette, **kwargs):
    fill, edge = palette
    ax.add_patch(Rectangle((x, y), w, h, fc=fill, ec=edge, **kwargs))


def workflow_number(ax, x, y, step, color):
    ax.add_patch(Circle((x, y), .105, fc=color, ec="none", zorder=5))
    ax.text(x, y, str(step), color=PAPER, fontsize=11.5, ha="center", va="center", zorder=6)


def workflow_message(ax, x1, x2, y, label, *, dashed=False, label_x=None):
    arrow(ax, x1, y, x2, y, dashed=dashed)
    ax.text((x1 + x2) / 2 if label_x is None else label_x, y + .09, label, ha="center", va="bottom",
            fontsize=12.8, bbox=LABEL_BG, zorder=3)


def workflow_activation(ax, x, lo, hi, palette):
    box(ax, x - .055, lo, .11, hi - lo, palette, lw=1.12, zorder=3)


def workflow():
    fig, ax = canvas(11.6, 8.70)
    supplier, contract, storage, fleet = (2.53, 5.00, 7.63, 10.32)
    roles = (
        (supplier, "Supplier", "(Release preparation)", ROLES[0]),
        (contract, "Fabric chaincode", "(External Java contract)", ROLES[1]),
        (storage, "Fabric storage", "(Collections and ledger)", ROLES[2]),
        (fleet, "Fleet operator", "(Peer client and MCA)", ROLES[3]),
    )
    for x, title, subtitle, palette in roles:
        box(ax, x - 1.10, 7.98, 2.20, .62, palette, lw=1.10, zorder=3)
        ax.text(x, 8.36, title, ha="center", va="center", fontsize=16.6, zorder=4)
        ax.text(x, 8.12, subtitle, ha="center", va="center", fontsize=14.1,
                style="italic", zorder=4)
        ax.plot([x, x], [.14, 7.98], dashes=(8, 6), color=palette[1],
                lw=.90, alpha=.74, zorder=0)

    bands = (
        (5.94, 7.67, "Phase 1", "Release\npreparation and\nchecks"),
        (4.75, 5.94, "Phase 2", "Private storage\nand ledger entry"),
        (2.89, 4.75, "Phase 3", "Authorised\nanchor retrieval"),
        (.14, 2.89, "Phase 4", "Selective\ndisclosure and\nverification"),
    )
    for (lo, hi, phase, description), palette in zip(bands, PHASES):
        box(ax, .03, lo, 1.45, hi - lo, palette, lw=.95, zorder=3)
        ax.text(.755, lo + .70 * (hi - lo), phase, ha="center", va="center",
                fontsize=17, weight="bold")
        ax.text(.755, lo + .36 * (hi - lo), description, ha="center", va="center",
                fontsize=12.5, linespacing=1.32)
        ax.hlines(lo, 1.48, 11.53, color=RULE, linestyles=(0, (8, 7)), lw=.87)

    workflow_activation(ax, supplier, 6.77, 7.53, ROLES[0])
    workflow_number(ax, 2.78, 7.40, 1, ROLES[0][1])
    ax.text(2.97, 7.40, "Derive release anchor", va="center", fontsize=16.0)
    ax.text(2.97, 7.12, "Inventory, release identity and private seeds", va="center",
            fontsize=13.4, bbox=LABEL_BG)

    workflow_activation(ax, contract, 6.08, 6.96, ROLES[1])
    workflow_number(ax, 2.80, 6.92, 2, ROLES[0][1])
    workflow_message(ax, supplier + .058, contract - .058, 6.70, "Submit CreateAsset")
    workflow_number(ax, 5.27, 6.76, 3, ROLES[1][1])
    ax.text(5.47, 6.76, "Check release serial", va="center", fontsize=15.6)
    workflow_message(ax, contract - .058, supplier, 6.27, "Refuse duplicate serial", dashed=True)

    workflow_activation(ax, contract, 5.19, 5.75, ROLES[1])
    workflow_activation(ax, storage, 4.94, 5.66, ROLES[2])
    workflow_number(ax, 5.30, 5.66, 4, ROLES[1][1])
    workflow_message(ax, contract + .058, storage - .058, 5.43, "Write private collections",
                     label_x=6.48)
    ax.text(6.42, 5.03, "Peers validate and commit", va="center", ha="center",
            fontsize=12.8, bbox=LABEL_BG)
    ax.text(7.90, 5.47, "Anchor metadata in shared collection", va="center",
            fontsize=13.6, bbox=LABEL_BG)
    ax.text(7.90, 5.19, "Ordered array in supplier-only collection", va="center",
            fontsize=13.6, bbox=LABEL_BG)
    ax.text(7.90, 4.91, "Private-write hashes in channel ledger", va="center",
            fontsize=13.6, bbox=LABEL_BG)

    workflow_activation(ax, contract, 3.04, 4.61, ROLES[1])
    workflow_activation(ax, storage, 3.53, 4.20, ROLES[2])
    workflow_number(ax, 5.96, 4.55, 5, ROLES[3][1])
    workflow_message(ax, fleet, contract + .058, 4.35, "Authenticate peer and call ReadAsset",
                     label_x=7.67)
    workflow_message(ax, contract + .058, storage - .058, 3.94, "Read shared metadata")
    workflow_message(ax, storage - .058, contract + .058, 3.52, "Anchor metadata", dashed=True)
    workflow_message(ax, contract + .058, fleet, 3.14, "Return anchor to authorised operator",
                     dashed=True, label_x=8.50)

    workflow_activation(ax, supplier, 1.43, 2.61, ROLES[0])
    workflow_number(ax, 4.47, 2.59, 6, ROLES[3][1])
    workflow_message(ax, fleet, supplier + .058, 2.37, "Request independently identified positions")
    workflow_number(ax, 4.55, 1.86, 7, ROLES[0][1])
    workflow_message(ax, supplier + .058, fleet, 1.64, "Return selected records and opening proof",
                     dashed=True)
    workflow_activation(ax, fleet, .34, 1.25, ROLES[3])
    workflow_number(ax, 6.91, 1.09, 8, ROLES[3][1])
    ax.text(7.12, 1.09, "Verify locally with MCA", va="center",
            fontsize=15.6, bbox=LABEL_BG)
    ax.text(7.12, .77, "Check the expected release and positions", va="center",
            fontsize=13.4, bbox=LABEL_BG)
    ax.text(7.12, .45, "Refuse altered or cross-release openings", va="center",
            fontsize=13.4, bbox=LABEL_BG)
    return fig


def save_png(fig, path):
    pixel_width = PRINT_WIDTH_INCH * DPI
    render_dpi = nextafter(pixel_width / fig.get_figwidth(), inf)
    with BytesIO() as raster:
        fig.savefig(raster, format="png", dpi=render_dpi, facecolor=PAPER)
        raster.seek(0)
        with Image.open(raster) as image:
            assert image.width == pixel_width
            image.save(path, dpi=(DPI, DPI), optimize=True)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="directory for workflow.pdf and workflow.png")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    figure = workflow()
    figure.savefig(args.output / "workflow.pdf", facecolor=PAPER, metadata=PDF_METADATA)
    save_png(figure, args.output / "workflow.png")
    plt.close(figure)


if __name__ == "__main__":
    main()
MCA_FILE_END_5

python3 - "$work" "${1:-}" <<'MCA_BUILD'
import hashlib
import io
from pathlib import Path
import shutil
import sys
import tempfile
from urllib.request import Request, urlopen
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

work = Path(sys.argv[1])
local = sys.argv[2]
asset_url = "https://github.com/iffti283/maritime-component-audit/releases/download/v0.1.0-rc4/MCA_Software.zip"
asset_hash = "64c17918db068359170b6fe675f61f09e1ef81a2560590f22c03710ac37e8c3e"
result = Path("MCA_Companion_1.zip")
if result.exists():
    raise SystemExit(f"File already exists: {result}")
if local:
    asset = Path(local)
else:
    asset = work / "MCA_Software.zip"
    with urlopen(Request(asset_url, headers={"User-Agent": "MCA-companion/1"}), timeout=90) as response, asset.open("wb") as dst:
        shutil.copyfileobj(response, dst)
if hashlib.sha256(asset.read_bytes()).hexdigest() != asset_hash:
    raise SystemExit("RC4 software archive SHA-256 mismatch")

root = work / "companion"
root.mkdir()
with ZipFile(asset) as archive:
    for item in archive.infolist():
        name = item.filename
        if not item.is_dir() and (name.startswith("software/") or name in ("LICENSE", "CITATION.bib")):
            archive.extract(item, root)
shutil.copytree(work / "overlay", root, dirs_exist_ok=True)

# Normalise only the three Office theme display names. All other workbook
# parts, including cells, formulae and styles, are copied byte for byte.
workbook = root / "software/examples/Freeboard_Audit.xlsx"
target = io.BytesIO()
import re
with ZipFile(workbook) as original, ZipFile(target, "w") as cleaned:
    for item in original.infolist():
        part = original.read(item)
        if item.filename == "xl/theme/theme1.xml":
            part, count = re.subn(rb'(<a:(?:theme|clrScheme|fmtScheme) name=")[^"]*(")', rb'\g<1>Office\2', part)
            if count != 3:
                raise ValueError("Unexpected workbook theme structure")
        cleaned.writestr(item, part)
workbook.write_bytes(target.getvalue())

def entries():
    return sorted(path for path in root.rglob("*") if path.is_file())

manifest = "".join(
    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}\n"
    for path in entries()
)
(root / "SHA256SUMS.txt").write_text(manifest, encoding="utf-8", newline="\n")
with tempfile.NamedTemporaryFile(dir=result.parent, delete=False) as tmp:
    temp_path = Path(tmp.name)
try:
    with ZipFile(temp_path, "w", compression=ZIP_DEFLATED, compresslevel=9) as output:
        for path in entries():
            info = ZipInfo(path.relative_to(root).as_posix(), date_time=(2026, 11, 19, 0, 0, 0))
            info.create_system = 3
            info.compress_type = ZIP_DEFLATED
            info.external_attr = (0o100755 if path.suffix == ".sh" else 0o100644) << 16
            output.writestr(info, path.read_bytes(), compresslevel=9)
    # Exclusive creation preserves an existing companion on concurrent runs.
    with result.open("xb") as dst, temp_path.open("rb") as src:
        shutil.copyfileobj(src, dst)
finally:
    temp_path.unlink(missing_ok=True)
print(f"{len(entries())} files packaged in {result}")
print(f"SHA-256 {hashlib.sha256(result.read_bytes()).hexdigest()}")
MCA_BUILD
