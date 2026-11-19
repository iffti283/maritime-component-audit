"""Capture Figure 3 from the running desktop verifier; optionally record its workflow."""

import argparse
from pathlib import Path
import sys

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
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
    # Explicit line breaks keep long identifiers inside the printed Qt fields.
    serial = window.serial.text()
    first, second, third, fourth, last = serial.split("-")
    window.serial.setText(f"{first}-\n{second}-{third}-{fourth}-\n{last}")
    window.serial.setMinimumHeight(3 * window.serial.fontMetrics().lineSpacing() + 6)
    window.component_digest.setFont(QFont("DejaVu Sans Mono", 12))
    digest = window.component_digest.text()
    prefix, suffix = digest.split("…")
    window.component_digest.setText(f"{prefix}…\n{suffix}")
    window.component_digest.setMinimumHeight(2 * window.component_digest.fontMetrics().lineSpacing() + 6)
    app.processEvents()
    render(window, output, "desktop_verification", "Maritime Component Audit desktop verifier")
    window.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "paper/figures")
    parser.add_argument("--frames", type=Path, help="Store window captures at 10 frames per second.")
    args = parser.parse_args()
    capture(args.output, args.frames)
