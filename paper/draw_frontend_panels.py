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
