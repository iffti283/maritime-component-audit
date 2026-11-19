"""Desktop audit inspector for verification of selective JSON disclosures."""

from pathlib import Path
import re
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QBrush, QColor, QFont, QPalette
from PyQt5.QtWidgets import (
    QAction, QApplication, QCheckBox, QFileDialog, QFormLayout, QGroupBox, QHeaderView,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QSizePolicy, QSpinBox, QSplitter, QStyle,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from demo_case import demo_cases
from figure_palette import INK, NAVY, PAPER, RED
from sbom_disclosure import read, verify

PAGE_SIZE = 50
INPUT_ERRORS = (ValueError, TypeError, KeyError, AttributeError, OverflowError,
                RecursionError, OSError)


def label(text=""):
    widget = QLabel(text)
    widget.setTextFormat(Qt.PlainText)
    widget.setWordWrap(True)
    widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return widget


def configure_application(app):
    app.setStyle("Windows")
    app.setFont(QFont("DejaVu Sans", 14))
    palette = app.palette()
    palette.setColor(QPalette.Window, QColor("#f6f5f1"))
    palette.setColor(QPalette.WindowText, QColor(INK))
    palette.setColor(QPalette.Text, QColor(INK))
    palette.setColor(QPalette.Highlight, QColor(NAVY))
    palette.setColor(QPalette.HighlightedText, QColor(PAPER))
    app.setPalette(palette)


def table(headers, stretch_column):
    result = QTableWidget(0, len(headers))
    result.setHorizontalHeaderLabels(headers)
    result.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
    result.horizontalHeader().setSectionResizeMode(stretch_column, QHeaderView.Stretch)
    result.verticalHeader().hide()
    result.verticalHeader().setDefaultSectionSize(31)
    result.setEditTriggers(QTableWidget.NoEditTriggers)
    result.setSelectionBehavior(QTableWidget.SelectRows)
    result.setSelectionMode(QTableWidget.SingleSelection)
    result.setAlternatingRowColors(True)
    return result


class VerifierWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Maritime Component Audit")
        self.resize(1176, 630)
        self.cases = demo_cases()
        self.using_demo = False
        self.files = {}
        self.visible_records = []
        self.verified_records = []
        self.requested_positions = []
        self._build_menu()
        self._build_inspector()
        self.statusBar().showMessage("Load the Freeboard-SK example or open the audit files.")

    def _build_menu(self):
        def action(title, icon, fn):
            item = QAction(self.style().standardIcon(icon), title, self)
            item.triggered.connect(fn)
            return item

        self.anchor_action = action("Open anchor", QStyle.SP_DialogOpenButton,
                                    lambda: self.choose_file("anchor"))
        self.disclosure_action = action("Open disclosure", QStyle.SP_DirOpenIcon,
                                        lambda: self.choose_file("proof"))
        self.demo_action = action("Load demo", QStyle.SP_FileDialogDetailedView, self.load_demo)
        self.verify_action = action("Verify selection", QStyle.SP_DialogApplyButton, self.verify_inputs)
        self.controls_action = action("Run integrity checks", QStyle.SP_BrowserReload, self.run_controls)
        file_menu = self.menuBar().addMenu("&File")
        file_menu.addActions([self.anchor_action, self.disclosure_action, self.demo_action])
        audit_menu = self.menuBar().addMenu("&Audit")
        audit_menu.addActions([self.verify_action, self.controls_action])
        name = label("Maritime Component Audit  ")
        name.setWordWrap(False)
        self.menuBar().setCornerWidget(name, Qt.TopRightCorner)
        toolbar = self.addToolBar("Audit toolbar")
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        toolbar.addActions([self.anchor_action, self.disclosure_action, self.demo_action])
        toolbar.addSeparator()
        toolbar.addActions([self.verify_action, self.controls_action])

    def _build_inspector(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(12, 10, 12, 10)

        upper = QSplitter(Qt.Horizontal)
        layout.addWidget(upper, 1)
        inputs = QGroupBox("Audit inputs")
        form = QFormLayout(inputs)
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        form.setLabelAlignment(Qt.AlignLeft)
        form.setVerticalSpacing(10)
        form.setHorizontalSpacing(14)
        form.setContentsMargins(14, 19, 14, 14)
        self.source = label("No inventory loaded")
        self.source.setWordWrap(False)
        self.file_labels = {key: label("Not loaded") for key in ("anchor", "proof")}
        self.positions = QLineEdit()
        self.positions.setPlaceholderText("e.g. 0, 4, 8")
        self.positions.textChanged.connect(self.reset_result)
        form.addRow("Source", self.source)
        form.addRow("Anchor", self.file_labels["anchor"])
        form.addRow("Disclosure", self.file_labels["proof"])
        form.addRow("Positions", self.positions)
        self.release = label("—")
        self.inventory_count = label("—")
        self.serial = label("—")
        self.serial.setFont(QFont("DejaVu Sans Mono", 11))
        self.serial.setMinimumWidth(self.serial.fontMetrics().horizontalAdvance("urn:uuid:00000000-0000-0000-0000-000000000000") + 6)
        form.addRow("Inventory serial", self.serial)
        form.addRow("Document version", self.release)
        form.addRow("Inventory records", self.inventory_count)
        upper.addWidget(inputs)

        self.result_group = QGroupBox("Disclosure verification")
        results = QVBoxLayout(self.result_group)
        results.setContentsMargins(14, 15, 14, 12)
        self.result_title = label("No verification result.")
        results.addWidget(self.result_title)
        self.records = table(["Position", "Component", "Version"], 1)
        self.records.currentCellChanged.connect(self.show_record)
        results.addWidget(self.records, 1)
        options = QHBoxLayout()
        self.show_all = QCheckBox("Show all disclosed records")
        self.show_all.toggled.connect(self.select_record_set)
        options.addWidget(self.show_all)
        options.addStretch()
        self.page_label = label("Page")
        self.page = QSpinBox()
        self.page.setMinimum(1)
        self.page.setAccessibleName("Record page")
        self.page.valueChanged.connect(self.display_page)
        options.addWidget(self.page_label)
        options.addWidget(self.page)
        results.addLayout(options)
        self.show_all.hide()
        self.page.hide()
        self.page_label.hide()
        details = QGroupBox("Selected record")
        detail_form = QFormLayout(details)
        detail_form.setVerticalSpacing(7)
        self.component = label("—")
        self.component_version = label("—")
        self.location = QLineEdit("—")
        self.location.setReadOnly(True)
        self.location.setFrame(False)
        self.location.setStyleSheet("background: transparent")
        self.location.setAccessibleName("Selected component BOM reference")
        self.component_digest = label("—")
        self.component_digest.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        detail_form.addRow("Component", self.component)
        detail_form.addRow("Version", self.component_version)
        detail_form.addRow("BOM reference", self.location)
        detail_form.addRow("Anchor digest", self.component_digest)
        results.addWidget(details)
        upper.addWidget(self.result_group)
        upper.setSizes([455, 687])
        upper.setCollapsible(0, False)
        upper.setCollapsible(1, False)

        self.controls_group = QGroupBox("Integrity tests with invalid inputs")
        controls_layout = QHBoxLayout(self.controls_group)
        controls_layout.setContentsMargins(14, 12, 14, 12)
        self.controls = table(["Test input", "Expected response", "Observed response", "Test result"], 0)
        self.controls.setRowCount(2)
        self.controls.setFixedHeight(99)
        self.controls.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.checks = (
            ("altered", "Altered component version"),
            ("replay", "Cross-release replay"),
        )
        for index, (_, title) in enumerate(self.checks):
            self.controls.setItem(index, 0, QTableWidgetItem(title))
            self.controls.setItem(index, 1, QTableWidgetItem("Block"))
            self.controls.setItem(index, 2, QTableWidgetItem("—"))
            self.controls.setItem(index, 3, QTableWidgetItem("Not run"))
        controls_layout.addWidget(self.controls)
        layout.addWidget(self.controls_group)
        self.controls_group.hide()
        self.digest = ""

    def reset_result(self):
        self.verified_records = []
        self.requested_positions = []
        self.show_all.blockSignals(True)
        self.show_all.setChecked(False)
        self.show_all.blockSignals(False)
        self.show_all.hide()
        self.page.hide()
        self.page_label.hide()
        self.visible_records = []
        self.digest = ""
        self.records.setRowCount(0)
        self.result_group.setTitle("Disclosure verification")
        self.result_title.setText("No verification result.")
        self.result_title.setStyleSheet("")
        self.serial.setText("—")
        self.release.setText("—")
        self.inventory_count.setText("—")
        self.show_record(-1)
        self.statusBar().showMessage("Choose Verify selection to check the loaded disclosure.")

    def load_demo(self):
        self.files.clear()
        self.using_demo = True
        self.controls_group.show()
        self.source.setText("Freeboard-SK demo")
        self.file_labels["anchor"].setText("Local demo anchor")
        self.file_labels["proof"].setText("Demo disclosure")
        self.positions.setText(", ".join(map(str, self.cases["original"][2])))
        self.reset_result()

    def choose_file(self, key):
        selection = {"anchor": "release anchor", "proof": "disclosure"}[key]
        filename, _ = QFileDialog.getOpenFileName(self, f"Open {selection}", "", "JSON (*.json);;All files (*)")
        if not filename:
            return
        if self.using_demo:
            self.using_demo = False
            self.controls_group.hide()
            for widget in self.file_labels.values():
                widget.setText("Not loaded")
        self.files[key] = Path(filename)
        self.file_labels[key].setText(self.files[key].name)
        self.source.setText("Imported files")
        self.reset_result()

    def verify_inputs(self):
        self.reset_result()
        try:
            values = re.split(r"[,\s]+", self.positions.text().strip())
            if any(not re.fullmatch(r"\d+", value) for value in values):
                raise ValueError("Enter integer positions separated by commas or spaces.")
            positions = list(map(int, values))
            if self.using_demo:
                anchor, disclosure, _ = self.cases["original"]
            else:
                if set(self.files) != {"anchor", "proof"}:
                    raise ValueError("Open both the release anchor and disclosure JSON files.")
                anchor, disclosure = read(self.files["anchor"]), read(self.files["proof"])
            accepted = verify(anchor, disclosure, positions)
        except INPUT_ERRORS as error:
            self.result_title.setText(f"Invalid input: {error}")
            self.statusBar().showMessage("Verification did not complete.")
            return
        self.serial.setText(anchor["serialNumber"])
        self.release.setText(str(anchor["version"]))
        self.inventory_count.setText(str(anchor["componentCount"]))
        if not accepted:
            self.result_title.setText("Disclosure rejected. The opening does not match the supplied anchor.")
            self.result_title.setStyleSheet(f"color: {RED}; font-weight: bold;")
            self.statusBar().showMessage("Disclosure rejected.")
            return

        records = disclosure["records"]
        self.result_group.setTitle("Verified disclosure")
        mode = {"batch": "Batch", "full": "Full", "individual": "Independent paths"}[disclosure["mode"]]
        self.digest = anchor["root"]
        self.verified_records = records
        self.requested_positions = sorted(positions)
        self.show_all.setVisible(len(records) > len(positions))
        self.result_title.setText(f"{mode} · release-bound v2 · {len(records)} records verified")
        self.select_record_set()
        self.records.setFocus()
        self.statusBar().showMessage(f"Verified: {len(records)} disclosed records match the supplied anchor.")

    def select_record_set(self):
        showing_all = self.show_all.isChecked() or len(self.verified_records) == len(self.requested_positions)
        count = len(self.verified_records) if showing_all else len(self.requested_positions)
        pages = max(1, (count + PAGE_SIZE - 1) // PAGE_SIZE)
        self.page.blockSignals(True)
        self.page.setMaximum(pages)
        self.page.setValue(1)
        self.page.setSuffix(f" / {pages}")
        self.page.blockSignals(False)
        self.page.setVisible(pages > 1)
        self.page_label.setVisible(pages > 1)
        self.display_page(1)

    def display_page(self, page):
        start = (page - 1) * PAGE_SIZE
        stop = start + PAGE_SIZE
        if self.show_all.isChecked() or len(self.verified_records) == len(self.requested_positions):
            self.visible_records = self.verified_records[start:stop]
        else:
            # A verified full opening has one ordered entry at every position.
            self.visible_records = [self.verified_records[i] for i in self.requested_positions[start:stop]]
        self.records.clearContents()
        self.records.setRowCount(len(self.visible_records))
        for row, record in enumerate(self.visible_records):
            component = record["component"]
            values = (record["index"], component.get("name", ""), component.get("version", ""))
            for column, value in enumerate(values):
                self.records.setItem(row, column, QTableWidgetItem(str(value)))
        if self.visible_records:
            self.records.setCurrentCell(0, 1)
            self.records.selectRow(0)
            self.show_record(0)

    def show_record(self, row, *_):
        if not 0 <= row < len(self.visible_records):
            self.component.setText("—")
            self.component_version.setText("—")
            self.location.setText("—")
            self.component_digest.setText("—")
            self.component_digest.setToolTip("")
            return
        record = self.visible_records[row]
        component = record["component"]
        self.component.setText(f"{record['index']} · {component.get('name', '')}")
        self.component_version.setText(str(component.get("version", "")))
        self.location.setText(str(component.get("bom-ref", "—")))
        self.location.setCursorPosition(0)
        self.component_digest.setText(f"{self.digest[:20]}…{self.digest[-12:]}")
        self.component_digest.setToolTip(self.digest)

    def run_controls(self):
        self.controls_group.show()
        for row, (key, _) in enumerate(self.checks):
            rejected = not verify(*self.cases[key])
            observed = QTableWidgetItem("Blocked" if rejected else "Accepted")
            self.controls.setItem(row, 2, observed)
            verdict = QTableWidgetItem("Passed" if rejected else "Failed")
            verdict.setForeground(QBrush(QColor("#176549" if rejected else RED)))
            self.controls.setItem(row, 3, verdict)


def main():
    app = QApplication(sys.argv)
    configure_application(app)
    window = VerifierWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
