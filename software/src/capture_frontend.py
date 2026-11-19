"""Export a Qt window as a vector PDF and a print-resolution PNG."""
from PyQt5.QtCore import QMarginsF, QSizeF, Qt
from PyQt5.QtGui import QImage, QPageSize, QPainter, QPdfWriter

DPI = 600
PRINT_WIDTH_INCHES = 6


def render(window, output, stem, title):
    pixels = DPI * PRINT_WIDTH_INCHES
    scale = pixels / window.width()
    height = round(window.height() * scale)
    png = QImage(pixels, height, QImage.Format_RGB32)
    png.fill(Qt.white)
    for setter in (png.setDotsPerMeterX, png.setDotsPerMeterY):
        setter(round(DPI / .0254))
    painter = QPainter(png)
    painter.scale(scale, scale)
    window.render(painter)
    painter.end()
    if not png.save(str(output / f"{stem}.png")):
        raise RuntimeError("Could not export the PNG.")

    pdf = QPdfWriter(str(output / f"{stem}.pdf"))
    pdf.setTitle(title)
    pdf.setCreator("Qt")
    pdf.setResolution(DPI)
    pdf.setPageSize(QPageSize(QSizeF(PRINT_WIDTH_INCHES, height / DPI), QPageSize.Inch))
    pdf.setPageMargins(QMarginsF(0, 0, 0, 0))
    painter = QPainter(pdf)
    painter.scale(scale, scale)
    window.render(painter)
    painter.end()
