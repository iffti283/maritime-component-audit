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
