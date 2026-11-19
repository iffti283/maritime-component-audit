"""Draw independent authentication paths and the shared frontier for Figure 2."""
from argparse import ArgumentParser
from io import BytesIO
from math import inf, nextafter
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt
from matplotlib.patches import Circle, FancyArrowPatch, Polygon, Rectangle
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "software/src"))
from figure_palette import INK, PAPER
from sbom_disclosure import frontier as proof_frontier

DPI = 600
PRINT_WIDTH_INCH = 6
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


def span_label(level, index):
    span = 2 ** level
    return str(index) if level == 0 else f"{index * span}–{(index + 1) * span - 1}"


def frontier():
    fig, ax = canvas(10.9, 6.16)
    ax.set_aspect("equal")
    positions, height = (2, 3, 6), 3
    supplied = proof_frontier(positions, height)
    independent = {leaf: proof_frontier((leaf,), height) for leaf in positions}
    rebuilt = {(level, i >> level) for level in range(1, height + 1) for i in positions}
    opened = {(0, i) for i in positions}
    needed = set(supplied) | opened | rebuilt

    # Colours describe a node's role in the batch, including when it also occurs
    # in an independent path. A range identifies a subtree by its outer leaves.
    ink = "#202327"
    muted = "#585b5e"
    roles = {
        "Opened leaf": "#f4bc3c",
        "Frontier hash": "#69b399",
        "Recomputed hash": "#a76ca0",
        "Below frontier": "#e4e3df",
    }

    node_shapes = {
        "Opened leaf": "square",
        "Frontier hash": "diamond",
        "Recomputed hash": "circle",
        "Below frontier": "circle",
    }

    def draw_node(x, y, radius, name, *, zorder=3):
        style = dict(fc=roles[name], ec=muted if name == "Below frontier" else ink,
                     lw=1.05, linestyle=(0, (2, 1.6)) if name == "Below frontier" else "-",
                     zorder=zorder)
        shape = node_shapes[name]
        if shape == "square":
            marker = Rectangle((x - radius, y - radius), 2 * radius, 2 * radius, **style)
        elif shape == "diamond":
            corner = 1.23 * radius
            marker = Polygon([(x, y + corner), (x + corner, y), (x, y - corner),
                              (x - corner, y)], **style)
        else:
            marker = Circle((x, y), radius, **style)
        ax.add_patch(marker)

    def role(node):
        if node in opened:
            return "Opened leaf"
        if node in supplied:
            return "Frontier hash"
        if node in rebuilt:
            return "Recomputed hash"
        return "Below frontier"

    def tier(bottom, top):
        ax.add_patch(Rectangle((.09, bottom), 10.72, top - bottom,
                               fc="none", ec="#505356", lw=1.04,
                               linestyle=(0, (6, 4)), zorder=0))

    def heading(x, y, letter, title):
        ax.text(x, y, letter, ha="center", va="center", fontsize=15.5,
                weight="bold", color="black")
        ax.text(x + .29, y, title, va="center", fontsize=18.5, weight="bold", color=ink)

    tier(2.63, 6.07)
    heading(.40, 5.80, "a", "Batch reconstruction")
    ax.text(10.53, 5.80, "Requested leaves   2, 3, 6", ha="right", va="center",
            fontsize=15.2, color=ink)

    leaf_y, step_y = 3.42, .64
    locations = {
        (level, index): (1.46 + 1.25 * (index * 2**level + (2**level - 1) / 2),
                         leaf_y + step_y * level)
        for level in range(height + 1)
        for index in range((1 << height) >> level)
    }
    for level, label in enumerate(("Leaves", "Level 1", "Level 2", "Root")):
        y = leaf_y + step_y * level
        ax.text(.32, y, label, va="center", fontsize=14.4, color=muted)

    radius = .232
    for (level, index), child_xy in locations.items():
        if level == height:
            continue
        parent_xy = locations[level + 1, index >> 1]
        is_used = (level, index) in needed
        ax.add_patch(FancyArrowPatch(
            child_xy, parent_xy, arrowstyle="-|>" if is_used else "-",
            mutation_scale=10.6, shrinkA=radius * 72 + .5, shrinkB=radius * 72 + .6,
            color=ink if is_used else "#949492", lw=1.32 if is_used else .90,
            linestyle="-" if is_used else (0, (3, 2.2)), zorder=1))

    for node, (x, y) in locations.items():
        name = role(node)
        draw_node(x, y, radius, name)
        ax.text(x, y, span_label(*node), ha="center", va="center", fontsize=15.4,
                color=ink, weight="bold", zorder=4)

    for x, label in zip((1.03, 3.43, 5.93, 8.81), roles):
        draw_node(x, 2.88, .086, label)
        ax.text(x + .16, 2.88, label, va="center", fontsize=14.5, color=ink)

    tier(.09, 2.49)
    heading(.40, 2.20, "b", "Sibling hashes in the proof")
    split = 5.64
    ax.plot([split, split], [.32, 1.91], lw=.86, color="#c5c4c1")
    ax.text(.36, 1.80, "Independent paths", va="center", fontsize=17.0,
            weight="bold", color=ink)
    ax.text(5.31, 1.80, f"{sum(map(len, independent.values()))} entries",
            ha="right", va="center", fontsize=15.5, color=ink)
    ax.text(5.96, 1.80, "Shared frontier", va="center", fontsize=17.0,
            weight="bold", color=ink)
    ax.text(10.50, 1.80, f"{len(supplied)} hashes", ha="right",
            va="center", fontsize=15.5, color=ink)

    def proof_strip(x, y, nodes, width, height):
        for i, node in enumerate(nodes):
            left = x + i * width
            fill = roles[role(node)]
            ax.add_patch(Rectangle((left, y - height / 2), width, height,
                                   fc=fill, ec=ink, lw=.85))
            ax.text(left + width / 2, y, span_label(*node), ha="center",
                    va="center", fontsize=15.2, color=ink, weight="bold")

    for row, (leaf, siblings) in enumerate(independent.items()):
        y = 1.40 - .425 * row
        ax.text(.45, y, f"Leaf {leaf}", va="center", fontsize=15.2, color=ink)
        proof_strip(1.47, y, siblings, 1.28, .365)
    ax.text(5.98, 1.38, "Leaves 2, 3 and 6", va="center", fontsize=15.2, color=ink)
    proof_strip(5.98, .94, supplied, 1.48, .438)
    ax.text(5.98, .48, "Each frontier hash is supplied once.", va="center",
            fontsize=14.5, color=muted)
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


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    destination = parser.parse_args().output
    destination.mkdir(parents=True, exist_ok=True)
    fig = frontier()
    fig.savefig(destination / "frontier_example.pdf", facecolor=PAPER, metadata=PDF_METADATA)
    save_png(fig, destination / "frontier_example.png")
    plt.close(fig)
