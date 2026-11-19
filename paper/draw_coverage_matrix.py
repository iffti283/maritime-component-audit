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
