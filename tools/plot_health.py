"""
Wizualizacja danych zdrowotnych z Mibro Watch C4.
Wczytuje health_export.csv i rysuje:
  1. Hipnogram (fazy snu)
  2. Tętno (HR) w ciągu dnia
"""

import csv
import datetime
import sys
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.dates as mdates
import numpy as np

CSV_PATH = "data/health_export.csv"

STAGE_ORDER  = {"Awake": 3, "REM": 2, "Light": 1, "Deep": 0}
STAGE_LABELS = {0: "Deep", 1: "Light", 2: "REM", 3: "Awake"}
STAGE_COLORS = {"Awake": "#f0a500", "REM": "#7b61ff", "Light": "#4fc3f7", "Deep": "#1565c0"}


def load_csv(path):
    sleep, hr, hr_agg, steps = [], [], [], None
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            t = row["type"]
            if t == "sleep":
                sleep.append({
                    "dt": datetime.datetime.fromisoformat(row["datetime"]),
                    "stage": row["value"],
                    "dur": int(row["extra"].replace("dur=", "").replace("min", "")),
                })
            elif t == "hr":
                hr.append({
                    "dt": datetime.datetime.fromisoformat(row["datetime"]),
                    "bpm": int(row["value"]),
                })
            elif t == "hr_agg":
                hr_agg.append({
                    "dt": datetime.datetime.fromisoformat(row["datetime"]),
                    "val": int(row["value"]),
                })
            elif t == "steps":
                steps = {
                    "steps": int(row["value"]),
                    "extra": row["extra"],
                }
    return sleep, hr, hr_agg, steps


def plot_hypnogram(ax, sleep):
    if not sleep:
        ax.text(0.5, 0.5, "Brak danych snu", ha="center", va="center",
                transform=ax.transAxes, fontsize=12, color="gray")
        return

    sorted_sleep = sorted(sleep, key=lambda r: r["dt"])

    for rec in sorted_sleep:
        start = mdates.date2num(rec["dt"])
        end   = mdates.date2num(rec["dt"] + datetime.timedelta(minutes=rec["dur"]))
        y     = STAGE_ORDER.get(rec["stage"], 3)
        color = STAGE_COLORS.get(rec["stage"], "#aaa")
        ax.barh(y, end - start, left=start, height=0.8,
                color=color, edgecolor="white", linewidth=0.3)

    ax.set_yticks(list(STAGE_ORDER.values()))
    ax.set_yticklabels([STAGE_LABELS[i] for i in sorted(STAGE_LABELS)], fontsize=10)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=0, ha="center")
    ax.set_xlabel("Czas", fontsize=10)
    ax.set_title("Hipnogram snu — Mibro Watch C4 (2026-05-09)", fontsize=13, fontweight="bold")
    ax.grid(axis="x", linestyle="--", alpha=0.4)
    ax.spines[["top", "right"]].set_visible(False)

    # Total time per stage
    totals = {}
    for r in sleep:
        totals[r["stage"]] = totals.get(r["stage"], 0) + r["dur"]
    legend_patches = [
        mpatches.Patch(color=STAGE_COLORS[s], label=f"{s}  {totals.get(s,0)} min")
        for s in ["Deep", "REM", "Light", "Awake"] if s in totals
    ]
    ax.legend(handles=legend_patches, loc="upper right", fontsize=9,
              framealpha=0.9, title="Czas w fazie")

    total = sum(r["dur"] for r in sleep)
    sleep_start = sorted_sleep[0]["dt"]
    sleep_end   = sorted_sleep[-1]["dt"] + datetime.timedelta(minutes=sorted_sleep[-1]["dur"])
    ax.set_xlim(mdates.date2num(sleep_start - datetime.timedelta(minutes=10)),
                mdates.date2num(sleep_end   + datetime.timedelta(minutes=10)))
    ax.text(0.01, 0.02, f"Łącznie: {total//60}h {total%60}min",
            transform=ax.transAxes, fontsize=9, color="#555",
            va="bottom")


def plot_hr(ax, hr, hr_agg, steps):
    if not hr and not hr_agg:
        ax.text(0.5, 0.5, "Brak danych HR", ha="center", va="center",
                transform=ax.transAxes, fontsize=12, color="gray")
        return

    all_hr = sorted(hr + hr_agg, key=lambda r: r["dt"])

    times = [r["dt"] for r in all_hr]
    bpms  = [r.get("bpm") or r.get("val") for r in all_hr]

    ax.plot(times, bpms, "o-", color="#e53935", linewidth=2,
            markersize=6, markerfacecolor="white", markeredgewidth=2)

    for t, b in zip(times, bpms):
        ax.annotate(str(b), (t, b), textcoords="offset points", xytext=(0, 8),
                    ha="center", fontsize=10, color="#c62828")

    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.set_ylabel("BPM", fontsize=10)
    ax.set_title("Tętno (HR)", fontsize=13, fontweight="bold")
    ax.grid(linestyle="--", alpha=0.4)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_ylim(min(bpms) - 10, max(bpms) + 15)

    if steps:
        ax.text(0.99, 0.05,
                f"Kroki: {steps['steps']}  |  {steps['extra']}",
                transform=ax.transAxes, fontsize=9, color="#555",
                ha="right", va="bottom")


def main():
    sleep, hr, hr_agg, steps = load_csv(CSV_PATH)
    print(f"Wczytano: {len(sleep)} faz snu, {len(hr)} HR, {len(hr_agg)} HR-agg")

    fig, axes = plt.subplots(2, 1, figsize=(14, 8),
                             gridspec_kw={"height_ratios": [3, 1.5]})
    fig.patch.set_facecolor("#fafafa")
    for ax in axes:
        ax.set_facecolor("#f5f5f5")

    plot_hypnogram(axes[0], sleep)
    plot_hr(axes[1], hr, hr_agg, steps)

    plt.tight_layout(pad=2.5)
    out = "health_chart.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"Zapisano: {out}")
    plt.show()


if __name__ == "__main__":
    main()
