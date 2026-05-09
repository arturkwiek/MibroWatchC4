"""
Parse health data from mibro_captured_frames.json and export to CSV.
Replaces the need for a live BLE connection when frames were already captured.

Usage:
    python export_captured_health.py
    python export_captured_health.py --json mibro_captured_frames.json --csv health_export.csv
"""

import json
import csv
import struct
import datetime
import argparse
import sys

from mibro import protocol as proto

FRAME_MAGIC = bytes([0x88, 0x01])


def load_frames(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _hex_field(entry: dict) -> str:
    return entry.get("hex") or entry.get("raw") or ""


def parse_all(frames: list[dict]):
    hr: list[proto.HRRecord] = []
    spo2: list[proto.SpO2Record] = []
    sleep: list[proto.SleepStageRecord] = []
    hr_agg: list[proto.HRAggregate] = []
    steps: proto.StepsRecord | None = None
    sleep_detail_raw: list[str] = []

    for entry in frames:
        raw_hex = _hex_field(entry)
        if not raw_hex:
            continue
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            continue

        frame = proto.parse_frame(raw)
        if frame is None or frame["cmd"] != 0x25:
            continue

        result = proto.parse_data_frame(frame["payload"])
        if result is None:
            continue

        t = result["type"]
        if t == "hr":
            hr.extend(result["records"])
        elif t == "spo2":
            spo2.extend(result["records"])
        elif t == "sleep_stage":
            sleep.extend(result["records"])
        elif t == "steps":
            if result["record"]:
                steps = result["record"]
        elif t == "hr_agg":
            hr_agg.extend(result["records"])
        elif t == "sleep_detail":
            sleep_detail_raw.append(result["raw"])

    return hr, spo2, sleep, hr_agg, steps, sleep_detail_raw


def dedup(records, key=lambda r: r.timestamp):
    """Remove duplicate records (same timestamp appear in duplicate frames)."""
    seen: set = set()
    out = []
    for r in records:
        k = key(r)
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def print_summary(hr, spo2, sleep, hr_agg, steps, sleep_detail_raw):
    print(f"\n{'='*55}")
    print("Mibro Watch C4  |  parsed from captured HCI frames")
    print(f"{'='*55}")

    print(f"\nHR records:        {len(hr)}")
    if hr:
        bpms = [r.bpm for r in hr]
        print(f"  avg={sum(bpms)//len(bpms)} min={min(bpms)} max={max(bpms)} bpm")
        for r in sorted(hr, key=lambda x: x.timestamp):
            print(f"  {r.dt.strftime('%H:%M')}  {r.bpm} bpm")

    print(f"\nSpO2 records:      {len(spo2)}")
    for r in sorted(spo2, key=lambda x: x.timestamp):
        print(f"  {r.dt.strftime('%H:%M')}  {r.spo2}%")

    print(f"\nSleep stages:      {len(sleep)}")
    for r in sorted(sleep, key=lambda x: x.timestamp):
        print(f"  {r.dt.strftime('%H:%M')}  {r.stage_name:<6}  {r.duration_min} min")

    print(f"\nHR-agg records:    {len(hr_agg)}")
    for r in sorted(hr_agg, key=lambda x: x.timestamp):
        print(f"  {r.dt.strftime('%H:%M')}  {r.value}")

    if steps:
        print(f"\nSteps today:       {steps.steps}")
        print(f"  calories={steps.calories}  distance={steps.distance_m}m")

    if sleep_detail_raw:
        print(f"\nSleep detail raw:  {len(sleep_detail_raw)} frames")

    print(f"{'='*55}\n")


def export_csv(path, hr, spo2, sleep, hr_agg, steps):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "datetime", "value", "unit", "extra"])

        for r in sorted(hr, key=lambda x: x.timestamp):
            w.writerow(["hr", r.dt.isoformat(), r.bpm, "bpm", ""])

        for r in sorted(spo2, key=lambda x: x.timestamp):
            w.writerow(["spo2", r.dt.isoformat(), r.spo2, "%", ""])

        for r in sorted(sleep, key=lambda x: x.timestamp):
            w.writerow(["sleep", r.dt.isoformat(), r.stage_name, "stage",
                        f"dur={r.duration_min}min"])

        for r in sorted(hr_agg, key=lambda x: x.timestamp):
            w.writerow(["hr_agg", r.dt.isoformat(), r.value, "bpm_agg", ""])

        if steps:
            w.writerow(["steps", datetime.datetime.now().date().isoformat(),
                        steps.steps, "steps",
                        f"cal={steps.calories} dist={steps.distance_m}m"])

    print(f"Exported to {path}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--json", default="data/mibro_captured_frames.json")
    p.add_argument("--csv", default="data/health_export.csv")
    p.add_argument("--no-dedup", action="store_true", help="Keep duplicate records")
    args = p.parse_args()

    print(f"Loading {args.json}…")
    frames = load_frames(args.json)
    print(f"  {len(frames)} total entries")

    hr, spo2, sleep, hr_agg, steps, sleep_detail_raw = parse_all(frames)

    if not args.no_dedup:
        hr = dedup(hr)
        spo2 = dedup(spo2)
        sleep = dedup(sleep)
        hr_agg = dedup(hr_agg)

    print_summary(hr, spo2, sleep, hr_agg, steps, sleep_detail_raw)
    export_csv(args.csv, hr, spo2, sleep, hr_agg, steps)


if __name__ == "__main__":
    main()
