"""
mibro_hci_parse.py -- Parser BTSnoop HCI log z Mibro Watch C4 BLE komunikacji.

INSTRUKCJA U?YCIA:
==================
1. Na telefonie Android:
   a) Settings -> About Phone -> kliknij "Build Number" 7 razy -> aktywuje Developer Options
   b) Settings -> Developer Options -> "Enable Bluetooth HCI snoop log" = ON
   c) Wy??cz i w??cz Bluetooth (reset bufora)
   d) Otw?rz aplikacj? Mibro -> synchronizuj dane z zegarkiem (poczekaj ~60s)
   e) Wy??cz i w??cz Bluetooth ponownie (?eby upewni? si? ?e log jest zapisany na dysk)

2. Skopiuj log na PC (JEDNA z metod):
   Metoda A -- ADB (zalecana, wymaga kabla USB lub Wi-Fi ADB):
     $ adb pull /data/misc/bluetooth/logs/btsnoop_hci.log .

   Metoda B -- Android 12+ bugreport:
     $ adb bugreport bugreport.zip
     # Wyci?gnij: bugreport.zip/FS/data/misc/bluetooth/logs/btsnoop_hci.log

   Metoda C -- ?cie?ki dla konkretnych producent?w:
     Samsung:      /sdcard/bluetooth/btsnoop_hci.log
     Xiaomi/MIUI:  /sdcard/MIUI/debug_log/btsnoop_hci.log
     Google Pixel: adb shell "cat /data/misc/bluetooth/logs/btsnoop_hci.log" > btsnoop_hci.log

3. Uruchom parser:
   python mibro_hci_parse.py btsnoop_hci.log
   python mibro_hci_parse.py btsnoop_hci.log --output protocol.json
   python mibro_hci_parse.py btsnoop_hci.log --verbose
"""

import struct
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

# --- Sta?e BLE/HCI ------------------------------------------------------------

BTSNOOP_MAGIC   = b"btsnoop\x00"
HCI_ACL_DATA    = 0x02
L2CAP_CID_ATT   = 0x0004

ATT_OPCODE = {
    0x01: "Error Response",
    0x02: "Exchange MTU Request",
    0x03: "Exchange MTU Response",
    0x04: "Find Info Request",
    0x05: "Find Info Response",
    0x08: "Read By Type Request",
    0x09: "Read By Type Response",
    0x0A: "Read Request",
    0x0B: "Read Response",
    0x10: "Read By Group Request",
    0x11: "Read By Group Response",
    0x12: "Write Request",
    0x13: "Write Response",
    0x52: "Write Command",
    0x1B: "Notify",
    0x1D: "Indicate",
    0x1E: "Confirm",
}

# Kr?tkie UUID -> czytelna nazwa
KNOWN_UUIDS = {
    "2CB0": "MIBRO_RX",
    "2CB1": "MIBRO_TX",
    "0100": "SIFLI_TX",
    "0200": "SIFLI_RX",
    "1912": "MIBRO_SVC",
    "2A19": "BATTERY",
    "2A00": "DEV_NAME",
    "2A01": "APPEARANCE",
    "2A05": "SVC_CHANGED",
    "2902": "CCCD",
}


# --- BTSnoop ------------------------------------------------------------------

class BTSnoopRecord:
    BTSNOOP_TS_OFFSET = 0x00E03AB44A676000  # ?s od 1 Jan 0001 do 1 Jan 1970

    def __init__(self, orig_len, incl_len, flags, ts_us, data):
        self.orig_len  = orig_len
        self.incl_len  = incl_len
        self.flags     = flags
        self.data      = data
        self.direction = "RX" if (flags & 1) else "TX"
        # Koryguj timestamp BTSnoop (mo?e by? w epoce 0001 lub Unix)
        if ts_us > self.BTSNOOP_TS_OFFSET:
            ts_us -= self.BTSNOOP_TS_OFFSET
        self.timestamp = datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc)


def parse_btsnoop_file(path: str) -> list[BTSnoopRecord]:
    records = []
    with open(path, "rb") as f:
        magic = f.read(8)
        if magic != BTSNOOP_MAGIC:
            raise ValueError(f"Nie jest plikiem BTSnoop (magic={magic!r})")
        version  = struct.unpack(">I", f.read(4))[0]
        datalink = struct.unpack(">I", f.read(4))[0]
        print(f"  BTSnoop v{version}, datalink={datalink}")

        while True:
            hdr = f.read(24)
            if len(hdr) < 24:
                break
            orig_len, incl_len, flags, _drops = struct.unpack(">IIII", hdr[:16])
            ts_hi, ts_lo = struct.unpack(">II", hdr[16:24])
            ts_us = (ts_hi << 32) | ts_lo
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            records.append(BTSnoopRecord(orig_len, incl_len, flags, ts_us, data))

    print(f"  Wczytano {len(records)} rekord?w BTSnoop")
    return records


# --- HCI / L2CAP -------------------------------------------------------------

def extract_att_payload(data: bytes) -> bytes | None:
    """Wyci?ga ATT payload z HCI ACL pakietu (z lub bez H4 prefiksu 0x02)."""
    offset = 1 if data and data[0] == HCI_ACL_DATA else 0
    if len(data) < offset + 8:
        return None
    # ACL header: handle(2) + total_len(2)
    total_len = struct.unpack("<H", data[offset+2:offset+4])[0]
    l2cap = data[offset+4:]
    if len(l2cap) < 4:
        return None
    l2cap_len = struct.unpack("<H", l2cap[0:2])[0]
    l2cap_cid = struct.unpack("<H", l2cap[2:4])[0]
    if l2cap_cid != L2CAP_CID_ATT:
        return None
    return l2cap[4:4 + l2cap_len]


# --- ATT ---------------------------------------------------------------------

def _uuid_label(uuid_str: str) -> str:
    short = uuid_str.replace("-", "").upper()[-4:]
    return KNOWN_UUIDS.get(short, uuid_str)


def parse_att(payload: bytes, handle_map: dict[int, str]) -> dict | None:
    if not payload:
        return None
    opcode = payload[0]
    body   = payload[1:]
    name   = ATT_OPCODE.get(opcode, f"0x{opcode:02X}")
    result = {"opcode": opcode, "name": name}

    if opcode in (0x12, 0x52):  # Write Request / Write Command
        if len(body) >= 2:
            handle = struct.unpack("<H", body[:2])[0]
            value  = body[2:]
            label  = handle_map.get(handle, f"h=0x{handle:04X}")
            result.update({"handle": handle, "label": label, "value": value})

    elif opcode == 0x1B:  # Handle Value Notification
        if len(body) >= 2:
            handle = struct.unpack("<H", body[:2])[0]
            value  = body[2:]
            label  = handle_map.get(handle, f"h=0x{handle:04X}")
            result.update({"handle": handle, "label": label, "value": value})

    elif opcode == 0x1D:  # Handle Value Indication
        if len(body) >= 2:
            handle = struct.unpack("<H", body[:2])[0]
            value  = body[2:]
            label  = handle_map.get(handle, f"h=0x{handle:04X}")
            result.update({"handle": handle, "label": label, "value": value})

    elif opcode == 0x0B:  # Read Response
        result.update({"value": body})

    elif opcode == 0x09:  # Read By Type Response -- dekoduje char declarations
        _parse_char_declarations(body, handle_map, result)

    elif opcode == 0x05:  # Find Information Response -- mapuje handle->UUID (deskryptory)
        _parse_find_info(body, handle_map, result)

    elif opcode == 0x11:  # Read By Group Type Response -- dekoduje serwisy
        _parse_group_response(body, result)

    elif opcode == 0x01:  # Error Response
        if len(body) >= 4:
            result.update({
                "req_opcode": body[0],
                "handle": struct.unpack("<H", body[1:3])[0],
                "error": body[3],
            })

    return result


def _parse_char_declarations(body: bytes, handle_map: dict, result: dict):
    """Parsuje Read By Type Response z deklaracjami charakterystyk (0x2803)."""
    if not body:
        return
    att_data_len = body[0]
    declarations = []
    offset = 1
    while offset + att_data_len <= len(body):
        chunk = body[offset:offset + att_data_len]
        if len(chunk) >= 5:
            # char_handle(2) + properties(1) + value_handle(2) + uuid(2 lub 16)
            char_handle  = struct.unpack("<H", chunk[0:2])[0]
            properties   = chunk[2]
            value_handle = struct.unpack("<H", chunk[3:5])[0]
            uuid_bytes   = chunk[5:]
            if len(uuid_bytes) == 2:
                uuid_str = f"{struct.unpack('<H', uuid_bytes)[0]:04X}"
            elif len(uuid_bytes) == 16:
                uuid_str = _bytes_to_uuid(uuid_bytes)
            else:
                uuid_str = uuid_bytes.hex().upper()
            label = _uuid_label(uuid_str)
            handle_map[value_handle] = label
            declarations.append({
                "char_handle": char_handle,
                "value_handle": value_handle,
                "uuid": uuid_str,
                "label": label,
                "props": properties,
            })
        offset += att_data_len
    if declarations:
        result["declarations"] = declarations


def _parse_find_info(body: bytes, handle_map: dict, result: dict):
    """Parsuje Find Information Response -- mapuje deskryptory (np. CCCD)."""
    if len(body) < 1:
        return
    fmt = body[0]
    uuid_size = 2 if fmt == 1 else 16
    items = []
    offset = 1
    while offset + 2 + uuid_size <= len(body):
        handle = struct.unpack("<H", body[offset:offset+2])[0]
        uuid_bytes = body[offset+2:offset+2+uuid_size]
        if uuid_size == 2:
            uuid_str = f"{struct.unpack('<H', uuid_bytes)[0]:04X}"
        else:
            uuid_str = _bytes_to_uuid(uuid_bytes)
        label = _uuid_label(uuid_str)
        handle_map[handle] = label
        items.append({"handle": handle, "uuid": uuid_str, "label": label})
        offset += 2 + uuid_size
    if items:
        result["descriptors"] = items


def _parse_group_response(body: bytes, result: dict):
    """Parsuje Read By Group Type Response (lista serwis?w)."""
    if not body:
        return
    att_data_len = body[0]
    services = []
    offset = 1
    while offset + att_data_len <= len(body):
        chunk = body[offset:offset + att_data_len]
        if len(chunk) >= 4:
            start = struct.unpack("<H", chunk[0:2])[0]
            end   = struct.unpack("<H", chunk[2:4])[0]
            uuid_bytes = chunk[4:]
            if len(uuid_bytes) == 2:
                uuid_str = f"{struct.unpack('<H', uuid_bytes)[0]:04X}"
            elif len(uuid_bytes) == 16:
                uuid_str = _bytes_to_uuid(uuid_bytes)
            else:
                uuid_str = uuid_bytes.hex().upper()
            services.append({"start": start, "end": end, "uuid": uuid_str,
                             "label": _uuid_label(uuid_str)})
        offset += att_data_len
    if services:
        result["services"] = services


def _bytes_to_uuid(b: bytes) -> str:
    h = b[::-1].hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}".upper()


# --- G??wna analiza -----------------------------------------------------------

def analyze(records: list[BTSnoopRecord], verbose: bool = False) -> list[dict]:
    """Analizuje rekordy BTSnoop. Zwraca wszystkie zdarzenia GATT."""
    handle_map: dict[int, str] = {}
    events = []

    for rec in records:
        data = rec.data
        if not data:
            continue

        att = None
        payload = extract_att_payload(data)
        if payload is None and len(data) >= 4:
            # Pr?ba bez H4 prefiksu (niekt?re implementacje BTSnoop)
            payload = extract_att_payload(b"\x02" + data)
        if payload is None:
            continue

        att = parse_att(payload, handle_map)
        if not att:
            continue

        evt = {
            "ts":  rec.timestamp.isoformat(),
            "dir": rec.direction,
            "att": att,
        }

        if verbose:
            label = att.get("label", att["name"])
            val   = att.get("value", b"")
            if isinstance(val, bytes):
                val = val.hex(" ").upper()
            print(f"  [{rec.direction}] {att['name']:25s}  {label:15s}  {val[:60]}")

        events.append(evt)

    return events


def extract_protocol_frames(events: list[dict]) -> list[dict]:
    """Wyci?ga komendy i odpowiedzi z/do zegarka (TX Write i RX Notify)."""
    frames = []
    for e in events:
        att = e["att"]
        if att["opcode"] not in (0x12, 0x52, 0x1B, 0x1D):
            continue
        value = att.get("value", b"")
        if isinstance(value, bytes):
            hex_str = value.hex(" ").upper()
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in value)
        else:
            hex_str = str(value)
            ascii_str = ""
        frames.append({
            "ts":    e["ts"],
            "dir":   e["dir"],
            "op":    att["name"],
            "label": att.get("label", f"h=0x{att.get('handle', 0):04X}"),
            "hex":   hex_str,
            "ascii": ascii_str,
            "raw":   value.hex() if isinstance(value, bytes) else "",
        })
    return frames


def print_report(frames: list[dict], events: list[dict]) -> None:
    SEP = "-" * 80

    # Serwisy odkryte podczas discovery
    services = []
    for e in events:
        svc = e["att"].get("services")
        if svc:
            services.extend(svc)
    if services:
        print(f"\n{'='*80}")
        print("  ODKRYTE SERWISY GATT")
        print('=' * 80)
        for s in services:
            print(f"    handles {s['start']:04X}-{s['end']:04X}  UUID {s['uuid']}  ({s['label']})")

    # Mapowanie handle -> UUID (zebrany podczas discovery)
    decls = []
    for e in events:
        d = e["att"].get("declarations")
        if d:
            decls.extend(d)
    if decls:
        print(f"\n{SEP}")
        print("  CHARAKTERYSTYKI (handle -> UUID)")
        print(SEP)
        for d in decls:
            props = d["props"]
            prop_str = ("R" if props & 0x02 else "-") + \
                       ("W" if props & 0x08 else "-") + \
                       ("w" if props & 0x04 else "-") + \
                       ("N" if props & 0x10 else "-") + \
                       ("I" if props & 0x20 else "-")
            print(f"    h=0x{d['value_handle']:04X}  [{prop_str}]  {d['uuid']}  {d['label']}")

    # Ramki protoko?u (komendy i odpowiedzi)
    mibro_frames = [f for f in frames
                    if any(k in f["label"] for k in ("MIBRO", "SIFLI"))]
    all_frames   = mibro_frames if mibro_frames else frames

    print(f"\n{'='*80}")
    title = "RAMKI PROTOKO?U MIBRO" if mibro_frames else "WSZYSTKIE RAMKI GATT WRITE/NOTIFY"
    print(f"  {title}  ({len(all_frames)} pakiet?w)")
    print(f"{'='*80}")

    prev_dir = None
    for i, f in enumerate(all_frames, 1):
        arrow = "-> ZEGAREK" if f["dir"] == "TX" else "<- ZEGAREK"
        if f["dir"] != prev_dir and i > 1:
            print()
        print(f"  [{i:3d}] {arrow}  {f['label']:12s}  {f['hex']}")
        if f["ascii"].strip("."):
            print(f"         {'':9s}  {'':12s}  {f['ascii']}")
        prev_dir = f["dir"]

    # Pierwsze TX pakiety = prawdopodobny handshake/auth
    tx = [f for f in all_frames if f["dir"] == "TX"]
    if tx:
        print(f"\n{SEP}")
        print("  PIERWSZE TX PAKIETY (sekwencja inicjalizacyjna):")
        print(SEP)
        for f in tx[:15]:
            print(f"    {f['label']:12s}  {f['hex']}")
            if f["ascii"].strip("."):
                print(f"    {'':12s}  {f['ascii']}")

    # Wykryj czy protok?? u?ywa EA EA (XTSR)
    xtsr = [f for f in all_frames if f["raw"].startswith("eaea")]
    if xtsr:
        print(f"\n{SEP}")
        print("  POTWIERDZONE: protok?? XTSR (nag??wek EA EA)")
        print(SEP)
        for f in xtsr:
            print(f"    {f['dir']}  {f['hex']}")
    else:
        first_bytes = set()
        for f in all_frames:
            if f["raw"]:
                first_bytes.add(f["raw"][:4])
        if first_bytes:
            print(f"\n{SEP}")
            print(f"  Pierwsze 2 bajty ramek: {', '.join(sorted(first_bytes))}")

    print(f"\n{'='*80}\n")


# --- CLI ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Parsuje BTSnoop HCI log z Mibro Watch BLE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("logfile", help="?cie?ka do pliku btsnoop_hci.log")
    ap.add_argument("--output", "-o", help="Zapisz wyniki do pliku JSON")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Wypisuj ka?dy pakiet ATT podczas parsowania")
    args = ap.parse_args()

    if not Path(args.logfile).exists():
        print(f"B??D: Plik {args.logfile!r} nie istnieje")
        sys.exit(1)

    print(f"\nParsowanie: {args.logfile}")
    records = parse_btsnoop_file(args.logfile)

    print("Analizowanie pakiet?w ATT...")
    events = analyze(records, verbose=args.verbose)
    print(f"  Znaleziono {len(events)} zdarze? ATT")

    frames = extract_protocol_frames(events)
    print_report(frames, events)

    if args.output:
        out = {
            "total_att_events": len(events),
            "protocol_frames":  frames,
            "all_events":       [
                {**e, "att": {k: v.hex() if isinstance(v, bytes) else v
                              for k, v in e["att"].items()}}
                for e in events
            ],
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"Zapisano do: {args.output}")

    # Zawsze zapisuj surowe ramki
    if frames:
        out_frames = "mibro_captured_frames.json"
        with open(out_frames, "w", encoding="utf-8") as f:
            json.dump(frames, f, indent=2, ensure_ascii=False)
        print(f"Ramki protoko?u zapisane do: {out_frames}")


if __name__ == "__main__":
    main()
