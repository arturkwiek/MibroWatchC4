"""
mibro_serial_auth.py — Próba auth z numerem seryjnym z advertising data.

Z advertising data: Company 0x0A4C (SIFLI Technology)
Manufacturer payload: 04 00 01 AW054/00006545 [MAC]
Serial string: "AW054/00006545"
Serial number only: "00006545"
Model code: "AW054"
"""
import asyncio
import struct
import json
from datetime import datetime
from pathlib import Path
from bleak import BleakClient

TARGET  = "10:7B:93:CE:B5:1F"
WRITE   = "00002CB1-0000-1000-8000-00805F9B34FB"
NOTIFY  = "00002CB0-0000-1000-8000-00805F9B34FB"
WRITE2  = "00000000-0000-0100-6473-5F696C666973"
NOTIFY2 = "00000000-0000-0200-6473-5F696C666973"
LOG     = Path("mibro_serial_auth_log.jsonl")

received: list[dict] = []

# Z advertising data:
SERIAL_FULL   = b"AW054/00006545"          # 14 bytes
SERIAL_NUM    = b"00006545"                 # 8 bytes — numer seryjny
MODEL_CODE    = b"AW054"                    # 5 bytes — model
MFR_PREFIX    = bytes([0x04, 0x00, 0x01])   # prefix z advertising
MAC_BYTES     = bytes([0x10, 0x7B, 0x93, 0xCE, 0xB5, 0x1F])
MAC_REV       = MAC_BYTES[::-1]

UNIX_NOW = lambda: int(datetime.now().timestamp())


def crc_xor(b: bytes) -> int:
    r = 0
    for x in b:
        r ^= x
    return r

def crc_sum(b: bytes) -> int:
    return sum(b) & 0xFF

def xtsr(type_: int, cmd: int, payload: bytes = b"", crc_fn=crc_xor) -> bytes:
    base = bytes([0xEA, 0xEA, type_, cmd]) + struct.pack(">H", len(payload)) + payload
    return base + bytes([crc_fn(base)])

def ts() -> str:
    return datetime.now().isoformat(timespec="milliseconds")

def log_print(tag: str, msg: str, data: bytes | None = None) -> dict:
    entry: dict = {"ts": ts(), "tag": tag, "msg": msg}
    if data:
        entry["hex"] = data.hex(" ").upper()
    line = f"[{entry['ts']}] [{tag:<10}] {msg}"
    if data:
        line += f"  → {entry['hex']}"
    print(line)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


async def safe_w(client: BleakClient, char: str, data: bytes, label: str,
                 response: bool = False) -> bool:
    """Write-without-response (response=False = szybsze, nie czeka na ACK)."""
    if not client.is_connected:
        return False
    try:
        await client.write_gatt_char(char, data, response=response)
        log_print("TX", label, data)
        return True
    except Exception as e:
        try:
            await client.write_gatt_char(char, data, response=not response)
            log_print("TX_FB", f"{label} (fallback)", data)
            return True
        except Exception as e2:
            log_print("ERR", f"{label}: {e}", data)
            return False


async def poll_2cb0(client: BleakClient, label: str) -> bytes | None:
    """Bezpośredni odczyt 2CB0 — bez czekania na notifikację."""
    try:
        val = bytes(await client.read_gatt_char(NOTIFY))
        if val and val != b"\x00":
            log_print("POLL", f"2CB0 po {label}", val)
            return val
    except Exception:
        pass
    return None


async def probe(client: BleakClient) -> None:
    log_print("CONN", f"Połączono z {TARGET}")

    def on_rx(sender: int, data: bytearray) -> None:
        entry = log_print("RX", f"NOTIF handle={sender}", bytes(data))
        received.append(entry)

    def on_rx2(sender: int, data: bytearray) -> None:
        entry = log_print("RX2", f"SIFLI handle={sender}", bytes(data))
        received.append(entry)

    # Subskrybuj NATYCHMIAST
    for uuid, cb, name in [(NOTIFY, on_rx, "2CB0"), (NOTIFY2, on_rx2, "0200")]:
        try:
            await client.start_notify(uuid, cb)
            log_print("SUB", f"{name} OK")
        except Exception as e:
            log_print("SUB_ERR", f"{name}: {e}")

    await asyncio.sleep(0.2)  # krótka chwila na subskrypcję

    # ─── Próby auth oparte na numerze seryjnym ─────────────────────────────

    auth_probes = [
        # 1. Pełny serial "AW054/00006545" jako payload handshake
        ("serial_full",     xtsr(0x01, 0x01, SERIAL_FULL)),
        ("serial_full_sum", xtsr(0x01, 0x01, SERIAL_FULL, crc_sum)),

        # 2. Tylko numer "00006545"
        ("serial_8",        xtsr(0x01, 0x01, SERIAL_NUM)),
        ("serial_8_sum",    xtsr(0x01, 0x01, SERIAL_NUM, crc_sum)),

        # 3. MFR prefix + serial + MAC (pełny mfr payload)
        ("mfr_full",        xtsr(0x01, 0x01, MFR_PREFIX + SERIAL_FULL + MAC_BYTES)),
        ("mfr_full_sum",    xtsr(0x01, 0x01, MFR_PREFIX + SERIAL_FULL + MAC_BYTES, crc_sum)),

        # 4. Samo MAC jak auth
        ("mac_fwd",         xtsr(0x01, 0x01, MAC_BYTES)),
        ("mac_rev",         xtsr(0x01, 0x01, MAC_REV)),

        # 5. Serial + MAC (bez prefiksu)
        ("serial_mac",      xtsr(0x01, 0x01, SERIAL_FULL + MAC_BYTES)),
        ("serial_mac_rev",  xtsr(0x01, 0x01, SERIAL_FULL + MAC_REV)),

        # 6. SIFLI specific: type=0x04 (sync), type=0x06 (auth?)
        ("t04_serial",      xtsr(0x04, 0x01, SERIAL_FULL)),
        ("t06_serial",      xtsr(0x06, 0x01, SERIAL_FULL)),
        ("t04_mac",         xtsr(0x04, 0x01, MAC_BYTES)),
        ("t06_mac",         xtsr(0x06, 0x01, MAC_BYTES)),

        # 7. Najpierw time sync, potem auth
        ("timesync_xor",    xtsr(0x01, 0x02, struct.pack("<I", UNIX_NOW()))),
        ("timesync_sum",    xtsr(0x01, 0x02, struct.pack("<I", UNIX_NOW()), crc_sum)),

        # 8. Raw mfr bytes bez XTSR wrapper (protokół bezpośredni?)
        ("raw_serial",      SERIAL_FULL),
        ("raw_mfr",         MFR_PREFIX + SERIAL_FULL + MAC_BYTES),
        ("raw_04_serial",   bytes([0x04, 0x00, 0x01]) + SERIAL_FULL),

        # 9. Próba zapisu na 2CB0 (kanał bidirectional) zamiast 2CB1
        # — oznaczone "_2CB0", osobna logika poniżej
    ]

    # Próby na 2CB1 (WRITE)
    log_print("PHASE", "Próby auth na 2CB1 (WRITE char)")
    for label, frame in auth_probes:
        if not client.is_connected or received:
            break
        ok = await safe_w(client, WRITE, frame, f"2CB1:{label}")
        if ok:
            await asyncio.sleep(0.35)
            if received:
                log_print("HIT", f"ODPOWIEDŹ po 2CB1:{label}!")
                break
            p = await poll_2cb0(client, f"2CB1:{label}")
            if p:
                received.append({"tag": "POLL", "hex": p.hex(" ").upper()})
                break

    if received:
        return

    # Próby na 2CB0 (NOTIFY char — bidirectional!)
    if client.is_connected:
        log_print("PHASE", "Próby auth na 2CB0 (NOTIFY char — write TO it)")
        for label, frame in auth_probes:
            if not client.is_connected or received:
                break
            ok = await safe_w(client, NOTIFY, frame, f"2CB0:{label}")
            if ok:
                await asyncio.sleep(0.35)
                if received:
                    log_print("HIT", f"ODPOWIEDŹ po 2CB0:{label}!")
                    break

    # Próby na kanale SIFLI
    if client.is_connected and not received:
        log_print("PHASE", "Próby auth na SIFLI (WRITE2 char)")
        for label, frame in auth_probes[:8]:
            if not client.is_connected or received:
                break
            ok = await safe_w(client, WRITE2, frame, f"SIFLI:{label}")
            if ok:
                await asyncio.sleep(0.35)
                if received:
                    log_print("HIT", f"ODPOWIEDŹ po SIFLI:{label}!")
                    break

    if client.is_connected:
        log_print("WAIT", "Finalne 2s czekania")
        await asyncio.sleep(2.0)


async def main() -> None:
    log_print("START", "Mibro auth probe — serial-based")

    async with BleakClient(TARGET, timeout=30.0,
                           disconnected_callback=lambda c: log_print("DISCO", "Rozłączono")) as client:
        if not client.is_connected:
            log_print("ERR", "Nie można połączyć")
            return
        await probe(client)

    print(f"\n{'='*60}")
    if received:
        print(f"  SUKCES! Odebrano {len(received)} odpowiedzi:")
        for r in received:
            print(f"    [{r['tag']}] {r.get('hex', '')}")
        print("\n  Sprawdź mibro_serial_auth_log.jsonl dla szczegółów")
    else:
        print("  BRAK odpowiedzi — zegarek nadal milczy")
        print("  → Jedyna pewna ścieżka: Android HCI snoop (instrukcja w mibro_hci_parse.py)")
    print("="*60)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main())
