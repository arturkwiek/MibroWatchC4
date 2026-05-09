"""
mibro_re.py — Systematyczny Reverse Engineering Mibro Watch C4 BLE.

Kluczowe wnioski z poprzednich sesji (logi z 2–7 maja 2026):
  ✗ Wysłano dziesiątki ramek (EA EA, AA-prefix) → zawsze 0 odpowiedzi
  ✗ Pairing zawsze się nie udaje ("FAILED")
  ✓ Subskrypcja 2CB0 i 0200 zawsze się udaje (bleak potwierdza)
  ✓ Write_gatt_char zawsze ACKowany (zegarek odbiera ramki)
  → Hipoteza #1: Brak CRC — zegarek czeka na 7. bajt (CRC), nie dostaje,
                 pomija ramkę, po timeout rozłącza.
  → Hipoteza #2: Zegarek potrzebuje konkretnej sekwencji auth przed
                 odpowiedzią (czas synchronizacji z MAC-derived key).
  → Hipoteza #3: Spontaniczne powiadomienia od zegarka giną, bo
                 subskrybujemy ZA PÓŹNO po połączeniu.

Strategia:
  Faza 0 : Połącz → natychmiast subskrybuj → czekaj 5 s na spontaniczne
           powiadomienia (bez żadnego zapisu).
  Faza 1 : XTSR EA EA z CRC8 (4 warianty CRC) — najważniejsze komendy.
  Faza 2 : XTSR ze zsynchronizowaniem czasu jako pierwszą komendą (często
           wymagane jako "handshake" w chińskich zegarkach).
  Faza 3 : Format 55 AA (alternatywny protokół chiński).
  Faza 4 : Ręczne pisanie do deskryptora CCCD (0x2902) zamiast start_notify.
  Faza 5 : Ramki z kluczem auth opartym na MAC adresie.

CRC8 wariacje dla EA EA 01 01 00 00 [handshake]:
  XOR(wszystkich bajtów):         0xEA^0xEA^0x01^0x01^0x00^0x00 = 0x00
  XOR(bajtów po EA EA):           0x01^0x01^0x00^0x00 = 0x00
  SUM(wszystkich) mod 256:        0xEA+0xEA+0x01+0x01 = 0xD6
  SUM(po EA EA) mod 256:          0x01+0x01 = 0x02
  ~SUM(wszystkich) mod 256:       ~0xD6 & 0xFF = 0x29
  (256-SUM) mod 256:              (256-0xD6) & 0xFF = 0x2A

Wszystkie odpowiedzi są logowane do: mibro_re_log.jsonl
"""

import asyncio
import struct
import json
import logging
from datetime import datetime
from pathlib import Path
from bleak import BleakClient

# ─── Konfiguracja ────────────────────────────────────────────────────────────

TARGET  = "10:7B:93:CE:B5:1F"  # Mibro Watch C4

# Serwis 0x1912 — główny kanał komunikacji
WRITE   = "00002CB1-0000-1000-8000-00805F9B34FB"  # write/write-no-resp/read
NOTIFY  = "00002CB0-0000-1000-8000-00805F9B34FB"  # notify/write/write-no-resp/read

# Serwis SIFLI — kanał zapasowy
WRITE2  = "00000000-0000-0100-6473-5F696C666973"  # write/write-no-resp/read
NOTIFY2 = "00000000-0000-0200-6473-5F696C666973"  # notify/write/write-no-resp/read

# Deskryptor CCCD (Client Characteristic Configuration)
CCCD_UUID = "00002902-0000-1000-8000-00805F9B34FB"

LOG_FILE = Path("mibro_re_log.jsonl")

# ─── Logger ──────────────────────────────────────────────────────────────────

received: list[dict] = []   # wszystkie odebrane notyfikacje


def now_iso() -> str:
    return datetime.now().isoformat(timespec="milliseconds")


def log(tag: str, msg: str, data: bytes | None = None) -> dict:
    ts = now_iso()
    entry: dict = {"ts": ts, "tag": tag, "msg": msg}
    if data is not None:
        entry["hex"] = " ".join(f"{b:02X}" for b in data)
        entry["dec"] = list(data)
        entry["bytes"] = len(data)
    line = f"[{ts}] [{tag:<10s}] {msg}"
    if data:
        line += f"  →  {entry['hex']}"
    print(line)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


# ─── CRC helpers ──────────────────────────────────────────────────────────────

def crc_xor_all(b: bytes) -> int:
    """XOR wszystkich bajtów ramki."""
    result = 0
    for byte in b:
        result ^= byte
    return result


def crc_xor_body(b: bytes) -> int:
    """XOR bajtów po nagłówku EA EA."""
    return crc_xor_all(b[2:])


def crc_sum_all(b: bytes) -> int:
    """Suma wszystkich bajtów mod 256."""
    return sum(b) & 0xFF


def crc_sum_body(b: bytes) -> int:
    """Suma bajtów po EA EA mod 256."""
    return sum(b[2:]) & 0xFF


def crc_neg_all(b: bytes) -> int:
    """Suma zanegowana (dopełnienie)."""
    return (~sum(b)) & 0xFF


def crc_twos_all(b: bytes) -> int:
    """Dopełnienie dwójkowe (256 - suma)."""
    return (256 - sum(b)) & 0xFF


# ─── Frame builders ───────────────────────────────────────────────────────────

def xtsr_frames(cmd_type: int, cmd_id: int, payload: bytes = b"") -> dict[str, bytes]:
    """
    Buduje ramki XTSR we wszystkich wariantach CRC.
    Format: EA EA [type:1] [cmd:1] [len_hi:1] [len_lo:1] [payload:len] [crc:1?]
    """
    base = bytes([0xEA, 0xEA, cmd_type, cmd_id]) + struct.pack(">H", len(payload)) + payload
    return {
        "no_crc":      base,
        "crc_xor_all": base + bytes([crc_xor_all(base)]),
        "crc_xor_body": base + bytes([crc_xor_body(base)]),
        "crc_sum_all": base + bytes([crc_sum_all(base)]),
        "crc_sum_body": base + bytes([crc_sum_body(base)]),
        "crc_neg_all": base + bytes([crc_neg_all(base)]),
        "crc_twos":    base + bytes([crc_twos_all(base)]),
    }


def build_55aa(cmd: int, payload: bytes = b"") -> bytes:
    """Format 55 AA — alternatywny protokół chiński."""
    hdr = bytes([0x55, 0xAA]) + struct.pack(">H", len(payload)) + bytes([cmd])
    full = hdr + payload
    return full + bytes([crc_sum_all(full)])


def build_aa55(cmd: int, payload: bytes = b"") -> bytes:
    """Format AA 55 (odwrócony)."""
    hdr = bytes([0xAA, 0x55]) + struct.pack(">H", len(payload)) + bytes([cmd])
    full = hdr + payload
    return full + bytes([crc_sum_all(full)])


# ─── Bleak helpers ────────────────────────────────────────────────────────────

async def safe_write(
    client: BleakClient,
    char_uuid: str,
    data: bytes,
    label: str,
    response: bool = True,
) -> bool:
    """Bezpieczny zapis z logowaniem. Próbuje write (response=True), fallback na no-resp."""
    if not client.is_connected:
        log("SKIP", f"Nie połączono — pominięto {label}")
        return False
    try:
        await client.write_gatt_char(char_uuid, data, response=response)
        log("TX_OK", f"{label} (response={response})", data)
        return True
    except Exception as exc_resp:
        if response:
            # Fallback: write-without-response
            try:
                await client.write_gatt_char(char_uuid, data, response=False)
                log("TX_NOACK", f"{label} (no-response fallback)", data)
                return True
            except Exception as exc_noresp:
                log("TX_ERR", f"{label}: {exc_resp} | noresp: {exc_noresp}", data)
        else:
            log("TX_ERR", f"{label}: {exc_resp}", data)
        return False


async def wait_for_rx(seconds: float, reason: str) -> bool:
    """Czeka na RX. Zwraca True jeśli coś odebrano."""
    log("WAIT", f"Czekam {seconds}s — {reason}")
    await asyncio.sleep(seconds)
    return len(received) > 0


# ─── Główna logika ────────────────────────────────────────────────────────────

async def run_phases(client: BleakClient) -> None:
    log("CONN", f"Połączono z {TARGET}")

    # Callbacki notyfikacji
    def on_notify(sender: int, data: bytearray) -> None:
        entry = log("RX_2CB0", f"Notifikacja! handle={sender}", bytes(data))
        received.append(entry)

    def on_notify2(sender: int, data: bytearray) -> None:
        entry = log("RX_0200", f"Notifikacja2! handle={sender}", bytes(data))
        received.append(entry)

    # ─── Faza 0: Subskrybuj natychmiast, czekaj na spontaniczne pakiety ───
    log("PHASE", "0 — Subskrybuj + czekaj na spontaniczne notifikacje (5s)")

    for uuid, cb, name in [
        (NOTIFY,  on_notify,  "2CB0"),
        (NOTIFY2, on_notify2, "0200"),
    ]:
        try:
            await client.start_notify(uuid, cb)
            log("SUB_OK", f"Subskrypcja {name} aktywna")
        except Exception as exc:
            log("SUB_ERR", f"{name}: {exc}")

    # Czekaj KRÓTKO na spontaniczne dane (poprzednia wersja czekała 5s → traciła auth-window)
    if await wait_for_rx(0.5, "spontaniczne notifikacje po połączeniu"):
        log("HIT", f"Zegarek spontanicznie wysłał {len(received)} pakiet(ów)!")
        return

    if not client.is_connected:
        log("WARN", "Rozłączono w fazie 0")
        return

    # ─── Faza 1: XTSR z CRC8 ─────────────────────────────────────────────
    log("PHASE", "1 — XTSR (EA EA) z wariantami CRC8")

    now_ts = int(datetime.now().timestamp())

    # Komendy do sprawdzenia: (etykieta, type, cmd, payload)
    xtsr_probes = [
        # Podstawowe komendy — type 0x01
        ("handshake",      0x01, 0x01, b""),
        ("set_time",       0x01, 0x02, struct.pack("<I", now_ts)),  # czas jako payload
        ("get_time",       0x01, 0x02, b""),
        ("device_info",    0x01, 0x11, b""),
        ("battery",        0x01, 0x20, b""),
        ("step_today",     0x01, 0x51, b""),
        ("hr_history",     0x01, 0x52, b""),
        ("sleep_history",  0x01, 0x53, b""),
        ("spo2_history",   0x01, 0x54, b""),
        ("history_start",  0x01, 0x80, b""),
        ("history_next",   0x01, 0x81, b""),
        # Type 0x00 variants
        ("t00:handshake",  0x00, 0x01, b""),
        ("t00:history",    0x00, 0x80, b""),
        # Type 0x02 variants
        ("t02:handshake",  0x02, 0x01, b""),
        ("t03:history",    0x03, 0x80, b""),
    ]

    # Warianty CRC do próby — TYLKO 3 NA RAMKĘ aby zmieścić się w 13s auth-window
    # XOR i SUM są najczęstsze w chińskich protokołach BLE
    crc_priority = ["crc_xor_all", "crc_sum_all", "crc_neg_all", "crc_xor_body",
                    "crc_sum_body", "crc_twos", "no_crc"]
    crc_fast = ["crc_xor_all", "crc_sum_all", "no_crc"]  # szybka ścieżka

    for label, t, cmd, payload in xtsr_probes:
        if not client.is_connected or received:
            break

        frames = xtsr_frames(t, cmd, payload)
        log("PROBE", f"XTSR {label} (type=0x{t:02X}, cmd=0x{cmd:02X}, payload={len(payload)}B)")

        for variant in crc_fast:  # tylko 3 warianty, 0.3s każdy = 0.9s na komendę
            if not client.is_connected or received:
                break
            frame = frames[variant]
            ok = await safe_write(client, WRITE, frame, f"xtsr:{label}:{variant}")
            if ok:
                # Szybka odpowiedź + poll 2CB0
                await asyncio.sleep(0.3)
                if received:
                    log("HIT", f"Odpowiedź (notify) po xtsr:{label}:{variant}!")
                    break
                # Spróbuj też odczytać 2CB0 bezpośrednio (polling zamiast notification)
                try:
                    poll_val = await client.read_gatt_char(NOTIFY)
                    if poll_val and bytes(poll_val) != b"\x00":
                        entry = log("POLL", f"Polled 2CB0 po {label}:{variant}", bytes(poll_val))
                        received.append(entry)
                        break
                except Exception:
                    pass

        await asyncio.sleep(0.1)

    log("STATUS", f"Po fazie 1: {len(received)} RX, połączony={client.is_connected}")
    if received:
        return

    # ─── Faza 2: Time sync jako pierwsza komenda (wymagana w wielu zegarkach) ─
    if client.is_connected:
        log("PHASE", "2 — Sekwencja: najpierw sync czasu, potem history")

        # Wiele chińskich zegarków wymaga "set time" jako pierwszego pakietu
        time_payload = struct.pack("<I", int(datetime.now().timestamp()))
        time_frames = xtsr_frames(0x01, 0x02, time_payload)

        for variant in crc_fast:
            if not client.is_connected:
                break
            frame = time_frames[variant]
            ok = await safe_write(client, WRITE, frame, f"timesync:{variant}")
            if ok:
                await asyncio.sleep(0.3)
                if received:
                    log("HIT", f"Odpowiedź po timesync:{variant}!")
                    break

        if received:
            return

        if client.is_connected:
            # Po time sync od razu pytaj o historię
            await asyncio.sleep(0.2)
            for label, t, cmd, payload in [("history_start", 0x01, 0x80, b""),
                                            ("history_next",  0x01, 0x81, b"")]:
                if not client.is_connected or received:
                    break
                frames = xtsr_frames(t, cmd, payload)
                for variant in crc_fast:
                    if not client.is_connected:
                        break
                    await safe_write(client, WRITE, frames[variant], f"after_ts:{label}:{variant}")
                    await asyncio.sleep(0.3)
                    if received:
                        break

    log("STATUS", f"Po fazie 2: {len(received)} RX")
    if received:
        return

    # ─── Faza 3: Format 55 AA ────────────────────────────────────────────
    if client.is_connected:
        log("PHASE", "3 — Format 55 AA (alternatywny protokół)")

        aa_probes = [
            ("55aa:handshake",   build_55aa(0x01)),
            ("55aa:get_time",    build_55aa(0x02)),
            ("55aa:set_time",    build_55aa(0x02, struct.pack("<I", int(datetime.now().timestamp())))),
            ("55aa:device_info", build_55aa(0x11)),
            ("55aa:battery",     build_55aa(0x20)),
            ("55aa:hr_history",  build_55aa(0x52)),
            ("55aa:history",     build_55aa(0x80)),
            # Format AA 55 (odwrócony)
            ("aa55:handshake",   build_aa55(0x01)),
            ("aa55:set_time",    build_aa55(0x02, struct.pack("<I", int(datetime.now().timestamp())))),
            ("aa55:history",     build_aa55(0x80)),
            # Ten sam format, ale pisany na 2CB0 (notify char) zamiast 2CB1
            ("2cb0:xtsr_hs",    xtsr_frames(0x01, 0x01)["crc_xor_all"]),
            ("2cb0:xtsr_ts",    xtsr_frames(0x01, 0x02, struct.pack("<I", int(datetime.now().timestamp())))["crc_xor_all"]),
        ]

        # Dla ostatnich 2 wpisów (2cb0:*) pisz na NOTIFY zamiast WRITE
        notify_labels = {"2cb0:xtsr_hs", "2cb0:xtsr_ts"}

        for label, frame in aa_probes:
            if not client.is_connected or received:
                break
            char = NOTIFY if label in notify_labels else WRITE
            ok = await safe_write(client, char, frame, label)
            if ok:
                await asyncio.sleep(0.3)
                if received:
                    log("HIT", f"Odpowiedź po {label}!")
                    break

    log("STATUS", f"Po fazie 3: {len(received)} RX")
    if received:
        return

    # ─── Faza 4: Ręczne pisanie do deskryptora CCCD ──────────────────────
    # Niektóre urządzenia (zwłaszcza SIFLI) wymagają ręcznego zapisu CCCD
    if client.is_connected:
        log("PHASE", "4 — Ręczne CCCD + ponowne XTSR")

        # Znajdź deskryptory 2902 dla 2CB0 i 0200
        cccd_handles = []
        for svc in client.services:
            for char in svc.characteristics:
                if char.uuid.upper() in (NOTIFY.upper(), NOTIFY2.upper()):
                    for desc in char.descriptors:
                        if "2902" in desc.uuid:
                            cccd_handles.append((char.uuid, desc.uuid))
                            log("CCCD", f"Znaleziono CCCD dla {char.uuid[-8:]} → {desc.uuid}")

        for char_uuid, desc_uuid in cccd_handles:
            try:
                # Włącz notyfikacje ręcznie: CCCD = 0x0001
                await client.write_gatt_descriptor(desc_uuid, b"\x01\x00")
                log("CCCD_OK", f"Zapisano 01 00 do {desc_uuid}")
            except Exception as exc:
                log("CCCD_ERR", f"{desc_uuid}: {exc}")

        if cccd_handles:
            await asyncio.sleep(1.0)

            # Ponów próbę z najprostszymi ramkami
            for label, t, cmd, payload in xtsr_probes[:5]:
                if not client.is_connected or received:
                    break
                frames = xtsr_frames(t, cmd, payload)
                for variant in crc_fast:
                    if not client.is_connected or received:
                        break
                    await safe_write(client, WRITE, frames[variant], f"post_cccd:{label}:{variant}")
                    await asyncio.sleep(0.3)
                    if received:
                        break

    log("STATUS", f"Po fazie 4: {len(received)} RX")
    if received:
        return

    # ─── Faza 5: Kanał zapasowy SIFLI (0100/0200) ─────────────────────────
    if client.is_connected:
        log("PHASE", "5 — Kanał SIFLI (WRITE2 0100, NOTIFY2 0200)")

        for label, t, cmd, payload in xtsr_probes[:8]:
            if not client.is_connected or received:
                break
            frames = xtsr_frames(t, cmd, payload)
            for variant in crc_fast:
                if not client.is_connected or received:
                    break
                await safe_write(client, WRITE2, frames[variant], f"sifli:{label}:{variant}")
                await asyncio.sleep(0.3)
                if received:
                    break

    log("STATUS", f"Po fazie 5: {len(received)} RX")
    if received:
        return

    # ─── Faza 6: Auth oparty na MAC (niektóre Xiaomi-ecosystem) ───────────
    if client.is_connected:
        log("PHASE", "6 — Auth z kluczem opartym na MAC")

        # MAC: 10:7B:93:CE:B5:1F → bytes: [0x10, 0x7B, 0x93, 0xCE, 0xB5, 0x1F]
        mac_bytes = bytes([0x10, 0x7B, 0x93, 0xCE, 0xB5, 0x1F])
        mac_rev   = mac_bytes[::-1]

        # Różne warianty ramek auth
        auth_frames = [
            # XTSR z MAC jako payload
            ("auth_mac_fwd",      xtsr_frames(0x01, 0x01, mac_bytes)["crc_xor_all"]),
            ("auth_mac_rev",      xtsr_frames(0x01, 0x01, mac_rev)["crc_xor_all"]),
            # Znane "magiczne" sekwencje auth dla Xiaomi
            ("xiaomi_auth1",      bytes([0x01, 0x00, 0x10, 0x7B, 0x93, 0xCE, 0xB5, 0x1F])),
            ("xiaomi_auth2",      bytes([0x02, 0x00, 0x1F, 0xB5, 0xCE, 0x93, 0x7B, 0x10])),
            # EA EA z kluczem 0xFF (broadcast handshake)
            ("xtsr_ff_key",       bytes([0xEA, 0xEA, 0x01, 0x01, 0x00, 0x06]) + mac_bytes + bytes([crc_xor_all(bytes([0xEA, 0xEA, 0x01, 0x01, 0x00, 0x06]) + mac_bytes)])),
        ]

        for label, frame in auth_frames:
            if not client.is_connected or received:
                break
            await safe_write(client, WRITE, frame, label)
            await asyncio.sleep(0.3)
            if received:
                log("HIT", f"Odpowiedź po {label}!")
                break

    # ─── Końcowe czekanie ─────────────────────────────────────────────────
    if client.is_connected:
        log("WAIT", "Finalne 2s czekania na opóźnione odpowiedzi")
        await asyncio.sleep(2.0)


# ─── Dekodowanie odpowiedzi ───────────────────────────────────────────────────

def decode_response(data: bytes, label: str = "") -> None:
    """Próbuje zdekodować odpowiedź XTSR."""
    print(f"\n{'='*60}")
    print(f"  DEKODOWANIE ODPOWIEDZI {label}")
    print(f"  RAW HEX: {' '.join(f'{b:02X}' for b in data)}")
    print(f"  DEC:     {list(data)}")
    print(f"  ASCII:   {data.decode('ascii', errors='replace')}")
    print(f"  Długość: {len(data)} bajtów")

    if len(data) >= 2 and data[0] == 0xEA and data[1] == 0xEA:
        print(f"  → Format: XTSR (EA EA header)")
        if len(data) >= 6:
            cmd_type = data[2]
            cmd_id   = data[3]
            length   = struct.unpack(">H", data[4:6])[0]
            payload  = data[6:6+length] if len(data) >= 6+length else data[6:]
            print(f"  → Type: 0x{cmd_type:02X}, Cmd: 0x{cmd_id:02X}, Len: {length}")
            print(f"  → Payload: {payload.hex(' ').upper()}")
            if len(data) >= 6+length+1:
                crc = data[6+length]
                expected_xor = crc_xor_all(data[:6+length])
                expected_sum = crc_sum_all(data[:6+length])
                print(f"  → CRC bajt: 0x{crc:02X} "
                      f"(XOR oczekiwany: 0x{expected_xor:02X}, "
                      f"SUM oczekiwany: 0x{expected_sum:02X})")
            # Dekoduj znane komendy odpowiedzi
            if cmd_id == 0x20 and length >= 1:
                print(f"  → BATERIA: {payload[0]}%")
            elif cmd_id == 0x02 and length >= 4:
                ts_val = struct.unpack("<I", payload[:4])[0]
                print(f"  → CZAS: {datetime.fromtimestamp(ts_val)}")
            elif cmd_id == 0x11:
                try:
                    fw = payload.decode("ascii", errors="replace").strip("\x00")
                    print(f"  → INFO URZĄDZENIA: {fw}")
                except Exception:
                    pass

    elif len(data) >= 2 and data[0] == 0x55 and data[1] == 0xAA:
        print(f"  → Format: 55 AA")

    print(f"{'='*60}\n")


# ─── Entry point ──────────────────────────────────────────────────────────────

async def main() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    log("START", f"Mibro Watch C4 RE probe — cel: {TARGET}")
    log("INFO", f"Log file: {LOG_FILE.resolve()}")

    def on_disconnect(c: BleakClient) -> None:
        log("DISCO", f"Rozłączono (nieoczekiwanie)")

    try:
        async with BleakClient(
            TARGET,
            disconnected_callback=on_disconnect,
            timeout=60.0,
        ) as client:
            if not client.is_connected:
                log("ERROR", "Nie udało się połączyć!")
                return

            await run_phases(client)

    except Exception as exc:
        log("EXCEPTION", str(exc))

    # ─── Podsumowanie ─────────────────────────────────────────────────────
    print(f"\n{'#'*60}")
    print(f"  WYNIKI RE PROBE")
    print(f"  Łączna liczba odebranych notyfikacji: {len(received)}")
    print(f"{'#'*60}")

    if received:
        print("\n  === ODEBRANE DANE ===")
        for i, r in enumerate(received, 1):
            print(f"  [{i}] {r['ts']} [{r['tag']}] {r.get('hex', '')} ({r.get('bytes', 0)} B)")
            raw = bytes(r["dec"]) if "dec" in r else b""
            if raw:
                decode_response(raw, r["tag"])
        print("\n  SUKCES — znaleziono protokół komunikacji!")
        print("  Sprawdź mibro_re_log.jsonl aby zobaczyć szczegóły.")
    else:
        print("\n  BRAK ODPOWIEDZI od zegarka.")
        print("  Zalecane kolejne kroki:")
        print("   1. Sniffing HCI na Android: włącz 'Enable Bluetooth HCI snoop log'")
        print("      w opcjach dewelopera, uruchom aplikację Mibro, skopiuj")
        print("      /data/misc/bluetooth/logs/btsnoop_hci.log i przeanalizuj w Wireshark.")
        print("   2. Spróbuj połączyć się po parę sekund od odpalenia aplikacji Mibro")
        print("      (zegarek może być w trybie sync tylko przez chwilę po otwarciu apki).")
        print("   3. Sprawdź czy zegarek ma włączony BLE (Settings → Phone → Bluetooth).")


if __name__ == "__main__":
    # Wyłącz gadatliwe logi bleak
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("bleak").setLevel(logging.WARNING)

    asyncio.run(main())
