# Mibro Watch C4 — Przewodnik pobierania danych historycznych

Szczegółowy opis protokołu odczytu danych zdrowotnych (tętno, SpO2, sen, kroki) z zegarka Mibro Watch C4 przez BLE. Przewodnik oparty na analizie rzeczywistego ruchu HCI i zawiera przykłady konkretnych bajtów z przechwyconych ramek.

---

## Spis treści

1. [Przegląd mechanizmu pobierania](#1-przegląd-mechanizmu-pobierania)
2. [Sekwencja komend](#2-sekwencja-komend)
3. [Szczegółowy format każdego typu danych](#3-szczegółowy-format-każdego-typu-danych)
   - 3.1 [Tętno HR (dtype=0x02)](#31-tętno-hr-dtype0x02)
   - 3.2 [Saturacja SpO2 (dtype=0x03)](#32-saturacja-spo2-dtype0x03)
   - 3.3 [Fazy snu (dtype=0x05)](#33-fazy-snu-dtype0x05)
   - 3.4 [Kroki dzienne (dtype=0x07)](#34-kroki-dzienne-dtype0x07)
   - 3.5 [Agregaty HR (dtype=0x09)](#35-agregaty-hr-dtype0x09)
   - 3.6 [Szczegóły snu (dtype=0x0B)](#36-szczegóły-snu-dtype0x0b)
   - 3.7 [Koniec transmisji (dtype=0x00)](#37-koniec-transmisji-dtype0x00)
4. [Kolejność i chunking ramek](#4-kolejność-i-chunking-ramek)
5. [Implementacja od zera](#5-implementacja-od-zera)
6. [Filtrowanie zakresu dat](#6-filtrowanie-zakresu-dat)
7. [Deduplikacja danych](#7-deduplikacja-danych)
8. [Kompletny przykład z obsługą błędów](#8-kompletny-przykład-z-obsługą-błędów)
9. [Tabela szybkiego odniesienia](#9-tabela-szybkiego-odniesienia)

---

## 1. Przegląd mechanizmu pobierania

Zegarek przechowuje dane zdrowotne wewnętrznie i wysyła je strumieniowo na żądanie. Mechanizm pobierania działa następująco:

1. **Host wysyła zakres czasu** (cmd=`0x25`) — 4-bajtowy Unix timestamp (Little-Endian) określający skąd zacząć
2. **Host wysyła trigger** (cmd=`0x30`) — pusta ramka inicjująca transmisję
3. **Zegarek wysyła strumieniowo dane** — seria notyfikacji na charakterystyce RX (`2CB0`), każda z CMD=`0x25`
4. **Zegarek wysyła znacznik końca** — ramka z `dtype=0x00`

```
Host (Windows)                           Zegarek Mibro C4
     │                                         │
     │─── CMD=0x25 [since_ts LE32] ──────────►│  "Daj dane od tej daty"
     │─── CMD=0x30 [] ────────────────────────►│  "Teraz wyślij"
     │                                         │
     │◄── CMD=0x25 [dtype=0x02 HR data] ───────│
     │◄── CMD=0x25 [dtype=0x05 sleep chunk 1] ─│
     │◄── CMD=0x25 [dtype=0x05 sleep chunk 2] ─│
     │◄── CMD=0x25 [dtype=0x05 sleep chunk 3] ─│
     │◄── CMD=0x25 [dtype=0x05 sleep chunk 4] ─│
     │◄── CMD=0x25 [dtype=0x07 steps] ─────────│
     │◄── CMD=0x25 [dtype=0x09 HR agg] ────────│
     │◄── CMD=0x25 [dtype=0x0B sleep detail] ──│
     │◄── CMD=0x25 [dtype=0x00 END] ───────────│  "Gotowe"
```

**Ważne obserwacje z analizy HCI:**
- Zegarek nie czeka na ACK — wysyła ramki jedna po drugiej
- Dane snu są rozbijane na wiele ramek (chunking, do 22 rekordów na ramkę)
- Całe dane z jednej doby mieszczą się w ~10 ramkach
- Zegarek trzyma dane typowo z ostatnich 7 dni
- Ten sam zestaw danych wysyłany jest całkowicie identycznie przy każdym triggerze dla tego samego timestamp

---

## 2. Sekwencja komend

### Krok 1: Ustaw zakres czasu (CMD=0x25 TX)

```
Ramka: 88 01 25 00 [since_ts 4B LE]
```

`since_ts` to 32-bitowy Unix timestamp w Little-Endian — najwcześniejszy moment, od którego chcesz dane.

**Przykład z HCI (2026-05-09 19:15:49 → ts=1778346949):**
```
88 01 25 00 | C5 6B FF 69
              └──────────┘
              0x69FF6BC5 = 1778346949
```

```python
import struct, datetime

since_dt = datetime.datetime.now() - datetime.timedelta(days=7)
since_ts = int(since_dt.timestamp())
frame_set_since = bytes([0x88, 0x01, 0x25, 0x00]) + struct.pack("<I", since_ts)
```

### Krok 2: Wyzwól pobieranie (CMD=0x30 TX)

```
Ramka: 88 01 30 00
```

Pusta ramka bez payloadu — zegarek natychmiast zaczyna wysyłać dane.

```python
frame_trigger = bytes([0x88, 0x01, 0x30, 0x00])
```

**Timing**: oba polecenia można wysłać jedno po drugim bez opóźnienia. Zegarek przetwarza je sekwencyjnie.

### Krok 3: Odbieraj notyfikacje do pojawienia się END

```python
async for raw in notifications:
    if raw[:4] != bytes([0x88, 0x01, 0x25, 0x00]):
        continue
    payload = raw[4:]
    dtype = payload[0]
    if dtype == 0x00:
        break  # koniec transmisji
    process(dtype, payload[1:])
```

---

## 3. Szczegółowy format każdego typu danych

Format ogólny ramki RX:
```
88 01 25 00 | dtype [1B] | data [...]
```

Dla typów z wieloma rekordami `data` zaczyna się od bajtu `count`:
```
88 01 25 00 | dtype [1B] | count [1B] | record_0 | record_1 | ... | record_N-1
```

---

### 3.1 Tętno HR (dtype=0x02)

**Cechy:** Pomiar co ~5 minut (300 sekund), automatyczny lub manualny trigger.

**Format ramki:**
```
88 01 25 00 | 02 | count [1B] | [ts_LE32 bpm_u8] × count
```

**Rozmiar rekordu:** 5 bajtów  
**Rozmiar ramki:** `2 + count × 5` bajtów w payloadzie

**Przykład z HCI (2 rekordy):**
```
88 01 25 00 02 02 39 79 FF 69 4B 65 7A FF 69 4C
            ── ── └──────────┘ ── └──────────┘ ──
         dtype  count  ts=1778350393  bpm=75  ts=1778350693  bpm=76
                       2026-05-09              2026-05-09
                         20:13:13                20:18:13
```

Weryfikacja: 1778350693 - 1778350393 = 300 sekund = dokładnie 5 minut ✓

**Parsowanie w Pythonie:**
```python
def parse_hr(data: bytes) -> list[dict]:
    """data = payload po dtype (zaczyna się od count)"""
    if not data:
        return []
    count = data[0]
    records = []
    for i in range(count):
        off = 1 + i * 5
        if off + 5 > len(data):
            break
        ts  = struct.unpack_from("<I", data, off)[0]
        bpm = data[off + 4]
        records.append({"ts": ts, "bpm": bpm, "dt": datetime.fromtimestamp(ts)})
    return records
```

**Zakresy wartości:**
- `ts`: Unix timestamp, zawsze w czasie lokalnym
- `bpm`: 0–255 (typowo 40–200 dla żywego człowieka; 0 może oznaczać brak odczytu)

---

### 3.2 Saturacja SpO2 (dtype=0x03)

**Format:** identyczny z HR, różni się tylko dtype i interpretacją wartości.

```
88 01 25 00 | 03 | count [1B] | [ts_LE32 spo2_u8] × count
```

**Rozmiar rekordu:** 5 bajtów (identycznie jak HR)

**Parsowanie:**
```python
def parse_spo2(data: bytes) -> list[dict]:
    count = data[0]
    records = []
    for i in range(count):
        off = 1 + i * 5
        if off + 5 > len(data):
            break
        ts   = struct.unpack_from("<I", data, off)[0]
        spo2 = data[off + 4]
        records.append({"ts": ts, "spo2": spo2, "dt": datetime.fromtimestamp(ts)})
    return records
```

**Zakresy wartości:**
- `spo2`: 0–100 (%), typowo 94–100; wartości < 90 wymagają uwagi

---

### 3.3 Fazy snu (dtype=0x05)

**Cechy:** Dane snu są rozbijane na wiele ramek po max. 22 rekordy każda. Jedna noc snu to zazwyczaj 3–5 ramek (53 rekordy w przykładzie = 4 ramki).

**Format ramki:**
```
88 01 25 00 | 05 | count [1B] | [ts_LE32 pad_u8 stage_u8 dur_min_u8 pad_u8] × count
```

**Rozmiar rekordu:** 8 bajtów

**Szczegółowy layout rekordu:**
```
Offset  Rozmiar  Opis
  0       4      Unix timestamp początku fazy (LE32)
  4       1      Padding — zawsze 0x00 (ignoruj)
  5       1      Faza snu: 0=Awake, 1=Light, 2=Deep, 3=REM
  6       1      Czas trwania fazy w minutach (u8)
  7       1      Padding — zawsze 0x00 (ignoruj)
```

**Przykład z HCI (pierwsze 3 rekordy):**
```
C4 68 FE 69  00  03  13  00   → 2026-05-09 00:50:44  REM   19 min
38 6D FE 69  00  01  09  00   → 2026-05-09 01:09:44  Light  9 min
54 6F FE 69  00  00  0A  00   → 2026-05-09 01:18:44  Awake 10 min
└──────────┘  └┘  └┘  └┘  └┘
 timestamp   pad stage dur pad
```

**Mapowanie faz:**
| Wartość | Nazwa | Opis |
|---------|-------|------|
| `0x00` | Awake | Przebudzenie lub bardzo lekki sen |
| `0x01` | Light | Sen lekki (NREM N1/N2) |
| `0x02` | Deep  | Sen głęboki (NREM N3 / SWS) |
| `0x03` | REM   | Sen REM (marzenia senne) |

**Parsowanie:**
```python
STAGE_NAMES = {0: "Awake", 1: "Light", 2: "Deep", 3: "REM"}

def parse_sleep_stages(data: bytes) -> list[dict]:
    """data = payload po dtype"""
    count = data[0]
    records = []
    for i in range(count):
        off = 1 + i * 8
        if off + 8 > len(data):
            break
        ts      = struct.unpack_from("<I", data, off)[0]
        stage   = data[off + 5]   # byte[4] to padding, byte[5] to stage
        dur_min = data[off + 6]
        records.append({
            "ts":       ts,
            "dt":       datetime.fromtimestamp(ts),
            "stage":    stage,
            "stage_name": STAGE_NAMES.get(stage, f"unknown({stage})"),
            "dur_min":  dur_min,
        })
    return records
```

**Łączenie chunków:** Kilka ramek z dtype=0x05 należy sklejać w jedną listę:
```python
all_sleep = []
for frame in received_frames:
    if frame["dtype"] == 0x05:
        all_sleep.extend(parse_sleep_stages(frame["data"]))

# Sortuj chronologicznie (zegarek wysyła w kolejności, ale dla pewności):
all_sleep.sort(key=lambda r: r["ts"])
```

**Typowy układ nocy snu:**

Z analizy HCI dla nocy 2026-05-09:
```
00:50  REM    19 min   ← początek snu
01:09  Light   9 min
01:18  Awake  10 min
...
04:58  Light  77 min   ← najdłuższy segment (głęboki NREM N2)
...
07:29  Deep   12 min   ← fazy SWS typowo w drugiej połowie nocy
07:45  REM     2 min
...
09:26  Deep    1 min   ← koniec snu
```

---

### 3.4 Kroki dzienne (dtype=0x07)

**Cechy:** Pojedynczy rekord — agregat z całego dnia. Nie ma `count` — dane zaczynają się bezpośrednio po dtype.

**Format ramki:**
```
88 01 25 00 | 07 | steps_LE32 | cal_LE32 | dist_m_LE32 | extra [5B]
```

**Rozmiar payloadu:** 17 bajtów (1 dtype + 16 danych)

**Przykład z HCI:**
```
88 01 25 00 07 D1 08 00 00 82 00 00 00 3B 00 00 00 06 95 07 00 00
            ── └─────────┘ └─────────┘ └─────────┘ └───────────┘
          dtype steps=2257  cal=130    dist=59m     extra (TBD)
```

Rozkład `extra` (5 bajtów `06 95 07 00 00`) jest nieznany — możliwe wartości:
- aktywne minuty
- strefy spalania (fat burn / cardio / peak)
- liczba kroków aktywnych vs. pasywnych

**Parsowanie:**
```python
def parse_steps(data: bytes) -> dict | None:
    """data = payload po dtype (brak count)"""
    if len(data) < 12:
        return None
    steps = struct.unpack_from("<I", data, 0)[0]
    cal   = struct.unpack_from("<I", data, 4)[0]
    dist  = struct.unpack_from("<I", data, 8)[0]
    extra = data[12:]  # 5 bajtów o nieznanym formacie
    return {
        "steps":     steps,
        "calories":  cal,
        "distance_m": dist,
        "extra_raw": extra.hex(),
    }
```

**Zakresy:**
- `steps`: typowo 0–30000 kroków/dzień
- `calories`: kcal (nie kJ), typowo 0–800
- `dist_m`: metry, typowo 0–25000

---

### 3.5 Agregaty HR (dtype=0x09)

**Cechy:** Format identyczny z HR (dtype=0x02). Najprawdopodobniej dzienne podsumowanie — wartość może być średnią, minimum lub maksimum tętna z okresu. Interpretacja wartości nie jest w pełni potwierdzona.

**Format:**
```
88 01 25 00 | 09 | count [1B] | [ts_LE32 val_u8] × count
```

**Przykład z HCI (1 rekord):**
```
88 01 25 00 09 01 38 79 FF 69 2E
            ── ── └──────────┘ ──
          dtype  1  ts=20:13:12  val=46
```

Wartość `46` przy timestampie 20:13 — możliwe że to dzienna minimalna wartość HR (spoczynkowe tętno).

**Parsowanie:** identyczne jak HR:
```python
def parse_hr_agg(data: bytes) -> list[dict]:
    return parse_hr(data)  # ten sam format binarny
```

---

### 3.6 Szczegóły snu (dtype=0x0B)

**Status: Format częściowo zdekodowany.**

**Format ramki:**
```
88 01 25 00 | 0B | [17 bajtów danych]
```

**Przykład z HCI:**
```
88 01 25 00 0B 03 01 20 76 FF 69 00 00 00 00 00 00 00 00 00 00 00
            ── ── ── └──────────────────────────────────────────┘
          dtype  ?   ? 16 bajtów (głównie zera)
```

Bajt[1]=`0x03`, bajt[2]=`0x01` — możliwe że to liczba sesji snu i wersja.  
Bajtów z danymi jest 12 z 16 = zera — prawdopodobnie pola niepełne (brak danych) lub zarezerwowane.

Ramka ta pojawia się raz, zaraz przed END. Prawdopodobna interpretacja: podsumowanie sesji snu (całkowity czas, jakość snu jako procent lub wynik).

**Parsowanie (surowe):**
```python
def parse_sleep_detail(data: bytes) -> dict:
    return {
        "raw": data.hex(),
        "len": len(data),
    }
```

---

### 3.7 Koniec transmisji (dtype=0x00)

Zegarek sygnalizuje koniec danych ramką:

```
88 01 25 00 | 00
```

Payload po nagłówku to `0x00` (1 bajt). Po otrzymaniu tej ramki nie należy czekać na więcej danych.

```python
if dtype == 0x00:
    print("Pobieranie zakończone")
    break
```

---

## 4. Kolejność i chunking ramek

### Kolejność przychodzących ramek

Z analizy HCI (zawsze w tej samej kolejności):

```
1. dtype=0x02  HR              (1 ramka, do 22 rekordów)
2. dtype=0x05  SleepStage      (N ramek po 22 rekordy, jedna sesja snu = 3–5 ramek)
3. dtype=0x07  Steps           (1 ramka, 1 rekord bez count)
4. dtype=0x09  HR aggregate    (1 ramka, do kilku rekordów)
5. dtype=0x0B  SleepDetail     (1 ramka, surowe)
6. dtype=0x00  END             (1 ramka)
```

Typy bez danych w danym dniu (np. brak SpO2) są **pomijane** — zegarek nie wysyła pustej ramki.

### Dlaczego dane snu są w wielu ramkach?

Ograniczenie MTU ATT (512 bajtów po nagłówkach to ok. 507 bajtów użytkowych). Jeden rekord snu to 8 bajtów. 22 rekordy × 8B = 176B + 2B nagłówka = 178B — to daje margines bezpieczeństwa.

Przykład z HCI: 53 rekordy snu = 4 ramki (22 + 22 + 6 + 3):
```
Ramka 1:  dtype=0x05  count=22  payload=178B
Ramka 2:  dtype=0x05  count=22  payload=178B
Ramka 3:  dtype=0x05  count=6   payload=50B
Ramka 4:  dtype=0x05  count=3   payload=26B
```

Implementacja musi akumulować rekordy przez wiele ramek tego samego dtype:

```python
sleep_records = []  # akumuluj rekordy ze wszystkich chunków

while True:
    raw = await recv()
    payload = raw[4:]
    dtype = payload[0]
    data  = payload[1:]

    if dtype == 0x00:
        break
    elif dtype == 0x05:
        sleep_records.extend(parse_sleep_stages(data))  # dołącz do istniejących
    elif dtype == 0x02:
        hr_records = parse_hr(data)  # zwykle jedna ramka
    # ...
```

---

## 5. Implementacja od zera

Minimalna implementacja pobierania danych bez używania `MibroClient`:

```python
import asyncio
import struct
from datetime import datetime, timedelta
from bleak import BleakClient

MAC       = "10:7B:93:CE:B5:1F"
TX_UUID   = "00002CB1-0000-1000-8000-00805f9b34fb"
RX_UUID   = "00002CB0-0000-1000-8000-00805f9b34fb"

STAGE_NAMES = {0: "Awake", 1: "Light", 2: "Deep", 3: "REM"}


def build_frame(cmd: int, data: bytes = b"") -> bytes:
    return bytes([0x88, 0x01, cmd, 0x00]) + data


def parse_frame(raw: bytes):
    if len(raw) < 4 or raw[:2] != bytes([0x88, 0x01]):
        return None
    return {"cmd": raw[2], "payload": raw[4:]}


async def download_health_data(since_days: int = 7):
    queue = asyncio.Queue()

    def on_notify(_, data):
        queue.put_nowait(bytes(data))

    since_ts = int((datetime.now() - timedelta(days=since_days)).timestamp())

    async with BleakClient(MAC) as client:
        await client.start_notify(RX_UUID, on_notify)

        # --- Handshake (uproszczony — wymagany przed pobieraniem danych) ---
        await client.write_gatt_char(TX_UUID, build_frame(0x01, bytes([0x01, 0x02])), response=False)
        await asyncio.sleep(0.5)
        # Odczyt odpowiedzi handshake i wysłanie etapu 2 pominięto dla zwięzłości
        # (w praktyce użyj mibro_client.MibroClient.handshake())

        # --- Ustaw zakres i wyzwól pobieranie ---
        await client.write_gatt_char(
            TX_UUID,
            build_frame(0x25, struct.pack("<I", since_ts)),
            response=False,
        )
        await client.write_gatt_char(TX_UUID, build_frame(0x30), response=False)

        # --- Odbierz strumień danych ---
        hr, sleep, steps = [], [], None

        while True:
            try:
                raw = await asyncio.wait_for(queue.get(), timeout=10.0)
            except asyncio.TimeoutError:
                print("Timeout — zegarek przestał wysyłać dane")
                break

            frame = parse_frame(raw)
            if not frame or frame["cmd"] != 0x25:
                continue

            payload = frame["payload"]
            if not payload:
                continue

            dtype = payload[0]
            data  = payload[1:]

            if dtype == 0x00:
                print("Pobieranie zakończone (END)")
                break

            elif dtype == 0x02:  # HR
                count = data[0]
                for i in range(count):
                    off = 1 + i * 5
                    ts  = struct.unpack_from("<I", data, off)[0]
                    bpm = data[off + 4]
                    hr.append((datetime.fromtimestamp(ts), bpm))
                    print(f"  HR: {datetime.fromtimestamp(ts).strftime('%H:%M')}  {bpm} bpm")

            elif dtype == 0x05:  # Fazy snu
                count = data[0]
                for i in range(count):
                    off = 1 + i * 8
                    ts  = struct.unpack_from("<I", data, off)[0]
                    stage   = data[off + 5]
                    dur_min = data[off + 6]
                    sleep.append((datetime.fromtimestamp(ts), stage, dur_min))
                    print(f"  Sen: {datetime.fromtimestamp(ts).strftime('%H:%M')}  "
                          f"{STAGE_NAMES.get(stage, stage)}  {dur_min} min")

            elif dtype == 0x07:  # Kroki
                if len(data) >= 12:
                    s = struct.unpack_from("<I", data, 0)[0]
                    c = struct.unpack_from("<I", data, 4)[0]
                    d = struct.unpack_from("<I", data, 8)[0]
                    steps = (s, c, d)
                    print(f"  Kroki: {s}, kcal: {c}, dystans: {d}m")

        return hr, sleep, steps


asyncio.run(download_health_data(since_days=1))
```

---

## 6. Filtrowanie zakresu dat

### Jak działa filtrowanie po stronie zegarka

Zegarek filtruje dane wg `since_ts` — zwraca tylko rekordy z `timestamp >= since_ts`. Nie ma parametru "do kiedy" — zawsze zwraca do chwili obecnej.

```python
# Pobierz dane z ostatnich 7 dni:
since_ts = int((datetime.now() - timedelta(days=7)).timestamp())

# Pobierz dane od konkretnej daty:
since_ts = int(datetime(2026, 5, 1, 0, 0, 0).timestamp())

# Pobierz wszystko (zegarek trzyma max ~7-14 dni):
since_ts = int((datetime.now() - timedelta(days=30)).timestamp())
```

### Filtrowanie po stronie klienta

Po pobraniu możesz dodatkowo filtrować po stronie klienta:

```python
from datetime import datetime, date

def filter_by_date(records: list[dict], target_date: date) -> list[dict]:
    return [r for r in records if r["dt"].date() == target_date]

def filter_by_range(records: list[dict], start: datetime, end: datetime) -> list[dict]:
    return [r for r in records if start <= r["dt"] < end]

# Przykład użycia:
today_hr = filter_by_date(hr_records, date.today())
night_sleep = filter_by_range(
    sleep_records,
    datetime(2026, 5, 9, 0, 0),
    datetime(2026, 5, 9, 12, 0),
)
```

---

## 7. Deduplikacja danych

### Dlaczego dane się duplikują

Z analizy HCI wynika, że każde wywołanie sekwencji `CMD=0x25` + `CMD=0x30` z tym samym `since_ts` zwraca identyczny zestaw danych. Przy wielokrotnym połączeniu lub ponownym triggerze możesz dostać te same rekordy dwa razy.

### Identyfikacja duplikatów

Dla rekordów z timestampem duplikat to rekord o tym samym `ts`:

```python
def dedup_by_timestamp(records: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for r in records:
        if r["ts"] not in seen:
            seen.add(r["ts"])
            result.append(r)
    return result
```

Dla kroków (jeden rekord bez timestampu) zachowaj tylko ostatni:

```python
steps = None  # przechowuj tylko ostatni rekord Steps
# ...
elif dtype == 0x07:
    steps = parse_steps(data)  # nadpisuje poprzedni
```

### Bezpieczne scalanie z istniejącą bazą

```python
def merge_records(existing: list[dict], new: list[dict], key="ts") -> list[dict]:
    """Scala listy rekordów, usuwa duplikaty wg klucza."""
    existing_keys = {r[key] for r in existing}
    added = [r for r in new if r[key] not in existing_keys]
    return existing + added
```

---

## 8. Kompletny przykład z obsługą błędów

```python
import asyncio
import struct
import csv
from datetime import datetime, timedelta
from typing import Optional
import logging

from bleak import BleakClient
from bleak.exc import BleakError

log = logging.getLogger(__name__)

MAC     = "10:7B:93:CE:B5:1F"
TX_UUID = "00002CB1-0000-1000-8000-00805f9b34fb"
RX_UUID = "00002CB0-0000-1000-8000-00805f9b34fb"

STAGE_NAMES = {0: "Awake", 1: "Light", 2: "Deep", 3: "REM"}
DATA_TIMEOUT = 15.0  # sekund na odebranie kolejnej ramki


class HealthDataDownloader:
    def __init__(self, mac: str = MAC):
        self.mac = mac
        self._queue: asyncio.Queue = asyncio.Queue()
        self.hr_records:    list[dict] = []
        self.spo2_records:  list[dict] = []
        self.sleep_records: list[dict] = []
        self.hr_agg:        list[dict] = []
        self.steps:         Optional[dict] = None

    def _on_notify(self, _, raw: bytearray):
        self._queue.put_nowait(bytes(raw))

    async def _recv(self, timeout: float = DATA_TIMEOUT) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def download(self, since_days: int = 7) -> bool:
        since_ts = int((datetime.now() - timedelta(days=since_days)).timestamp())
        log.info(f"Pobieranie od: {datetime.fromtimestamp(since_ts)}")

        try:
            async with BleakClient(self.mac) as client:
                await client.start_notify(RX_UUID, self._on_notify)

                # Tutaj powinien być handshake — skrócone dla czytelności
                # W praktyce: from mibro_client import MibroClient
                # i użyj client.handshake() przed tym krokiem

                # Wyślij zakres i trigger
                await client.write_gatt_char(
                    TX_UUID,
                    bytes([0x88, 0x01, 0x25, 0x00]) + struct.pack("<I", since_ts),
                    response=False,
                )
                await client.write_gatt_char(
                    TX_UUID,
                    bytes([0x88, 0x01, 0x30, 0x00]),
                    response=False,
                )

                # Odbieraj dane
                return await self._collect()

        except BleakError as e:
            log.error(f"Błąd BLE: {e}")
            return False

    async def _collect(self) -> bool:
        frames_received = 0
        end_received = False

        while True:
            raw = await self._recv()
            if raw is None:
                log.warning(f"Timeout po {frames_received} ramkach")
                break

            if len(raw) < 5 or raw[:2] != bytes([0x88, 0x01]) or raw[2] != 0x25:
                continue

            payload = raw[4:]
            dtype   = payload[0]
            data    = payload[1:]
            frames_received += 1

            if dtype == 0x00:
                end_received = True
                break

            self._dispatch(dtype, data)

        if end_received:
            log.info(f"OK — odebrano {frames_received} ramek")
        return end_received

    def _dispatch(self, dtype: int, data: bytes):
        if dtype == 0x02:
            self._parse_fixed5(data, self.hr_records,
                               lambda ts, v: {"ts": ts, "dt": datetime.fromtimestamp(ts), "bpm": v})

        elif dtype == 0x03:
            self._parse_fixed5(data, self.spo2_records,
                               lambda ts, v: {"ts": ts, "dt": datetime.fromtimestamp(ts), "spo2": v})

        elif dtype == 0x05:
            count = data[0] if data else 0
            for i in range(count):
                off = 1 + i * 8
                if off + 8 > len(data):
                    break
                ts      = struct.unpack_from("<I", data, off)[0]
                stage   = data[off + 5]
                dur_min = data[off + 6]
                self.sleep_records.append({
                    "ts":         ts,
                    "dt":         datetime.fromtimestamp(ts),
                    "stage":      stage,
                    "stage_name": STAGE_NAMES.get(stage, f"S{stage}"),
                    "dur_min":    dur_min,
                })

        elif dtype == 0x07:
            if len(data) >= 12:
                self.steps = {
                    "steps":      struct.unpack_from("<I", data, 0)[0],
                    "calories":   struct.unpack_from("<I", data, 4)[0],
                    "distance_m": struct.unpack_from("<I", data, 8)[0],
                }

        elif dtype == 0x09:
            self._parse_fixed5(data, self.hr_agg,
                               lambda ts, v: {"ts": ts, "dt": datetime.fromtimestamp(ts), "value": v})

        else:
            log.debug(f"Nieznany dtype=0x{dtype:02X}  data={data.hex()}")

    @staticmethod
    def _parse_fixed5(data: bytes, target: list, factory):
        count = data[0] if data else 0
        for i in range(count):
            off = 1 + i * 5
            if off + 5 > len(data):
                break
            ts  = struct.unpack_from("<I", data, off)[0]
            val = data[off + 4]
            target.append(factory(ts, val))

    def dedup(self):
        """Usuwa duplikaty (ten sam timestamp) ze wszystkich list."""
        for attr in ("hr_records", "spo2_records", "sleep_records", "hr_agg"):
            records = getattr(self, attr)
            seen = set()
            deduped = []
            for r in records:
                if r["ts"] not in seen:
                    seen.add(r["ts"])
                    deduped.append(r)
            setattr(self, attr, deduped)

    def export_csv(self, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["type", "datetime", "value", "unit", "extra"])
            for r in sorted(self.hr_records, key=lambda x: x["ts"]):
                w.writerow(["hr", r["dt"].isoformat(), r["bpm"], "bpm", ""])
            for r in sorted(self.spo2_records, key=lambda x: x["ts"]):
                w.writerow(["spo2", r["dt"].isoformat(), r["spo2"], "%", ""])
            for r in sorted(self.sleep_records, key=lambda x: x["ts"]):
                w.writerow(["sleep", r["dt"].isoformat(), r["stage_name"], "stage",
                             f"dur={r['dur_min']}min"])
            for r in sorted(self.hr_agg, key=lambda x: x["ts"]):
                w.writerow(["hr_agg", r["dt"].isoformat(), r["value"], "bpm_agg", ""])
            if self.steps:
                w.writerow(["steps", datetime.now().date().isoformat(),
                             self.steps["steps"], "steps",
                             f"cal={self.steps['calories']} dist={self.steps['distance_m']}m"])
        log.info(f"Zapisano: {path}")

    def print_summary(self):
        print(f"\n{'='*50}")
        print(f"HR:    {len(self.hr_records)} pomiarów")
        print(f"SpO2:  {len(self.spo2_records)} pomiarów")
        print(f"Sen:   {len(self.sleep_records)} faz")
        if self.sleep_records:
            total = sum(r["dur_min"] for r in self.sleep_records)
            print(f"       łącznie {total//60}h {total%60}min")
        if self.steps:
            print(f"Kroki: {self.steps['steps']}  kcal={self.steps['calories']}")
        print(f"{'='*50}\n")


async def main():
    dl = HealthDataDownloader(mac="10:7B:93:CE:B5:1F")
    ok = await dl.download(since_days=7)
    if ok:
        dl.dedup()
        dl.print_summary()
        dl.export_csv("health.csv")
    else:
        print("Pobieranie nieudane")


asyncio.run(main())
```

---

## 9. Tabela szybkiego odniesienia

### Typy danych w CMD=0x25 RX

| dtype | Nazwa | count? | Rozmiar rekordu | Ramek | Pola |
|-------|-------|--------|-----------------|-------|------|
| `0x00` | END | nie | — | 1 | (brak) |
| `0x02` | HR | **tak** | 5B | 1 | `ts_LE32 + bpm_u8` |
| `0x03` | SpO2 | **tak** | 5B | 1 | `ts_LE32 + spo2_u8` |
| `0x05` | SleepStage | **tak** | 8B | **N** | `ts_LE32 + 0x00 + stage_u8 + dur_u8 + 0x00` |
| `0x07` | Steps | **nie** | 16B | 1 | `steps_LE32 + cal_LE32 + dist_LE32 + extra_5B` |
| `0x09` | HR_agg | **tak** | 5B | 1 | `ts_LE32 + val_u8` |
| `0x0B` | SleepDetail | ? | 17B | 1 | surowe (TBD) |

### Fazy snu — byte[5] w rekordzie SleepStage

| Wartość | Polska nazwa | Angielska nazwa |
|---------|-------------|-----------------|
| `0x00` | Przebudzenie | Awake |
| `0x01` | Sen lekki | Light Sleep |
| `0x02` | Sen głęboki | Deep Sleep (SWS) |
| `0x03` | Sen REM | REM Sleep |

### Komendy TX

| CMD | Payload | Opis |
|-----|---------|------|
| `0x25` | `since_ts [LE32]` | Ustaw zakres danych (timestamp początku) |
| `0x30` | (brak) | Wyzwól pobieranie — zegarek zaczyna wysyłać |

### Rzeczywisty przykład — bajty z HCI

```
TX: 88 01 25 00  C5 6B FF 69        ← set_since = 2026-05-09 19:15:49
TX: 88 01 30 00                      ← trigger

RX: 88 01 25 00  02 02  3979FF69 4B  657AFF69 4C   ← 2×HR: 75bpm, 76bpm
RX: 88 01 25 00  05 16  C468FE69 00 03 13 00  ...  ← 22×SleepStage (pierwszy chunk)
RX: 88 01 25 00  05 16  8499FE69 00 00 04 00  ...  ← 22×SleepStage (drugi chunk)
RX: 88 01 25 00  05 06  10D1FE69 00 02 0B 00  ...  ← 6×SleepStage
RX: 88 01 25 00  05 03  8CDCFE69 00 02 14 00  ...  ← 3×SleepStage (ostatni chunk)
RX: 88 01 25 00  07  D1080000 82000000 3B000000 ...  ← Steps: 2257k, 130kcal, 59m
RX: 88 01 25 00  09 01  3879FF69 2E              ← 1×HR_agg: val=46
RX: 88 01 25 00  0B  03 01 20 76 FF 69 00...    ← SleepDetail (surowe)
RX: 88 01 25 00  00                              ← END
```
