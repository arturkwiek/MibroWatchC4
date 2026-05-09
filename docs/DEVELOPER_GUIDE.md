# Mibro Watch C4 — Developer Guide

Praktyczny przewodnik dla programistów, którzy chcą budować własne aplikacje odczytujące dane z zegarka **Mibro Watch C4** przez BLE.

> **Wymagania wstępne**: Python 3.10+, Windows 10/11 z Bluetooth LE, zegarek Mibro Watch C4.
> Cały gotowy kod jest w plikach `mibro_protocol.py`, `mibro_client.py` i narzędziach pomocniczych.

---

## Spis treści

1. [Szybki start](#1-szybki-start)
2. [Architektura biblioteki](#2-architektura-biblioteki)
3. [Instalacja i konfiguracja środowiska](#3-instalacja-i-konfiguracja-środowiska)
4. [Połączenie z zegarkiem](#4-połączenie-z-zegarkiem)
5. [Pobieranie danych zdrowotnych](#5-pobieranie-danych-zdrowotnych)
6. [Praca z danymi — typy i struktury](#6-praca-z-danymi--typy-i-struktury)
7. [Eksport i wizualizacja](#7-eksport-i-wizualizacja)
8. [Praca bez żywego połączenia BLE](#8-praca-bez-żywego-połączenia-ble)
9. [Rozszerzanie protokołu](#9-rozszerzanie-protokołu)
10. [Uwierzytelnianie — znane ograniczenia](#10-uwierzytelnianie--znane-ograniczenia)
11. [Przechwytywanie nowych logów HCI](#11-przechwytywanie-nowych-logów-hci)
12. [Rozwiązywanie problemów](#12-rozwiązywanie-problemów)

---

## 1. Szybki start

### Scenariusz A — masz zegarek pod ręką (live BLE)

```bash
# Zainstaluj zależności
pip install bleak pycryptodome

# Odłącz zegarek od telefonu, a potem:
python mibro_client.py --mac 10:7B:93:CE:B5:1F --days 7 --csv health.csv --debug

# Wygeneruj wykres
pip install matplotlib
python plot_health.py
```

### Scenariusz B — masz już plik JSON z ramkami (offline)

```bash
python export_captured_health.py --json mibro_captured_frames.json --csv health.csv
python plot_health.py
```

### Scenariusz C — nowy HCI log z telefonu

```bash
# Skopiuj log z telefonu
adb pull /data/misc/bluetooth/logs/btsnoop_hci.log .

# Sparsuj i wyciągnij ramki protokołu
python mibro_hci_parse.py btsnoop_hci.log

# Dalej jak w scenariuszu B
python export_captured_health.py
python plot_health.py
```

---

## 2. Architektura biblioteki

```
mibro_protocol.py          ← rdzeń: budowanie ramek, parsowanie danych
mibro_client.py            ← klient BLE (bleak), CLI, eksport CSV
mibro_hci_parse.py         ← parser logów BTSnoop HCI (Android)
export_captured_health.py  ← eksport danych z pliku JSON (bez BLE)
plot_health.py             ← wizualizacja matplotlib
frida_capture_auth.js      ← Frida hooks (przechwytywanie klucza auth)
```

### Przepływ danych

```
Android HCI log ──► mibro_hci_parse.py ──► mibro_captured_frames.json
                                                        │
Live BLE ────────────────────────────────────────────── ┘
     │                                                  │
     └──► mibro_client.py ──────────────────────────── ┘
               │                                        │
               └──────────────────────────────────────► export_captured_health.py
                                                                    │
                                                                    ▼
                                                             health_export.csv
                                                                    │
                                                                    ▼
                                                             plot_health.py ──► health_chart.png
```

---

## 3. Instalacja i konfiguracja środowiska

### Wymagane zależności

```bash
pip install bleak pycryptodome matplotlib
```

| Biblioteka | Po co |
|---|---|
| `bleak` | Klient BLE (async, cross-platform) |
| `pycryptodome` | AES do handshake auth |
| `matplotlib` | Wizualizacja hipnogramów i HR |

### Zalecana struktura projektu

```
projekt/
├── mibro_protocol.py          ← importuj jako bibliotekę
├── mibro_client.py            ← gotowy klient lub baza do rozbudowy
├── mibro_hci_parse.py         ← narzędzie do analizy logów
├── export_captured_health.py  ← narzędzie offline
├── plot_health.py             ← wizualizacja
├── frida_capture_auth.js      ← narzędzie RE (opcjonalne)
└── twoj_skrypt.py             ← tutaj budujesz swoją aplikację
```

### Wirtualne środowisko (zalecane)

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install bleak pycryptodome matplotlib
```

---

## 4. Połączenie z zegarkiem

### Podstawowe użycie (jako biblioteka)

```python
import asyncio
from mibro_client import MibroClient

async def main():
    client = MibroClient(mac="10:7B:93:CE:B5:1F")

    await client.connect()           # nawiąż połączenie BLE
    await client.handshake()         # uwierzytelnij sesję
    await client.sync_time()         # opcjonalnie: zsynchronizuj czas
    battery = await client.get_battery()
    print(f"Bateria: {battery}%")

    await client.disconnect()

asyncio.run(main())
```

### Obsługa błędów połączenia

```python
from bleak.exc import BleakError

async def safe_connect():
    client = MibroClient(mac="10:7B:93:CE:B5:1F")
    try:
        await client.connect()
        await client.handshake()
        return client
    except BleakError as e:
        print(f"Błąd BLE: {e}")
        # Najczęstsza przyczyna: zegarek podłączony do telefonu
        # → Force-stop aplikacji Mibro Fit na telefonie
        return None
    except asyncio.TimeoutError:
        print("Timeout — zegarek poza zasięgiem lub zajęty")
        return None
```

### Konfigurowalny MAC i parametry

```python
# MAC zegarka można odczytać z logu HCI lub przez skan BLE
from mibro_client import MibroClient, WATCH_MAC

client = MibroClient(
    mac=WATCH_MAC  # domyślnie "10:7B:93:CE:B5:1F"
)
```

### Skanowanie w poszukiwaniu zegarka

Jeśli nie znasz MAC-a, możesz użyć bleaka do znalezienia zegarka:

```python
from bleak import BleakScanner

async def find_mibro():
    devices = await BleakScanner.discover(timeout=10.0)
    for d in devices:
        if d.name and "mibro" in d.name.lower():
            print(f"Znaleziono: {d.name} @ {d.address}")
            return d.address
    return None
```

---

## 5. Pobieranie danych zdrowotnych

### Pełna synchronizacja

```python
async def sync(client: MibroClient, days: int = 7):
    await client.download_health_data(since_days=days)

    # Dane są dostępne jako atrybuty klienta:
    print(f"HR: {len(client.hr_records)} pomiarów")
    print(f"SpO2: {len(client.spo2_records)} pomiarów")
    print(f"Sen: {len(client.sleep_records)} faz")
    print(f"Kroki: {client.steps.steps if client.steps else 0}")
```

### Dostęp do konkretnego typu danych

```python
# Tętno — lista HRRecord (timestamp + bpm)
for r in client.hr_records:
    print(f"{r.dt.strftime('%Y-%m-%d %H:%M')}  {r.bpm} bpm")

# SpO2 — lista SpO2Record (timestamp + spo2)
for r in client.spo2_records:
    print(f"{r.dt.strftime('%Y-%m-%d %H:%M')}  {r.spo2}%")

# Fazy snu — lista SleepStageRecord (timestamp + stage + duration_min)
for r in client.sleep_records:
    print(f"{r.dt.strftime('%H:%M')}  {r.stage_name:<6}  {r.duration_min} min")

# Kroki — jeden StepsRecord (steps + calories + distance_m)
if client.steps:
    s = client.steps
    print(f"Kroków: {s.steps}, kcal: {s.calories}, dystans: {s.distance_m}m")

# Agregaty HR (dzienne min/max/avg)
for r in client.hr_agg_records:
    print(f"{r.dt.strftime('%H:%M')}  HR-agg={r.value}")
```

### Kompletny skrypt synchronizacji

```python
import asyncio
from mibro_client import MibroClient

async def full_sync(mac: str, days: int = 7, csv_path: str = "health.csv"):
    client = MibroClient(mac=mac)
    try:
        await client.connect()

        ok = await client.handshake()
        if not ok:
            print("Handshake nieudany")
            return

        await client.get_device_info()
        await client.sync_time()
        await client.get_battery()
        await client.download_health_data(since_days=days)

        client.print_summary()
        client.export_csv(csv_path)

    finally:
        await client.disconnect()

asyncio.run(full_sync("10:7B:93:CE:B5:1F", days=7, csv_path="health.csv"))
```

---

## 6. Praca z danymi — typy i struktury

Wszystkie typy danych zdefiniowane są w `mibro_protocol.py` jako dataclassy:

### HRRecord — pomiar tętna

```python
from mibro_protocol import HRRecord
import datetime

r = HRRecord(timestamp=1778265600, bpm=72)
print(r.dt)        # datetime.datetime
print(r.bpm)       # int, uderzenia na minutę
print(r.timestamp) # int, Unix timestamp
```

### SpO2Record — saturacja krwi

```python
from mibro_protocol import SpO2Record

r = SpO2Record(timestamp=1778265600, spo2=98)
print(r.dt)    # datetime.datetime
print(r.spo2)  # int, procent saturacji (0–100)
```

### SleepStageRecord — faza snu

```python
from mibro_protocol import SleepStageRecord

r = SleepStageRecord(timestamp=1778220000, stage=1, sub_stage=0, duration_min=45)
print(r.dt)            # datetime.datetime — początek fazy
print(r.stage)         # int: 0=Awake, 1=Light, 2=Deep, 3=REM
print(r.stage_name)    # str: "Awake" / "Light" / "Deep" / "REM"
print(r.duration_min)  # int — czas trwania fazy w minutach
```

### StepsRecord — kroki (dzienny)

```python
from mibro_protocol import StepsRecord

r = StepsRecord(steps=8432, calories=320, distance_m=5800)
print(r.steps)       # int
print(r.calories)    # int, kcal
print(r.distance_m)  # int, metry
```

### HRAggregate — agregat HR

```python
from mibro_protocol import HRAggregate

r = HRAggregate(timestamp=1778265600, value=68)
print(r.dt)     # datetime.datetime
print(r.value)  # int (interpretacja: min/max/avg — TBD)
```

---

## 7. Eksport i wizualizacja

### Eksport do CSV

```python
# Przez MibroClient (po live sync)
client.export_csv("health.csv")

# Lub przez skrypt offline
# python export_captured_health.py --json mibro_captured_frames.json --csv health.csv
```

Format CSV:

```
type,datetime,value,unit,extra
hr,2026-05-09T20:13:07,75,bpm,
sleep,2026-05-09T00:50:44,REM,stage,dur=19min
sleep,2026-05-09T01:09:44,Light,stage,dur=9min
steps,2026-05-09,2257,steps,cal=130 dist=59m
```

### Wczytanie CSV w Pandas

```python
import pandas as pd

df = pd.read_csv("health.csv", parse_dates=["datetime"])

# Filtrowanie per typ
hr_df    = df[df["type"] == "hr"].copy()
sleep_df = df[df["type"] == "sleep"].copy()
steps_df = df[df["type"] == "steps"].copy()

# Średnie tętno
print(hr_df["value"].astype(int).mean())

# Całkowity czas snu (minuty)
sleep_df["dur_min"] = sleep_df["extra"].str.extract(r"dur=(\d+)min").astype(int)
print(sleep_df["dur_min"].sum(), "min snu")
```

### Wizualizacja (matplotlib)

```bash
python plot_health.py
```

Generuje `health_chart.png` — hipnogram + wykres HR.

Żeby użyć funkcji wizualizacji we własnym skrypcie:

```python
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from plot_health import load_csv, plot_hypnogram, plot_hr

sleep, hr, hr_agg, steps = load_csv("health.csv")

fig, axes = plt.subplots(2, 1, figsize=(14, 8))
plot_hypnogram(axes[0], sleep)
plot_hr(axes[1], hr, hr_agg, steps)
plt.tight_layout()
plt.show()
```

---

## 8. Praca bez żywego połączenia BLE

Przydatne gdy zegarek jest zajęty (podłączony do telefonu) lub niedostępny.

### Z pliku JSON ramek

```bash
python export_captured_health.py \
    --json mibro_captured_frames.json \
    --csv  health_export.csv
```

Flagi:
- `--json PATH` — wejście (domyślnie: `mibro_captured_frames.json`)
- `--csv PATH`  — wyjście (domyślnie: `health_export.csv`)
- `--no-dedup`  — nie usuwaj duplikatów (domyślnie: usuwa)

### Programowe parsowanie ramek

```python
import json
import mibro_protocol as proto

with open("mibro_captured_frames.json") as f:
    frames = json.load(f)

for entry in frames:
    raw = bytes.fromhex(entry.get("hex") or entry.get("raw") or "")
    frame = proto.parse_frame(raw)
    if frame and frame["cmd"] == 0x25:
        result = proto.parse_data_frame(frame["payload"])
        if result and result["type"] == "hr":
            for r in result["records"]:
                print(f"{r.dt}  {r.bpm} bpm")
```

---

## 9. Rozszerzanie protokołu

### Dodanie nowej komendy

Jeśli odkryjesz nową komendę (np. `0x06` — profil użytkownika), dodaj do `mibro_protocol.py`:

```python
# W mibro_protocol.py

def build_set_user_profile(age: int, height_cm: int, weight_kg: int, step_goal: int) -> bytes:
    """cmd=0x06: ustaw profil użytkownika."""
    return build_frame(0x06, bytes([age, height_cm, weight_kg]) + struct.pack("<I", step_goal))


def parse_user_profile_response(payload: bytes) -> dict | None:
    if len(payload) < 7:
        return None
    return {
        "age":       payload[0],
        "height_cm": payload[1],
        "weight_kg": payload[2],
        "step_goal": struct.unpack_from("<I", payload, 3)[0],
    }
```

Następnie w `mibro_client.py`:

```python
async def set_user_profile(self, age: int, height_cm: int, weight_kg: int) -> None:
    await self._write(proto.build_set_user_profile(age, height_cm, weight_kg, 10000))
    await self._drain(timeout=1.0)
```

### Nasłuchiwanie nieznanych ramek

Żeby monitorować wszystkie przychodzące ramki podczas sesji:

```python
async def monitor_all(client: MibroClient, duration: float = 30.0):
    """Drukuje wszystkie ramki przez N sekund."""
    deadline = asyncio.get_event_loop().time() + duration
    while asyncio.get_event_loop().time() < deadline:
        raw = await client._recv(timeout=1.0)
        if raw:
            frame = proto.parse_frame(raw)
            if frame:
                print(f"CMD={frame['cmd']:02X}  payload={frame['payload'].hex()}")
            else:
                print(f"Non-protocol: {raw.hex()}")
```

### Wysyłanie surowej ramki

Gdy chcesz przetestować nieznaną komendę bez pisania helpera:

```python
# Wyślij cmd=0x34 z payload=00 (echo?)
raw_frame = proto.build_frame(0x34, bytes([0x00]))
await client._write(raw_frame)
response = await client._recv(timeout=3.0)
if response:
    print(f"Odpowiedź: {response.hex()}")
```

### Dodanie nowego typu danych (dtype)

Jeśli zegarek zacznie wysyłać nieznany dtype w odpowiedzi na cmd=0x25, rozszerz `parse_data_frame`:

```python
# Na końcu parse_data_frame w mibro_protocol.py

DATA_TYPE_STRESS = 0x0D  # przykładowo

if dtype == DATA_TYPE_STRESS:
    return {"type": "stress", "records": _parse_5byte_records(data, _make_stress)}

def _make_stress(ts, val):
    return {"timestamp": ts, "stress": val}
```

---

## 10. Uwierzytelnianie — znane ograniczenia

### Aktualny stan

Handshake wysyła `AES-128-ECB(key=deviceKey, plaintext=challenge)`. Problem: `deviceKey` jest osobnym kluczem ustalonym przy parowaniu — zegarek wysyła go tylko do oficjalnej aplikacji i przechowuje ją w SharedPreferences.

**W praktyce**: zegarek może nie weryfikować odpowiedzi auth. Kod wysyła jako fallback sam challenge z powrotem — jeśli zegarek nie zwraca błędu i odpowiada na komendy, klucz nie jest wymagany.

### Jak zdobyć prawdziwy deviceKey

#### Opcja 1: Frida (zalecana, nie wymaga roota)

Wymagania: zainstalowany `frida-server` na telefonie.

```bash
# Na PC:
pip install frida-tools
frida -U -n "com.xiaoxun.xunoversea.mibrofit" -l frida_capture_auth.js
```

Następnie: otwórz aplikację Mibro i zsynchronizuj zegarek. W terminalu pojawi się przechwycony klucz.

#### Opcja 2: ADB + SharedPreferences (wymaga root lub backup)

```bash
adb shell run-as com.xiaoxun.xunoversea.mibrofit \
    cat /data/data/com.xiaoxun.xunoversea.mibrofit/shared_prefs/wk_device.xml
```

Szukaj pola `deviceKey` lub `authKey`.

#### Opcja 3: mitmproxy (przechwycenie HTTPS)

Podczas synchronizacji aplikacja wysyła żądanie do `gateway.iwhop.cn`. W odpowiedzi serwer zwraca auth code, który aplikacja przesyła do zegarka. Przechwycenie odpowiedzi serwera daje gotowy auth code.

```bash
pip install mitmproxy
mitmweb --listen-port 8080
# Skonfiguruj telefon żeby używał proxy 8080
# Zaimportuj certyfikat mitmproxy na telefon
```

#### Użycie znalezionego klucza

Gdy masz `deviceKey` (32 znaków hex = 16 bajtów):

```python
# W mibro_protocol.py zmień compute_auth_response:
DEVICE_KEY = "0102030405060708090a0b0c0d0e0f10"  # ← twój klucz

def compute_auth_response(token_hex: str, challenge: bytes) -> bytes:
    from Crypto.Cipher import AES
    key = bytes.fromhex(DEVICE_KEY)  # użyj rzeczywistego klucza
    return AES.new(key, AES.MODE_ECB).encrypt(challenge[:16])
```

---

## 11. Przechwytywanie nowych logów HCI

Gdy chcesz zbadać nowe komendy lub zegarek zachowuje się inaczej niż oczekiwano, zbierz nowy log HCI.

### Kroki na telefonie Android

1. Włącz **Opcje deweloperskie**: Ustawienia → O telefonie → kliknij "Numer kompilacji" 7 razy
2. Ustawienia → Opcje deweloperskie → włącz **"Enable Bluetooth HCI snoop log"**
3. Wyłącz i włącz Bluetooth (czyszczenie bufora)
4. Otwórz **Mibro Fit** → wykonaj synchronizację (poczekaj ~60 sekund)
5. Wyłącz i włącz Bluetooth ponownie (zapis na dysk)

### Pobranie logu

```bash
# Metoda A (standardowa):
adb pull /data/misc/bluetooth/logs/btsnoop_hci.log .

# Metoda B (Samsung):
adb pull /sdcard/bluetooth/btsnoop_hci.log .

# Metoda C (bugreport, gdy brak dostępu do /data):
adb bugreport bugreport.zip
# Wyciągnij: bugreport.zip/FS/data/misc/bluetooth/logs/btsnoop_hci.log
```

### Parsowanie logu

```bash
python mibro_hci_parse.py btsnoop_hci.log --verbose
# → wyświetla wszystkie ramki
# → zapisuje mibro_captured_frames.json automatycznie
```

Flagi:
- `--verbose` / `-v` — drukuje każdy pakiet ATT podczas parsowania
- `--output FILE` — zapisuje pełne zdarzenia ATT do JSON

---

## 12. Rozwiązywanie problemów

### `asyncio.TimeoutError` przy połączeniu

**Przyczyna**: zegarek jest połączony z telefonem — BLE nie dopuszcza dwóch simultanicznych połączeń.

**Rozwiązanie**:
```bash
# Force-stop aplikacji Mibro Fit przez ADB
adb shell am force-stop com.xiaoxun.xunoversea.mibrofit
```
lub ręcznie: Ustawienia → Aplikacje → Mibro Fit → Wymuś zatrzymanie.

---

### `device unreachable when getting services`

**Przyczyna**: zegarek poza zasięgiem lub właśnie zmienił stan (zresetował BLE).

**Rozwiązanie**: Zbliż zegarek, upewnij się że ekran jest aktywny, spróbuj ponownie.

---

### Handshake OK ale brak danych (timeout na cmd=0x25)

**Możliwe przyczyny i rozwiązania**:

1. **Zakres dat zbyt stary** — zegarek trzyma dane tylko z ostatnich ~7 dni:
   ```bash
   python mibro_client.py --days 3  # zmniejsz zakres
   ```

2. **Brak danych zdrowotnych** — zegarek musi mieć włączone monitorowanie ciągłe w aplikacji Mibro Fit.

3. **Auth odrzucony** — zegarek ignoruje komendy po nieudanym auth:
   - Zdobyć deviceKey (patrz sekcja 10)
   - Lub sprawdzić czy fallback (challenge echo) jest akceptowany

---

### `ModuleNotFoundError: No module named 'bleak'`

```bash
# Sprawdź aktywne środowisko wirtualne
which python  # Linux/macOS
where python  # Windows

# Zainstaluj w aktywnym środowisku
pip install bleak pycryptodome
```

---

### Ramki przychodzą ale dane są śmieciem

**Sprawdź**: czy używasz właściwego kanału RX. Zegarek wysyła dane tylko na char `2CB0` (UUID `00002CB0-0000-1000-8000-00805f9b34fb`). Pomyl z `2CB1` i nic nie odbierzesz.

```python
# Weryfikacja w kodzie:
assert RX_CHAR_UUID.upper() == "00002CB0-0000-1000-8000-00805F9B34FB"
```

---

### Czas na zegarku jest błędny po synchronizacji

Synchronizacja czasu wysyła czas lokalny maszyny (bez strefy czasowej):

```python
# Jeśli zegarek pokazuje złą godzinę, sprawdź strefę:
import datetime
ts = int(datetime.datetime.now().timestamp())  # czas lokalny
# vs UTC:
ts_utc = int(datetime.datetime.utcnow().timestamp())
```

Zegarek najprawdopodobniej oczekuje czasu lokalnego (bez konwersji UTC). Jeśli wyświetla błędną strefę, sprawdź ustawienia strefy w aplikacji Mibro Fit.

---

### `struct.error: unpack requires a buffer of X bytes`

W `mibro_protocol.py` parsery sprawdzają długość, ale przy uszkodzonych danych mogą wystąpić błędy. Zawsze owijaj parsowanie w try/except:

```python
result = proto.parse_data_frame(frame["payload"])
if result is None:
    continue  # ramka uszkodzona lub nieznana
```

---

## Szybka ściągawka — komendy protokołu

```python
import mibro_protocol as proto

# Budowanie ramek:
proto.build_handshake_stage1()                           # CMD 0x01 etap 1
proto.build_handshake_stage2(auth_response)              # CMD 0x01 etap 2
proto.build_time_sync()                                  # CMD 0x02
proto.build_get_battery()                                # CMD 0x03
proto.build_get_device_info()                            # CMD 0x07
proto.build_set_since_timestamp(since_ts)                # CMD 0x25 (ustaw zakres)
proto.build_trigger_download()                           # CMD 0x30 (wyzwól pobieranie)
proto.build_frame(0x72)                                  # surowa ramka dla CMD 0x72

# Parsowanie:
proto.parse_frame(raw_bytes)                             # → {cmd, payload, raw}
proto.parse_handshake_response(payload)                  # → {serial, token_hex, challenge, mac}
proto.compute_auth_response(token_hex, challenge)        # → 16 bajtów
proto.parse_battery(payload)                             # → int (%)
proto.parse_device_info(payload)                         # → str
proto.parse_data_frame(payload)                          # → {type, records/record}

# Typy danych (dtype w cmd=0x25):
# 0x02 → "hr"          (lista HRRecord)
# 0x03 → "spo2"        (lista SpO2Record)
# 0x05 → "sleep_stage" (lista SleepStageRecord)
# 0x07 → "steps"       (StepsRecord)
# 0x09 → "hr_agg"      (lista HRAggregate)
# 0x0B → "sleep_detail" (raw hex)
# 0x00 → "end"
```
