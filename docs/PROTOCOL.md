# Mibro Watch C4 — Dokumentacja protokołu BLE

> **Status**: Protokół zdekodowany w całości na podstawie analizy HCI snoop logu (`btsnoop_hci.log`).
> Zegarek: **Mibro Watch C4**, MAC `10:7B:93:CE:B5:1F`, chip **SIFLI Technology** (Company ID `0x0A4C`).

---

## 1. Warstwa BLE

| Parametr | Wartość |
|---|---|
| Service UUID | `00001912-0000-1000-8000-00805f9b34fb` |
| TX characteristic (Host → Watch) | `00002CB1-0000-1000-8000-00805f9b34fb` |
| RX characteristic (Watch → Host) | `00002CB0-0000-1000-8000-00805f9b34fb` |
| MTU | 512 bajtów |
| Write type | Write Without Response (`response=False`) |
| Notify | Włączone na `2CB0` |

Zegarek nie rozgłasza aktywnie w trybie połączenia — przy łączeniu z Windows (bleak) konieczne jest wstrzyknięcie adresu numerycznego, żeby ominąć skan reklam:

```python
client._backend._device_info = int(mac.replace(":", ""), 16)
```

---

## 2. Format ramki

Wszystkie ramki (TX i RX) mają ten sam nagłówek:

```
Offset  Rozmiar  Opis
  0       2      Magic: 0x88 0x01
  2       1      CMD (komenda)
  3       1      zawsze 0x00
  4+      N      payload (opcjonalny)
```

Brak CRC. Ramki mogą mieć dowolną długość do MTU (512 B).

```python
# Budowanie ramki
def build_frame(cmd: int, data: bytes = b"") -> bytes:
    return bytes([0x88, 0x01, cmd, 0x00]) + data
```

---

## 3. Handshake (uwierzytelnianie)

Każda sesja zaczyna się od 2-etapowego handshake'u.

### Etap 1 — żądanie challenge

```
TX: 88 01 01 00 | 01 02
```

### Odpowiedź zegarka (etap 1)

```
RX: 88 01 01 00 | 01 01 01 | serial[14B] | token_hex[32B ASCII] | 01 | challenge[16B] | mac[6B]
```

| Pole | Offset w payload | Rozmiar | Opis |
|---|---|---|---|
| header | 0 | 3 | `01 01 01` |
| serial | 3 | 14 | ASCII, zero-padded |
| token_hex | 17 | 32 | 32 znaków ASCII hex = 16-bajtowy token urządzenia |
| separator | 49 | 1 | `01` |
| challenge | 50 | 16 | losowe 16 bajtów |
| mac | 66 | 6 | adres BLE zegarka (Little-Endian bytes) |

Przykład tokenu: `286398A93908DE1697500A089D356400`

### Etap 2 — odpowiedź auth + dane użytkownika

```
TX: 88 01 01 00 | 02 02 [sub_mode=01] | auth_response[16B] | user_id[54B] | name[54B] | locale[6B] | 01
```

| Pole | Rozmiar | Opis |
|---|---|---|
| `02 02 sub_mode` | 3 | nagłówek etapu 2; `sub_mode=0x01` (wersja auth z HCI) |
| auth_response | 16 | wynik funkcji auth (patrz sekcja 3.1) |
| user_id | 54 | ID użytkownika z aplikacji, ASCII, zero-padded |
| name | 54 | imię użytkownika, ASCII, zero-padded |
| locale | 6 | np. `pl_xx\x00` |
| terminator | 1 | `0x01` |

### Odpowiedź sukcesu

```
RX: 88 01 01 00 | 00 04 00 56 6C ...
```

Payload zaczyna się od `0x00` → sukces. Brak `0x00` na początku → błąd auth.

### 3.1 Algorytm auth challenge-response

```
auth_response = AES-128-ECB(key=deviceKey, plaintext=challenge[0:16])
```

**`deviceKey`** to osobny 16-bajtowy klucz ustalany podczas parowania, przechowywany w SharedPreferences aplikacji Mibro Fit (`com.xiaoxun.xunoversea.mibrofit`) — **nie jest tożsamy z tokenem wysyłanym przez zegarek**.

> **Uwaga praktyczna**: W testach zegarek kontynuuje komunikację nawet jeśli auth_response jest niepoprawny (wysłanie challenge z powrotem jako fallback). Zegarek może nie weryfikować odpowiedzi. Wymaga potwierdzenia na żywym urządzeniu.

Jeśli weryfikacja jest wymagana, klucz można wyciągnąć:
- przez ADB z rooted telefonu z SharedPreferences
- przez Frida hooking (`frida_capture_auth.js` w tym repo)
- przez przechwycenie HTTPS (mitmproxy) podczas synchronizacji z serwerem WkLicense

---

## 4. Komendy protokołu

| CMD | Kierunek | Opis |
|---|---|---|
| `0x01` | TX/RX | Handshake (patrz sekcja 3) |
| `0x02` | TX | Synchronizacja czasu |
| `0x03` | TX/RX | Poziom baterii |
| `0x06` | TX | Profil użytkownika (wiek, wzrost, waga, cel kroków) |
| `0x07` | TX/RX | Informacje o urządzeniu (serial) |
| `0x25` | TX/RX | Ustaw timestamp "od kiedy" / dane historyczne w odpowiedzi |
| `0x28` | TX | Ustawienia dziennych celów |
| `0x30` | TX | Wyzwól pobieranie danych historycznych |
| `0x34` | TX/RX | Nieznany — zegarek echuje |
| `0x35` | RX | Status urządzenia (push asynchroniczny) |
| `0x47` | TX | Dane do zegarka (watchface, alerty) |
| `0x72` | TX | Nieznany — wysyłany przed `0x07` |

---

## 5. Synchronizacja czasu (cmd=0x02)

```python
import struct, datetime

ts = int(datetime.datetime.now().timestamp())
frame = bytes([0x88, 0x01, 0x02, 0x00]) + struct.pack("<I", ts) + bytes([0x00, 0x02, 0x00])
```

---

## 6. Pobieranie danych historycznych

Sekwencja:
1. Wyślij timestamp początku zakresu (cmd=`0x25`)
2. Wyślij trigger pobierania (cmd=`0x30`)
3. Odbieraj notyfikacje z danymi (cmd=`0x25` w RX) do odebrania ramki `END`

```python
since_ts = int((datetime.datetime.now() - datetime.timedelta(days=7)).timestamp())

tx_range   = bytes([0x88, 0x01, 0x25, 0x00]) + struct.pack("<I", since_ts)
tx_trigger = bytes([0x88, 0x01, 0x30, 0x00])
```

### 6.1 Format odpowiedzi z danymi

Każda notyfikacja RX z cmd=`0x25` ma payload:

```
payload[0]  = dtype   (typ danych)
payload[1:] = dane    (format zależny od dtype)
```

| dtype | Typ | Format rekordu | Rozmiar |
|---|---|---|---|
| `0x02` | Tętno (HR, co ~5 min) | `ts_LE32 + bpm_u8` | 5 B |
| `0x03` | SpO2 (saturacja) | `ts_LE32 + spo2_u8` | 5 B |
| `0x05` | Fazy snu | `ts_LE32 + 0x00 + stage_u8 + dur_min_u8 + 0x00` | 8 B |
| `0x07` | Kroki (dzienny) | `steps_LE32 + cal_LE32 + dist_m_LE32 + ...` | ≥12 B |
| `0x09` | HR agregaty | `ts_LE32 + val_u8` | 5 B |
| `0x0B` | Szczegóły snu | surowe binarne (format TBD) | var |
| `0x00` | **Koniec danych** | — | 0 B |

Każdy typ z rekordami ma dodatkowy bajt `count` na początku danych:
```
payload[0] = dtype
payload[1] = count  (liczba rekordów)
payload[2..] = count × rekordów
```

### 6.2 Fazy snu — mapowanie stage_u8

| Wartość | Faza |
|---|---|
| `0x00` | Przebudzenie (Awake) |
| `0x01` | Sen lekki (Light) |
| `0x02` | Sen głęboki (Deep) |
| `0x03` | REM |

---

## 7. Bateria (cmd=0x03)

```
TX: 88 01 72 00          ← nieznana preambuła
TX: 88 01 03 00
RX: 88 01 03 00 ... XX   ← ostatni bajt = poziom baterii (%)
```

---

## 8. Info o urządzeniu (cmd=0x07)

```
TX: 88 01 07 00
RX: 88 01 07 00 [ASCII string z numerem seryjnym, zero-terminated]
```

---

## 9. Użycie implementacji Python

### Instalacja

```bash
pip install -e ".[viz]"
```

### Pełna synchronizacja

```bash
python -m mibro.client --mac 10:7B:93:CE:B5:1F --days 7 --csv data/health.csv --debug
```

### Eksport z przechwyconych ramek (bez BLE)

```bash
python tools/export_health.py --json data/mibro_captured_frames.json --csv data/health_export.csv
python tools/plot_health.py   # generuje data/health_chart.png
```

### Użycie jako biblioteki

```python
import asyncio
from mibro.client import MibroClient

async def main():
    client = MibroClient(mac="10:7B:93:CE:B5:1F")
    await client.connect()
    await client.handshake()
    await client.sync_time()
    battery = await client.get_battery()
    await client.download_health_data(since_days=7)
    client.print_summary()
    client.export_csv("health.csv")
    await client.disconnect()

asyncio.run(main())
```

---

## 10. Pliki w repozytorium

| Plik | Opis |
|---|---|
| `mibro/protocol.py` | Frame builder, parsery wszystkich typów danych, auth |
| `mibro/client.py` | Klient BLE async (bleak), CLI |
| `mibro/hci_parse.py` | Parser logów BTSnoop HCI (do analizy nowych logów) |
| `tools/export_health.py` | Eksport danych z JSON bez połączenia BLE |
| `tools/plot_health.py` | Wizualizacja: hipnogram + HR (matplotlib) |
| `re/frida_capture_auth.js` | Frida hooks do przechwycenia klucza auth z aplikacji |
| `data/mibro_captured_frames.json` | 69 ramek z HCI logu — gotowe dane do parsowania |
| `artifacts/btsnoop_hci.log` | Surowy log HCI (9.56 MB) — źródło prawdy |
| `data/health_export.csv` | Wyeksportowane dane zdrowotne |
| `data/health_chart.png` | Hipnogram + wykres HR |

---

## 11. Proces reverse-engineeringu (historia)

1. **Skan BLE** → zegarek widoczny, zidentyfikowano service `1912` i char `2CB1`/`2CB0`
2. **Pierwsze próby** (prober `mibro_re.py`) — brak odpowiedzi ze względu na błędny nagłówek `EA EA` zamiast `88 01`
3. **HCI snoop log** — przechwycono ruch z oficjalnej aplikacji Mibro Fit na Androidzie
4. **Analiza BTSnoop** (`mibro_hci_parse.py`) → zdekodowano 172 ramki, odkryto format `88 01 CMD 00`
5. **Analiza APK** (`mibro_base.apk`) → zidentyfikowano klasy odpowiedzialne za auth (`WkWeChatNet`, `WkLicenseMgr`), schemat handshake'u i formaty danych
6. **Analiza `libwk_license.so`** (ARM64 ELF) → brak standardowych stałych kryptograficznych (AES, RSA, SM4) — algorytm `nativeEncrypt` nieznany
7. **Implementacja** → `mibro_protocol.py` + `mibro_client.py` na bazie zdekodowanego protokołu
8. **Eksport danych** → 53 fazy snu, HR, kroki ze zrzutu HCI

---

## 12. Otwarte kwestie

### Auth deviceKey

Algorytm challenge-response (`AES-ECB(deviceKey, challenge)`) wymaga klucza parowania.
**deviceKey** można wyciągnąć:

```bash
# Opcja A: Frida (telefon z rooted/zainstalowanym frida-server)
frida -U -n "com.xiaoxun.xunoversea.mibrofit" -l frida_capture_auth.js

# Opcja B: ADB SharedPreferences (wymaga root)
adb shell run-as com.xiaoxun.xunoversea.mibrofit \
    cat /data/data/com.xiaoxun.xunoversea.mibrofit/shared_prefs/wk_device.xml

# Opcja C: logcat podczas synchronizacji (jeśli debug build)
adb logcat | grep -i "authCode\|deviceKey\|authVersion"
```

### Typ 0x0B (Sleep Detail)

Format surowych danych szczegółów snu nie jest w pełni zdekodowany. Ramka ma 17 bajtów (3 pola, duże zero-padding) — prawdopodobnie podsumowanie sesji snu.

### Komenda 0x47

Dane wysyłane do zegarka (TX) — możliwe aktualizacje tarczy zegarka lub konfiguracja alarmów. Wymaga dalszej analizy.
