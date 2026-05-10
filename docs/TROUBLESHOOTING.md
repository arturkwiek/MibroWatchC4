# Mibro Watch C4 — Troubleshooting

Problemy napotkane w praktyce podczas pracy z zegarkiem, połączeniem BLE i protokołem.

---

## 1. Zegarek nie pojawia się w skanie BLE

**Objaw**

```
Mibro NOT found  (13 devices visible)
```

**Przyczyna**

Zegarek jest **aktywnie połączony z telefonem** (Mibro Fit). Urządzenia BLE w trybie połączenia przestają wysyłać reklamy — stają się niewidoczne dla skanerów.

**Rozwiązanie**

Wymagane jest jedno z poniższych:

```bash
# A) Force-stop aplikacji przez ADB
adb shell am force-stop com.xiaoxun.xunoversea.mibrofit

# B) Wyłącz Bluetooth na telefonie całkowicie (zalecane — najszybsze)
# Ustawienia → Bluetooth → wyłącz

# C) Na zegarku: Ustawienia → Bluetooth → Rozłącz
```

> **Uwaga**: samo zamknięcie aplikacji przez interfejs może nie wystarczyć — system Android może utrzymywać połączenie BLE w tle. Potrzebne jest **Wymuś zatrzymanie** lub wyłączenie Bluetooth.

Po rozłączeniu zegarek pojawia się w skanie w ciągu kilku sekund.

---

## 2. `asyncio.TimeoutError` / `get_gatt_services_async` — timeout przy łączeniu

**Objaw**

```
asyncio.exceptions.CancelledError
...
asyncio.exceptions.TimeoutError
```

Wywołanie pojawia się wewnątrz `bleak.backends.winrt.client._get_services`.

**Przyczyna**

Zegarek jest sparowany z Windows, bleak nawiązuje połączenie na poziomie BLE (fizycznie), ale Windows nie może pobrać usług GATT bo:
- zegarek jest aktywnie połączony z telefonem, **LUB**
- Stos Bluetooth Windows ma nieaktualny stan po rozłączeniu

**Rozwiązanie**

```
1. Wyłącz Bluetooth na telefonie całkowicie
2. Poczekaj ~5 sekund (zegarek musi zwolnić połączenie)
3. Spróbuj ponownie
```

Jeśli problem się powtarza po poprawnym rozłączeniu telefonu:
```
# Zrestartuj adapter Bluetooth w Windows
# Menadżer urządzeń → Karty sieciowe → Bluetooth → Wyłącz → Włącz
# LUB: Ustawienia → Bluetooth → wyłącz/włącz
```

---

## 3. Handshake auth failure — zegarek rozłącza się po stage 2

**Objaw**

```
23:06:10 INFO Challenge: 7e3e632a...  Response: b55a1bb6...
23:06:18 WARNING No auth success frame — proceeding anyway
23:06:18 INFO Disconnected
...
bleak.exc.BleakError: Not connected
```

**Przyczyna**

`compute_auth_response` używa `token_hex` (wysyłanego przez zegarek) jako klucza AES. Jest to błędne założenie — `deviceKey` to **osobny klucz parowania** generowany przez serwer WkLicense (`gateway.iwhop.cn`) podczas pierwszego parowania i przechowywany w SharedPreferences aplikacji Mibro Fit.

Algorytm:
```
auth_response = AES-128-ECB(key=deviceKey, plaintext=challenge)
```

Token z zegarka (`286398A93908DE1697500A089D356400`) **nie jest** kluczem AES.

**Co dalej**

Zegarek rozłącza się ~8 s po odebraniu niepoprawnego stage 2. Dane zdrowotne są niedostępne bez prawidłowego klucza.

Sposoby pozyskania `deviceKey`:

```bash
# Opcja A: Frida (zalecana — nie wymaga roota)
pip install frida-tools
frida -U -n "com.xiaoxun.xunoversea.mibrofit" -l re/frida_capture_auth.js
# Otwórz Mibro Fit → synchronizuj zegarek → klucz pojawi się w terminalu

# Opcja B: ADB (wymaga roota lub phone backup)
adb shell run-as com.xiaoxun.xunoversea.mibrofit \
    cat /data/data/com.xiaoxun.xunoversea.mibrofit/shared_prefs/wk_device.xml

# Opcja C: mitmproxy (przechwycenie HTTPS)
pip install mitmproxy
mitmweb --listen-port 8080
# Skonfiguruj telefon na proxy 8080, zaimportuj certyfikat mitmproxy
# Synchronizuj zegarek → przechwytuje żądanie do gateway.iwhop.cn
```

Po zdobyciu klucza:

```python
# mibro/protocol.py — compute_auth_response:
DEVICE_KEY = "TWOJ_KLUCZ_HEX_32_ZNAKI"

def compute_auth_response(token_hex: str, challenge: bytes) -> bytes:
    from Crypto.Cipher import AES
    return AES.new(bytes.fromhex(DEVICE_KEY), AES.MODE_ECB).encrypt(challenge[:16])
```

---

## 4. Zegarek odpowiada bez stage 2, ale nie po błędnym stage 2

**Odkrycie z testów**

Eksperyment: po odebraniu stage 1, pominięcie stage 2 i wysłanie komendy:

```
TEST A: skip stage2, send get_battery immediately
Response: 880135000f00  ← CMD=0x35 (status push od zegarka)
```

Zegarek **nie rozłącza się** i przyjmuje zapisy BLE. Jednak komendy danych zdrowotnych (`0x25`, `0x30`) nie zwracają danych bez prawidłowego auth.

Po wysłaniu **błędnego** stage 2 zegarek rozłącza się natychmiast.

**Wniosek praktyczny**

Do odczytu danych zdrowotnych wymagana jest prawidłowa odpowiedź auth. Pominięcie stage 2 całkowicie może umożliwić podstawowe operacje (synchronizację czasu, odczyt baterii w niektórych trybach), ale pobieranie historii wymaga auth.

---

## 5. `ModuleNotFoundError: No module named 'mibro'`

**Objaw**

```python
ModuleNotFoundError: No module named 'mibro'
```

**Przyczyna**

Pakiet `mibro` nie jest zainstalowany w aktywnym środowisku Python.

**Rozwiązanie**

```bash
# Z katalogu głównego repozytorium:
pip install -e .          # core (bleak + pycryptodome)
pip install -e ".[viz]"   # + matplotlib

# Sprawdź aktywne środowisko:
where python   # Windows
which python   # Linux/macOS
```

---

## 6. Narzędzia DEX (`re/dex_*.py`) — `FileNotFoundError: mibro_apk`

**Objaw**

```
FileNotFoundError: [WinError 3] System nie może odnaleźć ścieżki: 'mibro_apk'
```

**Przyczyna**

Skrypty RE mają zakodowane ścieżki względne `mibro_apk/` i `mibro_apk/classes5.dex`. Po refaktorze katalog APK jest w `artifacts/mibro_apk/`.

**Rozwiązanie**

```bash
# Uruchom skrypty z katalogu artifacts/:
cd artifacts
python ../re/dex_auth_search.py
python ../re/dex_find_method.py
```

Lub tymczasowo zmień `DEX_DIR` na początku skryptu:
```python
DEX_DIR = "artifacts/mibro_apk"
```

---

## 7. `python -m mibro.hci_parse` nadpisuje `data/mibro_captured_frames.json`

**Objaw**

Parsowanie nowego logu HCI nadpisuje istniejący plik `data/mibro_captured_frames.json`.

**Przyczyna**

`hci_parse.py` zapisuje wynik zawsze do `mibro_captured_frames.json` (bez opcji zmiany nazwy przy wywołaniu z `--output`).

**Rozwiązanie**

```bash
# Podaj własną ścieżkę wyjściową:
python -m mibro.hci_parse artifacts/btsnoop_new.log --output data/frames_new.json

# Lub zrób kopię przed parsowaniem:
cp data/mibro_captured_frames.json data/mibro_captured_frames.backup.json
python -m mibro.hci_parse artifacts/btsnoop_hci.log
```

---

## 8. Challenge i auth response — analiza znanych wartości

Do przyszłego debugowania — znane prawidłowe wartości z HCI logu (sesja z aplikacją Mibro Fit):

| Pole | Wartość |
|------|---------|
| Serial | `AW054/00006545` |
| Token | `286398A93908DE1697500A089D356400` |
| Challenge (HCI) | `6d6d6a6464332b592a557475504b536f` |
| Auth response (HCI) | `efb3cf82c12ffe613b1d165d9fb78371` |
| Auth success frame | `88010100 00 04 00 566c...` |

Challenge zmienia się przy każdym połączeniu (generowany losowo przez zegarek, zawsze jako bajty ASCII 0x20–0x7E).

Weryfikacja klucza po jego zdobyciu:
```python
from Crypto.Cipher import AES
key = bytes.fromhex("TWOJ_KLUCZ")
challenge = bytes.fromhex("6d6d6a6464332b592a557475504b536f")
result = AES.new(key, AES.MODE_ECB).encrypt(challenge)
assert result.hex() == "efb3cf82c12ffe613b1d165d9fb78371", "Zły klucz!"
print("Klucz poprawny!")
```

---

## 9. Windows — zegarek sparowany z Windows i telefonem jednocześnie

**Kontekst**

Zegarek może być jednocześnie sparowany z Windows i telefonem, ale może utrzymywać aktywne połączenie tylko z jednym urządzeniem. Windows używa wstrzyknięcia adresu numerycznego żeby ominąć skan reklam:

```python
client._backend._device_info = int(mac.replace(":", ""), 16)
```

Jeśli ta linia rzuca `AttributeError`, bleak zmienił strukturę wewnętrzną — kod loguje ostrzeżenie i wraca do normalnego skanu. W takim przypadku zegarek musi aktywnie nadawać reklamy (telefon odłączony).

---

## Szybka lista kontrolna przed połączeniem

```
☐ Bluetooth na telefonie wyłączony (lub Mibro Fit force-stopped)
☐ Zegarek widoczny w skanie:
      python -c "import asyncio; from bleak import BleakScanner
      async def s(): devs = await BleakScanner.discover(8, return_adv=True); print('FOUND' if '10:7B:93:CE:B5:1F' in devs else f'NOT FOUND ({len(devs)} devices)')
      asyncio.run(s())"
☐ pip install -e . wykonane w aktywnym środowisku
☐ deviceKey znany (jeśli potrzebny pełny sync)
```
