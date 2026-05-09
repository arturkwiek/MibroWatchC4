# Mibro Watch C4 — BLE Data Reader

Python library and CLI tools for reading health data from **Mibro Watch C4** over BLE.  
Protocol reverse-engineered from Android HCI snoop logs and APK analysis.

## Features

- Full BLE sync: HR, SpO2, sleep stages, steps, battery, device info
- Offline export from captured HCI frames (no watch needed)
- CSV export and matplotlib visualization (hypnogram + HR chart)
- BTSnoop HCI log parser for RE work
- Tkinter GUI for BLE scanning and exploration

## Installation

```bash
git clone <repo>
cd BLE_services

# Core (BLE sync + export)
pip install -e .

# With visualization support
pip install -e ".[viz]"
```

## Quick start

```bash
# Live sync — disconnect watch from phone first
python -m mibro.client --mac 10:7B:93:CE:B5:1F --days 7 --csv data/health.csv

# Export from captured HCI frames (no BLE needed)
python tools/export_health.py --json data/mibro_captured_frames.json

# Visualize
python tools/plot_health.py

# Parse a new BTSnoop HCI log
python -m mibro.hci_parse artifacts/btsnoop_hci.log
```

## Library usage

```python
import asyncio
from mibro.client import MibroClient

async def main():
    client = MibroClient(mac="10:7B:93:CE:B5:1F")
    await client.connect()
    await client.handshake()
    await client.download_health_data(since_days=7)
    client.print_summary()
    client.export_csv("data/health.csv")
    await client.disconnect()

asyncio.run(main())
```

## Health data types

| Type | Records | Fields |
|------|---------|--------|
| HR | per ~5 min | `timestamp`, `bpm` |
| SpO2 | per measurement | `timestamp`, `spo2` (%) |
| Sleep stages | per phase | `timestamp`, `stage` (Awake/Light/Deep/REM), `duration_min` |
| Steps | daily total | `steps`, `calories`, `distance_m` |
| HR aggregate | periodic | `timestamp`, `value` |

## Repository layout

```
mibro/          BLE protocol library (importable package)
  protocol.py     Frame builder, data parsers, dataclasses
  client.py       Async BLE client (bleak), CLI entry point
  hci_parse.py    BTSnoop HCI log parser
  bluetooth_uuids.py  Bluetooth SIG UUID lookup

tools/          Command-line tools
  export_health.py    Export health data from captured JSON → CSV
  plot_health.py      Hypnogram + HR chart (matplotlib)
  ble_scanner.py      General BLE scanner / service explorer
  adv_scan.py         BLE advertisement scanner

gui/            Desktop application
  ble_desktop_gui.py  Tkinter GUI for BLE scanning and exploration

re/             Reverse engineering scripts (APK/DEX/native analysis)
  dex_*.py            DEX bytecode analysis tools
  frida_capture_auth.js  Frida hooks for auth key capture

docs/           Documentation
  PROTOCOL.md              Wire-level protocol reference
  DEVELOPER_GUIDE.md       Developer guide with code examples
  HISTORICAL_DATA_GUIDE.md Deep-dive on health data download

data/           Captured data (partially gitignored)
  mibro_captured_frames.json  HCI frames ready to parse

artifacts/      Large binary files — gitignored
  btsnoop_hci.log, mibro_base.apk, libwk_license.so, …
```

## Documentation

- [Protocol reference](docs/PROTOCOL.md) — wire-level frame format, commands, data types
- [Developer guide](docs/DEVELOPER_GUIDE.md) — getting started, code examples, troubleshooting
- [Historical data guide](docs/HISTORICAL_DATA_GUIDE.md) — deep-dive on health data download

## Device

| Parameter | Value |
|-----------|-------|
| Model | Mibro Watch C4 |
| Chip | SIFLI Technology (Company ID `0x0A4C`) |
| MAC | `10:7B:93:CE:B5:1F` |
| BLE Service | `00001912-0000-1000-8000-00805f9b34fb` |
| TX (host→watch) | `00002CB1-0000-1000-8000-00805f9b34fb` |
| RX (watch→host) | `00002CB0-0000-1000-8000-00805f9b34fb` |
| Frame header | `88 01 CMD 00` (no CRC) |

## Known limitations

- **Auth key**: The challenge-response handshake uses `AES-128-ECB(deviceKey, challenge)` where `deviceKey` is a per-pairing secret stored in the Mibro Fit app's SharedPreferences. In practice the watch appears to respond to commands even with an incorrect auth response. If strict auth is required, extract the key via Frida (`re/frida_capture_auth.js`) or ADB from a rooted device.
- **Sleep detail** (dtype `0x0B`): raw binary format not fully decoded.
- **Windows BLE**: requires the watch to be paired with Windows first. The client injects the numeric BT address to bypass advertisement scanning.
