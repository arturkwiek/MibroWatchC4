# Mibro Watch C4 — BLE Data Reader

Python library and tools for reading health data from **Mibro Watch C4** over BLE.  
Protocol reverse-engineered from HCI snoop logs and APK analysis.

## Quick start

```bash
pip install bleak pycryptodome matplotlib

# Live sync (disconnect watch from phone first)
python -m mibro.client --mac 10:7B:93:CE:B5:1F --days 7 --csv data/health.csv

# Export from captured frames (no BLE needed)
python tools/export_health.py --json data/mibro_captured_frames.json

# Visualize
python tools/plot_health.py
```

## Repository layout

```
mibro/          BLE protocol library (import as package)
  protocol.py     Frame builder and data parsers
  client.py       Async BLE client (bleak)
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
  mibro_re.py         Early protocol prober
  mibro_serial_auth.py  Serial auth analysis
  frida_capture_auth.js  Frida hooks for auth key capture

docs/           Documentation
  PROTOCOL.md              Wire-level protocol reference
  DEVELOPER_GUIDE.md       Getting started guide
  HISTORICAL_DATA_GUIDE.md Deep-dive on health data download

data/           Captured data and logs (partially gitignored)
  mibro_captured_frames.json  HCI frames ready to parse

artifacts/      Large binary files — gitignored
  btsnoop_hci.log, mibro_base.apk, libwk_license.so, …
```

## Documentation

- [Protocol reference](docs/PROTOCOL.md)
- [Developer guide](docs/DEVELOPER_GUIDE.md)
- [Historical data guide](docs/HISTORICAL_DATA_GUIDE.md)

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

## Device

| Parameter | Value |
|-----------|-------|
| Model | Mibro Watch C4 |
| Chip | SIFLI Technology |
| MAC | `10:7B:93:CE:B5:1F` |
| BLE Service | `1912` |
| TX (host→watch) | `2CB1` |
| RX (watch→host) | `2CB0` |
