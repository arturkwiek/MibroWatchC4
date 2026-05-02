"""CLI BLE scanner and service explorer.

Flow:
1) Scan nearby BLE devices.
2) Let the user choose one device.
3) Connect and print services/characteristics/descriptors with SIG names.
"""

import asyncio
import argparse
import sys
from typing import Optional

from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from bluetooth_sig_uuids import lookup_service, lookup_characteristic, lookup_descriptor

# ── Terminal colour helpers ───────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"


def _c(text: str, *codes: str) -> str:
    """Wrap text in ANSI escape codes (no-op on Windows without VT enabled)."""
    return "".join(codes) + text + RESET


# ── Scanning ──────────────────────────────────────────────────────────────────

async def scan_devices(timeout: float = 10.0) -> list[tuple[BLEDevice, AdvertisementData]]:
    """Return a list of (device, advertisement_data) found during *timeout* seconds."""
    # This is the same discovery primitive used by the GUI worker.
    print(_c(f"\nScanning for BLE devices ({timeout:.0f}s)…", CYAN, BOLD))
    results = await BleakScanner.discover(timeout=timeout, return_adv=True)
    # results is a dict {address: (device, adv_data)}
    devices = sorted(results.values(), key=lambda p: p[1].rssi or -999, reverse=True)
    return devices


def print_device_list(devices: list[tuple[BLEDevice, AdvertisementData]]) -> None:
    if not devices:
        print(_c("  No devices found.", RED))
        return
    print()
    print(_c(f"  {'#':>3}  {'Name':<32}  {'Address':<20}  {'RSSI':>6}", BOLD))
    print("  " + "─" * 70)
    for i, (dev, adv) in enumerate(devices, start=1):
        name = dev.name or _c("(unknown)", DIM)
        rssi = adv.rssi if adv.rssi is not None else "?"
        print(f"  {i:>3}  {name:<32}  {dev.address:<20}  {rssi:>6}")


def select_device(devices: list[tuple[BLEDevice, AdvertisementData]]) -> Optional[BLEDevice]:
    if not devices:
        return None
    while True:
        try:
            raw = input(_c("\nEnter device number (or 0 to rescan, q to quit): ", YELLOW))
        except (EOFError, KeyboardInterrupt):
            return None
        if raw.strip().lower() == "q":
            return None
        try:
            choice = int(raw.strip())
        except ValueError:
            print(_c("  Please enter a valid number.", RED))
            continue
        if choice == 0:
            return "RESCAN"  # type: ignore[return-value]
        if 1 <= choice <= len(devices):
            return devices[choice - 1][0]
        print(_c(f"  Number must be between 1 and {len(devices)}.", RED))


# ── Service / Characteristic display ─────────────────────────────────────────

def _uuid_display(uuid: str) -> str:
    """Return a coloured UUID string with its standard name (if known)."""
    uuid_l = uuid.lower()
    name = lookup_service(uuid_l) or lookup_characteristic(uuid_l) or lookup_descriptor(uuid_l)
    if name:
        return f"{_c(uuid, CYAN)}  →  {_c(name, GREEN)}"
    return _c(uuid, CYAN)


def _char_props(props) -> str:
    """Return a human-readable string for characteristic properties."""
    flags = []
    if "read"             in props: flags.append("Read")
    if "write"            in props: flags.append("Write")
    if "write-without-response" in props: flags.append("WriteNoResp")
    if "notify"           in props: flags.append("Notify")
    if "indicate"         in props: flags.append("Indicate")
    if "broadcast"        in props: flags.append("Broadcast")
    return ", ".join(flags) if flags else str(props)


async def explore_device(device: BLEDevice, show_characteristics: bool = True) -> None:
    # Pretty-printer for the GATT tree, intended for terminal troubleshooting.
    print()
    print(_c(f"Connecting to: {device.name or device.address} …", CYAN, BOLD))

    try:
        async with BleakClient(device) as client:
            if not client.is_connected:
                print(_c("  Connection failed.", RED))
                return

            print(_c(f"Connected  ✓  ({device.address})\n", GREEN, BOLD))
            services = client.services

            if not services:
                print(_c("  No services found on this device.", YELLOW))
                return

            service_list = list(services)
            print(_c(f"  Found {len(service_list)} service(s):\n", BOLD))

            for svc in service_list:
                svc_name = lookup_service(svc.uuid) or _c("(vendor-specific / unknown)", DIM)
                short_uuid = svc.uuid.upper()
                print(f"  {_c('SERVICE', BOLD)}  {_c(short_uuid, CYAN)}")
                print(f"           Name  : {_c(svc_name, GREEN) if lookup_service(svc.uuid) else svc_name}")
                print(f"           Handle: {svc.handle}")

                if show_characteristics:
                    chars = svc.characteristics
                    if chars:
                        for char in chars:
                            char_name = lookup_characteristic(char.uuid) or _c("(unknown)", DIM)
                            props_str = _char_props(char.properties)
                            print(f"    {_c('├─ CHAR', DIM)}  {_c(char.uuid.upper(), CYAN)}")
                            print(f"    {_c('│', DIM)}        Name      : "
                                  f"{_c(char_name, YELLOW) if lookup_characteristic(char.uuid) else char_name}")
                            print(f"    {_c('│', DIM)}        Properties: {props_str}")

                            for desc in char.descriptors:
                                desc_name = lookup_descriptor(desc.uuid) or _c("(unknown)", DIM)
                                print(f"    {_c('│  └─ DESC', DIM)}  {_c(desc.uuid.upper(), CYAN)}")
                                print(f"    {_c('│           ', DIM)}  Name: "
                                      f"{_c(desc_name, YELLOW) if lookup_descriptor(desc.uuid) else desc_name}")
                print()

    except Exception as exc:  # noqa: BLE001
        print(_c(f"  Error: {exc}", RED))


# ── Entry point ───────────────────────────────────────────────────────────────

async def main(timeout: float, show_characteristics: bool) -> None:
    # The CLI loop intentionally stays simple and linear for easy debugging.
    # Enable ANSI codes on Windows
    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    while True:
        devices = await scan_devices(timeout)
        print_device_list(devices)

        selected = select_device(devices)
        if selected is None:
            print("Bye.")
            break
        if selected == "RESCAN":  # type: ignore[comparison-overlap]
            continue

        await explore_device(selected, show_characteristics=show_characteristics)

        try:
            again = input(_c("Explore another device? [y/N]: ", YELLOW)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if again != "y":
            break


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="BLE Service Explorer – scan, connect, and list GATT services."
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="BLE scan duration in seconds (default: 10)",
    )
    parser.add_argument(
        "--services-only", "-s",
        action="store_true",
        help="Show services only, skip characteristics and descriptors",
    )
    args = parser.parse_args()
    asyncio.run(main(args.timeout, show_characteristics=not args.services_only))


if __name__ == "__main__":
    cli()
