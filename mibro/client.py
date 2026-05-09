"""
Mibro Watch C4 BLE client.

Usage:
    python -m mibro.client                      # connect + full sync
    python -m mibro.client --days 7             # sync last 7 days
    python -m mibro.client --mac AA:BB:CC:DD:EE:FF  # specify MAC
    python -m mibro.client --csv health.csv     # save to CSV
"""

import asyncio
import csv
import datetime
import logging
import sys
import argparse
from typing import Optional

from bleak import BleakClient, BleakScanner

from mibro import protocol as proto


def _mac_to_int(mac: str) -> int:
    addr = 0
    for b in mac.split(":"):
        addr = (addr << 8) | int(b, 16)
    return addr

log = logging.getLogger("mibro")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)

WATCH_MAC = "10:7B:93:CE:B5:1F"
SERVICE_UUID = "00001912-0000-1000-8000-00805f9b34fb"
TX_CHAR_UUID  = "00002CB1-0000-1000-8000-00805f9b34fb"  # write to watch
RX_CHAR_UUID  = "00002CB0-0000-1000-8000-00805f9b34fb"  # notify from watch

WRITE_TIMEOUT = 5.0
AUTH_TIMEOUT  = 8.0
DATA_TIMEOUT  = 30.0


class MibroClient:
    def __init__(self, mac: str = WATCH_MAC):
        self.mac = mac
        self._client: Optional[BleakClient] = None
        self._rx_queue: asyncio.Queue = asyncio.Queue()
        self._token_hex: Optional[str] = None

        # Collected health data
        self.hr_records: list[proto.HRRecord] = []
        self.spo2_records: list[proto.SpO2Record] = []
        self.sleep_records: list[proto.SleepStageRecord] = []
        self.steps: Optional[proto.StepsRecord] = None
        self.hr_agg_records: list[proto.HRAggregate] = []
        self.battery_pct: Optional[int] = None
        self.device_serial: Optional[str] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        log.info(f"Connecting to {self.mac}â€¦")
        self._client = BleakClient(self.mac)
        # On Windows, inject the numeric BT address so bleak skips BLE advertisement
        # scanning and connects directly (needed when device is already paired with Windows).
        try:
            self._client._backend._device_info = _mac_to_int(self.mac)
            log.debug("Injected numeric BT address â€” bypassing advertisement scan")
        except AttributeError:
            pass  # non-Windows backend, or bleak internals changed â€” fall back to scan
        await self._client.connect()
        log.info("Connected. Enabling notificationsâ€¦")
        await self._client.start_notify(RX_CHAR_UUID, self._on_notify)

    async def disconnect(self) -> None:
        if self._client and self._client.is_connected:
            await self._client.disconnect()
        log.info("Disconnected")

    def _on_notify(self, _sender, data: bytearray) -> None:
        self._rx_queue.put_nowait(bytes(data))

    async def _write(self, frame: bytes) -> None:
        await self._client.write_gatt_char(TX_CHAR_UUID, frame, response=False)

    async def _recv(self, timeout: float = WRITE_TIMEOUT) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self._rx_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def _drain(self, timeout: float = 0.5) -> list[bytes]:
        """Collect all pending notifications with a short timeout."""
        frames = []
        while True:
            f = await self._recv(timeout)
            if f is None:
                break
            frames.append(f)
        return frames

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    async def handshake(self) -> bool:
        """Two-step auth handshake. Returns True on success."""
        log.info("Starting handshakeâ€¦")

        # Stage 1: request challenge
        await self._write(proto.build_handshake_stage1())

        # Collect responses; some status frames arrive before the auth frame
        hs_payload = None
        deadline = asyncio.get_event_loop().time() + AUTH_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            raw = await self._recv(timeout=AUTH_TIMEOUT)
            if raw is None:
                break
            frame = proto.parse_frame(raw)
            if frame and frame["cmd"] == 0x01 and frame["payload"][:1] == b"\x01":
                hs_payload = frame["payload"]
                break
            log.debug(f"Skipping non-auth frame: {raw.hex()}")

        if hs_payload is None:
            log.error("No handshake response received")
            return False

        parsed = proto.parse_handshake_response(hs_payload)
        if parsed is None:
            log.error(f"Cannot parse handshake payload: {hs_payload.hex()}")
            return False

        self._token_hex = parsed["token_hex"]
        self.device_serial = parsed["serial"]
        log.info(f"Serial: {parsed['serial']}  Token: {parsed['token_hex']}  MAC: {parsed['mac']}")

        # Stage 2: send auth response
        auth_resp = proto.compute_auth_response(parsed["token_hex"], parsed["challenge"])
        log.info(f"Challenge: {parsed['challenge'].hex()}  Response: {auth_resp.hex()}")
        await self._write(proto.build_handshake_stage2(auth_resp))

        # Wait for auth success (cmd=0x01, payload[0]=0x00)
        deadline2 = asyncio.get_event_loop().time() + AUTH_TIMEOUT
        while asyncio.get_event_loop().time() < deadline2:
            raw = await self._recv(timeout=AUTH_TIMEOUT)
            if raw is None:
                break
            frame = proto.parse_frame(raw)
            if frame and frame["cmd"] == 0x01 and frame["payload"][:1] == b"\x00":
                log.info("Auth SUCCESS")
                return True
            log.debug(f"Post-auth frame: {raw.hex()}")

        log.warning("No auth success frame â€” proceeding anyway (watch may not verify)")
        return True

    # ------------------------------------------------------------------
    # Basic device operations
    # ------------------------------------------------------------------

    async def get_device_info(self) -> Optional[str]:
        await self._write(proto.build_get_device_info())
        for _ in range(5):
            raw = await self._recv()
            if raw is None:
                break
            f = proto.parse_frame(raw)
            if f and f["cmd"] == 0x07 and f["payload"]:
                self.device_serial = proto.parse_device_info(f["payload"])
                return self.device_serial
        return None

    async def sync_time(self) -> None:
        await self._write(proto.build_time_sync())
        await self._drain(timeout=1.0)

    async def get_battery(self) -> Optional[int]:
        await self._write(proto.build_frame(0x72))  # seen before battery request in capture
        await self._write(proto.build_get_battery())
        for _ in range(10):
            raw = await self._recv()
            if raw is None:
                break
            f = proto.parse_frame(raw)
            if f and f["cmd"] == 0x03:
                self.battery_pct = proto.parse_battery(f["payload"])
                return self.battery_pct
        return None

    # ------------------------------------------------------------------
    # Health data download
    # ------------------------------------------------------------------

    async def download_health_data(self, since_days: int = 7) -> None:
        since_ts = int(
            (datetime.datetime.now() - datetime.timedelta(days=since_days)).timestamp()
        )
        log.info(f"Downloading data since {datetime.datetime.fromtimestamp(since_ts)} ({since_days} days)â€¦")

        await self._write(proto.build_set_since_timestamp(since_ts))
        await self._write(proto.build_trigger_download())

        deadline = asyncio.get_event_loop().time() + DATA_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            raw = await self._recv(timeout=DATA_TIMEOUT)
            if raw is None:
                log.warning("Data stream timed out")
                break

            frame = proto.parse_frame(raw)
            if not frame:
                continue

            if frame["cmd"] != 0x25:
                log.debug(f"Non-data frame during download: cmd={frame['cmd']:02X}")
                continue

            result = proto.parse_data_frame(frame["payload"])
            if result is None:
                continue

            dtype = result["type"]
            if dtype == "end":
                log.info("Data download complete")
                break
            elif dtype == "hr":
                self.hr_records.extend(result["records"])
                log.info(f"  HR: +{len(result['records'])} records (total {len(self.hr_records)})")
            elif dtype == "spo2":
                self.spo2_records.extend(result["records"])
                log.info(f"  SpO2: +{len(result['records'])} records")
            elif dtype == "sleep_stage":
                self.sleep_records.extend(result["records"])
                log.info(f"  Sleep: +{len(result['records'])} stages")
            elif dtype == "steps":
                self.steps = result["record"]
                if self.steps:
                    log.info(f"  Steps: {self.steps.steps} steps, {self.steps.calories} cal, {self.steps.distance_m}m")
            elif dtype == "hr_agg":
                self.hr_agg_records.extend(result["records"])
                log.info(f"  HR-agg: +{len(result['records'])} records")
            elif dtype == "sleep_detail":
                log.debug(f"  Sleep detail raw: {result['raw'][:40]}â€¦")
            else:
                log.debug(f"  Unknown frame type: {dtype}")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_csv(self, path: str) -> None:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["type", "datetime", "value", "unit", "extra"])

            for r in sorted(self.hr_records, key=lambda x: x.timestamp):
                w.writerow(["hr", r.dt.isoformat(), r.bpm, "bpm", ""])

            for r in sorted(self.spo2_records, key=lambda x: x.timestamp):
                w.writerow(["spo2", r.dt.isoformat(), r.spo2, "%", ""])

            for r in sorted(self.sleep_records, key=lambda x: x.timestamp):
                w.writerow(["sleep", r.dt.isoformat(), r.stage_name, "stage",
                             f"dur={r.duration_min}min"])

            for r in sorted(self.hr_agg_records, key=lambda x: x.timestamp):
                w.writerow(["hr_agg", r.dt.isoformat(), r.value, "bpm_agg", ""])

            if self.steps:
                w.writerow(["steps", datetime.datetime.now().isoformat(),
                             self.steps.steps, "steps",
                             f"cal={self.steps.calories} dist={self.steps.distance_m}m"])

        log.info(f"Saved {path}")

    def print_summary(self) -> None:
        print(f"\n{'='*50}")
        print(f"Mibro Watch C4  |  {self.mac}")
        if self.device_serial:
            print(f"Serial: {self.device_serial}")
        if self.battery_pct is not None:
            print(f"Battery: {self.battery_pct}%")
        print(f"\nHR records:        {len(self.hr_records)}")
        if self.hr_records:
            bpms = [r.bpm for r in self.hr_records]
            print(f"  avg={sum(bpms)//len(bpms)} min={min(bpms)} max={max(bpms)} bpm")
        print(f"SpO2 records:      {len(self.spo2_records)}")
        if self.spo2_records:
            vals = [r.spo2 for r in self.spo2_records]
            print(f"  avg={sum(vals)//len(vals)}% min={min(vals)}% max={max(vals)}%")
        print(f"Sleep stage recs:  {len(self.sleep_records)}")
        print(f"HR aggregate recs: {len(self.hr_agg_records)}")
        if self.steps:
            print(f"Steps today:       {self.steps.steps} ({self.steps.calories} cal, {self.steps.distance_m}m)")
        print(f"{'='*50}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

async def _run(mac: str, days: int, csv_path: Optional[str]) -> None:
    client = MibroClient(mac=mac)
    try:
        await client.connect()
        ok = await client.handshake()
        if not ok:
            log.error("Handshake failed â€” aborting")
            return

        await client.get_device_info()
        await client.sync_time()
        await client.get_battery()
        await client.download_health_data(since_days=days)
        client.print_summary()

        if csv_path:
            client.export_csv(csv_path)

    finally:
        await client.disconnect()


def main() -> None:
    p = argparse.ArgumentParser(description="Mibro Watch C4 BLE health data reader")
    p.add_argument("--mac", default=WATCH_MAC, help="Watch BLE MAC address")
    p.add_argument("--days", type=int, default=7, help="Days of history to download")
    p.add_argument("--csv", default=None, help="Export to CSV file")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = p.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    asyncio.run(_run(args.mac, args.days, args.csv))


if __name__ == "__main__":
    main()

