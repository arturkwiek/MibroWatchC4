"""
Mibro Watch C4 BLE protocol implementation.
Frame format: [88 01 CMD 00 DATA...]
Service UUID: 1912  TX→watch: 2CB1  RX←watch: 2CB0
"""

import struct
import datetime
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Frame builder
# ---------------------------------------------------------------------------

FRAME_MAGIC = bytes([0x88, 0x01])


def build_frame(cmd: int, data: bytes = b"") -> bytes:
    return FRAME_MAGIC + bytes([cmd, 0x00]) + data


def parse_frame(raw: bytes) -> Optional[dict]:
    if len(raw) < 4 or raw[:2] != FRAME_MAGIC:
        return None
    cmd = raw[2]
    payload = raw[4:]
    return {"cmd": cmd, "payload": payload, "raw": raw}


# ---------------------------------------------------------------------------
# Authentication (handshake cmd=0x01)
# ---------------------------------------------------------------------------

def build_handshake_stage1() -> bytes:
    """Step 1: request challenge from watch."""
    return build_frame(0x01, bytes([0x01, 0x02]))


def compute_auth_response(token_hex: str, challenge: bytes) -> bytes:
    """
    Compute 16-byte auth response for the challenge.

    The algorithm is: AES-128-ECB(key=bytes.fromhex(token_hex), plaintext=challenge).
    The stored deviceKey in the Mibro app is set during pairing; we assume the token
    is the key. If authentication fails, use extract_device_key() via ADB to get the
    real key from the app's SharedPreferences.
    """
    try:
        from Crypto.Cipher import AES
        key = bytes.fromhex(token_hex)
        return AES.new(key, AES.MODE_ECB).encrypt(challenge[:16])
    except Exception as e:
        log.warning(f"AES auth failed: {e} — sending challenge back as fallback")
        return challenge[:16]


def parse_handshake_response(payload: bytes) -> Optional[dict]:
    """
    Parse stage-1 watch response.
    Format: [01 01 01] [serial_14B] [token_32B_ascii_hex] [01] [challenge_16B] [mac_6B]
    """
    if len(payload) < 3 + 14 + 32 + 1 + 16 + 6:
        return None
    try:
        serial = payload[3:17].decode("ascii", errors="replace").rstrip("\x00")
        token_hex = payload[17:49].decode("ascii", errors="replace")
        challenge = payload[50:66]
        mac_bytes = payload[66:72]
        mac = ":".join(f"{b:02X}" for b in mac_bytes)
        return {
            "serial": serial,
            "token_hex": token_hex,
            "challenge": challenge,
            "mac": mac,
        }
    except Exception as e:
        log.warning(f"Failed to parse handshake response: {e}")
        return None


def build_handshake_stage2(
    auth_response: bytes,
    user_id: str = "407197",
    name: str = "Artur",
    locale: str = "pl_xx",
    sub_mode: int = 0x01,
) -> bytes:
    """
    Step 2: send auth response + user info.
    Exact layout from HCI capture: 88 01 01 00 [02 02 sub_mode] [auth_16B] [uid_54B] [name_54B] [locale_6B] [01]
    sub_mode=0x01 is the auth version observed in the wild.
    """
    uid_bytes = user_id.encode()[:54]
    uid_field = uid_bytes + b"\x00" * (54 - len(uid_bytes))
    name_bytes = name.encode()[:54]
    name_field = name_bytes + b"\x00" * (54 - len(name_bytes))
    locale_bytes = locale.encode()[:5] + b"\x00"
    data = bytes([0x02, 0x02, sub_mode]) + auth_response[:16] + uid_field + name_field + locale_bytes + b"\x01"
    return build_frame(0x01, data)


# ---------------------------------------------------------------------------
# Time sync (cmd=0x02) and battery (cmd=0x03)
# ---------------------------------------------------------------------------

def build_time_sync(ts: Optional[int] = None) -> bytes:
    """Set current time on watch. ts = unix timestamp (default: now)."""
    if ts is None:
        ts = int(datetime.datetime.now().timestamp())
    return build_frame(0x02, struct.pack("<I", ts) + bytes([0x00, 0x02, 0x00]))


def parse_battery(payload: bytes) -> Optional[int]:
    """Parse cmd=0x03 response → battery %."""
    if payload:
        return payload[-1]
    return None


# ---------------------------------------------------------------------------
# Health data download (cmd=0x25)
# ---------------------------------------------------------------------------

DATA_TYPE_HR = 0x02
DATA_TYPE_SPO2 = 0x03
DATA_TYPE_SLEEP_STAGE = 0x05
DATA_TYPE_STEPS = 0x07
DATA_TYPE_HR_AGGREGATE = 0x09
DATA_TYPE_SLEEP_DETAIL = 0x0B
DATA_TYPE_END = 0x00


def build_set_since_timestamp(since_ts: int) -> bytes:
    """Set the start timestamp for data download (cmd=0x25)."""
    return build_frame(0x25, struct.pack("<I", since_ts))


def build_trigger_download() -> bytes:
    """Trigger health data download (cmd=0x30)."""
    return build_frame(0x30)


@dataclass
class HRRecord:
    timestamp: int
    bpm: int

    @property
    def dt(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.timestamp)


@dataclass
class SpO2Record:
    timestamp: int
    spo2: int

    @property
    def dt(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.timestamp)


@dataclass
class SleepStageRecord:
    timestamp: int
    stage: int       # 0=awake, 1=light, 2=deep, 3=REM (guessed)
    sub_stage: int
    duration_min: int

    @property
    def dt(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.timestamp)

    @property
    def stage_name(self) -> str:
        return {0: "Awake", 1: "Light", 2: "Deep", 3: "REM"}.get(self.stage, f"S{self.stage}")


@dataclass
class StepsRecord:
    steps: int
    calories: int
    distance_m: int


@dataclass
class HRAggregate:
    timestamp: int
    value: int

    @property
    def dt(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.timestamp)


def parse_data_frame(payload: bytes) -> Optional[dict]:
    """
    Parse a cmd=0x25 data notification.
    Returns dict with 'type' and 'records' keys, or None on error.
    """
    if not payload:
        return None
    dtype = payload[0]

    if dtype == DATA_TYPE_END:
        return {"type": "end"}

    data = payload[1:]  # remaining bytes after type byte

    if dtype == DATA_TYPE_HR:
        return {"type": "hr", "records": _parse_5byte_records(data, _make_hr)}

    if dtype == DATA_TYPE_SPO2:
        return {"type": "spo2", "records": _parse_5byte_records(data, _make_spo2)}

    if dtype == DATA_TYPE_SLEEP_STAGE:
        return {"type": "sleep_stage", "records": _parse_sleep_stages(data)}

    if dtype == DATA_TYPE_STEPS:
        return {"type": "steps", "record": _parse_steps(data)}

    if dtype == DATA_TYPE_HR_AGGREGATE:
        return {"type": "hr_agg", "records": _parse_5byte_records(data, _make_hr_agg)}

    if dtype == DATA_TYPE_SLEEP_DETAIL:
        return {"type": "sleep_detail", "raw": data.hex()}

    return {"type": f"unknown_{dtype:02x}", "raw": payload.hex()}


def _parse_5byte_records(data: bytes, factory) -> list:
    if not data:
        return []
    count = data[0]
    records = []
    for i in range(count):
        offset = 1 + i * 5
        if offset + 5 > len(data):
            break
        ts = struct.unpack_from("<I", data, offset)[0]
        val = data[offset + 4]
        records.append(factory(ts, val))
    return records


def _make_hr(ts, bpm) -> HRRecord:
    return HRRecord(timestamp=ts, bpm=bpm)


def _make_spo2(ts, spo2) -> SpO2Record:
    return SpO2Record(timestamp=ts, spo2=spo2)


def _make_hr_agg(ts, val) -> HRAggregate:
    return HRAggregate(timestamp=ts, value=val)


def _parse_sleep_stages(data: bytes) -> list:
    """8 bytes per record: ts(4) + pad(1) + stage(1) + dur_min(1) + pad(1)"""
    if not data:
        return []
    count = data[0]
    records = []
    for i in range(count):
        offset = 1 + i * 8
        if offset + 8 > len(data):
            break
        ts = struct.unpack_from("<I", data, offset)[0]
        stage = data[offset + 5]   # byte[4] is always 0x00 padding; byte[5] is stage
        dur_min = data[offset + 6]
        records.append(SleepStageRecord(
            timestamp=ts,
            stage=stage,
            sub_stage=0,
            duration_min=dur_min,
        ))
    return records


def _parse_steps(data: bytes) -> Optional[StepsRecord]:
    if len(data) < 12:
        return None
    steps = struct.unpack_from("<I", data, 0)[0]
    cal = struct.unpack_from("<I", data, 4)[0]
    dist = struct.unpack_from("<I", data, 8)[0]
    return StepsRecord(steps=steps, calories=cal, distance_m=dist)


# ---------------------------------------------------------------------------
# Device info (cmd=0x07)
# ---------------------------------------------------------------------------

def build_get_device_info() -> bytes:
    return build_frame(0x07)


def parse_device_info(payload: bytes) -> str:
    return payload.decode("ascii", errors="replace").rstrip("\x00")


# ---------------------------------------------------------------------------
# Battery request (cmd=0x03)
# ---------------------------------------------------------------------------

def build_get_battery() -> bytes:
    return build_frame(0x03)
