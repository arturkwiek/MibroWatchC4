"""
Mibro Watch C4 BLE library.

Quick start:
    from mibro.client import MibroClient
    from mibro import protocol
"""
from mibro.protocol import (
    build_frame,
    parse_frame,
    build_handshake_stage1,
    build_handshake_stage2,
    compute_auth_response,
    parse_handshake_response,
    build_time_sync,
    build_get_battery,
    build_get_device_info,
    build_set_since_timestamp,
    build_trigger_download,
    parse_data_frame,
    parse_battery,
    parse_device_info,
    HRRecord,
    SpO2Record,
    SleepStageRecord,
    StepsRecord,
    HRAggregate,
)

__all__ = [
    "build_frame", "parse_frame",
    "build_handshake_stage1", "build_handshake_stage2",
    "compute_auth_response", "parse_handshake_response",
    "build_time_sync", "build_get_battery", "build_get_device_info",
    "build_set_since_timestamp", "build_trigger_download",
    "parse_data_frame", "parse_battery", "parse_device_info",
    "HRRecord", "SpO2Record", "SleepStageRecord", "StepsRecord", "HRAggregate",
]
