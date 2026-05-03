"""Desktop GUI for BLE service discovery.

Architecture overview:
- App (tk main thread): handles rendering, user actions, and clipboard/menu.
- AsyncWorker (background thread): handles BLE I/O through bleak/asyncio.
- Queue messages: the only bridge between worker and UI, which keeps the GUI responsive.

Characteristic interaction (added in v2):
- After connecting, the BleakClient is kept alive (persistent connection).
- Selecting a characteristic row enables Read / Subscribe / Write buttons.
- Results (raw bytes) are shown as HEX, ASCII and decimal in the value panel.
- Subscribed characteristics are highlighted in the service tree.
"""

import asyncio
import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4

from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from bluetooth_sig_uuids import (
    lookup_characteristic,
    lookup_descriptor,
    lookup_service,
)

# Colour accents (status text only; everything else uses system colours)
C_OK   = "#006400"   # dark green
C_WARN = "#8B6500"   # dark amber
C_ERR  = "#8B0000"   # dark red
C_INFO = "#00008B"   # dark blue
C_SUB  = "#8B008B"   # dark magenta – subscribed characteristic

# Candidate vendor-specific channels for MiBro-like command/notify transport.
PROBE_WRITE_UUIDS = (
    "00002CB1-0000-1000-8000-00805F9B34FB",
    "00000000-0000-0100-6473-5F696C666973",
)
PROBE_NOTIFY_UUIDS = (
    "00002CB0-0000-1000-8000-00805F9B34FB",
    "00000000-0000-0200-6473-5F696C666973",
)

# Protocol probe — focused on the reactive 2CB1→2CB0 channel.
PROTO_PROBE_WRITE_UUID   = "00002CB1-0000-1000-8000-00805F9B34FB"
PROTO_PROBE_NOTIFY_UUID  = "00002CB0-0000-1000-8000-00805F9B34FB"
PROTO_PROBE_WRITE2_UUID  = "00000000-0000-0100-6473-5F696C666973"  # secondary channel
PROTO_PROBE_NOTIFY2_UUID = "00000000-0000-0200-6473-5F696C666973"  # secondary channel

# Passive listen: just subscribe and wait — no writes.
# Both notify channels subscribed; any device-initiated packet is captured.
PASSIVE_LISTEN_DURATION = 60  # seconds
PASSIVE_LISTEN_NOTIFY_UUIDS = [
    PROTO_PROBE_NOTIFY_UUID,   # primary  2CB0
    PROTO_PROBE_NOTIFY2_UUID,  # secondary 0200
]

# Structured frames to probe the Mibro command channel.
# Previous sessions confirmed: EA EA prefix → 10 frames sent, 0 responses.
# New strategy: AA-prefix (common Chinese wearable format [AA CMD LEN_HI LEN_LO])
# plus secondary channel write (0100).  All fits in < 8 s within ~13 s timeout.
PROTO_PROBE_FRAMES: list[tuple[str, bytes]] = [
    # ── Primary channel (2CB1) — AA-prefix format [AA CMD LEN_HI LEN_LO] ──
    ("aa:handshake",          bytes.fromhex("AA010000")),   # cmd 0x01 hello
    ("aa:get_time",           bytes.fromhex("AA020000")),   # cmd 0x02 time
    ("aa:device_info",        bytes.fromhex("AA110000")),   # cmd 0x11 info
    ("aa:battery",            bytes.fromhex("AA200000")),   # cmd 0x20 battery
    ("aa:heart_rate_start",   bytes.fromhex("AA0F0000")),   # cmd 0x0F HR (common)
    ("aa:history_start",      bytes.fromhex("AA800000")),   # cmd 0x80 history
    ("aa:history_next",       bytes.fromhex("AA810000")),   # cmd 0x81 next page
    # ── Secondary channel (0100) — same AA-prefix ──
    ("aa:ch2:handshake",      bytes.fromhex("AA010000")),   # same cmds on ch2
    ("aa:ch2:battery",        bytes.fromhex("AA200000")),
    ("aa:ch2:history_start",  bytes.fromhex("AA800000")),
]

# ── Messages: async thread → GUI thread ──────────────────────────────────────

@dataclass
class MsgDeviceFound:
    device: BLEDevice
    adv: AdvertisementData

@dataclass
class MsgScanDone:
    pass

@dataclass
class MsgStatus:
    text: str
    colour: str = "black"

@dataclass
class MsgConnectError:
    error: str

@dataclass
class MsgConnected:
    """Sent after BleakClient connects and the service tree has been queued."""
    pass

@dataclass
class MsgDisconnected:
    """Sent on manual disconnect or unexpected drop."""
    pass

@dataclass
class MsgCharValue:
    """Result of a Read GATT characteristic operation."""
    uuid: str
    data: bytes

@dataclass
class MsgNotification:
    """Incoming Notify or Indicate from a subscribed characteristic."""
    uuid: str
    data: bytes

@dataclass
class MsgWriteOk:
    """Write completed successfully."""
    uuid: str

@dataclass
class MsgSubscribed:
    uuid: str

@dataclass
class MsgUnsubscribed:
    uuid: str

@dataclass
class MsgPaired:
    """Pairing/bonding completed successfully."""
    pass

@dataclass
class MsgPairError:
    error: str

@dataclass
class MsgProbeTx:
    """One probe frame sent to a write characteristic."""
    uuid: str
    data: bytes

@dataclass
class MsgProbeDone:
    """Probe finished with summary counters."""
    sent_frames: int
    notify_channels_active: int

@dataclass
class MsgProtoCharRead:
    """Value of a characteristic read at rest before sending probe frames."""
    uuid: str
    data: bytes

@dataclass
class MsgProtoTx:
    """One structured protocol-probe frame sent to the write characteristic."""
    label: str
    uuid: str
    data: bytes

@dataclass
class MsgProtoProbeDone:
    """Protocol probe finished."""
    frames_sent: int
    responses_received: int
    disconnect_frame: Optional[str]  # label of the last frame attempted when disconnect occurred

@dataclass
class MsgPassiveListenDone:
    """Passive listen session finished."""
    duration_s: int
    notifications_received: int

@dataclass
class MsgServiceTree:
    """Entire service tree for one device."""

    @dataclass
    class Descriptor:
        uuid: str
        name: str

    @dataclass
    class Characteristic:
        uuid: str
        name: str
        props: list[str]
        descriptors: list["MsgServiceTree.Descriptor"] = field(default_factory=list)

    @dataclass
    class Service:
        uuid: str
        name: str
        handle: int
        characteristics: list["MsgServiceTree.Characteristic"] = field(default_factory=list)

    services: list["MsgServiceTree.Service"] = field(default_factory=list)


# ── Async worker ──────────────────────────────────────────────────────────────

class AsyncWorker:
    """Runs BLE operations in a dedicated asyncio loop on a daemon thread.

    After a successful connect() the BleakClient is kept alive so the GUI
    can issue Read / Write / Subscribe commands without reconnecting each time.
    Call start_disconnect() explicitly (or it fires on unexpected drop).
    """

    def __init__(self, gui_queue: queue.Queue):
        self._q = gui_queue
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._client: Optional[BleakClient] = None
        self._subscribed: set[str] = set()

    def _run(self):
        self._loop.run_forever()

    def submit(self, coro):
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    # Public API called from the GUI thread

    def start_scan(self, timeout: float):
        self.submit(self._scan(timeout))

    def start_connect(self, device: BLEDevice):
        self.submit(self._connect(device))

    def start_disconnect(self):
        self.submit(self._disconnect())

    def start_read(self, uuid: str):
        self.submit(self._read_char(uuid))

    def start_write(self, uuid: str, data: bytes, with_response: bool):
        self.submit(self._write_char(uuid, data, with_response))

    def start_subscribe(self, uuid: str):
        self.submit(self._subscribe_char(uuid))

    def start_unsubscribe(self, uuid: str):
        self.submit(self._unsubscribe_char(uuid))

    def start_pair(self):
        self.submit(self._pair())

    def start_probe_history(self):
        self.submit(self._probe_history())

    def start_proto_probe(self):
        self.submit(self._proto_probe())

    def start_passive_listen(self):
        self.submit(self._passive_listen())

    def is_subscribed(self, uuid: str) -> bool:
        return uuid.lower() in self._subscribed

    # Internal coroutines

    async def _scan(self, timeout: float):
        # Worker never touches widgets directly; it emits events back to the UI queue.
        self._q.put(MsgStatus(f"Scanning for {timeout:.0f} s...", C_INFO))
        try:
            results: dict = await BleakScanner.discover(timeout=timeout, return_adv=True)
            for dev, adv in sorted(results.values(),
                                   key=lambda p: p[1].rssi or -999,
                                   reverse=True):
                self._q.put(MsgDeviceFound(dev, adv))
            self._q.put(MsgScanDone())
            self._q.put(MsgStatus(
                f"Scan complete -- {len(results)} device(s) found.", C_OK))
        except Exception as exc:
            self._q.put(MsgStatus(f"Scan error: {exc}", C_ERR))
            self._q.put(MsgScanDone())

    def _on_unexpected_disconnect(self, _client):
        """Called by bleak on the asyncio thread when the connection drops."""
        self._client = None
        self._subscribed.clear()
        self._q.put(MsgDisconnected())

    async def _connect(self, device: BLEDevice):
        self._q.put(MsgStatus(
            f"Connecting to {device.name or device.address}...", C_WARN))
        try:
            self._client = BleakClient(
                device,
                disconnected_callback=self._on_unexpected_disconnect,
            )
            await self._client.connect()
            if not self._client.is_connected:
                self._q.put(MsgConnectError("Connection failed."))
                self._client = None
                return

            self._q.put(MsgStatus(
                f"Connected  OK  —  {device.name or device.address}", C_OK))
            msg = MsgServiceTree()

            for svc in self._client.services:
                # Convert bleak objects into plain dataclasses so the GUI layer
                # can render them without depending on bleak internals.
                svc_name = lookup_service(svc.uuid) or "(vendor-specific)"
                s = MsgServiceTree.Service(
                    uuid=svc.uuid.upper(),
                    name=svc_name,
                    handle=svc.handle,
                )
                for char in svc.characteristics:
                    char_name = lookup_characteristic(char.uuid) or "(unknown)"
                    c = MsgServiceTree.Characteristic(
                        uuid=char.uuid.upper(),
                        name=char_name,
                        props=list(char.properties),
                    )
                    for desc in char.descriptors:
                        desc_name = lookup_descriptor(desc.uuid) or "(unknown)"
                        c.descriptors.append(
                            MsgServiceTree.Descriptor(
                                uuid=desc.uuid.upper(), name=desc_name)
                        )
                    s.characteristics.append(c)
                msg.services.append(s)

            self._q.put(msg)
            self._q.put(MsgConnected())
        except Exception as exc:
            self._q.put(MsgConnectError(str(exc)))
            self._q.put(MsgStatus(f"Connection error: {exc}", C_ERR))
            self._client = None

    async def _disconnect(self):
        client, self._client = self._client, None
        self._subscribed.clear()
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass
        self._q.put(MsgDisconnected())

    async def _pair(self):
        if not self._client or not self._client.is_connected:
            self._q.put(MsgStatus("Not connected – connect first, then pair.", C_ERR))
            return
        self._q.put(MsgStatus("Pairing / bonding with device...", C_WARN))
        try:
            result = await self._client.pair()
            if result:
                self._q.put(MsgPaired())
            else:
                self._q.put(MsgPairError("Pairing returned False (device rejected or already paired)."))
        except Exception as exc:
            self._q.put(MsgPairError(str(exc)))

    async def _read_char(self, uuid: str):
        if not self._client or not self._client.is_connected:
            self._q.put(MsgStatus("Not connected.", C_ERR))
            return
        try:
            data = await self._client.read_gatt_char(uuid)
            self._q.put(MsgCharValue(uuid, bytes(data)))
        except Exception as exc:
            self._q.put(MsgStatus(f"Read error: {exc}", C_ERR))

    async def _write_char(self, uuid: str, data: bytes, with_response: bool):
        if not self._client or not self._client.is_connected:
            self._q.put(MsgStatus("Not connected.", C_ERR))
            return
        try:
            await self._client.write_gatt_char(uuid, data, response=with_response)
            self._q.put(MsgWriteOk(uuid))
        except Exception as exc:
            self._q.put(MsgStatus(f"Write error: {exc}", C_ERR))

    async def _subscribe_char(self, uuid: str):
        if not self._client or not self._client.is_connected:
            self._q.put(MsgStatus("Not connected.", C_ERR))
            return
        try:
            def _cb(_sender, data):
                self._q.put(MsgNotification(uuid, bytes(data)))
            await self._client.start_notify(uuid, _cb)
            self._subscribed.add(uuid.lower())
            self._q.put(MsgSubscribed(uuid))
        except Exception as exc:
            self._q.put(MsgStatus(f"Subscribe error: {exc}", C_ERR))

    async def _unsubscribe_char(self, uuid: str):
        if not self._client or not self._client.is_connected:
            return
        try:
            await self._client.stop_notify(uuid)
            self._subscribed.discard(uuid.lower())
            self._q.put(MsgUnsubscribed(uuid))
        except Exception as exc:
            self._q.put(MsgStatus(f"Unsubscribe error: {exc}", C_ERR))

    async def _probe_history(self):
        """Run a conservative probe on candidate write/notify UUID pairs."""
        if not self._client or not self._client.is_connected:
            self._q.put(MsgStatus("Not connected - connect first, then run probe.", C_ERR))
            self._q.put(MsgProbeDone(sent_frames=0, notify_channels_active=0))
            return

        available_chars = {
            char.uuid.lower(): char
            for svc in self._client.services
            for char in svc.characteristics
        }

        notify_channels_active = 0
        for uuid in PROBE_NOTIFY_UUIDS:
            key = uuid.lower()
            if key not in available_chars:
                continue
            if key in self._subscribed:
                notify_channels_active += 1
                continue
            try:
                def _cb(_sender, data, _u=uuid.upper()):
                    self._q.put(MsgNotification(_u, bytes(data)))

                await self._client.start_notify(key, _cb)
                self._subscribed.add(key)
                notify_channels_active += 1
                self._q.put(MsgSubscribed(uuid.upper()))
            except Exception as exc:
                self._q.put(MsgStatus(f"Probe subscribe failed on {uuid}: {exc}", C_ERR))

        probe_frames = (
            bytes.fromhex("00"),
            bytes.fromhex("01"),
            bytes.fromhex("02"),
            bytes.fromhex("00 00"),
            bytes.fromhex("01 00"),
        )

        sent_frames = 0
        for uuid in PROBE_WRITE_UUIDS:
            key = uuid.lower()
            char = available_chars.get(key)
            if char is None:
                continue

            props_lower = [p.lower() for p in char.properties]
            can_write = any(p.startswith("write") for p in props_lower)
            if not can_write:
                continue
            with_response = "write" in props_lower

            for frame in probe_frames:
                if not self._client or not self._client.is_connected:
                    self._q.put(MsgStatus("Probe: connection lost — stopping early.", C_WARN))
                    break
                self._q.put(MsgProbeTx(uuid=uuid.upper(), data=frame))
                try:
                    await self._client.write_gatt_char(key, frame, response=with_response)
                    sent_frames += 1
                except Exception as exc:
                    self._q.put(MsgStatus(f"Probe write failed on {uuid}: {exc}", C_ERR))
                    break
                await asyncio.sleep(0.25)

        # Leave a short window for responses from the last transmitted frame.
        await asyncio.sleep(1.0)
        self._q.put(MsgProbeDone(
            sent_frames=sent_frames,
            notify_channels_active=notify_channels_active,
        ))

    async def _proto_probe(self):
        """Structured protocol probe on the primary XTSR command channel (2CB1→2CB0).

        Steps:
          1. Subscribe to 2CB0 notify channel to catch device responses.
          2. Send each frame from PROTO_PROBE_FRAMES with a 0.5 s inter-frame gap.
             All 10 frames fit within ~6 s — well inside the device's ~13 s
             auth-timeout window — leaving ample time for notify replies.
          3. Track which frame (if any) preceded a disconnect for protocol analysis.
        """
        if not self._client or not self._client.is_connected:
            self._q.put(MsgStatus("Not connected — connect first, then run Protocol Probe.", C_ERR))
            self._q.put(MsgProtoProbeDone(frames_sent=0, responses_received=0, disconnect_frame=None))
            return

        available_chars = {
            char.uuid.lower(): char
            for svc in self._client.services
            for char in svc.characteristics
        }

        # ── Step 1: subscribe to notify channel ───────────────────────────────
        responses_received = 0
        notify_key = PROTO_PROBE_NOTIFY_UUID.lower()
        if notify_key in available_chars and notify_key not in self._subscribed:
            try:
                def _cb(_sender, data, _u=PROTO_PROBE_NOTIFY_UUID):
                    nonlocal responses_received
                    responses_received += 1
                    self._q.put(MsgNotification(_u, bytes(data)))

                await self._client.start_notify(notify_key, _cb)
                self._subscribed.add(notify_key)
                self._q.put(MsgSubscribed(PROTO_PROBE_NOTIFY_UUID))
            except Exception as exc:
                self._q.put(MsgStatus(f"Proto subscribe failed: {exc}", C_ERR))

        # ── Also subscribe secondary notify channel ────────────────────────
        notify2_key = PROTO_PROBE_NOTIFY2_UUID.lower()
        if notify2_key in available_chars and notify2_key not in self._subscribed:
            try:
                def _cb2(_sender, data, _u=PROTO_PROBE_NOTIFY2_UUID):
                    nonlocal responses_received
                    responses_received += 1
                    self._q.put(MsgNotification(_u, bytes(data)))

                await self._client.start_notify(notify2_key, _cb2)
                self._subscribed.add(notify2_key)
                self._q.put(MsgSubscribed(PROTO_PROBE_NOTIFY2_UUID))
            except Exception as exc:
                self._q.put(MsgStatus(f"Proto subscribe ch2 failed: {exc}", C_ERR))

        # ── Step 2: send structured frames ────────────────────────────────────
        # First 7 frames go to primary channel (2CB1), last 3 to secondary (0100).
        SPLIT = 7  # index at which frames switch to secondary channel
        write_key = PROTO_PROBE_WRITE_UUID.lower()
        write2_key = PROTO_PROBE_WRITE2_UUID.lower()
        write_char = available_chars.get(write_key)
        if write_char is None:
            self._q.put(MsgStatus("Protocol probe: write characteristic not found on device.", C_ERR))
            self._q.put(MsgProtoProbeDone(frames_sent=0, responses_received=responses_received, disconnect_frame=None))
            return

        props_lower = [p.lower() for p in write_char.properties]
        with_response = "write" in props_lower

        frames_sent = 0
        disconnect_frame: Optional[str] = None

        for idx, (label, frame) in enumerate(PROTO_PROBE_FRAMES):
            if not self._client or not self._client.is_connected:
                disconnect_frame = label
                self._q.put(MsgStatus(
                    f"Protocol probe: connection lost before '{label}' — check log for triggering frame.",
                    C_WARN,
                ))
                break

            # Route first SPLIT frames to primary channel, rest to secondary
            if idx < SPLIT:
                target_key = write_key
                target_uuid = PROTO_PROBE_WRITE_UUID
                target_char = write_char
                target_wr = with_response
            else:
                target_key = write2_key
                target_char = available_chars.get(write2_key)
                target_uuid = PROTO_PROBE_WRITE2_UUID
                target_wr = "write" in [p.lower() for p in target_char.properties] if target_char else False

            if target_char is None:
                self._q.put(MsgStatus(f"Protocol probe: write char not found for '{label}'", C_ERR))
                continue

            self._q.put(MsgProtoTx(label=label, uuid=target_uuid, data=frame))
            try:
                await self._client.write_gatt_char(target_key, frame, response=target_wr)
                frames_sent += 1
            except Exception as exc:
                disconnect_frame = label
                self._q.put(MsgStatus(f"Protocol probe write failed on '{label}': {exc}", C_ERR))
                break
            await asyncio.sleep(0.5)

        # Final window to catch any delayed last-frame response.
        await asyncio.sleep(1.0)
        self._q.put(MsgProtoProbeDone(
            frames_sent=frames_sent,
            responses_received=responses_received,
            disconnect_frame=disconnect_frame,
        ))

    async def _passive_listen(self):
        """Subscribe to all notify channels and wait passively for device-initiated packets.

        No writes are sent — this tests whether the device broadcasts anything
        spontaneously (heartbeat, status, unsolicited data) after BLE connection.
        Duration: PASSIVE_LISTEN_DURATION seconds.
        """
        if not self._client or not self._client.is_connected:
            self._q.put(MsgStatus("Not connected — connect first, then run Passive Listen.", C_ERR))
            self._q.put(MsgPassiveListenDone(duration_s=0, notifications_received=0))
            return

        available_chars = {
            char.uuid.lower(): char
            for svc in self._client.services
            for char in svc.characteristics
        }

        rx_count = [0]

        for uuid in PASSIVE_LISTEN_NOTIFY_UUIDS:
            key = uuid.lower()
            if key not in available_chars or key in self._subscribed:
                continue
            try:
                def _cb(_sender, data, _u=uuid):
                    rx_count[0] += 1
                    self._q.put(MsgNotification(_u, bytes(data)))

                await self._client.start_notify(key, _cb)
                self._subscribed.add(key)
                self._q.put(MsgSubscribed(uuid))
            except Exception as exc:
                self._q.put(MsgStatus(f"Passive listen subscribe failed on {uuid}: {exc}", C_ERR))

        self._q.put(MsgStatus(
            f"Passive listen: subscribed to notify channels, watching {PASSIVE_LISTEN_DURATION} s for device-initiated packets...",
            C_WARN,
        ))
        await asyncio.sleep(PASSIVE_LISTEN_DURATION)
        self._q.put(MsgPassiveListenDone(
            duration_s=PASSIVE_LISTEN_DURATION,
            notifications_received=rx_count[0],
        ))


# ── Main GUI ──────────────────────────────────────────────────────────────────

class App(tk.Tk):
    """Main desktop window coordinating scan/connect and results presentation."""
    POLL_MS = 80

    def __init__(self):
        super().__init__()
        self.title("BLE Service Explorer")
        self.geometry("1100x820")
        self.minsize(820, 600)

        self._gui_queue: queue.Queue = queue.Queue()
        self._worker = AsyncWorker(self._gui_queue)
        self._log_path = Path(__file__).with_name("ble_scan_history.json")
        self._event_log_path = Path(__file__).with_name("ble_ui_action_log.jsonl")
        self._probe_log_path = Path(__file__).with_name("ble_history_probe_log.jsonl")
        self._proto_probe_log_path = Path(__file__).with_name("ble_proto_probe_log.jsonl")
        self._passive_log_path = Path(__file__).with_name("ble_passive_log.jsonl")

        # address -> (BLEDevice, AdvertisementData, treeview_iid)
        self._devices: dict[str, tuple[BLEDevice, AdvertisementData, str]] = {}
        self._selected_device: Optional[BLEDevice] = None

        # uuid (upper) -> list[str] of property strings, filled during tree build
        self._char_props: dict[str, list[str]] = {}
        # Currently selected characteristic UUID (upper-case) from service tree
        self._selected_char_uuid: Optional[str] = None
        # True when a BleakClient is live
        self._connected: bool = False
        self._probe_active: bool = False
        self._probe_session_id: Optional[str] = None
        self._proto_probe_active: bool = False
        self._proto_probe_session_id: Optional[str] = None
        self._passive_listen_active: bool = False
        self._passive_listen_session_id: Optional[str] = None

        self._build_styles()
        self._build_ui()
        self._poll_queue()
        self._log_event(
            event_type="app_started",
            source="system",
            action="main_window_initialized",
            details={"window": "BLE Service Explorer"},
        )

    def _build_styles(self):
        style = ttk.Style(self)
        for theme in ("vista", "winnative", "xpnative", "clam"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Treeview", rowheight=22)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        # ── Menu bar ──────────────────────────────────────────────────────────
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Scan", accelerator="F5",
                              command=self._on_scan)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        edit_menu = tk.Menu(menubar, tearoff=False)
        edit_menu.add_command(label="Copy selected UUID", accelerator="Ctrl+C",
                      command=self._copy_selected_uuid)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        self.configure(menu=menubar)
        self.bind("<F5>", lambda _e: self._on_scan())
        self.bind("<Control-c>", lambda _e: self._copy_selected_uuid())

        # ── Toolbar ───────────────────────────────────────────────────────────
        toolbar = ttk.Frame(self, relief="raised", padding=(4, 3))
        toolbar.pack(fill="x", side="top")

        self._btn_scan = ttk.Button(
            toolbar, text="Scan  (F5)", width=11, command=self._on_scan)
        self._btn_scan.pack(side="left", padx=(0, 4))

        self._btn_connect = ttk.Button(
            toolbar, text="Connect", width=10,
            command=self._on_connect, state="disabled")
        self._btn_connect.pack(side="left", padx=(0, 4))

        self._btn_disconnect = ttk.Button(
            toolbar, text="Disconnect", width=12,
            command=self._on_disconnect, state="disabled")
        self._btn_disconnect.pack(side="left", padx=(0, 4))

        self._btn_pair = ttk.Button(
            toolbar, text="Pair / Bond", width=11,
            command=self._on_pair, state="disabled")
        self._btn_pair.pack(side="left", padx=(0, 12))

        self._btn_probe_history = ttk.Button(
            toolbar, text="Probe History", width=13,
            command=self._on_probe_history, state="disabled")
        self._btn_probe_history.pack(side="left", padx=(0, 4))

        self._btn_proto_probe = ttk.Button(
            toolbar, text="Protocol Probe", width=14,
            command=self._on_proto_probe, state="disabled")
        self._btn_proto_probe.pack(side="left", padx=(0, 4))

        self._btn_passive_listen = ttk.Button(
            toolbar, text="Passive Listen", width=14,
            command=self._on_passive_listen, state="disabled")
        self._btn_passive_listen.pack(side="left", padx=(0, 12))

        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=6)

        ttk.Label(toolbar, text="Scan time (s):").pack(side="left", padx=(0, 4))
        self._timeout_var = tk.DoubleVar(value=10.0)
        ttk.Spinbox(toolbar, from_=3, to=60, increment=1,
                    textvariable=self._timeout_var, width=5).pack(side="left")

        # ── Main area ─────────────────────────────────────────────────────────
        main = ttk.Frame(self, padding=(6, 4))
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=3)
        main.rowconfigure(0, weight=1)

        # ── Left: device list ─────────────────────────────────────────────────
        lf_dev = ttk.LabelFrame(main, text="Nearby Devices", padding=(4, 4))
        lf_dev.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        lf_dev.columnconfigure(0, weight=1)
        lf_dev.rowconfigure(0, weight=1)

        self._dev_tree = ttk.Treeview(
            lf_dev, columns=("name", "address", "rssi"),
            show="headings", selectmode="browse")
        self._dev_tree.heading(
            "name",    text="Name",
            command=lambda: self._sort_dev("name"))
        self._dev_tree.heading(
            "address", text="Address",
            command=lambda: self._sort_dev("address"))
        self._dev_tree.heading(
            "rssi",    text="RSSI",
            command=lambda: self._sort_dev("rssi"))
        self._dev_tree.column("name",    width=160, anchor="w", minwidth=80)
        self._dev_tree.column("address", width=140, anchor="w", minwidth=100)
        self._dev_tree.column("rssi",    width=70,  anchor="e", minwidth=50)
        self._dev_tree.grid(row=0, column=0, sticky="nsew")

        vsb_dev = ttk.Scrollbar(lf_dev, orient="vertical",
                                 command=self._dev_tree.yview)
        vsb_dev.grid(row=0, column=1, sticky="ns")
        self._dev_tree.configure(yscrollcommand=vsb_dev.set)

        self._dev_tree.bind("<<TreeviewSelect>>", self._on_device_selected)
        self._dev_tree.bind("<Double-1>",  lambda _e: self._on_connect())
        self._dev_tree.bind("<Return>",    lambda _e: self._on_connect())

        self._dev_tree.tag_configure("rssi_good", foreground=C_OK)
        self._dev_tree.tag_configure("rssi_ok",   foreground=C_WARN)
        self._dev_tree.tag_configure("rssi_weak", foreground=C_ERR)
        self._dev_tree.tag_configure("no_name",   foreground="gray")

        # ── Right: vertical paned window (service tree + interaction panel) ───
        right_pane = ttk.PanedWindow(main, orient="vertical")
        right_pane.grid(row=0, column=1, sticky="nsew")

        # Service tree (top pane)
        lf_svc = ttk.LabelFrame(
            right_pane, text="Services & Characteristics", padding=(4, 4))
        right_pane.add(lf_svc, weight=3)
        lf_svc.columnconfigure(0, weight=1)
        lf_svc.rowconfigure(0, weight=1)

        self._svc_tree = ttk.Treeview(
            lf_svc, columns=("uuid", "name", "extra"),
            show="tree headings", selectmode="browse")
        self._svc_tree.heading("#0",    text="")
        self._svc_tree.heading("uuid",  text="UUID")
        self._svc_tree.heading("name",  text="Standard Name  (Bluetooth SIG)")
        self._svc_tree.heading("extra", text="Properties / Handle")
        self._svc_tree.column("#0",    width=20,  stretch=False)
        self._svc_tree.column("uuid",  width=300, anchor="w", minwidth=180)
        self._svc_tree.column("name",  width=270, anchor="w", minwidth=140)
        self._svc_tree.column("extra", width=190, anchor="w", minwidth=80)
        self._svc_tree.grid(row=0, column=0, sticky="nsew")

        vsb_svc = ttk.Scrollbar(lf_svc, orient="vertical",
                                  command=self._svc_tree.yview)
        vsb_svc.grid(row=0, column=1, sticky="ns")
        hsb_svc = ttk.Scrollbar(lf_svc, orient="horizontal",
                                  command=self._svc_tree.xview)
        hsb_svc.grid(row=1, column=0, sticky="ew")
        self._svc_tree.configure(yscrollcommand=vsb_svc.set,
                                  xscrollcommand=hsb_svc.set)
        self._svc_tree.bind("<Button-3>", self._show_svc_context_menu)
        self._svc_tree.bind("<<TreeviewSelect>>", self._on_char_selected)

        self._svc_tree.tag_configure("service",      font=("Segoe UI", 9, "bold"))
        self._svc_tree.tag_configure("known_svc",    foreground=C_OK)
        self._svc_tree.tag_configure("unknown_svc",  foreground="gray")
        self._svc_tree.tag_configure("known_char",   foreground=C_INFO)
        self._svc_tree.tag_configure("unknown_char", foreground="gray")
        self._svc_tree.tag_configure("subscribed",   foreground=C_SUB)
        self._svc_tree.tag_configure("desc",         foreground="gray",
                                      font=("Segoe UI", 8))

        self._svc_menu = tk.Menu(self, tearoff=False)
        self._svc_menu.add_command(label="Copy UUID", command=self._copy_selected_uuid)

        # ── Characteristic interaction panel (bottom pane) ────────────────────
        lf_interact = ttk.LabelFrame(
            right_pane, text="Characteristic Interaction", padding=(6, 4))
        right_pane.add(lf_interact, weight=1)
        lf_interact.columnconfigure(1, weight=1)

        # Row 0: which characteristic is selected
        ttk.Label(lf_interact, text="Selected:").grid(
            row=0, column=0, sticky="w", padx=(0, 6))
        self._sel_char_var = tk.StringVar(value="— select a characteristic row above —")
        ttk.Label(lf_interact, textvariable=self._sel_char_var,
                  foreground=C_INFO, font=("Segoe UI", 9)).grid(
            row=0, column=1, columnspan=3, sticky="w")

        # Row 1: value read-out (HEX / ASCII / DEC)
        ttk.Label(lf_interact, text="Value:").grid(
            row=1, column=0, sticky="nw", padx=(0, 6), pady=(4, 0))
        self._val_text = tk.Text(
            lf_interact, height=3, width=60,
            font=("Courier New", 9), state="disabled",
            relief="sunken", wrap="word")
        self._val_text.grid(row=1, column=1, columnspan=3, sticky="ew",
                            pady=(4, 4))

        # Row 2: action buttons + write entry
        self._btn_read = ttk.Button(
            lf_interact, text="Read", width=8,
            command=self._on_read, state="disabled")
        self._btn_read.grid(row=2, column=0, padx=(0, 4))

        self._btn_subscribe = ttk.Button(
            lf_interact, text="Subscribe", width=12,
            command=self._on_subscribe, state="disabled")
        self._btn_subscribe.grid(row=2, column=1, sticky="w", padx=(0, 8))

        self._write_var = tk.StringVar()
        self._write_entry = ttk.Entry(
            lf_interact, textvariable=self._write_var, width=28,
            state="disabled")
        self._write_entry.grid(row=2, column=2, sticky="ew", padx=(0, 4))
        self._write_entry.bind("<Return>", lambda _e: self._on_write())

        self._btn_write = ttk.Button(
            lf_interact, text="Write (hex)", width=11,
            command=self._on_write, state="disabled")
        self._btn_write.grid(row=2, column=3)

        # Row 3: hint text
        ttk.Label(lf_interact,
                  text="Write field accepts space-separated hex bytes,  e.g.   01 A2 FF",
                  foreground="gray", font=("Segoe UI", 8)).grid(
            row=3, column=1, columnspan=3, sticky="w", pady=(2, 0))

        # ── Status bar ────────────────────────────────────────────────────────
        self._status_bar = ttk.Frame(self, relief="sunken", padding=(4, 2))
        self._status_bar.pack(fill="x", side="bottom")
        self._set_status("Ready -- press  Scan  to discover nearby BLE devices.")

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_scan(self):
        self._log_event(
            event_type="ui_click",
            source="toolbar",
            action="scan",
            details={"timeout_s": float(self._timeout_var.get())},
        )
        # Auto-disconnect before starting a new scan
        if self._connected:
            self._worker.start_disconnect()
        for item in self._dev_tree.get_children():
            self._dev_tree.delete(item)
        self._clear_service_tree()
        self._char_props.clear()
        self._devices.clear()
        self._selected_device = None
        self._btn_connect.configure(state="disabled")
        self._btn_scan.configure(state="disabled")
        timeout = max(3.0, float(self._timeout_var.get()))
        self._worker.start_scan(timeout)

    def _on_connect(self):
        if self._selected_device is None:
            return
        self._log_event(
            event_type="ui_click",
            source="toolbar",
            action="connect",
            details={
                "device_name": self._selected_device.name or "",
                "device_address": self._selected_device.address,
            },
        )
        self._clear_service_tree()
        self._char_props.clear()
        self._btn_connect.configure(state="disabled")
        self._worker.start_connect(self._selected_device)

    def _on_disconnect(self):
        self._log_event(
            event_type="ui_click",
            source="toolbar",
            action="disconnect",
            details={
                "device_name": self._selected_device.name or "" if self._selected_device else "",
                "device_address": self._selected_device.address if self._selected_device else "",
            },
        )
        self._btn_disconnect.configure(state="disabled")
        self._worker.start_disconnect()

    def _on_pair(self):
        self._log_event(
            event_type="ui_click",
            source="toolbar",
            action="pair",
            details={
                "device_name": self._selected_device.name or "" if self._selected_device else "",
                "device_address": self._selected_device.address if self._selected_device else "",
            },
        )
        self._btn_pair.configure(state="disabled")
        self._worker.start_pair()

    def _on_probe_history(self):
        if not self._connected:
            self._set_status("Not connected - connect first, then run probe.", C_ERR)
            return
        self._probe_active = True
        self._probe_session_id = datetime.now().strftime("%Y%m%dT%H%M%S") + "-" + uuid4().hex[:8]
        self._btn_probe_history.configure(state="disabled")
        self._log_event(
            event_type="ui_click",
            source="toolbar",
            action="probe_history",
            details={
                "session_id": self._probe_session_id,
                "write_candidates": list(PROBE_WRITE_UUIDS),
                "notify_candidates": list(PROBE_NOTIFY_UUIDS),
            },
        )
        self._set_status(
            "Probe started: subscribing notify channels and sending conservative test frames...",
            C_WARN,
        )
        self._worker.start_probe_history()

    def _on_passive_listen(self):
        if not self._connected:
            self._set_status("Not connected — connect first, then run Passive Listen.", C_ERR)
            return
        self._passive_listen_active = True
        self._passive_listen_session_id = datetime.now().strftime("%Y%m%dT%H%M%S") + "-" + uuid4().hex[:8]
        self._btn_passive_listen.configure(state="disabled")
        self._log_event(
            event_type="ui_click",
            source="toolbar",
            action="passive_listen",
            details={
                "session_id": self._passive_listen_session_id,
                "notify_uuids": PASSIVE_LISTEN_NOTIFY_UUIDS,
                "duration_s": PASSIVE_LISTEN_DURATION,
            },
        )
        self._set_status(
            f"Passive Listen: subscribing notify channels, waiting {PASSIVE_LISTEN_DURATION} s...",
            C_WARN,
        )
        self._worker.start_passive_listen()

    def _on_proto_probe(self):
        if not self._connected:
            self._set_status("Not connected — connect first, then run Protocol Probe.", C_ERR)
            return
        self._proto_probe_active = True
        self._proto_probe_session_id = datetime.now().strftime("%Y%m%dT%H%M%S") + "-" + uuid4().hex[:8]
        self._btn_proto_probe.configure(state="disabled")
        self._log_event(
            event_type="ui_click",
            source="toolbar",
            action="proto_probe",
            details={
                "session_id": self._proto_probe_session_id,
                "write_uuid": PROTO_PROBE_WRITE_UUID,
                "notify_uuid": PROTO_PROBE_NOTIFY_UUID,
                "frame_count": len(PROTO_PROBE_FRAMES),
                "frame_labels": [lbl for lbl, _ in PROTO_PROBE_FRAMES],
            },
        )
        self._set_status(
            f"Protocol Probe started: subscribing notify channels, then sending {len(PROTO_PROBE_FRAMES)} frames (0.5 s/frame) across primary+secondary channels...",
            C_WARN,
        )
        self._worker.start_proto_probe()

    def _on_device_selected(self, _event=None):
        sel = self._dev_tree.selection()
        if not sel:
            self._selected_device = None
            self._btn_connect.configure(state="disabled")
            return
        entry = self._devices.get(sel[0])
        if entry:
            self._selected_device = entry[0]
            self._btn_connect.configure(state="normal")
            self._log_event(
                event_type="ui_select",
                source="device_tree",
                action="select_device",
                details={
                    "device_name": self._selected_device.name or "",
                    "device_address": self._selected_device.address,
                },
            )

    def _on_char_selected(self, _event=None):
        """Populate the interaction panel when a service-tree row is selected."""
        sel = self._svc_tree.selection()
        if not sel:
            return
        values = self._svc_tree.item(sel[0], "values")
        tags   = self._svc_tree.item(sel[0], "tags")
        if not values:
            return
        uuid = values[0]

        # Service rows – nothing to interact with
        if "service" in tags:
            self._selected_char_uuid = None
            self._sel_char_var.set("— service row (select a characteristic) —")
            self._set_interact_buttons(can_read=False, can_write=False, can_subscribe=False)
            self._log_event(
                event_type="ui_select",
                source="service_tree",
                action="select_service_row",
                details={"uuid": uuid},
            )
            return

        # Descriptor rows – read-only, no write/notify
        if "desc" in tags:
            self._selected_char_uuid = None
            self._sel_char_var.set(f"Descriptor: {uuid}  —  {values[1]}")
            self._set_interact_buttons(can_read=False, can_write=False, can_subscribe=False)
            self._log_event(
                event_type="ui_select",
                source="service_tree",
                action="select_descriptor_row",
                details={"uuid": uuid, "name": values[1]},
            )
            return

        # Characteristic row
        self._selected_char_uuid = uuid
        name = values[1] if len(values) > 1 else ""
        label = f"{uuid}  —  {name}" if name and name != "(unknown)" else uuid
        self._sel_char_var.set(label)

        props_lower = [p.lower() for p in self._char_props.get(uuid, [])]
        # Some stacks expose variants like read-encrypted / write-signed,
        # so we check by prefix, not only exact string matches.
        can_read      = any(p.startswith("read") for p in props_lower)
        can_write     = any(p.startswith("write") for p in props_lower)
        can_subscribe = "notify" in props_lower or "indicate" in props_lower

        self._set_interact_buttons(
            # Keep Read available when connected even if flags are incomplete.
            can_read      = True,
            can_write     = can_write     and self._connected,
            can_subscribe = can_subscribe and self._connected,
        )
        self._log_event(
            event_type="ui_select",
            source="service_tree",
            action="select_characteristic_row",
            details={
                "uuid": uuid,
                "name": name,
                "properties": props_lower,
                "connected": self._connected,
            },
        )

    def _set_interact_buttons(self, can_read: bool, can_write: bool, can_subscribe: bool):
        self._btn_read.configure(state="normal" if can_read else "disabled")
        self._write_entry.configure(state="normal" if can_write else "disabled")
        self._btn_write.configure(state="normal" if can_write else "disabled")
        if can_subscribe:
            subscribed = (self._selected_char_uuid is not None and
                          self._worker.is_subscribed(self._selected_char_uuid))
            self._btn_subscribe.configure(
                state="normal",
                text="Unsubscribe" if subscribed else "Subscribe",
            )
        else:
            self._btn_subscribe.configure(state="disabled", text="Subscribe")

    def _on_read(self):
        if not self._selected_char_uuid:
            return
        self._log_event(
            event_type="ui_click",
            source="interaction_panel",
            action="read",
            details={"uuid": self._selected_char_uuid, "connected": self._connected},
        )
        if not self._connected:
            self._set_status("Not connected.", C_ERR)
            return

        props_lower = [p.lower() for p in self._char_props.get(self._selected_char_uuid, [])]
        if not any(p.startswith("read") for p in props_lower):
            self._set_status("This characteristic may not support Read. Trying anyway...", C_WARN)
        self._worker.start_read(self._selected_char_uuid)

    def _on_write(self):
        if not self._selected_char_uuid:
            return
        raw = self._write_var.get().strip()
        self._log_event(
            event_type="ui_click",
            source="interaction_panel",
            action="write",
            details={"uuid": self._selected_char_uuid, "payload_hex": raw},
        )
        if not raw:
            self._set_status("Enter hex bytes in the write field,  e.g.  01 A2 FF", C_WARN)
            return
        try:
            data = bytes(int(b, 16) for b in raw.split())
        except ValueError:
            self._set_status("Invalid hex bytes.  Example:  01 A2 FF", C_ERR)
            return
        props_lower = [p.lower() for p in self._char_props.get(self._selected_char_uuid, [])]
        # Prefer write-with-response; fall back to write-* variants without response.
        with_response = "write" in props_lower
        self._worker.start_write(self._selected_char_uuid, data, with_response)

    def _on_subscribe(self):
        if not self._selected_char_uuid:
            return
        self._log_event(
            event_type="ui_click",
            source="interaction_panel",
            action="toggle_subscribe",
            details={
                "uuid": self._selected_char_uuid,
                "currently_subscribed": self._worker.is_subscribed(self._selected_char_uuid),
            },
        )
        if self._worker.is_subscribed(self._selected_char_uuid):
            self._worker.start_unsubscribe(self._selected_char_uuid)
        else:
            self._worker.start_subscribe(self._selected_char_uuid)

    def _sort_dev(self, col: str):
        items = [(self._dev_tree.set(k, col), k)
                 for k in self._dev_tree.get_children("")]
        try:
            items.sort(key=lambda t: float(t[0].replace(" dBm", "")))
        except ValueError:
            items.sort(key=lambda t: t[0].lower())
        for idx, (_, k) in enumerate(items):
            self._dev_tree.move(k, "", idx)

    # ── Queue polling ─────────────────────────────────────────────────────────

    def _poll_queue(self):
        # Pull queued worker events in small batches to keep UI updates smooth.
        try:
            while True:
                self._handle_message(self._gui_queue.get_nowait())
        except queue.Empty:
            pass
        self.after(self.POLL_MS, self._poll_queue)

    def _handle_message(self, msg):
        # Single dispatch point for all worker events -> keeps UI state changes centralized.
        if isinstance(msg, MsgStatus):
            self._log_event(
                event_type="worker_status",
                source="worker",
                action="status",
                details={"text": msg.text, "colour": msg.colour},
            )
            self._set_status(msg.text, msg.colour)
        elif isinstance(msg, MsgDeviceFound):
            self._add_device(msg.device, msg.adv)
        elif isinstance(msg, MsgScanDone):
            self._log_event(event_type="worker_event", source="worker", action="scan_done")
            self._btn_scan.configure(state="normal")
        elif isinstance(msg, MsgServiceTree):
            self._log_event(
                event_type="worker_event",
                source="worker",
                action="service_tree_received",
                details={"service_count": len(msg.services)},
            )
            self._populate_service_tree(msg)
            self._save_result_to_json(msg)
        elif isinstance(msg, MsgConnected):
            self._log_event(event_type="worker_event", source="worker", action="connected")
            self._connected = True
            self._btn_disconnect.configure(state="normal")
            self._btn_pair.configure(state="normal")
            self._btn_probe_history.configure(state="normal")
            self._btn_proto_probe.configure(state="normal")
            self._btn_passive_listen.configure(state="normal")
            self._btn_connect.configure(state="disabled")
            # Re-evaluate interaction buttons now that connection is live
            self._on_char_selected()
        elif isinstance(msg, MsgDisconnected):
            self._log_event(event_type="worker_event", source="worker", action="disconnected")
            self._connected = False
            self._probe_active = False
            self._proto_probe_active = False
            self._passive_listen_active = False
            self._btn_disconnect.configure(state="disabled")
            self._btn_pair.configure(state="disabled")
            self._btn_probe_history.configure(state="disabled")
            self._btn_proto_probe.configure(state="disabled")
            self._btn_passive_listen.configure(state="disabled")
            self._btn_connect.configure(
                state="normal" if self._selected_device else "disabled")
            # Keep Read enabled for selected characteristic so user can retry
            # after reconnect and gets explicit feedback when not connected.
            self._on_char_selected()
            self._set_status("Disconnected by device. Reconnect to continue Read/Write/Subscribe.", C_WARN)
        elif isinstance(msg, MsgConnectError):
            self._log_event(
                event_type="worker_error",
                source="worker",
                action="connect_error",
                details={"error": msg.error},
            )
            self._connected = False
            self._probe_active = False
            self._proto_probe_active = False
            self._passive_listen_active = False
            self._btn_probe_history.configure(state="disabled")
            self._btn_proto_probe.configure(state="disabled")
            self._btn_passive_listen.configure(state="disabled")
            self._set_status(f"Error: {msg.error}", C_ERR)
            messagebox.showerror("Connection Error", msg.error)
            self._btn_connect.configure(
                state="normal" if self._selected_device else "disabled")
        elif isinstance(msg, MsgCharValue):
            self._log_event(
                event_type="worker_result",
                source="worker",
                action="read_result",
                details={"uuid": msg.uuid, "bytes": len(msg.data)},
            )
            self._show_char_value(msg.uuid, msg.data, label="Read")
        elif isinstance(msg, MsgNotification):
            self._log_event(
                event_type="worker_result",
                source="worker",
                action="notification",
                details={"uuid": msg.uuid, "bytes": len(msg.data)},
            )
            self._show_char_value(msg.uuid, msg.data, label="Notify")
            if self._probe_active:
                self._append_probe_log(direction="rx_notify", uuid=msg.uuid, data=msg.data)
            if self._proto_probe_active:
                self._append_proto_log(entry_type="rx_notify", uuid=msg.uuid, data=msg.data)
            if self._passive_listen_active:
                self._append_passive_log(entry_type="rx_notify", uuid=msg.uuid, data=msg.data)
        elif isinstance(msg, MsgWriteOk):
            self._log_event(
                event_type="worker_result",
                source="worker",
                action="write_ok",
                details={"uuid": msg.uuid},
            )
            self._set_status(f"Write OK  →  {msg.uuid}", C_OK)
        elif isinstance(msg, MsgProbeTx):
            self._log_event(
                event_type="worker_result",
                source="worker",
                action="probe_tx",
                details={"uuid": msg.uuid, "bytes": len(msg.data)},
            )
            self._append_probe_log(direction="tx", uuid=msg.uuid, data=msg.data)
        elif isinstance(msg, MsgProbeDone):
            self._log_event(
                event_type="worker_event",
                source="worker",
                action="probe_done",
                details={
                    "sent_frames": msg.sent_frames,
                    "notify_channels_active": msg.notify_channels_active,
                    "session_id": self._probe_session_id,
                },
            )
            self._probe_active = False
            self._btn_probe_history.configure(state="normal" if self._connected else "disabled")
            self._set_status(
                f"Probe complete: sent {msg.sent_frames} frame(s), active notify channel(s): {msg.notify_channels_active}.",
                C_OK,
            )
        elif isinstance(msg, MsgProtoCharRead):
            self._log_event(
                event_type="worker_result",
                source="worker",
                action="proto_char_read",
                details={"uuid": msg.uuid, "bytes": len(msg.data)},
            )
            self._append_proto_log(entry_type="char_read", uuid=msg.uuid, data=msg.data)
            self._show_char_value(msg.uuid, msg.data, label="Proto-Read")
        elif isinstance(msg, MsgProtoTx):
            self._log_event(
                event_type="worker_result",
                source="worker",
                action="proto_tx",
                details={"label": msg.label, "uuid": msg.uuid, "bytes": len(msg.data)},
            )
            self._append_proto_log(entry_type="tx", uuid=msg.uuid, data=msg.data, label=msg.label)
        elif isinstance(msg, MsgProtoProbeDone):
            disc = msg.disconnect_frame or "none"
            self._log_event(
                event_type="worker_event",
                source="worker",
                action="proto_probe_done",
                details={
                    "frames_sent": msg.frames_sent,
                    "responses_received": msg.responses_received,
                    "disconnect_frame": disc,
                    "session_id": self._proto_probe_session_id,
                },
            )
            self._proto_probe_active = False
            self._btn_proto_probe.configure(state="normal" if self._connected else "disabled")
            rx = msg.responses_received
            colour = C_OK if rx > 0 else C_WARN
            disc_note = f"  |  disconnect on: {disc}" if disc != "none" else ""
            self._set_status(
                f"Protocol Probe complete: {msg.frames_sent} sent, {rx} notify response(s){disc_note}.",
                colour,
            )
        elif isinstance(msg, MsgPassiveListenDone):
            rx = msg.notifications_received
            self._log_event(
                event_type="worker_event",
                source="worker",
                action="passive_listen_done",
                details={
                    "duration_s": msg.duration_s,
                    "notifications_received": rx,
                    "session_id": self._passive_listen_session_id,
                },
            )
            self._passive_listen_active = False
            self._btn_passive_listen.configure(state="normal" if self._connected else "disabled")
            colour = C_OK if rx > 0 else C_WARN
            self._set_status(
                f"Passive Listen complete: {rx} notification(s) received in {msg.duration_s} s.",
                colour,
            )
        elif isinstance(msg, MsgSubscribed):
            self._log_event(
                event_type="worker_result",
                source="worker",
                action="subscribed",
                details={"uuid": msg.uuid},
            )
            self._update_subscribed_tag(msg.uuid, subscribed=True)
            self._btn_subscribe.configure(text="Unsubscribe")
            self._set_status(f"Subscribed  →  {msg.uuid}", C_OK)
        elif isinstance(msg, MsgUnsubscribed):
            self._log_event(
                event_type="worker_result",
                source="worker",
                action="unsubscribed",
                details={"uuid": msg.uuid},
            )
            self._update_subscribed_tag(msg.uuid, subscribed=False)
            self._btn_subscribe.configure(text="Subscribe")
            self._set_status(f"Unsubscribed  →  {msg.uuid}", C_INFO)
        elif isinstance(msg, MsgPaired):
            self._log_event(event_type="worker_event", source="worker", action="paired")
            self._btn_pair.configure(state="normal")
            self._set_status("Paired / bonded successfully. Connection should now stay stable.", C_OK)
        elif isinstance(msg, MsgPairError):
            self._log_event(
                event_type="worker_error",
                source="worker",
                action="pair_error",
                details={"error": msg.error},
            )
            self._btn_pair.configure(state="normal" if self._connected else "disabled")
            self._set_status(f"Pair error: {msg.error}", C_ERR)

    # ── Device list ───────────────────────────────────────────────────────────

    def _add_device(self, device: BLEDevice, adv: AdvertisementData):
        rssi = adv.rssi if adv.rssi is not None else -999
        name = device.name or ""

        if rssi >= -60:
            rssi_tag = "rssi_good"
        elif rssi >= -80:
            rssi_tag = "rssi_ok"
        else:
            rssi_tag = "rssi_weak"

        tags = (rssi_tag,) if name else (rssi_tag, "no_name")
        display_name = name if name else "(no name)"
        rssi_str = f"{rssi} dBm" if rssi != -999 else "?"
        addr = device.address

        if addr in self._devices:
            iid = self._devices[addr][2]
            self._dev_tree.item(iid, values=(display_name, addr, rssi_str),
                                tags=tags)
        else:
            iid = self._dev_tree.insert("", "end", iid=addr,
                                         values=(display_name, addr, rssi_str),
                                         tags=tags)
        self._devices[addr] = (device, adv, iid)

    # ── Service tree ──────────────────────────────────────────────────────────

    def _clear_service_tree(self):
        for item in self._svc_tree.get_children():
            self._svc_tree.delete(item)

    def _iter_svc_tree(self):
        """Yield every item ID in the service tree (recursive DFS)."""
        def recurse(parent):
            for child in self._svc_tree.get_children(parent):
                yield child
                yield from recurse(child)
        yield from recurse("")

    def _populate_service_tree(self, msg: MsgServiceTree):
        self._clear_service_tree()
        self._char_props.clear()
        for svc in msg.services:
            known_svc = svc.name != "(vendor-specific)"
            svc_tags = ("service", "known_svc" if known_svc else "unknown_svc")
            svc_node = self._svc_tree.insert(
                "", "end",
                values=(svc.uuid, svc.name, f"handle={svc.handle}"),
                tags=svc_tags,
                open=True,
            )
            for char in svc.characteristics:
                # Store properties for later use by the interaction panel
                self._char_props[char.uuid] = char.props
                known_char = char.name != "(unknown)"
                char_tags = ("known_char" if known_char else "unknown_char",)
                props_str = "  ".join(p.capitalize() for p in char.props)
                char_node = self._svc_tree.insert(
                    svc_node, "end",
                    values=(char.uuid, char.name, props_str),
                    tags=char_tags,
                )
                for desc in char.descriptors:
                    self._svc_tree.insert(
                        char_node, "end",
                        values=(desc.uuid, desc.name, "descriptor"),
                        tags=("desc",),
                    )
        total = len(msg.services)
        self._set_status_segments([
            (f"Found {total} service(s).   ", "black"),
            ("■ standard service",            C_OK),
            ("   ■ standard characteristic",  C_INFO),
            ("   ■ vendor-specific/unknown",  "gray"),
            ("   ■ subscribed",               C_SUB),
        ])

    def _update_subscribed_tag(self, uuid: str, subscribed: bool):
        """Mark or unmark a characteristic row with the 'subscribed' colour."""
        for item in self._iter_svc_tree():
            vals = self._svc_tree.item(item, "values")
            if vals and vals[0] == uuid:
                tags = list(self._svc_tree.item(item, "tags"))
                for t in ("known_char", "unknown_char", "subscribed"):
                    if t in tags:
                        tags.remove(t)
                if subscribed:
                    tags.append("subscribed")
                else:
                    known = bool(self._char_props.get(uuid))
                    tags.append("known_char" if known else "unknown_char")
                self._svc_tree.item(item, tags=tags)
                break

    # ── Characteristic value display ──────────────────────────────────────────

    def _show_char_value(self, uuid: str, data: bytes, label: str = "Value"):
        """Display raw bytes as HEX, printable ASCII and decimal."""
        hex_str   = " ".join(f"{b:02X}" for b in data)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        dec_str   = " ".join(str(b) for b in data)
        self._log_event(
            event_type="value_display",
            source="ui",
            action="show_value",
            details={
                "label": label,
                "uuid": uuid,
                "hex": hex_str,
                "ascii": ascii_str,
                "dec": dec_str,
            },
        )
        ts = datetime.now().strftime("%H:%M:%S")
        self._val_text.configure(state="normal")
        self._val_text.delete("1.0", "end")
        self._val_text.insert("end", f"[{ts}]  {label}  ←  {uuid}\n")
        self._val_text.insert("end", f"HEX    {hex_str}\n")
        self._val_text.insert("end", f"ASCII  {ascii_str}     DEC  {dec_str}")
        self._val_text.configure(state="disabled")
        self._set_status(
            f"{label} ← {uuid}  ({len(data)} byte{'s' if len(data) != 1 else ''})", C_OK)

    # ── JSON persistence ──────────────────────────────────────────────────────

    def _save_result_to_json(self, msg: MsgServiceTree):
        # Persist every successful read so unknown UUIDs can be inspected later.
        if self._selected_device is None:
            return

        entry = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "device": {
                "name": self._selected_device.name or "",
                "address": self._selected_device.address,
            },
            "services": [],
        }

        for svc in msg.services:
            svc_data = {
                "uuid": svc.uuid,
                "name": svc.name,
                "handle": svc.handle,
                "characteristics": [],
            }
            for char in svc.characteristics:
                char_data = {
                    "uuid": char.uuid,
                    "name": char.name,
                    "properties": char.props,
                    "descriptors": [],
                }
                for desc in char.descriptors:
                    char_data["descriptors"].append({
                        "uuid": desc.uuid,
                        "name": desc.name,
                    })
                svc_data["characteristics"].append(char_data)
            entry["services"].append(svc_data)

        payload = {"history": []}
        if self._log_path.exists():
            try:
                payload = json.loads(self._log_path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict) or "history" not in payload:
                    payload = {"history": []}
            except (json.JSONDecodeError, OSError):
                payload = {"history": []}

        payload["history"].append(entry)
        # Keep history bounded to avoid unbounded growth over time.
        payload["history"] = payload["history"][-200:]

        try:
            self._log_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self._log_event(
                event_type="file_log",
                source="json_history",
                action="saved_scan_result",
                details={
                    "file": self._log_path.name,
                    "entries": len(payload["history"]),
                    "device_address": self._selected_device.address,
                },
            )
            self._set_status(
                f"Saved result to {self._log_path.name} (entries: {len(payload['history'])}).",
                C_INFO,
            )
        except OSError as exc:
            self._log_event(
                event_type="file_error",
                source="json_history",
                action="save_failed",
                details={"error": str(exc)},
            )
            self._set_status(f"Could not save JSON log: {exc}", C_ERR)

    # ── Clipboard / context menu ──────────────────────────────────────────────

    def _copy_selected_uuid(self):
        # The first visible column stores UUID for service/char/descriptor rows.
        sel = self._svc_tree.selection()
        if not sel:
            self._set_status("Select a service/characteristic/descriptor row first.", C_WARN)
            return

        values = self._svc_tree.item(sel[0], "values")
        if not values:
            self._set_status("Selected row has no UUID to copy.", C_WARN)
            return

        uuid = values[0]
        if not uuid:
            self._set_status("Selected row has no UUID to copy.", C_WARN)
            return

        self.clipboard_clear()
        self.clipboard_append(uuid)
        self.update_idletasks()
        self._log_event(
            event_type="ui_click",
            source="context_menu",
            action="copy_uuid",
            details={"uuid": uuid},
        )
        self._set_status(f"Copied UUID: {uuid}", C_INFO)

    def _show_svc_context_menu(self, event):
        row = self._svc_tree.identify_row(event.y)
        if row:
            self._svc_tree.selection_set(row)
        self._log_event(event_type="ui_click", source="service_tree", action="open_context_menu")
        self._svc_menu.tk_popup(event.x_root, event.y_root)

    def _log_event(self, event_type: str, source: str, action: str,
                   details: Optional[dict] = None):
        """Append a single app event record as JSONL for debugging and audit."""
        entry = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "event_type": event_type,
            "source": source,
            "action": action,
            "details": details or {},
        }
        try:
            with self._event_log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            # Logging must never break UI flow.
            pass

    def _append_probe_log(self, direction: str, uuid: str, data: bytes):
        """Append raw probe traffic (TX/RX) to a dedicated JSONL file."""
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        entry = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "session_id": self._probe_session_id,
            "device": {
                "name": (self._selected_device.name if self._selected_device else "") or "",
                "address": self._selected_device.address if self._selected_device else "",
            },
            "direction": direction,
            "uuid": uuid,
            "bytes": len(data),
            "hex": " ".join(f"{b:02X}" for b in data),
            "ascii": ascii_str,
            "dec": " ".join(str(b) for b in data),
        }
        try:
            with self._probe_log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _append_proto_log(self, entry_type: str, uuid: str, data: bytes,
                          label: Optional[str] = None):
        """Append one protocol-probe entry (char_read / tx / rx_notify) to the JSONL log."""
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        entry: dict = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "session_id": self._proto_probe_session_id,
            "device": {
                "name": (self._selected_device.name if self._selected_device else "") or "",
                "address": self._selected_device.address if self._selected_device else "",
            },
            "type": entry_type,
            "uuid": uuid,
            "bytes": len(data),
            "hex": " ".join(f"{b:02X}" for b in data),
            "ascii": ascii_str,
            "dec": " ".join(str(b) for b in data),
        }
        if label is not None:
            entry["label"] = label
        try:
            with self._proto_probe_log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _append_passive_log(self, entry_type: str, uuid: str, data: bytes):
        """Append one passive-listen entry (rx_notify) to the JSONL log."""
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        entry: dict = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "session_id": self._passive_listen_session_id,
            "device": {
                "name": (self._selected_device.name if self._selected_device else "") or "",
                "address": self._selected_device.address if self._selected_device else "",
            },
            "type": entry_type,
            "uuid": uuid,
            "bytes": len(data),
            "hex": " ".join(f"{b:02X}" for b in data),
            "ascii": ascii_str,
            "dec": " ".join(str(b) for b in data),
        }
        try:
            with self._passive_log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

    # ── Status bar ────────────────────────────────────────────────────────────

    def _set_status_segments(self, segments: list[tuple[str, str]]):
        """Render status bar as coloured segments: [(text, colour), ...]."""
        for w in self._status_bar.winfo_children():
            w.destroy()
        for text, colour in segments:
            ttk.Label(
                self._status_bar, text=text, foreground=colour,
                anchor="w", font=("Segoe UI", 9),
            ).pack(side="left")

    def _set_status(self, text: str, colour: str = "black"):
        self._set_status_segments([(text, colour)])


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    App().mainloop()
