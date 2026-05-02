"""Desktop GUI for BLE service discovery.

Architecture overview:
- App (tk main thread): handles rendering, user actions, and clipboard/menu.
- AsyncWorker (background thread): handles BLE I/O through bleak/asyncio.
- Queue messages: the only bridge between worker and UI, which keeps the GUI responsive.
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

# Internal messages passed between async thread and GUI thread

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


# Async worker running in a background thread

class AsyncWorker:
    """Runs BLE operations in a dedicated asyncio loop on a daemon thread."""

    def __init__(self, gui_queue: queue.Queue):
        self._q = gui_queue
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        self._loop.run_forever()

    def submit(self, coro):
        asyncio.run_coroutine_threadsafe(coro, self._loop)

    def start_scan(self, timeout: float):
        self.submit(self._scan(timeout))

    def start_connect(self, device: BLEDevice):
        self.submit(self._connect(device))

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

    async def _connect(self, device: BLEDevice):
        self._q.put(MsgStatus(
            f"Connecting to {device.name or device.address}...", C_WARN))
        try:
            async with BleakClient(device) as client:
                if not client.is_connected:
                    self._q.put(MsgConnectError("Connection failed."))
                    return

                self._q.put(MsgStatus(
                    f"Connected  OK  {device.name or device.address}", C_OK))
                msg = MsgServiceTree()

                for svc in client.services:
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
        except Exception as exc:
            self._q.put(MsgConnectError(str(exc)))
            self._q.put(MsgStatus(f"Connection error: {exc}", C_ERR))


# Main GUI

class App(tk.Tk):
    """Main desktop window coordinating scan/connect and results presentation."""
    POLL_MS = 80

    def __init__(self):
        super().__init__()
        self.title("BLE Service Explorer")
        self.geometry("1100x700")
        self.minsize(820, 520)

        self._gui_queue: queue.Queue = queue.Queue()
        self._worker = AsyncWorker(self._gui_queue)
        self._log_path = Path(__file__).with_name("ble_scan_history.json")

        # address -> (BLEDevice, AdvertisementData, treeview_iid)
        self._devices: dict[str, tuple[BLEDevice, AdvertisementData, str]] = {}
        self._selected_device: Optional[BLEDevice] = None

        self._build_styles()
        self._build_ui()
        self._poll_queue()

    def _build_styles(self):
        style = ttk.Style(self)
        for theme in ("vista", "winnative", "xpnative", "clam"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Treeview", rowheight=22)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        # Menu bar
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

        # Toolbar
        toolbar = ttk.Frame(self, relief="raised", padding=(4, 3))
        toolbar.pack(fill="x", side="top")

        self._btn_scan = ttk.Button(
            toolbar, text="Scan  (F5)", width=11, command=self._on_scan)
        self._btn_scan.pack(side="left", padx=(0, 4))

        self._btn_connect = ttk.Button(
            toolbar, text="Connect", width=10,
            command=self._on_connect, state="disabled")
        self._btn_connect.pack(side="left", padx=(0, 12))

        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=6)

        ttk.Label(toolbar, text="Scan time (s):").pack(side="left", padx=(0, 4))
        self._timeout_var = tk.DoubleVar(value=10.0)
        ttk.Spinbox(toolbar, from_=3, to=60, increment=1,
                    textvariable=self._timeout_var, width=5).pack(side="left")

        # Main area
        main = ttk.Frame(self, padding=(6, 4))
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=3)
        main.rowconfigure(0, weight=1)

        # Left: device list
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

        # Right: service tree
        lf_svc = ttk.LabelFrame(
            main, text="Services & Characteristics", padding=(4, 4))
        lf_svc.grid(row=0, column=1, sticky="nsew")
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

        self._svc_tree.tag_configure("service",      font=("Segoe UI", 9, "bold"))
        self._svc_tree.tag_configure("known_svc",    foreground=C_OK)
        self._svc_tree.tag_configure("unknown_svc",  foreground="gray")
        self._svc_tree.tag_configure("known_char",   foreground=C_INFO)
        self._svc_tree.tag_configure("unknown_char", foreground="gray")
        self._svc_tree.tag_configure("desc",         foreground="gray",
                                      font=("Segoe UI", 8))

        self._svc_menu = tk.Menu(self, tearoff=False)
        self._svc_menu.add_command(label="Copy UUID", command=self._copy_selected_uuid)

        # Status bar
        status_bar = ttk.Frame(self, relief="sunken", padding=(4, 2))
        status_bar.pack(fill="x", side="bottom")

        self._status_var = tk.StringVar(
            value="Ready -- press  Scan  to discover nearby BLE devices.")
        self._status_lbl = ttk.Label(
            status_bar, textvariable=self._status_var,
            anchor="w", font=("Segoe UI", 9))
        self._status_lbl.pack(side="left", fill="x", expand=True)

    # Event handlers

    def _on_scan(self):
        for item in self._dev_tree.get_children():
            self._dev_tree.delete(item)
        self._clear_service_tree()
        self._devices.clear()
        self._selected_device = None
        self._btn_connect.configure(state="disabled")
        self._btn_scan.configure(state="disabled")
        timeout = max(3.0, float(self._timeout_var.get()))
        self._worker.start_scan(timeout)

    def _on_connect(self):
        if self._selected_device is None:
            return
        self._clear_service_tree()
        self._btn_connect.configure(state="disabled")
        self._worker.start_connect(self._selected_device)

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

    def _sort_dev(self, col: str):
        items = [(self._dev_tree.set(k, col), k)
                 for k in self._dev_tree.get_children("")]
        try:
            items.sort(key=lambda t: float(t[0].replace(" dBm", "")))
        except ValueError:
            items.sort(key=lambda t: t[0].lower())
        for idx, (_, k) in enumerate(items):
            self._dev_tree.move(k, "", idx)

    # Queue polling

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
            self._set_status(msg.text, msg.colour)
        elif isinstance(msg, MsgDeviceFound):
            self._add_device(msg.device, msg.adv)
        elif isinstance(msg, MsgScanDone):
            self._btn_scan.configure(state="normal")
        elif isinstance(msg, MsgServiceTree):
            self._populate_service_tree(msg)
            self._save_result_to_json(msg)
        elif isinstance(msg, MsgConnectError):
            self._set_status(f"Error: {msg.error}", C_ERR)
            messagebox.showerror("Connection Error", msg.error)
            self._btn_connect.configure(state="normal")

    # Device list

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

    # Service tree

    def _clear_service_tree(self):
        for item in self._svc_tree.get_children():
            self._svc_tree.delete(item)

    def _populate_service_tree(self, msg: MsgServiceTree):
        self._clear_service_tree()
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
        self._set_status(
            f"Found {total} service(s).   "
            "Green = standard GATT service   "
            "Blue = standard characteristic   "
            "Grey = vendor-specific / unknown",
            C_OK,
        )

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
            self._set_status(
                f"Saved result to {self._log_path.name} (entries: {len(payload['history'])}).",
                C_INFO,
            )
        except OSError as exc:
            self._set_status(f"Could not save JSON log: {exc}", C_ERR)

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
        self._set_status(f"Copied UUID: {uuid}", C_INFO)

    def _show_svc_context_menu(self, event):
        row = self._svc_tree.identify_row(event.y)
        if row:
            self._svc_tree.selection_set(row)
        self._svc_menu.tk_popup(event.x_root, event.y_root)

    # Status bar

    def _set_status(self, text: str, colour: str = "black"):
        self._status_var.set(text)
        self._status_lbl.configure(foreground=colour)


# Entry point

if __name__ == "__main__":
    App().mainloop()
