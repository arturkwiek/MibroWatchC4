import asyncio
from bleak import BleakClient

TARGET = "10:7B:93:CE:B5:1F"

async def read_all():
    async with BleakClient(TARGET, timeout=30.0) as c:
        print(f"Connected: {c.is_connected}")
        for svc in c.services:
            print(f"\nSvc {svc.uuid}  ({svc.description})")
            for ch in svc.characteristics:
                sep = ",".join(ch.properties)
                print(f"  Char {ch.uuid[-8:]}  [{sep}]")
                if "read" in ch.properties:
                    try:
                        val = bytes(await c.read_gatt_char(ch.uuid))
                        print(f"    READ OK: {val.hex(' ').upper()!r}  ascii={val!r}")
                    except Exception as e:
                        print(f"    READ ERR: {e}")
                for desc in ch.descriptors:
                    try:
                        dval = bytes(await c.read_gatt_descriptor(desc.handle))
                        print(f"    Desc {desc.uuid[-8:]}  val={dval.hex(' ').upper()!r}")
                    except Exception as e:
                        print(f"    Desc {desc.uuid[-8:]}  ERR: {e}")

asyncio.run(read_all())
