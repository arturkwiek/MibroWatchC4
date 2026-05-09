import asyncio
from bleak import BleakScanner

async def scan():
    devices = await BleakScanner.discover(timeout=6.0, return_adv=True)
    for addr, (dev, adv) in devices.items():
        if "10:7B:93:CE:B5:1F" in addr.upper():
            print("=== Mibro Watch C4 Advertising Data ===")
            print(f"Name:          {dev.name}")
            print(f"RSSI:          {adv.rssi}")
            print(f"Local name:    {adv.local_name}")
            print(f"TX power:      {adv.tx_power}")
            print(f"Service UUIDs: {adv.service_uuids}")
            if adv.manufacturer_data:
                print("Manufacturer data:")
                for company_id, mfr_bytes in adv.manufacturer_data.items():
                    b = bytes(mfr_bytes)
                    print(f"  Company 0x{company_id:04X}: {b.hex(' ').upper()}")
                    print(f"  ASCII:         {b!r}")
            if adv.service_data:
                print("Service data:")
                for uuid, sdata in adv.service_data.items():
                    print(f"  {uuid}: {bytes(sdata).hex(' ').upper()}")
            print(f"Platform data: {adv.platform_data}")

asyncio.run(scan())
