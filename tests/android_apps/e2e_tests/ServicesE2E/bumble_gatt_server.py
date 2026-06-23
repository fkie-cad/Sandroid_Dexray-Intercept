"""
Minimal GATT server connecting to Android emulator via netsim.
Presents a virtual BLE peripheral at address F0:F1:F2:F3:F4:F5
with one readable/writable characteristic for BT-1 hook testing.
"""
import asyncio
import logging

from bumble.device import Device
from bumble.transport import open_transport
from bumble.gatt import Service, Characteristic
from bumble.core import UUID

DEVICE_ADDRESS = "F0:F1:F2:F3:F4:F5"
SERVICE_UUID   = UUID("12345678-1234-5678-1234-56789abcdef0")
CHAR_UUID      = UUID("00001101-0000-1000-8000-00805F9B34FB")
CHAR_VALUE     = bytes([0x01, 0x02, 0x03, 0x04])

async def main():
    print(f"Connecting to netsim...")
    async with await open_transport("android-netsim") as transport:
        device = Device.with_hci(
            name="Bumble E2E",
            address=DEVICE_ADDRESS,
            hci_source=transport.source,
            hci_sink=transport.sink,
        )

        characteristic = Characteristic(
            uuid=CHAR_UUID,
            properties=(
                Characteristic.Properties.READ |
                Characteristic.Properties.WRITE
            ),
            permissions=(
                Characteristic.READABLE |
                Characteristic.WRITEABLE
            ),
            value=CHAR_VALUE,
        )

        device.add_services([Service(SERVICE_UUID, [characteristic])])

        await device.power_on()

        @device.on('connection')
        def on_connection(connection):
            print(f"Connected: {connection}")

        @device.on('disconnection')
        def on_disconnection(connection, reason):
            print(f"Disconnected: {connection}, reason={reason}")

        await device.start_advertising(auto_restart=True)

        print(f"GATT server advertising at {DEVICE_ADDRESS}")
        print("Waiting for connections - Ctrl+C to stop")

        await asyncio.get_event_loop().create_future()  # run until interrupted

asyncio.run(main())