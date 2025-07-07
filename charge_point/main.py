import asyncio
import ssl
import configparser
from ocpp.v201 import ChargePoint as cp
from ocpp.v201 import call
import websockets
import base64
from ocpp.v201.enums import RegistrationStatusEnumType
import random
import datetime
import secrets
import string

from password_store import store_password, load_password

# --- CONFIGURATION ---

CP_IDENTITY_KEY = "id"
CP_SECTION = "CHARGE_POINT"
CSMS_URL_KEY = "url"
CSMS_SECTION = "CSMS"

def generate_password(length=24):
    # Allowed: alphanumeric and special chars in OCPP passwordString
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def ensure_dynamic_password(config):
    cp_id = config.get(CP_SECTION, CP_IDENTITY_KEY, fallback='CP001')
    cp_password = load_password()  # <-- ENCRYPTED LOAD
    # Only use local password file, no REST registration
    if not cp_password:
        cp_password = generate_password()
        print(f"[CP] Generated password for {cp_id}.")
        store_password(cp_password)  # <-- ENCRYPTED SAVE
    return cp_id, cp_password

class ChargePoint(cp):
    def __init__(self, charge_point_id, websocket):
        super().__init__(charge_point_id, websocket)
        self.connected = False

    async def send_boot_notification(self):
        await asyncio.sleep(1)  # small delay to ensure session is up
        request = call.BootNotification(
            charging_station={
                'model': 'SecureWallbox XYZ',
                'vendor_name': 'SecureEV'
            },
            reason="PowerUp"
        )
        try:
            response = await self.call(request)
            if response is None:
                print("Boot Notification failed: No response received (possible CallError from CSMS)")
                return
            print(f"Boot Notification Response: {response}")
            if hasattr(response, 'status') and response.status == RegistrationStatusEnumType.accepted:
                self.connected = True
                print("Successfully registered with CSMS")
            else:
                print(f"Registration failed with status: {getattr(response, 'status', 'Unknown')}")
        except Exception as e:
            print(f"Error during Boot Notification: {e}")

    async def send_meter_values(self):
        while not self.connected:
            await asyncio.sleep(1)
        while self.connected:
            await asyncio.sleep(10)
            try:
                meter_value = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'sampledValue': [{
                        'value': random.randint(100, 5000)/100,
                        'measurand': 'Power.Active.Import',
                        'unitOfMeasure': {'unit': 'kW'}
                    }]
                }
                request = call.MeterValues(
                    evse_id=1,
                    meter_value=[meter_value]
                )
                await self.call(request)
                print(f"Sent meter value: {meter_value['sampledValue'][0]['value']} kW")
            except Exception as e:
                print(f"Error sending meter values: {e}")
                self.connected = False

async def main():
    config = configparser.ConfigParser()
    config.read('config.ini')

    # --- Dynamic credential handling ---
    cp_id, cp_password = ensure_dynamic_password(config)
    base_url = config.get(CSMS_SECTION, CSMS_URL_KEY, fallback='wss://localhost:9000')
    csms_url = f"{base_url.rstrip('/')}/{cp_id}"

    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile='certs/ca.crt')
    ssl_context.load_cert_chain(certfile='certs/client.crt', keyfile='certs/client.key') 
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    auth_string = f"{cp_id}:{cp_password}"
    auth_header = f"Basic {base64.b64encode(auth_string.encode()).decode()}"

    while True:
        try:
            print(f"Connecting to CSMS at {csms_url}...")
            async with websockets.connect(
                csms_url,
                subprotocols=['ocpp2.0.1'],
                ssl=ssl_context,
                extra_headers={"Authorization": auth_header}
            ) as ws:
                print("WebSocket connection established")
                cp_obj = ChargePoint(cp_id, ws)

                await asyncio.gather(
                    cp_obj.start(),
                    cp_obj.send_boot_notification(),
                    cp_obj.send_meter_values()
                )

        except websockets.exceptions.InvalidStatusCode as e:
            print(f"Connection failed with status code {e.status_code}")
            if e.status_code == 401:
                print("Authentication failed - check your credentials")
            await asyncio.sleep(5)
        except Exception as e:
            print(f"Connection error: {e}")
            await asyncio.sleep(5)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Charge point stopped by user.")