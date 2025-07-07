import asyncio
import ssl
import configparser
import websockets
from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import base64
import datetime
from ocpp.v201 import ChargePoint as OcppChargePoint
from ocpp.v201 import call_result
from ocpp.routing import on
import re 

# --- secure DB-backed authentication ---
from csms_db import create_table, check_basic_auth, add_cp, cp_exists

flask_app = Flask(__name__)
socketio = SocketIO(flask_app, async_mode='threading')
flask_app.config['SECRET_KEY'] = 'your-secret-key'

# Ensure DB table exists at startup
create_table()

# Store latest meter values per charge point
latest_meter_values = {}

class MyChargePoint(OcppChargePoint):
    @on("BootNotification")
    async def on_boot_notification(self, charging_station, reason, **kwargs):
        print(f"BootNotification received from {self.id}")
        socketio.emit('security_event', {
            "timestamp": datetime.datetime.now().isoformat(),
            "charge_point_id": self.id,
            "event_type": "BootNotification",
            "severity": "Info"
        })
        return call_result.BootNotification(
            current_time=datetime.datetime.utcnow().isoformat(),
            interval=10,
            status="Accepted"
        )

    @on("MeterValues")
    async def on_meter_values(self, evse_id, meter_value, **kwargs):
        def format_meter_values(meter_value):
            formatted = []
            for val in meter_value:
                ts = val.get('timestamp', '')
                samples = val.get('sampledValue', [])
                for s in samples:
                    value = s.get('value', '')
                    measurand = s.get('measurand', '')
                    unit = (s.get('unitOfMeasure') or {}).get('unit', '')
                    formatted.append(f"{measurand or ''}: {value} {unit or ''} at {ts}")
            return "; ".join(formatted) if formatted else "No values"

        print(f"MeterValues received from {self.id} | EVSE ID: {evse_id} | meter_value: {meter_value}")
        socketio.emit('security_event', {
            "timestamp": datetime.datetime.now().isoformat(),
            "charge_point_id": self.id,
            "event_type": "MeterValues",
            "severity": "Info",
            "details": format_meter_values(meter_value)
        })
        # --- Emit meter_value event for dashboard ---
        socketio.emit('meter_value', {
            "charge_point_id": self.id,
            "timestamp": datetime.datetime.now().isoformat(),
            "value": meter_value
        })
        latest_meter_values[self.id] = {
            "timestamp": datetime.datetime.now().isoformat(),
            "value": meter_value
        }
        return call_result.MeterValues()

class CentralSystem:
    def __init__(self):
        self.connected_chargers = {}

    def _emit_security_event(self, charge_point_id, event_type, severity, details):
        socketio.emit('security_event', {
            "timestamp": datetime.datetime.now().isoformat(),
            "charge_point_id": charge_point_id,
            "event_type": event_type,
            "severity": severity,
            "details": details
        })

    async def on_connect(self, websocket, path):
        charge_point_id = path.strip('/')
        if not charge_point_id:
            print("WARNING: Charge point connected without an ID in the URL path! Example: wss://host:port/CP001")
            charge_point_id = "UnknownCP"

        headers = websocket.request_headers
        auth_valid = False
        username = None

        # --- TLS Security Check and Event Emission ---
        ssl_object = websocket.transport.get_extra_info('ssl_object')
        if ssl_object:
            cipher = ssl_object.cipher()
            protocol = ssl_object.version() if hasattr(ssl_object, "version") else "Unknown"
            peercert = ssl_object.getpeercert()
            cert_subject = ""
            if peercert and "subject" in peercert and peercert["subject"]:
                 cert_subject = ", ".join(f"{attr[0]}={attr[1]}" for rdn in peercert["subject"] for attr in rdn if len(attr) == 2)

            # -- Allow TLSv1.2 and anything above (e.g., TLSv1.3, TLSv2.0) --
            version_num = None
            if protocol and protocol.startswith("TLSv"):
                match = re.match(r"TLSv(\d+)\.(\d+)", protocol)
                if match:
                    major, minor = int(match.group(1)), int(match.group(2))
                    version_num = major + minor / 10.0
            if not version_num or version_num < 1.2:
                self._emit_security_event(
                    charge_point_id,
                    "InvalidTLSVersion",
                    "Error",
                    f"Rejected connection with protocol {protocol}"
                )
                await websocket.close()
                return

            # Check cipher suite (OCPP profile 2 required ciphers for TLS 1.2 only)
            allowed_ciphers_tls12 = [
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-ECDSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES256-GCM-SHA384"
            ]
            if protocol.startswith("TLSv1.2"):
                if cipher[0] not in allowed_ciphers_tls12:
                    self._emit_security_event(
                        charge_point_id,
                        "InvalidTLSCipherSuite",
                        "Error",
                        f"Rejected connection with cipher {cipher[0]}"
                    )
                    await websocket.close()
                    return
            # For TLSv1.3 and above, accept the negotiated cipher (do not reject)
            self._emit_security_event(
                charge_point_id,
                "TLS Connection Secure",
                "Success",
                f"TLS {protocol}, Cipher: {cipher[0]}, Certificate Subject: {cert_subject}"
            )
        else:
            self._emit_security_event(
                charge_point_id,
                "Unsecure Connection Attempt",
                "Warning",
                "No SSL/TLS encryption"
            )
            await websocket.close()
            return

        if "Authorization" not in headers:
            print(f"[{charge_point_id}] Missing Authorization header.")
            self._emit_security_event(
                charge_point_id,
                "InvalidAuthentication",
                "Error",
                "Missing Authorization header"
            )
            await websocket.close()
            return

        try:
            auth_type, auth_string = headers["Authorization"].split(" ", 1)
            if auth_type.lower() != "basic":
                print(f"[{charge_point_id}] Invalid auth type: {auth_type}")
                self._emit_security_event(
                    charge_point_id,
                    "InvalidAuthentication",
                    "Error",
                    f"Invalid auth type: {auth_type}"
                )
                await websocket.close()
                return
            decoded = base64.b64decode(auth_string).decode("utf-8")
            username, password = decoded.split(":", 1)
            # --- Auto-registration logic for new CPs ---
            if cp_exists(username):
                if check_basic_auth(username, password):
                    auth_valid = True
                else:
                    print(f"[{username}] Invalid credentials.")
                    self._emit_security_event(
                        username,
                        "InvalidAuthentication",
                        "Error",
                        "Authentication failed (username or password incorrect)"
                    )
                    await websocket.close()
                    return
            else:
                # First time registration: store CP and password in DB
                add_cp(username, password)
                print(f"[{username}] Registered new CP (first-time connection).")
                self._emit_security_event(
                    username,
                    "FirstTimeRegistration",
                    "Success",
                    "Registered new CP and accepted credentials"
                )
                auth_valid = True
        except Exception as e:
            print(f"[{charge_point_id}] Auth error: {e}")
            self._emit_security_event(
                charge_point_id,
                "InvalidAuthentication",
                "Error",
                f"Authentication error: {e}"
            )
            await websocket.close()
            return

        if not auth_valid:
            print(f"[{charge_point_id}] Invalid credentials.")
            self._emit_security_event(
                charge_point_id,
                "InvalidAuthentication",
                "Error",
                "Authentication failed (username or password incorrect)"
            )
            await websocket.close()
            return

        # --- Authenticated: emit username (never password) ---
        self._emit_security_event(
            charge_point_id,
            "Authenticated",
            "Success",
            f"Authenticated Username: {username}"
        )

        print(f"[{charge_point_id}] Authenticated successfully.")
        charge_point = MyChargePoint(charge_point_id, websocket)

        now = datetime.datetime.now().isoformat()
        self.connected_chargers[charge_point_id] = {
            "instance": charge_point,
            "status": "connected",
            "websocket": websocket,
            "last_activity": now
        }
        self.update_dashboard()

        try:
            await charge_point.start()
        except Exception as e:
            print(f"ChargePoint {charge_point_id} error: {e}")
        finally:
            await self.on_disconnect(charge_point_id)

    async def on_disconnect(self, charge_point_id):
        if charge_point_id in self.connected_chargers:
            self.connected_chargers[charge_point_id]["status"] = "disconnected"
            self.connected_chargers[charge_point_id]["last_activity"] = datetime.datetime.now().isoformat()
            print(f"[{charge_point_id}] Disconnected.")
            self.update_dashboard()

    def update_dashboard(self):
        status_data = {
            "connected": [
                {
                    "charge_point_id": charge_point_id,
                    "status": data["status"],
                    "last_activity": data.get("last_activity")
                }
                for charge_point_id, data in self.connected_chargers.items()
                if data["status"] == "connected"
            ],
            "disconnected": [
                {
                    "charge_point_id": charge_point_id,
                    "status": data["status"],
                    "last_activity": data.get("last_activity")
                }
                for charge_point_id, data in self.connected_chargers.items()
                if data["status"] == "disconnected"
            ],
            "total": len(self.connected_chargers)
        }
        print("Dashboard status_update:", status_data)
        socketio.emit('status_update', status_data)
        # Also emit latest meter values to new dashboard clients
        socketio.emit('meter_values_bulk', latest_meter_values)

@flask_app.route('/')
def dashboard():
    return render_template('dashboard.html')

@socketio.on('connect')
def handle_connect():
    print('Dashboard client connected')
    # Emit the latest meter values to new dashboard client
    socketio.emit('meter_values_bulk', latest_meter_values)

def run_flask_app():
    # For dashboard only; can optionally be secured with SSL for production
    socketio.run(flask_app, host='0.0.0.0', port=5000, debug=False)

async def run_csms():
    config = configparser.ConfigParser()
    config.read('config.ini')
    csms_host = config.get('CSMS', 'host', fallback='0.0.0.0')
    csms_port = config.getint('CSMS', 'port', fallback=9000)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain('certs/server.crt', 'certs/server.key')
    ssl_context.load_verify_locations(cafile='certs/ca.crt')
    ssl_context.verify_mode = ssl.CERT_REQUIRED  # Now requires client certs
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Add all OCPP profile 2 required ciphers (ECDHE-ECDSA + ECDHE-RSA)
    ssl_context.set_ciphers(
        'ECDHE-ECDSA-AES128-GCM-SHA256:'
        'ECDHE-ECDSA-AES256-GCM-SHA384:'
        'ECDHE-RSA-AES128-GCM-SHA256:'
        'ECDHE-RSA-AES256-GCM-SHA384'
    )

    csms = CentralSystem()
    server = await websockets.serve(
        csms.on_connect,
        csms_host,
        csms_port,
        subprotocols=['ocpp2.0.1'],
        ssl=ssl_context
    )
    print(f"CSMS running on wss://{csms_host}:{csms_port}")
    await server.wait_closed()

if __name__ == '__main__':
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()
    asyncio.run(run_csms())