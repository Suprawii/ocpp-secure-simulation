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
import secrets
import time
from collections import defaultdict, deque

# --- secure DB-backed authentication ---
from csms_db import create_table, check_basic_auth, add_cp, cp_exists

flask_app = Flask(__name__)
socketio = SocketIO(flask_app, async_mode='threading')
flask_app.config['SECRET_KEY'] = 'your-secret-key'

# Ensure DB table exists at startup
create_table()

# Store latest meter values per charge point
latest_meter_values = {}

# --- Replay attack defense: Nonce and timestamp management ---
NONCE_EXPIRY_SECONDS = 120  # How long a nonce is valid for (from issuance)
NONCE_LENGTH = 16
MESSAGE_TIME_WINDOW = 30    # seconds allowed for incoming messages to be considered "fresh"

# Per-CP nonce store: {cp_id: {"nonce": str, "issued": datetime, "used": bool}}
cp_nonces = {}

def gen_nonce():
    return secrets.token_urlsafe(NONCE_LENGTH)

# --- Rate limiting data structures and config ---
cp_request_times = defaultdict(lambda: deque(maxlen=100))
cp_blocked_until = {}
RATE_LIMIT = 20      # max MeterValues per minute per CP
BLOCK_DURATION = 60  # seconds to block after exceeding rate

class MyChargePoint(OcppChargePoint):
    @on("BootNotification")
    async def on_boot_notification(self, charging_station, reason, **kwargs):
        print(f"BootNotification received from {self.id}")

        # --- Issue fresh nonce on BootNotification ---
        nonce = gen_nonce()
        cp_nonces[self.id] = {
            "nonce": nonce,
            "issued": datetime.datetime.now(datetime.timezone.utc),
            "used": False
        }

        socketio.emit('security_event', {
            "timestamp": datetime.datetime.now().isoformat(),
            "charge_point_id": self.id,
            "event_type": "BootNotification",
            "severity": "Info",
            "details": f"Issued nonce {nonce} for replay attack defense"
        })
        return call_result.BootNotification(
            current_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            interval=10,
            status="Accepted",
            custom_data={"vendorId": "SecureEV", "nonce": nonce}
        )

    @on("MeterValues")
    async def on_meter_values(self, evse_id, meter_value, custom_data=None, **kwargs):
        print(f"MeterValues received from {self.id}: {meter_value} (custom_data={custom_data})")

        cp_id = self.id
        nonce = None
        if custom_data and "nonce" in custom_data:
            nonce = custom_data["nonce"]
        timestamp = None
        if meter_value and len(meter_value) > 0:
            timestamp = meter_value[0].get('timestamp')

        # --- RATE LIMITING CHECK ---
        now_ts = time.time()
        # Blocked check
        if cp_id in cp_blocked_until and now_ts < cp_blocked_until[cp_id]:
            socketio.emit('security_event', {
                "timestamp": datetime.datetime.now().isoformat(),
                "charge_point_id": cp_id,
                "event_type": "RateLimit",
                "severity": "Warning",
                "details": f"Blocked for exceeding rate limit (until {datetime.datetime.fromtimestamp(cp_blocked_until[cp_id])})"
            })
            return call_result.MeterValues(
                custom_data={"vendorId": "SecureEV", "error": "Rate limit exceeded, temporarily blocked"}
            )
        # Rate counting
        req_times = cp_request_times[cp_id]
        req_times.append(now_ts)
        # Remove old timestamps (older than 60s)
        while req_times and now_ts - req_times[0] > 60:
            req_times.popleft()
        if len(req_times) > RATE_LIMIT:
            # Block CP
            cp_blocked_until[cp_id] = now_ts + BLOCK_DURATION
            socketio.emit('security_event', {
                "timestamp": datetime.datetime.now().isoformat(),
                "charge_point_id": cp_id,
                "event_type": "RateLimit",
                "severity": "Error",
                "details": f"Blocked for {BLOCK_DURATION}s due to {len(req_times)} requests/min"
            })
            return call_result.MeterValues(
                custom_data={"vendorId": "SecureEV", "error": f"Rate limit exceeded: blocked for {BLOCK_DURATION}s"}
            )

        # 1. Timestamp check
        if not timestamp:
            socketio.emit('security_event', {
                "timestamp": datetime.datetime.now().isoformat(),
                "charge_point_id": self.id,
                "event_type": "MeterValues",
                "severity": "Error",
                "details": "Missing timestamp"
            })
            return call_result.MeterValues(
                custom_data={"vendorId": "SecureEV", "error": "Missing timestamp"}
            )
        try:
            msg_time = datetime.datetime.fromisoformat(timestamp)
            now = datetime.datetime.now(datetime.timezone.utc)
            if abs((now - msg_time).total_seconds()) > MESSAGE_TIME_WINDOW:
                socketio.emit('security_event', {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "charge_point_id": self.id,
                    "event_type": "MeterValues",
                    "severity": "Error",
                    "details": "Stale timestamp (possible replay)"
                })
                return call_result.MeterValues(
                    custom_data={"vendorId": "SecureEV", "error": "Stale timestamp (possible replay)"}
                )
        except Exception:
            socketio.emit('security_event', {
                "timestamp": datetime.datetime.now().isoformat(),
                "charge_point_id": self.id,
                "event_type": "MeterValues",
                "severity": "Error",
                "details": "Invalid timestamp format"
            })
            return call_result.MeterValues(
                custom_data={"vendorId": "SecureEV", "error": "Invalid timestamp format"}
            )

        # 2. Nonce check
        cp_nonce_info = cp_nonces.get(cp_id)
        if not nonce or not cp_nonce_info or cp_nonce_info["nonce"] != nonce:
            socketio.emit('security_event', {
                "timestamp": datetime.datetime.now().isoformat(),
                "charge_point_id": self.id,
                "event_type": "MeterValues",
                "severity": "Error",
                "details": "Invalid or missing nonce"
            })
            return call_result.MeterValues(
                custom_data={"vendorId": "SecureEV", "error": "Invalid or missing nonce"}
            )
        if cp_nonce_info["used"]:
            socketio.emit('security_event', {
                "timestamp": datetime.datetime.now().isoformat(),
                "charge_point_id": self.id,
                "event_type": "MeterValues",
                "severity": "Error",
                "details": "Nonce already used (replay)"
            })
            return call_result.MeterValues(
                custom_data={"vendorId": "SecureEV", "error": "Nonce already used (replay)"}
            )
        if (datetime.datetime.now(datetime.timezone.utc) - cp_nonce_info["issued"]).total_seconds() > NONCE_EXPIRY_SECONDS:
            socketio.emit('security_event', {
                "timestamp": datetime.datetime.now().isoformat(),
                "charge_point_id": self.id,
                "event_type": "MeterValues",
                "severity": "Error",
                "details": "Nonce expired"
            })
            return call_result.MeterValues(
                custom_data={"vendorId": "SecureEV", "error": "Nonce expired"}
            )
        # Mark nonce as used now (single-use)
        cp_nonce_info["used"] = True

        # --- CREATE AND ISSUE NEW NONCE FOR NEXT MESSAGE ---
        new_nonce = gen_nonce()
        cp_nonces[self.id] = {
            "nonce": new_nonce,
            "issued": datetime.datetime.now(datetime.timezone.utc),
            "used": False
        }

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

        socketio.emit('security_event', {
            "timestamp": datetime.datetime.now().isoformat(),
            "charge_point_id": self.id,
            "event_type": "MeterValues",
            "severity": "Info",
            "details": format_meter_values(meter_value)
        })
        socketio.emit('meter_value', {
            "charge_point_id": self.id,
            "timestamp": datetime.datetime.now().isoformat(),
            "value": meter_value
        })
        latest_meter_values[self.id] = {
            "timestamp": datetime.datetime.now().isoformat(),
            "value": meter_value
        }
        return call_result.MeterValues(custom_data={"vendorId": "SecureEV", "status": "Accepted", "nonce": new_nonce})

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
        socketio.emit('meter_values_bulk', latest_meter_values)

@flask_app.route('/')
def dashboard():
    return render_template('dashboard.html')

@socketio.on('connect')
def handle_connect():
    print('Dashboard client connected')
    socketio.emit('meter_values_bulk', latest_meter_values)

def run_flask_app():
    socketio.run(flask_app, host='0.0.0.0', port=5000, debug=False)

async def run_csms():
    config = configparser.ConfigParser()
    config.read('config.ini')
    csms_host = config.get('CSMS', 'host', fallback='0.0.0.0')
    csms_port = config.getint('CSMS', 'port', fallback=9000)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain('certs/server.crt', 'certs/server.key')
    ssl_context.load_verify_locations(cafile='certs/ca.crt')
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
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