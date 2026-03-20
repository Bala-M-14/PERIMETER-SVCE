"""
PerimeterIQ — Python Command Center
DSC Blueprints 2026 — SVCE — Team PerimeterIQ
Version 23 — v21 base preserved, fixes applied:
  1. FastAPI lifespan replaces deprecated @app.on_event("startup")
     which caused loop_ref to never be set on newer FastAPI versions,
     breaking all WebSocket broadcasts silently.
  2. DB path resolved relative to this script file — not CWD.
  3. Threat scoring: only INTRUSION_CLASS events counted in frequency
     window. Heartbeats (every 5s) no longer inflate threat level.
  4. AUTH_ACK sent back over WebSocket so dashboard waits for
     confirmation before activating bypass UI.
  5. Object classification by velocity — additive field, never
     overrides any existing logic.
  6. Sequence gap detection — already have seq_id in every packet.
  7. EVT_TAMPER added to event map and threat map.
"""

import serial
import struct
import threading
import sqlite3
import datetime
import asyncio
import json
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

# ── PATHS ─────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(SCRIPT_DIR, "perimeter.db")

# ── CONFIGURATION ─────────────────────────────────────────
PORT                = os.environ.get("PERIMETERIQ_PORT", "COM8")
BAUD                = 115200
THRESH              = 2000
PACKET_SZ           = 16
AUTH_WINDOW_SECONDS = 10

# ── EVENT MAP ─────────────────────────────────────────────
EVT_MAP = {
    0x01: "ARMED",
    0x02: "BREAK_A",
    0x03: "BREAK_B",
    0x04: "L_TO_R",
    0x05: "R_TO_L",
    0x06: "INSIDE_A",
    0x07: "INSIDE_B",
    0x08: "INSIDE_FULL",
    0x09: "STATIONARY",
    0x0A: "RETREAT",
    0x0B: "STATIONARY_L_TO_R",
    0x0C: "STATIONARY_R_TO_L",
    0x0F: "HEARTBEAT",
    0x10: "TAMPER",
}

# ── THREAT MAP ────────────────────────────────────────────
THREAT_MAP = {
    "L_TO_R":             "ELEVATED",
    "R_TO_L":             "ELEVATED",
    "STATIONARY":         "CRITICAL",
    "INSIDE_FULL":        "CRITICAL",
    "STATIONARY_L_TO_R":  "ELEVATED",
    "STATIONARY_R_TO_L":  "ELEVATED",
    "INSIDE_A":           "ELEVATED",
    "INSIDE_B":           "ELEVATED",
    "TAMPER":             "CRITICAL",
    "RETREAT":            "NONE",
    "BREAK_A":            "NONE",
    "BREAK_B":            "NONE",
    "HEARTBEAT":          "NONE",
    "ARMED":              "NONE",
}

# Only these events count toward the 60s frequency window.
# Heartbeats arrive every 5s — must never inflate threat level.
INTRUSION_CLASS = frozenset({
    "L_TO_R", "R_TO_L",
    "INSIDE_A", "INSIDE_B", "INSIDE_FULL",
    "STATIONARY", "STATIONARY_L_TO_R", "STATIONARY_R_TO_L",
    "TAMPER",
})

# ── MULTI-USER REGISTRY ───────────────────────────────────
USER_REGISTRY = {
    "0xDE44": {"name": "Ayman",    "level": "ADMIN"},
    "ADMIN":  {"name": "Admin",    "level": "ADMIN"},
    "OP001":  {"name": "Operator", "level": "OPERATOR"},
    "GUEST":  {"name": "Guest",    "level": "GUEST"},
}

# ── SESSION STATE ─────────────────────────────────────────
session = {
    "lr": 0, "rl": 0, "inside": 0, "stationary": 0,
    "retreat": 0, "tamper": 0, "total": 0,
    "is_authed": False, "auth_user": "", "auth_level": "",
    "auth_started_at": 0.0,
    "packets_received": 0, "packets_corrupt": 0, "packets_dropped": 0,
}

recent_events:     list[float]     = []
connected_clients: list[WebSocket] = []
last_seq: int = -1

# ── FASTAPI LIFESPAN ──────────────────────────────────────
loop_ref = None

@asynccontextmanager
async def lifespan(app):
    global loop_ref
    loop_ref = asyncio.get_event_loop()
    yield

app = FastAPI(lifespan=lifespan)

# ── AUTH HELPERS ──────────────────────────────────────────
def refresh_auth_state():
    if session["is_authed"] and session["auth_started_at"] > 0:
        if (time.time() - session["auth_started_at"]) > AUTH_WINDOW_SECONDS:
            session["is_authed"]       = False
            session["auth_user"]       = ""
            session["auth_level"]      = ""
            session["auth_started_at"] = 0.0

def activate_session(badge_id: str):
    user = USER_REGISTRY.get(badge_id, {"name": badge_id, "level": "OPERATOR"})
    session["is_authed"]       = True
    session["auth_user"]       = user["name"]
    session["auth_level"]      = user["level"]
    session["auth_started_at"] = time.time()

# ── API ROUTES ────────────────────────────────────────────
@app.get("/")
async def serve_dashboard():
    path = os.path.join(SCRIPT_DIR, "dashboard.html")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse(
            "<h2>dashboard.html not found in same folder as serial_reader.py</h2>",
            status_code=404)

@app.post("/api/authenticate")
async def api_authenticate(data: dict):
    badge_id = data.get("badge_id", "UNKNOWN")
    activate_session(badge_id)
    serial_ok = False
    try:
        if serial_port and serial_port.is_open:
            serial_port.write(b"AUTH\n")
            serial_ok = True
    except Exception as e:
        print(f"[WARN  ]  Serial write failed (AUTH): {e}")
    return {"status": "ok", "user": session["auth_user"],
            "level": session["auth_level"], "serial_ok": serial_ok}

@app.post("/api/lockdown")
async def api_lockdown(data: dict):
    await broadcast({"event": "LOCKDOWN", "active": data.get("active", True)})
    return {"status": "ok"}

@app.get("/api/security")
async def api_security():
    refresh_auth_state()
    return {
        "status":           "BYPASS" if session["is_authed"] else "ARMED",
        "auth_user":        session["auth_user"],
        "auth_level":       session["auth_level"],
        "total_events":     session["total"],
        "lr":               session["lr"],
        "rl":               session["rl"],
        "packets_received": session["packets_received"],
        "packets_corrupt":  session["packets_corrupt"],
        "packets_dropped":  session["packets_dropped"],
    }

@app.get("/api/events")
async def api_events():
    """Return last 50 events from DB for dashboard replay."""
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT ts, event, velocity, threat, object_class "
            "FROM events ORDER BY id DESC LIMIT 50"
        ).fetchall()
        conn.close()
        return [{"ts": r[0], "event": r[1], "velocity": r[2],
                 "threat": r[3], "object_class": r[4]} for r in rows]
    except Exception:
        return []

# ── WEBSOCKET ─────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    try:
        while True:
            msg = await ws.receive_text()
            try:
                data = json.loads(msg)
                cmd  = data.get("cmd", "")
                if cmd == "AUTH":
                    badge_id  = data.get("user", "OPERATOR")
                    activate_session(badge_id)
                    serial_ok = False
                    try:
                        if serial_port and serial_port.is_open:
                            serial_port.write(b"AUTH\n")
                            serial_ok = True
                    except Exception as e:
                        print(f"[WARN  ]  Serial write failed (WS AUTH): {e}")
                    # Send ACK back — dashboard waits for this before activating UI
                    await ws.send_text(json.dumps({
                        "event":     "AUTH_ACK",
                        "user":      session["auth_user"],
                        "level":     session["auth_level"],
                        "serial_ok": serial_ok,
                    }))
                elif cmd == "RESET":
                    session["is_authed"]       = False
                    session["auth_user"]        = ""
                    session["auth_level"]       = ""
                    session["auth_started_at"]  = 0.0
                    try:
                        if serial_port and serial_port.is_open:
                            serial_port.write(b"RESET\n")
                    except Exception:
                        pass
            except Exception:
                pass
    except WebSocketDisconnect:
        if ws in connected_clients:
            connected_clients.remove(ws)

async def broadcast(payload: dict):
    dead = []
    for ws in connected_clients:
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in connected_clients:
            connected_clients.remove(ws)

# ── CRC VALIDATION ────────────────────────────────────────
def validate_checksum(raw: bytes) -> bool:
    crc = 0
    for b in raw[2:14]:
        crc ^= b
    return crc == raw[14]

# ── PACKET PARSER ─────────────────────────────────────────
def parse_packet(raw: bytes):
    seq   = (raw[2] << 8) | raw[3]
    evt   = raw[4]
    ra    = (raw[5] << 8) | raw[6]
    rb    = (raw[7] << 8) | raw[8]
    vel   = struct.unpack_from('<f', raw, 9)[0]
    score = raw[13]
    return seq, evt, ra, rb, vel, score

# ── OBJECT CLASSIFIER ─────────────────────────────────────
# Physics: velocity = SENSOR_GAP (0.10m) / crossing_time_seconds.
# Applied only to directional crossing events where velocity is valid.
# This field is purely additive — it never modifies threat level logic.
VELOCITY_EVENTS = frozenset({
    "L_TO_R", "R_TO_L",
    "STATIONARY_L_TO_R", "STATIONARY_R_TO_L",
})

def classify_object(evt_name: str, velocity: float) -> str:
    if evt_name not in VELOCITY_EVENTS or velocity <= 0.0:
        return "UNKNOWN"
    if velocity <= 0.8:  return "HUMAN_SLOW"
    if velocity <= 1.5:  return "HUMAN_WALK"
    if velocity <= 3.0:  return "HUMAN_RUN"
    return "MECHANICAL"

# ── THREAT CLASSIFIER ─────────────────────────────────────
def classify_threat(evt_name: str, velocity: float) -> str:
    base = THREAT_MAP.get(evt_name, "NONE")
    if base == "NONE":
        return "NONE"

    # Only intrusion-class events update the sliding 60s window
    if evt_name in INTRUSION_CLASS:
        now_e = time.time()
        recent_events.append(now_e)
        cutoff = now_e - 60.0
        while recent_events and recent_events[0] < cutoff:
            recent_events.pop(0)

    freq = len(recent_events)

    if (velocity > 1.5 or freq >= 5 or
            evt_name in ("STATIONARY", "INSIDE_FULL", "TAMPER")):
        return "CRITICAL"
    if freq >= 3 or base == "ELEVATED":
        return "ELEVATED"
    return "NONE"

# ── DATABASE ──────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT,
            event        TEXT,
            raw_a        INTEGER,
            raw_b        INTEGER,
            velocity     REAL,
            score        INTEGER,
            threat       TEXT,
            object_class TEXT,
            seq          INTEGER,
            checksum     TEXT
        )
    """)
    conn.commit()
    return conn

def save_event(conn, evt_name, ra, rb, vel, score,
               threat, obj_class, seq, crc_ok):
    conn.execute("""
        INSERT INTO events
          (ts, event, raw_a, raw_b, velocity, score,
           threat, object_class, seq, checksum)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.datetime.now().isoformat(),
        evt_name, ra, rb, round(vel, 3), score,
        threat, obj_class, seq,
        "VALID" if crc_ok else "INVALID",
    ))
    conn.commit()

# ── SERIAL READER THREAD ──────────────────────────────────
serial_port = None

def serial_reader():
    global serial_port, last_seq
    db  = init_db()
    buf = bytearray()

    print(f"[SERIAL]  Connecting to {PORT} at {BAUD} baud...")
    try:
        serial_port = serial.Serial(PORT, BAUD, timeout=1)
        print(f"[  OK  ]  Connected to {PORT}")
    except serial.SerialException as e:
        print(f"[ERROR ]  Cannot open {PORT}: {e}")
        print(f"[INFO  ]  Set port: set PERIMETERIQ_PORT=COMx  (Windows)")
        print(f"[INFO  ]  Set port: export PERIMETERIQ_PORT=/dev/ttyUSB0  (Linux/Mac)")
        return

    while True:
        try:
            chunk = serial_port.read(serial_port.in_waiting or 1)
            if chunk:
                buf.extend(chunk)

            while len(buf) >= PACKET_SZ:
                if buf[0] == 0xAA and buf[1] == 0xBB:
                    raw = bytes(buf[:PACKET_SZ])
                    buf = buf[PACKET_SZ:]
                    session["packets_received"] += 1

                    crc_ok = validate_checksum(raw)
                    if not crc_ok:
                        session["packets_corrupt"] += 1
                        print(f"[CORRUPT]  CRC fail "
                              f"(total: {session['packets_corrupt']})")
                        continue

                    seq, evt_code, ra, rb, vel, score = parse_packet(raw)

                    # Sequence gap detection
                    if last_seq >= 0:
                        expected = (last_seq + 1) % 65536
                        if seq != expected:
                            dropped = (seq - last_seq - 1) % 65536
                            session["packets_dropped"] += dropped
                            print(f"[GAP   ]  Seq gap: "
                                  f"expected {expected}, got {seq} "
                                  f"({dropped} dropped)")
                    last_seq = seq

                    evt_name  = EVT_MAP.get(evt_code, f"UNK_0x{evt_code:02X}")
                    threat    = classify_threat(evt_name, vel)
                    obj_class = classify_object(evt_name, vel)
                    beam_a    = "BROKEN" if ra > THRESH else "CLEAR"
                    beam_b    = "BROKEN" if rb > THRESH else "CLEAR"

                    # Session counters
                    if   evt_name == "L_TO_R":    session["lr"]        += 1; session["total"] += 1
                    elif evt_name == "R_TO_L":    session["rl"]        += 1; session["total"] += 1
                    elif evt_name in ("INSIDE_A", "INSIDE_B", "INSIDE_FULL"):
                                                  session["inside"]    += 1; session["total"] += 1
                    elif evt_name == "STATIONARY": session["stationary"]+= 1; session["total"] += 1
                    elif evt_name == "RETREAT":   session["retreat"]   += 1
                    elif evt_name == "TAMPER":    session["tamper"]    += 1; session["total"] += 1

                    save_event(db, evt_name, ra, rb, vel, score,
                               threat, obj_class, seq, crc_ok)
                    refresh_auth_state()

                    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    print(
                        f"[{ts}]  seq={seq:05d}  {evt_name:<22}"
                        f"  A={ra:4d}({beam_a})  B={rb:4d}({beam_b})"
                        f"  v={vel:.2f}m/s  conf={score}%"
                        f"  threat={threat}  class={obj_class}"
                    )

                    payload = {
                        "event":        evt_name,
                        "raw_a":        ra,
                        "raw_b":        rb,
                        "velocity":     round(vel, 3),
                        "confidence":   score,
                        "threat":       threat,
                        "object_class": obj_class,
                        "seq":          seq,
                        "beam_a":       beam_a,
                        "beam_b":       beam_b,
                        "ts":           ts,
                        "is_authed":    session["is_authed"],
                        "auth_level":   session["auth_level"],
                        "dropped":      session["packets_dropped"],
                    }

                    if loop_ref:
                        asyncio.run_coroutine_threadsafe(
                            broadcast(payload), loop_ref
                        )
                else:
                    buf = buf[1:]

        except Exception as e:
            print(f"[ERROR ]  Serial reader: {e}")
            break

# ── MAIN ──────────────────────────────────────────────────
if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════╗")
    print("║   PERIMETER IQ — PYTHON COMMAND CENTER      ║")
    print("║   DSC Blueprints 2026 — SVCE                ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║   PORT      :  {PORT:<30}║")
    print(f"║   BAUD      :  {BAUD:<30}║")
    print(f"║   THRESHOLD :  {THRESH:<30}║")
    print(f"║   DATABASE  :  {os.path.basename(DB_PATH):<30}║")
    print(f"║   DASHBOARD :  http://localhost:5000         ║")
    print("╚══════════════════════════════════════════════╝")
    print()
    print("[INFO  ]  dashboard.html must be in the SAME folder as this script")
    print("[INFO  ]  Windows port: set PERIMETERIQ_PORT=COM7")
    print("[INFO  ]  If DB schema error: delete perimeter.db and restart")
    print()

    t = threading.Thread(target=serial_reader, daemon=True)
    t.start()

    uvicorn.run(app, host="0.0.0.0", port=5000)
