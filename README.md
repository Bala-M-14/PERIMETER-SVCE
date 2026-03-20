# PerimeterIQ — Directional Intrusion Detection System

> **DSC Blueprints 2026 @ SVCE · SAEC · Team PerimeterIQ**

A real-time, dual-beam laser perimeter security system built on the **ESP32** microcontroller with a **Python FastAPI** backend and a live web dashboard. The system classifies intruders by movement direction, velocity, and behaviour — and streams every event to a browser in milliseconds over WebSocket.

---

## Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Hardware Requirements](#hardware-requirements)
- [Wiring](#wiring)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [1. Flash the Firmware](#1-flash-the-firmware)
  - [2. Install Python Dependencies](#2-install-python-dependencies)
  - [3. Run the Command Center](#3-run-the-command-center)
  - [4. Open the Dashboard](#4-open-the-dashboard)
- [Configuration](#configuration)
- [Event Reference](#event-reference)
- [Threat Levels](#threat-levels)
- [Object Classification](#object-classification)
- [Auth & Bypass System](#auth--bypass-system)
- [Packet Protocol](#packet-protocol)
- [License](#license)

---

## Features

| Feature | Details |
|---|---|
| **Dual-beam laser detection** | Two IR/laser beams (A & B) with LDR receivers |
| **Directional crossing** | Left-to-Right, Right-to-Left, stationary loitering |
| **Velocity measurement** | Computed from microsecond-resolution timestamps |
| **Object classification** | `HUMAN_SLOW`, `HUMAN_WALK`, `HUMAN_RUN`, `MECHANICAL` |
| **Threat scoring** | `NONE` → `ELEVATED` → `CRITICAL` with 60-second frequency window |
| **Tamper detection** | Simultaneous both-beam break fires `EVT_TAMPER` |
| **Retreat detection** | Double-break of same beam within 800 ms |
| **Anti-tailgate** | Cancels auth window if follower detected on the first beam |
| **Non-blocking buzzer** | Step-engine patterns — no `delay()` blocking in the loop |
| **Auth bypass** | 10-second crossing-mute window via `AUTH` serial command |
| **CRC-8 packet validation** | XOR checksum on every 16-byte packet |
| **Sequence gap detection** | Detects dropped packets by checking sequence numbers |
| **SQLite event log** | Every event persisted to `perimeter.db` |
| **Live WebSocket dashboard** | Real-time browser UI, no page refresh needed |
| **Multi-user registry** | ADMIN / OPERATOR / GUEST roles |

---

## System Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Physical Layer                        │
│   Laser A ──→ LDR A ──→ ESP32 GPIO 34                   │
│   Laser B ──→ LDR B ──→ ESP32 GPIO 35                   │
│                          ESP32 GPIO 14 ──→ Buzzer        │
└────────────────────────┬─────────────────────────────────┘
                         │ USB Serial (115200 baud)
                         │ 16-byte binary packets + ASCII cmds
┌────────────────────────▼─────────────────────────────────┐
│              Python Command Center (serial_reader.py)    │
│   • Reads & validates packets (CRC-8, seq gap check)     │
│   • Classifies threat + object type                      │
│   • Persists events to SQLite (perimeter.db)             │
│   • FastAPI server on :5000                              │
│     ├─ GET  /            → dashboard.html                │
│     ├─ GET  /api/events  → last 50 events (JSON)         │
│     ├─ GET  /api/security→ session state (JSON)          │
│     ├─ POST /api/authenticate → badge auth               │
│     ├─ POST /api/lockdown     → lockdown broadcast       │
│     └─ WS   /ws         → real-time event stream        │
└────────────────────────┬─────────────────────────────────┘
                         │ WebSocket + REST
┌────────────────────────▼─────────────────────────────────┐
│                  Browser Dashboard                       │
│               dashboard.html (vanilla JS)                │
│   • Live event feed, threat indicator, counters          │
│   • Auth bypass panel, lockdown trigger                  │
│   • Beam status, velocity, confidence, object class      │
└──────────────────────────────────────────────────────────┘
```

---

## Hardware Requirements

| Component | Qty | Notes |
|---|---|---|
| ESP32 DevKit (any 38-pin variant) | 1 | Tested on ESP32-WROOM-32 |
| LDR (Light Dependent Resistor) | 2 | One per beam channel |
| Laser pointer / IR LED | 2 | Aligned with each LDR |
| 10 kΩ resistor | 2 | Voltage divider for each LDR |
| Passive buzzer | 1 | 3.3 V or 5 V compatible |
| Breadboard + jumper wires | — | For prototyping |
| USB-A to Micro-USB / USB-C cable | 1 | For serial + power |

---

## Wiring

```
ESP32 GPIO 34  ──────────────────────┐
                                      │
                            LDR A    │
3.3V ──── [10 kΩ] ──┬──── [LDR A] ──┘──── GND
                     │
                  (junction → GPIO 34)

ESP32 GPIO 35  ──────────────────────┐
                                      │
                            LDR B    │
3.3V ──── [10 kΩ] ──┬──── [LDR B] ──┘──── GND
                     │
                  (junction → GPIO 35)

ESP32 GPIO 14 ──── [Buzzer +] ──── GND (other terminal)
```

> **Note:** GPIO 34 and 35 are input-only (no internal pull-up). Use the 10 kΩ external divider as shown. The system uses `analogReadResolution(12)` and `ADC_11db` attenuation; the laser-blocked threshold is `raw > 2000` (out of 4095).

---

## Project Structure

```
PerimeterIQ/
├── firmware/
│   └── perimeter_iq/
│       └── perimeter_iq.ino   # ESP32 Arduino sketch (state-machine, packet TX)
├── dashboard.html             # Single-file web dashboard (HTML + CSS + JS)
├── serial_reader.py           # Python backend (FastAPI + serial reader)
├── requirements.txt           # Python dependencies
├── .gitignore
└── README.md
```

---

## Getting Started

### 1. Flash the Firmware

1. Install the [Arduino IDE](https://www.arduino.cc/en/software) (≥ 2.x recommended).
2. Add the ESP32 board package:
   - Go to **File → Preferences → Additional Board Manager URLs** and add:
     ```
     https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
     ```
3. Open `firmware/perimeter_iq/perimeter_iq.ino`.
4. Select **Board: ESP32 Dev Module** and the correct **Port**.
5. Click **Upload**.

### 2. Install Python Dependencies

```bash
# Create and activate a virtual environment (recommended)
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Command Center

```bash
# Default port is COM8 on Windows. Override with the environment variable:

# Windows
set PERIMETERIQ_PORT=COM7
python serial_reader.py

# Linux / macOS
export PERIMETERIQ_PORT=/dev/ttyUSB0
python serial_reader.py
```

The banner will confirm the port, baud rate, and dashboard URL:

```
╔══════════════════════════════════════════════╗
║   PERIMETER IQ — PYTHON COMMAND CENTER      ║
║   DSC Blueprints 2026 @ SVCE — SAEC         ║
╠══════════════════════════════════════════════╣
║   PORT      :  COM7                          ║
║   BAUD      :  115200                        ║
║   THRESHOLD :  2000                          ║
║   DATABASE  :  perimeter.db                  ║
║   DASHBOARD :  http://localhost:5000         ║
╚══════════════════════════════════════════════╝
```

### 4. Open the Dashboard

Navigate to **[http://localhost:5000](http://localhost:5000)** in your browser.

---

## Configuration

| Parameter | Location | Default | Description |
|---|---|---|---|
| `PERIMETERIQ_PORT` | Env variable | `COM8` | Serial port of the ESP32 |
| `BAUD` | `serial_reader.py` | `115200` | Must match firmware |
| `THRESH` | Both files | `2000` | ADC raw value above which beam is "broken" |
| `AUTH_WINDOW_SECONDS` | `serial_reader.py` | `10` | Auth bypass window duration (seconds) |
| `STATIONARY_MS` | `perimeter_iq.ino` | `5000` | Time before `STATIONARY` event fires (ms) |
| `SINGLE_TIMEOUT_MS` | `perimeter_iq.ino` | `8000` | Time before `INSIDE_A/B` fires (ms) |
| `HEARTBEAT_MS` | `perimeter_iq.ino` | `5000` | Heartbeat packet interval (ms) |
| `RETREAT_WINDOW_MS` | `perimeter_iq.ino` | `800` | Double-break window for retreat detection (ms) |

---

## Event Reference

| Code | Event Name | Description |
|---|---|---|
| `0x01` | `ARMED` | System powered on and armed |
| `0x02` | `BREAK_A` | Beam A break detected (mid-crossing) |
| `0x03` | `BREAK_B` | Beam B break detected (mid-crossing) |
| `0x04` | `L_TO_R` | Full left-to-right crossing confirmed |
| `0x05` | `R_TO_L` | Full right-to-left crossing confirmed |
| `0x06` | `INSIDE_A` | Object entered from A side, did not cross (8 s timeout) |
| `0x07` | `INSIDE_B` | Object entered from B side, did not cross (8 s timeout) |
| `0x08` | `INSIDE_FULL` | Object stationary inside, both beams blocked > 13 s |
| `0x09` | `STATIONARY` | Both beams blocked for 5 s — loitering |
| `0x0A` | `RETREAT` | Object reversed before completing crossing |
| `0x0B` | `STATIONARY_L_TO_R` | Exited left-to-right after loitering |
| `0x0C` | `STATIONARY_R_TO_L` | Exited right-to-left after loitering |
| `0x0F` | `HEARTBEAT` | Periodic alive packet (every 5 s) |
| `0x10` | `TAMPER` | Both beams broken simultaneously (cover/tamper) |

---

## Threat Levels

| Level | Trigger Conditions |
|---|---|
| `NONE` | Heartbeat, armed, retreat, beam-only events |
| `ELEVATED` | Directional crossing or inside event with low frequency |
| `CRITICAL` | Velocity > 1.5 m/s, ≥ 5 intrusions in 60 s, `STATIONARY`, `INSIDE_FULL`, or `TAMPER` |

---

## Object Classification

Applies only to directional crossing events (`L_TO_R`, `R_TO_L`, `STATIONARY_L_TO_R`, `STATIONARY_R_TO_L`).

| Class | Velocity Range |
|---|---|
| `HUMAN_SLOW` | ≤ 0.8 m/s |
| `HUMAN_WALK` | 0.8 – 1.5 m/s |
| `HUMAN_RUN` | 1.5 – 3.0 m/s |
| `MECHANICAL` | > 3.0 m/s |
| `UNKNOWN` | Non-velocity event or invalid reading |

---

## Auth & Bypass System

1. The dashboard sends `{"cmd": "AUTH", "user": "<badge_id>"}` over WebSocket.
2. The backend validates the badge against `USER_REGISTRY` and grants a **10-second bypass window**.
3. The `AUTH` command is forwarded over serial to the ESP32, which mutes the buzzer for the next crossing.
4. An `AUTH_ACK` is returned over WebSocket so the UI can show the bypass is active.
5. Anti-tailgate logic cancels the bypass if a second person is detected on the first beam during the authorised crossing.

**Default Users:**

| Badge ID | Name | Level |
|---|---|---|
| `0xDE44` | Ayman | ADMIN |
| `ADMIN` | Admin | ADMIN |
| `OP001` | Operator | OPERATOR |
| `GUEST` | Guest | GUEST |

---

## Packet Protocol

Every packet is **16 bytes**, always starting with `0xAA 0xBB`.

| Byte(s) | Field | Description |
|---|---|---|
| 0–1 | SOF | `0xAA 0xBB` (Start of Frame) |
| 2–3 | Sequence | 16-bit counter, big-endian |
| 4 | Event code | See Event Reference |
| 5–6 | Raw A | ADC reading, beam A (big-endian) |
| 7–8 | Raw B | ADC reading, beam B (big-endian) |
| 9–12 | Velocity | IEEE 754 float, m/s (little-endian) |
| 13 | Confidence | 0–100 % |
| 14 | CRC-8 | XOR of bytes 2–13 |
| 15 | Reserved | `0x00` |

---

## License

This project is developed by **SAEC Team PerimeterIQ** for the **DSC Blueprints 2026** competition at SVCE.  
© 2026 SAEC Team PerimeterIQ. All rights reserved.
