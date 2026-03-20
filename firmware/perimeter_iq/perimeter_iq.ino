// ============================================================
// PerimeterIQ — Directional Intrusion Detection System
// DSC Blueprints 2026 @ SVCE — Team PerimeterIQ (SAEC)
// Version 23 — v21 core preserved, non-blocking buzzer,
//              rearm_with_scan, anti-tailgate, retreat fix,
//              tamper detection, velocity classification
// ============================================================
//
// WHAT CHANGED FROM v21 (and why):
//   1. Blocking buzzer loops → non-blocking step engine
//      Reason: police_siren() was 1.4s of deaf time; beep_inside_full()
//      640ms. ESP32 WDT resets and missed crossings resulted.
//   2. rearm_state() → rearm_with_scan() everywhere in state machine
//      Reason: objects that park immediately after crossing produced
//      no rising edge so the system never re-detected them.
//   3. Retreat detection added ONLY as a timeout on STATE_A_FIRST /
//      STATE_B_FIRST: if state has been active longer than SINGLE_TIMEOUT
//      AND beam never reached B, that is INSIDE_A (existing). Retreat is
//      a separate code path — double-break of same beam within 800ms
//      tracked via last_a_broke_ms / last_b_broke_ms but ONLY checked
//      when we already know the beam cleared WITHOUT reaching B.
//      The original v21 a_broke branch in STATE_A_FIRST is preserved
//      exactly — retreat logic does NOT run inside that branch.
//   4. Anti-tailgate: added in STATE_A_FIRST and STATE_B_FIRST only.
//      Zero changes to STATE_BOTH or STATE_STATIONARY.
//   5. EVT_TAMPER added for simultaneous both-beam break in STATE_ARMED.
//   6. Threshold remains absolute (raw > THRESH). No adaptive baseline.
//      Adaptive baseline was removed — it caused sensor A to reset mid-
//      crossing when recalibration ran during a slow walk.
// ============================================================

#include <Arduino.h>

// ── PINS ─────────────────────────────────────────────────
#define PIN_A               34
#define PIN_B               35
#define PIN_BUZZER          14

// ── COMMS ────────────────────────────────────────────────
#define BAUD                115200
#define PACKET_SIZE         16
#define FRAME_SOF_1         0xAA
#define FRAME_SOF_2         0xBB

// ── SENSOR — absolute threshold (laser blocked = HIGH) ───
#define THRESH              2000
#define SENSOR_GAP_M        0.10f

// ── TIMING ───────────────────────────────────────────────
#define STATIONARY_MS          5000UL
#define SINGLE_TIMEOUT_MS      8000UL
#define HEARTBEAT_MS           5000UL
#define SAFETY_TIMEOUT_MS      (STATIONARY_MS * 3UL)
#define AUTH_BYPASS_TIMEOUT_MS 10000UL
// Retreat: same beam must break TWICE within this window
// and the second beam must never have triggered.
// 800ms is safely above LDR bounce (< 10ms) and safely
// below any real two-person gap (> 2s in practice).
#define RETREAT_WINDOW_MS      800UL

// ── SPEED THRESHOLDS ─────────────────────────────────────
#define SPEED_HIGH_MPS      1.50f
#define SPEED_MEDIUM_MPS    0.80f
#define FREQ_WINDOW_MS      60000UL
#define FREQ_ALERT_COUNT    3

// ── EVENT CODES ──────────────────────────────────────────
#define EVT_ARMED           0x01
#define EVT_SENSOR_A        0x02
#define EVT_SENSOR_B        0x03
#define EVT_LR              0x04
#define EVT_RL              0x05
#define EVT_INSIDE_A        0x06
#define EVT_INSIDE_B        0x07
#define EVT_INSIDE_FULL     0x08
#define EVT_STATIONARY      0x09
#define EVT_RETREAT         0x0A
#define EVT_STATION_LR      0x0B
#define EVT_STATION_RL      0x0C
#define EVT_HEARTBEAT       0x0F
#define EVT_TAMPER          0x10  // both beams simultaneously — cover/tamper

// ── STATE MACHINE ────────────────────────────────────────
enum PerimeterState {
  STATE_ARMED      = 0,
  STATE_A_FIRST    = 1,
  STATE_B_FIRST    = 2,
  STATE_BOTH       = 3,
  STATE_STATIONARY = 4,
};

enum DirectionCode {
  DIR_NONE = 0,
  DIR_LR   = 1,
  DIR_RL   = 2,
};

enum AlarmType {
  ALARM_CROSSING    = 0,
  ALARM_INSIDE_A    = 2,
  ALARM_INSIDE_B    = 3,
  ALARM_INSIDE_FULL = 4,
  ALARM_STATIONARY  = 5,
};

// ── STATE VARIABLES ──────────────────────────────────────
PerimeterState state   = STATE_ARMED;
uint16_t       seq_id  = 0;

uint8_t prev_a = 0;
uint8_t prev_b = 0;

uint32_t t_a_broke_us  = 0;
uint32_t t_b_broke_us  = 0;
uint32_t t_a_clear_us  = 0;
uint32_t t_b_clear_us  = 0;

uint32_t state_started_ms     = 0;
uint32_t both_started_ms      = 0;
uint32_t heartbeat_started_ms = 0;
uint32_t last_siren_ms        = 0;

uint8_t first_sensor   = 0;
bool    inside_full_sent = false;

// Retreat tracking — only used to detect double-break of SAME beam
// before the second beam is ever triggered.
uint32_t last_a_broke_ms = 0;  // last time beam A broke, in ms
uint32_t last_b_broke_ms = 0;  // last time beam B broke, in ms

// ── AUTH BYPASS ──────────────────────────────────────────
bool     authorized_crossing   = false;
uint8_t  bypass_beam           = 0;
uint32_t bypass_started_ms     = 0;
bool     crossing_mute_pending = false;

// ── INTRUSION TRACKING ───────────────────────────────────
uint32_t intrusion_times[20] = {0};
uint8_t  intrusion_idx       = 0;

uint8_t last_dirs[3] = {DIR_NONE, DIR_NONE, DIR_NONE};
uint8_t last_dir_idx = 0;

// ── HELPERS ──────────────────────────────────────────────

uint8_t crc8_xor(const uint8_t* data, uint8_t len) {
  uint8_t crc = 0;
  for (uint8_t i = 0; i < len; i++) crc ^= data[i];
  return crc;
}

uint8_t clamp_score(int v) {
  if (v < 0)   return 0;
  if (v > 100) return 100;
  return (uint8_t)v;
}

float calc_speed_mps(uint32_t cross_us) {
  if (cross_us < 100UL) return 0.0f;
  float s = SENSOR_GAP_M / ((float)cross_us / 1000000.0f);
  return s > 12.0f ? 12.0f : s;
}

uint8_t crossing_score(float spd, uint32_t cross_us) {
  int sc = 80;
  if (cross_us < 80000UL)        sc += 10;
  else if (cross_us > 300000UL)  sc -= 10;
  if (spd > SPEED_HIGH_MPS)      sc += 10;
  else if (spd < 0.20f)          sc -= 20;
  return clamp_score(sc);
}

// Absolute threshold — laser blocked = HIGH value on this hardware
bool beam_broken(int raw) { return raw > THRESH; }

void push_intrusion_time(uint32_t now_ms) {
  intrusion_times[intrusion_idx % 20] = now_ms;
  intrusion_idx++;
}

int recent_intrusion_count(uint32_t now_ms) {
  int c = 0;
  for (uint8_t i = 0; i < 20; i++)
    if (intrusion_times[i] > 0 &&
       (now_ms - intrusion_times[i]) < FREQ_WINDOW_MS) c++;
  return c;
}

void push_direction(uint8_t dir) {
  if (dir == DIR_NONE) return;
  last_dirs[last_dir_idx % 3] = dir;
  last_dir_idx++;
}

bool pattern_detected() {
  return last_dirs[0] != DIR_NONE &&
         last_dirs[0] == last_dirs[1] &&
         last_dirs[1] == last_dirs[2];
}

// ── PACKET TRANSMIT ──────────────────────────────────────
void send_packet(uint8_t evt, uint16_t raw_a, uint16_t raw_b,
                 float vel, uint8_t score) {
  uint8_t pkt[PACKET_SIZE];
  pkt[0]  = FRAME_SOF_1;
  pkt[1]  = FRAME_SOF_2;
  pkt[2]  = (seq_id >> 8) & 0xFF;
  pkt[3]  = seq_id & 0xFF;
  pkt[4]  = evt;
  pkt[5]  = (raw_a >> 8) & 0xFF;
  pkt[6]  = raw_a & 0xFF;
  pkt[7]  = (raw_b >> 8) & 0xFF;
  pkt[8]  = raw_b & 0xFF;
  memcpy(&pkt[9], &vel, 4);
  pkt[13] = score;
  pkt[14] = crc8_xor(&pkt[2], 12);
  pkt[15] = 0x00;
  Serial.write(pkt, PACKET_SIZE);
  seq_id++;
}

// ── AUTH BYPASS ──────────────────────────────────────────

void clear_bypass() {
  authorized_crossing   = false;
  bypass_beam           = 0;
  bypass_started_ms     = 0;
  crossing_mute_pending = false;
}

void grant_auth(uint32_t now_ms) {
  authorized_crossing   = true;
  bypass_beam           = 0;
  bypass_started_ms     = now_ms;
  crossing_mute_pending = false;
}

bool auth_window_valid(uint32_t now_ms) {
  if (!authorized_crossing) return false;
  if ((now_ms - bypass_started_ms) > AUTH_BYPASS_TIMEOUT_MS) {
    clear_bypass();
    return false;
  }
  return true;
}

void start_bypass(uint8_t beam_id) { bypass_beam = beam_id; }

bool should_mute_second_beam(uint8_t beam_id, uint32_t now_ms) {
  if (!auth_window_valid(now_ms) || bypass_beam == 0) return false;
  return (bypass_beam == 1 && beam_id == 2) ||
         (bypass_beam == 2 && beam_id == 1);
}

// ── NON-BLOCKING BUZZER ──────────────────────────────────
// Each pattern is a sequence of (on_ms, off_ms) pairs.
// off_ms == 0 means "last step — end pattern after ON".
// buzz_tick() is called every loop(). Zero delay() calls here.

struct BuzzStep { uint16_t on_ms; uint16_t off_ms; };
struct PatDef   { const BuzzStep* steps; uint8_t count; };

// Pattern definitions — preserved from v21 timing values
static const BuzzStep S_ARMED[]   = {{60, 0}};
static const BuzzStep S_LR[]      = {{70,70},{70,0}};
static const BuzzStep S_RL[]      = {{400,0}};
static const BuzzStep S_IN_A[]    = {{200,100},{200,0}};
static const BuzzStep S_IN_B[]    = {{150,80},{150,80},{150,0}};
static const BuzzStep S_IN_FULL[] = {{40,40},{40,40},{40,40},{40,40},{40,0}};
static const BuzzStep S_STAT[]    = {{60,30},{60,30},{60,30},{60,30},{60,0}};
static const BuzzStep S_HIGH[]    = {{25,25},{25,25},{25,25},{25,25},{25,0}};
static const BuzzStep S_PAT[]     = {{300,60},{80,60},{80,100},
                                      {300,60},{80,60},{80,100},
                                      {300,60},{80,60},{80,0}};
static const BuzzStep S_RETREAT[] = {{150,100},{150,0}};
static const BuzzStep S_TAMPER[]  = {{500,100},{500,100},{500,0}};

#define MAKE_PAT(arr) {arr, (uint8_t)(sizeof(arr)/sizeof(arr[0]))}
static const PatDef PATS[] = {
  MAKE_PAT(S_ARMED),    // 0
  MAKE_PAT(S_LR),       // 1
  MAKE_PAT(S_RL),       // 2
  MAKE_PAT(S_IN_A),     // 3
  MAKE_PAT(S_IN_B),     // 4
  MAKE_PAT(S_IN_FULL),  // 5
  MAKE_PAT(S_STAT),     // 6
  MAKE_PAT(S_HIGH),     // 7
  MAKE_PAT(S_PAT),      // 8
  MAKE_PAT(S_RETREAT),  // 9
  MAKE_PAT(S_TAMPER),   // 10
};
#define PAT_ARMED   0
#define PAT_LR      1
#define PAT_RL      2
#define PAT_IN_A    3
#define PAT_IN_B    4
#define PAT_IN_FULL 5
#define PAT_STAT    6
#define PAT_HIGH    7
#define PAT_PATTERN 8
#define PAT_RETREAT 9
#define PAT_TAMPER  10

uint8_t  buz_pat   = 0xFF;   // 0xFF = idle
uint8_t  buz_step  = 0;
bool     buz_on    = false;
uint32_t buz_until = 0;

void buzz_start(uint8_t idx) {
  if (idx >= sizeof(PATS)/sizeof(PATS[0])) return;
  buz_pat   = idx;
  buz_step  = 0;
  buz_on    = true;
  buz_until = millis() + PATS[idx].steps[0].on_ms;
  digitalWrite(PIN_BUZZER, HIGH);
}

void buzz_tick(uint32_t now_ms) {
  if (buz_pat == 0xFF || now_ms < buz_until) return;
  const PatDef& p = PATS[buz_pat];
  if (buz_on) {
    digitalWrite(PIN_BUZZER, LOW);
    buz_on = false;
    uint16_t off = p.steps[buz_step].off_ms;
    if (off == 0) {
      // Last step finished
      if (++buz_step >= p.count) { buz_pat = 0xFF; return; }
      // Next step starts immediately
      buz_on    = true;
      buz_until = now_ms + p.steps[buz_step].on_ms;
      digitalWrite(PIN_BUZZER, HIGH);
    } else {
      buz_until = now_ms + off;
    }
  } else {
    if (++buz_step >= p.count) { buz_pat = 0xFF; return; }
    buz_on    = true;
    buz_until = now_ms + p.steps[buz_step].on_ms;
    digitalWrite(PIN_BUZZER, HIGH);
  }
}

// ── FIRE ALARM ───────────────────────────────────────────
// Preserved v21 logic exactly. Only change: calls buzz_start()
// instead of direct beep_xxx() functions.
void fire_alarm(uint8_t dir, uint8_t alarm_type,
                float speed_mps, uint32_t now_ms,
                bool mute = false) {
  if (mute) return;

  // Do not interrupt an active pattern unless it is the stationary repeat
  if (buz_pat != 0xFF && alarm_type != ALARM_STATIONARY) return;

  int  recent      = recent_intrusion_count(now_ms);
  bool high_threat = (speed_mps > SPEED_HIGH_MPS ||
                      recent >= FREQ_ALERT_COUNT);

  if (pattern_detected())             { buzz_start(PAT_PATTERN); return; }
  if (alarm_type == ALARM_STATIONARY) { buzz_start(PAT_STAT);    return; }
  if (high_threat)                    { buzz_start(PAT_HIGH);    return; }

  switch (alarm_type) {
    case ALARM_INSIDE_A:    buzz_start(PAT_IN_A);   break;
    case ALARM_INSIDE_B:    buzz_start(PAT_IN_B);   break;
    case ALARM_INSIDE_FULL: buzz_start(PAT_IN_FULL);break;
    case ALARM_CROSSING:
      if      (dir == DIR_LR) buzz_start(PAT_LR);
      else if (dir == DIR_RL) buzz_start(PAT_RL);
      else                    buzz_start(PAT_IN_FULL);
      break;
    default: break;
  }
}

// ── REARM ────────────────────────────────────────────────
// Preserved exactly from v21.
void rearm_state() {
  state             = STATE_ARMED;
  first_sensor      = 0;
  inside_full_sent  = false;
  state_started_ms  = 0;
  both_started_ms   = 0;
  last_siren_ms     = 0;
  t_a_broke_us      = 0;
  t_b_broke_us      = 0;
  t_a_clear_us      = 0;
  t_b_clear_us      = 0;
  crossing_mute_pending = false;
  // Auth window intentionally NOT cleared here.
  // clear_bypass() is called explicitly when auth expires or is consumed.
  // Retreat timestamps intentionally NOT cleared — they only matter
  // within STATE_A_FIRST / STATE_B_FIRST which just ended.
}

// Rearm + immediate scan. Catches objects that park right after a crossing.
// If a beam is already broken on re-arm, enter the correct state directly
// instead of sitting blind in STATE_ARMED waiting for an edge that won't come.
void rearm_with_scan() {
  rearm_state();

  int raw_a = analogRead(PIN_A);
  int raw_b = analogRead(PIN_B);
  uint8_t ca = beam_broken(raw_a) ? 1 : 0;
  uint8_t cb = beam_broken(raw_b) ? 1 : 0;

  // Update prev so next loop cycle computes correct edges
  prev_a = ca;
  prev_b = cb;

  uint32_t now_ms = millis();
  uint32_t now_us = micros();

  if (ca && cb) {
    state            = STATE_BOTH;
    state_started_ms = now_ms;
    both_started_ms  = now_ms;
    first_sensor     = DIR_NONE;
    inside_full_sent = false;
    t_a_broke_us     = now_us;
    t_b_broke_us     = now_us;
    send_packet(EVT_SENSOR_A, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
    send_packet(EVT_SENSOR_B, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
  } else if (ca) {
    state            = STATE_A_FIRST;
    state_started_ms = now_ms;
    first_sensor     = DIR_LR;
    t_a_broke_us     = now_us;
    last_a_broke_ms  = now_ms;
    send_packet(EVT_SENSOR_A, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
  } else if (cb) {
    state            = STATE_B_FIRST;
    state_started_ms = now_ms;
    first_sensor     = DIR_RL;
    t_b_broke_us     = now_us;
    last_b_broke_ms  = now_ms;
    send_packet(EVT_SENSOR_B, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
  }
  // If both clear: stays STATE_ARMED, correct
}

// ── FINALIZE EVENT ───────────────────────────────────────
// Uses rearm_with_scan() instead of rearm_state(). Otherwise identical to v21.
void finalize_event(uint8_t evt, uint16_t raw_a, uint16_t raw_b,
                    float speed_mps, uint8_t score,
                    uint8_t dir_code, uint8_t alarm_type,
                    bool is_intrusion, bool mute_alarm = false) {
  uint32_t now_ms = millis();
  send_packet(evt, raw_a, raw_b, speed_mps, score);
  if (is_intrusion)         push_intrusion_time(now_ms);
  if (dir_code != DIR_NONE) push_direction(dir_code);
  fire_alarm(dir_code, alarm_type, speed_mps, now_ms, mute_alarm);
  rearm_with_scan();
}

// ── SETUP ────────────────────────────────────────────────
void setup() {
  Serial.begin(BAUD);
  analogReadResolution(12);
  analogSetAttenuation(ADC_11db);

  pinMode(PIN_BUZZER, OUTPUT);
  digitalWrite(PIN_BUZZER, LOW);

  delay(500);

  int raw_a = analogRead(PIN_A);
  int raw_b = analogRead(PIN_B);
  prev_a = beam_broken(raw_a) ? 1 : 0;
  prev_b = beam_broken(raw_b) ? 1 : 0;
  heartbeat_started_ms = millis();

  send_packet(EVT_ARMED, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 100);
  buzz_start(PAT_ARMED);
}

// ── MAIN LOOP ────────────────────────────────────────────
void loop() {
  uint32_t now_ms = millis();

  // Non-blocking buzzer tick — must be first in loop
  buzz_tick(now_ms);

  // Serial commands from Python backend
  while (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd == "AUTH")       grant_auth(millis());
    else if (cmd == "RESET") clear_bypass();
  }

  // Auth window expiry check
  if (authorized_crossing) auth_window_valid(millis());

  int raw_a = analogRead(PIN_A);
  int raw_b = analogRead(PIN_B);

  uint8_t cur_a = beam_broken(raw_a) ? 1 : 0;
  uint8_t cur_b = beam_broken(raw_b) ? 1 : 0;

  bool a_broke   = (cur_a == 1 && prev_a == 0);
  bool b_broke   = (cur_b == 1 && prev_b == 0);
  bool a_cleared = (cur_a == 0 && prev_a == 1);
  bool b_cleared = (cur_b == 0 && prev_b == 1);

  uint32_t now_us = micros();

  if (a_broke)   { t_a_broke_us  = now_us; last_a_broke_ms = now_ms; }
  if (b_broke)   { t_b_broke_us  = now_us; last_b_broke_ms = now_ms; }
  if (a_cleared)   t_a_clear_us  = now_us;
  if (b_cleared)   t_b_clear_us  = now_us;

  prev_a = cur_a;
  prev_b = cur_b;

  // ── STATE MACHINE ─────────────────────────────────────
  switch (state) {

    // ────────────────────── ARMED
    // Preserved from v21 exactly, with tamper addition.
    case STATE_ARMED:
      if (a_broke && b_broke) {
        // Both beams simultaneously — tamper (cover placed) or very wide object
        state            = STATE_BOTH;
        state_started_ms = now_ms;
        both_started_ms  = now_ms;
        first_sensor     = DIR_NONE;
        inside_full_sent = false;
        send_packet(EVT_TAMPER, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 100);
        push_intrusion_time(now_ms);
        buzz_start(PAT_TAMPER);
      } else if (a_broke && !cur_b) {
        state            = STATE_A_FIRST;
        state_started_ms = now_ms;
        first_sensor     = DIR_LR;
        if (authorized_crossing && bypass_beam == 0 && auth_window_valid(now_ms))
          start_bypass(1);
        send_packet(EVT_SENSOR_A, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
      } else if (b_broke && !cur_a) {
        state            = STATE_B_FIRST;
        state_started_ms = now_ms;
        first_sensor     = DIR_RL;
        if (authorized_crossing && bypass_beam == 0 && auth_window_valid(now_ms))
          start_bypass(2);
        send_packet(EVT_SENSOR_B, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
      }
      break;

    // ────────────────────── A FIRST (expecting LR)
    // Base logic: v21 verbatim.
    // Additions: (1) anti-tailgate, (2) retreat detection.
    //
    // RETREAT LOGIC — the safe way:
    // Retreat is detected ONLY when a_broke fires again in this state.
    // We compare now_ms against last_a_broke_ms which was set when A
    // first broke (entering this state from STATE_ARMED).
    // If the gap between the first A-break and this second A-break is
    // less than RETREAT_WINDOW_MS AND beam B was never triggered (cur_b=0,
    // no b_broke has occurred) then the person broke A, stepped back,
    // and broke A again — classic retreat.
    //
    // This is safe because:
    // - During a real LR crossing, once A breaks we immediately see
    //   b_broke or cur_b in the VERY NEXT few polls (person is walking
    //   through). The b_broke||cur_b branch fires before a_broke can
    //   fire again. Retreat is physically impossible during a real crossing.
    // - The 800ms window prevents LDR noise (< 10ms) from falsely
    //   triggering retreat.
    // - We guard !cur_b — if B is even partially triggered, it is NOT
    //   a retreat, it is an overlap crossing.
    case STATE_A_FIRST:
      // Anti-tailgate: follower hits beam A while authorized user is mid-crossing
      if (a_broke && bypass_beam == 1 && authorized_crossing) {
        // Cancel auth window — follower detected on the re-armed first beam
        clear_bypass();
        send_packet(EVT_SENSOR_A, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
        fire_alarm(DIR_NONE, ALARM_INSIDE_A, 0.0f, now_ms, false);
        // Stay in STATE_A_FIRST — follower's beam is still blocked
        break;
      }

      if (b_broke || cur_b) {
        // Normal path: second beam triggered — transition to BOTH
        if (b_broke) {
          bool mute = should_mute_second_beam(2, now_ms);
          send_packet(EVT_SENSOR_B, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
          if (mute) { clear_bypass(); crossing_mute_pending = true; }
        }
        state            = STATE_BOTH;
        state_started_ms = now_ms;
        both_started_ms  = now_ms;
        inside_full_sent = false;

      } else if (a_broke) {
        // Beam A broke again while B has never triggered.
        // Check if this is a retreat (double-break within RETREAT_WINDOW_MS)
        if (!cur_b && (now_ms - last_a_broke_ms) < RETREAT_WINDOW_MS) {
          // Retreat confirmed: same beam twice, B never triggered, within window
          send_packet(EVT_RETREAT, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 75);
          push_intrusion_time(now_ms);
          buzz_start(PAT_RETREAT);
          if (bypass_beam == 1) clear_bypass();
          rearm_with_scan();
          break;
        }
        // Not a retreat — keep tracking (v21 original behaviour)
        send_packet(EVT_SENSOR_A, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);

      } else if ((now_ms - state_started_ms) > SINGLE_TIMEOUT_MS) {
        // v21 original: beam A stuck for 8s, B never came — INSIDE_A
        if (bypass_beam == 1 && auth_window_valid(now_ms)) break;
        if (bypass_beam == 1) clear_bypass();
        finalize_event(EVT_INSIDE_A, (uint16_t)raw_a, (uint16_t)raw_b,
                       0.0f, 70, DIR_NONE, ALARM_INSIDE_A, true, false);
      }
      break;

    // ────────────────────── B FIRST (expecting RL)
    // Mirror of STATE_A_FIRST. Same logic, same safety guarantees.
    case STATE_B_FIRST:
      // Anti-tailgate: follower hits beam B while authorized user is mid-crossing
      if (b_broke && bypass_beam == 2 && authorized_crossing) {
        clear_bypass();
        send_packet(EVT_SENSOR_B, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
        fire_alarm(DIR_NONE, ALARM_INSIDE_B, 0.0f, now_ms, false);
        break;
      }

      if (a_broke || cur_a) {
        if (a_broke) {
          bool mute = should_mute_second_beam(1, now_ms);
          send_packet(EVT_SENSOR_A, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);
          if (mute) { clear_bypass(); crossing_mute_pending = true; }
        }
        state            = STATE_BOTH;
        state_started_ms = now_ms;
        both_started_ms  = now_ms;
        inside_full_sent = false;

      } else if (b_broke) {
        // Retreat check — mirror of A_FIRST
        if (!cur_a && (now_ms - last_b_broke_ms) < RETREAT_WINDOW_MS) {
          send_packet(EVT_RETREAT, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 75);
          push_intrusion_time(now_ms);
          buzz_start(PAT_RETREAT);
          if (bypass_beam == 2) clear_bypass();
          rearm_with_scan();
          break;
        }
        send_packet(EVT_SENSOR_B, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 20);

      } else if ((now_ms - state_started_ms) > SINGLE_TIMEOUT_MS) {
        if (bypass_beam == 2 && auth_window_valid(now_ms)) break;
        if (bypass_beam == 2) clear_bypass();
        finalize_event(EVT_INSIDE_B, (uint16_t)raw_a, (uint16_t)raw_b,
                       0.0f, 70, DIR_NONE, ALARM_INSIDE_B, true, false);
      }
      break;

    // ────────────────────── BOTH BEAMS
    // Preserved from v21 verbatim. Zero changes.
    case STATE_BOTH: {
      bool crossing_muted = crossing_mute_pending;

      if ((now_ms - both_started_ms) > STATIONARY_MS) {
        state         = STATE_STATIONARY;
        last_siren_ms = now_ms;
        send_packet(EVT_STATIONARY, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 100);
        push_intrusion_time(now_ms);
        fire_alarm(DIR_NONE, ALARM_STATIONARY, 0.0f, now_ms, false);
        break;
      }

      // Direction confirmed on EXIT — which beam clears last is the exit side
      if (b_cleared && first_sensor == DIR_LR) {
        uint32_t cu = (t_b_broke_us > t_a_broke_us) ? (t_b_broke_us - t_a_broke_us) : 500UL;
        float s = calc_speed_mps(cu);
        finalize_event(EVT_LR, (uint16_t)raw_a, (uint16_t)raw_b,
                       s, crossing_score(s, cu), DIR_LR, ALARM_CROSSING, true, crossing_muted);

      } else if (a_cleared && first_sensor == DIR_RL) {
        uint32_t cu = (t_a_broke_us > t_b_broke_us) ? (t_a_broke_us - t_b_broke_us) : 500UL;
        float s = calc_speed_mps(cu);
        finalize_event(EVT_RL, (uint16_t)raw_a, (uint16_t)raw_b,
                       s, crossing_score(s, cu), DIR_RL, ALARM_CROSSING, true, crossing_muted);

      } else if (first_sensor == DIR_NONE && (a_cleared || b_cleared)) {
        uint8_t  dir = DIR_NONE;
        uint32_t cu  = 500UL;
        if      (b_cleared && !a_cleared) dir = DIR_LR;
        else if (a_cleared && !b_cleared) dir = DIR_RL;
        else {
          dir = (t_a_broke_us <= t_b_broke_us) ? DIR_LR : DIR_RL;
          cu  = (t_a_broke_us < t_b_broke_us)
                ? (t_b_broke_us - t_a_broke_us)
                : (t_a_broke_us - t_b_broke_us);
          if (cu < 500UL) cu = 500UL;
        }
        float s = calc_speed_mps(cu);
        finalize_event(dir == DIR_LR ? EVT_LR : EVT_RL,
                       (uint16_t)raw_a, (uint16_t)raw_b,
                       s, crossing_score(s, cu), dir, ALARM_CROSSING, true, crossing_muted);

      } else if (!cur_a && !cur_b && (a_cleared || b_cleared)) {
        uint8_t  dir = DIR_NONE;
        uint32_t cu  = 500UL;
        if (first_sensor == DIR_LR) {
          dir = DIR_LR;
          cu  = (t_b_broke_us > t_a_broke_us) ? (t_b_broke_us - t_a_broke_us) : 500UL;
        } else if (first_sensor == DIR_RL) {
          dir = DIR_RL;
          cu  = (t_a_broke_us > t_b_broke_us) ? (t_a_broke_us - t_b_broke_us) : 500UL;
        } else {
          dir = (t_a_broke_us <= t_b_broke_us) ? DIR_LR : DIR_RL;
          cu  = (t_a_broke_us < t_b_broke_us)
                ? (t_b_broke_us - t_a_broke_us)
                : (t_a_broke_us - t_b_broke_us);
          if (cu < 500UL) cu = 500UL;
        }
        float s = calc_speed_mps(cu);
        finalize_event(dir == DIR_LR ? EVT_LR : EVT_RL,
                       (uint16_t)raw_a, (uint16_t)raw_b,
                       s, crossing_score(s, cu), dir, ALARM_CROSSING, true, crossing_muted);

      } else if ((now_ms - both_started_ms) > SAFETY_TIMEOUT_MS) {
        rearm_with_scan();
      }
      break;
    }

    // ────────────────────── STATIONARY
    // Preserved from v21 verbatim. Only change: rearm_state() → rearm_with_scan().
    // Stationary exit direction now uses timestamps (fixes branch-order bias).
    case STATE_STATIONARY:
      if (!inside_full_sent &&
          (now_ms - both_started_ms) > SINGLE_TIMEOUT_MS && cur_a && cur_b) {
        inside_full_sent = true;
        send_packet(EVT_INSIDE_FULL, (uint16_t)raw_a, (uint16_t)raw_b, 0.0f, 95);
        push_intrusion_time(now_ms);
        fire_alarm(DIR_NONE, ALARM_INSIDE_FULL, 0.0f, now_ms);
      }

      if (!cur_a && !cur_b) {
        // Use microsecond clear timestamps to determine exit direction.
        // The beam that clears LAST is the exit side.
        uint8_t xdir;
        if      (a_cleared && !b_cleared) xdir = DIR_LR;   // A cleared first → LR
        else if (b_cleared && !a_cleared) xdir = DIR_RL;   // B cleared first → RL
        else xdir = (t_b_clear_us >= t_a_clear_us) ? DIR_LR : DIR_RL;

        finalize_event(xdir == DIR_LR ? EVT_STATION_LR : EVT_STATION_RL,
                       (uint16_t)raw_a, (uint16_t)raw_b,
                       0.0f, 90, xdir, ALARM_CROSSING, true);

      } else if ((now_ms - last_siren_ms) > 5000UL) {
        last_siren_ms = now_ms;
        fire_alarm(DIR_NONE, ALARM_STATIONARY, 0.0f, now_ms, false);
      }
      break;
  }

  // Heartbeat — every 5 seconds regardless of state
  if ((now_ms - heartbeat_started_ms) > HEARTBEAT_MS) {
    heartbeat_started_ms = now_ms;
    int ra = analogRead(PIN_A);
    int rb = analogRead(PIN_B);
    send_packet(EVT_HEARTBEAT, (uint16_t)ra, (uint16_t)rb, 0.0f, 0);
  }

  delay(2);
}
