import argparse
import logging
import math
import os
import sys
import threading
import time
from collections import deque

import numpy as np
import pygame
from scapy.all import ICMP, IP, TCP, UDP, sniff

if os.name == "nt":
    import msvcrt
else:
    import select
    import termios
    import tty

# Define ANSI color codes
ANSI_COLORS = {
    "blue": "\033[34m",
    "green": "\033[32m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "reset": "\033[0m",
}

# Audio settings
SAMPLE_RATE = 44100
FLOW_TIMEOUT = 60  # Seconds
MAX_FLOW_DURATION = 300  # Seconds
TRAFFIC_WINDOW_SECONDS = 8.0
INSTANT_WINDOW_SECONDS = 1.0
TEMPO_BASELINE_STEP_BPM = 4.0
TEMPO_BASELINE_DEFAULT_OFFSET = -16.0
TEMPO_BASELINE_MIN_OFFSET = -72.0
TEMPO_BASELINE_MAX_OFFSET = 28.0

# Musical settings (deeper/groove-focused)
CHORD_PROGRESSION = [0, 3, 5, 7]  # i, III, iv, v (relative to C)
PROTOCOL_SCALES = {
    "TCP": [0, 3, 5, 7, 10],  # Minor pentatonic
    "UDP": [0, 2, 3, 5, 7, 9, 10],  # Dorian flavor
    "ICMP": [0, 1, 3, 5, 7, 8, 10],  # Phrygian flavor
}
PROTOCOL_COLOR_SHIFT = {
    "TCP": 0,
    "UDP": 1,
    "ICMP": -1,
}
PROTOCOL_TIMBRE = {
    "TCP": 0.24,
    "UDP": 0.42,
    "ICMP": 0.58,
}

# Flow tracking
flows = {}
flows_lock = threading.Lock()


def init_audio():
    """Initialize pygame mixer for low-latency mono synthesis."""
    pygame.mixer.pre_init(frequency=SAMPLE_RATE, size=-16, channels=1, buffer=512)
    pygame.mixer.init(frequency=SAMPLE_RATE, channels=1)
    pygame.mixer.set_num_channels(24)


# Setup logging
logger = logging.getLogger("pcapsing")
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(message)s")
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# File handler
file_handler = logging.FileHandler("flows.log")
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter("%(message)s")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)


def ansi_color(text, color):
    """Wrap text with ANSI color codes."""
    color_code = ANSI_COLORS.get(color, ANSI_COLORS["reset"])
    reset_code = ANSI_COLORS["reset"]
    return f"{color_code}{text}{reset_code}"


def midi_to_frequency(midi_note):
    """Convert MIDI note number to frequency in Hz."""
    return 440.0 * (2 ** ((midi_note - 69) / 12.0))


def synthesize_tone(frequency, duration, volume, timbre):
    """
    Create a warm synthesized tone with simple ADSR envelope.

    timbre: 0.0..1.0 controls harmonic richness.
    """
    if frequency <= 0 or duration <= 0 or volume <= 0:
        return None

    sample_count = max(1, int(SAMPLE_RATE * duration))
    t = np.linspace(0, duration, sample_count, False)

    fundamental = np.sin(2 * np.pi * frequency * t)
    second = np.sin(2 * np.pi * frequency * 2.0 * t)
    third = np.sin(2 * np.pi * frequency * 3.0 * t)

    waveform = (
        0.72 * fundamental
        + (0.20 + 0.16 * timbre) * second
        + (0.08 + 0.12 * timbre) * third
    )

    # Subtle slow movement to avoid static tone feel.
    waveform *= 0.93 + 0.07 * np.sin(2 * np.pi * 5.0 * t)

    # Envelope to avoid clicks.
    attack = max(1, int(sample_count * 0.06))
    decay = max(1, int(sample_count * 0.12))
    release = max(1, int(sample_count * 0.20))
    sustain_level = 0.68

    envelope = np.full(sample_count, sustain_level, dtype=np.float32)
    envelope[:attack] = np.linspace(0.0, 1.0, attack)
    decay_end = min(sample_count, attack + decay)
    envelope[attack:decay_end] = np.linspace(1.0, sustain_level, decay_end - attack)
    envelope[-release:] = np.linspace(envelope[-release], 0.0, release)

    waveform = np.clip(waveform * envelope * volume, -1.0, 1.0)
    int_waveform = (waveform * 32767).astype(np.int16)
    return pygame.sndarray.make_sound(int_waveform)


def synthesize_kick(duration=0.22, volume=0.3):
    """Deep kick made from a fast pitch-drop sine."""
    sample_count = max(1, int(SAMPLE_RATE * duration))
    t = np.linspace(0, duration, sample_count, False)

    # Exponential-ish downward pitch sweep.
    freq = 130.0 * np.exp(-t * 15.0) + 38.0
    phase = 2.0 * np.pi * np.cumsum(freq) / SAMPLE_RATE
    body = np.sin(phase)
    click = 0.2 * np.sin(2.0 * np.pi * 1800.0 * t) * np.exp(-t * 55.0)
    envelope = np.exp(-t * 11.0)

    waveform = np.clip((body + click) * envelope * volume, -1.0, 1.0)
    return pygame.sndarray.make_sound((waveform * 32767).astype(np.int16))


def synthesize_snare(duration=0.18, volume=0.22):
    """Soft snare from shaped noise + short tone."""
    sample_count = max(1, int(SAMPLE_RATE * duration))
    t = np.linspace(0, duration, sample_count, False)

    noise = np.random.uniform(-1.0, 1.0, sample_count)
    low = np.convolve(noise, np.ones(14) / 14.0, mode="same")
    noise_hp = noise - low
    tone = 0.24 * np.sin(2.0 * np.pi * 210.0 * t)
    envelope = np.exp(-t * 24.0)

    waveform = np.clip((0.8 * noise_hp + tone) * envelope * volume, -1.0, 1.0)
    return pygame.sndarray.make_sound((waveform * 32767).astype(np.int16))


def synthesize_hihat(duration=0.07, volume=0.12):
    """Short closed hi-hat from high-passed noise."""
    sample_count = max(1, int(SAMPLE_RATE * duration))
    t = np.linspace(0, duration, sample_count, False)

    noise = np.random.uniform(-1.0, 1.0, sample_count)
    low = np.convolve(noise, np.ones(20) / 20.0, mode="same")
    noise_hp = noise - low
    envelope = np.exp(-t * 60.0)

    waveform = np.clip(noise_hp * envelope * volume, -1.0, 1.0)
    return pygame.sndarray.make_sound((waveform * 32767).astype(np.int16))


class Flow:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.bytes_src_to_dst = 0
        self.bytes_dst_to_src = 0
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.state = "INIT"

    def update(self, packet):
        self.last_seen = time.time()
        pkt_len = len(packet)

        if self.protocol == "TCP" and TCP in packet:
            pkt_layer = packet[TCP]
        elif self.protocol == "UDP" and UDP in packet:
            pkt_layer = packet[UDP]
        elif self.protocol == "ICMP" and ICMP in packet:
            pkt_layer = packet[ICMP]
        else:
            return

        if packet[IP].src == self.src_ip and getattr(pkt_layer, "sport", None) == self.src_port:
            self.bytes_src_to_dst += pkt_len
        else:
            self.bytes_dst_to_src += pkt_len

        if self.protocol == "TCP":
            flags = int(pkt_layer.flags)
            if flags & 0x04:
                self.state = "RESET"
            elif flags & 0x01:
                self.state = "FIN_WAIT"
            elif (flags & 0x12) == 0x12:
                self.state = "SYN_RECEIVED"
            elif flags & 0x02:
                self.state = "SYN_SENT"
            elif flags & 0x10:
                self.state = "ESTABLISHED"

    def total_bytes(self):
        return self.bytes_src_to_dst + self.bytes_dst_to_src

    def __str__(self):
        duration = int(self.last_seen - self.start_time)
        return (
            f"{self.protocol} Flow {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} | "
            f"Bytes: {self.bytes_src_to_dst}/{self.bytes_dst_to_src} | "
            f"Duration: {duration}s | State: {self.state}"
        )


class TrafficStats:
    """Maintains recent traffic activity used by the melody engine."""

    def __init__(self, window_seconds=TRAFFIC_WINDOW_SECONDS, instant_window=INSTANT_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.instant_window = instant_window
        self.lock = threading.Lock()
        self.events = deque()  # (timestamp, protocol, packet_length)
        self.window_packets = 0
        self.window_bytes = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}

    def _prune_locked(self, now_ts):
        cutoff = now_ts - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            _, protocol, pkt_len = self.events.popleft()
            self.window_packets = max(0, self.window_packets - 1)
            self.window_bytes = max(0, self.window_bytes - pkt_len)
            if protocol in self.protocol_counts:
                self.protocol_counts[protocol] = max(0, self.protocol_counts[protocol] - 1)

    def record_packet(self, protocol, pkt_len):
        now_ts = time.time()
        with self.lock:
            self.events.append((now_ts, protocol, pkt_len))
            self.window_packets += 1
            self.window_bytes += pkt_len
            if protocol in self.protocol_counts:
                self.protocol_counts[protocol] += 1
            self._prune_locked(now_ts)

    def snapshot(self, active_flows):
        now_ts = time.time()
        with self.lock:
            self._prune_locked(now_ts)

            packets = self.window_packets
            bytes_count = self.window_bytes
            pps = packets / self.window_seconds
            bps = bytes_count / self.window_seconds

            instant_cutoff = now_ts - self.instant_window
            instant_packets = 0
            for event_ts, _, _ in reversed(self.events):
                if event_ts < instant_cutoff:
                    break
                instant_packets += 1
            instant_pps = instant_packets / self.instant_window

            proto_counts = {k: max(0, v) for k, v in self.protocol_counts.items()}

        total_proto_packets = sum(proto_counts.values())
        if total_proto_packets > 0:
            dominant_protocol = max(proto_counts, key=proto_counts.get)
            protocol_mix = {k: v / total_proto_packets for k, v in proto_counts.items()}
        else:
            dominant_protocol = "TCP"
            protocol_mix = {k: 0.0 for k in proto_counts}

        burstiness = 0.0
        if pps > 0.05:
            burstiness = max(0.0, min(2.0, instant_pps / (pps + 1e-6)))

        return {
            "pps": pps,
            "bps": bps,
            "instant_pps": instant_pps,
            "burstiness": burstiness,
            "dominant_protocol": dominant_protocol,
            "protocol_mix": protocol_mix,
            "active_flows": active_flows,
        }


class MelodyEngine:
    """Continuously generates groove-oriented music driven by traffic rhythm."""

    def __init__(self, traffic_stats, stop_event):
        self.traffic_stats = traffic_stats
        self.stop_event = stop_event
        self.current_bpm = 64.0
        self.current_swing = 0.57
        self.tempo_baseline_offset = TEMPO_BASELINE_DEFAULT_OFFSET
        self.tempo_lock = threading.Lock()
        self.smoothed_intensity = 0.08
        self.step_index = 0
        self.degree_cursor = 0
        self.last_lead_midi = 57
        self.next_status_log_ts = 0.0

    def adjust_tempo_baseline(self, delta_bpm):
        """Adjust baseline tempo offset while preserving traffic-driven behavior."""
        with self.tempo_lock:
            self.tempo_baseline_offset = max(
                TEMPO_BASELINE_MIN_OFFSET,
                min(TEMPO_BASELINE_MAX_OFFSET, self.tempo_baseline_offset + delta_bpm),
            )
            return self.tempo_baseline_offset

    def reset_tempo_baseline(self):
        with self.tempo_lock:
            self.tempo_baseline_offset = 0.0
            return self.tempo_baseline_offset

    def get_tempo_baseline_offset(self):
        with self.tempo_lock:
            return self.tempo_baseline_offset

    def _target_intensity(self, snapshot):
        pps_component = min(1.0, math.log1p(snapshot["pps"]) / math.log1p(180.0))
        flow_component = min(1.0, snapshot["active_flows"] / 32.0)
        bps_component = min(1.0, math.log1p(snapshot["bps"]) / math.log1p(220000.0))
        return max(0.05, 0.55 * pps_component + 0.25 * flow_component + 0.20 * bps_component)

    def _update_tempo(self, snapshot):
        baseline_offset = self.get_tempo_baseline_offset()

        target_bpm = 74.0 + baseline_offset + min(42.0, math.sqrt(snapshot["pps"] + 1.0) * 6.2)
        target_bpm += min(9.0, snapshot["burstiness"] * 4.5)
        self.current_bpm += 0.09 * (target_bpm - self.current_bpm)
        min_bpm = max(38.0, 70.0 + baseline_offset)
        max_bpm = max(min_bpm + 12.0, 126.0 + baseline_offset)
        self.current_bpm = max(min_bpm, min(max_bpm, self.current_bpm))

        target_swing = 0.54 + min(0.10, max(0.0, snapshot["burstiness"] - 0.8) * 0.05 + self.smoothed_intensity * 0.03)
        self.current_swing += 0.16 * (target_swing - self.current_swing)
        self.current_swing = max(0.52, min(0.64, self.current_swing))

        # 16th-note base with swing applied across step pairs.
        base_16th = 60.0 / self.current_bpm / 4.0
        pair_duration = base_16th * 2.0
        if self.step_index % 2 == 0:
            return pair_duration * self.current_swing
        return pair_duration * (1.0 - self.current_swing)

    def _play_sound(self, sound):
        if sound is None:
            return
        try:
            sound.play()
        except Exception as exc:
            logger.error(f"{ansi_color('Audio playback error:', 'red')} {exc}")

    def _compose_step(self, snapshot, step_seconds):
        dominant = snapshot["dominant_protocol"]
        scale = PROTOCOL_SCALES[dominant]
        chord = CHORD_PROGRESSION[(self.step_index // 16) % len(CHORD_PROGRESSION)]
        step = self.step_index % 16
        intensity = self.smoothed_intensity
        burst = snapshot["burstiness"]

        protocol_mix = snapshot["protocol_mix"]
        blended_timbre = (
            protocol_mix.get("TCP", 0.0) * PROTOCOL_TIMBRE["TCP"]
            + protocol_mix.get("UDP", 0.0) * PROTOCOL_TIMBRE["UDP"]
            + protocol_mix.get("ICMP", 0.0) * PROTOCOL_TIMBRE["ICMP"]
        )
        if blended_timbre <= 0:
            blended_timbre = PROTOCOL_TIMBRE[dominant]

        color_shift = int(
            round(
                protocol_mix.get("TCP", 0.0) * PROTOCOL_COLOR_SHIFT["TCP"]
                + protocol_mix.get("UDP", 0.0) * PROTOCOL_COLOR_SHIFT["UDP"]
                + protocol_mix.get("ICMP", 0.0) * PROTOCOL_COLOR_SHIFT["ICMP"]
            )
        )

        # Groove percussion.
        kick_hit = step in {0, 8} or (intensity > 0.22 and step in {6, 14}) or (burst > 1.15 and step in {3, 11})
        snare_hit = step in {4, 12} or (intensity > 0.62 and step == 15)
        hat_hit = (step % 2 == 1) or (intensity > 0.45 and step in {2, 6, 10, 14})

        if kick_hit:
            kick = synthesize_kick(duration=max(0.11, step_seconds * 1.45), volume=0.18 + 0.28 * intensity)
            self._play_sound(kick)
        if snare_hit:
            snare = synthesize_snare(duration=max(0.08, step_seconds * 1.15), volume=0.08 + 0.20 * intensity)
            self._play_sound(snare)
        if hat_hit:
            hat_volume = 0.03 + 0.08 * intensity + (0.02 if step in {3, 7, 11, 15} else 0.0)
            hat = synthesize_hihat(duration=max(0.04, step_seconds * 0.65), volume=hat_volume)
            self._play_sound(hat)

        # Grave background bed: low pad chords every half bar.
        if step in {0, 8}:
            pad_root = 43 + chord
            pad_duration = step_seconds * (8.4 if step == 0 else 6.8)
            pad_volume = 0.03 + 0.05 * intensity
            for note in (pad_root, pad_root + 7, pad_root + 10):
                pad_sound = synthesize_tone(
                    midi_to_frequency(note),
                    duration=pad_duration,
                    volume=pad_volume,
                    timbre=0.08 + 0.16 * blended_timbre,
                )
                self._play_sound(pad_sound)

        # Bass groove line.
        bass_pattern = {0: 0, 3: 2, 6: 4, 8: 0, 10: 2, 11: 3, 14: 4}
        if step in bass_pattern:
            bass_degree = bass_pattern[step] % len(scale)
            bass_midi = 31 + chord + scale[bass_degree] + int(round(color_shift * 0.5))
            bass_midi = int(max(28, min(50, bass_midi)))
            bass_duration = step_seconds * (2.4 if step in {0, 8} else 1.7)
            bass_volume = 0.06 + 0.15 * intensity
            bass_sound = synthesize_tone(
                midi_to_frequency(bass_midi),
                duration=bass_duration,
                volume=bass_volume,
                timbre=0.05,
            )
            self._play_sound(bass_sound)

        # Syncopated lead melody.
        lead_steps = {1, 7, 9, 13}
        if intensity > 0.30:
            lead_steps.update({3, 10, 15})
        if intensity > 0.60 or burst > 1.20:
            lead_steps.update({5, 11})

        if step in lead_steps:
            motion = int(snapshot["instant_pps"] * 0.22 + snapshot["active_flows"] * 0.14 + burst * 1.8)
            self.degree_cursor = (self.degree_cursor + motion + 1) % len(scale)

            target_midi = 55 + chord + scale[self.degree_cursor] + color_shift

            # Keep melodic movement smooth and pleasant.
            while target_midi - self.last_lead_midi > 5:
                target_midi -= 12
            while self.last_lead_midi - target_midi > 5:
                target_midi += 12

            target_midi = int(max(50, min(79, target_midi)))
            self.last_lead_midi = target_midi

            lead_duration = max(0.05, step_seconds * (0.82 if step % 2 == 0 else 0.72))
            lead_volume = 0.05 + 0.17 * intensity
            lead_timbre = min(0.72, 0.28 + blended_timbre * 0.5)
            lead_sound = synthesize_tone(
                midi_to_frequency(target_midi),
                duration=lead_duration,
                volume=lead_volume,
                timbre=lead_timbre,
            )
            self._play_sound(lead_sound)

            if intensity > 0.55 and step in {10, 15}:
                harmony_sound = synthesize_tone(
                    midi_to_frequency(min(84, target_midi + 7)),
                    duration=max(0.05, lead_duration * 0.72),
                    volume=lead_volume * 0.40,
                    timbre=min(1.0, lead_timbre + 0.12),
                )
                self._play_sound(harmony_sound)

    def _maybe_log_status(self, snapshot):
        now_ts = time.time()
        if now_ts < self.next_status_log_ts:
            return

        self.next_status_log_ts = now_ts + 5.0
        timestamp = time.strftime("[%m/%d/%y %H:%M:%S]")
        protocol = snapshot["dominant_protocol"]
        protocol_color = {"TCP": "blue", "UDP": "green", "ICMP": "magenta"}.get(protocol, "reset")
        message = (
            f"{timestamp} Melody | BPM:{self.current_bpm:5.1f} "
            f"PPS:{snapshot['pps']:6.1f} ActiveFlows:{snapshot['active_flows']:4d} "
            f"Dominant:{ansi_color(protocol, protocol_color)} "
            f"Burst:{snapshot['burstiness']:.2f} Swing:{self.current_swing:.2f} "
            f"BaseShift:{self.get_tempo_baseline_offset():+4.0f}"
        )
        logger.info(message)

    def run(self):
        while not self.stop_event.is_set():
            loop_start = time.time()

            with flows_lock:
                active_flows = len(flows)

            snapshot = self.traffic_stats.snapshot(active_flows)
            target_intensity = self._target_intensity(snapshot)
            self.smoothed_intensity += 0.18 * (target_intensity - self.smoothed_intensity)
            step_seconds = self._update_tempo(snapshot)
            self._compose_step(snapshot, step_seconds)

            self._maybe_log_status(snapshot)
            self.step_index += 1

            elapsed = time.time() - loop_start
            sleep_for = max(0.01, step_seconds - elapsed)
            self.stop_event.wait(sleep_for)


def log_hotkey_help():
    logger.info(
        "Tempo hotkeys: "
        + ansi_color("[ or - slower", "yellow")
        + " | "
        + ansi_color("] or = faster", "yellow")
        + " | "
        + ansi_color("0 reset baseline", "yellow")
    )


def handle_tempo_hotkey(char, melody_engine):
    if char in ("-", "_", "["):
        baseline = melody_engine.adjust_tempo_baseline(-TEMPO_BASELINE_STEP_BPM)
        logger.info(f"{ansi_color('Tempo baseline', 'cyan')} {baseline:+.0f} BPM")
        return

    if char in ("=", "+", "]"):
        baseline = melody_engine.adjust_tempo_baseline(TEMPO_BASELINE_STEP_BPM)
        logger.info(f"{ansi_color('Tempo baseline', 'cyan')} {baseline:+.0f} BPM")
        return

    if char == "0":
        melody_engine.reset_tempo_baseline()
        logger.info(f"{ansi_color('Tempo baseline reset to 0 BPM', 'cyan')}")
        return

    if char in ("h", "H", "?"):
        log_hotkey_help()


def hotkey_control_thread(stop_event, melody_engine):
    """
    Listen for tempo hotkeys while sniffing runs.
    """
    if not sys.stdin.isatty():
        logger.info(
            ansi_color(
                "Hotkeys disabled (stdin is not a TTY). Run in an interactive terminal to use tempo keys.",
                "yellow",
            )
        )
        return

    if os.name == "nt":
        while not stop_event.is_set():
            if msvcrt.kbhit():
                try:
                    key = msvcrt.getwch()
                    handle_tempo_hotkey(key, melody_engine)
                except Exception as exc:
                    logger.warning(f"{ansi_color('Hotkey read error:', 'yellow')} {exc}")
            else:
                stop_event.wait(0.1)
        return

    fd = sys.stdin.fileno()
    original_settings = None
    try:
        original_settings = termios.tcgetattr(fd)
        tty.setcbreak(fd)

        while not stop_event.is_set():
            ready, _, _ = select.select([sys.stdin], [], [], 0.2)
            if not ready:
                continue

            key = sys.stdin.read(1)
            if key:
                handle_tempo_hotkey(key, melody_engine)
    except Exception as exc:
        logger.warning(f"{ansi_color('Hotkey control unavailable:', 'yellow')} {exc}")
    finally:
        if original_settings is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, original_settings)
            except Exception:
                pass


def log_flow_summary(flow, label="closed"):
    protocol_color = {"TCP": "blue", "UDP": "green", "ICMP": "magenta"}.get(flow.protocol, "reset")
    timestamp = time.strftime("[%m/%d/%y %H:%M:%S]")
    flow_str = ansi_color(str(flow), protocol_color)
    logger.info(f"{timestamp} Flow {label}: {flow_str}")


def flow_monitor_thread(stop_event):
    """
    Monitor flow lifecycle for cleanup; no direct sound triggering.
    """
    while not stop_event.wait(1.0):
        current_time = time.time()
        expired_flows = []

        with flows_lock:
            for flow_id, flow in list(flows.items()):
                if current_time - flow.last_seen > FLOW_TIMEOUT:
                    expired_flows.append((flow_id, flow))
                elif current_time - flow.start_time > MAX_FLOW_DURATION:
                    flow.start_time = current_time
                    flow.bytes_src_to_dst = 0
                    flow.bytes_dst_to_src = 0

            for flow_id, _ in expired_flows:
                del flows[flow_id]

        for _, flow in expired_flows:
            # Keep logs concise: only report meaningful flows.
            if flow.total_bytes() > 0:
                log_flow_summary(flow, label="expired")


traffic_stats = TrafficStats()


def packet_handler(packet):
    """Handle incoming packets and update flows + traffic stats."""
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol_num = packet[IP].proto
    pkt_len = len(packet)

    if protocol_num == 6 and TCP in packet:
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif protocol_num == 17 and UDP in packet:
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif protocol_num == 1 and ICMP in packet:
        proto = "ICMP"
        src_port = 0
        dst_port = 0
    else:
        return

    traffic_stats.record_packet(proto, pkt_len)

    if proto == "ICMP":
        flow_id = (src_ip, 0, dst_ip, 0, proto)
        reverse_flow_id = (dst_ip, 0, src_ip, 0, proto)
    else:
        flow_id = (src_ip, src_port, dst_ip, dst_port, proto)
        reverse_flow_id = (dst_ip, dst_port, src_ip, src_port, proto)

    with flows_lock:
        if flow_id in flows:
            flows[flow_id].update(packet)
        elif reverse_flow_id in flows:
            flows[reverse_flow_id].update(packet)
        else:
            flows[flow_id] = Flow(src_ip, src_port, dst_ip, dst_port, proto)


def main():
    parser = argparse.ArgumentParser(
        description="Network traffic sonification: continuous groove that adapts to live traffic rhythm"
    )
    parser.add_argument("--tcp", action="store_true", help="Include only TCP traffic")
    parser.add_argument("--udp", action="store_true", help="Include only UDP traffic")
    parser.add_argument("--icmp", action="store_true", help="Include only ICMP traffic")
    parser.add_argument(
        "--include-multicast",
        action="store_true",
        help="Include multicast and broadcast traffic",
    )
    parser.add_argument("--interface", "-i", type=str, help="Network interface to sniff on")
    args = parser.parse_args()

    filters = []
    if args.tcp:
        filters.append("tcp")
    if args.udp:
        filters.append("udp")
    if args.icmp:
        filters.append("icmp")
    if not args.include_multicast:
        filters.append("not multicast and not broadcast")
    filter_str = " and ".join(filters) if filters else None

    timestamp = time.strftime("[%m/%d/%y %H:%M:%S]")
    filter_display = ansi_color(filter_str if filter_str else "None", "cyan")
    interface_display = ansi_color(args.interface, "magenta") if args.interface else "None"
    startup_message = (
        f"{timestamp} Starting Continuous Traffic Groove Monitor...\n"
        f"{timestamp} Filter applied: {filter_display}\n"
        f"{timestamp} Interface: {interface_display}\n"
        f"{timestamp} Tempo keys: [-/=] slower/faster baseline, [0] reset, [h] help\n"
        f"{timestamp} Starting tempo baseline shift: {TEMPO_BASELINE_DEFAULT_OFFSET:+.0f} BPM"
    )
    logger.info(startup_message)

    try:
        init_audio()
    except Exception as exc:
        logger.error(f"{ansi_color('Failed to initialize audio:', 'red')} {exc}")
        return

    stop_event = threading.Event()
    melody_engine = MelodyEngine(traffic_stats, stop_event)

    melody_thread = threading.Thread(target=melody_engine.run, daemon=True)
    monitor_thread = threading.Thread(target=flow_monitor_thread, args=(stop_event,), daemon=True)
    hotkey_thread = threading.Thread(target=hotkey_control_thread, args=(stop_event, melody_engine), daemon=True)
    melody_thread.start()
    monitor_thread.start()
    hotkey_thread.start()

    try:
        sniff(filter=filter_str, prn=packet_handler, iface=args.interface, store=False)
    except KeyboardInterrupt:
        logger.info(f"{ansi_color('[Stopping packet sniffing.]', 'yellow')}")
    finally:
        stop_event.set()
        melody_thread.join(timeout=2.0)
        monitor_thread.join(timeout=2.0)
        hotkey_thread.join(timeout=1.0)
        try:
            pygame.mixer.fadeout(300)
            pygame.mixer.quit()
        except Exception:
            pass


if __name__ == "__main__":
    main()
