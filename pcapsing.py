import argparse
from collections import deque
from copy import copy
from functools import partial
import logging
from pathlib import Path
import queue
import re
import select
import sys
import termios
import threading
import time
import tty

import numpy as np
import pygame
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP

# Avoid root-owned cache files when packet capture is launched through sudo.
sys.dont_write_bytecode = True

# Define ANSI color codes
ANSI_COLORS = {
    'blue': '\033[34m',
    'green': '\033[32m',
    'magenta': '\033[35m',
    'cyan': '\033[36m',
    'yellow': '\033[33m',
    'red': '\033[31m',
    'reset': '\033[0m'
}

# Audio settings
SAMPLE_RATE = 44100  # Samples per second
DURATION = 0.2        # Duration of each tone in seconds (reduced from 0.5)
AMBIENT_DURATION = 12.0  # Duration of overlapping ambient pads
AMBIENT_INTERVAL = 5.0  # Seconds between traffic snapshots in ambient mode
MAX_FLOW_DURATION = 300  # 5 minutes in seconds

# Initialize pygame mixer with mono sound and multiple channels
pygame.mixer.init(frequency=SAMPLE_RATE, channels=1)
pygame.mixer.set_num_channels(32)  # Increase number of channels to handle multiple sounds

# Create a queue for audio playback with increased maxsize
audio_queue = queue.Queue(maxsize=1000)  # Increased from 100 to 1000

# Flow tracking
flows = {}
flows_lock = threading.Lock()
FLOW_TIMEOUT = 60  # Seconds

# Recent traffic used to drive the optional ambient soundscape
ambient_stats = {
    protocol: {'bytes': 0, 'packets': 0}
    for protocol in ('TCP', 'UDP', 'ICMP')
}
ambient_stats_lock = threading.Lock()

# Runtime controls for changing the soundscape while capturing
MUSIC_PRESETS = {
    'calm': {'interval': 8.0, 'duration': 16.0, 'volume_factor': 0.55},
    'balanced': {
        'interval': AMBIENT_INTERVAL,
        'duration': AMBIENT_DURATION,
        'volume_factor': 1.0,
    },
    'active': {'interval': 2.5, 'duration': 7.0, 'volume_factor': 1.35},
}
# Circle-of-fifths order keeps automatic and manual root changes consonant.
ROOT_NOTES = (
    ('C', 0),
    ('G', 7),
    ('D', 2),
    ('A', 9),
    ('E', 4),
    ('B', 11),
    ('F#', 6),
    ('C#', 1),
    ('G#', 8),
    ('D#', 3),
    ('A#', 10),
    ('F', 5),
)
ROOT_CHOICES = ('auto',) + tuple(note for note, _ in ROOT_NOTES)
BACKGROUND_MODES = ('auto', 'synapses', 'clusters', 'pulse')
SCENE_BY_PROTOCOL = {'TCP': 'synapses', 'UDP': 'clusters', 'ICMP': 'pulse'}
SCENE_UPDATE_INTERVAL = 1.0
SCENE_HOLD_SECONDS = 8.0
SCENE_CROSSFADE_SECONDS = 12.0
SCENE_SWITCH_MARGIN = 0.08
VIEW_PAN_STEP = 0.02
DEFAULT_MASTER_VOLUME = 1.3
ROOT_HOLD_SECONDS = {'low': 45.0, 'medium': 30.0, 'high': 15.0}
ROOT_MANUAL_OVERRIDE_SECONDS = 60.0
VARIATION_LEVELS = ('low', 'medium', 'high')
VARIATION_CONFIG = {
    'low': {
        'motif_interval': 6.0,
        'motif_notes': 1,
        'motif_duration': 4.0,
        'note_spacing': 1.0,
        'accent_interval': 4.0,
        'volume_factor': 0.55,
    },
    'medium': {
        'motif_interval': 3.0,
        'motif_notes': 2,
        'motif_duration': 3.0,
        'note_spacing': 0.65,
        'accent_interval': 1.4,
        'volume_factor': 0.78,
    },
    'high': {
        'motif_interval': 1.5,
        'motif_notes': 4,
        'motif_duration': 1.8,
        'note_spacing': 0.35,
        'accent_interval': 0.5,
        'volume_factor': 1.0,
    },
}
SCENE_SCALES = {
    'synapses': (0, 2, 5, 7, 9),
    'clusters': (0, 3, 5, 7, 10),
    'pulse': (0, 1, 6, 7, 10),
}
SCENE_AUDIO_CONFIG = {
    'synapses': {
        'protocol_transpose': {'TCP': 0, 'UDP': 0, 'ICMP': 0},
        'partials': ((1.0, 1.0), (1.004, 0.35), (2.0, 0.18)),
        'lfo_rate': 0.05,
        'lfo_depth': 0.15,
        'attack': 2.0,
        'release': 3.0,
        'delay': 0.22,
        'volume_factor': 0.78,
    },
    'clusters': {
        'protocol_transpose': {'TCP': -5, 'UDP': -2, 'ICMP': -7},
        'partials': ((0.5, 0.38), (1.0, 1.0), (1.5, 0.16)),
        'lfo_rate': 0.02,
        'lfo_depth': 0.10,
        'attack': 3.0,
        'release': 4.0,
        'delay': 0.38,
        'volume_factor': 0.86,
    },
    'pulse': {
        'protocol_transpose': {'TCP': -6, 'UDP': 1, 'ICMP': 6},
        'partials': ((1.0, 1.0), (1.5, 0.28), (2.01, 0.22)),
        'lfo_rate': 0.11,
        'lfo_depth': 0.32,
        'attack': 1.0,
        'release': 2.2,
        'delay': 0.14,
        'volume_factor': 0.62,
    },
}
music_state = {
    'paused': False,
    'muted': False,
    'master_volume': DEFAULT_MASTER_VOLUME,
    'preset': 'balanced',
    'root_index': 0,
    'root_auto': True,
    'root_override_until': 0.0,
    'pad_duration': AMBIENT_DURATION,
    'background_index': 0,
    'fullscreen': False,
    'view_x': 0.0,
    'view_y': 0.0,
    'variation_index': 1,
}
music_state_lock = threading.Lock()
scene_input = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
scene_input_lock = threading.Lock()
scene_state = {
    'current': 'synapses',
    'previous': 'synapses',
    'candidate': 'synapses',
    'candidate_since': time.monotonic(),
    'transition_started': time.monotonic() - SCENE_CROSSFADE_SECONDS,
    'activity': {'TCP': 0.0, 'UDP': 0.0, 'ICMP': 0.0},
}
scene_state_lock = threading.Lock()
motif_stats = {
    'bytes': 0,
    'packets': 0,
    'packet_size_total': 0,
    'forward': 0,
    'reverse': 0,
    'new_flows': 0,
    'destinations': set(),
    'ports': set(),
    'protocol_packets': {'TCP': 0, 'UDP': 0, 'ICMP': 0},
}
motif_stats_lock = threading.Lock()
phrase_state = {'chord_degree': 0, 'inversion': 0}
phrase_state_lock = threading.Lock()
network_event_queue = queue.Queue(maxsize=256)
auto_root_input = {
    'packets': 0,
    'forward': 0,
    'reverse': 0,
    'new_flows': 0,
    'destinations': set(),
    'last_change': time.monotonic(),
}
auto_root_input_lock = threading.Lock()

# Terminal UI state, traffic counters, and buffered log messages
ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
tui_active = False
tui_messages = deque(maxlen=5)
tui_message_lock = threading.Lock()
visual_stats = {
    'pending_bytes': 0,
    'pending_packets': 0,
    'total_bytes': 0,
    'total_packets': 0,
    'protocol_packets': {'TCP': 0, 'UDP': 0, 'ICMP': 0},
    'protocol_activity': {'TCP': 0.0, 'UDP': 0.0, 'ICMP': 0.0},
    'last_sample': time.monotonic(),
    'energy': 0.0,
}
visual_stats_lock = threading.Lock()


class ConsoleWhenNoTui(logging.Filter):
    """Prevent ordinary console logs from corrupting the full-screen TUI."""

    def filter(self, record):
        return not tui_active


class TuiLogHandler(logging.Handler):
    """Keep recent log messages available to the TUI renderer."""

    def emit(self, record):
        message = ANSI_ESCAPE_PATTERN.sub('', self.format(record))
        with tui_message_lock:
            tui_messages.append(message.replace('\n', ' | '))


# Setup logging
logger = logging.getLogger("pcapsing")
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(message)s")
console_handler.setFormatter(console_formatter)
console_handler.addFilter(ConsoleWhenNoTui())
logger.addHandler(console_handler)

tui_log_handler = TuiLogHandler()
tui_log_handler.setLevel(logging.INFO)
tui_log_handler.setFormatter(console_formatter)
logger.addHandler(tui_log_handler)

# File handler. Fall back to per-user state if a sudo-created local log is
# not writable during a later unprivileged run.
try:
    file_handler = logging.FileHandler("flows.log")
except PermissionError:
    fallback_log_dir = Path.home() / '.local' / 'state' / 'pcapsing'
    fallback_log_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(fallback_log_dir / 'flows.log')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter("%(message)s")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Define note frequencies for C major scale
NOTE_FREQUENCIES = {
    'C': 261.63,  # C4
    'D': 293.66,
    'E': 329.63,
    'F': 349.23,
    'G': 392.00,
    'A': 440.00,
    'B': 493.88
}

# Protocol sound configurations
PROTOCOL_SOUND_CONFIG = {
    'TCP': {
        'base_octave': 3,  # C3 to B3
        'states': {
            'INIT': 'C',
            'SYN_SENT': 'D',
            'SYN_RECEIVED': 'E',
            'ESTABLISHED': 'F',
            'FIN_WAIT': 'G',
            'RESET': 'A'
        },
        'color': 'blue'
    },
    'UDP': {
        'base_octave': 4,  # C4 to B4
        'states': {
            'INIT': 'C',
            'ESTABLISHED': 'D'
        },
        'color': 'green'
    },
    'ICMP': {
        'base_octave': 5,  # C5 to B5
        'states': {
            'INIT': 'C',
            'ESTABLISHED': 'D'
        },
        'color': 'magenta'
    }
}

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
        self.state = 'INIT'

    def update(self, packet):
        self.last_seen = time.time()
        pkt_len = len(packet)
        
        # Safely access the protocol layer
        if self.protocol == 'TCP' and TCP in packet:
            pkt_layer = packet[TCP]
        elif self.protocol == 'UDP' and UDP in packet:
            pkt_layer = packet[UDP]
        elif self.protocol == 'ICMP' and ICMP in packet:
            pkt_layer = packet[ICMP]
        else:
            # If the expected layer isn't present, skip updating
            return
        
        # Update byte counts. ICMP has no ports, so IP direction is enough.
        source_matches = packet[IP].src == self.src_ip
        port_matches = (
            self.protocol == 'ICMP'
            or getattr(pkt_layer, 'sport', None) == self.src_port
        )
        if source_matches and port_matches:
            self.bytes_src_to_dst += pkt_len
        else:
            self.bytes_dst_to_src += pkt_len

        # Check terminal TCP flags before ACK/SYN so combined flags are not
        # mistaken for an established connection.
        if self.protocol == 'TCP':
            flags = pkt_layer.flags
            if flags & 0x04:  # RST
                self.state = 'RESET'
            elif flags & 0x01:  # FIN
                self.state = 'FIN_WAIT'
            elif flags & 0x12 == 0x12:  # SYN-ACK
                self.state = 'SYN_RECEIVED'
            elif flags & 0x02:  # SYN
                self.state = 'SYN_SENT'
            elif flags & 0x10:  # ACK
                self.state = 'ESTABLISHED'
        else:
            self.state = 'ESTABLISHED'

    def __str__(self):
        duration = int(self.last_seen - self.start_time)
        return (f"{self.protocol} Flow {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} | "
                f"Bytes: {self.bytes_src_to_dst}/{self.bytes_dst_to_src} | "
                f"Duration: {duration}s | State: {self.state}")

def ansi_color(text, color):
    """
    Wrap text with ANSI color codes.
    """
    color_code = ANSI_COLORS.get(color, ANSI_COLORS['reset'])
    reset_code = ANSI_COLORS['reset']
    return f"{color_code}{text}{reset_code}"

def record_scene_packet(protocol):
    """Record one packet for automatic audio/visual scene selection."""
    with scene_input_lock:
        scene_input[protocol] += 1


def get_scene_snapshot():
    """Return the shared auto scene and its current audio crossfade."""
    now = time.monotonic()
    with scene_state_lock:
        progress = min(
            1.0,
            (now - scene_state['transition_started']) / SCENE_CROSSFADE_SECONDS,
        )
        return {
            'current': scene_state['current'],
            'previous': scene_state['previous'],
            'transition': progress,
            'activity': scene_state['activity'].copy(),
        }


def scene_controller_thread(stop_event):
    """Smooth protocol activity and select one shared auto soundscape."""
    while not stop_event.wait(SCENE_UPDATE_INTERVAL):
        with scene_input_lock:
            packet_counts = scene_input.copy()
            for protocol in scene_input:
                scene_input[protocol] = 0

        packet_total = sum(packet_counts.values())
        now = time.monotonic()
        transition_message = None

        with scene_state_lock:
            for protocol, count in packet_counts.items():
                target = count / packet_total if packet_total else 0.0
                scene_state['activity'][protocol] = (
                    scene_state['activity'][protocol] * 0.82 + target * 0.18
                )

            activity = scene_state['activity']
            dominant_protocol = max(activity, key=activity.get)
            desired_scene = SCENE_BY_PROTOCOL[dominant_protocol]
            current_protocol = next(
                protocol
                for protocol, scene in SCENE_BY_PROTOCOL.items()
                if scene == scene_state['current']
            )
            dominance_margin = (
                activity[dominant_protocol] - activity[current_protocol]
            )

            if (
                desired_scene != scene_state['current']
                and dominance_margin >= SCENE_SWITCH_MARGIN
            ):
                if desired_scene != scene_state['candidate']:
                    scene_state['candidate'] = desired_scene
                    scene_state['candidate_since'] = now
                elif now - scene_state['candidate_since'] >= SCENE_HOLD_SECONDS:
                    previous = scene_state['current']
                    scene_state['previous'] = previous
                    scene_state['current'] = desired_scene
                    scene_state['transition_started'] = now
                    scene_state['candidate'] = desired_scene
                    transition_message = (
                        f"Auto soundscape: {previous} -> {desired_scene} "
                        f"({dominant_protocol} dominant)"
                    )
            else:
                scene_state['candidate'] = scene_state['current']
                scene_state['candidate_since'] = now

        if transition_message:
            logger.info(ansi_color(transition_message, 'cyan'))


def get_music_settings():
    """Return a consistent snapshot of the keyboard-controlled music state."""
    with music_state_lock:
        settings = music_state.copy()

    settings.update(MUSIC_PRESETS[settings['preset']])
    settings['duration'] = settings['pad_duration']
    root_name, transpose = ROOT_NOTES[settings['root_index']]
    settings['root_name'] = root_name
    settings['transpose'] = transpose
    override_remaining = max(
        0.0,
        settings['root_override_until'] - time.monotonic(),
    )
    if not settings['root_auto']:
        settings['root_mode'] = 'manual'
    elif override_remaining > 0:
        settings['root_mode'] = f"auto paused {int(override_remaining)}s"
    else:
        settings['root_mode'] = 'auto'
    settings['background'] = BACKGROUND_MODES[settings['background_index']]
    settings['variation'] = VARIATION_LEVELS[settings['variation_index']]
    settings['variation_config'] = VARIATION_CONFIG[settings['variation']]

    auto_scene = get_scene_snapshot()
    if settings['background'] == 'auto':
        settings['scene'] = auto_scene['current']
        settings['previous_scene'] = auto_scene['previous']
        settings['scene_transition'] = auto_scene['transition']
    else:
        settings['scene'] = settings['background']
        settings['previous_scene'] = settings['background']
        settings['scene_transition'] = 1.0
    settings['scene_activity'] = auto_scene['activity']
    return settings


def record_auto_root_packet(destination, forward, new_flow):
    """Accumulate traffic pressure for slow circle-of-fifths movement."""
    with auto_root_input_lock:
        auto_root_input['packets'] += 1
        auto_root_input['forward' if forward else 'reverse'] += 1
        auto_root_input['new_flows'] += int(new_flow)
        if len(auto_root_input['destinations']) < 256:
            auto_root_input['destinations'].add(destination)


def reset_auto_root_window():
    """Restart the root hold period after a manual or automatic change."""
    with auto_root_input_lock:
        auto_root_input.update(
            packets=0,
            forward=0,
            reverse=0,
            new_flows=0,
            destinations=set(),
            last_change=time.monotonic(),
        )


def maybe_advance_auto_root():
    """Advance one fifth at a motif boundary when traffic supports a change."""
    now = time.monotonic()
    with music_state_lock:
        automatic = music_state['root_auto']
        override_until = music_state['root_override_until']
        variation = VARIATION_LEVELS[music_state['variation_index']]
        paused = music_state['paused'] or music_state['muted']

    if not automatic or paused or now < override_until:
        return False

    with auto_root_input_lock:
        elapsed = now - auto_root_input['last_change']
        if (
            elapsed < ROOT_HOLD_SECONDS[variation]
            or auto_root_input['packets'] < 8
            or not auto_root_input['destinations']
        ):
            return False

        step = 1 if auto_root_input['forward'] >= auto_root_input['reverse'] else -1
        destination_count = len(auto_root_input['destinations'])
        new_flow_count = auto_root_input['new_flows']
        auto_root_input.update(
            packets=0,
            forward=0,
            reverse=0,
            new_flows=0,
            destinations=set(),
            last_change=now,
        )

    with music_state_lock:
        if (
            not music_state['root_auto']
            or now < music_state['root_override_until']
        ):
            return False
        previous_root = ROOT_NOTES[music_state['root_index']][0]
        music_state['root_index'] = (
            music_state['root_index'] + step
        ) % len(ROOT_NOTES)
        next_root = ROOT_NOTES[music_state['root_index']][0]

    direction = 'clockwise' if step > 0 else 'counterclockwise'
    logger.info(
        f"Auto root: {previous_root} -> {next_root} ({direction}; "
        f"destinations={destination_count}, new_flows={new_flow_count})"
    )
    return True


def record_musical_packet(
    protocol,
    packet_size,
    destination,
    destination_port,
    forward,
    new_flow,
):
    """Collect bounded traffic features for evolving motifs and chords."""
    with motif_stats_lock:
        motif_stats['bytes'] += packet_size
        motif_stats['packets'] += 1
        motif_stats['packet_size_total'] += packet_size
        motif_stats['forward' if forward else 'reverse'] += 1
        motif_stats['new_flows'] += int(new_flow)
        motif_stats['protocol_packets'][protocol] += 1
        if len(motif_stats['destinations']) < 256:
            motif_stats['destinations'].add(destination)
        if len(motif_stats['ports']) < 128:
            motif_stats['ports'].add(destination_port)


def take_motif_snapshot():
    """Take and reset the short-term feature window used by motifs."""
    with motif_stats_lock:
        snapshot = {
            key: (value.copy() if isinstance(value, (set, dict)) else value)
            for key, value in motif_stats.items()
        }
        motif_stats.update(
            bytes=0,
            packets=0,
            packet_size_total=0,
            forward=0,
            reverse=0,
            new_flows=0,
            destinations=set(),
            ports=set(),
            protocol_packets={'TCP': 0, 'UDP': 0, 'ICMP': 0},
        )
    return snapshot


def queue_network_event(protocol, state, event_kind, packet_size):
    """Queue a meaningful flow event without blocking packet capture."""
    try:
        network_event_queue.put_nowait(
            (protocol, state, event_kind, packet_size)
        )
    except queue.Full:
        pass


def get_phrase_snapshot():
    with phrase_state_lock:
        return phrase_state.copy()


def record_visual_packet(protocol, packet_size):
    """Record traffic that drives the terminal visualization."""
    with visual_stats_lock:
        visual_stats['pending_bytes'] += packet_size
        visual_stats['pending_packets'] += 1
        visual_stats['total_bytes'] += packet_size
        visual_stats['total_packets'] += 1
        visual_stats['protocol_packets'][protocol] += 1


def get_flow_snapshot(limit=48):
    """Return recent active flows for the neural visualization."""
    now = time.time()
    with flows_lock:
        recent_flows = sorted(
            flows.values(),
            key=lambda flow: flow.last_seen,
            reverse=True,
        )[:limit]
        return [
            {
                'src': f"{flow.src_ip}:{flow.src_port}",
                'dst': f"{flow.dst_ip}:{flow.dst_port}",
                'protocol': flow.protocol,
                'state': flow.state,
                'bytes': flow.bytes_src_to_dst + flow.bytes_dst_to_src,
                'age': max(0.0, now - flow.last_seen),
            }
            for flow in recent_flows
        ]


def get_visual_snapshot():
    """Return smoothed traffic energy and reset the short visualization window."""
    settings = get_music_settings()
    flow_snapshot = get_flow_snapshot()
    now = time.monotonic()

    with visual_stats_lock:
        elapsed = max(0.05, now - visual_stats['last_sample'])
        byte_rate = visual_stats['pending_bytes'] / elapsed
        packet_rate = visual_stats['pending_packets'] / elapsed
        protocol_packets = visual_stats['protocol_packets'].copy()
        packet_total = max(1, sum(protocol_packets.values()))
        for protocol, count in protocol_packets.items():
            target_activity = count / packet_total
            visual_stats['protocol_activity'][protocol] = (
                visual_stats['protocol_activity'][protocol] * 0.88
                + target_activity * 0.12
            )

        visual_stats['pending_bytes'] = 0
        visual_stats['pending_packets'] = 0
        visual_stats['protocol_packets'] = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
        visual_stats['last_sample'] = now

        target_energy = min(1.0, np.log1p(byte_rate) / 12.0)
        if settings['paused'] or settings['muted']:
            target_energy = 0.0
        visual_stats['energy'] = (
            visual_stats['energy'] * 0.82 + target_energy * 0.18
        )

        return {
            'energy': visual_stats['energy'],
            'byte_rate': byte_rate,
            'packet_rate': packet_rate,
            'total_bytes': visual_stats['total_bytes'],
            'total_packets': visual_stats['total_packets'],
            'protocol_packets': protocol_packets,
            'protocol_activity': visual_stats['protocol_activity'].copy(),
            'flows': flow_snapshot,
        }


def get_tui_messages():
    """Return recent, ANSI-free log messages for the terminal UI."""
    with tui_message_lock:
        return list(tui_messages)


def music_state_message():
    """Format the current music controls for terminal feedback."""
    settings = get_music_settings()
    status = 'paused' if settings['paused'] else 'playing'
    if settings['muted']:
        status = 'muted'
    return (
        f"Music: {status} | preset={settings['preset']} | "
        f"volume={settings['master_volume']:.1f} | "
        f"root={settings['root_name']} ({settings['root_mode']}) | "
        f"pad={settings['duration']:.0f}s | variation={settings['variation']} | "
        f"scene={settings['scene']} ({settings['background']}) | "
        f"fullscreen={'on' if settings['fullscreen'] else 'off'} | "
        f"view=({settings['view_x']:.2f},{settings['view_y']:.2f})"
    )


def log_keyboard_help():
    """Display the interactive keyboard controls."""
    logger.info(
        "Keyboard: Space pause | M mute | Up/Down volume | "
        "1 calm | 2 balanced | 3 active | n next root | Shift+N auto | "
        "[/] pad length | "
        "WASD pan network | V variation | B scene | F fullscreen | "
        "R reset | H help | Q quit"
    )


def handle_music_key(key, stop_event):
    """Apply one key command and return whether it was recognized."""
    normalized = key.lower()
    mixer_action = None
    reset_root_window = False
    log_state_change = normalized not in ('w', 'a', 's', 'd')

    with music_state_lock:
        if normalized == 'q':
            stop_event.set()
            logger.info(ansi_color('[Stopping packet sniffing.]', 'yellow'))
            return True
        if key == ' ':
            music_state['paused'] = not music_state['paused']
            mixer_action = 'pause' if music_state['paused'] else 'unpause'
        elif normalized == 'm':
            music_state['muted'] = not music_state['muted']
            if music_state['muted']:
                mixer_action = 'stop'
        elif key in ('\x1b[A', '+', '='):
            music_state['master_volume'] = min(
                2.0,
                music_state['master_volume'] + 0.1,
            )
        elif key in ('\x1b[B', '-', '_'):
            music_state['master_volume'] = max(
                0.0,
                music_state['master_volume'] - 0.1,
            )
        elif key in ('1', '2', '3'):
            preset = {'1': 'calm', '2': 'balanced', '3': 'active'}[key]
            music_state['preset'] = preset
            music_state['pad_duration'] = MUSIC_PRESETS[preset]['duration']
        elif key == 'N':
            music_state['root_auto'] = not music_state['root_auto']
            music_state['root_override_until'] = 0.0
            reset_root_window = True
        elif normalized == 'n':
            music_state['root_index'] = (
                music_state['root_index'] + 1
            ) % len(ROOT_NOTES)
            if music_state['root_auto']:
                music_state['root_override_until'] = (
                    time.monotonic() + ROOT_MANUAL_OVERRIDE_SECONDS
                )
            reset_root_window = True
        elif normalized == 'v':
            music_state['variation_index'] = (
                music_state['variation_index'] + 1
            ) % len(VARIATION_LEVELS)
        elif normalized == 'b':
            music_state['background_index'] = (
                music_state['background_index'] + 1
            ) % len(BACKGROUND_MODES)
        elif normalized == 'f':
            music_state['fullscreen'] = not music_state['fullscreen']
        elif normalized == 'w':
            music_state['view_y'] = max(
                -0.4,
                round(music_state['view_y'] - VIEW_PAN_STEP, 2),
            )
        elif normalized == 's':
            music_state['view_y'] = min(
                0.4,
                round(music_state['view_y'] + VIEW_PAN_STEP, 2),
            )
        elif normalized == 'a':
            music_state['view_x'] = max(
                -0.4,
                round(music_state['view_x'] - VIEW_PAN_STEP, 2),
            )
        elif normalized == 'd':
            music_state['view_x'] = min(
                0.4,
                round(music_state['view_x'] + VIEW_PAN_STEP, 2),
            )
        elif key == '[':
            music_state['pad_duration'] = max(
                2.0,
                music_state['pad_duration'] - 1.0,
            )
        elif key == ']':
            music_state['pad_duration'] = min(
                20.0,
                music_state['pad_duration'] + 1.0,
            )
        elif normalized == 'r':
            music_state.update(
                paused=False,
                muted=False,
                master_volume=DEFAULT_MASTER_VOLUME,
                preset='balanced',
                root_index=0,
                root_auto=True,
                root_override_until=0.0,
                pad_duration=AMBIENT_DURATION,
                view_x=0.0,
                view_y=0.0,
                variation_index=1,
            )
            mixer_action = 'unpause'
            reset_root_window = True
        elif normalized in ('h', '?'):
            log_keyboard_help()
            return True
        else:
            return False

    if reset_root_window:
        reset_auto_root_window()

    if mixer_action == 'pause':
        pygame.mixer.pause()
    elif mixer_action == 'unpause':
        pygame.mixer.unpause()
    elif mixer_action == 'stop':
        pygame.mixer.stop()

    if log_state_change:
        logger.info(ansi_color(music_state_message(), 'cyan'))
    return True


def read_terminal_key():
    """Read one key, including terminal arrow-key escape sequences."""
    key = sys.stdin.read(1)
    if key != '\x1b':
        return key

    sequence = key
    for _ in range(2):
        readable, _, _ = select.select([sys.stdin], [], [], 0.05)
        if not readable:
            break
        sequence += sys.stdin.read(1)
    return sequence


def keyboard_control_loop(stop_event, sniffer):
    """Handle keyboard commands until quit, Ctrl-C, or capture failure."""
    terminal_fd = sys.stdin.fileno()
    previous_settings = termios.tcgetattr(terminal_fd)
    tty.setcbreak(terminal_fd)
    log_keyboard_help()
    logger.info(ansi_color(music_state_message(), 'cyan'))

    try:
        while not stop_event.is_set():
            capture_error = getattr(sniffer, 'exception', None)
            if capture_error:
                raise capture_error

            readable, _, _ = select.select([sys.stdin], [], [], 0.2)
            if readable:
                handle_music_key(read_terminal_key(), stop_event)
    finally:
        termios.tcsetattr(terminal_fd, termios.TCSADRAIN, previous_settings)


def generate_tone(
    protocol,
    state,
    volume=0.5,
    ambient=False,
    ambient_duration=AMBIENT_DURATION,
    transpose=0,
    soundscape='synapses',
):
    """
    Generate a tone based on protocol and state.

    Ambient tones are long, softly modulated pads. The default mode retains
    the original short sine-wave tones.
    """
    config = PROTOCOL_SOUND_CONFIG.get(protocol)
    if not config:
        return None  # Unsupported protocol

    note = config['states'].get(state)
    if not note:
        return None  # Unsupported state

    scene_audio = SCENE_AUDIO_CONFIG.get(
        soundscape,
        SCENE_AUDIO_CONFIG['synapses'],
    )
    if ambient:
        transpose += scene_audio['protocol_transpose'][protocol]
        volume *= scene_audio['volume_factor']

    # Calculate frequency based on octave and note
    base_freq = NOTE_FREQUENCIES[note]
    octave = config['base_octave']
    frequency = base_freq * (2 ** (octave - 4))  # Adjust octave
    frequency *= 2 ** (transpose / 12)

    duration = ambient_duration if ambient else DURATION
    sample_count = int(SAMPLE_RATE * duration)
    t = np.linspace(0, duration, sample_count, False)

    if ambient:
        # Each shared visual scene has a matching register, harmonic spectrum,
        # modulation speed, envelope, and delay character.
        waveform = sum(
            weight * np.sin(2 * np.pi * frequency * ratio * t)
            for ratio, weight in scene_audio['partials']
        )
        waveform /= sum(weight for _, weight in scene_audio['partials'])

        lfo_depth = scene_audio['lfo_depth']
        lfo = (1.0 - lfo_depth) + lfo_depth * np.sin(
            2 * np.pi * scene_audio['lfo_rate'] * t
        )
        attack_time = min(scene_audio['attack'], duration * 0.35)
        release_time = min(scene_audio['release'], duration * 0.45)
        attack = np.clip(t / attack_time, 0, 1)
        release = np.clip((duration - t) / release_time, 0, 1)
        envelope = np.minimum(attack, release) ** 1.5
        waveform *= envelope * lfo

        # Scene-specific delay adds space without another audio dependency.
        delay = int(scene_audio['delay'] * SAMPLE_RATE)
        waveform[delay:] += 0.2 * waveform[:-delay]
        waveform = np.tanh(waveform) * volume
    else:
        waveform = np.sin(2 * np.pi * frequency * t) * volume

    samples = (waveform * 32767).astype(np.int16)
    sound = pygame.sndarray.make_sound(samples)
    return sound, frequency, volume

def motif_sound_thread(stop_event):
    """Generate constrained melodic phrases from short-term traffic features."""
    while True:
        settings = get_music_settings()
        variation = settings['variation_config']
        if stop_event.wait(variation['motif_interval']):
            break

        snapshot = take_motif_snapshot()
        if snapshot['packets'] == 0:
            continue

        # Root movement happens only at motif boundaries, after a long hold.
        maybe_advance_auto_root()
        settings = get_music_settings()
        if settings['paused'] or settings['muted']:
            continue

        protocol = max(
            snapshot['protocol_packets'],
            key=snapshot['protocol_packets'].get,
        )
        scene = settings['scene']
        scale = SCENE_SCALES[scene]
        average_size = snapshot['packet_size_total'] / snapshot['packets']
        diversity = len(snapshot['destinations'])
        port_count = len(snapshot['ports'])
        seed = int(average_size // 96) + diversity * 3 + snapshot['new_flows']
        start_index = seed % len(scale)
        direction = 1 if snapshot['forward'] >= snapshot['reverse'] else -1
        octave = 12 if average_size > 1100 else 0
        chord_degree = scale[(diversity + snapshot['new_flows']) % len(scale)]
        inversion = (port_count + snapshot['new_flows']) % 3

        with phrase_state_lock:
            phrase_state['chord_degree'] = chord_degree
            phrase_state['inversion'] = inversion

        motif_volume = min(
            0.22,
            (
                0.045
                + 0.025 * np.log10(1 + snapshot['bytes'] / 1000)
            )
            * settings['master_volume']
            * variation['volume_factor'],
        )

        for note_index in range(variation['motif_notes']):
            scale_index = (start_index + direction * note_index) % len(scale)
            melodic_offset = scale[scale_index] + octave
            sound_data = generate_tone(
                protocol,
                'ESTABLISHED',
                volume=motif_volume,
                ambient=True,
                ambient_duration=variation['motif_duration'],
                transpose=settings['transpose'] + melodic_offset,
                soundscape=scene,
            )
            if sound_data:
                try:
                    audio_queue.put_nowait(sound_data)
                except queue.Full:
                    break

            if (
                note_index + 1 < variation['motif_notes']
                and stop_event.wait(variation['note_spacing'])
            ):
                return

        logger.info(
            f"Traffic motif | variation={settings['variation']} | "
            f"scene={scene} | notes={variation['motif_notes']} | "
            f"destinations={diversity} | avg_packet={average_size:.0f}B"
        )


def accent_sound_thread(stop_event):
    """Turn sparse network lifecycle events into rate-limited accents."""
    last_played = 0.0
    accent_offsets = {
        'SYN': 7,
        'SYN_ACK': 12,
        'FIN': -5,
        'RST': 1,
        'ICMP': 12,
        'NEW': 0,
    }

    while not stop_event.is_set():
        try:
            protocol, state, event_kind, packet_size = network_event_queue.get(
                timeout=0.2
            )
        except queue.Empty:
            continue

        try:
            settings = get_music_settings()
            minimum_interval = settings['variation_config']['accent_interval']
            now = time.monotonic()
            if (
                settings['paused']
                or settings['muted']
                or now - last_played < minimum_interval
            ):
                continue

            scene_offset = SCENE_AUDIO_CONFIG[settings['scene']][
                'protocol_transpose'
            ][protocol]
            accent_volume = min(
                0.28,
                (0.09 + 0.025 * np.log10(1 + packet_size))
                * settings['master_volume']
                * settings['variation_config']['volume_factor'],
            )
            sound_data = generate_tone(
                protocol,
                state,
                volume=accent_volume,
                transpose=(
                    settings['transpose']
                    + scene_offset
                    + accent_offsets[event_kind]
                ),
            )
            if sound_data:
                try:
                    audio_queue.put_nowait(sound_data)
                except queue.Full:
                    continue
                last_played = now
                logger.info(
                    f"Network accent | {event_kind} | {protocol} | "
                    f"variation={settings['variation']}"
                )
        finally:
            network_event_queue.task_done()


def audio_playback_thread():
    """
    Thread function to play sounds from the audio queue.
    """
    while True:
        item = audio_queue.get()
        if item is None:
            break
        sound, frequency, volume = item
        try:
            sound.play()
        except Exception as e:
            # Log audio playback errors in red
            logger.error(f"{ansi_color('Audio playback error:', 'red')} {e}")
        audio_queue.task_done()

def flow_monitor_thread(ambient, stop_event):
    """
    Thread function to monitor and process flows.
    """
    while not stop_event.wait(0.1):
        current_time = time.time()
        completed_flows = []

        with flows_lock:
            for flow_id, flow in list(flows.items()):
                if current_time - flow.last_seen > FLOW_TIMEOUT:
                    completed_flows.append(flows.pop(flow_id))
                elif current_time - flow.start_time > MAX_FLOW_DURATION:
                    completed_flows.append(copy(flow))
                    flow.start_time = current_time
                    flow.bytes_src_to_dst = 0
                    flow.bytes_dst_to_src = 0

        # Audio generation can be expensive, so do it after releasing the lock.
        for flow in completed_flows:
            if ambient:
                log_flow(flow)
            else:
                generate_and_log_sound(flow)

def log_flow(flow):
    """Log a completed flow without generating a discrete sound."""
    timestamp = time.strftime("[%m/%d/%y %H:%M:%S]")
    color = PROTOCOL_SOUND_CONFIG.get(flow.protocol, {}).get('color', 'reset')
    logger.info(f"{timestamp} {ansi_color(str(flow), color)}")


def ambient_sound_thread(stop_event):
    """Turn rolling traffic snapshots into overlapping ambient pads."""
    while True:
        settings = get_music_settings()
        if stop_event.wait(settings['interval']):
            break

        with ambient_stats_lock:
            snapshot = {
                protocol: values.copy()
                for protocol, values in ambient_stats.items()
            }
            for values in ambient_stats.values():
                values['bytes'] = 0
                values['packets'] = 0

        settings = get_music_settings()
        if settings['paused'] or settings['muted']:
            continue

        phrase = get_phrase_snapshot()
        inversion_offsets = (
            {'TCP': 0, 'UDP': 0, 'ICMP': 0},
            {'TCP': 12, 'UDP': 0, 'ICMP': 0},
            {'TCP': 0, 'UDP': 12, 'ICMP': 0},
        )[phrase['inversion']]
        transition = settings['scene_transition']
        if (
            settings['previous_scene'] == settings['scene']
            or transition >= 0.999
        ):
            scene_layers = ((settings['scene'], 1.0),)
        else:
            # Equal-power crossfade avoids a volume dip midway through a scene
            # transition while the old and new harmonic palettes overlap.
            scene_layers = (
                (settings['previous_scene'], np.sqrt(1.0 - transition)),
                (settings['scene'], np.sqrt(transition)),
            )

        for protocol, values in snapshot.items():
            if values['packets'] == 0:
                continue

            # Logarithmic scaling keeps large bursts quiet and usable.
            base_volume = min(
                0.40,
                (
                    0.055
                    + 0.05 * np.log10(1 + values['bytes'] / 1000)
                )
                * settings['volume_factor']
                * settings['master_volume'],
            )
            played_layers = []

            for soundscape, scene_weight in scene_layers:
                if scene_weight < 0.04:
                    continue
                sound_data = generate_tone(
                    protocol,
                    'ESTABLISHED',
                    volume=base_volume * scene_weight,
                    ambient=True,
                    ambient_duration=settings['duration'],
                    transpose=(
                        settings['transpose']
                        + phrase['chord_degree']
                        + inversion_offsets[protocol]
                    ),
                    soundscape=soundscape,
                )
                if not sound_data:
                    continue

                sound, frequency, actual_volume = sound_data
                try:
                    audio_queue.put_nowait((sound, frequency, actual_volume))
                except queue.Full:
                    logger.warning(
                        ansi_color(
                            'Audio queue full. Dropping ambient pad.',
                            'yellow',
                        )
                    )
                    continue
                played_layers.append(
                    f"{soundscape}:{frequency:.1f}Hz/{actual_volume:.2f}"
                )

            timestamp = time.strftime("[%m/%d/%y %H:%M:%S]")
            color = PROTOCOL_SOUND_CONFIG[protocol]['color']
            message = (
                f"{timestamp} {ansi_color(protocol, color)} ambient layer | "
                f"Scene: {settings['scene']} | Preset: {settings['preset']} | "
                f"Root: {settings['root_name']} | Packets: {values['packets']} | "
                f"Bytes: {values['bytes']} | "
                f"Sound: {', '.join(played_layers) or 'dropped'}"
            )
            logger.info(message)


def generate_and_log_sound(flow):
    """
    Generate sound based on the flow and log the details.
    """
    # Calculate volume with a minimum threshold to avoid volume 0
    calculated_volume = min(1.0, (flow.bytes_src_to_dst + flow.bytes_dst_to_src) / 2000)
    volume = max(calculated_volume, 0.05)  # Set a minimum volume of 0.05
    settings = get_music_settings()
    if settings['paused'] or settings['muted']:
        log_flow(flow)
        return

    volume = min(
        1.0,
        volume * settings['volume_factor'] * settings['master_volume'],
    )
    sound_data = generate_tone(
        flow.protocol,
        flow.state,
        volume=volume,
        transpose=settings['transpose'],
    )
    if sound_data:
        sound, freq, vol = sound_data
        try:
            audio_queue.put_nowait((sound, freq, vol))
        except queue.Full:
            logger.warning(f"{ansi_color('Audio queue full. Dropping sound for flow:', 'yellow')} {flow}")
            return

        # Determine color based on protocol
        if flow.protocol == 'TCP':
            protocol_color = 'blue'
        elif flow.protocol == 'UDP':
            protocol_color = 'green'
        elif flow.protocol == 'ICMP':
            protocol_color = 'magenta'
        else:
            protocol_color = 'reset'

        # Get current timestamp
        timestamp = time.strftime("[%m/%d/%y %H:%M:%S]")

        # Format log message with ANSI colors
        flow_str = ansi_color(str(flow), protocol_color)
        freq_str = ansi_color(f"{freq:.1f}Hz", 'cyan')
        vol_str = ansi_color(f"{vol:.2f}", 'cyan')
        log_message = f"{timestamp} {flow_str} | Sound: {freq_str}, Vol:{vol_str}"
        logger.info(log_message)

def packet_handler(packet, ambient=False):
    """
    Handle incoming packets and update flows.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_num = packet[IP].proto

        if protocol_num == 6 and TCP in packet:
            proto = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol_num == 17 and UDP in packet:
            proto = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif protocol_num == 1 and ICMP in packet:
            proto = 'ICMP'
            src_port = 0
            dst_port = 0
        else:
            proto = 'OTHER'
            src_port = 0
            dst_port = 0

        if proto in ['TCP', 'UDP', 'ICMP']:
            record_scene_packet(proto)
            if tui_active:
                record_visual_packet(proto, len(packet))

            if ambient:
                with ambient_stats_lock:
                    ambient_stats[proto]['bytes'] += len(packet)
                    ambient_stats[proto]['packets'] += 1

            if proto == 'ICMP':
                # For ICMP, ports are not applicable
                flow_id = (src_ip, 0, dst_ip, 0, proto)
                reverse_flow_id = (dst_ip, 0, src_ip, 0, proto)
            else:
                flow_id = (src_ip, src_port, dst_ip, dst_port, proto)
                reverse_flow_id = (dst_ip, dst_port, src_ip, src_port, proto)

            with flows_lock:
                new_flow = False
                if flow_id in flows:
                    flow = flows[flow_id]
                    forward = True
                elif reverse_flow_id in flows:
                    flow = flows[reverse_flow_id]
                    forward = False
                else:
                    flow = Flow(src_ip, src_port, dst_ip, dst_port, proto)
                    flows[flow_id] = flow
                    new_flow = True
                    forward = True
                flow.update(packet)

            if ambient:
                record_auto_root_packet(dst_ip, forward, new_flow)
                record_musical_packet(
                    proto,
                    len(packet),
                    dst_ip,
                    dst_port,
                    forward,
                    new_flow,
                )

                event_kind = None
                event_state = flow.state
                if proto == 'TCP':
                    flags = packet[TCP].flags
                    if flags & 0x04:
                        event_kind, event_state = 'RST', 'RESET'
                    elif flags & 0x01:
                        event_kind, event_state = 'FIN', 'FIN_WAIT'
                    elif flags & 0x12 == 0x12:
                        event_kind, event_state = 'SYN_ACK', 'SYN_RECEIVED'
                    elif flags & 0x02:
                        event_kind, event_state = 'SYN', 'SYN_SENT'
                    elif new_flow:
                        event_kind = 'NEW'
                elif proto == 'ICMP':
                    event_kind, event_state = 'ICMP', 'ESTABLISHED'
                elif new_flow:
                    event_kind, event_state = 'NEW', 'ESTABLISHED'

                if event_kind:
                    queue_network_event(
                        proto,
                        event_state,
                        event_kind,
                        len(packet),
                    )

def main():
    global tui_active

    parser = argparse.ArgumentParser(description="Network Flow Audio Sniffer with Enhanced Logging and Sound Features")
    parser.add_argument('--tcp', action='store_true', help='Include only TCP flows')
    parser.add_argument('--udp', action='store_true', help='Include only UDP flows')
    parser.add_argument('--icmp', action='store_true', help='Include only ICMP flows')
    parser.add_argument('--include-multicast', action='store_true', help='Include multicast and broadcast flows')
    parser.add_argument('--interface', '-i', type=str, help='Network interface to sniff on')
    parser.add_argument(
        '--ambient',
        action='store_true',
        help='Play a quiet, continuously evolving ambient soundscape',
    )
    parser.add_argument(
        '--volume',
        type=float,
        default=DEFAULT_MASTER_VOLUME,
        help='Set initial master volume from 0.0 to 2.0 (default: 1.3)',
    )
    parser.add_argument(
        '--variation',
        choices=VARIATION_LEVELS,
        default='medium',
        help='Set melodic and event variation (default: medium)',
    )
    parser.add_argument(
        '--root',
        choices=ROOT_CHOICES,
        default='auto',
        help='Set a fixed root note or enable slow automatic changes',
    )
    parser.add_argument(
        '--tui',
        action='store_true',
        help='Show an animated living-network visualization',
    )
    parser.add_argument(
        '--fullscreen',
        action='store_true',
        help='Start the TUI in visual-only full-screen mode',
    )
    parser.add_argument(
        '--background',
        choices=BACKGROUND_MODES,
        default='auto',
        help='Select the synchronized visual/music scene (default: auto)',
    )
    args = parser.parse_args()
    if not 0.0 <= args.volume <= 2.0:
        parser.error('--volume must be between 0.0 and 2.0')

    with music_state_lock:
        music_state['master_volume'] = args.volume
        music_state['variation_index'] = VARIATION_LEVELS.index(args.variation)
        music_state['root_auto'] = args.root == 'auto'
        music_state['root_override_until'] = 0.0
        if args.root != 'auto':
            music_state['root_index'] = next(
                index
                for index, (root_name, _) in enumerate(ROOT_NOTES)
                if root_name == args.root
            )
        music_state['fullscreen'] = args.fullscreen
        music_state['background_index'] = BACKGROUND_MODES.index(args.background)
    reset_auto_root_window()

    tui_requested = args.tui or args.fullscreen or args.background != 'auto'
    tui_active = tui_requested and sys.stdin.isatty()
    if tui_requested and not tui_active:
        logger.warning('TUI disabled because standard input is not a terminal.')

    protocol_filters = []
    if args.tcp:
        protocol_filters.append('tcp')
    if args.udp:
        protocol_filters.append('udp')
    if args.icmp:
        protocol_filters.append('icmp')

    filters = []
    if protocol_filters:
        filters.append(f"({' or '.join(protocol_filters)})")
    if not args.include_multicast:
        filters.append('not multicast and not broadcast')
    filter_str = ' and '.join(filters) if filters else None

    # Display startup information with colors
    timestamp = time.strftime("[%m/%d/%y %H:%M:%S]")
    filter_display = ansi_color(filter_str if filter_str else 'None', 'cyan')
    interface_display = ansi_color(args.interface, 'magenta') if args.interface else 'None'
    mode_display = ansi_color('ambient' if args.ambient else 'standard', 'cyan')
    startup_message = (
        f"{timestamp} Starting Network Flow Audio Sniffer...\n"
        f"{timestamp} Sound mode: {mode_display}\n"
        f"{timestamp} Variation: {args.variation}\n"
        f"{timestamp} Root: {args.root}\n"
        f"{timestamp} Visualization: {'neural network TUI' if tui_active else 'none'}\n"
        f"{timestamp} Filter applied: {filter_display}"
    )
    if args.interface:
        startup_message += f"\n{timestamp} Sniffing on interface: {interface_display}"
    logger.info(startup_message)

    # Start threads
    stop_event = threading.Event()
    playback_thread = threading.Thread(target=audio_playback_thread, daemon=True)
    playback_thread.start()

    monitor_thread = threading.Thread(
        target=flow_monitor_thread,
        args=(args.ambient, stop_event),
        daemon=True,
    )
    monitor_thread.start()

    scene_thread = threading.Thread(
        target=scene_controller_thread,
        args=(stop_event,),
        daemon=True,
    )
    scene_thread.start()

    ambient_thread = None
    motif_thread = None
    accent_thread = None
    if args.ambient:
        ambient_thread = threading.Thread(
            target=ambient_sound_thread,
            args=(stop_event,),
            daemon=True,
        )
        motif_thread = threading.Thread(
            target=motif_sound_thread,
            args=(stop_event,),
            daemon=True,
        )
        accent_thread = threading.Thread(
            target=accent_sound_thread,
            args=(stop_event,),
            daemon=True,
        )
        ambient_thread.start()
        motif_thread.start()
        accent_thread.start()

    packet_callback = partial(packet_handler, ambient=args.ambient)
    sniffer = AsyncSniffer(
        filter=filter_str,
        prn=packet_callback,
        iface=args.interface,
    )
    capture_failed = False

    try:
        sniffer.start()
        if tui_active:
            from pcapsing_tui import run_tui

            try:
                run_tui(
                    stop_event,
                    sniffer,
                    handle_music_key,
                    get_music_settings,
                    get_visual_snapshot,
                    get_tui_messages,
                )
            finally:
                tui_active = False
        elif sys.stdin.isatty():
            keyboard_control_loop(stop_event, sniffer)
        else:
            logger.info(
                'Keyboard controls disabled because standard input is not a terminal.'
            )
            while not stop_event.wait(0.2):
                capture_error = getattr(sniffer, 'exception', None)
                if capture_error:
                    raise capture_error
    except KeyboardInterrupt:
        logger.info(ansi_color('[Stopping packet sniffing.]', 'yellow'))
    except PermissionError:
        capture_failed = True
        logger.error(
            ansi_color(
                'Packet capture permission denied. Run with sudo as shown in README.md.',
                'red',
            )
        )
    except Exception as error:
        capture_failed = True
        logger.error(ansi_color(f'Packet capture failed: {error}', 'red'))
    finally:
        tui_active = False
        stop_event.set()
        if sniffer.running:
            try:
                sniffer.stop()
            except Exception as error:
                if not capture_failed:
                    capture_failed = True
                    logger.error(ansi_color(f'Could not stop capture: {error}', 'red'))
        monitor_thread.join()
        scene_thread.join()
        if ambient_thread:
            ambient_thread.join()
        if motif_thread:
            motif_thread.join()
        if accent_thread:
            accent_thread.join()
        audio_queue.put(None)
        playback_thread.join()
        pygame.mixer.quit()

    if capture_failed:
        raise SystemExit(1)

if __name__ == "__main__":
    main()

