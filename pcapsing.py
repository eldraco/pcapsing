import argparse
import threading
import queue
import time
import numpy as np
import pygame
from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging
from rich.logging import RichHandler
from rich.console import Console

# Audio settings
SAMPLE_RATE = 44100  # Samples per second
DURATION = 0.5       # Duration of each tone in seconds
MAX_FLOW_DURATION = 300  # 5 minutes in seconds

# Initialize pygame mixer with mono sound
pygame.mixer.init(frequency=SAMPLE_RATE, channels=1)

# Create a queue for audio playback
audio_queue = queue.Queue(maxsize=100)

# Flow tracking
flows = {}
FLOW_TIMEOUT = 60  # Seconds

# Setup rich console
console = Console()

# Setup logging with RichHandler for console and FileHandler for file
logger = logging.getLogger("pcapsing")
logger.setLevel(logging.INFO)

# Console handler with Rich
console_handler = RichHandler(rich_tracebacks=True)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# File handler without 'INFO'
file_handler = logging.FileHandler("flows.log")
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter("%(asctime)s - %(message)s")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Define note frequencies for C major scale in different octaves
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
        }
    },
    'UDP': {
        'base_octave': 4,  # C4 to B4
        'states': {
            'INIT': 'C',
            'ESTABLISHED': 'D'
        }
    },
    'ICMP': {
        'base_octave': 5,  # C5 to B5
        'states': {
            'INIT': 'C',
            'ESTABLISHED': 'D'
        }
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
        
        # Update byte counts
        if packet[IP].src == self.src_ip and getattr(pkt_layer, 'sport', None) == self.src_port:
            self.bytes_src_to_dst += pkt_len
        else:
            self.bytes_dst_to_src += pkt_len

        # Update state for TCP
        if self.protocol == 'TCP':
            flags = pkt_layer.flags
            if flags & 0x02:  # SYN
                self.state = 'SYN_SENT'
            elif flags & 0x12:  # SYN-ACK
                self.state = 'SYN_RECEIVED'
            elif flags & 0x10:  # ACK
                self.state = 'ESTABLISHED'
            elif flags & 0x01:  # FIN
                self.state = 'FIN_WAIT'
            elif flags & 0x04:  # RST
                self.state = 'RESET'

    def __str__(self):
        duration = int(self.last_seen - self.start_time)
        return (f"{self.protocol} Flow {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} | "
                f"Bytes: {self.bytes_src_to_dst}/{self.bytes_dst_to_src} | "
                f"Duration: {duration}s | State: {self.state}")

def generate_tone(protocol, state, volume=0.5):
    """
    Generate a sine wave tone based on protocol and state.
    """
    config = PROTOCOL_SOUND_CONFIG.get(protocol)
    if not config:
        return None  # Unsupported protocol

    note = config['states'].get(state)
    if not note:
        return None  # Unsupported state

    # Calculate frequency based on octave and note
    base_freq = NOTE_FREQUENCIES[note]
    octave = config['base_octave']
    frequency = base_freq * (2 ** (octave - 4))  # Adjust octave

    # Generate waveform
    sample_count = int(SAMPLE_RATE * DURATION)
    t = np.linspace(0, DURATION, sample_count, False)
    waveform = np.sin(2 * np.pi * frequency * t)
    waveform = (waveform * volume * 32767).astype(np.int16)
    sound = pygame.sndarray.make_sound(waveform)
    return sound, frequency, volume

def audio_playback_thread():
    while True:
        item = audio_queue.get()
        if item is None:
            break
        sound, frequency, volume = item
        try:
            sound.play()
            logger.info(f"{frequency:.1f}Hz, Vol:{volume:.2f}")
        except Exception as e:
            logger.error(f"[red]Audio playback error:[/red] {e}")
        audio_queue.task_done()

def flow_monitor_thread():
    while True:
        time.sleep(1)
        current_time = time.time()
        expired_flows = []
        long_flows = []

        for flow_id, flow in list(flows.items()):
            # Check for flow timeout
            if current_time - flow.last_seen > FLOW_TIMEOUT:
                expired_flows.append(flow_id)
            
            # Check for max flow duration
            elif current_time - flow.start_time > MAX_FLOW_DURATION:
                long_flows.append(flow_id)
        
        # Process expired flows
        for flow_id in expired_flows:
            flow = flows[flow_id]
            generate_and_log_sound(flow)
            del flows[flow_id]
        
        # Process long flows by splitting them
        for flow_id in long_flows:
            flow = flows[flow_id]
            generate_and_log_sound(flow)
            # Reset flow metrics
            flow.start_time = current_time
            flow.bytes_src_to_dst = 0
            flow.bytes_dst_to_src = 0

def generate_and_log_sound(flow):
    frequency, volume = 440.0, 0.5  # Default values
    sound_data = generate_tone(flow.protocol, flow.state, volume=min(1.0, (flow.bytes_src_to_dst + flow.bytes_dst_to_src) / 2000))
    if sound_data:
        sound, freq, vol = sound_data
        try:
            audio_queue.put_nowait((sound, freq, vol))
        except queue.Full:
            logger.warning(f"Audio queue full. Dropping sound for flow: {flow}")
            return

        # Log the flow details and sound attributes in a concise format
        log_message = f"{flow} | Sound: {freq:.1f}Hz, Vol:{vol:.2f}"
        logger.info(log_message)

def packet_handler(packet):
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
            if proto == 'ICMP':
                # For ICMP, ports are not applicable
                flow_id = (src_ip, 0, dst_ip, 0, proto)
                reverse_flow_id = (dst_ip, 0, src_ip, 0, proto)
            else:
                flow_id = (src_ip, src_port, dst_ip, dst_port, proto)
                reverse_flow_id = (dst_ip, dst_port, src_ip, src_port, proto)

            if flow_id in flows:
                flows[flow_id].update(packet)
            elif reverse_flow_id in flows:
                flows[reverse_flow_id].update(packet)
            else:
                flows[flow_id] = Flow(src_ip, src_port, dst_ip, dst_port, proto)

def main():
    parser = argparse.ArgumentParser(description="Network Flow Audio Sniffer with Enhanced Logging and Sound Features")
    parser.add_argument('--tcp', action='store_true', help='Include only TCP flows')
    parser.add_argument('--udp', action='store_true', help='Include only UDP flows')
    parser.add_argument('--icmp', action='store_true', help='Include only ICMP flows')
    parser.add_argument('--include-multicast', action='store_true', help='Include multicast and broadcast flows')
    parser.add_argument('--interface', '-i', type=str, help='Network interface to sniff on')
    args = parser.parse_args()

    filters = []
    if args.tcp:
        filters.append('tcp')
    if args.udp:
        filters.append('udp')
    if args.icmp:
        filters.append('icmp')
    if not args.include_multicast:
        filters.append('not multicast and not broadcast')
    filter_str = ' and '.join(filters) if filters else None

    console.print("Starting Network Flow Audio Sniffer...")
    console.print(f"Filter applied: [bold cyan]{filter_str if filter_str else 'None'}[/bold cyan]")
    if args.interface:
        console.print(f"Sniffing on interface: [bold magenta]{args.interface}[/bold magenta]")

    # Start threads
    playback_thread = threading.Thread(target=audio_playback_thread, daemon=True)
    playback_thread.start()

    monitor_thread = threading.Thread(target=flow_monitor_thread, daemon=True)
    monitor_thread.start()

    try:
        sniff(filter=filter_str, prn=packet_handler, iface=args.interface)
    except KeyboardInterrupt:
        console.print("\nStopping packet sniffing.")
    finally:
        audio_queue.put(None)
        playback_thread.join()
        pygame.mixer.quit()

if __name__ == "__main__":
    # Ensure rich is available
    try:
        from rich.console import Console
    except ImportError:
        print("Please install the 'rich' library to enable enhanced logging:")
        print("pip install rich")
        exit(1)
    
    main()

