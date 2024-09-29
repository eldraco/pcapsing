import argparse
import threading
import queue
import time
import numpy as np
import pygame
from scapy.all import sniff, IP, TCP, UDP

# Audio settings
SAMPLE_RATE = 44100  # Samples per second
DURATION = 0.5       # Duration of each tone in seconds

# Initialize pygame mixer with mono sound
pygame.mixer.init(frequency=SAMPLE_RATE, channels=1)

# Create a queue for audio playback
audio_queue = queue.Queue(maxsize=100)

# Flow tracking
flows = {}
FLOW_TIMEOUT = 60  # Seconds

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
        if packet[IP].src == self.src_ip and packet.sport == self.src_port:
            self.bytes_src_to_dst += pkt_len
        else:
            self.bytes_dst_to_src += pkt_len

        if self.protocol == 'TCP':
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags
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

def generate_tone(frequency, duration, volume=0.5):
    sample_count = int(SAMPLE_RATE * duration)
    t = np.linspace(0, duration, sample_count, False)
    waveform = np.sin(2 * np.pi * frequency * t)
    waveform = (waveform * volume * 32767).astype(np.int16)
    sound = pygame.sndarray.make_sound(waveform)
    return sound

def audio_playback_thread():
    while True:
        item = audio_queue.get()
        if item is None:
            break
        sound = item
        try:
            sound.play()
        except Exception:
            pass
        audio_queue.task_done()

def flow_monitor_thread():
    while True:
        time.sleep(1)
        current_time = time.time()
        expired_flows = []

        for flow_id, flow in list(flows.items()):
            if current_time - flow.last_seen > FLOW_TIMEOUT:
                duration = flow.last_seen - flow.start_time
                frequency = 440.0 + (flow.bytes_src_to_dst % 500)
                volume = min(1.0, flow.bytes_src_to_dst / 1000 + flow.bytes_dst_to_src / 1000)
                state = flow.state

                sound = generate_tone(frequency, DURATION, volume)
                try:
                    audio_queue.put_nowait(sound)
                except queue.Full:
                    pass

                expired_flows.append(flow_id)

        for flow_id in expired_flows:
            del flows[flow_id]

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6 and TCP in packet:
            proto = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 17 and UDP in packet:
            proto = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            proto = 'OTHER'
            src_port = 0
            dst_port = 0

        flow_id = (src_ip, src_port, dst_ip, dst_port, proto)

        if flow_id in flows:
            flows[flow_id].update(packet)
        else:
            if proto in ['TCP', 'UDP']:
                flows[flow_id] = Flow(src_ip, src_port, dst_ip, dst_port, proto)

def main():
    parser = argparse.ArgumentParser(description="Network Flow Audio Sniffer")
    parser.add_argument('--tcp', action='store_true', help='Include only TCP flows')
    parser.add_argument('--udp', action='store_true', help='Include only UDP flows')
    parser.add_argument('--include-multicast', action='store_true', help='Include multicast and broadcast flows')
    parser.add_argument('--interface', '-i', type=str, help='Network interface to sniff on')
    args = parser.parse_args()

    filters = []
    if args.tcp:
        filters.append('tcp')
    if args.udp:
        filters.append('udp')
    if not args.include_multicast:
        filters.append('not multicast and not broadcast')
    filter_str = ' and '.join(filters) if filters else None

    # Start threads
    playback_thread = threading.Thread(target=audio_playback_thread, daemon=True)
    playback_thread.start()

    monitor_thread = threading.Thread(target=flow_monitor_thread, daemon=True)
    monitor_thread.start()

    try:
        sniff(filter=filter_str, prn=packet_handler, iface=args.interface)
    except KeyboardInterrupt:
        pass
    finally:
        audio_queue.put(None)
        playback_thread.join()
        pygame.mixer.quit()

if __name__ == "__main__":
    main()

