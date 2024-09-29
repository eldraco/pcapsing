import argparse
import threading
import queue
import time
import numpy as np
import pygame
from scapy.all import sniff, IP, TCP, UDP
import logging

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

# Setup logging
logging.basicConfig(
    filename='flows.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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
        else:
            # If the expected layer isn't present, skip updating
            return
        
        if packet[IP].src == self.src_ip and pkt_layer.sport == self.src_port:
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
        duration = self.last_seen - self.start_time
        return (f"Flow(src_ip={self.src_ip}, src_port={self.src_port}, "
                f"dst_ip={self.dst_ip}, dst_port={self.dst_port}, "
                f"protocol={self.protocol}, bytes_src_to_dst={self.bytes_src_to_dst}, "
                f"bytes_dst_to_src={self.bytes_dst_to_src}, duration={duration:.2f}s, "
                f"state={self.state})")

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
        except Exception as e:
            logging.error(f"Audio playback error: {e}")
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
                volume = min(1.0, (flow.bytes_src_to_dst + flow.bytes_dst_to_src) / 2000)
                state = flow.state

                sound = generate_tone(frequency, DURATION, volume)
                try:
                    audio_queue.put_nowait(sound)
                except queue.Full:
                    logging.warning(f"Audio queue full. Dropping sound for flow: {flow_id}")
                    pass

                # Log the flow details and sound attributes
                logging.info(f"Processed {flow} | Sound -> Frequency: {frequency:.2f} Hz, Volume: {volume:.2f}, Duration: {DURATION}s")

                expired_flows.append(flow_id)

        for flow_id in expired_flows:
            del flows[flow_id]

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
        else:
            proto = 'OTHER'
            src_port = 0
            dst_port = 0

        if proto in ['TCP', 'UDP']:
            flow_id = (src_ip, src_port, dst_ip, dst_port, proto)
            reverse_flow_id = (dst_ip, dst_port, src_ip, src_port, proto)

            if flow_id in flows:
                flows[flow_id].update(packet)
            elif reverse_flow_id in flows:
                flows[reverse_flow_id].update(packet)
            else:
                flows[flow_id] = Flow(src_ip, src_port, dst_ip, dst_port, proto)

def main():
    parser = argparse.ArgumentParser(description="Network Flow Audio Sniffer with Logging")
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

    print("Starting Network Flow Audio Sniffer...")
    print(f"Filter applied: {filter_str if filter_str else 'None'}")
    if args.interface:
        print(f"Sniffing on interface: {args.interface}")

    # Start threads
    playback_thread = threading.Thread(target=audio_playback_thread, daemon=True)
    playback_thread.start()

    monitor_thread = threading.Thread(target=flow_monitor_thread, daemon=True)
    monitor_thread.start()

    try:
        sniff(filter=filter_str, prn=packet_handler, iface=args.interface)
    except KeyboardInterrupt:
        print("\nStopping packet sniffing.")
    finally:
        audio_queue.put(None)
        playback_thread.join()
        pygame.mixer.quit()

if __name__ == "__main__":
    main()

