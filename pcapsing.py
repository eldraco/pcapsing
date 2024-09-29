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

# Dictionary to track flows
flows = {}
FLOW_TIMEOUT = 60  # Seconds

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

        for flow_id, flow_info in flows.items():
            if current_time - flow_info['last_seen'] > FLOW_TIMEOUT:
                # Generate sound for the flow
                frequency = 440.0
                volume = 0.5

                # Adjust frequency and volume based on flow attributes
                frequency += (flow_info['packet_count'] % 100)
                volume += (flow_info['packet_count'] % 10) / 100
                volume = max(0.0, min(volume, 1.0))

                sound = generate_tone(frequency, DURATION, volume)
                try:
                    audio_queue.put_nowait(sound)
                except queue.Full:
                    pass

                expired_flows.append(flow_id)

        # Remove expired flows
        for flow_id in expired_flows:
            del flows[flow_id]

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet.proto
        flow_id = (src_ip, dst_ip, proto)

        current_time = time.time()
        if flow_id in flows:
            flows[flow_id]['packet_count'] += 1
            flows[flow_id]['last_seen'] = current_time
        else:
            flows[flow_id] = {
                'packet_count': 1,
                'last_seen': current_time
            }

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

    # Start the audio playback thread
    playback_thread = threading.Thread(target=audio_playback_thread, daemon=True)
    playback_thread.start()

    # Start the flow monitor thread
    flow_thread = threading.Thread(target=flow_monitor_thread, daemon=True)
    flow_thread.start()

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

