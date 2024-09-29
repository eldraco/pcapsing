import argparse
from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import sounddevice as sd
import threading
import queue

# Audio settings
SAMPLE_RATE = 44100  # Samples per second
DURATION = 0.2       # Duration of each tone in seconds

# Create a queue for audio playback
audio_queue = queue.Queue()

def generate_tone(frequency, duration, volume=0.5):
    """
    Generate a sine wave tone at a given frequency and duration.
    """
    t = np.linspace(0, duration, int(SAMPLE_RATE * duration), False)
    tone = np.sin(frequency * t * 2 * np.pi)
    return (tone * volume).astype(np.float32)

def audio_playback_thread():
    """
    Thread function to continuously play sounds from the audio queue.
    """
    while True:
        frequency, duration, volume = audio_queue.get()
        if frequency is None:
            # Signal to exit the thread
            break
        try:
            tone = generate_tone(frequency, duration, volume)
            sd.play(tone, SAMPLE_RATE)
            sd.wait()
        except Exception as e:
            print(f"Audio playback error: {e}")
        audio_queue.task_done()

def packet_to_sound(packet):
    """
    Map packet attributes to sound properties and add them to the audio queue.
    """
    # Initialize default frequency and volume
    frequency = 440.0  # A4 note
    volume = 0.5

    # Adjust frequency based on protocol
    if TCP in packet:
        frequency += 100
    elif UDP in packet:
        frequency += 200
    else:
        frequency += 50

    # Adjust frequency based on packet length
    length = len(packet)
    frequency += (length % 100)  # Modulo to keep frequency in audible range

    # Adjust volume based on IP addresses
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        try:
            volume += (int(src_ip.split('.')[-1]) % 10) / 100
            volume += (int(dst_ip.split('.')[-1]) % 10) / 100
        except ValueError:
            pass  # In case of IPv6 addresses or unexpected format

    # Ensure volume stays within [0.0, 1.0]
    volume = max(0.0, min(volume, 1.0))

    # Add the sound parameters to the audio queue
    audio_queue.put((frequency, DURATION, volume))

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Audio Sniffer")
    parser.add_argument('--tcp', action='store_true', help='Include only TCP packets')
    parser.add_argument('--udp', action='store_true', help='Include only UDP packets')
    parser.add_argument('--include-multicast', action='store_true', help='Include multicast and broadcast packets')
    parser.add_argument('--interface', '-i', type=str, help='Network interface to sniff on')
    args = parser.parse_args()

    # Build the filter string for scapy
    filters = []
    if args.tcp:
        filters.append('tcp')
    if args.udp:
        filters.append('udp')
    if not args.include_multicast:
        filters.append('not multicast and not broadcast')
    filter_str = ' and '.join(filters) if filters else None

    print("Starting packet sniffing...")
    print(f"Filter applied: {filter_str if filter_str else 'None'}")
    if args.interface:
        print(f"Sniffing on interface: {args.interface}")

    # Start the audio playback thread
    playback_thread = threading.Thread(target=audio_playback_thread, daemon=True)
    playback_thread.start()

    try:
        sniff(filter=filter_str, prn=packet_to_sound, iface=args.interface)
    except KeyboardInterrupt:
        print("\nStopping packet sniffing.")
    finally:
        # Signal the audio playback thread to exit
        audio_queue.put((None, None, None))
        playback_thread.join()

if __name__ == "__main__":
    main()

