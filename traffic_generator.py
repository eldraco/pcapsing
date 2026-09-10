#!/usr/bin/env python3
"""Generate bounded loopback traffic for testing Pcapsing's music engine."""

import argparse
from dataclasses import dataclass, field
import shutil
import socket
import struct
import subprocess
import threading
import time

HOST = '127.0.0.1'
SOURCE_ALIASES = ('127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5')
TCP_PORTS = tuple(range(39000, 39004))
UDP_PORTS = tuple(range(39100, 39104))
PROFILES = ('journey', 'small', 'upload', 'download', 'connections', 'udp', 'icmp', 'mixed')


@dataclass
class TrafficTotals:
    sent_bytes: int = 0
    received_bytes: int = 0
    messages: int = 0
    connections: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_sent(self, size):
        with self.lock:
            self.sent_bytes += size
            self.messages += 1

    def record_received(self, size):
        with self.lock:
            self.received_bytes += size

    def record_connection(self):
        with self.lock:
            self.connections += 1

    def snapshot(self):
        with self.lock:
            return self.sent_bytes, self.received_bytes, self.messages, self.connections


class LocalTrafficLab:
    """Local TCP/UDP sinks and sources used by the traffic profiles."""

    def __init__(self):
        self.stop_event = threading.Event()
        self.sockets = []
        self.threads = []

    def start(self):
        for port in TCP_PORTS:
            thread = threading.Thread(
                target=self._tcp_server,
                args=(port,),
                daemon=True,
            )
            thread.start()
            self.threads.append(thread)

        for port in UDP_PORTS:
            thread = threading.Thread(
                target=self._udp_server,
                args=(port,),
                daemon=True,
            )
            thread.start()
            self.threads.append(thread)

        # Give listener threads time to bind before clients start.
        time.sleep(0.15)

    def close(self):
        self.stop_event.set()
        for listener in self.sockets:
            try:
                listener.close()
            except OSError:
                pass
        for thread in self.threads:
            thread.join(timeout=1)

    def _tcp_server(self, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, port))
        listener.listen()
        listener.settimeout(0.2)
        self.sockets.append(listener)

        while not self.stop_event.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._handle_tcp_connection,
                args=(connection,),
                daemon=True,
            )
            thread.start()
            self.threads.append(thread)

    def _handle_tcp_connection(self, connection):
        with connection:
            connection.settimeout(0.5)
            try:
                mode = connection.recv(1)
                if mode == b'D':
                    header = self._receive_exact(connection, 8)
                    if len(header) != 8:
                        return
                    chunk_size, delay_microseconds = struct.unpack('!II', header)
                    payload = b'd' * max(1, min(chunk_size, 65536))
                    delay = max(0.001, delay_microseconds / 1_000_000)
                    while not self.stop_event.is_set():
                        connection.sendall(payload)
                        time.sleep(delay)
                else:
                    while not self.stop_event.is_set():
                        data = connection.recv(65536)
                        if not data:
                            break
            except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
                return

    @staticmethod
    def _receive_exact(connection, size):
        data = bytearray()
        while len(data) < size:
            chunk = connection.recv(size - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def _udp_server(self, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind((HOST, port))
        listener.settimeout(0.2)
        self.sockets.append(listener)
        while not self.stop_event.is_set():
            try:
                listener.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                break


def _deadline_wait(deadline, stop_event, delay):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    stop_event.wait(min(delay, remaining))
    return time.monotonic() < deadline and not stop_event.is_set()


def _tcp_socket(port, alias):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.bind((alias, 0))
    connection.connect((HOST, port))
    return connection


def run_small(duration, rate, lab, totals):
    """Small, slow TCP messages: low register and sparse motifs."""
    deadline = time.monotonic() + duration
    connection = _tcp_socket(TCP_PORTS[0], SOURCE_ALIASES[0])
    totals.record_connection()
    with connection:
        connection.sendall(b'U')
        payload = b's' * 96
        delay = 1 / max(0.2, 2 * rate)
        while time.monotonic() < deadline and not lab.stop_event.is_set():
            connection.sendall(payload)
            totals.record_sent(len(payload))
            if not _deadline_wait(deadline, lab.stop_event, delay):
                break


def run_upload(duration, rate, lab, totals):
    """Sustained large outbound TCP packets: louder, higher motifs."""
    deadline = time.monotonic() + duration
    connection = _tcp_socket(TCP_PORTS[1], SOURCE_ALIASES[1])
    totals.record_connection()
    with connection:
        connection.sendall(b'U')
        payload = b'u' * 16384
        delay = 1 / max(1, 18 * rate)
        while time.monotonic() < deadline and not lab.stop_event.is_set():
            connection.sendall(payload)
            totals.record_sent(len(payload))
            if not _deadline_wait(deadline, lab.stop_event, delay):
                break


def run_download(duration, rate, lab, totals):
    """Sustained inbound TCP packets: descending motifs/root pressure."""
    deadline = time.monotonic() + duration
    connection = _tcp_socket(TCP_PORTS[2], SOURCE_ALIASES[2])
    totals.record_connection()
    chunk_size = 16384
    delay_microseconds = int(1_000_000 / max(1, 18 * rate))
    with connection:
        connection.sendall(b'D' + struct.pack('!II', chunk_size, delay_microseconds))
        connection.settimeout(0.5)
        while time.monotonic() < deadline and not lab.stop_event.is_set():
            try:
                data = connection.recv(65536)
            except socket.timeout:
                continue
            if not data:
                break
            totals.record_received(len(data))


def run_connections(duration, rate, lab, totals):
    """Many short TCP flows: SYN/FIN accents and chord inversions."""
    deadline = time.monotonic() + duration
    index = 0
    delay = 1 / max(0.5, 4 * rate)
    while time.monotonic() < deadline and not lab.stop_event.is_set():
        port = TCP_PORTS[index % len(TCP_PORTS)]
        alias = SOURCE_ALIASES[index % len(SOURCE_ALIASES)]
        try:
            with _tcp_socket(port, alias) as connection:
                payload = b'U' + bytes([index % 256]) * (128 + index % 8 * 64)
                connection.sendall(payload)
                totals.record_sent(len(payload))
                totals.record_connection()
        except OSError:
            if lab.stop_event.is_set():
                break
            raise
        index += 1
        if not _deadline_wait(deadline, lab.stop_event, delay):
            break


def run_udp(duration, rate, lab, totals):
    """Bursty multi-port UDP: clustered scene and irregular motifs."""
    deadline = time.monotonic() + duration
    sockets = []
    for alias in SOURCE_ALIASES:
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.bind((alias, 0))
        sockets.append(sender)

    sizes = (128, 512, 1400, 4096)
    burst_index = 0
    try:
        while time.monotonic() < deadline and not lab.stop_event.is_set():
            burst_size = max(4, int(18 * rate))
            for index in range(burst_size):
                sender = sockets[(burst_index + index) % len(sockets)]
                port = UDP_PORTS[(burst_index + index) % len(UDP_PORTS)]
                size = sizes[(burst_index + index) % len(sizes)]
                payload = bytes([(burst_index + index) % 256]) * size
                sender.sendto(payload, (HOST, port))
                totals.record_sent(size)
            burst_index += burst_size
            if not _deadline_wait(deadline, lab.stop_event, max(0.25, 1.5 / rate)):
                break
    finally:
        for sender in sockets:
            sender.close()


def run_icmp(duration, rate, lab, totals):
    """ICMP echo traffic: pulse scene and echo-like accents."""
    ping = shutil.which('ping')
    if not ping:
        print('  warning: ping command not found; skipping ICMP phase')
        lab.stop_event.wait(duration)
        return

    interval = max(0.2, 0.7 / rate)
    count = max(1, int(duration / interval))
    command = [
        ping,
        '-n',
        '-q',
        '-I',
        SOURCE_ALIASES[3],
        '-i',
        f'{interval:.2f}',
        '-s',
        '1200',
        '-c',
        str(count),
        HOST,
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        process.wait(timeout=duration + 2)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=2)
    except KeyboardInterrupt:
        process.terminate()
        process.wait(timeout=2)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
    totals.record_sent(count * 1200)


def run_mixed(duration, rate, lab, totals):
    """Concurrent TCP, UDP, and short-flow traffic."""
    workers = [
        threading.Thread(target=run_upload, args=(duration, rate * 0.5, lab, totals)),
        threading.Thread(target=run_udp, args=(duration, rate * 0.7, lab, totals)),
        threading.Thread(target=run_connections, args=(duration, rate * 0.4, lab, totals)),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()


PROFILE_RUNNERS = {
    'small': run_small,
    'upload': run_upload,
    'download': run_download,
    'connections': run_connections,
    'udp': run_udp,
    'icmp': run_icmp,
    'mixed': run_mixed,
}

PROFILE_DESCRIPTIONS = {
    'small': 'small, slow TCP messages',
    'upload': 'large sustained outbound TCP transfer',
    'download': 'large sustained inbound TCP transfer',
    'connections': 'many short TCP connections',
    'udp': 'bursty UDP across ports and loopback aliases',
    'icmp': 'ICMP echoes with larger payloads',
    'mixed': 'concurrent TCP, UDP, and connection bursts',
}


def run_profile(name, duration, rate, lab, totals):
    print(f'[{time.strftime("%H:%M:%S")}] {name}: {PROFILE_DESCRIPTIONS[name]} ({duration:.1f}s)')
    PROFILE_RUNNERS[name](duration, rate, lab, totals)


def run_journey(duration, rate, lab, totals):
    phases = ('small', 'connections', 'upload', 'download', 'udp', 'icmp')
    phase_duration = duration / len(phases)
    for phase in phases:
        if lab.stop_event.is_set():
            break
        run_profile(phase, phase_duration, rate, lab, totals)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            'Generate bounded traffic on 127.0.0.0/8 for testing Pcapsing. '
            'No packets are sent to external hosts.'
        )
    )
    parser.add_argument(
        '--profile',
        choices=PROFILES,
        default='journey',
        help='Traffic behavior to generate (default: journey)',
    )
    parser.add_argument(
        '--duration',
        type=float,
        default=120.0,
        help='Total duration in seconds (default: 120)',
    )
    parser.add_argument(
        '--rate',
        type=float,
        default=1.0,
        help='Rate multiplier from 0.1 to 5.0 (default: 1.0)',
    )
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error('--duration must be greater than zero')
    if not 0.1 <= args.rate <= 5.0:
        parser.error('--rate must be between 0.1 and 5.0')
    return args


def main():
    args = parse_args()
    lab = LocalTrafficLab()
    totals = TrafficTotals()

    print('Pcapsing loopback traffic generator')
    print('Capture it with: --interface lo')
    print('Press Ctrl-C to stop.\n')
    lab.start()
    started = time.monotonic()

    try:
        if args.profile == 'journey':
            run_journey(args.duration, args.rate, lab, totals)
        else:
            run_profile(args.profile, args.duration, args.rate, lab, totals)
    except KeyboardInterrupt:
        print('\nStopping traffic generation...')
    finally:
        lab.close()

    elapsed = max(0.001, time.monotonic() - started)
    sent, received, messages, connections = totals.snapshot()
    print(
        f'Complete: {elapsed:.1f}s | sent={sent / 1024:.1f}KiB | '
        f'received={received / 1024:.1f}KiB | messages={messages} | '
        f'connections={connections}'
    )


if __name__ == '__main__':
    main()
