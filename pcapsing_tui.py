"""Full-screen living-network visualization for Pcapsing."""

from collections import Counter, defaultdict
import math
import select
import shutil
import sys
import termios
import tty

RESET = "\033[0m"
CLEAR_SCREEN = "\033[2J"
CURSOR_HOME = "\033[H"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"

ROOT_COLORS = {
    'C': 45,
    'C#': 51,
    'D': 75,
    'D#': 105,
    'E': 141,
    'F': 48,
    'F#': 84,
    'G': 220,
    'G#': 214,
    'A': 208,
    'A#': 198,
    'B': 201,
}
PROTOCOL_COLORS = {'TCP': 75, 'UDP': 48, 'ICMP': 201}
SCENE_BY_PROTOCOL = {'TCP': 'synapses', 'UDP': 'clusters', 'ICMP': 'pulse'}
KEY_LINES = (
    "WASD pan network  Space pause  M mute  Up/Down volume",
    "1 calm  2 balanced  3 active  V variation",
    "n next root  Shift+N toggle auto  [/] pad  B scene  F fullscreen",
    "R reset  H help  Q quit",
)


def _color(code):
    return f"\033[38;5;{code}m"


def _stable_int(value):
    """Return a process-independent integer for stable endpoint placement."""
    result = 2_166_136_261
    for byte in str(value).encode('utf-8'):
        result = ((result ^ byte) * 16_777_619) & 0xFFFFFFFF
    return result


def _noise(*values):
    """Return stable pseudo-random noise in the range 0..1."""
    value = 0x345678
    for item in values:
        value = ((value ^ _stable_int(item)) * 1_000_003) & 0xFFFFFFFF
        value ^= value >> 13
    return (value & 0xFFFF) / 0xFFFF


def _read_key():
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


def _paint(cells, x, y, character, color, overwrite=True):
    if not (0 <= y < len(cells) and 0 <= x < len(cells[y])):
        return
    if overwrite or cells[y][x][0] == ' ':
        cells[y][x] = (character, color)


def _render_cells(row):
    chunks = []
    active_color = None
    for character, color in row:
        if color != active_color:
            chunks.append(RESET if color is None else _color(color))
            active_color = color
        chunks.append(character)
    chunks.append(RESET)
    return ''.join(chunks)


def _resolve_scene(settings, metrics):
    """Use the exact same scene selected for the ambient music."""
    if 'scene' in settings:
        return settings['scene']
    if settings.get('background', 'auto') != 'auto':
        return settings['background']

    activity = metrics.get('protocol_activity', {})
    if not activity or sum(activity.values()) < 0.01:
        return 'synapses'
    return SCENE_BY_PROTOCOL[max(activity, key=activity.get)]


def _synthetic_flows():
    """Keep a faint dormant network visible before packets arrive."""
    protocols = ('TCP', 'UDP', 'ICMP')
    flows = []
    for index in range(12):
        flows.append(
            {
                'src': 'local-core',
                'dst': f'dormant-{index}',
                'protocol': protocols[index % len(protocols)],
                'state': 'INIT',
                'bytes': 0,
                'age': 60.0,
            }
        )
    return flows


def _network_model(flows, width, height, scene, settings):
    """Build stable node positions and protocol identities from active flows."""
    if not flows:
        flows = _synthetic_flows()

    degree = Counter()
    protocol_score = defaultdict(Counter)
    for flow in flows:
        src = flow['src']
        dst = flow['dst']
        protocol = flow['protocol']
        degree[src] += 1
        degree[dst] += 1
        protocol_score[src][protocol] += 1
        protocol_score[dst][protocol] += 1

    node_limit = max(10, min(30, width * height // 55))
    ordered_nodes = [node for node, _ in degree.most_common(node_limit)]
    primary = ordered_nodes[0]

    pan_x = int(settings.get('view_x', 0.0) * width * 0.75)
    pan_y = int(settings.get('view_y', 0.0) * height * 0.75)
    center_x = width // 2 + pan_x
    center_y = height // 2 + pan_y
    positions = {primary: (center_x, center_y)}
    node_protocol = {
        node: protocol_score[node].most_common(1)[0][0]
        for node in ordered_nodes
    }

    cluster_offsets = {
        'TCP': (-0.25, -0.16),
        'UDP': (0.27, -0.10),
        'ICMP': (0.02, 0.25),
    }
    max_x_radius = max(4, int(width * 0.43))
    max_y_radius = max(3, int(height * 0.40))

    for index, node in enumerate(ordered_nodes[1:], start=1):
        seed = _stable_int(node)
        angle = _noise(seed, 11) * math.tau

        if scene == 'clusters':
            protocol = node_protocol[node]
            cluster_x, cluster_y = cluster_offsets[protocol]
            center_node_x = center_x + int(cluster_x * width)
            center_node_y = center_y + int(cluster_y * height)
            radius_x = max(3, int(width * (0.07 + 0.09 * _noise(seed, 13))))
            radius_y = max(2, int(height * (0.07 + 0.10 * _noise(seed, 17))))
            x = center_node_x + int(math.cos(angle) * radius_x)
            y = center_node_y + int(math.sin(angle) * radius_y)
        elif scene == 'pulse':
            ring = 0.35 + 0.55 * _noise(seed, 19)
            x = center_x + int(math.cos(angle) * max_x_radius * ring)
            y = center_y + int(math.sin(angle) * max_y_radius * ring)
        else:
            ring = 0.18 + 0.78 * _noise(seed, 23)
            x = center_x + int(math.cos(angle) * max_x_radius * ring)
            y = center_y + int(math.sin(angle) * max_y_radius * ring)

        positions[node] = (
            max(1, min(width - 2, x)),
            max(1, min(height - 2, y)),
        )

    return flows, positions, degree, node_protocol, primary


def _connection_character(delta_x, delta_y, protocol, step):
    if protocol == 'UDP' and step % 2:
        return '·'
    if abs(delta_x) > abs(delta_y) * 1.8:
        return '─'
    if abs(delta_y) > abs(delta_x) * 1.8:
        return '│'
    return '╲' if delta_x * delta_y > 0 else '╱'


def _draw_connection(cells, start, end, flow, frame, energy):
    """Draw one synapse and a directional packet impulse."""
    start_x, start_y = start
    end_x, end_y = end
    delta_x = end_x - start_x
    delta_y = end_y - start_y
    steps = max(abs(delta_x), abs(delta_y))
    if steps < 2:
        return

    protocol = flow['protocol']
    age = flow.get('age', 0.0)
    byte_energy = min(1.0, math.log1p(flow.get('bytes', 0)) / 14.0)
    resting_color = 244 if age < 8 else (240 if age < 30 else 237)
    if flow.get('state') == 'RESET':
        resting_color = 196

    pulse_speed = 0.010 + energy * 0.035 + byte_energy * 0.018
    pulse_offset = (_stable_int(flow['src'] + flow['dst']) % 100) / 100
    pulse_position = (frame * pulse_speed + pulse_offset) % 1.0

    for step in range(1, steps):
        fraction = step / steps
        x = round(start_x + delta_x * fraction)
        y = round(start_y + delta_y * fraction)
        is_pulse = abs(fraction - pulse_position) < max(0.04, 1.4 / steps)
        character = _connection_character(delta_x, delta_y, protocol, step)
        color = resting_color
        if is_pulse:
            character = '●' if byte_energy > 0.45 else '•'
            color = PROTOCOL_COLORS[protocol]
        _paint(cells, x, y, character, color, overwrite=is_pulse)


def _draw_pulse_field(cells, center, frame, energy, color):
    """Draw ICMP-like waves expanding through the neural field."""
    center_x, center_y = center
    max_radius = max(3, min(len(cells), len(cells[0]) // 2))
    pulse_speed = 0.08 + energy * 0.17
    for ring_index in range(3):
        radius = 1 + int((frame * pulse_speed + ring_index * 5) % max_radius)
        points = max(12, radius * 8)
        for point in range(points):
            angle = math.tau * point / points
            x = center_x + round(math.cos(angle) * radius * 2)
            y = center_y + round(math.sin(angle) * radius)
            if point % 2 == ring_index % 2:
                _paint(cells, x, y, '·', color, overwrite=False)


def _draw_cluster_halos(cells, positions, node_protocol, frame):
    """Give protocol groups the appearance of softly firing neural lobes."""
    grouped = defaultdict(list)
    for node, position in positions.items():
        grouped[node_protocol[node]].append(position)

    for protocol, points in grouped.items():
        if not points:
            continue
        center_x = round(sum(point[0] for point in points) / len(points))
        center_y = round(sum(point[1] for point in points) / len(points))
        radius_x = max(3, max(abs(point[0] - center_x) for point in points) + 2)
        radius_y = max(2, max(abs(point[1] - center_y) for point in points) + 1)
        for index in range(max(12, radius_x * 3)):
            angle = math.tau * index / max(12, radius_x * 3)
            x = center_x + round(math.cos(angle) * radius_x)
            y = center_y + round(math.sin(angle) * radius_y)
            if _noise(protocol, index, frame // 5) > 0.35:
                _paint(
                    cells,
                    x,
                    y,
                    '·',
                    PROTOCOL_COLORS[protocol],
                    overwrite=False,
                )


def _build_scene(width, height, frame, energy, settings, metrics, scene):
    cells = [[(' ', None) for _ in range(width)] for _ in range(height)]
    root_color = ROOT_COLORS.get(settings['root_name'], 45)
    flows, positions, degree, node_protocol, primary = _network_model(
        metrics.get('flows', []),
        width,
        height,
        scene,
        settings,
    )

    # Slow background impulses suggest dormant neurons without becoming a
    # generic starfield. Network energy increases their density and motion.
    dust_count = int(width * height * (0.003 + energy * 0.009))
    drift = int(frame * (0.01 + energy * 0.025))
    for index in range(dust_count):
        x = (int(_noise(index, 101) * width) + drift) % width
        y = (int(_noise(index, 103) * height) + drift // 2) % height
        color = root_color if _noise(index, 107) > 0.82 else 238
        _paint(cells, x, y, '·', color, overwrite=False)

    for flow in flows:
        if flow['src'] not in positions or flow['dst'] not in positions:
            continue
        _draw_connection(
            cells,
            positions[flow['src']],
            positions[flow['dst']],
            flow,
            frame,
            energy,
        )

    if scene == 'clusters':
        _draw_cluster_halos(cells, positions, node_protocol, frame)
    elif scene == 'pulse':
        activity = settings.get('scene_activity', {})
        dominant_protocol = max(activity, key=activity.get) if activity else 'ICMP'
        _draw_pulse_field(
            cells,
            positions[primary],
            frame,
            energy,
            PROTOCOL_COLORS[dominant_protocol],
        )

    # Nodes are drawn last so axons and pulses never obscure them.
    max_degree = max(degree.values())
    for node, (x, y) in positions.items():
        protocol = node_protocol[node]
        node_strength = degree[node] / max_degree
        if node == primary:
            character = '◉'
            color = root_color
        elif node_strength > 0.55:
            character = '◎'
            color = PROTOCOL_COLORS[protocol]
        elif node_strength > 0.25:
            character = '●'
            color = PROTOCOL_COLORS[protocol]
        else:
            character = '○'
            color = 245
        _paint(cells, x, y, character, color)

        if energy * node_strength > 0.42:
            halo_color = PROTOCOL_COLORS[protocol]
            for offset_x, offset_y in ((-1, 0), (1, 0), (0, -1), (0, 1)):
                _paint(
                    cells,
                    x + offset_x,
                    y + offset_y,
                    '·',
                    halo_color,
                    overwrite=False,
                )

    return [_render_cells(row) for row in cells], len(positions), len(flows)


def _fit(text, width):
    if len(text) > width:
        return text[:max(0, width - 1)] + '…'
    return text.ljust(width)


def _format_bytes(value):
    units = ('B', 'KiB', 'MiB', 'GiB')
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f}{unit}"
        amount /= 1024
    return f"{amount:.1f}GiB"


def _visual_energy(settings, metrics):
    return min(
        1.0,
        metrics['energy']
        * settings['volume_factor']
        * max(0.25, settings['master_volume']),
    )


def _compact_screen(width, settings, metrics, messages, scene):
    status = 'MUTED' if settings['muted'] else ('PAUSED' if settings['paused'] else 'PLAYING')
    activation = int(_visual_energy(settings, metrics) * 100)
    flow_count = len(metrics.get('flows', []))
    lines = [
        _fit('PCAPSING — LIVING NETWORK', width),
        _fit(
            f"{status} | {settings['preset']} | variation {settings['variation']} | "
            f"scene {scene} | root {settings['root_name']}/{settings['root_mode']}",
            width,
        ),
        _fit(
            f"Activation {activation}% | {flow_count} flows | "
            f"{metrics['packet_rate']:.1f} pkt/s | "
            f"{_format_bytes(metrics['byte_rate'])}/s",
            width,
        ),
        '',
    ]
    lines.extend(_fit(line, width) for line in KEY_LINES)
    if messages:
        lines.extend(('', _fit(messages[-1], width)))
    return lines


def _render_screen(settings, metrics, messages, frame):
    terminal = shutil.get_terminal_size((80, 24))
    width = max(20, min(terminal.columns, 120))
    height = terminal.lines
    scene_name = _resolve_scene(settings, metrics)
    energy = _visual_energy(settings, metrics)

    if settings['fullscreen']:
        scene, _, _ = _build_scene(
            width,
            height,
            frame,
            energy,
            settings,
            metrics,
            scene_name,
        )
        return CURSOR_HOME + '\n'.join(f"{line}\033[K" for line in scene)

    if width < 58 or height < 20:
        lines = _compact_screen(width, settings, metrics, messages, scene_name)
        return CURSOR_HOME + '\n'.join(f"{line}\033[K" for line in lines)

    reserved_rows = 8 + len(KEY_LINES)
    scene_height = max(8, min(22, height - reserved_rows))
    scene, node_count, flow_count = _build_scene(
        width,
        scene_height,
        frame,
        energy,
        settings,
        metrics,
        scene_name,
    )

    status = 'MUTED' if settings['muted'] else ('PAUSED' if settings['paused'] else 'PLAYING')
    bar_width = min(24, max(10, width // 4))
    filled = int(energy * bar_width)
    activation_bar = '█' * filled + '░' * (bar_width - filled)
    activation_percent = int(energy * 100)
    title = ' PCAPSING — LIVING NEURAL NETWORK '
    header = title.center(width, '═')

    lines = [header, *scene]
    lines.append(
        _fit(
            f" {status:<7}  preset {settings['preset']:<8}  "
            f"variation {settings['variation']:<6}  scene {scene_name:<9}  "
            f"root {settings['root_name']}/{settings['root_mode']}  "
            f"volume {settings['master_volume']:.1f}  pad {settings['duration']:.0f}s",
            width,
        )
    )
    lines.append(
        _fit(
            f" Activation {activation_percent:3d}% [{activation_bar}]  "
            f"{metrics['packet_rate']:7.1f} pkt/s  "
            f"{_format_bytes(metrics['byte_rate'])}/s  "
            f"total {_format_bytes(metrics['total_bytes'])}",
            width,
        )
    )
    protocol_text = '  '.join(
        f"{protocol} {metrics['protocol_packets'].get(protocol, 0)}"
        for protocol in ('TCP', 'UDP', 'ICMP')
    )
    lines.append(
        _fit(
            f" Neural graph: {node_count} nodes  {flow_count} flows  |  {protocol_text}",
            width,
        )
    )
    lines.append('─' * width)
    lines.extend(_fit(f" {line}", width) for line in KEY_LINES)

    available_messages = max(0, height - len(lines))
    if available_messages and messages:
        for message in messages[-available_messages:]:
            lines.append(_fit(f" › {message}", width))

    lines = lines[:height]
    return CURSOR_HOME + '\n'.join(f"{line}\033[K" for line in lines)


def run_tui(
    stop_event,
    sniffer,
    handle_key,
    get_music_settings,
    get_visual_snapshot,
    get_messages,
):
    """Run the animated TUI and keyboard loop until capture stops."""
    terminal_fd = sys.stdin.fileno()
    previous_settings = termios.tcgetattr(terminal_fd)
    tty.setcbreak(terminal_fd)
    frame = 0

    sys.stdout.write(CLEAR_SCREEN + CURSOR_HOME + HIDE_CURSOR)
    sys.stdout.flush()

    try:
        while not stop_event.is_set():
            capture_error = getattr(sniffer, 'exception', None)
            if capture_error:
                raise capture_error

            settings = get_music_settings()
            metrics = get_visual_snapshot()
            messages = get_messages()
            sys.stdout.write(_render_screen(settings, metrics, messages, frame))
            sys.stdout.flush()

            if not settings['paused'] and not settings['muted']:
                frame += 1

            readable, _, _ = select.select([sys.stdin], [], [], 0.12)
            if readable:
                handle_key(_read_key(), stop_event)
    finally:
        termios.tcsetattr(terminal_fd, termios.TCSADRAIN, previous_settings)
        sys.stdout.write(RESET + SHOW_CURSOR + '\n')
        sys.stdout.flush()
