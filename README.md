# Pcapsing

A network sniffer that plays sounds according to the captured traffic to make it easier to monitor traffic in the background

# Installation

Create and activate an isolated Python environment, then install the dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Ubuntu, if creating the environment reports that `ensurepip` is unavailable, install the missing system package first:

```bash
sudo apt install python3.12-venv libpcap0.8
```

# Usage

Run with the original short flow tones:

```bash
python3 pcapsing.py
```

Without `--ambient`, Pcapsing uses the legacy synchronous capture path and original flow-based volume/pitch behavior. The TUI, adaptive scenes, motifs, accents, automatic roots, and other new controls are only enabled when `--ambient` is present.

Run with overlapping ambient pads generated from five-second traffic snapshots:

```bash
python3 pcapsing.py --ambient
```

Add the animated living-network visualization:

```bash
python3 pcapsing.py --ambient --tui
```

The default master volume is `1.3`. Set a louder or quieter initial level with `--volume` (range `0.0` to `2.0`):

```bash
python3 pcapsing.py --ambient --tui --volume 1.6
```

Control musical variation with `--variation low|medium|high` (default: `medium`):

- `low` keeps mostly pads with one sparse motif note and rare event accents.
- `medium` adds two-note traffic motifs and restrained lifecycle accents.
- `high` produces four-note motifs and more frequent event accents.

Motif direction follows flow direction, average packet size selects register, destination and port diversity change scale degree and chord inversion, and SYN/FIN/RST/ICMP events produce rate-limited accents.

In ambient mode, root movement is automatic by default. It follows the circle of fifths (`C → G → D → A → E → B → F# → C# → G# → D# → A# → F`), changes only at motif boundaries, and uses traffic direction to choose clockwise or counterclockwise movement. The minimum hold is 45 seconds at low variation, 30 seconds at medium, and 15 seconds at high. Lock a root with `--root C` (or another note), or explicitly select `--root auto`.

The visualization turns active flows into a living neural graph. Endpoints become neurons, flows become axons, packet direction becomes a traveling impulse, traffic volume controls activation, and inactive connections gradually fade. TCP, UDP, and ICMP use blue, green, and magenta activity. Endpoint addresses determine stable positions but are not printed in the interface.

Start in visual-only full-screen mode:

```bash
python3 pcapsing.py --ambient --tui --fullscreen
```

Choose a synchronized visual and musical neural environment with `--background auto|synapses|clusters|pulse`. In `auto` mode, TCP favors a persistent synaptic web with shimmering pads, UDP favors distributed neural clusters with warm low chords, and ICMP favors expanding signal pulses with faster, more dissonant drones. A scene must remain dominant for eight seconds before a twelve-second musical crossfade begins, preventing abrupt changes.

Both modes support protocol and interface filters:

```bash
python3 pcapsing.py --ambient --tcp --interface eth0
```

Use `python3 pcapsing.py --help` to see all options.

Raw packet capture requires `CAP_NET_RAW` on Linux. Do not run the complete audio/TUI process with `sudo -E`: root inherits the user's audio runtime and produces `XDG_RUNTIME_DIR` ownership warnings. Instead, create a dedicated interpreter copy and grant capabilities only to that copy:

```bash
cp --dereference .venv/bin/python .venv/bin/python-pcapsing
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python-pcapsing
getcap .venv/bin/python-pcapsing
```

Do not apply `setcap` to `.venv/bin/python` itself because it is normally a symlink to the system Python. Run Pcapsing as your regular user:

```bash
.venv/bin/python-pcapsing pcapsing.py --ambient --tui --interface wlp2s0
```

List available interfaces with `ip -brief link`.

# Traffic generator

`traffic_generator.py` creates bounded traffic entirely inside `127.0.0.0/8`; it does not send packets to external hosts. Run Pcapsing on loopback in one terminal:

```bash
.venv/bin/python-pcapsing pcapsing.py \
  --ambient --tui --background auto --variation high --interface lo
```

Then run the two-minute demonstration journey without `sudo` in another terminal:

```bash
.venv/bin/python traffic_generator.py --profile journey --duration 120
```

Available profiles:

| Profile | Traffic behavior |
| --- | --- |
| `small` | Small, slow TCP messages |
| `upload` | Sustained large outbound TCP transfer |
| `download` | Sustained large inbound TCP transfer |
| `connections` | Many short TCP flows for SYN/FIN accents |
| `udp` | Bursty UDP across several ports and loopback aliases |
| `icmp` | ICMP echoes with larger payloads |
| `mixed` | Concurrent TCP, UDP, and short-flow traffic |
| `journey` | Runs all profiles sequentially |

Use `--rate 0.1` through `--rate 5.0` to adjust intensity. The generator needs no elevated privileges; only the packet-capture process does.

# Keyboard controls

When the program is attached to a terminal, these controls are available while packets are being captured. They are visible below the animation unless full-screen mode is active:

| Key | Action |
| --- | --- |
| `W` / `A` / `S` / `D` | Pan around the neural network |
| `Space` | Pause or resume sound |
| `M` | Mute or unmute |
| `Up` / `Down` | Increase or decrease master volume |
| `1` | Calm: quieter 16-second pads every 8 seconds |
| `2` | Balanced: 12-second pads every 5 seconds |
| `3` | Active: louder 7-second pads every 2.5 seconds |
| `V` | Cycle low, medium, and high musical variation |
| `n` | Move to the next root and pause automatic changes for 60 seconds |
| `Shift+N` | Toggle automatic root changes on or off |
| `[` / `]` | Shorten or lengthen ambient pads |
| `B` | Cycle through automatic, synapses, clusters, and pulse scenes |
| `F` | Toggle visual-only full-screen mode |
| `R` | Reset the musical state and network view |
| `H` or `?` | Show the key reference |
| `Q` | Stop capture and quit cleanly |

The preset, variation, root, and pad-length controls primarily affect `--ambient` mode. Keyboard controls are disabled automatically when standard input is redirected or is not a terminal.

# Video

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/k8rNwy6lDLE/0.jpg)](https://www.youtube.com/watch?v=k8rNwy6lDLE)  




