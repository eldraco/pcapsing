# Pcapsing

A network sniffer that turns live traffic into continuous groove music so you can monitor activity by listening.

Instead of alarm-like beeps, it now runs a continuous melody engine:
- tempo follows packet rate and burstiness,
- note and harmonic color follow protocol mix (TCP/UDP/ICMP),
- texture and rhythmic density change with traffic intensity,
- low bass + pad background keep the sound deeper and smoother.

# Usage
`python pcapsing.py`

# Video

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/k8rNwy6lDLE/0.jpg)](https://www.youtube.com/watch?v=k8rNwy6lDLE)  




Common filters:
- `python pcapsing.py --tcp`
- `python pcapsing.py --udp`
- `python pcapsing.py --icmp`
- `python pcapsing.py -i en0`

Runtime tempo hotkeys (while running in terminal):
- `-` or `[` slower baseline tempo
- `=` or `]` faster baseline tempo
- `0` reset baseline tempo
- `h` or `?` show hotkey help

These keys shift only the base tempo. Traffic still controls relative rhythm changes.
The app now starts with a slower default baseline (`-16 BPM`) and allows much slower values than before.
