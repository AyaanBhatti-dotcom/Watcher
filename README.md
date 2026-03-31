# Watcher

Lightweight Linux terminal monitor for CTF/KOTH and quick incident-response visibility.

![Platform](https://img.shields.io/badge/platform-linux-informational)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Shell](https://img.shields.io/badge/bash-4%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Watcher provides a live dashboard with:

- active users (`w`)
- SSH auth events from system logs
- security alerts (new IPs, brute-force thresholds, no-PTY sessions)
- suspicious process detection using command and binary heuristics

## Why This Exists

During KOTH/CTF, you often need quick situational awareness without deploying heavy tooling.  
Watcher is intentionally simple, local, and low-dependency.

## Implementations

- `watcher.py` - Python implementation (standard library only)
- `watcher.sh` - Bash implementation for hosts without Python

## Features

- Live refresh every 3 seconds
- SSH event parsing:
  - accepted password/publickey logins
  - failed/invalid attempts
  - session-opened events
- Alerting:
  - first-seen source IP
  - brute-force thresholds in 60s windows
  - no-PTY session detection
- Process inspection:
  - reverse-shell style pattern matches
  - known suspicious binaries (example: `xmrig`, `hydra`)
  - root processes launching from `/tmp`, `/dev/shm`, `/var/tmp`

## Requirements

- Linux (Kali/Debian target)
- Recommended: run with `sudo` for full visibility

### Python mode

- Python 3.8+
- No `pip` dependencies

### Shell mode

- Bash 4+ (uses associative arrays)
- Tools: `ps`, `w`, `awk`, `sed`, `grep`

## SSH Log Sources

Watcher reads the first existing file from:

- `/var/log/auth.log`
- `/var/log/secure`
- `/var/log/syslog`
- `/var/log/messages`

## Quick Start

### Python

```bash
sudo python3 watcher.py
```

### Shell (no Python target)

```bash
chmod +x watcher.sh
sudo ./watcher.sh
```

Stop with `Ctrl+C`.

## Dashboard Sections

- `[USERS]` active sessions
- `[SSH EVENTS]` parsed auth activity
- `[SSH ALERTS]` notable detections
- `[PROCESSES]` suspicious entries + top CPU consumers

## Troubleshooting

### `log=NOT FOUND`

Your host may be writing SSH logs somewhere else.

```bash
ls -l /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages
journalctl -u ssh -n 50 --no-pager
journalctl -u sshd -n 50 --no-pager
```

If logs are only in `journald`, configure file logging (rsyslog) or add a journald-reader path in your script.

### Not running as root

Without `sudo`, you may miss:

- SSH log access
- full process metadata

## Security Notes

- Watcher is a helper, not a full EDR/SIEM.
- Heuristic detection can produce false positives.
- Validate alerts before taking action.

## Project Structure

```text
.
├── watcher.py
├── watcher.sh
└── README.md
```

## Upload to GitHub

From this folder:

```bash
git init
git add watcher.py watcher.sh README.md
git commit -m "Add Watcher Python and Bash monitors"
git branch -M main
git remote add origin https://github.com/<your-username>/Watcher.git
git push -u origin main
```

If remote already has commits, pull/rebase before pushing.

## License

Add a `LICENSE` file before publishing (MIT is a common choice).
