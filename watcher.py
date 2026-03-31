#!/usr/bin/env python3
import os
import re
import sys
import time
import subprocess
from datetime import datetime

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

SSH_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]

known_ips      = set()
ssh_log_pos    = {}
recent_fail    = {}   # ip -> [timestamps]

SUSPICIOUS_CMD_PATTERNS = [
    re.compile(r, re.IGNORECASE) for r in [
        r'\bnc\b.*-[eE]',
        r'\bncat\b.*-[eE]',
        r'\bsocat\b.*(exec|system)',
        r'bash\s+-i\s*>[&>]',
        r'/dev/tcp/',
        r'/dev/udp/',
        r'python[23]?\s.*\bsocket\b.*\bconnect\b',
        r'python[23]?\s.*\bsubprocess\b.*\bshell\b',
        r'perl\s+-e.*socket',
        r'ruby\s+-rsocket',
        r'curl\s+.+\|\s*(ba)?sh',
        r'wget\s+.+\|\s*(ba)?sh',
        r'curl\s+.+\|\s*python',
    ]
]

SUSPICIOUS_NAMES = {'xmrig', 'minerd', 'cpuminer', 'ncrack', 'hydra', 'masscan'}


# ─── helpers ──────────────────────────────────────────────────────────────────

def clear_screen():
    sys.stdout.write("\033[H\033[2J")
    sys.stdout.flush()


def find_ssh_log():
    for p in SSH_LOG_PATHS:
        if os.path.exists(p):
            return p
    return None


def init_log_pos(log_path):
    if log_path and log_path not in ssh_log_pos:
        try:
            with open(log_path, 'r', errors='replace') as f:
                f.seek(0, 2)
                ssh_log_pos[log_path] = f.tell()
        except OSError:
            ssh_log_pos[log_path] = 0


# ─── data collection ──────────────────────────────────────────────────────────

def get_users():
    try:
        r = subprocess.run(['w', '-h'], capture_output=True, text=True, timeout=4)
    except Exception:
        return []
    users = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        users.append({
            'user':  parts[0],
            'tty':   parts[1],
            'from':  parts[2],
            'login': parts[3],
            'idle':  parts[4],
        })
    return users


def monitor_ssh(log_path):
    events = []
    alerts = []

    if not log_path or not os.path.exists(log_path):
        return events, alerts

    try:
        with open(log_path, 'r', errors='replace') as f:
            f.seek(ssh_log_pos.get(log_path, 0))
            lines = f.readlines()
            ssh_log_pos[log_path] = f.tell()
    except OSError:
        return events, alerts

    pat_accept_pass  = re.compile(r'(\w{3}\s+\d+\s+[\d:]+).*Accepted password for (\S+) from ([\d.:a-fA-F]+)')
    pat_accept_key   = re.compile(r'(\w{3}\s+\d+\s+[\d:]+).*Accepted publickey for (\S+) from ([\d.:a-fA-F]+)')
    pat_session_open = re.compile(r'(\w{3}\s+\d+\s+[\d:]+).*session opened for user (\S+)')
    pat_failed       = re.compile(r'(\w{3}\s+\d+\s+[\d:]+).*Failed \w+ for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+)')
    pat_no_tty       = re.compile(r'(\w{3}\s+\d+\s+[\d:]+).*sshd.*no PTY allocated')
    pat_invalid      = re.compile(r'(\w{3}\s+\d+\s+[\d:]+).*Invalid user (\S+) from ([\d.:a-fA-F]+)')

    now = time.time()

    for line in lines:
        m = pat_accept_pass.search(line)
        if m:
            ts, user, ip = m.group(1), m.group(2), m.group(3)
            events.append({'ts': ts, 'user': user, 'ip': ip, 'type': 'password'})
            _flag_new_ip(ip, ts, user, alerts)
            continue

        m = pat_accept_key.search(line)
        if m:
            ts, user, ip = m.group(1), m.group(2), m.group(3)
            events.append({'ts': ts, 'user': user, 'ip': ip, 'type': 'pubkey'})
            _flag_new_ip(ip, ts, user, alerts)
            continue

        m = pat_session_open.search(line)
        if m:
            ts, user = m.group(1), m.group(2)
            events.append({'ts': ts, 'user': user, 'ip': '-', 'type': 'session'})
            continue

        m = pat_failed.search(line)
        if m:
            ts, user, ip = m.group(1), m.group(2), m.group(3)
            _track_brute(ip, ts, user, alerts, now)
            continue

        m = pat_invalid.search(line)
        if m:
            ts, user, ip = m.group(1), m.group(2), m.group(3)
            _track_brute(ip, ts, user, alerts, now)
            continue

        m = pat_no_tty.search(line)
        if m:
            ts = m.group(1)
            alerts.append({'ts': ts, 'user': '?', 'ip': '-',
                           'reason': 'SSH session with no PTY (non-interactive / potential tunnel)'})

    return events, alerts


def _flag_new_ip(ip, ts, user, alerts):
    if ip not in known_ips:
        known_ips.add(ip)
        alerts.append({'ts': ts, 'user': user, 'ip': ip,
                       'reason': f'New source IP: {ip}'})


def _track_brute(ip, ts, user, alerts, now):
    bucket = recent_fail.setdefault(ip, [])
    bucket.append(now)
    recent_fail[ip] = [t for t in bucket if now - t < 60]
    count = len(recent_fail[ip])
    if count in (5, 15, 30):
        alerts.append({'ts': ts, 'user': user, 'ip': ip,
                       'reason': f'Brute-force: {count} failures in 60s from {ip}'})


def scan_processes():
    try:
        r = subprocess.run(
            ['ps', 'aux', '--no-headers'],
            capture_output=True, text=True, timeout=5
        )
    except Exception:
        return [], []

    normal = []
    suspicious = []

    for line in r.stdout.splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue

        user  = parts[0]
        pid   = parts[1]
        cpu   = parts[2]
        mem   = parts[3]
        cmd   = parts[10]

        proc = {'user': user, 'pid': pid, 'cpu': cpu, 'mem': mem, 'cmd': cmd[:90]}

        reason = _suspicious_reason(user, cmd)
        if reason:
            proc['reason'] = reason
            suspicious.append(proc)
        else:
            normal.append(proc)

    return normal, suspicious


def _suspicious_reason(user, cmd):
    for pat in SUSPICIOUS_CMD_PATTERNS:
        if pat.search(cmd):
            return f'Suspicious pattern: {pat.pattern[:50]}'

    binary = os.path.basename(cmd.split()[0]) if cmd.split() else ''
    if binary.lower() in SUSPICIOUS_NAMES:
        return f'Suspicious binary: {binary}'

    if user == 'root' and re.search(r'(?:^|[\s/])(?:/tmp|/dev/shm|/var/tmp)/', cmd):
        return 'root process executing from world-writable path'

    return None


# ─── rendering ────────────────────────────────────────────────────────────────

def render_users(users):
    print(f"{BOLD}{CYAN}[USERS]{RESET}")
    if not users:
        print(f"  {DIM}No users currently logged in.{RESET}")
        return
    print(f"  {BOLD}{'USER':<14} {'TTY':<10} {'FROM':<22} {'LOGIN':<8} {'IDLE'}{RESET}")
    print(f"  {'─'*65}")
    for u in users:
        print(f"  {u['user']:<14} {u['tty']:<10} {u['from']:<22} {u['login']:<8} {u['idle']}")


def render_ssh_events(events):
    print(f"\n{BOLD}{CYAN}[SSH EVENTS]{RESET}  {DIM}(last 12){RESET}")
    if not events:
        print(f"  {DIM}No new SSH events since start.{RESET}")
        return
    print(f"  {BOLD}{'TIMESTAMP':<18} {'TYPE':<10} {'USER':<14} {'IP'}{RESET}")
    print(f"  {'─'*60}")
    for e in events[-12:]:
        print(f"  {e['ts']:<18} {e['type'].upper():<10} {e['user']:<14} {e['ip']}")


def render_ssh_alerts(alerts):
    print(f"\n{BOLD}{RED}[SSH ALERTS]{RESET}  {DIM}(last 10){RESET}")
    if not alerts:
        print(f"  {GREEN}None.{RESET}")
        return
    for a in alerts[-10:]:
        print(f"  {RED}[!]{RESET} {a['ts']}  user={a['user']}  ip={a['ip']}")
        print(f"      {RED}{a['reason']}{RESET}")


def render_processes(normal, suspicious):
    print(f"\n{BOLD}{CYAN}[PROCESSES]{RESET}")

    if suspicious:
        print(f"  {RED}{BOLD}─── SUSPICIOUS ─────────────────────────────────────────────{RESET}")
        for p in suspicious:
            print(f"  {RED}[!] pid={p['pid']:<7} user={p['user']:<12} cpu={p['cpu']}%  mem={p['mem']}%{RESET}")
            print(f"      {RED}cmd: {p['cmd']}{RESET}")
            print(f"      {YELLOW}why: {p['reason']}{RESET}")
        print()

    top = sorted(
        normal,
        key=lambda x: float(x['cpu']) if x['cpu'].replace('.', '', 1).isdigit() else 0,
        reverse=True
    )[:12]

    print(f"  {BOLD}{'USER':<14} {'PID':<7} {'CPU%':<6} {'MEM%':<6} CMD{RESET}")
    print(f"  {'─'*72}")
    for p in top:
        print(f"  {p['user']:<14} {p['pid']:<7} {p['cpu']:<6} {p['mem']:<6} {p['cmd']}")


# ─── main loop ────────────────────────────────────────────────────────────────

def main():
    log_path = find_ssh_log()
    init_log_pos(log_path)

    all_events = []
    all_alerts = []

    sys.stdout.write(f"Watcher initializing...  log={log_path or 'NOT FOUND'}\n")
    sys.stdout.flush()
    time.sleep(0.8)

    while True:
        try:
            users                      = get_users()
            new_events, new_alerts     = monitor_ssh(log_path)
            normal_procs, susp_procs   = scan_processes()

            all_events.extend(new_events)
            all_alerts.extend(new_alerts)
            all_events = all_events[-50:]
            all_alerts = all_alerts[-50:]

            clear_screen()
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_label = log_path or 'log=N/A'
            print(f"{BOLD}Watcher  {ts}  │  {log_label}  │  q=^C{RESET}")
            print(f"{'═'*72}")

            render_users(users)
            render_ssh_events(all_events)
            render_ssh_alerts(all_alerts)
            render_processes(normal_procs, susp_procs)

            sys.stdout.flush()
            time.sleep(3)

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Watcher stopped.{RESET}")
            sys.exit(0)
        except Exception:
            time.sleep(3)


if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.stderr.write(f"{YELLOW}[warn] Not running as root — SSH log and some process details may be unavailable.{RESET}\n")
    main()
