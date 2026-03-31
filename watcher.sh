#!/usr/bin/env bash
set -u

RED=$'\033[91m'
YELLOW=$'\033[93m'
GREEN=$'\033[92m'
CYAN=$'\033[96m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
RESET=$'\033[0m'

SSH_LOG_PATHS=("/var/log/auth.log" "/var/log/secure" "/var/log/syslog" "/var/log/messages")
SUSPICIOUS_NAMES=("xmrig" "minerd" "cpuminer" "ncrack" "hydra" "masscan")

declare -A KNOWN_IPS=()
declare -A FAIL_TS=()
declare -a ALL_EVENTS=()
declare -a ALL_ALERTS=()

LOG_PATH=""
LOG_LINE_POS=0

clear_screen() {
  printf '\033[H\033[2J'
}

now_ts() {
  date '+%Y-%m-%d %H:%M:%S'
}

find_ssh_log() {
  local p
  for p in "${SSH_LOG_PATHS[@]}"; do
    [[ -f "$p" ]] && { echo "$p"; return; }
  done
  echo ""
}

init_log_pos() {
  local log_path="$1"
  [[ -z "$log_path" ]] && return
  LOG_LINE_POS=$(wc -l < "$log_path" 2>/dev/null || echo 0)
}

append_capped() {
  local -n arr_ref=$1
  local value="$2"
  local max="$3"
  arr_ref+=("$value")
  while ((${#arr_ref[@]} > max)); do
    arr_ref=("${arr_ref[@]:1}")
  done
}

get_users() {
  w -h 2>/dev/null || true
}

_prune_fail_bucket() {
  local ip="$1"
  local now epoch kept=()
  now=$(date +%s)
  for epoch in ${FAIL_TS[$ip]:-}; do
    (( now - epoch < 60 )) && kept+=("$epoch")
  done
  FAIL_TS[$ip]="${kept[*]:-}"
}

_track_brute() {
  local ip="$1" ts="$2" user="$3"
  local now count
  now=$(date +%s)
  FAIL_TS[$ip]="${FAIL_TS[$ip]:-} $now"
  _prune_fail_bucket "$ip"
  count=$(wc -w <<< "${FAIL_TS[$ip]:-}")
  if [[ "$count" == "5" || "$count" == "15" || "$count" == "30" ]]; then
    append_capped ALL_ALERTS "${ts}|${user}|${ip}|Brute-force: ${count} failures in 60s from ${ip}" 50
  fi
}

monitor_ssh() {
  local log_path="$1"
  [[ -z "$log_path" || ! -f "$log_path" ]] && return

  local total
  total=$(wc -l < "$log_path" 2>/dev/null || echo 0)
  (( total < LOG_LINE_POS )) && LOG_LINE_POS=0

  local start=$((LOG_LINE_POS + 1))
  local line ts user ip
  while IFS= read -r line; do
    ts=$(awk '{print $1" "$2" "$3}' <<< "$line")

    if [[ "$line" =~ Accepted\ password\ for\ ([^[:space:]]+)\ from\ ([0-9a-fA-F:\.]+) ]]; then
      user="${BASH_REMATCH[1]}"
      ip="${BASH_REMATCH[2]}"
      append_capped ALL_EVENTS "${ts}|password|${user}|${ip}" 50
      if [[ -z "${KNOWN_IPS[$ip]+x}" ]]; then
        KNOWN_IPS[$ip]=1
        append_capped ALL_ALERTS "${ts}|${user}|${ip}|New source IP: ${ip}" 50
      fi
      continue
    fi

    if [[ "$line" =~ Accepted\ publickey\ for\ ([^[:space:]]+)\ from\ ([0-9a-fA-F:\.]+) ]]; then
      user="${BASH_REMATCH[1]}"
      ip="${BASH_REMATCH[2]}"
      append_capped ALL_EVENTS "${ts}|pubkey|${user}|${ip}" 50
      if [[ -z "${KNOWN_IPS[$ip]+x}" ]]; then
        KNOWN_IPS[$ip]=1
        append_capped ALL_ALERTS "${ts}|${user}|${ip}|New source IP: ${ip}" 50
      fi
      continue
    fi

    if [[ "$line" =~ session\ opened\ for\ user\ ([^[:space:]]+) ]]; then
      user="${BASH_REMATCH[1]}"
      append_capped ALL_EVENTS "${ts}|session|${user}|-" 50
      continue
    fi

    if [[ "$line" =~ Failed[[:space:]][^[:space:]]+[[:space:]]for[[:space:]](invalid[[:space:]]user[[:space:]])?([^[:space:]]+)[[:space:]]from[[:space:]]([0-9a-fA-F:\.]+) ]]; then
      user="${BASH_REMATCH[2]}"
      ip="${BASH_REMATCH[3]}"
      _track_brute "$ip" "$ts" "$user"
      continue
    fi

    if [[ "$line" =~ Invalid\ user\ ([^[:space:]]+)\ from\ ([0-9a-fA-F:\.]+) ]]; then
      user="${BASH_REMATCH[1]}"
      ip="${BASH_REMATCH[2]}"
      _track_brute "$ip" "$ts" "$user"
      continue
    fi

    if [[ "$line" =~ no\ PTY ]]; then
      append_capped ALL_ALERTS "${ts}|?|-|SSH session with no PTY (non-interactive / potential tunnel)" 50
      continue
    fi
  done < <(sed -n "${start},\$p" "$log_path" 2>/dev/null)

  LOG_LINE_POS=$total
}

suspicious_reason() {
  local user="$1" cmd="$2" binary

  if grep -Eiq '\bnc\b.*-[eE]|\bncat\b.*-[eE]|\bsocat\b.*(exec|system)|bash[[:space:]]+-i[[:space:]]*>[&>]|/dev/tcp/|/dev/udp/|python[23]?[[:space:]].*\bsocket\b.*\bconnect\b|python[23]?[[:space:]].*\bsubprocess\b.*\bshell\b|perl[[:space:]]+-e.*socket|ruby[[:space:]]+-rsocket|curl[[:space:]]+.+\|[[:space:]]*(ba)?sh|wget[[:space:]]+.+\|[[:space:]]*(ba)?sh|curl[[:space:]]+.+\|[[:space:]]*python' <<< "$cmd"; then
    echo "Suspicious pattern match"
    return
  fi

  binary=$(awk '{print $1}' <<< "$cmd")
  binary="${binary##*/}"
  local s
  for s in "${SUSPICIOUS_NAMES[@]}"; do
    if [[ "${binary,,}" == "$s" ]]; then
      echo "Suspicious binary: $binary"
      return
    fi
  done

  if [[ "$user" == "root" ]] && grep -Eq '(^|[[:space:]/])(/tmp|/dev/shm|/var/tmp)/' <<< "$cmd"; then
    echo "root process executing from world-writable path"
    return
  fi

  echo ""
}

render_users() {
  local users="$1"
  printf "%s%s[USERS]%s\n" "$BOLD" "$CYAN" "$RESET"
  if [[ -z "$users" ]]; then
    printf "  %sNo users currently logged in.%s\n" "$DIM" "$RESET"
    return
  fi
  printf "  %s%-14s %-10s %-22s %-8s %s%s\n" "$BOLD" "USER" "TTY" "FROM" "LOGIN" "IDLE" "$RESET"
  printf "  %s\n" "─────────────────────────────────────────────────────────────────"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    awk '{printf "  %-14s %-10s %-22s %-8s %s\n",$1,$2,$3,$4,$5}' <<< "$line"
  done <<< "$users"
}

render_ssh_events() {
  printf "\n%s%s[SSH EVENTS]%s  %s(last 12)%s\n" "$BOLD" "$CYAN" "$RESET" "$DIM" "$RESET"
  if ((${#ALL_EVENTS[@]} == 0)); then
    printf "  %sNo new SSH events since start.%s\n" "$DIM" "$RESET"
    return
  fi
  printf "  %s%-18s %-10s %-14s %s%s\n" "$BOLD" "TIMESTAMP" "TYPE" "USER" "IP" "$RESET"
  printf "  %s\n" "────────────────────────────────────────────────────────────"

  local start=0 i ts type user ip
  ((${#ALL_EVENTS[@]} > 12)) && start=$((${#ALL_EVENTS[@]} - 12))
  for ((i=start; i<${#ALL_EVENTS[@]}; i++)); do
    IFS='|' read -r ts type user ip <<< "${ALL_EVENTS[$i]}"
    printf "  %-18s %-10s %-14s %s\n" "$ts" "${type^^}" "$user" "$ip"
  done
}

render_ssh_alerts() {
  printf "\n%s%s[SSH ALERTS]%s  %s(last 10)%s\n" "$BOLD" "$RED" "$RESET" "$DIM" "$RESET"
  if ((${#ALL_ALERTS[@]} == 0)); then
    printf "  %sNone.%s\n" "$GREEN" "$RESET"
    return
  fi

  local start=0 i ts user ip reason
  ((${#ALL_ALERTS[@]} > 10)) && start=$((${#ALL_ALERTS[@]} - 10))
  for ((i=start; i<${#ALL_ALERTS[@]}; i++)); do
    IFS='|' read -r ts user ip reason <<< "${ALL_ALERTS[$i]}"
    printf "  %s[!]%s %s  user=%s  ip=%s\n" "$RED" "$RESET" "$ts" "$user" "$ip"
    printf "      %s%s%s\n" "$RED" "$reason" "$RESET"
  done
}

render_processes() {
  printf "\n%s%s[PROCESSES]%s\n" "$BOLD" "$CYAN" "$RESET"

  local suspicious_out="" normal_out=""
  local line user pid cpu mem cmd reason
  while IFS=$'\t' read -r user pid cpu mem cmd; do
    [[ -z "${user:-}" ]] && continue
    reason=$(suspicious_reason "$user" "$cmd")
    if [[ -n "$reason" ]]; then
      suspicious_out+="${pid}|${user}|${cpu}|${mem}|${cmd}|${reason}"$'\n'
    else
      normal_out+="${user}|${pid}|${cpu}|${mem}|${cmd}"$'\n'
    fi
  done < <(ps aux --no-headers 2>/dev/null | awk '{
    user=$1; pid=$2; cpu=$3; mem=$4;
    $1=$2=$3=$4=$5=$6=$7=$8=$9=$10="";
    sub(/^ +/,"");
    print user "\t" pid "\t" cpu "\t" mem "\t" $0
  }')

  if [[ -n "$suspicious_out" ]]; then
    printf "  %s%s─── SUSPICIOUS ─────────────────────────────────────────────%s\n" "$RED" "$BOLD" "$RESET"
    while IFS='|' read -r pid user cpu mem cmd reason; do
      [[ -z "${pid:-}" ]] && continue
      printf "  %s[!] pid=%-7s user=%-12s cpu=%s%%  mem=%s%%%s\n" "$RED" "$pid" "$user" "$cpu" "$mem" "$RESET"
      printf "      %scmd: %s%s\n" "$RED" "$cmd" "$RESET"
      printf "      %swhy: %s%s\n" "$YELLOW" "$reason" "$RESET"
    done <<< "$suspicious_out"
    printf "\n"
  fi

  printf "  %s%-14s %-7s %-6s %-6s %s%s\n" "$BOLD" "USER" "PID" "CPU%" "MEM%" "CMD" "$RESET"
  printf "  %s\n" "────────────────────────────────────────────────────────────────────────"
  ps aux --sort=-%cpu --no-headers 2>/dev/null | awk '
    NR<=12 {
      user=$1; pid=$2; cpu=$3; mem=$4;
      $1=$2=$3=$4=$5=$6=$7=$8=$9=$10="";
      sub(/^ +/,"");
      printf("  %-14s %-7s %-6s %-6s %s\n", user, pid, cpu, mem, substr($0,1,90));
    }'
}

main() {
  LOG_PATH=$(find_ssh_log)
  init_log_pos "$LOG_PATH"

  if [[ "$EUID" -ne 0 ]]; then
    printf "%s[warn] Not running as root - SSH log and some process details may be unavailable.%s\n" "$YELLOW" "$RESET" >&2
  fi

  printf "Watcher initializing...  log=%s\n" "${LOG_PATH:-NOT FOUND}"
  sleep 0.8

  while true; do
    LOG_PATH="${LOG_PATH:-$(find_ssh_log)}"
    monitor_ssh "$LOG_PATH"

    clear_screen
    local ts
    ts=$(now_ts)
    printf "%sWatcher  %s  |  %s  |  q=Ctrl+C%s\n" "$BOLD" "$ts" "${LOG_PATH:-log=N/A}" "$RESET"
    printf "════════════════════════════════════════════════════════════════════════\n"

    render_users "$(get_users)"
    render_ssh_events
    render_ssh_alerts
    render_processes

    sleep 3
  done
}

main
