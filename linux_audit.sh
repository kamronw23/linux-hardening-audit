#!/usr/bin/env bash
# =============================================================================
# linux_audit.sh - read-only Linux security hardening audit
# Author: Kam'ron Washington
#
# Checks a Linux host against common hardening guidance (inspired by the
# CIS Benchmarks) and prints PASS / WARN / FAIL with a fix for each finding.
# It changes NOTHING on the system; it only reads configuration.
#
# Usage:
#   sudo ./linux_audit.sh              # full audit (root sees more)
#   sudo ./linux_audit.sh --report r.txt   # also save a plain-text report
# =============================================================================

set -u

REPORT=""
[[ "${1:-}" == "--report" && -n "${2:-}" ]] && REPORT="$2"

if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[36m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YEL=""; BLU=""; BLD=""; RST=""
fi

PASS=0; WARN=0; FAIL=0
LINES=()

log()     { LINES+=("$1"); }
section() { printf "\n%s== %s ==%s\n" "$BLD$BLU" "$1" "$RST"; log ""; log "== $1 =="; }
pass()    { PASS=$((PASS+1)); printf "  %s[PASS]%s %s\n" "$GRN" "$RST" "$1"; log "  [PASS] $1"; }
warn()    { WARN=$((WARN+1)); printf "  %s[WARN]%s %s\n         fix: %s\n" "$YEL" "$RST" "$1" "$2"; log "  [WARN] $1 | fix: $2"; }
fail()    { FAIL=$((FAIL+1)); printf "  %s[FAIL]%s %s\n         fix: %s\n" "$RED" "$RST" "$1" "$2"; log "  [FAIL] $1 | fix: $2"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# Effective sshd setting: ask sshd itself if possible (handles Include/defaults), else grep the file.
sshd_val() {
  local key="$1" v=""
  if have sshd && [[ $EUID -eq 0 ]]; then
    v=$(sshd -T 2>/dev/null | awk -v k="$(echo "$key" | tr 'A-Z' 'a-z')" '$1==k {print $2; exit}')
  fi
  if [[ -z "$v" && -r /etc/ssh/sshd_config ]]; then
    v=$(grep -Ei "^\s*$key\s+" /etc/ssh/sshd_config | tail -1 | awk '{print $2}')
  fi
  echo "${v,,}"
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This audit targets Linux. Detected: $(uname -s). Run it on a Linux VM or server."
  exit 1
fi
[[ $EUID -ne 0 ]] && printf "%sNote: not running as root, so some checks will be skipped. Use sudo for a full audit.%s\n" "$YEL" "$RST"

printf "%sLinux Hardening Audit%s: %s (%s) - %s\n" "$BLD" "$RST" "$(hostname)" \
  "$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -r)" "$(date '+%Y-%m-%d %H:%M')"

# -----------------------------------------------------------------------------
section "1. SSH Configuration"
if [[ -r /etc/ssh/sshd_config ]] || have sshd; then
  v=$(sshd_val PermitRootLogin)
  case "$v" in
    no) pass "Root login over SSH is disabled" ;;
    prohibit-password|without-password) warn "Root may log in with keys (PermitRootLogin $v)" "set 'PermitRootLogin no' in /etc/ssh/sshd_config" ;;
    *) fail "Root login over SSH is allowed (PermitRootLogin ${v:-default})" "set 'PermitRootLogin no' and restart sshd" ;;
  esac
  v=$(sshd_val PasswordAuthentication)
  [[ "$v" == "no" ]] && pass "SSH password authentication is disabled (keys only)" \
    || warn "SSH password authentication is enabled" "use SSH keys, then set 'PasswordAuthentication no'"
  v=$(sshd_val MaxAuthTries)
  [[ -n "$v" && "$v" -le 4 ]] 2>/dev/null && pass "MaxAuthTries is $v" \
    || warn "MaxAuthTries is ${v:-6 (default)}" "set 'MaxAuthTries 4' to slow brute-force attempts"
  v=$(sshd_val PermitEmptyPasswords)
  [[ "$v" == "yes" ]] && fail "SSH allows empty passwords" "set 'PermitEmptyPasswords no'" \
    || pass "SSH does not allow empty passwords"
  v=$(sshd_val X11Forwarding)
  [[ "$v" == "yes" ]] && warn "X11 forwarding is enabled" "set 'X11Forwarding no' unless you need it" \
    || pass "X11 forwarding is disabled"
else
  pass "OpenSSH server not installed (nothing to harden)"
fi

# -----------------------------------------------------------------------------
section "2. Users & Authentication"
uid0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)
[[ -z "$uid0" ]] && pass "Only root has UID 0" \
  || fail "Non-root accounts with UID 0: $uid0" "remove or change the UID of these accounts; they are full root"

if [[ -r /etc/shadow ]]; then
  empty=$(awk -F: '($2=="") {print $1}' /etc/shadow)
  [[ -z "$empty" ]] && pass "No accounts with empty passwords" \
    || fail "Accounts with EMPTY passwords: $empty" "run 'passwd -l <user>' or set a password"
else
  printf "  [SKIP] /etc/shadow not readable (needs root)\n"
fi

shells=$(awk -F: '$3>=1000 && $3<65534 && $7!~/(nologin|false)$/ {print $1}' /etc/passwd | tr '\n' ' ')
printf "  [INFO] Human accounts with a login shell: %s\n" "${shells:-none}"
log "  [INFO] Human accounts with a login shell: ${shells:-none}"

sudoers=$(getent group sudo wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ' | xargs)
printf "  [INFO] sudo/wheel members: %s\n" "${sudoers:-none}"
log "  [INFO] sudo/wheel members: ${sudoers:-none}"
if [[ $EUID -eq 0 ]] && grep -rqsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
  warn "NOPASSWD entries exist in sudoers" "require a password for sudo unless a service account truly needs it"
fi

if [[ -r /etc/login.defs ]]; then
  max=$(awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs)
  [[ -n "$max" && "$max" -le 365 ]] && pass "PASS_MAX_DAYS is $max" \
    || warn "Password max age is ${max:-unset}" "set PASS_MAX_DAYS 365 (or per your policy) in /etc/login.defs"
fi

# -----------------------------------------------------------------------------
section "3. Firewall"
if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
  pass "UFW firewall is active"
elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running; then
  pass "firewalld is running"
elif have nft && [[ $EUID -eq 0 ]] && nft list ruleset 2>/dev/null | grep -q 'hook input'; then
  pass "nftables input rules are loaded"
elif have iptables && [[ $EUID -eq 0 ]] && [[ $(iptables -S INPUT 2>/dev/null | wc -l) -gt 1 ]]; then
  pass "iptables INPUT rules are present"
else
  fail "No active host firewall detected" "enable one: 'sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable'"
fi

# -----------------------------------------------------------------------------
section "4. Network Exposure"
if have ss; then
  listen=$(ss -tulnH 2>/dev/null | awk '{print $1" "$5}' | grep -vE '127\.0\.0\.|\[::1\]' | sort -u)
  if [[ -z "$listen" ]]; then
    pass "No services listening on external interfaces"
  else
    printf "  [INFO] Services listening on non-loopback addresses:\n"
    while read -r proto addr; do
      port="${addr##*:}"
      printf "         %-4s %s\n" "$proto" "$addr"; log "         $proto $addr"
      case "$port" in
        21)   fail "FTP (21) is exposed; credentials travel in cleartext" "replace with SFTP" ;;
        23)   fail "Telnet (23) is exposed; cleartext remote shell" "disable telnet and use SSH" ;;
        111)  warn "rpcbind (111) is exposed" "disable if NFS is not in use: 'systemctl disable --now rpcbind'" ;;
        3306|5432|6379|27017|9200) warn "A database/cache port ($port) is reachable from the network" "bind it to 127.0.0.1 or restrict it with the firewall" ;;
      esac
    done <<< "$listen"
  fi
fi
v=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
[[ "$v" == "0" ]] && pass "IP forwarding is disabled" \
  || warn "IP forwarding is enabled" "set net.ipv4.ip_forward=0 unless this host is a router/VPN/container host"
v=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
[[ "$v" == "0" ]] && pass "ICMP redirects are ignored" \
  || warn "ICMP redirects are accepted" "set net.ipv4.conf.all.accept_redirects=0"
v=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
[[ "$v" == "1" ]] && pass "TCP SYN cookies are enabled (SYN-flood protection)" \
  || warn "TCP SYN cookies are disabled" "set net.ipv4.tcp_syncookies=1"

# -----------------------------------------------------------------------------
section "5. File Permissions"
check_perm() {  # path max_octal description
  [[ -e "$1" ]] || return
  local p; p=$(stat -c '%a' "$1")
  if (( 8#$p & ~8#$2 )); then
    fail "$1 has permissions $p (should be $2 or stricter)" "chmod $2 $1"
  else
    pass "$1 permissions are $p"
  fi
}
check_perm /etc/passwd 644
check_perm /etc/shadow 640
check_perm /etc/group 644
check_perm /etc/ssh/sshd_config 600

if [[ $EUID -eq 0 ]]; then
  ww=$(find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20)
  [[ -z "$ww" ]] && pass "No world-writable files on the root filesystem" \
    || warn "World-writable files found (first 20):"$'\n'"$(sed 's/^/           /' <<< "$ww")" "chmod o-w <file> unless intentional"

  known='/(usr/)?(s?bin|lib(exec)?)/'
  suid=$(find / -xdev -perm -4000 -type f 2>/dev/null | grep -Ev "^$known" | head -20)
  [[ -z "$suid" ]] && pass "No SUID binaries outside standard system paths" \
    || warn "SUID binaries in unusual locations (privilege-escalation risk):"$'\n'"$(sed 's/^/           /' <<< "$suid")" "verify each; remove SUID with 'chmod u-s <file>' if not needed"
fi

# -----------------------------------------------------------------------------
section "6. Logging & Auditing"
if have systemctl; then
  for svc in rsyslog systemd-journald auditd fail2ban; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      pass "$svc is running"
    else
      case "$svc" in
        auditd)   warn "auditd is not running" "install and enable it for detailed security auditing: 'apt install auditd'" ;;
        fail2ban) warn "fail2ban is not running" "install it to auto-ban IPs that brute-force SSH" ;;
        rsyslog)  have journalctl || warn "No syslog daemon running" "enable rsyslog or journald" ;;
        *)        warn "$svc is not running" "systemctl enable --now $svc" ;;
      esac
    fi
  done
fi

# -----------------------------------------------------------------------------
section "7. Updates"
if have apt-get; then
  n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')
  s=$(apt-get -s upgrade 2>/dev/null | grep '^Inst' | grep -ci security)
  [[ "$n" -eq 0 ]] && pass "No pending package updates" \
    || { [[ "$s" -gt 0 ]] && fail "$n pending updates ($s security)" "sudo apt update && sudo apt upgrade" \
         || warn "$n pending updates" "sudo apt update && sudo apt upgrade"; }
  dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii' && pass "unattended-upgrades is installed" \
    || warn "Automatic security updates are not configured" "sudo apt install unattended-upgrades"
elif have dnf; then
  n=$(dnf -q check-update 2>/dev/null | grep -cE '^\S+\s+\S+\s+\S+$')
  [[ "$n" -eq 0 ]] && pass "No pending package updates" || warn "$n pending updates" "sudo dnf upgrade"
fi

# -----------------------------------------------------------------------------
TOTAL=$((PASS+WARN+FAIL))
SCORE=$(( TOTAL > 0 ? (PASS*100)/TOTAL : 0 ))
printf "\n%s== Summary ==%s\n  %sPASS %d%s   %sWARN %d%s   %sFAIL %d%s   ->  hardening score %d%%\n" \
  "$BLD" "$RST" "$GRN" "$PASS" "$RST" "$YEL" "$WARN" "$RST" "$RED" "$FAIL" "$RST" "$SCORE"
log ""; log "Summary: PASS $PASS  WARN $WARN  FAIL $FAIL  score ${SCORE}%"

if [[ -n "$REPORT" ]]; then
  printf "%s\n" "Linux Hardening Audit - $(hostname) - $(date)" "${LINES[@]}" > "$REPORT"
  echo "  Report saved to $REPORT"
fi
exit $(( FAIL > 0 ? 2 : 0 ))
