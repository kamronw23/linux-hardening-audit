# 🐧 linux-hardening-audit

A **read-only** Bash script that audits a Linux server against common hardening guidance (inspired by the [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)) and prints a **PASS / WARN / FAIL** report with the exact fix for every finding.

It changes nothing on the system. It's safe to run on a server you care about, and it's a good first step when you take over a new box.

---

## ✅ What It Checks

| # | Area | Checks |
|---|---|---|
| 1 | **SSH** | Root login, password auth vs keys, `MaxAuthTries`, empty passwords, X11 forwarding (reads the *effective* config via `sshd -T`) |
| 2 | **Users & Auth** | Extra UID 0 accounts, empty passwords, accounts with login shells, sudo/wheel members, `NOPASSWD` sudo rules, password max age |
| 3 | **Firewall** | UFW, firewalld, nftables, or iptables active |
| 4 | **Network exposure** | Services listening on non-loopback interfaces, cleartext protocols (FTP/Telnet), exposed databases, IP forwarding, ICMP redirects, SYN cookies |
| 5 | **File permissions** | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `sshd_config`, world-writable files, SUID binaries in unusual paths |
| 6 | **Logging** | rsyslog/journald, **auditd**, **fail2ban** |
| 7 | **Updates** | Pending (security) updates, automatic security updates |

It works on Debian/Ubuntu and RHEL/Fedora-family distributions, and it runs automatically on Ubuntu through GitHub Actions on every push (ShellCheck lint plus a full audit run, with the report saved as a build artifact).

---

## 🚀 Usage

```bash
git clone https://github.com/kamronw23/linux-hardening-audit.git
cd linux-hardening-audit
chmod +x linux_audit.sh
sudo ./linux_audit.sh
sudo ./linux_audit.sh --report audit-$(hostname).txt   # also save a text report
```

Without `sudo` it still runs, but it skips the checks that need root (`/etc/shadow`, the SUID/world-writable scan, firewall rules).

**Exit codes:** `0` = no FAIL findings · `2` = at least one FAIL. Useful for scripting and CI.

### Example output (abridged, from an intentionally weak lab VM)
```
== 1. SSH Configuration ==
  [FAIL] Root login over SSH is allowed (PermitRootLogin yes)
         fix: set 'PermitRootLogin no' and restart sshd
  [WARN] SSH password authentication is enabled
         fix: use SSH keys, then set 'PasswordAuthentication no'
  [PASS] SSH does not allow empty passwords

== 3. Firewall ==
  [FAIL] No active host firewall detected
         fix: enable one: 'sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable'
...
== Summary ==
  PASS 14   WARN 6   FAIL 2   ->  hardening score 63%
```

---

## 🔗 Why These Checks Matter

| Finding | Attack it enables | ATT&CK |
|---|---|---|
| SSH password auth / root login | Brute force straight to root | T1110, T1078 |
| No firewall, exposed DB ports | Remote exploitation, data theft | T1190 |
| Extra UID 0 account | Hidden backdoor root account | T1136, T1078.003 |
| Unusual SUID binaries | Local privilege escalation | T1548.001 |
| auditd / logging off | Attacker activity goes unrecorded | T1562.001 |
| Missing security updates | Exploiting known CVEs | T1068, T1190 |

## 🗺️ Roadmap

- [ ] `--json` output for SIEM ingestion
- [ ] Optional `--fix` mode that applies safe remediations after confirmation
- [ ] Before/after screenshots from hardening my own Ubuntu lab VM

---

Part of my [cybersecurity portfolio](https://github.com/kamronw23/Portfolio) · See also: [security-scripts](https://github.com/kamronw23/security-scripts) · [siem-detection-rules](https://github.com/kamronw23/siem-detection-rules)
