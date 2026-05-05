# Cisco ASA / FTD Reference — Syslog + Config Audit

## Table of Contents
1. [Config Audit](#1-config-audit)
2. [Syslog Analysis](#2-syslog-analysis)
3. [Key Indicators Quick Reference](#3-key-indicators-quick-reference)

---

## 1. Config Audit

### 1.1 Management Access Exposure
```
http server enable
http 0.0.0.0 0.0.0.0 outside        ← CRITICAL: ASDM open to all IPs on outside
ssh 0.0.0.0 0.0.0.0 outside         ← CRITICAL: SSH open to all
telnet 0.0.0.0 0.0.0.0 inside       ← HIGH: Telnet is plaintext
```
**Safe pattern:** `ssh <specific-IP> <mask> outside`

### 1.2 AAA / Local Users
```
username admin password <hash> privilege 15    ← priv 15 = full admin
username <name> password <hash> privilege 15   ← non-default admin account
```
**Flag:** Multiple privilege-15 accounts, especially unfamiliar names.

### 1.3 Password Encryption
```
no service password-encryption    ← CRITICAL: passwords stored in plaintext
service password-encryption       ← OK (type 7, weak but encoded)
enable password <hash> level 15   ← check if default/weak
```

### 1.4 ACL — Inbound (outside → inside)
```
access-list OUTSIDE_IN extended permit ip any any    ← CRITICAL: no filtering
access-list OUTSIDE_IN extended permit tcp any host <DMZ-IP> eq 3389   ← RDP exposed
```
**Flag:** `permit ip any any`, `permit tcp any any`, or permitting high-risk ports (22, 23, 3389, 445).

### 1.5 NAT / Port Forwarding
```
object network OBJ_SERVER
 host 192.168.1.10
nat (inside,outside) static interface service tcp 3389 3389   ← RDP exposed
```
List all static NAT entries and map to internal hosts + ports.

### 1.6 VPN Configuration
```
crypto map OUTSIDE_MAP 10 match address VPN_ACL
crypto map OUTSIDE_MAP 10 set peer <remote-IP>
```
Check for split tunneling, weak encryption (`des`, `3des`, `md5` = old/weak).

### 1.7 Firmware / Version
Extract from `show version` output or config header:
```
: Saved
: Serial Number: <serial>
: Hardware: ASA5505 / ASA5508 / FTD-1010 / etc.
ASA Version 9.x.x
```
Flag: ASA 9.x < 9.16.4 has multiple known CVEs.
FTD: Check against Cisco PSIRT for current version.

---

## 2. Syslog Analysis

### 2.1 Log Format
Cisco ASA syslogs follow this pattern:
```
<timestamp> <hostname> %ASA-<severity>-<message-id>: <message>
# Example:
Apr 29 17:16:08 ASA5508 %ASA-6-302013: Built inbound TCP connection 12345 for outside:80.82.65.127/54321 (80.82.65.127/54321) to inside:192.168.1.1/443 (211.20.153.13/443)
```

FTD uses structured format via FMC or syslog:
```
<timestamp> <hostname> SFIMS: [<policy>] <event_type> {<proto>} <src>:<port> -> <dst>:<port>
```

### 2.2 Key Message IDs

**Authentication Events:**
| Message ID | Meaning |
|-----------|---------|
| `%ASA-6-113004` | AAA user authentication successful |
| `%ASA-6-113005` | AAA user authentication rejected |
| `%ASA-5-111010` | User executed command (SSH/Telnet) |
| `%ASA-5-111009` | User executed command (privileged) |

**Connection Events:**
| Message ID | Meaning |
|-----------|---------|
| `%ASA-6-302013` | Built TCP connection |
| `%ASA-6-302014` | Teardown TCP connection (has bytes transferred) |
| `%ASA-4-106023` | Deny by ACL |
| `%ASA-2-106001` | Inbound TCP connection denied |

**VPN Events:**
| Message ID | Meaning |
|-----------|---------|
| `%ASA-6-713228` | IKE SA established |
| `%ASA-5-722033` | SSL VPN user connected |
| `%ASA-4-722051` | SSL VPN user disconnected — note bytes in/out |

**IDS/IPS (FTD):**
| Event Type | Meaning |
|-----------|---------|
| `Intrusion Event` | IPS signature triggered |
| `Connection Event` | Firewall connection log |

### 2.3 Brute Force Detection
```python
import re
from collections import Counter

with open('asa-syslog.log') as f:
    lines = f.readlines()

# Count 113005 (auth failures) per source IP
failures = Counter()
for line in lines:
    if '113005' in line:
        ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        if ip:
            failures[ip.group(1)] += 1

print("Top brute force sources:")
for ip, count in failures.most_common(10):
    print(f"  {ip}: {count} failures")
```

### 2.4 Config Change Detection
```
%ASA-5-111010: User 'admin', running 'cli' from IP <IP>, executed 'write mem'
%ASA-5-111010: User 'admin', running 'cli' from IP <IP>, executed 'copy running-config tftp'
```
**Flag:** Any `write mem`, `copy`, `no access-list`, `no crypto map` from unexpected IPs.

---

## 3. Key Indicators Quick Reference

| Indicator | Risk |
|-----------|------|
| `http 0.0.0.0 0.0.0.0 outside` | 🔴 ASDM exposed to internet |
| `ssh 0.0.0.0 0.0.0.0 outside` | 🔴 SSH exposed to internet |
| Unfamiliar privilege-15 account | 🔴 Unauthorized admin account |
| `no service password-encryption` | 🔴 Plaintext passwords |
| `permit ip any any` in outside ACL | 🔴 No filtering |
| 113005 > 20 from single IP | 🔴 Brute force in progress |
| 113004 from unexpected geography | 🔴 Unauthorized admin login |
| `copy running-config tftp` | 🔴 Config exfiltration |
| `write mem` after suspicious login | 🟠 Possible config tampering |
| RDP/SMB/SQL ports in static NAT | 🟠 High-risk services exposed |
| Weak VPN cipher (DES/3DES/MD5) | 🟠 Encryption downgrade risk |
