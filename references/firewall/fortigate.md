# FortiGate Reference — Conf Audit + Event Log Analysis

## Table of Contents
1. [Config File Audit](#1-config-file-audit)
2. [Event Log Analysis](#2-event-log-analysis)
3. [Key Indicators Quick Reference](#3-key-indicators-quick-reference)

---

## 1. Config File Audit

### 1.1 WAN Interface — Admin Exposure
```
config system interface
  edit "wan1"
    set allowaccess ping https ssh    ← CRITICAL if https or ssh present
```
**Risk:** Any internet IP can reach the management interface.
**Check for:** `trusthost1/2/3` under `config system admin` → if absent, no IP whitelist exists.

```
config system admin
  edit "admin"
    set trusthost1 <IP/mask>    ← should be present; if absent = open to world
```

### 1.2 Admin Accounts
```
config system admin
  edit "<username>"
    set accprofile "super_admin"    ← highest privilege
    set password ENC <hash>
    # trusthost absent = no IP restriction
```
**Flag:** Any account with `super_admin` and no `trusthost` — especially non-default names (not "admin").

### 1.3 Admin Lockout Settings
Look for under `config system global`:
```
set admin-lockout-threshold 3     ← should exist
set admin-lockout-duration 60
```
**Flag:** If absent → no brute-force protection.

### 1.4 Firewall Policies — Inbound (WAN→internal)
For each `config firewall policy` entry check:

| Field | Dangerous Value | Safe Value |
|-------|----------------|------------|
| `srcaddr` | `"all"` | specific address group |
| `service` | `"ALL"` | specific named services |
| `ips-sensor` | absent | profile name set |
| `av-profile` | absent | profile name set |
| `ssl-ssh-profile` | absent | profile name set |
| `nat` | `enable` with no session limits | — |

**Critical combination:** `srcaddr=all` + `service=ALL` + no UTM = full exposure, zero inspection.

### 1.5 VIP (Port Forwarding)
```
config firewall vip
  edit "<name>"
    set extip <WAN-IP>
    set extintf "wan1"
    set portforward enable
    set extport <port>
    set mappedip <internal-IP>
    set mappedport <port>
```
Map all VIPs: `WAN-IP:port → internal-IP:port`. Note ports that expose:
- 22 (SSH), 23 (Telnet), 3389 (RDP), 445 (SMB), 1433 (MSSQL), 3306 (MySQL)

### 1.6 Firmware Version
```
#config-version=FGT60F-7.0.3-FW-build0237-XXXXXX
```
Extract version and check against known critical CVEs:

| FortiOS Version | Critical CVEs |
|----------------|---------------|
| 7.0.x < 7.0.14 | CVE-2022-40684 (Auth bypass, CVSS 9.6), CVE-2023-27997 (SSL-VPN RCE, CVSS 9.2) |
| 6.4.x < 6.4.13 | CVE-2022-40684, CVE-2023-27997 |
| 6.2.x | CVE-2022-40684, multiple SSL-VPN vulns |
| Any with SSL-VPN | CVE-2024-21762 (OOB Write, CVSS 9.6) |

---

## 2. Event Log Analysis

### 2.1 Log Format
FortiGate memory/disk logs are key=value pairs:
```
date=2026-04-02 time=20:44:15 devname="FG60F" logid="0100032001"
type="event" subtype="system" level="information" action="login"
status="success" user="adminAAA" ui="https(80.82.65.127)"
srcip=80.82.65.127 dstip=211.20.153.13 msg="Administrator adminAAA logged in..."
```

### 2.2 Key Event Patterns

**Admin Login Success:**
```python
# Filter criteria
'action="login"' AND 'status="success"'
# Extract: date, time, user, srcip, ui (contains protocol)
```

**Admin Login Failure (Brute Force):**
```python
'action="login"' AND 'status="failed"'
# High volume from single IP = brute force
# threshold: >20 failures in 1 hour = flag
```

**Config Download (Intelligence Gathering):**
```python
'action="download"' OR 'logdesc' contains 'download'
# Attacker exfiltrating full config = knows internal topology
```

**Config Change:**
```python
'action="set"' OR 'action="edit"' OR 'logdesc' contains 'config'
```

**SSH Session Duration:**
```python
# Look for login + logout pairs with same srcip
# session_duration = logout_time - login_time
# >3600s (1h) = suspicious; >7200s (2h) = highly suspicious
```

### 2.3 Source IP Analysis

For each unique srcip in successful logins:
1. Note geolocation (ASN lookup)
2. Flag non-local, non-office IPs → especially:
   - Eastern Europe (UA, RO, RU, BG)
   - South America (BR, AR)
   - Known VPN/datacenter ASNs (AS34109, AS29551, AS262621, etc.)
3. Count login frequency and time pattern
4. Check for IP rotation pattern (same attacker, different exit nodes)

### 2.4 Timeline Reconstruction Python Template
```python
import re, pandas as pd
from collections import defaultdict

lines = open('memory-event-system.log', encoding='latin-1').readlines()

events = []
for line in lines:
    if 'login' not in line: continue
    d = re.search(r'date=(\S+) time=(\S+)', line)
    user = re.search(r'user="([^"]+)"', line)
    status = re.search(r'status="([^"]+)"', line)
    srcip = re.search(r'srcip=(\S+)', line)
    action = re.search(r'action="([^"]+)"', line)
    if d and status:
        events.append({
            'datetime': d.group(1) + ' ' + d.group(2),
            'user': user.group(1) if user else '',
            'status': status.group(1),
            'srcip': srcip.group(1) if srcip else '',
            'action': action.group(1) if action else '',
        })

df = pd.DataFrame(events)
print("=== Successful logins by user+IP ===")
print(df[df['status']=='success'].groupby(['user','srcip']).size())
print("\n=== Download events ===")
print(df[df['action']=='download'])
```

---

## 3. Key Indicators Quick Reference

| Indicator | Meaning | Risk |
|-----------|---------|------|
| `allowaccess ping https ssh` on wan interface | Management interface exposed to internet | 🔴 Critical |
| Admin account without `trusthost` | No IP restriction on admin login | 🔴 Critical |
| No `admin-lockout-threshold` | Brute force protection disabled | 🔴 Critical |
| `action="login" status="success"` from non-local IP | Unauthorized admin access | 🔴 Critical |
| `action="download"` after suspicious login | Config exfiltration — attacker maps internal network | 🔴 Critical |
| `service=ALL` on inbound policy | Full attack surface exposure | 🔴 Critical |
| No IPS/AV profile on inbound policy | Traffic not inspected | 🟠 High |
| SSH session >3600s from external IP | Attacker using FW as pivot/jump host | 🔴 Critical |
| FortiOS 7.0.x without patch | CVE-2022-40684 auth bypass possible | 🔴 Critical |
| `srcaddr=all` on inbound policy | No source IP restriction | 🟠 High |
| Multiple login successes from rotating IPs | VPN/Tor node rotation — evasion | 🔴 Critical |
