# Sharetech Reference — ST / SG Series Log + Config Audit

## Table of Contents
1. [Device Identification](#0-device-identification)
2. [Config Audit](#1-config-audit)
3. [Log Format & Analysis](#2-log-format--analysis)
4. [Key Indicators Quick Reference](#3-key-indicators-quick-reference)

---

## 0. Device Identification

**ST Series** (UTM appliances): ST-2004G, ST-2104G, ST-3004, ST-3104, ST-5004
**SG Series** (Next-Gen FW): SG-2100, SG-4100, SG-6100

Config files often begin with:
```
# Sharetech ST-2104G Configuration
# Firmware Version: x.x.x.x
# Date: YYYY-MM-DD
```

Or from exported syslog:
```
<timestamp> <hostname> sysd=sharetech type=event ...
<timestamp> <hostname> kernel: [<seconds>] firewall: ...
```

Web UI exported logs are typically CSV or plain text with semicolon or comma delimiters.

---

## 1. Config Audit

### 1.1 WAN / Admin Access
Sharetech stores admin access rules under:
```
[admin_access]
wan_http = yes     ← CRITICAL: Web UI accessible from WAN
wan_https = yes    ← CRITICAL
wan_ssh = yes      ← CRITICAL
trusted_ip =       ← empty = no IP restriction
```
Or in CLI format:
```
set system admin wan-access http enable    ← flag
set system admin trusted-ip <IP>           ← should be set
```

### 1.2 Admin Accounts
```
[users]
admin:$apr1$<hash>:admin      ← default admin account
<username>:<hash>:admin       ← additional admin — flag if unknown
```

### 1.3 Firewall Rules — Inbound
```
[firewall_rules]
rule_id=1 src=any dst=<WAN-IP> dport=any action=accept    ← CRITICAL
rule_id=2 src=any dst=192.168.1.10 dport=3389 action=accept   ← RDP exposed
```
**Flag:** `src=any` + `dport=any` or high-risk ports without IPS/content filter enabled.

### 1.4 Port Forwarding / Virtual Server
```
[virtual_server]
vs_id=1 proto=tcp ext_port=443 int_ip=192.168.1.10 int_port=443
vs_id=2 proto=tcp ext_port=8080 int_ip=192.168.1.20 int_port=80
```
Build port map. Flag: 22, 23, 445, 3389, 1433, 3306, 5900 (VNC).

### 1.5 IPS / Content Filter Status
```
[ips]
enable = no      ← CRITICAL: IPS disabled
[content_filter]
enable = no      ← web filtering off
```

---

## 2. Log Format & Analysis

### 2.1 Syslog Format (ST Series)
```
# Standard syslog format:
<priority> <timestamp> <hostname> <process>[<pid>]: <message>

# Admin login:
<134>Apr 28 10:25:01 ST-2104G admin_auth[1234]: user=admin login_from=192.168.1.100 result=success proto=https

# Firewall deny:
<134>Apr 28 10:26:15 ST-2104G kernel: firewall DENY IN=eth0 OUT=eth1 SRC=80.82.65.127 DST=192.168.1.1 PROTO=TCP DPT=443

# IPS alert:
<130>Apr 28 10:27:00 ST-2104G ips[567]: alert sig_id=1234 sig_name="SMB Exploit" src=192.168.1.230 dst=192.168.1.50 action=drop
```

### 2.2 Syslog Format (SG Series)
SG series uses more structured key=value:
```
date=2026-04-28 time=10:25:01 devname="SG-4100" type="traffic" subtype="forward"
action="accept" srcip=80.82.65.127 dstip=192.168.1.10 srcport=54321 dstport=443
proto=6 sentbyte=1240 rcvdbyte=890 duration=45 policy_id=5

date=2026-04-28 time=10:25:03 devname="SG-4100" type="event" subtype="admin"
action="login" user="admin" srcip=192.168.1.100 result="success" ui="webui"
```
Note: SG format closely resembles FortiGate — apply similar parsing logic.

### 2.3 Web UI Exported CSV
When exported from web console, typical columns:
```
時間, 類型, 來源IP, 目的IP, 來源埠, 目的埠, 協定, 動作, 說明
2026/04/28 10:25:01, 管理員登入, 80.82.65.127, 211.20.153.13, 54321, 443, TCP, 成功, admin 登入成功
```
Parse with: `pd.read_csv(file, encoding='utf-8-sig')` or `encoding='big5'`

### 2.4 Key Parsing Patterns

**Admin Login Events:**
```python
import re

# ST series syslog
login_pattern = re.compile(
    r'(\w{3}\s+\d+ \d+:\d+:\d+).*admin_auth.*user=(\S+).*login_from=(\S+).*result=(\S+)'
)
# SG series
sg_login_pattern = re.compile(
    r'date=(\S+) time=(\S+).*action="login".*user="([^"]+)".*srcip=(\S+).*result="(\S+)"'
)
```

**Firewall Deny (potential attack):**
```python
deny_pattern = re.compile(
    r'firewall DENY.*SRC=(\S+).*DST=(\S+).*DPT=(\d+)'
)
# High DPT count from single SRC = scan/attack
```

**IPS Alerts:**
```python
ips_pattern = re.compile(
    r'ips.*sig_name="([^"]+)".*src=(\S+).*dst=(\S+).*action=(\S+)'
)
```

### 2.5 Brute Force Detection
```python
from collections import Counter
import re

with open('sharetech-log.txt') as f:
    lines = f.readlines()

login_failures = Counter()
for line in lines:
    if 'result=fail' in line or 'result=failed' in line or '驗證失敗' in line:
        ip = re.search(r'login_from=(\S+)|srcip=(\S+)', line)
        if ip:
            src = ip.group(1) or ip.group(2)
            login_failures[src.rstrip(',')] += 1

print("Brute force candidates (>20 failures):")
for ip, count in login_failures.most_common():
    if count > 20:
        print(f"  {ip}: {count} failures")
```

---

## 3. Key Indicators Quick Reference

| Indicator | Log Pattern | Risk |
|-----------|------------|------|
| Admin web UI open on WAN | `wan_https = yes` + no `trusted_ip` | 🔴 Critical |
| Admin login from external IP | `login_from=<non-RFC1918>` + `result=success` | 🔴 Critical |
| >20 login failures from single IP | `result=fail` repeated | 🔴 Brute force |
| IPS disabled | `[ips] enable = no` | 🔴 Critical |
| Unknown admin account | `<unknown>:<hash>:admin` in config | 🔴 Critical |
| `src=any dport=any action=accept` | Firewall rule | 🔴 Critical |
| Port 445/3389/22 in virtual server | High-risk service exposed | 🟠 High |
| `action=drop` on IPS with EternalBlue sig | Attempted SMB exploit | 🔴 Critical |
| Large byte transfers outbound | Data exfiltration possible | 🟠 High |
| Config export event | `copy config` / 設定備份 | 🟠 High (if unexpected) |
