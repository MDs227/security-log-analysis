# Linux — auth.log / secure / syslog Analysis

## Table of Contents
1. [Log File Locations](#1-log-file-locations)
2. [Authentication Events](#2-authentication-events)
3. [Persistence & Lateral Movement](#3-persistence--lateral-movement)
4. [Key Parsing Templates](#4-key-parsing-templates)
5. [Quick Indicators Reference](#5-quick-indicators-reference)

---

## 1. Log File Locations

| Distro | Auth Log | Syslog | Kernel |
|--------|---------|--------|--------|
| Ubuntu/Debian | `/var/log/auth.log` | `/var/log/syslog` | `/var/log/kern.log` |
| CentOS/RHEL/Rocky | `/var/log/secure` | `/var/log/messages` | `/var/log/messages` |
| Both (systemd) | `journalctl -u ssh` | `journalctl` | `journalctl -k` |

Rotated logs: `auth.log.1`, `auth.log.2.gz`, `secure-20260428` etc.
Always decompress and check rotated logs: `zcat auth.log.2.gz >> all_auth.log`

---

## 2. Authentication Events

### SSH Login Success
```
Apr 29 03:44:12 server sshd[1234]: Accepted password for root from 192.168.1.230 port 54321 ssh2
Apr 29 03:44:12 server sshd[1234]: Accepted publickey for admin from 10.0.0.5 port 44321 ssh2: RSA SHA256:<fingerprint>
```
**Extract:** timestamp, username, source IP, auth method (password vs publickey)
**Flag:** `root` login from non-local IP; `password` auth from external IP (should be key-only)

### SSH Login Failure / Brute Force
```
Apr 28 10:15:03 server sshd[2345]: Failed password for invalid user admin from 192.168.1.103 port 12345 ssh2
Apr 28 10:15:04 server sshd[2345]: Failed password for root from 192.168.1.103 port 12346 ssh2
Apr 28 10:15:05 server sshd[2345]: Invalid user postgres from 192.168.1.103 port 12347
```
**Threshold:** >20 failures from single IP in 10 minutes = brute force

### PAM / sudo Events
```
Apr 29 04:15:22 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
Apr 29 04:15:22 server sudo: pam_unix(sudo:session): session opened for user root by admin(uid=1000)
```
**Flag:** `sudo bash`, `sudo su`, `sudo -i` = full root shell acquired
**Flag:** Unfamiliar user running sudo at unusual hours

### New Session / Login
```
Apr 29 03:44:15 server systemd-logind[890]: New session 42 of user root.
Apr 29 03:44:15 server sshd[1234]: pam_unix(sshd:session): session opened for user root
```

### Session Close (Duration)
```
Apr 29 09:15:44 server sshd[1234]: pam_unix(sshd:session): session closed for user root
```
Duration = close_time - open_time. Flag: sessions >2 hours from external IPs.

---

## 3. Persistence & Lateral Movement

### New User / Group Created
```
Apr 28 10:30:01 server useradd[3456]: new user: name=backdoor, UID=1001, GID=1001, ...
Apr 28 10:30:02 server usermod[3457]: add 'backdoor' to group 'sudo'
Apr 28 10:30:02 server passwd[3458]: pam_unix(passwd:chauthtok): password changed for backdoor
```
**Flag:** New user with sudo/wheel group, created at unusual time, unknown name

### SSH Authorized Keys Modification
Look for file access logs or direct grep on common persistence locations:
```bash
# Evidence in logs (if auditd enabled):
type=PATH msg=audit: name="/root/.ssh/authorized_keys" ...

# Or check file timestamps in incident context:
ls -la /root/.ssh/ /home/*/.ssh/
find / -name "authorized_keys" -newer /var/log/auth.log -2024
```

### Crontab / Scheduled Tasks
```bash
# Evidence in syslog:
Apr 28 10:35:00 server cron[4567]: (root) CMD (/tmp/.x/update.sh)
Apr 28 10:35:00 server CRON[4568]: pam_unix(crond:session): session opened for user root

# Suspicious patterns:
# Cron running from /tmp, /dev/shm, /var/tmp
# Cron with base64 encoded commands
# wget/curl piped to bash from cron
```

### Process Masquerading
```bash
# In /var/log/syslog or audit logs:
kernel: [12345.678] audit: type=EXECVE msg=audit(timestamp): argc=3 a0="./kthreadd" a1="-c" a2="..."
# Process names mimicking kernel threads: kthreadd, kworker, kswapd
# Look in: /tmp, /dev/shm, /var/tmp — kernel threads don't run from there
```

### Reverse Shell Indicators
```
# Outbound connections from server processes (in syslog/firewall logs):
Apr 29 04:20:33 server kernel: FIREWALL ACCEPT OUT=eth0 SRC=192.168.1.50 DST=80.82.65.127 DPT=4444
# bash/sh connecting to external IP on non-standard high port = reverse shell
# Common ports: 4444, 1337, 8888, 9001, 443 (blending with HTTPS)
```

---

## 4. Key Parsing Templates

### Basic Auth Log Analysis
```python
import re, pandas as pd
from collections import Counter, defaultdict

def parse_auth_log(path):
    events = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            # Extract common fields
            ts = re.search(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
            host = re.search(r'^\S+\s+\S+\s+(\S+)', line)
            
            ev = {
                'timestamp': ts.group(1) if ts else '',
                'raw': line.strip(),
                'success': 'Accepted' in line or 'session opened' in line,
                'failure': 'Failed' in line or 'Invalid user' in line,
            }
            
            # SSH specific
            ssh_accept = re.search(r'Accepted (\S+) for (\S+) from (\S+) port', line)
            ssh_fail   = re.search(r'Failed \S+ for (?:invalid user )?(\S+) from (\S+)', line)
            sudo_cmd   = re.search(r'sudo:.*USER=(\S+).*COMMAND=(.+)', line)
            new_user   = re.search(r'useradd.*new user: name=(\S+)', line)
            
            if ssh_accept:
                ev.update({'type':'ssh_success','method':ssh_accept.group(1),
                           'user':ssh_accept.group(2),'src_ip':ssh_accept.group(3)})
            elif ssh_fail:
                ev.update({'type':'ssh_fail','user':ssh_fail.group(1),
                           'src_ip':ssh_fail.group(2)})
            elif sudo_cmd:
                ev.update({'type':'sudo','as_user':sudo_cmd.group(1),
                           'command':sudo_cmd.group(2)})
            elif new_user:
                ev.update({'type':'new_user','username':new_user.group(1)})
            
            events.append(ev)
    return pd.DataFrame(events)

df = parse_auth_log('/var/log/auth.log')

print("=== SSH Success (external IPs) ===")
ssh_ok = df[df['type']=='ssh_success'].copy()
external = ssh_ok[~ssh_ok['src_ip'].str.startswith(('192.168.','10.','172.'))]
print(external[['timestamp','user','src_ip','method']].to_string())

print("\n=== Brute Force Sources (>20 failures) ===")
ssh_fail = df[df['type']=='ssh_fail'].copy()
print(ssh_fail.groupby('src_ip').size().sort_values(ascending=False).head(10))

print("\n=== sudo Commands ===")
sudo = df[df['type']=='sudo'].copy()
print(sudo[['timestamp','as_user','command']].to_string())

print("\n=== New Users Created ===")
new_u = df[df['type']=='new_user'].copy()
print(new_u[['timestamp','username']].to_string())
```

---

## 5. Quick Indicators Reference

| Indicator | Log Pattern | Risk |
|-----------|------------|------|
| Root SSH login from external IP | `Accepted password for root from <ext-IP>` | 🔴 Critical |
| Password auth from external IP | `Accepted password for ... from <ext-IP>` | 🔴 High (should be key-only) |
| >20 SSH failures from single IP | `Failed password` repeated | 🔴 Brute force |
| Unknown user created with sudo | `useradd` + `usermod ... sudo` | 🔴 Critical |
| `sudo bash` / `sudo su -` | sudo session to root shell | 🔴 High |
| New authorized_keys entry | File modification at unusual time | 🔴 Persistence |
| Cron job from `/tmp` or `/dev/shm` | CRON + suspicious path | 🔴 Critical |
| SSH session >2h from external | Session duration in paired open/close | 🟠 High |
| Process masquerading kernel name | EXECVE from `/tmp/kthreadd` etc. | 🔴 Critical |
| Reverse shell port connection | Outbound high-port from server process | 🔴 Critical |
| `wget`/`curl` \| `bash` from cron | Download-and-execute persistence | 🔴 Critical |
