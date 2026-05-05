# Windows Server — Specific Indicators & Boot/Uptime Analysis

## Table of Contents
1. [Boot Sequence & Uptime Forensics](#1-boot-sequence--uptime-forensics)
2. [Ransomware-Specific Patterns](#2-ransomware-specific-patterns)
3. [Service & Process Indicators](#3-service--process-indicators)
4. [EOL / Patch Status Assessment](#4-eol--patch-status-assessment)

---

## 1. Boot Sequence & Uptime Forensics

### Normal Clean Shutdown Sequence
```
6006  → EventLog service stopped (clean)
1074  → USER32: who initiated shutdown + reason code
1076  → USER32: admin documents the reason (optional but expected in managed env)
---- system offline ----
6009  → OS version at next boot
6005  → EventLog service started
6013  → Uptime = <small number of seconds from last boot>
```

### Abnormal / Forced Shutdown Sequence
```
1074  → shutdown triggered (no preceding admin session)
  ← NO 1076 follow-up
---- system offline ----
6008  → "Previous shutdown was unexpected"
6009  → OS version
6005  → EventLog started
6013  → Uptime = small number (17s, 23s, etc.)
```
**Flag:** 1074 with `0x84050013` and no 1076 = unattended security-triggered shutdown.

### Reconstructing Boot History
```python
import pandas as pd, re
from datetime import timedelta

df = load_windows_csv('system.csv')  # use helper from event-ids.md

# Build boot timeline
boots = df[df['事件識別碼'].isin([6005, 6008, 6009, 6013, 1074])].copy()
boots = boots.sort_values('日期和時間')

# Extract uptime from 6013
def parse_uptime(row):
    if row['事件識別碼'] == 6013:
        m = re.search(r'(\d+)\s*秒', str(row['訊息']))
        if m:
            secs = int(m.group(1))
            return secs, secs/86400
    return None, None

boots[['uptime_sec','uptime_days']] = boots.apply(
    lambda r: pd.Series(parse_uptime(r)), axis=1)

print("Boot history:")
print(boots[['日期和時間','事件識別碼','uptime_days']].dropna(subset=['uptime_days']))
```

### Infer Boot Time from Uptime
```python
# If 6013 fires at 2026-04-29 12:00:00 with uptime=29052139 sec
from datetime import datetime, timedelta

event_time = datetime(2026, 4, 29, 12, 0, 0)
uptime_sec = 29052139
boot_time = event_time - timedelta(seconds=uptime_sec)
print(f"Estimated boot time: {boot_time}")
print(f"Days running: {uptime_sec/86400:.1f}")
```

---

## 2. Ransomware-Specific Patterns

### Shadow Copy Deletion (Pre-encryption)
Look for EventID 4688 with:
```
vssadmin.exe delete shadows /all /quiet
wmic shadowcopy delete
bcdedit.exe /set {default} recoveryenabled no
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
wbadmin.exe delete catalog -quiet
```

### Antivirus / Defender Disable
```
# EventID 7040 or 7036
Windows Defender Antivirus Service → stopped / disabled
MsMpEng.exe → terminated (4689)

# EventID 4688
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
net.exe stop "WinDefend"
sc.exe config WinDefend start= disabled
```

### Ransomware Service Installation (EventID 7045)
```
# New service name patterns used by common ransomware families:
Service name contains: windows_bat, svchost32, update_helper,
                       c3pool_miner, svhost, taskhost, lsass
Binary path in: C:\Windows\Temp\, C:\Users\Public\, D:\Backup\, %APPDATA%
```

### NSSM (Non-Sucking Service Manager) Abuse
```
# EventID 7045 or Application log EventID 1040
服務名稱: <suspicious_name>
執行路徑: <binary_path>\nssm.exe "<malware.exe>"

# Known malware-as-service paths seen in incidents:
C:\Windows\system32\config\systemprofile\c3pool\xmrig.exe   ← Monero miner
C:\Users\Public\<random>.exe
D:\SQLBackup\<version=0.0.0.0>.exe
```

### Remote Access Tool Installation
```
# EventID 1033 (MsiInstaller) - legitimate installers used maliciously:
Chrome Remote Desktop Host    ← T1219 - Remote Access Software
AnyDesk                       ← T1219
TeamViewer                    ← T1219
Ammyy Admin                   ← T1219
RustDesk                      ← T1219

# Flag if:
# 1. Installed outside business hours
# 2. Installed after suspicious login events
# 3. Not in standard software inventory
```

### Pass-the-Hash / Lateral Movement Confirmation
```
# EventID 4624 Type 3 with NtLmSsp:
登入處理程序: NtLmSsp
驗證封裝: NTLM
封裝名稱 (僅 NTLM): NTLM V2
來源網路位址: <internal IP>  ← from another internal machine = lateral movement

# Workstation name anomalies:
工作站名稱: windowsXP       ← attacker's machine hostname leaking
工作站名稱: WORKGROUP        ← non-domain machine
工作站名稱: DESKTOP-XXXXXXX  ← personal workstation connecting to server
```

---

## 3. Service & Process Indicators

### Malicious Service Patterns (EventID 7045 / 7040)
```python
df_sys = load_windows_csv('system.csv')

e7045 = df_sys[df_sys['事件識別碼'] == 7045]
# Parse service name and binary path
for _, r in e7045.iterrows():
    svc_name = get_field(r['訊息'], '服務名稱')
    svc_path = get_field(r['訊息'], '服務檔案名稱')
    print(f"{r['日期和時間']} | {svc_name} | {svc_path}")
    
    # Flag suspicious paths
    suspicious_paths = ['\\temp\\', '\\public\\', '\\appdata\\', 
                        'sqlbackup', 'systemprofile', 'xmrig', 'miner']
    if any(p in svc_path.lower() for p in suspicious_paths):
        print("  ⚠️  SUSPICIOUS PATH")
```

### Crash Analysis (EventID 1000)
```python
df_app = load_windows_csv('application.csv')

e1000 = df_app[df_app['事件識別碼'] == 1000].copy()

# Flag version 0.0.0.0 binaries
for _, r in e1000.iterrows():
    app_name = get_field(r['訊息'], '失敗的應用程式名稱')
    app_ver  = get_field(r['訊息'], '失敗的應用程式版本')
    exc_code = get_field(r['訊息'], '例外狀況代碼')
    mod_name = get_field(r['訊息'], '失敗的模組名稱')
    
    if app_ver == '0.0.0.0':
        print(f"⚠️  {r['日期和時間']} | UNVERSIONED BINARY: {app_name} | {exc_code}")
```

---

## 4. EOL / Patch Status Assessment

### Determine Patch History from Setup Log (3.csv / Setup events)
```python
# EventID 9 from Microsoft-Windows-Servicing = component installed
df_setup = load_windows_csv('setup.csv')
updates = df_setup[df_setup['來源'].str.contains('Servicing|WindowsUpdate', na=False)]
print("Last 10 updates/installations:")
print(updates[['日期和時間','訊息']].tail(10).to_string())

# If no updates found after a certain date:
last_update = updates['日期和時間'].max()
print(f"Last recorded update: {last_update}")
print("⚠️  If >180 days ago, patch management is severely lacking")
```

### SMBv1 Status Inference
Direct log evidence is rarely available, but infer from:
1. OS version (WS2008/2012 ship with SMBv1 enabled by default)
2. EventID 3000 from `LanmanServer` — if SMBv1 disabled it shows: `The server message block (SMB) v1 protocol is disabled`
3. If no such event AND old OS: **assume SMBv1 still enabled** → EternalBlue risk

### EternalBlue / MS17-010 Risk Assessment
```
Affected: All Windows versions before March 2017 patches
  → Windows XP, Vista, 7, 8, Server 2003, 2008, 2008R2, 2012, 2012R2

Patch:
  Windows 7 / Server 2008 R2 → KB4012212
  Windows Server 2012 → KB4012213
  Windows Server 2012 R2 → KB4012216

Evidence of exploitation attempt:
  EventID 4688 → lsass.exe spawning unexpected children
  EventID 7045 → service installed immediately after anomalous network login
  Network logs → Port 445 connections from internal IPs scanning subnets
```

### OS Version Risk Summary
| Build | Product | SMBv1 Default | EternalBlue | Status |
|-------|---------|--------------|-------------|--------|
| 6.0.x | WS 2008 | **Enabled** | **Vulnerable** | **EOL** |
| 6.1.x | WS 2008 R2 | **Enabled** | **Vulnerable if unpatched** | **EOL** |
| 6.2.x | WS 2012 | **Enabled** | Vulnerable if unpatched | **EOL** |
| 6.3.x | WS 2012 R2 | **Enabled** | Vulnerable if unpatched | **EOL** |
| 10.0.14393 | WS 2016 | Disabled | Patched in CU | OK |
| 10.0.17763 | WS 2019 | Disabled | Patched in CU | OK |

**Note:** WS2019 (10.0.17763) is supported but if `build 17763` without further CU updates since 2021 → many patches missing. Always check 6013/6009 uptime against last setup log entry.
