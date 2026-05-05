# Windows Event IDs — Master Reference Table

All EventIDs listed with Traditional Chinese field names as they appear in Taiwan-locale Windows.

## Table of Contents
1. [Security Log — Authentication](#1-security-log--authentication)
2. [Security Log — Account Management](#2-security-log--account-management)
3. [Security Log — Process & Object](#3-security-log--process--object)
4. [System Log — Service & Boot](#4-system-log--service--boot)
5. [Application Log — Key Sources](#5-application-log--key-sources)
6. [Parsing Templates](#6-parsing-templates)

---

## 1. Security Log — Authentication

### Login Success: EventID 4624
**Source:** `Microsoft-Windows-Security-Auditing`
**Key fields:**
```
帳戶名稱     ← TWO occurrences: [0]=subject (usually SYSTEM), [1]=logged-in account
帳戶網域
登入類型     ← most important field
來源網路位址
來源連接埠
登入處理程序   ← NtLmSsp = NTLM, Kerberos = domain, User32 = local console
驗證封裝     ← NTLM / Kerberos / Negotiate
```

**Login Types:**
| Type | Name | Description |
|------|------|-------------|
| 2 | Interactive | Local console login |
| 3 | Network | SMB, net use, file share access |
| 4 | Batch | Scheduled task |
| 5 | Service | Service account logon |
| 7 | Unlock | Screen unlock (RDP reconnect or console) |
| 8 | NetworkCleartext | Plaintext credentials (IIS basic auth) |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached domain credentials |

**Ransomware lateral movement flags:**
- Type 3 from internal IP with `NtLmSsp` + `NTLM V2` = Pass-the-Hash
- Workstation name showing unexpected values (`windowsXP`, `WORKGROUP`, `DESKTOP-XXXXX` from server) = suspicious
- Type 3 from IP that also appears in firewall logs = confirmed lateral path

### Login Failure: EventID 4625
**Key fields:**
```
帳戶名稱     ← [1] = attempted account name
來源網路位址
失敗原因     ← "不明的使用者名稱或錯誤密碼" = wrong password; "帳戶目前已鎖定" = locked
```
**Flag:** >50 failures from single IP in short window = brute force

### Explicit Credential Login: EventID 4648
Logged when process uses credentials different from logged-in user (RunAs, PtH):
```
帳戶名稱     ← account used
目標伺服器名稱 ← target machine
處理程序名稱  ← process invoking the auth (cmd.exe, powershell.exe = suspicious)
```

### NTLM Authentication: EventID 4776
```
登入帳戶     ← account attempting NTLM auth
工作站       ← source machine name (often reveals attacker's hostname)
錯誤碼       ← 0x0 = success; 0xC000006A = wrong password
```

### Kerberos TGT/Service Ticket: EventID 4768 / 4769
```
帳戶名稱
用戶端位址   ← source IP
加密類型     ← 0x17 = RC4 (weak, used in PtH with NTLM hash) = flag
失敗碼       ← 0x12 = account disabled; 0x18 = wrong password
```

---

## 2. Security Log — Account Management

| EventID | Meaning | Ransomware Relevance |
|---------|---------|---------------------|
| 4720 | User account created | Attacker creates backdoor account |
| 4722 | User account enabled | Re-enabling disabled account |
| 4723 | Password change attempt (user) | — |
| 4724 | Password reset (admin) | Normal admin action |
| 4725 | User account disabled | Attacker disabling recovery accounts |
| 4726 | User account deleted | Covering tracks |
| **4738** | **User account changed** | **密碼被竄改的主要指標** |
| 4740 | User account locked out | Triggered by brute force |
| 4728 | User added to global group | Privilege escalation |
| 4732 | User added to local group | Lateral privilege escalation |
| 4756 | User added to universal group | Domain privilege escalation |

**4738 Critical Fields:**
```
目標帳戶名稱        ← modified account
呼叫者使用者名稱    ← who made the change
                    ← "SYSTEM" with no preceding admin action = malware-modified
最近的密碼設定      ← timestamp updates = password was changed
```
**Flag:** SYSTEM modifying Administrator password without preceding legitimate admin session = ransomware/malware behavior.

---

## 3. Security Log — Process & Object

| EventID | Meaning | Notes |
|---------|---------|-------|
| **4688** | New process created | Requires "Process Tracking" audit policy enabled |
| 4689 | Process terminated | — |
| 4657 | Registry value modified | Config tampering |
| 4698 | Scheduled task created | Persistence mechanism |
| 4699 | Scheduled task deleted | Covering tracks |
| 4700 | Scheduled task enabled | — |
| 4702 | Scheduled task modified | — |
| **1102** | Audit log cleared | 🔴 Attacker covering tracks |
| 4656 | Object handle requested | File/directory access |
| 4663 | Object accessed | — |

**4688 Suspicious Process Patterns:**
```
新的程序名稱 contains:
  - powershell.exe, cmd.exe (from unusual parents)
  - wscript.exe, cscript.exe
  - mshta.exe, certutil.exe (LOLBins)
  - vssadmin.exe Delete Shadows  ← 🔴 ransomware deleting backups
  - bcdedit.exe /set recoveryenabled no  ← 🔴 disabling recovery
  - wbadmin delete catalog  ← 🔴 deleting backup catalog
  - net.exe stop "Windows Defender"  ← 🔴 disabling AV
  - sc.exe config <service> start= disabled
```

---

## 4. System Log — Service & Boot

| EventID | Source | Meaning |
|---------|--------|---------|
| **6005** | EventLog | Event log service started = system boot |
| **6006** | EventLog | Event log service stopped = clean shutdown |
| **6008** | EventLog | Previous shutdown unexpected = dirty shutdown / crash / forced off |
| **6009** | EventLog | OS version at boot — extract: major/minor/build |
| **6013** | EventLog | System uptime in seconds — `uptime / 86400` = days running |
| **1074** | USER32 | System shutdown/restart initiated |
| **1076** | USER32 | Shutdown reason documented by user (follow-up to 1074) |
| 7045 | SCM | New service installed |
| **7040** | SCM | Service start type changed |
| **7036** | SCM | Service entered running/stopped state |

**EventID 1074 Critical Fields:**
```
程序                ← process that called shutdown
  Explorer.EXE    ← user clicked Start→Shutdown (or malware impersonating user)
  winlogon.exe    ← system-level shutdown
使用者名稱          ← account
理由代碼
  0x84050013      ← "Security Issue" — legitimate use: AV shutdown / ransomware-triggered
  0x500ff         ← "Other (Unplanned)" — power loss or forced shutdown
  0x80020003      ← Operating System: Reconfigure (Planned)
關機類型
  重新啟動 / 關機 / 電源關閉
```
**Flag:** 0x84050013 without preceding admin session + no 1076 follow-up = malware-triggered.
**Flag:** 0x84050013 + 0x500ff within seconds of each other = double shutdown command (ransomware pattern).

**EventID 6013 — Uptime Calculation:**
```python
uptime_seconds = int(re.search(r'執行時間是 (\d+) 秒', msg).group(1))
boot_time = event_time - timedelta(seconds=uptime_seconds)
days_running = uptime_seconds / 86400
# >180 days = no recent maintenance; >300 days = severely neglected
```

**EventID 6009 — EOL Check:**
```
Microsoft Windows <major>.<minor>.<build> Service Pack <n>
```
| Version String | Product | EOL Date |
|----------------|---------|----------|
| 6.0.6001 SP1 | Windows Server 2008 SP1 | **2020-01-14** |
| 6.1.7601 SP1 | Windows Server 2008 R2 SP1 | **2020-01-14** |
| 6.2.9200 | Windows Server 2012 | **2023-10-10** |
| 6.3.9600 | Windows Server 2012 R2 | **2023-10-10** |
| 10.0.14393 | Windows Server 2016 | 2027-01-12 |
| 10.0.17763 | Windows Server 2019 | 2029-01-09 |

---

## 5. Application Log — Key Sources

| Source | Relevant Events | Ransomware Relevance |
|--------|----------------|---------------------|
| **MsiInstaller** | 1033 (install success), 1034 (remove) | Unexpected software installation |
| **nssm** | 1040 | Service management — malware as a service |
| **Application Error** | 1000 (crash) | `version=0.0.0.0` = unsigned/malware binary |
| **MSSQLSERVER** | 18264 (backup), 3014 (backup fail) | Check backup path for unusual locations |
| Chrome/Edge | 256+ | Browser-based C2 or exfiltration activity |
| **Windows Error Reporting** | 1001 | Crash dumps — useful for identifying crashed malware |

**Application Error 1000 — Malware Indicators:**
```
失敗的應用程式名稱: <name>
失敗的應用程式版本: 0.0.0.0     ← 🔴 no version info = likely malware
例外狀況代碼: 0xc0000005        ← access violation (common in malware)
失敗的模組名稱: KERNELBASE.dll  ← .NET exception wrapper
```
**Flag:** Binary in unusual paths: `C:\Windows\Temp\`, `D:\SQLBackup\`, `C:\Users\Public\`, `%APPDATA%`, `%TEMP%`.

---

## 6. Parsing Templates

### Load Any Windows Event CSV
```python
import pandas as pd, re

def load_windows_csv(path):
    # Detect delimiter
    with open(path, encoding='utf-8-sig') as f:
        first_line = f.readline()
    sep = '，' if '，' in first_line else ','
    
    # Security log has '關鍵字' as first col, others have '等級'
    is_security = '關鍵字' in first_line
    cols = ['關鍵字' if is_security else '等級',
            '日期和時間', '來源', '事件識別碼', '工作類別', '訊息']
    
    df = pd.read_csv(path, encoding='utf-8-sig', sep=sep,
                     engine='python', names=cols, skiprows=1,
                     on_bad_lines='skip')
    df['事件識別碼'] = pd.to_numeric(df['事件識別碼'], errors='coerce')
    return df

# Extract field from Windows event message
def get_field(msg, field_name, occurrence=0):
    """Extract named field value from Windows event message."""
    matches = re.findall(field_name + r':\s*\t*([^\r\n\t]+)', str(msg))
    if len(matches) > occurrence:
        val = matches[occurrence].strip()
        return val if val != '-' else ''
    return ''
```

### Quick Security Analysis
```python
df = load_windows_csv('security.csv')

# Login failures summary
e4625 = df[df['事件識別碼'] == 4625].copy()
e4625['account'] = e4625['訊息'].apply(lambda x: get_field(x, '帳戶名稱', 1))
e4625['src_ip']  = e4625['訊息'].apply(lambda x: get_field(x, '來源網路位址'))
print(e4625.groupby(['src_ip', 'account']).size().sort_values(ascending=False).head(20))

# Successful network logins (type 3) — lateral movement
e4624 = df[df['事件識別碼'] == 4624].copy()
e4624['account']    = e4624['訊息'].apply(lambda x: get_field(x, '帳戶名稱', 1))
e4624['login_type'] = e4624['訊息'].apply(lambda x: get_field(x, '登入類型'))
e4624['src_ip']     = e4624['訊息'].apply(lambda x: get_field(x, '來源網路位址'))
e4624['auth_pkg']   = e4624['訊息'].apply(lambda x: get_field(x, '驗證封裝'))
t3 = e4624[e4624['login_type'] == '3']
print("\nType 3 (Network) logins:")
print(t3[['日期和時間','account','src_ip','auth_pkg']].to_string())

# Password changes
e4738 = df[df['事件識別碼'] == 4738].copy()
e4738['target']   = e4738['訊息'].apply(lambda x: get_field(x, '目標帳戶名稱'))
e4738['by_who']   = e4738['訊息'].apply(lambda x: get_field(x, '呼叫者使用者名稱'))
print("\nPassword changes (4738):")
print(e4738[['日期和時間','target','by_who']].to_string())
```
