---
name: security-log-analysis
description: >
  End-to-end forensic investigation of security incidents across multiple platforms — firewalls
  (FortiGate, Cisco ASA/FTD, Sharetech ST/SG), Windows (Event Logs, Server), Linux (auth/syslog),
  and infrastructure (Hyper-V, Veeam). Core strength: cross-platform correlation that traces an
  attack chain across firewall → endpoint → lateral movement in a single unified timeline.

  Trigger when: user mentions incident response, ransomware, breach forensics, "找攻擊路徑",
  "還原時間軸", "把所有 log 串起來", "分析這批 log", "有沒有橫向移動", or provides log/config
  files for security review. Also triggers when sources span two or more platforms (firewall +
  Windows, Windows + Linux, etc.) — that is when cross-platform correlation adds the most value.
  Single-platform requests ("幫我看這份 FortiGate conf") also trigger this skill.
---

## Workflow

```
INGEST → TRIAGE → ANALYZE → CORRELATE → REPORT
```

Entry points:
- **"分析 /path/to/客戶A"** → run full workflow
- **"幫我看這份 FortiGate conf"** → jump to ANALYZE (FortiGate only)
- **"整理成報告"** → jump to REPORT using existing evidence files

Before starting: read `start.md` first if it exists. Client context prevents wasted effort.

---

## Step 1: Ingest & File Identification

Scan directory recursively, decompress archives, classify files:

| Extension | Type |
|-----------|------|
| `.conf`, `.cfg` | firewall_config |
| `.csv`, `.log`, `.txt` | event_log |
| `.evtx` | windows_evtx — convert with `python-evtx` or `evtxdump` |
| `.7z`, `.zip`, `.tar.gz` | archive — extract to `raw/`, then re-scan |

**Encoding (Taiwan environments):** `utf-8-sig` (BOM), `big5`, `cp950`, `latin-1`

**CSV delimiter detection:**
- English comma `,` → standard CSV
- Chinese comma `，` → `sep='，'` with `engine='python'`
- Tab `\t` → TSV

**Archive extraction:**
```bash
pip install py7zr --break-system-packages -q
python3 -c "import py7zr; py7zr.SevenZipFile('file.7z','r').extractall('raw/')"
```

Never modify `raw/` files. Work from copies only.

---

## Step 2: Triage & Platform Detection

Read `start.md` to extract: incident timeframe, affected hosts/IPs, client-reported symptoms.

Detect platforms from file content and load corresponding references:

| Signal | Platform | Reference |
|--------|----------|-----------|
| `config system interface` or `config firewall policy` | FortiGate | `references/firewall/fortigate.md` |
| `access-list`, `crypto map`, `interface GigabitEthernet` | Cisco ASA/FTD | `references/firewall/cisco-asa-ftd.md` |
| `SHARETECH`, `ST-`, `SG-`, `sysd=` | Sharetech ST/SG | `references/firewall/sharetech.md` |
| `Microsoft-Windows-Security-Auditing` or EventID column | Windows Security | `references/windows/event-ids.md` |
| `Service Control Manager`, `EventLog`, `USER32` | Windows System/App | `references/windows/server.md` |
| `sshd`, `PAM`, `sudo`, `useradd`, `auth.log` patterns | Linux | `references/linux/auth-syslog.md` |
| `Microsoft-Windows-Hyper-V` | Hyper-V | `references/infrastructure/hyper-v.md` |
| `VeeamBackup`, backup job events | Veeam | `references/infrastructure/veeam.md` |

**Stop and ask the user if:**
- No `start.md` and files lack any incident timeframe context
- Only one log source present with < 24h coverage (not enough for timeline)
- Log timestamps are all identical or missing (likely export error)
- File encoding cannot be determined after trying all options above

---

## Step 3: Platform Analysis

Save findings to `analysis/evidence/<platform>.md` using these filenames:

| Platform | Evidence file |
|----------|--------------|
| FortiGate | `analysis/evidence/fortigate.md` |
| Cisco ASA/FTD | `analysis/evidence/cisco-asa-ftd.md` |
| Sharetech | `analysis/evidence/sharetech.md` |
| Windows Security | `analysis/evidence/windows-security.md` |
| Windows System/App | `analysis/evidence/windows-system.md` |
| Linux | `analysis/evidence/linux.md` |
| Hyper-V | `analysis/evidence/hyper-v.md` |
| Veeam | `analysis/evidence/veeam.md` |

Each file must contain: confirmed IOCs, chronological event list with timestamps, risk ratings (🔴 Critical / 🟠 High / 🟡 Medium), data gaps.

### FortiGate — Key Heuristics

**Config audit:**
- `allowaccess ping https ssh` on WAN interface → management exposed to internet 🔴
- Admin account without `trusthost` → no IP restriction 🔴
- No `admin-lockout-threshold` in `config system global` → brute-force protection disabled 🔴
- `srcaddr=all` + `service=ALL` + no UTM profile on inbound policy → full exposure 🔴
- VIP forwarding port 22 / 3389 / 445 / 1433 to internal host → direct attack surface 🟠

**Event log:**
- `action="login" status="success"` from non-local IP → unauthorized admin access 🔴
- `action="download"` after suspicious login → config exfiltration (attacker maps network) 🔴
- SSH session > 3600s from external IP → pivot / jump host use 🔴
- Login failures > 20 from single IP in 1h → brute force 🟠
- Successful logins from rotating IPs (same ASN, different exits) → VPN node rotation 🔴

**FortiOS CVE check** — extract version from `#config-version=` line:

| Version | Critical CVEs |
|---------|--------------|
| 7.0.x < 7.0.14 | CVE-2022-40684 (auth bypass, CVSS 9.6), CVE-2023-27997 (SSL-VPN RCE, CVSS 9.2) |
| 6.4.x < 6.4.13 | CVE-2022-40684, CVE-2023-27997 |
| Any with SSL-VPN enabled | CVE-2024-21762 (OOB Write, CVSS 9.6) |

### Windows — Key Heuristics

| EventID | Flag condition | Risk |
|---------|---------------|------|
| 4624 Login Type 3 | `NtLmSsp` + `NTLM V2` from internal IP = Pass-the-Hash | 🔴 |
| 4625 | > 50 failures from single IP in short window = brute force | 🔴 |
| 4648 | `cmd.exe` or `powershell.exe` as calling process = suspicious RunAs / PtH | 🔴 |
| 4738 | `SYSTEM` modifying Administrator password without preceding admin session = malware | 🔴 |
| 4720 + 4728 | New user added to privileged group = backdoor account | 🔴 |
| 4688 | `vssadmin.exe Delete Shadows`, `bcdedit /set recoveryenabled no`, `wbadmin delete catalog` = pre-encryption | 🔴 |
| 1102 | Audit log cleared = covering tracks | 🔴 |
| 6008 | Unexpected shutdown = forced reboot (ransomware-triggered) | 🟠 |
| 1074 reason `0x84050013` | Security-issue shutdown without preceding admin session = malware-triggered | 🔴 |

**EOL OS** — from EventID 6009:
| Build | Product | Status |
|-------|---------|--------|
| 6.1.7601 | Windows Server 2008 R2 | **EOL 2020-01-14** |
| 6.2.9200 | Windows Server 2012 | **EOL 2023-10-10** |
| 6.3.9600 | Windows Server 2012 R2 | **EOL 2023-10-10** |

### Linux — Key Heuristics

| Indicator | Pattern | Risk |
|-----------|---------|------|
| Root SSH from external IP | `Accepted password for root from <ext-IP>` | 🔴 |
| SSH brute force | > 20 `Failed password` from single IP in 10 min | 🔴 |
| New user with sudo | `useradd` + `usermod ... sudo` within same session | 🔴 |
| Root shell via sudo | `sudo bash`, `sudo su -`, `sudo -i` | 🔴 |
| Cron from temp path | CRON job from `/tmp`, `/dev/shm`, `/var/tmp` | 🔴 |
| Process name spoofing | `EXECVE` of `kthreadd`/`kworker` from `/tmp` | 🔴 |
| Download-and-execute persistence | `wget`/`curl` piped to `bash` from cron | 🔴 |
| Long external SSH session | Session duration > 2h from external IP | 🟠 |

---

## Step 4: Cross-Platform Correlation

1. **Unify timestamps** → `YYYY-MM-DD HH:MM:SS +0800` (assume Taiwan local unless stated)
2. **Build IP ↔ hostname lookup table** from all sources
3. **Reconstruct attack chain** — initial access → persistence → lateral movement → impact
4. **Cross-source confirmation:** same IP in FortiGate login log AND Windows 4624 = confirmed lateral path 🔴
5. **Note gaps** — list missing sources and what questions they would close

**MITRE ATT&CK mapping for ransomware:**

| Phase | Common TTPs |
|-------|------------|
| Initial Access | T1190 (Exploit Public-Facing App), T1078 (Valid Accounts), T1133 (External Remote Services) |
| Persistence | T1543 (Create/Modify System Process), T1219 (Remote Access Software), T1136 (Create Account) |
| Lateral Movement | T1021.002 (SMB/Windows Admin Shares), T1550.002 (Pass-the-Hash) |
| Defense Evasion | T1070.001 (Clear Windows Event Logs), T1562.001 (Disable AV) |
| Impact | T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1496 (Resource Hijacking) |

---

## Step 5: Report Output

Write `analysis/findings.md` and `analysis/timeline.md`.

**findings.md:**
```markdown
# 資安事件分析報告 — <客戶名稱>
**分析日期：** YYYY-MM-DD
**日誌範圍：** <earliest> ～ <latest>
**分析平台：** [list]

## 執行摘要
[3-5 sentences: initial breach, dwell time, impact scope, risk level]

## 風險評估
| 層面 | 等級 | 說明 |
|------|------|------|
| 整體風險 | 🔴 嚴重 | ... |
| 初始破口 | ... | ... |
| 橫向移動 | ... | ... |
| 資料影響 | ... | ... |

## 攻擊時間軸（詳見 timeline.md）
[5 key nodes summary]

## 各平台發現
[Platform-organized findings]

## IOC 清單
[IPs, accounts, file hashes, domains, suspicious process paths]

## 修補建議
[P1 (immediate) / P2 (within 1 week) / P3 (within 1 month)]

## 資料缺口
[Missing log sources and what questions they would answer]
```

**timeline.md:**
```markdown
# 攻擊時間軸

| 時間 | 來源 | EventID / 指標 | 事件 | 風險 |
|------|------|----------------|------|------|
| 2026-04-02 20:44 | FortiGate | login success | adminAAA 首次登入，srcip=80.82.65.127 | 🔴 |
```

Mark findings clearly: **推估** (inferred) vs **確認** (confirmed with log evidence).

---

## Directory Convention

```
<client-dir>/
├── start.md                      ← read first
├── raw/                          ← never modify
│   ├── *.conf / *.cfg
│   ├── *.csv / *.log / *.txt
│   └── *.7z / *.zip
├── analysis/
│   ├── findings.md
│   ├── timeline.md
│   └── evidence/
│       ├── fortigate.md
│       ├── windows-security.md
│       ├── windows-system.md
│       ├── linux.md
│       └── ...
└── report/
```

**Taiwan timezone** — assume +0800 unless log explicitly states otherwise.
**Chinese Windows logs** — field names in Traditional Chinese; mappings are in the reference files.
