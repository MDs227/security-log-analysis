---
name: security-log-analysis
description: |
  End-to-end forensic analysis of security incident logs across multiple platforms — firewalls
  (FortiGate, Cisco ASA/FTD, Sharetech ST/SG), Windows Server/PC (Event Logs), Linux servers
  (auth/syslog), and infrastructure (Hyper-V, Veeam). Use this skill whenever the user mentions
  incident response, log analysis, ransomware investigation, breach forensics, or provides log
  files or config files for security review. Also triggers when the user asks to "analyze logs",
  "check this config", "find the attack path", "look for IOCs", or "produce a security report".
  Covers the full workflow: ingest raw files from a client directory → triage → cross-platform
  analysis → attack timeline reconstruction → Markdown findings report + optional PPTX output.
---

# Security Log Analysis Skill

Forensic analysis workflow for security incidents involving multi-platform log sources.
Covers everything from raw file ingestion through cross-validated attack timeline to final report.

---

## Quick Start

When given a client directory or a set of log files, follow this sequence:

```
1. INGEST    → scan directory, identify file types, decompress archives
2. TRIAGE    → determine which platforms are present, read start.md if exists
3. ANALYZE   → run platform-specific analysis for each source found
4. CORRELATE → build unified attack timeline, cross-validate findings
5. REPORT    → write findings.md + timeline.md in analysis/ subdirectory
```

If the user says something like:
- **"分析 /path/to/客戶A"** → run the full workflow on that directory
- **"幫我看這份 FortiGate conf"** → jump to ANALYZE → fortigate only
- **"這個 Windows log 有沒有問題"** → jump to ANALYZE → windows only
- **"整理成報告"** → jump to REPORT using already-completed analysis

---

## Directory Convention

Expect client data in this structure (create if missing):

```
<client-dir>/
├── start.md          ← background context (incident time, affected hosts, client notes)
├── raw/              ← all original files, untouched
│   ├── *.conf / *.cfg
│   ├── *.csv / *.log / *.txt
│   ├── *.7z / *.zip / *.tar.gz
│   └── ...
├── analysis/         ← CREATE THIS — Claude writes here
│   ├── findings.md   ← main findings document
│   ├── timeline.md   ← unified chronological attack timeline
│   └── evidence/     ← per-platform extracts (optional)
│       ├── firewall.md
│       ├── windows_security.md
│       ├── windows_system.md
│       └── ...
└── report/           ← final deliverables (PPTX if requested)
```

---

## Step 1: Ingest & File Identification

Scan the directory recursively. For each file:

```python
# Pseudo-logic — adapt to actual bash/python as needed
extensions = {
    '.conf':   'firewall_config',
    '.cfg':    'firewall_config',
    '.csv':    'event_log',
    '.log':    'event_log',
    '.txt':    'event_log',
    '.evtx':   'windows_evtx',   # use python-evtx or evtxdump to convert first
    '.7z':     'archive',         # extract with: 7z x file.7z -o<dir>
    '.zip':    'archive',         # extract with: unzip
    '.tar.gz': 'archive',         # extract with: tar xzf
}
```

**Encoding detection** — always check before parsing:
```bash
file <filename>          # rough check
python3 -c "
import chardet
with open('file', 'rb') as f:
    print(chardet.detect(f.read(4096)))
"
```
Common encodings in Taiwan environments: `utf-8-sig` (BOM), `big5`, `cp950`, `latin-1`.

**CSV delimiter detection** — check first 2 raw lines:
- English comma `,` → standard CSV
- Chinese comma `，` → use `sep='，'` with `engine='python'`
- Tab `\t` → TSV

**Archive extraction:**
```bash
pip install py7zr --break-system-packages -q   # for .7z
python3 -c "import py7zr; py7zr.SevenZipFile('file.7z','r').extractall('raw/')"
```

After extraction, re-scan for newly extracted files and classify them.

---

## Step 2: Triage

Read `start.md` if it exists — extract:
- Known incident timeframe
- Affected host names / IPs
- Client-reported symptoms
- Any platforms already confirmed

Identify which platform reference files to load based on files found:

| Files found | Load reference |
|-------------|---------------|
| `.conf` with `config system interface` or `config firewall policy` | `references/firewall/fortigate.md` |
| `.conf` with `access-list`, `crypto map`, `interface GigabitEthernet` | `references/firewall/cisco-asa-ftd.md` |
| `.conf` or `.log` with `SHARETECH`, `ST-`, `SG-`, `sysd=` | `references/firewall/sharetech.md` |
| CSV/log with `Microsoft-Windows-Security-Auditing` or EventID column | `references/windows/event-ids.md` |
| CSV/log with `Service Control Manager`, `EventLog`, system events | `references/windows/server.md` |
| `/var/log/auth`, `sshd`, `PAM`, `sudo`, `useradd` patterns | `references/linux/auth-syslog.md` |
| Hyper-V Management, `Microsoft-Windows-Hyper-V` | `references/infrastructure/hyper-v.md` |
| Veeam, `VeeamBackup`, backup job events | `references/infrastructure/veeam.md` |

Load only the references needed. For large incidents with 3+ platforms, load all relevant ones.

---

## Step 3: Platform Analysis

Run each applicable platform analysis. Save interim findings to `analysis/evidence/<platform>.md`.

**Key outputs per platform:**
- List of confirmed IOCs (IPs, accounts, file paths, hashes if available)
- Chronological event list with timestamps
- Risk-rated findings (🔴 Critical / 🟠 High / 🟡 Medium)
- Unanswered questions / data gaps

See individual reference files for platform-specific logic.

---

## Step 4: Cross-Platform Correlation

After individual platform analysis, correlate findings:

1. **Unify timestamps** — convert all to `YYYY-MM-DD HH:MM:SS +0800` (Taiwan local)
2. **Map IP ↔ hostname** — build a lookup table from all sources combined
3. **Trace attack chain** — sequence events across platforms to reconstruct:
   - Initial access vector
   - Persistence mechanisms
   - Lateral movement path
   - Impact / data affected
4. **Identify gaps** — note missing log sources that would strengthen the case

**MITRE ATT&CK mapping** — tag each confirmed TTP:

| Phase | Common TTPs in ransomware cases |
|-------|---------------------------------|
| Initial Access | T1190 (Exploit Public-Facing App), T1078 (Valid Accounts), T1133 (External Remote Services) |
| Persistence | T1543 (Create/Modify System Process), T1219 (Remote Access Software) |
| Lateral Movement | T1021.002 (SMB/Windows Admin Shares), T1550.002 (Pass-the-Hash) |
| Impact | T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1496 (Resource Hijacking) |

---

## Step 5: Report Output

Write `analysis/findings.md` using this structure:

```markdown
# 資安事件分析報告 — <客戶名稱>
**分析日期：** YYYY-MM-DD
**日誌範圍：** <earliest timestamp> ～ <latest timestamp>
**分析平台：** FortiGate / Windows Security / Windows System / ...

## 執行摘要
[3-5 句話總結：初始破口、潛伏時間、影響範圍、風險等級]

## 風險評估
| 層面 | 等級 | 說明 |
|------|------|------|
| 整體風險 | 🔴 嚴重 | ... |
| 初始破口 | ... | ... |
| 橫向移動 | ... | ... |
| 資料影響 | ... | ... |

## 攻擊時間軸（詳見 timeline.md）
[摘要版 — 5 個關鍵節點]

## 各平台發現
[依平台分節，每節列 findings]

## IOC 清單
[IPs, accounts, file hashes, domains]

## 修補建議
[優先序 P1/P2/P3]

## 資料缺口
[哪些日誌沒有但應該要有]
```

Write `analysis/timeline.md` as a pure chronological table:

```markdown
# 攻擊時間軸

| 時間 | 來源 | EventID / 指標 | 事件 | 風險 |
|------|------|----------------|------|------|
| 2026-04-02 20:44 | FortiGate | login success | adminAAA 首次登入，srcip=80.82.65.127（荷蘭） | 🔴 |
| ... | ... | ... | ... | ... |
```

---

## Platform Reference Files

Read these files when the corresponding platform is detected:

- **`references/firewall/fortigate.md`** — FortiGate conf audit + event log analysis
- **`references/firewall/cisco-asa-ftd.md`** — Cisco ASA/FTD syslog + config audit
- **`references/firewall/sharetech.md`** — Sharetech ST/SG series log format + indicators
- **`references/windows/event-ids.md`** — Master EventID reference table (Security/System/App)
- **`references/windows/server.md`** — Windows Server specific indicators + boot/uptime analysis
- **`references/linux/auth-syslog.md`** — Linux auth.log / secure / syslog analysis
- **`references/infrastructure/hyper-v.md`** — Hyper-V event log indicators
- **`references/infrastructure/veeam.md`** — Veeam backup log analysis for ransomware indicators

---

## Notes

- **Always read `start.md` first** if it exists — client context prevents wasted analysis
- **Never modify files in `raw/`** — work from copies or read-only
- **Taiwan timezone** — assume +0800 unless log explicitly states otherwise
- **Chinese Windows logs** — field names will be in Traditional Chinese; key mappings are in the reference files
- When in doubt about a finding, **mark it clearly as推估 (inferred)** vs **確認 (confirmed from log)**
