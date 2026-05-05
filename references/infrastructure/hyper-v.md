# Hyper-V — Event Log Analysis for Incident Response

## Log Sources

| Source | Log Location in Windows | Key Events |
|--------|------------------------|------------|
| `Microsoft-Windows-Hyper-V-VMMS` | Application / Hyper-V-VMMS Admin | VM lifecycle |
| `Microsoft-Windows-Hyper-V-Worker` | Application / Hyper-V-Worker Admin | VM runtime errors |
| `Microsoft-Windows-Hyper-V-Config` | Application / Hyper-V-Config Admin | VM config changes |
| Windows Security Log | `Microsoft-Windows-Security-Auditing` | Host OS auth events |

In exported CSV, look for `來源` containing `Hyper-V` or `VMMS`.

---

## Key Event IDs

### VM Lifecycle

| EventID | Meaning | Ransomware Relevance |
|---------|---------|---------------------|
| **18500** | VM started | Normal — or malware starting VM to deploy payload |
| **18501** | VM stopped (graceful) | — |
| **18502** | VM saved state | — |
| **18503** | VM paused | Unusual at odd hours |
| **18504** | VM resumed | — |
| **18510** | VM deleted | 🔴 VM destroyed — ransomware targeting VMs |
| **18512** | VM snapshot created | Could be defensive (pre-attack backup) or ransomware preparation |
| **18513** | VM snapshot deleted | 🔴 Ransomware deleting snapshots to prevent recovery |
| **18580** | VM config changed | Who changed what |
| **18520** | VM migration started | — |
| **18521** | VM migration completed | Check source/destination |

### Host-Level Events Affecting VMs

| EventID | Source | Meaning |
|---------|--------|---------|
| 7045 | SCM | New service on Hyper-V host — check for ransomware service |
| 4688 | Security | Process on host — `vmwp.exe` children suspicious |
| 1074 | USER32 | Host shutdown — all VMs go down |
| 6008 | EventLog | Host crashed — ungraceful VM shutdown |

---

## Ransomware Targeting VMs

Modern ransomware (LockBit, BlackBasta, Akira) specifically targets Hyper-V:

### Pattern 1: Stop VMs → Encrypt VHDX Files
```
# Event sequence:
18501 (VM stopped) × N   ← attacker stops all VMs
[no more VM events]       ← ransomware encrypts .vhdx files on the host filesystem
18500 × 0               ← VMs cannot start (files encrypted)
```
**Detection:** Multiple 18501 events in rapid succession from non-admin time

### Pattern 2: Snapshot Deletion
```
18513 (snapshot deleted) × N
# All recovery points removed before encryption
```

### Pattern 3: VHD/VHDX Direct Encryption
```
# In Application Error log on host:
# vmwp.exe crashes when trying to start VM (VHDX is encrypted/corrupted)
EventID 1000: 失敗應用程式: vmwp.exe, version: 0.0.0.0 (or normal ver)
例外狀況代碼: 0xc0000005
```

---

## Analysis Template

```python
import pandas as pd, re

df = load_windows_csv('application.csv')  # from event-ids.md helper

# Filter Hyper-V events
hv = df[df['來源'].str.contains('Hyper-V|VMMS', na=False, case=False)].copy()

print(f"Total Hyper-V events: {len(hv)}")
print("\nEvent ID distribution:")
print(hv['事件識別碼'].value_counts())

# VM deletion / snapshot deletion
critical = hv[hv['事件識別碼'].isin([18510, 18513])]
if len(critical) > 0:
    print("\n⚠️  CRITICAL: VM deletion or snapshot deletion events:")
    print(critical[['日期和時間','事件識別碼','訊息']].to_string())

# Mass VM shutdown (>3 VMs stopped in <5 minutes)
stops = hv[hv['事件識別碼'] == 18501].copy()
stops['parsed_time'] = pd.to_datetime(stops['日期和時間'], errors='coerce', 
                                       format='%Y/%m/%d %p %I:%M:%S')
stops_sorted = stops.sort_values('parsed_time')
# Check for clustering
if len(stops) >= 3:
    time_span = (stops_sorted['parsed_time'].max() - 
                 stops_sorted['parsed_time'].min()).total_seconds()
    if time_span < 300:  # within 5 minutes
        print(f"\n⚠️  {len(stops)} VMs stopped within {time_span:.0f} seconds — possible ransomware")
        print(stops_sorted[['日期和時間','訊息']].to_string())
```

---

## Quick Indicators

| Indicator | Risk |
|-----------|------|
| 18510 (VM deleted) outside maintenance window | 🔴 Critical |
| 18513 (snapshot deleted) × multiple | 🔴 Critical — preventing recovery |
| Multiple 18501 (VM stop) in rapid succession | 🔴 Ransomware VM shutdown sweep |
| vmwp.exe crash (EventID 1000) | 🟠 VMs may be corrupted/encrypted |
| New service on Hyper-V host | 🔴 Ransomware/malware installed on hypervisor |
| Host 6008 (unexpected shutdown) | 🟠 VMs lost data — forceful power-off |
| VM config change (18580) from unexpected account | 🟠 Unauthorized VM modification |
