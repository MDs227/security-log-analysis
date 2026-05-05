# Veeam Backup & Replication — Ransomware Indicator Analysis

## Focus
This reference focuses on **detecting whether backups were targeted, deleted, or encrypted** — 
the primary concern in ransomware incidents. Normal operational analysis is out of scope.

---

## Log Sources

| Source | Location | Notes |
|--------|----------|-------|
| Veeam Application Log | Windows Application Event Log | EventIDs from `Veeam Backup` source |
| Veeam Job Reports | `%ProgramData%\Veeam\Backup\` | `.log` files per job |
| Veeam Database | SQL Server `VeeamBackup` database | If accessible |
| Windows Security Log | Host running Veeam | Auth events for Veeam service account |

In exported CSV look for `來源` containing `Veeam` or `VeeamBackup`.

---

## Key Event IDs

| EventID | Meaning | Ransomware Relevance |
|---------|---------|---------------------|
| **1** | Job finished successfully | Baseline — note last successful backup time |
| **2** | Job finished with warnings | — |
| **4** | Job failed | Repeated failures before attack = backups already broken |
| **190** | Backup deleted from repository | 🔴 Critical — backup removed |
| **191** | Restore point deleted | 🔴 Critical — point-in-time recovery removed |
| **200** | Repository reclaimed / removed | 🔴 Critical |
| **330** | Veeam service started | — |
| **331** | Veeam service stopped | 🔴 Stopping backup service = pre-encryption step |
| **560** | Immutability violation attempted | 🔴 Ransomware tried to delete immutable backup |
| **750** | Backup copy job failed | Check if target repo was encrypted |

---

## Critical Analysis: "Were Backups Destroyed?"

### Step 1: Find Last Successful Backup
```python
df = load_windows_csv('application.csv')

veeam = df[df['來源'].str.contains('Veeam', na=False, case=False)].copy()
veeam_ok = veeam[veeam['事件識別碼'] == 1]  # Job success

print("Last successful backups:")
print(veeam_ok[['日期和時間','訊息']].tail(10).to_string())
```

### Step 2: Check for Deletion Events (190/191/200)
```python
deletions = veeam[veeam['事件識別碼'].isin([190, 191, 200])]
if len(deletions) > 0:
    print("\n🔴 BACKUP DELETION EVENTS FOUND:")
    print(deletions[['日期和時間','事件識別碼','訊息']].to_string())
else:
    print("\n✅ No backup deletion events in log")
```

### Step 3: Check for Service Termination Before Attack
```python
from datetime import datetime

# Known attack time — set from start.md or analysis
attack_time = datetime(2026, 4, 29, 17, 16)

svc_stops = veeam[veeam['事件識別碼'] == 331]
# Filter stops before attack
for _, r in svc_stops.iterrows():
    t = pd.to_datetime(r['日期和時間'], errors='coerce')
    if t and t < pd.Timestamp(attack_time):
        print(f"⚠️  Veeam service stopped at {r['日期和時間']} — BEFORE attack")
```

### Step 4: Gap Analysis — Were Backups Running During Attack?
```python
# Check if backup jobs were running during the attack window
# (attacker may have waited for backup window to close)
all_jobs = veeam[veeam['事件識別碼'].isin([1, 4])].copy()
all_jobs['parsed'] = pd.to_datetime(all_jobs['日期和時間'], errors='coerce')
all_jobs_sorted = all_jobs.sort_values('parsed')

# Find gap
if len(all_jobs_sorted) >= 2:
    last_job = all_jobs_sorted.iloc[-1]
    second_last = all_jobs_sorted.iloc[-2]
    gap_hours = (last_job['parsed'] - second_last['parsed']).total_seconds() / 3600
    print(f"\nLast 2 backup events:")
    print(f"  {second_last['日期和時間']} — EventID {second_last['事件識別碼']}")
    print(f"  {last_job['日期和時間']} — EventID {last_job['事件識別碼']}")
    print(f"  Gap: {gap_hours:.1f} hours")
    if gap_hours > 48:
        print("  ⚠️  Gap >48h — backups may have been disabled before attack")
```

---

## Backup Repository Encryption Detection

If Veeam's backup repository is on the same server or accessible share:
```
# Indicators that repository was encrypted:
# 1. Backup job failures with "file not found" or "access denied" on .vbk/.vib/.vrb files
# 2. Veeam log files themselves contain ransomware extension (e.g., .locked, .encrypted)
# 3. Repository path shows files with uniform size and random-looking names

# Common Veeam backup file extensions (should NOT have additional extensions):
.vbk   ← full backup
.vib   ← incremental backup
.vrb   ← reverse incremental backup
.vbm   ← backup metadata

# If you see: backup.vbk.locked, backup.vib.WNCRYPT → encrypted by ransomware
```

---

## Recovery Assessment

After confirming backup status, document:

| Question | Findings |
|----------|---------|
| Last clean backup date | `YYYY-MM-DD HH:MM` |
| Backup retention period | N days/points |
| Were any backups deleted? | Yes/No + EventID evidence |
| Was Veeam service stopped? | Yes/No + timestamp |
| Is offsite/immutable copy available? | Yes/No |
| Estimated data loss (RPO) | N hours |

---

## Quick Indicators

| Indicator | Risk |
|-----------|------|
| EventID 190/191/200 (backup deleted) | 🔴 Critical — recovery may be impossible |
| EventID 331 (service stopped) before attack | 🔴 Attacker disabled backup protection |
| EventID 560 (immutability violation) | 🔴 Ransomware tried to delete protected backups |
| Repeated EventID 4 (job failures) before incident | 🟠 Backups were already broken |
| No EventID 1 (success) for >7 days before attack | 🟠 No recent clean restore point |
| Repository files with ransomware extensions | 🔴 Backups directly encrypted |
| Gap >48h between last two backup events | 🟠 Possible pre-attack disabling |
